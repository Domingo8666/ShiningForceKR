#!/usr/bin/env python3
"""Verify a ROM-free, non-build-eligible Korean display test phrase.

The tracked v5.1 BPS contains its expanded Korean font and Huffman engine as
source-independent TargetRead data.  This module validates the exact glyph
tiles and encodes one deliberately tiny technical marker without reading or
writing a ROM.  It does not select or modify a script entry.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from collections import deque
import json
from pathlib import Path

try:
    from .patch_io import (
        BPSSparseTarget,
        PatchError,
        extract_bps_target_literals,
        sha256_bytes,
    )
    from .sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from .v5_1_engine import (
        EXPECTED_PATCH_SHA256,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
        analyze_patch,
    )
except ImportError:  # direct script execution
    from patch_io import (
        BPSSparseTarget,
        PatchError,
        extract_bps_target_literals,
        sha256_bytes,
    )
    from sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from v5_1_engine import (
        EXPECTED_PATCH_SHA256,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
        analyze_patch,
    )


SCHEMA_VERSION = 1
TEST_PHRASE = "한다"
TEST_PURPOSE = "technical-poc-only"

FONT_PAGE_COUNT = 244
FONT_PAGE_SELECT_SYMBOL = 0x5F
FONT_GLYPH_FIRST_SYMBOL = 0x02
FONT_GLYPH_LAST_SYMBOL = 0x20
FONT_DATA_FIRST_BANK = 0x22
FONT_PAGES_PER_BANK = 4
FONT_PAGE_STRIDE = 0x0C00
FONT_PAGE_DATA_OFFSET = 0x0040
FONT_TILE_BYTES = 32
ROM_BANK_BYTES = 0x4000


@dataclass(frozen=True)
class GlyphSpec:
    character: str
    page: int
    symbol: int
    tile_sha256: str
    identification: str = "manual-visual-identification-pending-runtime-proof"


TEST_GLYPHS = {
    "한": GlyphSpec(
        character="한",
        page=6,
        symbol=0x11,
        tile_sha256=(
            "9480834f5c532ab8706bcb35a6aac1a3"
            "6138d5ab84e09f90c0c030678bbc03b4"
        ),
        identification="exact-galmuri7-bdf-pixel-match",
    ),
    "다": GlyphSpec(
        character="다",
        page=6,
        symbol=0x04,
        tile_sha256=(
            "3a0eab5abafdc86a7d5d31e100af8bab"
            "4de9b030339d748c75dab031547663ee"
        ),
        identification="exact-galmuri7-bdf-pixel-match",
    ),
}


def font_tile_offset(page: int, symbol: int) -> int:
    if not 0 <= page < FONT_PAGE_COUNT:
        raise PatchError(f"font page is out of range: {page}")
    if not FONT_GLYPH_FIRST_SYMBOL <= symbol <= FONT_GLYPH_LAST_SYMBOL:
        raise PatchError(f"font glyph symbol is out of range: 0x{symbol:02x}")
    bank = FONT_DATA_FIRST_BANK + page // FONT_PAGES_PER_BANK
    page_in_bank = page % FONT_PAGES_PER_BANK
    glyph_index = symbol - FONT_GLYPH_FIRST_SYMBOL
    return (
        bank * ROM_BANK_BYTES
        + FONT_PAGE_DATA_OFFSET
        + page_in_bank * FONT_PAGE_STRIDE
        + glyph_index * FONT_TILE_BYTES
    )


def page_select_symbols(page: int) -> list[int]:
    if not 0 <= page < FONT_PAGE_COUNT:
        raise PatchError(f"font page is out of range: {page}")
    high = (page >> 4) + 2
    low = (page & 0x0F) + 2
    if high > 0x20 or low > 0x20:
        raise PatchError(f"font page cannot be represented: {page}")
    return [FONT_PAGE_SELECT_SYMBOL, high, low]


def symbols_for_text(
    text: str, glyphs: dict[str, GlyphSpec] = TEST_GLYPHS
) -> list[int]:
    if not text:
        raise PatchError("test phrase must not be empty")
    output: list[int] = []
    selected_page: int | None = None
    for character in text:
        glyph = glyphs.get(character)
        if glyph is None:
            raise PatchError(f"no approved test glyph for U+{ord(character):04X}")
        if glyph.character != character:
            raise PatchError("test glyph key and character disagree")
        if glyph.page != selected_page:
            output.extend(page_select_symbols(glyph.page))
            selected_page = glyph.page
        output.append(glyph.symbol)
    return output


def validate_glyphs(
    sparse: BPSSparseTarget,
    text: str = TEST_PHRASE,
    glyphs: dict[str, GlyphSpec] = TEST_GLYPHS,
) -> list[dict[str, object]]:
    validated: list[dict[str, object]] = []
    seen: set[str] = set()
    for character in text:
        if character in seen:
            continue
        seen.add(character)
        glyph = glyphs.get(character)
        if glyph is None:
            raise PatchError(f"no approved test glyph for U+{ord(character):04X}")
        offset = font_tile_offset(glyph.page, glyph.symbol)
        end = offset + FONT_TILE_BYTES
        if end > len(sparse.data) or any(value == 0 for value in sparse.known[offset:end]):
            raise PatchError(
                f"glyph U+{ord(character):04X} is not source-independent"
            )
        tile = sparse.data[offset:end]
        actual_sha256 = sha256_bytes(tile)
        if actual_sha256 != glyph.tile_sha256:
            raise PatchError(
                f"glyph U+{ord(character):04X} tile identity mismatch"
            )
        validated.append(
            {
                "character": character,
                "codepoint": f"U+{ord(character):04X}",
                "page": glyph.page,
                "symbol": glyph.symbol,
                "file_offset": offset,
                "tile_sha256": actual_sha256,
                "identification": glyph.identification,
            }
        )
    return validated


def build_test_phrase_plan(
    patch: bytes, text: str = TEST_PHRASE
) -> dict[str, object]:
    if text != TEST_PHRASE:
        raise PatchError("only the approved technical test phrase is supported")

    engine = analyze_patch(patch)
    sparse = extract_bps_target_literals(patch)
    glyphs = validate_glyphs(sparse, text)
    display_symbols = symbols_for_text(text)
    symbols = display_symbols + [CANDIDATE_END_SYMBOL]

    trees = load_trees_at(
        sparse.data,
        sparse.known,
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )
    encoded, encoded_bits = encode_symbols(trees, symbols)
    decoded, decoded_bits = decode_symbols(
        encoded,
        bytes((1,)) * len(encoded),
        trees,
        0,
        max_symbols=len(symbols),
        max_bytes=len(encoded),
    )
    if decoded != symbols or decoded_bits != encoded_bits:
        raise PatchError("test phrase Huffman roundtrip mismatch")

    return {
        "artifact_kind": "rom-free-korean-test-phrase-plan",
        "schema_version": SCHEMA_VERSION,
        "status": "verified-static-non-build-eligible",
        "purpose": TEST_PURPOSE,
        "phrase": text,
        "patch_sha256": EXPECTED_PATCH_SHA256,
        "font": {
            "page_count": FONT_PAGE_COUNT,
            "page_select_symbol": FONT_PAGE_SELECT_SYMBOL,
            "glyphs": glyphs,
        },
        "encoding": {
            "initial_symbol": CANDIDATE_END_SYMBOL,
            "end_symbol": CANDIDATE_END_SYMBOL,
            "symbols": symbols,
            "symbols_hex": [f"0x{symbol:02X}" for symbol in symbols],
            "encoded_bits": encoded_bits,
            "encoded_bytes": len(encoded),
            "encoded_hex": encoded.hex(),
            "roundtrip_exact": True,
        },
        "checks": {
            "v5_1_patch_identity": "pass",
            "korean_engine_static_layout": engine["status"],
            "font_tiles_source_independent": "pass",
            "font_tile_identities": "pass",
            "unknown_glyph_policy": "fail",
            "huffman_encode_decode_roundtrip": "pass",
            "rom_read": False,
            "rom_written": False,
        },
        "translation_build_eligible": False,
        "required_before_build": [
            "runtime-consumer-resolution-schema-v2",
            "exact-visible-entry-identification",
            "selected-entry-no-change-roundtrip",
            "verified-non-overlapping-expected-writes",
            "cold-boot-emulator-display-proof",
        ],
    }


def _code_lengths(trees: dict[int, object]) -> dict[int, dict[int, int]]:
    """Return symbol-code lengths without exposing encoded ROM data."""

    result: dict[int, dict[int, int]] = {}
    for previous, parsed in trees.items():
        lengths: dict[int, int] = {}
        stack = [(parsed.root, 0)]
        while stack:
            node, depth = stack.pop()
            if node.is_leaf:
                assert node.symbol is not None
                if node.symbol in lengths:
                    raise PatchError("duplicate Huffman leaf symbol")
                lengths[node.symbol] = depth
                continue
            if node.left is None or node.right is None:
                raise PatchError("malformed Huffman branch")
            stack.append((node.right, depth + 1))
            stack.append((node.left, depth + 1))
        result[int(previous)] = lengths
    return result


def length_preserving_symbols(
    trees: dict[int, object],
    target_bits: int,
    text: str = TEST_PHRASE,
) -> list[int]:
    """Find a deterministic, display-equivalent exact-length test sequence.

    Only the verified page-select control and the two approved glyphs may be
    emitted. Repeated page selections do not draw pixels. The sequence must be
    on page 6 before every visible glyph and again before the terminator so the
    renderer state is restored.
    """

    if text != TEST_PHRASE:
        raise PatchError("only the approved technical test phrase is supported")
    if not isinstance(target_bits, int) or isinstance(target_bits, bool):
        raise PatchError("target bit length must be an integer")
    if not 1 <= target_bits <= 2048:
        raise PatchError("target bit length is outside the safe search range")

    lengths = _code_lengths(trees)

    def transition(
        previous: int, symbols: tuple[int, ...]
    ) -> tuple[int, int] | None:
        bits = 0
        for symbol in symbols:
            code_length = lengths.get(previous, {}).get(symbol)
            if code_length is None:
                return None
            bits += code_length
            previous = symbol
        return bits, previous

    page_tokens = [
        (page, tuple(page_select_symbols(page)))
        for page in range(FONT_PAGE_COUNT)
    ]
    glyph_symbols = (
        TEST_GLYPHS["한"].symbol,
        TEST_GLYPHS["다"].symbol,
    )
    start = (0, CANDIDATE_END_SYMBOL, None, 0)
    queue = deque([start])
    paths: dict[
        tuple[int, int, int | None, int],
        tuple[int, ...],
    ] = {start: ()}

    while queue:
        state = queue.popleft()
        bits, previous, page, glyph_index = state
        if glyph_index == len(glyph_symbols) and page == 6:
            ending = transition(previous, (CANDIDATE_END_SYMBOL,))
            if ending is not None and bits + ending[0] == target_bits:
                return list(paths[state] + (CANDIDATE_END_SYMBOL,))

        for selected_page, token in page_tokens:
            encoded = transition(previous, token)
            if encoded is None or bits + encoded[0] >= target_bits:
                continue
            candidate = (
                bits + encoded[0],
                encoded[1],
                selected_page,
                glyph_index,
            )
            if candidate not in paths:
                paths[candidate] = paths[state] + token
                queue.append(candidate)

        if page == 6 and glyph_index < len(glyph_symbols):
            glyph = glyph_symbols[glyph_index]
            encoded = transition(previous, (glyph,))
            if encoded is not None and bits + encoded[0] < target_bits:
                candidate = (
                    bits + encoded[0],
                    encoded[1],
                    page,
                    glyph_index + 1,
                )
                if candidate not in paths:
                    paths[candidate] = paths[state] + (glyph,)
                    queue.append(candidate)

    raise PatchError(
        "no display-equivalent exact-length technical phrase encoding exists"
    )


def build_length_preserving_test_phrase_plan(
    patch: bytes,
    target_bits: int,
    text: str = TEST_PHRASE,
) -> dict[str, object]:
    """Build the approved test phrase at an exact compressed bit length."""

    plan = build_test_phrase_plan(patch, text)
    sparse = extract_bps_target_literals(patch)
    trees = load_trees_at(
        sparse.data,
        sparse.known,
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )
    symbols = length_preserving_symbols(trees, target_bits, text)
    encoded, encoded_bits = encode_symbols(
        trees,
        symbols,
        max_bits=target_bits,
    )
    decoded, decoded_bits = decode_symbols(
        encoded,
        bytes((1,)) * len(encoded),
        trees,
        0,
        max_symbols=len(symbols),
        max_bytes=len(encoded),
    )
    if (
        encoded_bits != target_bits
        or decoded != symbols
        or decoded_bits != encoded_bits
    ):
        raise PatchError("length-preserving phrase roundtrip mismatch")

    encoding = plan["encoding"]
    assert isinstance(encoding, dict)
    encoding.update(
        {
            "symbols": symbols,
            "symbols_hex": [f"0x{symbol:02X}" for symbol in symbols],
            "encoded_bits": encoded_bits,
            "encoded_bytes": len(encoded),
            "encoded_hex": encoded.hex(),
            "roundtrip_exact": True,
            "length_preserving": True,
            "page_select_only_padding": True,
            "final_selected_page": 6,
        }
    )
    plan["status"] = (
        "verified-static-exact-length-non-build-eligible"
    )
    return plan


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--patch",
        type=Path,
        default=root / "patch" / "Final_Conflict_Japan_to_Korean_v5.1.bps",
    )
    parser.add_argument("--json", type=Path, help="optional ROM-free JSON output")
    parser.add_argument("--stdout", action="store_true", help="also print JSON")
    args = parser.parse_args()

    plan = build_test_phrase_plan(args.patch.read_bytes())
    rendered = json.dumps(plan, ensure_ascii=False, indent=2) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered, encoding="utf-8")
        print(f"Wrote ROM-free test phrase plan: {args.json}")
    if args.stdout or not args.json:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
