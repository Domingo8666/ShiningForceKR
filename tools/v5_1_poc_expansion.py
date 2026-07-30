#!/usr/bin/env python3
"""Build a four-glyph exact-length PoC after the first visible proof passes."""

from __future__ import annotations

from collections import deque

try:
    from .patch_io import PatchError, extract_bps_target_literals
    from .sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from .v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
        analyze_patch,
    )
    from .v5_1_test_phrase import (
        FONT_PAGE_COUNT,
        GlyphSpec,
        _code_lengths,
        page_select_symbols,
        symbols_for_text,
        validate_glyphs,
    )
    from .v5_1_visible_entry_proof import validate_visible_entry_proof
except ImportError:  # direct script execution
    from patch_io import PatchError, extract_bps_target_literals
    from sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
        analyze_patch,
    )
    from v5_1_test_phrase import (
        FONT_PAGE_COUNT,
        GlyphSpec,
        _code_lengths,
        page_select_symbols,
        symbols_for_text,
        validate_glyphs,
    )
    from v5_1_visible_entry_proof import validate_visible_entry_proof


EXPANSION_PHRASE = "시험한다"
EXPANSION_PAGE = 89
EXPANSION_PURPOSE = "technical-poc-expanded-visible-entry"
EXPANSION_GLYPHS = {
    "시": GlyphSpec(
        character="시",
        page=EXPANSION_PAGE,
        symbol=0x14,
        tile_sha256=(
            "b41ccdb812764832dae89fc47c52101abe0a2f13b676681bb"
            "1fb69799eeec728"
        ),
        ink_mask=(0x00, 0x24, 0x24, 0x24, 0x54, 0x54, 0x8C, 0x04),
        identification="exact-galmuri7-bdf-pixel-match",
    ),
    "험": GlyphSpec(
        character="험",
        page=EXPANSION_PAGE,
        symbol=0x19,
        tile_sha256=(
            "4f90f6ef6aa37219966e6882a9895bba372c845362b254f9d"
            "81e4339cc7cd923"
        ),
        ink_mask=(0x00, 0x44, 0xF4, 0x9C, 0x64, 0x7C, 0x44, 0x7C),
        identification="exact-galmuri7-bdf-pixel-match",
    ),
    "한": GlyphSpec(
        character="한",
        page=EXPANSION_PAGE,
        symbol=0x12,
        tile_sha256=(
            "9480834f5c532ab8706bcb35a6aac1a36138d5ab84e09f90"
            "c0c030678bbc03b4"
        ),
        ink_mask=(0x00, 0x44, 0xFC, 0x96, 0x64, 0x04, 0x40, 0x7C),
        identification="exact-galmuri7-bdf-pixel-match",
    ),
    "다": GlyphSpec(
        character="다",
        page=EXPANSION_PAGE,
        symbol=0x04,
        tile_sha256=(
            "3a0eab5abafdc86a7d5d31e100af8bab4de9b030339d748c"
            "75dab031547663ee"
        ),
        ink_mask=(0x00, 0xF4, 0x84, 0x84, 0x86, 0x84, 0xF4, 0x04),
        identification="exact-galmuri7-bdf-pixel-match",
    ),
}


def _exact_length_symbols(
    trees: dict[int, object],
    target_bits: int,
) -> list[int]:
    if (
        not isinstance(target_bits, int)
        or isinstance(target_bits, bool)
        or not 1 <= target_bits <= 2048
    ):
        raise PatchError("expanded PoC target bit length is invalid")
    lengths = _code_lengths(trees)

    def transition(
        previous: int,
        symbols: tuple[int, ...],
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
    glyph_symbols = tuple(
        EXPANSION_GLYPHS[character].symbol
        for character in EXPANSION_PHRASE
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
        if glyph_index == len(glyph_symbols) and page == EXPANSION_PAGE:
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

        if page == EXPANSION_PAGE and glyph_index < len(glyph_symbols):
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
        "no exact-length four-glyph technical PoC encoding exists"
    )


def build_expanded_phrase_plan(
    patch: bytes,
    target_bits: int,
    visible_entry_proof: dict[str, object],
) -> dict[str, object]:
    validate_visible_entry_proof(visible_entry_proof)
    runtime = visible_entry_proof["runtime_entry"]
    assert isinstance(runtime, dict)
    if (
        runtime["encoded_bits"] != target_bits
        or int(runtime["record_length_bytes"]) * 8 < target_bits
        or visible_entry_proof["status"] != "exact-visible-entry-confirmed"
    ):
        raise PatchError("visible entry proof does not match the PoC bit budget")

    engine = analyze_patch(patch)
    sparse = extract_bps_target_literals(patch)
    glyphs = validate_glyphs(
        sparse,
        EXPANSION_PHRASE,
        EXPANSION_GLYPHS,
    )
    base_symbols = symbols_for_text(
        EXPANSION_PHRASE,
        EXPANSION_GLYPHS,
    ) + [CANDIDATE_END_SYMBOL]
    trees = load_trees_at(
        sparse.data,
        sparse.known,
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )
    base_encoded, base_bits = encode_symbols(trees, base_symbols)
    base_decoded, base_decoded_bits = decode_symbols(
        base_encoded,
        bytes((1,)) * len(base_encoded),
        trees,
        0,
        max_symbols=len(base_symbols),
        max_bytes=len(base_encoded),
    )
    if base_decoded != base_symbols or base_decoded_bits != base_bits:
        raise PatchError("expanded PoC base encoding roundtrip mismatch")

    symbols = _exact_length_symbols(trees, target_bits)
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
        raise PatchError("expanded PoC exact-length roundtrip mismatch")

    return {
        "artifact_kind": "rom-free-korean-poc-expansion-plan",
        "schema_version": 1,
        "status": "verified-static-exact-length-non-build-eligible",
        "purpose": EXPANSION_PURPOSE,
        "phrase": EXPANSION_PHRASE,
        "phrase_codepoints": [
            f"U+{ord(character):04X}" for character in EXPANSION_PHRASE
        ],
        "visible_entry_proof": {
            "baseline_target_sha256": visible_entry_proof[
                "baseline_target_sha256"
            ],
            "test_target_sha256": visible_entry_proof[
                "test_target_sha256"
            ],
            "physical_start": runtime["physical_start"],
            "logical_start": runtime["logical_start"],
            "mapped_bank": runtime["mapped_bank"],
            "record_length_bytes": runtime["record_length_bytes"],
            "original_encoded_bits": runtime["encoded_bits"],
        },
        "font": {
            "page": EXPANSION_PAGE,
            "glyphs": glyphs,
        },
        "encoding": {
            "initial_symbol": CANDIDATE_END_SYMBOL,
            "end_symbol": CANDIDATE_END_SYMBOL,
            "base_encoded_bits": base_bits,
            "symbols": symbols,
            "symbols_hex": [f"0x{symbol:02X}" for symbol in symbols],
            "encoded_bits": encoded_bits,
            "encoded_bytes": len(encoded),
            "encoded_hex": encoded.hex(),
            "roundtrip_exact": True,
            "length_preserving": True,
            "page_select_only_padding": True,
            "final_selected_page": EXPANSION_PAGE,
        },
        "checks": {
            "korean_engine_static_layout": engine["status"],
            "four_glyph_tiles_source_independent": "pass",
            "four_glyph_tile_identities": "pass",
            "base_huffman_roundtrip": "pass",
            "exact_length_huffman_roundtrip": "pass",
            "visible_entry_proof": "pass",
            "rom_read": False,
            "rom_written": False,
        },
        "translation_build_eligible": False,
        "next_checkpoint": "cold-boot-and-confirm-expanded-poc-on-screen",
    }
