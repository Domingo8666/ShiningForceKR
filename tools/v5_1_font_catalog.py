#!/usr/bin/env python3
"""Identify source-independent v5.1 Korean tiles with Galmuri7 pixels."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re

try:
    from .fetch_galmuri7_bdf import BDF_SHA256, BDF_SIZE, COMMIT, URL, digest
    from .patch_io import PatchError, extract_bps_target_literals, sha256_bytes
    from .v5_1_engine import analyze_patch
    from .v5_1_test_phrase import (
        FONT_GLYPH_FIRST_SYMBOL,
        FONT_GLYPH_LAST_SYMBOL,
        FONT_PAGE_COUNT,
        FONT_TILE_BYTES,
        font_tile_offset,
    )
except ImportError:  # direct script execution
    from fetch_galmuri7_bdf import BDF_SHA256, BDF_SIZE, COMMIT, URL, digest
    from patch_io import PatchError, extract_bps_target_literals, sha256_bytes
    from v5_1_engine import analyze_patch
    from v5_1_test_phrase import (
        FONT_GLYPH_FIRST_SYMBOL,
        FONT_GLYPH_LAST_SYMBOL,
        FONT_PAGE_COUNT,
        FONT_TILE_BYTES,
        font_tile_offset,
    )


SCHEMA_VERSION = 1
HANGUL_FIRST = 0xAC00
HANGUL_LAST = 0xD7A3


def _parse_bdf_glyphs(
    lines: list[str],
) -> dict[int, tuple[int, ...]]:
    """Parse BDF glyphs that fit the game's eight-pixel cell."""

    glyphs: dict[int, tuple[int, ...]] = {}
    encoding: int | None = None
    width: int | None = None
    height: int | None = None
    bitmap_rows: list[int] | None = None
    bitmap_supported = True
    for line in lines:
        if line.startswith("ENCODING "):
            encoding = int(line.split()[1])
        elif line.startswith("BBX "):
            parts = line.split()
            width = int(parts[1])
            height = int(parts[2])
        elif line == "BITMAP":
            bitmap_rows = []
            bitmap_supported = True
        elif line == "ENDCHAR":
            if (
                encoding is not None
                and encoding >= 0
                and width is not None
                and height is not None
                and 0 <= width <= 8
                and 0 <= height <= 8
                and bitmap_rows is not None
                and bitmap_supported
                and len(bitmap_rows) == height
            ):
                if encoding in glyphs:
                    raise PatchError(f"duplicate BDF encoding U+{encoding:04X}")
                glyphs[encoding] = tuple(
                    [0] * (8 - len(bitmap_rows)) + bitmap_rows
                )
            encoding = None
            width = None
            height = None
            bitmap_rows = None
            bitmap_supported = True
        elif bitmap_rows is not None and re.fullmatch(
            r"[0-9A-Fa-f]{2}",
            line,
        ):
            bitmap_rows.append(int(line, 16))
        elif bitmap_rows is not None and re.fullmatch(
            r"[0-9A-Fa-f]+",
            line,
        ):
            bitmap_supported = False
    return glyphs


def parse_bdf_glyphs(data: bytes) -> dict[int, tuple[int, ...]]:
    """Parse every verified Galmuri7 glyph that fits an 8×8 cell."""

    if len(data) != BDF_SIZE or digest(data) != BDF_SHA256:
        raise PatchError("Galmuri7 BDF identity mismatch")
    glyphs = _parse_bdf_glyphs(data.decode("utf-8").splitlines())
    if len(glyphs) < 11_172:
        raise PatchError(
            f"unexpected Galmuri7 8x8 glyph count: {len(glyphs)}"
        )
    return glyphs


def parse_bdf_hangul(data: bytes) -> dict[int, tuple[int, ...]]:
    """Parse 8-pixel-wide Hangul bitmap rows from the verified BDF."""

    glyphs = {
        codepoint: mask
        for codepoint, mask in parse_bdf_glyphs(data).items()
        if HANGUL_FIRST <= codepoint <= HANGUL_LAST
    }
    if len(glyphs) != 11_172:
        raise PatchError(
            f"unexpected Galmuri7 Hangul glyph count: {len(glyphs)}"
        )
    return glyphs


def tile_ink_mask(tile: bytes) -> tuple[int, ...]:
    """Collapse one Game Gear 4bpp tile to eight one-bit ink rows."""

    if len(tile) != FONT_TILE_BYTES:
        raise PatchError("font tile must be exactly 32 bytes")
    return tuple(
        ~(tile[index] & tile[index + 1] & tile[index + 2] & tile[index + 3])
        & 0xFF
        for index in range(0, FONT_TILE_BYTES, 4)
    )


def match_masks(
    masks: list[tuple[int, int, tuple[int, ...], str]],
    glyphs: dict[int, tuple[int, ...]],
) -> tuple[list[dict[str, object]], dict[str, int]]:
    reverse: dict[tuple[int, ...], list[int]] = defaultdict(list)
    for codepoint, mask in glyphs.items():
        reverse[mask].append(codepoint)

    entries: list[dict[str, object]] = []
    counts: Counter[str] = Counter()
    unique_codepoints: set[int] = set()
    for page, symbol, mask, tile_hash in masks:
        candidates = reverse.get(mask, [])
        if len(candidates) == 1:
            status = "unique"
            unique_codepoints.add(candidates[0])
        elif candidates:
            status = "ambiguous"
        else:
            status = "unmatched"
        counts[status] += 1
        entries.append(
            {
                "page": page,
                "symbol": symbol,
                "status": status,
                "codepoints": [f"U+{value:04X}" for value in candidates],
                "characters": [chr(value) for value in candidates],
                "tile_sha256": tile_hash,
            }
        )
    summary = {
        "total_tiles": len(entries),
        "unique_matches": counts["unique"],
        "ambiguous_matches": counts["ambiguous"],
        "unmatched_tiles": counts["unmatched"],
        "distinct_unique_codepoints": len(unique_codepoints),
    }
    return entries, summary


def build_font_catalog(patch: bytes, bdf: bytes) -> dict[str, object]:
    analyze_patch(patch)
    sparse = extract_bps_target_literals(patch)
    glyphs = parse_bdf_hangul(bdf)
    masks: list[tuple[int, int, tuple[int, ...], str]] = []
    for page in range(FONT_PAGE_COUNT):
        for symbol in range(
            FONT_GLYPH_FIRST_SYMBOL,
            FONT_GLYPH_LAST_SYMBOL + 1,
        ):
            offset = font_tile_offset(page, symbol)
            end = offset + FONT_TILE_BYTES
            if any(value == 0 for value in sparse.known[offset:end]):
                raise PatchError("font catalog contains source-dependent bytes")
            tile = sparse.data[offset:end]
            masks.append(
                (
                    page,
                    symbol,
                    tile_ink_mask(tile),
                    sha256_bytes(tile),
                )
            )
    entries, summary = match_masks(masks, glyphs)
    known = {
        (entry["page"], entry["symbol"]): entry
        for entry in entries
    }
    if (
        known[(6, 0x11)]["codepoints"] != ["U+D55C"]
        or known[(6, 0x04)]["codepoints"] != ["U+B2E4"]
        or known[(27, 0x1F)]["codepoints"] == ["U+D55C"]
    ):
        raise PatchError("known Korean test glyph identities did not match")
    return {
        "artifact_kind": "local-v5-1-galmuri7-font-catalog",
        "schema_version": SCHEMA_VERSION,
        "status": "verified-static-local-analysis",
        "reference": {
            "url": URL,
            "commit": COMMIT,
            "size": BDF_SIZE,
            "sha256": BDF_SHA256,
            "license": "SIL Open Font License 1.1",
        },
        "summary": summary,
        "known_test_glyphs": {
            "한": known[(6, 0x11)],
            "다": known[(6, 0x04)],
            "discarded_page_27_symbol_1f": known[(27, 0x1F)],
        },
        "entries": entries,
    }


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--patch",
        type=Path,
        default=root / "patch" / "Final_Conflict_Japan_to_Korean_v5.1.bps",
    )
    parser.add_argument(
        "--bdf",
        type=Path,
        default=root / "analysis" / "local" / "Galmuri7.bdf",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=root / "analysis" / "local" / "v5_1_font_catalog.json",
    )
    args = parser.parse_args()

    result = build_font_catalog(
        args.patch.read_bytes(),
        args.bdf.read_bytes(),
    )
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote local font catalog: {args.json}")
    print(json.dumps(result["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
