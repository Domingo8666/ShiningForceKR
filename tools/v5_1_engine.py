#!/usr/bin/env python3
"""Validate the source-independent Korean engine data embedded in v5.1 BPS.

The BPS extension is made entirely of TargetRead bytes, so this module can
inspect the relocated Huffman trees and Korean font runtime without storing or
reading the copyrighted Japanese ROM. Script lookup discovery remains a
separate consumer-code checkpoint.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from .patch_io import PatchError, extract_bps_target_literals, sha256_bytes
    from .sfgfc_huffman import load_trees_at
except ImportError:  # direct script execution
    from patch_io import PatchError, extract_bps_target_literals, sha256_bytes
    from sfgfc_huffman import load_trees_at

EXPECTED_PATCH_SIZE = 1_080_753
EXPECTED_PATCH_SHA256 = "7f92221afc8dc4b13712776d7eeca3571b9896fd746cefbc44b5a5806501633b"
EXPECTED_SOURCE_SIZE = 0x80000
EXPECTED_TARGET_SIZE = 0x17C000
EXPECTED_SOURCE_CRC32 = 0x6019FE5E
EXPECTED_TARGET_CRC32 = 0x23BAC434

KO_TREE_BANK = 0x20
KO_TREE_BANK_BASE = KO_TREE_BANK * 0x4000
KO_VECTOR_OFFSET = 0x80100
KO_VECTOR_LOGICAL = 0x4100
KO_VECTOR_ENTRIES = 256
KO_TREE_DATA_START = 0x80300
KO_TREE_DATA_END = 0x808D3
DECODER_PATCH_CODE = (0x33FA, 0x3405)
DECODER_TREE_BANK_LITERAL = 0x3432
DECODER_ENTRY_CANDIDATES = (0x33FA, 0x3411, 0x3431)
EXPECTED_CONTEXTS = (
    *range(0x00, 0x21),
    0x5F, 0x64, 0xC9, 0xCA, 0xCC, 0xCD, 0xCF, 0xD0, 0xD1,
    0xD2, 0xD4, 0xD5, 0xD6, 0xD8, 0xD9, 0xDB, 0xDC, 0xDD,
)

FONT_RUNTIME_PRIMARY = (0x87000, 0x8730B)
FONT_RUNTIME_SECONDARY = (0x87A00, 0x87A9D)
FONT_PAGE_MAP = (0x87400, 0x874F4)
FONT_DATA_FIRST_BANK = 0x22
FONT_DATA_LAST_BANK = 0x5E
FULL_FONT_BANK_LAST = 0x5D
BANK_SIZE = 0x4000


def _require_known(known: bytes, start: int, end: int, label: str) -> None:
    if start < 0 or end > len(known) or any(value == 0 for value in known[start:end]):
        raise PatchError(f"{label} is not fully recoverable from BPS literals")


def _last_non_ff(data: bytes) -> int:
    for index in range(len(data) - 1, -1, -1):
        if data[index] != 0xFF:
            return index + 1
    return 0


def analyze_patch(patch: bytes) -> dict[str, object]:
    if len(patch) != EXPECTED_PATCH_SIZE or sha256_bytes(patch) != EXPECTED_PATCH_SHA256:
        raise PatchError("v5.1 BPS identity mismatch")

    sparse = extract_bps_target_literals(patch)
    report = sparse.report
    if (
        report.source_size != EXPECTED_SOURCE_SIZE
        or report.target_size != EXPECTED_TARGET_SIZE
        or report.source_crc32 != EXPECTED_SOURCE_CRC32
        or report.target_crc32 != EXPECTED_TARGET_CRC32
    ):
        raise PatchError("v5.1 BPS header/footer identity mismatch")

    _require_known(
        sparse.known,
        EXPECTED_SOURCE_SIZE,
        EXPECTED_TARGET_SIZE,
        "expanded ROM region",
    )
    trees = load_trees_at(
        sparse.data,
        sparse.known,
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )
    contexts = tuple(sorted(trees))
    if contexts != EXPECTED_CONTEXTS:
        raise PatchError(
            f"unexpected Korean Huffman contexts: expected {len(EXPECTED_CONTEXTS)}, "
            f"found {len(contexts)}"
        )

    tree_start = min(tree.symbol_offset for tree in trees.values())
    tree_end = max(
        tree.structure_offset + (tree.structure_bits + 7) // 8
        for tree in trees.values()
    )
    if (tree_start, tree_end) != (KO_TREE_DATA_START, KO_TREE_DATA_END):
        raise PatchError(
            f"unexpected Korean Huffman data span: 0x{tree_start:x}..0x{tree_end:x}"
        )

    full_font_banks: list[int] = []
    font_bank_usage: list[dict[str, int | bool]] = []
    for bank in range(FONT_DATA_FIRST_BANK, FONT_DATA_LAST_BANK + 1):
        start = bank * BANK_SIZE
        payload = sparse.data[start : start + BANK_SIZE]
        used_end = _last_non_ff(payload)
        full_shape = bank <= FULL_FONT_BANK_LAST and all(
            value == 0xFF for value in payload[0x3000:]
        )
        if full_shape:
            full_font_banks.append(bank)
        font_bank_usage.append(
            {
                "bank": bank,
                "file_offset": start,
                "last_non_ff_exclusive": start + used_end,
                "tail_after_0x3000_is_ff": all(
                    value == 0xFF for value in payload[0x3000:]
                ),
            }
        )

    _require_known(sparse.known, FONT_RUNTIME_PRIMARY[0], FONT_RUNTIME_PRIMARY[1], "primary Korean font runtime")
    _require_known(sparse.known, FONT_RUNTIME_SECONDARY[0], FONT_RUNTIME_SECONDARY[1], "secondary Korean font runtime")
    _require_known(sparse.known, FONT_PAGE_MAP[0], FONT_PAGE_MAP[1], "font page map")
    if sparse.data[0x87000:0x87007] != bytes.fromhex("c3007a03c31272"):
        raise PatchError("primary Korean runtime signature mismatch")
    if sparse.data[0x87A00:0x87A08] != bytes.fromhex("f5c5d5e5dde5fde5"):
        raise PatchError("secondary Korean runtime signature mismatch")
    _require_known(
        sparse.known,
        DECODER_PATCH_CODE[0],
        DECODER_PATCH_CODE[1],
        "patched decoder code signature",
    )
    _require_known(
        sparse.known,
        DECODER_TREE_BANK_LITERAL,
        DECODER_TREE_BANK_LITERAL + 1,
        "patched decoder tree-bank literal",
    )
    if sparse.data[slice(*DECODER_PATCH_CODE)] != bytes.fromhex(
        "21e83f197e23666f041804"
    ):
        raise PatchError("patched decoder code signature mismatch")
    if sparse.data[DECODER_TREE_BANK_LITERAL] != KO_TREE_BANK:
        raise PatchError("patched decoder tree-bank literal mismatch")

    page_map = sparse.data[slice(*FONT_PAGE_MAP)]
    return {
        "status": "verified-static",
        "patch": {
            "size": len(patch),
            "sha256": EXPECTED_PATCH_SHA256,
            "source_size": report.source_size,
            "target_size": report.target_size,
            "source_crc32": f"{report.source_crc32:08x}",
            "target_crc32": f"{report.target_crc32:08x}",
            "action_counts": list(report.action_counts),
            "known_without_source": sum(sparse.known),
            "extension_known_without_source": sum(sparse.known[EXPECTED_SOURCE_SIZE:]),
        },
        "huffman": {
            "bank": KO_TREE_BANK,
            "vector_file_offset": KO_VECTOR_OFFSET,
            "vector_logical_address": KO_VECTOR_LOGICAL,
            "vector_entries": KO_VECTOR_ENTRIES,
            "populated_trees": len(trees),
            "empty_trees": KO_VECTOR_ENTRIES - len(trees),
            "contexts": list(contexts),
            "tree_data_start": tree_start,
            "tree_data_end_exclusive": tree_end,
            "minimum_leaves": min(tree.leaf_count for tree in trees.values()),
            "maximum_leaves": max(tree.leaf_count for tree in trees.values()),
        },
        "font_runtime": {
            "primary_code_start": FONT_RUNTIME_PRIMARY[0],
            "primary_code_end_exclusive": FONT_RUNTIME_PRIMARY[1],
            "secondary_code_start": FONT_RUNTIME_SECONDARY[0],
            "secondary_code_end_exclusive": FONT_RUNTIME_SECONDARY[1],
            "page_map_start": FONT_PAGE_MAP[0],
            "page_map_end_exclusive": FONT_PAGE_MAP[1],
            "page_map_entries": len(page_map),
            "page_map_sha256": sha256_bytes(page_map),
            "font_data_first_bank": FONT_DATA_FIRST_BANK,
            "font_data_last_bank": FONT_DATA_LAST_BANK,
            "full_0x3000_payload_banks": full_font_banks,
            "bank_usage": font_bank_usage,
        },
        "decoder_anchor": {
            "status": "static-patch-anchor",
            "patched_code_start": DECODER_PATCH_CODE[0],
            "patched_code_end_exclusive": DECODER_PATCH_CODE[1],
            "tree_bank_literal_offset": DECODER_TREE_BANK_LITERAL,
            "tree_bank": sparse.data[DECODER_TREE_BANK_LITERAL],
            "execute_candidates": list(DECODER_ENTRY_CANDIDATES),
        },
        "checkpoints": {
            "korean_tree_vector": "pass",
            "korean_font_runtime": "pass",
            "script_lookup": "investigating",
            "dictionary_or_token_semantics": "investigating",
            "translation_build_eligible": False,
        },
    }


def to_markdown(result: dict[str, object]) -> str:
    patch = result["patch"]
    huffman = result["huffman"]
    font = result["font_runtime"]
    decoder = result["decoder_anchor"]
    assert (
        isinstance(patch, dict)
        and isinstance(huffman, dict)
        and isinstance(font, dict)
        and isinstance(decoder, dict)
    )
    contexts = " ".join(f"0x{value:02X}" for value in huffman["contexts"])
    return "\n".join(
        [
            "# v5.1 Korean engine static report",
            "",
            "Status: verified-static",
            "",
            "## Source-independent BPS data",
            "",
            f"- Known target bytes without the ROM: {patch['known_without_source']:,}",
            f"- Fully known extension bytes: {patch['extension_known_without_source']:,}",
            f"- Target CRC32 declared by BPS: {patch['target_crc32']}",
            "",
            "## Relocated Korean Huffman block",
            "",
            f"- Bank: 0x{huffman['bank']:02X}",
            f"- Vector: file 0x{huffman['vector_file_offset']:06X}, logical 0x{huffman['vector_logical_address']:04X}",
            f"- Trees: {huffman['populated_trees']} populated, {huffman['empty_trees']} empty",
            f"- Tree/symbol span: 0x{huffman['tree_data_start']:06X}..0x{huffman['tree_data_end_exclusive']:06X}",
            f"- Leaf range: {huffman['minimum_leaves']}..{huffman['maximum_leaves']}",
            f"- Contexts: {contexts}",
            "",
            "## Korean font runtime",
            "",
            f"- Primary code: 0x{font['primary_code_start']:06X}..0x{font['primary_code_end_exclusive']:06X}",
            f"- Secondary code: 0x{font['secondary_code_start']:06X}..0x{font['secondary_code_end_exclusive']:06X}",
            f"- Page map: 0x{font['page_map_start']:06X}..0x{font['page_map_end_exclusive']:06X} ({font['page_map_entries']} entries)",
            f"- Font data banks: 0x{font['font_data_first_bank']:02X}..0x{font['font_data_last_bank']:02X}",
            "",
            "## Patched decoder anchor",
            "",
            f"- Patched code: 0x{decoder['patched_code_start']:06X}..0x{decoder['patched_code_end_exclusive']:06X}",
            f"- Tree-bank literal: file 0x{decoder['tree_bank_literal_offset']:06X} = 0x{decoder['tree_bank']:02X}",
            "- Execute candidates: "
            + ", ".join(
                f"0x{value:04X}" for value in decoder["execute_candidates"]
            ),
            "",
            "## Guardrail",
            "",
            "The script lookup and token semantics are not yet proven. These static findings do not make any translation entry build-eligible.",
            "",
        ]
    )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--patch",
        type=Path,
        default=root / "patch" / "Final_Conflict_Japan_to_Korean_v5.1.bps",
    )
    parser.add_argument("--json", type=Path, help="optional JSON output path")
    parser.add_argument("--markdown", type=Path, help="optional Markdown output path")
    parser.add_argument("--stdout", action="store_true", help="also print JSON")
    args = parser.parse_args()

    result = analyze_patch(args.patch.read_bytes())
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote engine JSON: {args.json}")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(to_markdown(result), encoding="utf-8")
        print(f"Wrote engine report: {args.markdown}")
    if args.stdout or (not args.json and not args.markdown):
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
