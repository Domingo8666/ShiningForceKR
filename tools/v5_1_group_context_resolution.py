#!/usr/bin/env python3
"""Test whether one initial Huffman context decodes the confirmed group.

Raw context values, encoded bytes, decoded symbols, and reconstructed records
remain in an ignored phone-local report.  The published artifact contains only
aggregate counts and provenance needed to decide the next extraction step.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Callable

try:
    from .patch_io import PatchError, sha256_file
    from .sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from .v5_1_confirmed_group_extract import (
        LOCAL_REPORT_PATH as LOCAL_GROUP_PATH,
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        _bits_equal,
        validate_confirmed_group_extract,
    )
    from .v5_1_consumer import verify_target_identity
    from .v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
    from .v5_1_renderer_output_trace import DEFAULT_ROM, _load_json_object
except ImportError:  # direct script execution
    from patch_io import PatchError, sha256_file
    from sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from v5_1_confirmed_group_extract import (
        LOCAL_REPORT_PATH as LOCAL_GROUP_PATH,
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        _bits_equal,
        validate_confirmed_group_extract,
    )
    from v5_1_consumer import verify_target_identity
    from v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
    from v5_1_renderer_output_trace import DEFAULT_ROM, _load_json_object


ARTIFACT_KIND = "sanitized-v5-1-group-context-resolution"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_group_context_resolution.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_group_context_resolution.json")
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_group_extract_sha256",
    "captured_utc",
    "group",
    "context_test",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
GROUP_KEYS = {
    "selector",
    "record_count",
}
CONTEXT_TEST_KEYS = {
    "available_context_count",
    "canonical_context_exact_entry_count",
    "records_with_zero_candidates",
    "records_with_one_candidate",
    "records_with_multiple_candidates",
    "total_candidate_matches",
    "maximum_candidates_per_record",
    "best_context_exact_entry_count",
    "best_context_tie_count",
    "common_context_count",
    "resolved_entry_count",
    "remaining_unresolved_count",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _bounded_int(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def classify_context_candidates(
    records: list[dict[str, object]],
    contexts: list[int],
    try_decode: Callable[
        [dict[str, object], int],
        tuple[list[int], int] | None,
    ],
) -> tuple[dict[str, int], dict[str, object]]:
    """Aggregate exact record decodes without publishing candidate values."""

    if (
        not records
        or not contexts
        or contexts != sorted(set(contexts))
        or any(not 0 <= context <= 0xFF for context in contexts)
    ):
        raise ValueError("group context inputs are invalid")

    coverage = {context: 0 for context in contexts}
    local_records: list[dict[str, object]] = []
    zero = 0
    one = 0
    multiple = 0
    total_matches = 0
    maximum = 0
    canonical_exact = 0

    for record in records:
        matches: list[dict[str, object]] = []
        for context in contexts:
            decoded = try_decode(record, context)
            if decoded is None:
                continue
            symbols, encoded_bits = decoded
            matches.append(
                {
                    "initial_context_hex": f"0x{context:02X}",
                    "symbols_hex": [
                        f"0x{symbol:02X}" for symbol in symbols
                    ],
                    "encoded_bits": encoded_bits,
                }
            )
            coverage[context] += 1
        candidate_count = len(matches)
        zero += int(candidate_count == 0)
        one += int(candidate_count == 1)
        multiple += int(candidate_count > 1)
        total_matches += candidate_count
        maximum = max(maximum, candidate_count)
        canonical_exact += int(
            any(
                item["initial_context_hex"]
                == f"0x{CANDIDATE_END_SYMBOL:02X}"
                for item in matches
            )
        )
        local_records.append(
            {
                "entry_id": record.get("entry_id"),
                "ordinal": record.get("ordinal"),
                "candidate_count": candidate_count,
                "candidate_decodes": matches,
            }
        )

    record_count = len(records)
    best_coverage = max(coverage.values())
    best_contexts = [
        context
        for context, count in coverage.items()
        if count == best_coverage
    ]
    common_contexts = [
        context
        for context, count in coverage.items()
        if count == record_count
    ]
    fully_resolved = len(common_contexts) == 1
    resolved_records: list[dict[str, object]] = []
    if fully_resolved:
        selected_hex = f"0x{common_contexts[0]:02X}"
        by_id = {
            str(record.get("entry_id")): record
            for record in records
        }
        for result in local_records:
            match = next(
                item
                for item in result["candidate_decodes"]
                if item["initial_context_hex"] == selected_hex
            )
            source = by_id[str(result.get("entry_id"))]
            resolved_records.append(
                {
                    **source,
                    "symbols_hex": match["symbols_hex"],
                    "encoded_bits": match["encoded_bits"],
                    "roundtrip_exact": True,
                    "terminator_exact": True,
                    "classification": "resolved-common-initial-context",
                    "decode_error": None,
                }
            )

    safe_counts = {
        "available_context_count": len(contexts),
        "canonical_context_exact_entry_count": canonical_exact,
        "records_with_zero_candidates": zero,
        "records_with_one_candidate": one,
        "records_with_multiple_candidates": multiple,
        "total_candidate_matches": total_matches,
        "maximum_candidates_per_record": maximum,
        "best_context_exact_entry_count": best_coverage,
        "best_context_tie_count": len(best_contexts),
        "common_context_count": len(common_contexts),
        "resolved_entry_count": record_count if fully_resolved else 0,
        "remaining_unresolved_count": 0 if fully_resolved else record_count,
    }
    local = {
        "candidate_contexts_hex": [
            f"0x{context:02X}" for context in contexts
        ],
        "coverage_by_context": [
            {
                "initial_context_hex": f"0x{context:02X}",
                "exact_entry_count": coverage[context],
            }
            for context in contexts
        ],
        "best_contexts_hex": [
            f"0x{context:02X}" for context in best_contexts
        ],
        "common_contexts_hex": [
            f"0x{context:02X}" for context in common_contexts
        ],
        "records": local_records,
        "resolved_records": resolved_records,
    }
    return safe_counts, local


def analyze_group_contexts(
    *,
    rom: bytes,
    records: list[dict[str, object]],
) -> tuple[dict[str, int], dict[str, object]]:
    verify_target_identity(rom)
    known = bytes([1]) * len(rom)
    trees = load_trees_at(
        rom,
        known,
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )

    def try_decode(
        record: dict[str, object],
        initial_context: int,
    ) -> tuple[list[int], int] | None:
        encoded_hex = record.get("encoded_hex")
        if (
            not isinstance(encoded_hex, str)
            or re.fullmatch(r"(?:[0-9A-F]{2})+", encoded_hex) is None
        ):
            raise ValueError("group context encoded record is invalid")
        payload = bytes.fromhex(encoded_hex)
        if len(payload) != record.get("record_length_bytes"):
            raise ValueError("group context record length is inconsistent")
        try:
            symbols, encoded_bits = decode_symbols(
                payload,
                bytes([1]) * len(payload),
                trees,
                0,
                initial_symbol=initial_context,
                end_symbol=CANDIDATE_END_SYMBOL,
                max_symbols=0x1000,
                max_bytes=len(payload),
            )
            reencoded, reencoded_bits = encode_symbols(
                trees,
                symbols,
                initial_symbol=initial_context,
                end_symbol=CANDIDATE_END_SYMBOL,
                max_bits=len(payload) * 8,
            )
        except PatchError:
            return None
        if (
            encoded_bits != reencoded_bits
            or not _bits_equal(payload, reencoded, encoded_bits)
            or symbols.count(CANDIDATE_END_SYMBOL) != 1
        ):
            return None
        return symbols, encoded_bits

    return classify_context_candidates(
        records,
        sorted(trees),
        try_decode,
    )


def build_group_context_resolution(
    *,
    target_sha256: str,
    source_group_extract_sha256: str,
    selector: int,
    record_count: int,
    context_test: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    common = int(context_test["common_context_count"])
    best = int(context_test["best_context_exact_entry_count"])
    if common == 1:
        status = "group-initial-context-unique"
        checkpoint = "map-confirmed-group-glyphs-to-unicode"
    elif common > 1:
        status = "group-initial-context-ambiguous"
        checkpoint = "trace-group-initial-context-at-runtime"
    elif best > int(context_test["canonical_context_exact_entry_count"]):
        status = "group-context-partially-narrows"
        checkpoint = "classify-confirmed-group-record-variants"
    else:
        status = "group-context-hypothesis-rejected"
        checkpoint = "classify-confirmed-group-record-variants"
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": target_sha256,
        "source_group_extract_sha256": source_group_extract_sha256,
        "captured_utc": captured_utc,
        "group": {
            "selector": selector,
            "record_count": record_count,
        },
        "context_test": {
            key: int(context_test[key])
            for key in CONTEXT_TEST_KEYS
        },
        "local_payload_policy": (
            "contexts-encoded-bytes-symbols-codepoints-and-text-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": checkpoint,
    }
    validate_group_context_resolution(safe)
    return safe


def validate_group_context_resolution(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("group context resolution fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "group-initial-context-unique",
            "group-initial-context-ambiguous",
            "group-context-partially-narrows",
            "group-context-hypothesis-rejected",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_group_extract_sha256"])
    ):
        raise ValueError("group context resolution policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("group context timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("group context timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("group context timestamp must include UTC")

    group = value["group"]
    if not isinstance(group, dict) or set(group) != GROUP_KEYS:
        raise ValueError("group context group fields do not match")
    if (
        not _bounded_int(group["selector"], 0, 0xFFFF)
        or not _bounded_int(group["record_count"], 1, 0xFF)
    ):
        raise ValueError("group context group is invalid")
    counts = value["context_test"]
    if not isinstance(counts, dict) or set(counts) != CONTEXT_TEST_KEYS:
        raise ValueError("group context count fields do not match")
    record_count = int(group["record_count"])
    available = counts["available_context_count"]
    if not _bounded_int(available, 1, 0x100):
        raise ValueError("group context available count is invalid")
    for key in CONTEXT_TEST_KEYS - {"available_context_count"}:
        if not _bounded_int(counts[key], 0, 0x1000000):
            raise ValueError(f"group context {key} is invalid")
    if (
        counts["records_with_zero_candidates"]
        + counts["records_with_one_candidate"]
        + counts["records_with_multiple_candidates"]
        != record_count
        or counts["canonical_context_exact_entry_count"] > record_count
        or counts["best_context_exact_entry_count"] > record_count
        or counts["best_context_tie_count"] > available
        or counts["common_context_count"] > available
        or counts["maximum_candidates_per_record"] > available
    ):
        raise ValueError("group context aggregate counts are inconsistent")
    common = int(counts["common_context_count"])
    best = int(counts["best_context_exact_entry_count"])
    canonical = int(counts["canonical_context_exact_entry_count"])
    expected_status = (
        "group-initial-context-unique"
        if common == 1
        else "group-initial-context-ambiguous"
        if common > 1
        else "group-context-partially-narrows"
        if best > canonical
        else "group-context-hypothesis-rejected"
    )
    expected_checkpoint = (
        "map-confirmed-group-glyphs-to-unicode"
        if common == 1
        else "trace-group-initial-context-at-runtime"
        if common > 1
        else "classify-confirmed-group-record-variants"
    )
    expected_resolved = record_count if common == 1 else 0
    if (
        value["status"] != expected_status
        or value["next_checkpoint"] != expected_checkpoint
        or counts["resolved_entry_count"] != expected_resolved
        or counts["remaining_unresolved_count"]
        != record_count - expected_resolved
    ):
        raise ValueError("group context result is inconsistent")
    if value["local_payload_policy"] != (
        "contexts-encoded-bytes-symbols-codepoints-and-text-local-only"
    ):
        raise ValueError("group context local policy is invalid")
    if value["translation_build_eligible"] is not False:
        raise ValueError("group context cannot enable release builds")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    safe_group_path = root / GROUP_EXTRACT_PATH
    local_group_path = root / LOCAL_GROUP_PATH
    prerequisites = (rom_path, safe_group_path, local_group_path)
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Group context resolution is not ready")
            return 0
        raise SystemExit("group context resolution input is missing")

    safe_group = _load_json_object(safe_group_path)
    validate_confirmed_group_extract(safe_group)
    if safe_group["status"] == "confirmed-group-roundtrip-pass":
        if args.if_ready:
            print("Group context resolution is not required")
            return 0
        raise SystemExit("confirmed group has no unresolved records")
    if safe_group["status"] != (
        "confirmed-group-population-enumerated-with-unresolved"
    ):
        if args.if_ready:
            print("Group context resolution waits for group enumeration")
            return 0
        raise SystemExit("confirmed group population is incomplete")

    local_group = _load_json_object(local_group_path)
    target_sha256 = sha256_file(rom_path)
    if (
        target_sha256 != safe_group["target_sha256"]
        or local_group.get("target_sha256") != target_sha256
    ):
        raise ValueError("group context target identities disagree")
    records = local_group.get("records")
    if not isinstance(records, list):
        raise ValueError("group context local records are missing")
    counts, local_analysis = analyze_group_contexts(
        rom=rom_path.read_bytes(),
        records=records,
    )
    group = safe_group["group"]
    assert isinstance(group, dict)
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_group_context_resolution(
        target_sha256=target_sha256,
        source_group_extract_sha256=sha256_file(safe_group_path),
        selector=int(group["selector"]),
        record_count=int(group["declared_entry_count"]),
        context_test=counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-group-context-resolution",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "captured_utc": captured_utc,
        "source_group_extract_sha256": sha256_file(safe_group_path),
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-contexts-encoded-bytes-symbols-codepoints-or-text"
        ),
    }
    safe_path = root / PUBLISH_RELATIVE_PATH
    local_path = root / LOCAL_REPORT_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR group context resolution: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
