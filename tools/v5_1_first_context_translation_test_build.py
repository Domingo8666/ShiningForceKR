#!/usr/bin/env python3
"""Build and statically verify the approved first-context translation ROM."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

try:
    from .expected_writes import (
        ExpectedWrite,
        apply_expected_writes,
        expected_writes_to_ips,
    )
    from .patch_io import PatchError, parse_ips, sha256_bytes, sha256_file
    from .sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        load_trees_at,
    )
    from .v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
    from .v5_1_confirmed_group_extract import (
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        validate_confirmed_group_extract,
    )
    from .v5_1_first_context_record_reinsertion import (
        LOCAL_REPORT_PATH as LOCAL_REINSERTION_PATH,
        PUBLISH_RELATIVE_PATH as REINSERTION_PATH,
        TARGET_PATH,
        validate_first_context_record_reinsertion,
    )
    from .v5_1_first_context_translation_encoding import (
        LOCAL_COMBINED_FONT_OVERLAY_PATH,
        LOCAL_REPORT_PATH as LOCAL_ENCODING_PATH,
    )
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_test_phrase import FONT_TILE_BYTES, font_tile_offset
except ImportError:  # pragma: no cover - direct script execution
    from expected_writes import (
        ExpectedWrite,
        apply_expected_writes,
        expected_writes_to_ips,
    )
    from patch_io import PatchError, parse_ips, sha256_bytes, sha256_file
    from sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        load_trees_at,
    )
    from v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
    from v5_1_confirmed_group_extract import (
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        validate_confirmed_group_extract,
    )
    from v5_1_first_context_record_reinsertion import (
        LOCAL_REPORT_PATH as LOCAL_REINSERTION_PATH,
        PUBLISH_RELATIVE_PATH as REINSERTION_PATH,
        TARGET_PATH,
        validate_first_context_record_reinsertion,
    )
    from v5_1_first_context_translation_encoding import (
        LOCAL_COMBINED_FONT_OVERLAY_PATH,
        LOCAL_REPORT_PATH as LOCAL_ENCODING_PATH,
    )
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_test_phrase import FONT_TILE_BYTES, font_tile_offset


ARTIFACT_KIND = "sanitized-v5-1-first-context-translation-test-build"
LOCAL_ARTIFACT_KIND = "local-v5-1-first-context-translation-test-build"
SCHEMA_VERSION = 3
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_translation_test_build.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_first_context_translation_test_build.json"
)
TEST_ROM_PATH = Path(
    "build/Final_Conflict_Korean_first_context_translation_test.gg"
)
TEST_OVERLAY_PATH = Path(
    "build/Final_Conflict_Korean_first_context_translation_test.ips"
)
COUNT_KEYS = {
    "context_entry_count",
    "record_write_count",
    "font_write_count",
    "write_count",
    "changed_byte_count",
    "record_length_field_verified_count",
    "record_length_changed_count",
    "decoded_roundtrip_entry_count",
    "decoded_failure_entry_count",
    "record_suffix_preserved_entry_count",
    "font_glyph_assignment_count",
    "font_glyph_verified_count",
    "encoded_length_exact_count",
}
SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "baseline_target_sha256",
    "test_target_sha256",
    "test_overlay_sha256",
    "first_context_record_reinsertion_sha256",
    "local_build_sha256",
    "captured_utc",
    "verification",
    "expected_write_audit_complete",
    "record_length_fields_verified",
    "huffman_roundtrip_complete",
    "font_tiles_verified",
    "static_translation_build_confirmed",
    "runtime_layout_confirmed",
    "source_and_target_text_local_only",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return timestamp.utcoffset() == timezone.utc.utcoffset(timestamp)


def build_translation_writes(
    *,
    target: bytes,
    font_overlay: bytes,
    reinsertion_rows: list[dict[str, object]],
    group_selector: int,
    group_physical_start: int,
    declared_group_entry_count: int,
) -> tuple[list[ExpectedWrite], int, int]:
    parsed = parse_ips(font_overlay)
    if parsed.final_size is not None:
        raise ValueError("first context font overlay changes image size")
    writes = []
    for index, record in enumerate(parsed.records):
        start = record.offset
        end = start + len(record.data)
        if not 0 <= start < end <= len(target):
            raise ValueError("first context font overlay range is invalid")
        before = target[start:end]
        if before == record.data:
            continue
        writes.append(
            ExpectedWrite(
                writer=f"first-context-font-{index:03d}",
                purpose="first-context-static-translation-build",
                offset=start,
                before=before,
                after=record.data,
                allowed_start=start,
                allowed_end_exclusive=end,
            )
        )
    font_write_count = len(writes)
    if (
        not isinstance(group_selector, int)
        or isinstance(group_selector, bool)
        or not isinstance(group_physical_start, int)
        or isinstance(group_physical_start, bool)
        or not 0 <= group_physical_start < len(target)
        or not isinstance(declared_group_entry_count, int)
        or isinstance(declared_group_entry_count, bool)
        or not 1 <= declared_group_entry_count <= 0xFF
    ):
        raise ValueError("first context group identity is invalid")
    record_write_count = 0
    seen_payload_ranges = set()
    ordered_rows = sorted(
        reinsertion_rows,
        key=lambda item: int(item["length_offset"]),
    )
    for row in ordered_rows:
        alias_keys = row.get("alias_keys")
        length_offset = row.get("length_offset")
        start = row.get("payload_start")
        end = row.get("payload_end")
        encoded_hex = row.get("encoded_payload_hex")
        encoded_bits = row.get("encoded_payload_bits")
        fits = row.get("fits_in_place")
        if (
            not isinstance(alias_keys, list)
            or not isinstance(length_offset, int)
            or isinstance(length_offset, bool)
            or not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or not isinstance(encoded_hex, str)
            or not isinstance(encoded_bits, int)
            or isinstance(encoded_bits, bool)
            or fits is not True
            or not 0 <= length_offset < start < end <= len(target)
            or start != length_offset + 1
        ):
            raise ValueError("first context record write row is invalid")
        encoded = bytes.fromhex(encoded_hex)
        if (
            not 1 <= encoded_bits <= (end - start) * 8
            or len(encoded) != (encoded_bits + 7) // 8
        ):
            raise ValueError("first context record write bit length is invalid")
        payload_range = (start, end)
        if payload_range in seen_payload_ranges:
            raise ValueError("first context record write is duplicated")
        seen_payload_ranges.add(payload_range)
        write_end = start + len(encoded)
        before = target[start:write_end]
        after = bytearray(before)
        for bit_index in range(encoded_bits):
            value = (
                encoded[bit_index >> 3] >> (7 - (bit_index & 7))
            ) & 1
            byte_index = bit_index >> 3
            mask = 1 << (7 - (bit_index & 7))
            if value:
                after[byte_index] |= mask
            else:
                after[byte_index] &= ~mask
        if before == bytes(after):
            raise ValueError("first context record write changes no bytes")
        writes.append(
            ExpectedWrite(
                writer=f"first-context-record-{int(row['review_index']):03d}",
                purpose="first-context-static-translation-build",
                offset=start,
                before=before,
                after=bytes(after),
                allowed_start=start,
                allowed_end_exclusive=end,
            )
        )
        record_write_count += 1
    if record_write_count == 0:
        raise ValueError("first context record rows are missing")
    return writes, font_write_count, record_write_count


def verify_translation_build(
    *,
    baseline: bytes,
    test: bytes,
    reinsertion_rows: list[dict[str, object]],
    encoding_rows: list[dict[str, object]],
    font_assignments: list[dict[str, object]],
    group_selector: int,
    group_physical_start: int,
    declared_group_entry_count: int,
) -> dict[str, int]:
    if len(reinsertion_rows) != len(encoding_rows):
        raise ValueError("first context build verification row count disagrees")
    known = bytes((1,)) * len(test)
    trees = load_trees_at(
        baseline,
        bytes((1,)) * len(baseline),
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )
    roundtrips = 0
    failures = 0
    length_fields_verified = 0
    length_fields_changed = 0
    encoded_lengths_exact = 0
    suffixes_preserved = 0
    for reinsertion, encoding in zip(reinsertion_rows, encoding_rows):
        length_offset = int(reinsertion["length_offset"])
        payload_start = int(reinsertion["payload_start"])
        original_length = int(reinsertion["original_length_bytes"])
        expected_symbols = encoding.get("symbols")
        expected_bits = encoding.get("encoded_bits")
        expected_bytes = encoding.get("encoded_bytes")
        target_bits = encoding.get("target_encoded_bits")
        initial_context = encoding.get("initial_context")
        if not isinstance(expected_symbols, list) or not isinstance(
            expected_bits,
            int,
        ) or not isinstance(expected_bytes, int) or isinstance(
            expected_bytes,
            bool,
        ) or not isinstance(
            target_bits,
            int,
        ) or not isinstance(
            initial_context,
            int,
        ):
            raise ValueError("first context build expected symbols are missing")
        encoded_lengths_exact += int(expected_bits == target_bits)
        length_fields_verified += int(
            baseline[length_offset] == original_length
            and test[length_offset] == original_length
            and expected_bytes == int(reinsertion["encoded_payload_bytes"])
            and expected_bytes == (expected_bits + 7) // 8
            and expected_bits <= original_length * 8
        )
        length_fields_changed += int(
            test[length_offset] != baseline[length_offset]
        )
        try:
            decoded, decoded_bits = decode_symbols(
                test,
                known,
                trees,
                payload_start,
                initial_symbol=initial_context,
                end_symbol=CANDIDATE_END_SYMBOL,
                max_symbols=len(expected_symbols),
                max_bytes=original_length,
            )
        except PatchError:
            failures += 1
            continue
        if decoded == expected_symbols and decoded_bits == expected_bits:
            roundtrips += 1
        else:
            failures += 1
        suffixes_preserved += int(
            all(
                (
                    (baseline[payload_start + (bit_index >> 3)]
                     >> (7 - (bit_index & 7)))
                    & 1
                )
                == (
                    (test[payload_start + (bit_index >> 3)]
                     >> (7 - (bit_index & 7)))
                    & 1
                )
                for bit_index in range(expected_bits, original_length * 8)
            )
        )
    verified_glyphs = 0
    for assignment in font_assignments:
        page = assignment.get("page")
        symbol = assignment.get("symbol")
        tile_sha256 = assignment.get("tile_sha256")
        if (
            not isinstance(page, int)
            or not isinstance(symbol, int)
            or not _is_sha256(tile_sha256)
        ):
            raise ValueError("first context build font assignment is invalid")
        start = font_tile_offset(page, symbol)
        end = start + FONT_TILE_BYTES
        verified_glyphs += int(
            sha256_bytes(test[start:end]) == tile_sha256
        )
    return {
        "context_entry_count": len(encoding_rows),
        "record_length_field_verified_count": length_fields_verified,
        "record_length_changed_count": length_fields_changed,
        "decoded_roundtrip_entry_count": roundtrips,
        "decoded_failure_entry_count": failures,
        "record_suffix_preserved_entry_count": suffixes_preserved,
        "font_glyph_assignment_count": len(font_assignments),
        "font_glyph_verified_count": verified_glyphs,
        "encoded_length_exact_count": encoded_lengths_exact,
    }


def build_first_context_translation_test_build(
    *,
    baseline_target_sha256: str,
    test_target_sha256: str,
    test_overlay_sha256: str,
    first_context_record_reinsertion_sha256: str,
    local_build_sha256: str,
    verification: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    complete = (
        verification["context_entry_count"] >= 4
        and verification["record_write_count"]
        == verification["context_entry_count"]
        and verification["record_length_field_verified_count"]
        == verification["context_entry_count"]
        and verification["record_length_changed_count"] == 0
        and verification["decoded_roundtrip_entry_count"]
        == verification["context_entry_count"]
        and verification["decoded_failure_entry_count"] == 0
        and verification["record_suffix_preserved_entry_count"]
        == verification["context_entry_count"]
        and verification["font_glyph_assignment_count"] > 0
        and verification["font_glyph_verified_count"]
        == verification["font_glyph_assignment_count"]
        and verification["changed_byte_count"] > 0
    )
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "first-context-translation-static-build-ready"
            if complete
            else "first-context-translation-static-build-incomplete"
        ),
        "baseline_target_sha256": baseline_target_sha256,
        "test_target_sha256": test_target_sha256,
        "test_overlay_sha256": test_overlay_sha256,
        "first_context_record_reinsertion_sha256":
            first_context_record_reinsertion_sha256,
        "local_build_sha256": local_build_sha256,
        "captured_utc": captured_utc,
        "verification": verification,
        "expected_write_audit_complete": complete,
        "record_length_fields_verified": complete,
        "huffman_roundtrip_complete": complete,
        "font_tiles_verified": complete,
        "static_translation_build_confirmed": complete,
        "runtime_layout_confirmed": False,
        "source_and_target_text_local_only": True,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "capture-first-context-translation-runtime-screen"
            if complete
            else "repair-first-context-translation-static-build"
        ),
    }
    validate_first_context_translation_test_build(value)
    return value


def validate_first_context_translation_test_build(
    value: dict[str, object],
) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError("first context translation build fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "first-context-translation-static-build-ready",
            "first-context-translation-static-build-incomplete",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "baseline_target_sha256",
                "test_target_sha256",
                "test_overlay_sha256",
                "first_context_record_reinsertion_sha256",
                "local_build_sha256",
            )
        )
        or not _is_utc_timestamp(value["captured_utc"])
    ):
        raise ValueError("first context translation build identity is invalid")
    verification = value["verification"]
    if not isinstance(verification, dict) or set(verification) != COUNT_KEYS:
        raise ValueError("first context translation build counts do not match")
    if any(
        not isinstance(count, int)
        or isinstance(count, bool)
        or count < 0
        or count > 10000000
        for count in verification.values()
    ):
        raise ValueError("first context translation build count is invalid")
    complete = (
        verification["context_entry_count"] >= 4
        and verification["record_write_count"]
        == verification["context_entry_count"]
        and verification["record_length_field_verified_count"]
        == verification["context_entry_count"]
        and verification["record_length_changed_count"] == 0
        and verification["decoded_roundtrip_entry_count"]
        == verification["context_entry_count"]
        and verification["decoded_failure_entry_count"] == 0
        and verification["record_suffix_preserved_entry_count"]
        == verification["context_entry_count"]
        and verification["font_glyph_assignment_count"] > 0
        and verification["font_glyph_verified_count"]
        == verification["font_glyph_assignment_count"]
        and verification["changed_byte_count"] > 0
    )
    if (
        value["status"]
        != (
            "first-context-translation-static-build-ready"
            if complete
            else "first-context-translation-static-build-incomplete"
        )
        or value["expected_write_audit_complete"] is not complete
        or value["record_length_fields_verified"] is not complete
        or value["huffman_roundtrip_complete"] is not complete
        or value["font_tiles_verified"] is not complete
        or value["static_translation_build_confirmed"] is not complete
        or value["runtime_layout_confirmed"] is not False
        or value["source_and_target_text_local_only"] is not True
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != (
            "capture-first-context-translation-runtime-screen"
            if complete
            else "repair-first-context-translation-static-build"
        )
    ):
        raise ValueError("first context translation build is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = {
        "target": root / TARGET_PATH,
        "group_extract": root / GROUP_EXTRACT_PATH,
        "reinsertion": root / REINSERTION_PATH,
        "local_reinsertion": root / LOCAL_REINSERTION_PATH,
        "local_encoding": root / LOCAL_ENCODING_PATH,
        "font_overlay": root / LOCAL_COMBINED_FONT_OVERLAY_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print("First context translation test build is not ready")
            return 0
        raise SystemExit("first context translation build input is missing")
    baseline = paths["target"].read_bytes()
    group_extract = _load_json_object(paths["group_extract"])
    validate_confirmed_group_extract(group_extract)
    reinsertion = _load_json_object(paths["reinsertion"])
    local_reinsertion = _load_json_object(paths["local_reinsertion"])
    local_encoding = _load_json_object(paths["local_encoding"])
    validate_first_context_record_reinsertion(reinsertion)
    if (
        group_extract["target_sha256"] != sha256_bytes(baseline)
        or reinsertion["status"]
        != "first-context-record-reinsertion-plan-ready"
        or reinsertion["target_sha256"] != sha256_bytes(baseline)
        or local_reinsertion.get("target_sha256")
        != reinsertion["target_sha256"]
        or local_encoding.get("target_sha256") != reinsertion["target_sha256"]
    ):
        if args.if_ready:
            print("First context translation test build plan is blocked")
            return 0
        raise SystemExit("first context translation build plan is blocked")
    reinsertion_rows = local_reinsertion.get("rows")
    encoding_rows = local_encoding.get("rows")
    font_assignments = local_encoding.get("character_assignments")
    if not all(
        isinstance(value, list)
        for value in (reinsertion_rows, encoding_rows, font_assignments)
    ):
        raise ValueError("first context translation build rows are missing")
    assert isinstance(reinsertion_rows, list)
    assert isinstance(encoding_rows, list)
    assert isinstance(font_assignments, list)
    writes, font_write_count, record_write_count = build_translation_writes(
        target=baseline,
        font_overlay=paths["font_overlay"].read_bytes(),
        reinsertion_rows=reinsertion_rows,
        group_selector=int(group_extract["group"]["selector"]),
        group_physical_start=int(group_extract["group"]["physical_start"]),
        declared_group_entry_count=int(
            group_extract["group"]["declared_entry_count"]
        ),
    )
    test, audit = apply_expected_writes(baseline, writes)
    overlay = expected_writes_to_ips(writes)
    verification = verify_translation_build(
        baseline=baseline,
        test=test,
        reinsertion_rows=reinsertion_rows,
        encoding_rows=encoding_rows,
        font_assignments=font_assignments,
        group_selector=int(group_extract["group"]["selector"]),
        group_physical_start=int(group_extract["group"]["physical_start"]),
        declared_group_entry_count=int(
            group_extract["group"]["declared_entry_count"]
        ),
    )
    verification.update(
        {
            "record_write_count": record_write_count,
            "font_write_count": font_write_count,
            "write_count": len(writes),
            "changed_byte_count": int(audit["changed_byte_count"]),
        }
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    test_path = root / TEST_ROM_PATH
    overlay_path = root / TEST_OVERLAY_PATH
    test_path.parent.mkdir(parents=True, exist_ok=True)
    test_path.write_bytes(test)
    overlay_path.write_bytes(overlay)
    local = {
        "artifact_kind": LOCAL_ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "baseline_target_sha256": sha256_bytes(baseline),
        "test_target_sha256": sha256_bytes(test),
        "test_overlay_sha256": sha256_bytes(overlay),
        "captured_utc": captured_utc,
        "verification": verification,
        "write_audit": audit,
        "publication_policy": (
            "never-publish-rom-overlay-record-offsets-symbols-or-text"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_first_context_translation_test_build(
        baseline_target_sha256=sha256_bytes(baseline),
        test_target_sha256=sha256_bytes(test),
        test_overlay_sha256=sha256_bytes(overlay),
        first_context_record_reinsertion_sha256=sha256_file(
            paths["reinsertion"]
        ),
        local_build_sha256=sha256_file(local_path),
        verification=verification,
        captured_utc=captured_utc,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR first context translation test build: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
