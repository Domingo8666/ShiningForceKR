#!/usr/bin/env python3
"""Plan an in-place reinsertion for the approved first-context translation."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

try:
    from .patch_io import sha256_bytes, sha256_file
    from .v5_1_first_context_translation_encoding import (
        LOCAL_REPORT_PATH as LOCAL_ENCODING_PATH,
        PUBLISH_RELATIVE_PATH as ENCODING_PATH,
        validate_first_context_translation_encoding,
    )
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_source_target_runtime_context import (
        LOCAL_REPORT_PATH as LOCAL_CONTEXT_PATH,
    )
    from .v5_1_source_target_section_projection import (
        LOCAL_REPORT_PATH as LOCAL_PROJECTION_PATH,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_bytes, sha256_file
    from v5_1_first_context_translation_encoding import (
        LOCAL_REPORT_PATH as LOCAL_ENCODING_PATH,
        PUBLISH_RELATIVE_PATH as ENCODING_PATH,
        validate_first_context_translation_encoding,
    )
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_source_target_runtime_context import (
        LOCAL_REPORT_PATH as LOCAL_CONTEXT_PATH,
    )
    from v5_1_source_target_section_projection import (
        LOCAL_REPORT_PATH as LOCAL_PROJECTION_PATH,
    )


ARTIFACT_KIND = "sanitized-v5-1-first-context-record-reinsertion"
LOCAL_ARTIFACT_KIND = "local-v5-1-first-context-record-reinsertion"
SCHEMA_VERSION = 1
TARGET_PATH = Path("build/Final_Conflict_Korean_v5.1.gg")
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_record_reinsertion.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_first_context_record_reinsertion.json"
)
COUNT_KEYS = {
    "context_entry_count",
    "distinct_target_record_count",
    "in_place_fit_entry_count",
    "overflow_entry_count",
    "shared_alias_entry_count",
    "logical_alias_reference_count",
    "duplicate_alias_reference_count",
    "malformed_alias_entry_count",
    "selected_alias_missing_entry_count",
    "original_payload_byte_count",
    "encoded_payload_byte_count",
    "available_payload_bit_count",
    "encoded_payload_bit_count",
    "total_slack_byte_count",
    "minimum_slack_byte_count",
    "maximum_slack_byte_count",
    "exact_encoded_length_entry_count",
    "original_encoded_bit_count",
}
SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "review_batch_sha256",
    "first_context_translation_encoding_sha256",
    "local_reinsertion_sha256",
    "captured_utc",
    "capacity",
    "target_records_distinct",
    "in_place_storage_confirmed",
    "shared_alias_impact_clear",
    "record_storage_capacity_confirmed",
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


def build_reinsertion_rows(
    *,
    target: bytes,
    context_rows: list[dict[str, object]],
    projection_pairs: list[dict[str, object]],
    encoding_rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    if not (
        len(context_rows) == len(encoding_rows)
        and len(context_rows) >= 4
    ):
        raise ValueError("first context reinsertion row count disagrees")
    pair_index = {}
    for pair in projection_pairs:
        if not isinstance(pair, dict):
            raise ValueError("first context reinsertion projection is invalid")
        key = (pair.get("source_section_index"), pair.get("source_line_index"))
        if key in pair_index:
            raise ValueError("first context reinsertion projection is duplicated")
        pair_index[key] = pair
    rows = []
    for expected_index, (context_row, encoding_row) in enumerate(
        zip(context_rows, encoding_rows),
        start=1,
    ):
        if (
            not isinstance(context_row, dict)
            or context_row.get("mapping_status") != "unique"
            or not isinstance(encoding_row, dict)
            or encoding_row.get("review_index") != expected_index
        ):
            raise ValueError("first context reinsertion context row is invalid")
        key = (
            context_row.get("source_section_index"),
            context_row.get("source_line_index"),
        )
        pair = pair_index.get(key)
        target_record = None if pair is None else pair.get("target_record")
        if not isinstance(target_record, dict):
            raise ValueError("first context reinsertion target record is missing")
        length_offset = target_record.get("length_offset")
        original_length = target_record.get("record_length_bytes")
        aliases = target_record.get("aliases")
        target_selector = pair.get("target_selector")
        target_ordinal = pair.get("target_ordinal")
        encoded_hex = encoding_row.get("encoded_hex")
        encoded_bits = encoding_row.get("encoded_bits")
        encoded_bytes = encoding_row.get("encoded_bytes")
        original_encoded_bits = encoding_row.get("target_encoded_bits")
        if (
            not isinstance(length_offset, int)
            or isinstance(length_offset, bool)
            or not isinstance(original_length, int)
            or isinstance(original_length, bool)
            or not isinstance(aliases, list)
            or not isinstance(target_selector, int)
            or isinstance(target_selector, bool)
            or not isinstance(target_ordinal, int)
            or isinstance(target_ordinal, bool)
            or not isinstance(encoded_hex, str)
            or not isinstance(encoded_bits, int)
            or isinstance(encoded_bits, bool)
            or not isinstance(encoded_bytes, int)
            or isinstance(encoded_bytes, bool)
            or not isinstance(original_encoded_bits, int)
            or isinstance(original_encoded_bits, bool)
        ):
            raise ValueError("first context reinsertion record fields are invalid")
        alias_keys = []
        aliases_well_formed = True
        for alias in aliases:
            if not isinstance(alias, dict):
                aliases_well_formed = False
                continue
            selector = alias.get("selector")
            ordinal = alias.get("ordinal")
            if (
                not isinstance(selector, int)
                or isinstance(selector, bool)
                or not isinstance(ordinal, int)
                or isinstance(ordinal, bool)
            ):
                aliases_well_formed = False
                continue
            alias_keys.append((selector, ordinal))
        selected_alias_present = (
            target_selector,
            target_ordinal,
        ) in alias_keys
        payload = bytes.fromhex(encoded_hex)
        payload_start = length_offset + 1
        payload_end = payload_start + original_length
        if (
            not 0 <= length_offset < len(target)
            or target[length_offset] != original_length
            or not 0 <= payload_start <= payload_end <= len(target)
            or len(payload) != encoded_bytes
            or not 1 <= encoded_bits <= encoded_bytes * 8
            or encoded_bits != original_encoded_bits
        ):
            raise ValueError("first context reinsertion record bounds disagree")
        rows.append(
            {
                "review_index": expected_index,
                "length_offset": length_offset,
                "payload_start": payload_start,
                "payload_end": payload_end,
                "original_length_bytes": original_length,
                "encoded_payload_hex": encoded_hex,
                "encoded_payload_bytes": encoded_bytes,
                "encoded_payload_bits": encoded_bits,
                "original_encoded_bits": original_encoded_bits,
                "encoded_length_exact": encoded_bits == original_encoded_bits,
                "slack_bytes": original_length - encoded_bytes,
                "fits_in_place": encoded_bytes <= original_length,
                "alias_count": len(aliases),
                "alias_keys": alias_keys,
                "aliases_well_formed": aliases_well_formed,
                "selected_alias_present": selected_alias_present,
                "original_payload_sha256": sha256_bytes(
                    target[payload_start:payload_end]
                ),
                "encoded_payload_sha256": sha256_bytes(payload),
            }
        )
    return rows


def summarize_reinsertion_rows(
    rows: list[dict[str, object]],
) -> dict[str, int]:
    if not rows:
        raise ValueError("first context reinsertion rows are missing")
    slacks = [int(row["slack_bytes"]) for row in rows]
    alias_keys = [
        alias_key
        for row in rows
        for alias_key in row["alias_keys"]
    ]
    return {
        "context_entry_count": len(rows),
        "distinct_target_record_count": len(
            {int(row["length_offset"]) for row in rows}
        ),
        "in_place_fit_entry_count": sum(
            bool(row["fits_in_place"]) for row in rows
        ),
        "overflow_entry_count": sum(
            not bool(row["fits_in_place"]) for row in rows
        ),
        "shared_alias_entry_count": sum(
            int(row["alias_count"]) > 1 for row in rows
        ),
        "logical_alias_reference_count": len(alias_keys),
        "duplicate_alias_reference_count": (
            len(alias_keys) - len(set(alias_keys))
        ),
        "malformed_alias_entry_count": sum(
            not bool(row["aliases_well_formed"]) for row in rows
        ),
        "selected_alias_missing_entry_count": sum(
            not bool(row["selected_alias_present"]) for row in rows
        ),
        "original_payload_byte_count": sum(
            int(row["original_length_bytes"]) for row in rows
        ),
        "encoded_payload_byte_count": sum(
            int(row["encoded_payload_bytes"]) for row in rows
        ),
        "available_payload_bit_count": sum(
            int(row["original_length_bytes"]) * 8 for row in rows
        ),
        "encoded_payload_bit_count": sum(
            int(row["encoded_payload_bits"]) for row in rows
        ),
        "total_slack_byte_count": sum(slacks),
        "minimum_slack_byte_count": min(slacks),
        "maximum_slack_byte_count": max(slacks),
        "exact_encoded_length_entry_count": sum(
            bool(row["encoded_length_exact"]) for row in rows
        ),
        "original_encoded_bit_count": sum(
            int(row["original_encoded_bits"]) for row in rows
        ),
    }


def build_first_context_record_reinsertion(
    *,
    target_sha256: str,
    review_batch_sha256: str,
    first_context_translation_encoding_sha256: str,
    local_reinsertion_sha256: str,
    capacity: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    distinct = (
        capacity["distinct_target_record_count"]
        == capacity["context_entry_count"]
    )
    fits = (
        capacity["in_place_fit_entry_count"]
        == capacity["context_entry_count"]
        and capacity["overflow_entry_count"] == 0
    )
    aliases_clear = (
        capacity["logical_alias_reference_count"]
        >= capacity["context_entry_count"]
        and capacity["duplicate_alias_reference_count"] == 0
        and capacity["malformed_alias_entry_count"] == 0
        and capacity["selected_alias_missing_entry_count"] == 0
    )
    ready = (
        capacity["context_entry_count"] >= 4
        and distinct
        and fits
        and aliases_clear
        and capacity["exact_encoded_length_entry_count"]
        == capacity["context_entry_count"]
        and capacity["original_encoded_bit_count"]
        == capacity["encoded_payload_bit_count"]
    )
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "first-context-record-reinsertion-plan-ready"
            if ready
            else "first-context-record-reinsertion-plan-blocked"
        ),
        "target_sha256": target_sha256,
        "review_batch_sha256": review_batch_sha256,
        "first_context_translation_encoding_sha256":
            first_context_translation_encoding_sha256,
        "local_reinsertion_sha256": local_reinsertion_sha256,
        "captured_utc": captured_utc,
        "capacity": capacity,
        "target_records_distinct": distinct,
        "in_place_storage_confirmed": fits,
        "shared_alias_impact_clear": aliases_clear,
        "record_storage_capacity_confirmed": ready,
        "runtime_layout_confirmed": False,
        "source_and_target_text_local_only": True,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "build-first-context-in-place-test-patch"
            if ready
            else "repair-first-context-record-reinsertion-plan"
        ),
    }
    validate_first_context_record_reinsertion(value)
    return value


def validate_first_context_record_reinsertion(
    value: dict[str, object],
) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError("first context reinsertion fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "first-context-record-reinsertion-plan-ready",
            "first-context-record-reinsertion-plan-blocked",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "review_batch_sha256",
                "first_context_translation_encoding_sha256",
                "local_reinsertion_sha256",
            )
        )
        or not _is_utc_timestamp(value["captured_utc"])
    ):
        raise ValueError("first context reinsertion identity is invalid")
    capacity = value["capacity"]
    if not isinstance(capacity, dict) or set(capacity) != COUNT_KEYS:
        raise ValueError("first context reinsertion counts do not match")
    if any(
        not isinstance(count, int)
        or isinstance(count, bool)
        or not -10000000 <= count <= 10000000
        for count in capacity.values()
    ):
        raise ValueError("first context reinsertion count is invalid")
    distinct = (
        capacity["distinct_target_record_count"]
        == capacity["context_entry_count"]
    )
    fits = (
        capacity["in_place_fit_entry_count"]
        == capacity["context_entry_count"]
        and capacity["overflow_entry_count"] == 0
    )
    aliases_clear = (
        capacity["logical_alias_reference_count"]
        >= capacity["context_entry_count"]
        and capacity["duplicate_alias_reference_count"] == 0
        and capacity["malformed_alias_entry_count"] == 0
        and capacity["selected_alias_missing_entry_count"] == 0
    )
    ready = (
        capacity["context_entry_count"] >= 4
        and distinct
        and fits
        and aliases_clear
        and capacity["exact_encoded_length_entry_count"]
        == capacity["context_entry_count"]
        and capacity["original_encoded_bit_count"]
        == capacity["encoded_payload_bit_count"]
    )
    if (
        value["status"]
        != (
            "first-context-record-reinsertion-plan-ready"
            if ready
            else "first-context-record-reinsertion-plan-blocked"
        )
        or value["target_records_distinct"] is not distinct
        or value["in_place_storage_confirmed"] is not fits
        or value["shared_alias_impact_clear"] is not aliases_clear
        or value["record_storage_capacity_confirmed"] is not ready
        or value["runtime_layout_confirmed"] is not False
        or value["source_and_target_text_local_only"] is not True
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != (
            "build-first-context-in-place-test-patch"
            if ready
            else "repair-first-context-record-reinsertion-plan"
        )
    ):
        raise ValueError("first context reinsertion result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = {
        "target": root / TARGET_PATH,
        "encoding": root / ENCODING_PATH,
        "local_encoding": root / LOCAL_ENCODING_PATH,
        "local_context": root / LOCAL_CONTEXT_PATH,
        "local_projection": root / LOCAL_PROJECTION_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print("First context record reinsertion is not ready")
            return 0
        raise SystemExit("first context reinsertion input is missing")
    target = paths["target"].read_bytes()
    encoding = _load_json_object(paths["encoding"])
    local_encoding = _load_json_object(paths["local_encoding"])
    local_context = _load_json_object(paths["local_context"])
    local_projection = _load_json_object(paths["local_projection"])
    validate_first_context_translation_encoding(encoding)
    if (
        encoding["status"] != "first-context-translation-encoding-ready"
        or encoding["target_sha256"] != sha256_bytes(target)
        or local_encoding.get("target_sha256") != encoding["target_sha256"]
        or local_context.get("target_sha256") != encoding["target_sha256"]
        or local_projection.get("target_sha256") != encoding["target_sha256"]
    ):
        raise ValueError("first context reinsertion identity disagrees")
    context_rows = local_context.get("analysis", {}).get("rows")
    projection_pairs = local_projection.get("projection", {}).get("pairs")
    encoding_rows = local_encoding.get("rows")
    if not all(
        isinstance(value, list)
        for value in (context_rows, projection_pairs, encoding_rows)
    ):
        raise ValueError("first context reinsertion rows are missing")
    assert isinstance(context_rows, list)
    assert isinstance(projection_pairs, list)
    assert isinstance(encoding_rows, list)
    rows = build_reinsertion_rows(
        target=target,
        context_rows=context_rows,
        projection_pairs=projection_pairs,
        encoding_rows=encoding_rows,
    )
    capacity = summarize_reinsertion_rows(rows)
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    local = {
        "artifact_kind": LOCAL_ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "target_sha256": encoding["target_sha256"],
        "review_batch_sha256": encoding["review_batch_sha256"],
        "captured_utc": captured_utc,
        "capacity": capacity,
        "rows": rows,
        "publication_policy": (
            "never-publish-record-offsets-aliases-payloads-source-or-target-text"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_first_context_record_reinsertion(
        target_sha256=str(encoding["target_sha256"]),
        review_batch_sha256=str(encoding["review_batch_sha256"]),
        first_context_translation_encoding_sha256=sha256_file(
            paths["encoding"]
        ),
        local_reinsertion_sha256=sha256_file(local_path),
        capacity=capacity,
        captured_utc=captured_utc,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR first context reinsertion plan: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
