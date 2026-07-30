#!/usr/bin/env python3
"""Compare confirmed target records with the clean source ROM locally.

ROM bytes and per-record deltas remain in an ignored phone-local report.  The
published artifact contains only hashes, aggregate counts, and the resulting
classification.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

try:
    from .analyze_v5_1 import (
        EXPECTED_SOURCE_SHA256,
        EXPECTED_SOURCE_SIZE,
    )
    from .patch_io import sha256_bytes, sha256_file
    from .v5_1_confirmed_group_extract import (
        LOCAL_REPORT_PATH as LOCAL_GROUP_PATH,
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        parse_length_prefixed_group,
        validate_confirmed_group_extract,
    )
    from .v5_1_group_runtime_context import (
        LOCAL_REPORT_PATH as LOCAL_RUNTIME_CONTEXT_PATH,
        PUBLISH_RELATIVE_PATH as RUNTIME_CONTEXT_PATH,
        validate_group_runtime_context,
    )
    from .v5_1_renderer_output_trace import _load_json_object
except ImportError:  # direct script execution
    from analyze_v5_1 import EXPECTED_SOURCE_SHA256, EXPECTED_SOURCE_SIZE
    from patch_io import sha256_bytes, sha256_file
    from v5_1_confirmed_group_extract import (
        LOCAL_REPORT_PATH as LOCAL_GROUP_PATH,
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        parse_length_prefixed_group,
        validate_confirmed_group_extract,
    )
    from v5_1_group_runtime_context import (
        LOCAL_REPORT_PATH as LOCAL_RUNTIME_CONTEXT_PATH,
        PUBLISH_RELATIVE_PATH as RUNTIME_CONTEXT_PATH,
        validate_group_runtime_context,
    )
    from v5_1_renderer_output_trace import _load_json_object


ARTIFACT_KIND = "sanitized-v5-1-group-source-delta"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_group_source_delta.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_group_source_delta.json")
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "source_sha256",
    "target_sha256",
    "source_group_extract_sha256",
    "source_runtime_context_sha256",
    "captured_utc",
    "group",
    "delta",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
GROUP_KEYS = {
    "selector",
    "record_count",
}
DELTA_KEYS = {
    "source_parsed_entry_count",
    "target_parsed_entry_count",
    "unchanged_entry_count",
    "changed_entry_count",
    "same_length_entry_count",
    "different_length_entry_count",
    "runtime_resolved_unchanged_count",
    "runtime_resolved_changed_count",
    "runtime_unresolved_unchanged_count",
    "runtime_unresolved_changed_count",
    "source_total_record_bytes",
    "target_total_record_bytes",
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


def compare_group_source_records(
    *,
    source_records: list[dict[str, object]],
    target_records: list[dict[str, object]],
    runtime_resolved_entry_ids: set[str],
) -> tuple[dict[str, int], dict[str, object]]:
    if (
        not source_records
        or len(source_records) != len(target_records)
        or len(source_records) > 0xFF
    ):
        raise ValueError("group source delta record population is invalid")
    unchanged = 0
    same_length = 0
    resolved_unchanged = 0
    resolved_changed = 0
    unresolved_unchanged = 0
    unresolved_changed = 0
    local_records: list[dict[str, object]] = []
    for ordinal, (source, target) in enumerate(
        zip(source_records, target_records, strict=True)
    ):
        source_payload = source.get("payload")
        encoded_hex = target.get("encoded_hex")
        entry_id = target.get("entry_id")
        if (
            not isinstance(source_payload, bytes)
            or not isinstance(encoded_hex, str)
            or re.fullmatch(r"(?:[0-9A-F]{2})+", encoded_hex) is None
            or not isinstance(entry_id, str)
            or target.get("ordinal") != ordinal
            or source.get("ordinal") != ordinal
        ):
            raise ValueError("group source delta record is invalid")
        target_payload = bytes.fromhex(encoded_hex)
        is_unchanged = source_payload == target_payload
        is_same_length = len(source_payload) == len(target_payload)
        is_resolved = entry_id in runtime_resolved_entry_ids
        unchanged += int(is_unchanged)
        same_length += int(is_same_length)
        resolved_unchanged += int(is_resolved and is_unchanged)
        resolved_changed += int(is_resolved and not is_unchanged)
        unresolved_unchanged += int(not is_resolved and is_unchanged)
        unresolved_changed += int(not is_resolved and not is_unchanged)
        local_records.append(
            {
                "entry_id": entry_id,
                "ordinal": ordinal,
                "runtime_context_resolved": is_resolved,
                "unchanged_from_source": is_unchanged,
                "same_length": is_same_length,
                "source_length": len(source_payload),
                "target_length": len(target_payload),
                "source_encoded_hex": source_payload.hex().upper(),
                "target_encoded_hex": encoded_hex,
                "source_encoded_sha256": hashlib.sha256(
                    source_payload
                ).hexdigest(),
                "target_encoded_sha256": hashlib.sha256(
                    target_payload
                ).hexdigest(),
            }
        )
    count = len(source_records)
    safe_counts = {
        "source_parsed_entry_count": count,
        "target_parsed_entry_count": count,
        "unchanged_entry_count": unchanged,
        "changed_entry_count": count - unchanged,
        "same_length_entry_count": same_length,
        "different_length_entry_count": count - same_length,
        "runtime_resolved_unchanged_count": resolved_unchanged,
        "runtime_resolved_changed_count": resolved_changed,
        "runtime_unresolved_unchanged_count": unresolved_unchanged,
        "runtime_unresolved_changed_count": unresolved_changed,
        "source_total_record_bytes": sum(
            int(record["record_length_bytes"])
            for record in source_records
        ),
        "target_total_record_bytes": sum(
            int(record["record_length_bytes"])
            for record in target_records
        ),
    }
    local = {"records": local_records}
    return safe_counts, local


def build_group_source_delta(
    *,
    source_sha256: str,
    target_sha256: str,
    source_group_extract_sha256: str,
    source_runtime_context_sha256: str,
    selector: int,
    record_count: int,
    delta: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    unresolved_unchanged = int(
        delta["runtime_unresolved_unchanged_count"]
    )
    unresolved_changed = int(delta["runtime_unresolved_changed_count"])
    if unresolved_unchanged > 0 and unresolved_changed == 0:
        status = "runtime-unresolved-records-source-identical"
        checkpoint = "decode-source-identical-records-with-original-trees"
    elif unresolved_unchanged > 0:
        status = "runtime-unresolved-records-mixed-source-delta"
        checkpoint = "split-original-and-target-record-decoders"
    else:
        status = "runtime-unresolved-records-all-target-modified"
        checkpoint = "classify-target-modified-record-format"
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "source_sha256": source_sha256,
        "target_sha256": target_sha256,
        "source_group_extract_sha256": source_group_extract_sha256,
        "source_runtime_context_sha256": source_runtime_context_sha256,
        "captured_utc": captured_utc,
        "group": {
            "selector": selector,
            "record_count": record_count,
        },
        "delta": {
            key: int(delta[key])
            for key in DELTA_KEYS
        },
        "local_payload_policy": (
            "source-target-record-bytes-and-deltas-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": checkpoint,
    }
    validate_group_source_delta(safe)
    return safe


def validate_group_source_delta(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("group source delta fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "runtime-unresolved-records-source-identical",
            "runtime-unresolved-records-mixed-source-delta",
            "runtime-unresolved-records-all-target-modified",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "source_sha256",
                "target_sha256",
                "source_group_extract_sha256",
                "source_runtime_context_sha256",
            )
        )
    ):
        raise ValueError("group source delta policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("group source delta timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("group source delta timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("group source delta timestamp must include UTC")
    group = value["group"]
    if not isinstance(group, dict) or set(group) != GROUP_KEYS:
        raise ValueError("group source delta group fields do not match")
    if (
        not _bounded_int(group["selector"], 0, 0xFFFF)
        or not _bounded_int(group["record_count"], 1, 0xFF)
    ):
        raise ValueError("group source delta group is invalid")
    delta = value["delta"]
    if not isinstance(delta, dict) or set(delta) != DELTA_KEYS:
        raise ValueError("group source delta count fields do not match")
    count = int(group["record_count"])
    for key in DELTA_KEYS:
        maximum = 0x1000000 if "bytes" in key else count
        if not _bounded_int(delta[key], 0, maximum):
            raise ValueError(f"group source delta {key} is invalid")
    if (
        delta["source_parsed_entry_count"] != count
        or delta["target_parsed_entry_count"] != count
        or delta["unchanged_entry_count"]
        + delta["changed_entry_count"] != count
        or delta["same_length_entry_count"]
        + delta["different_length_entry_count"] != count
        or delta["runtime_resolved_unchanged_count"]
        + delta["runtime_resolved_changed_count"]
        + delta["runtime_unresolved_unchanged_count"]
        + delta["runtime_unresolved_changed_count"] != count
    ):
        raise ValueError("group source delta aggregates are inconsistent")
    unresolved_unchanged = int(
        delta["runtime_unresolved_unchanged_count"]
    )
    unresolved_changed = int(delta["runtime_unresolved_changed_count"])
    expected_status = (
        "runtime-unresolved-records-source-identical"
        if unresolved_unchanged > 0 and unresolved_changed == 0
        else "runtime-unresolved-records-mixed-source-delta"
        if unresolved_unchanged > 0
        else "runtime-unresolved-records-all-target-modified"
    )
    expected_checkpoint = (
        "decode-source-identical-records-with-original-trees"
        if expected_status == "runtime-unresolved-records-source-identical"
        else "split-original-and-target-record-decoders"
        if expected_status == "runtime-unresolved-records-mixed-source-delta"
        else "classify-target-modified-record-format"
    )
    if (
        value["status"] != expected_status
        or value["next_checkpoint"] != expected_checkpoint
        or value["local_payload_policy"]
        != "source-target-record-bytes-and-deltas-local-only"
        or value["translation_build_eligible"] is not False
    ):
        raise ValueError("group source delta result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--source-rom", type=Path, required=True)
    args = parser.parse_args()
    source_path = (
        args.source_rom
        if args.source_rom.is_absolute()
        else root / args.source_rom
    )
    group_path = root / GROUP_EXTRACT_PATH
    local_group_path = root / LOCAL_GROUP_PATH
    runtime_path = root / RUNTIME_CONTEXT_PATH
    local_runtime_path = root / LOCAL_RUNTIME_CONTEXT_PATH
    prerequisites = (
        source_path,
        group_path,
        local_group_path,
        runtime_path,
        local_runtime_path,
    )
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Group source delta is not ready")
            return 0
        raise SystemExit("group source delta input is missing")
    source = source_path.read_bytes()
    if (
        len(source) != EXPECTED_SOURCE_SIZE
        or sha256_bytes(source) != EXPECTED_SOURCE_SHA256
    ):
        raise ValueError("group source delta clean ROM identity mismatch")
    group = _load_json_object(group_path)
    local_group = _load_json_object(local_group_path)
    runtime = _load_json_object(runtime_path)
    local_runtime = _load_json_object(local_runtime_path)
    validate_confirmed_group_extract(group)
    validate_group_runtime_context(runtime)
    if (
        local_group.get("target_sha256") != group["target_sha256"]
        or runtime["target_sha256"] != group["target_sha256"]
        or runtime["source_group_extract_sha256"]
        != sha256_file(group_path)
        or local_runtime.get("target_sha256") != group["target_sha256"]
        or local_runtime.get("source_group_extract_sha256")
        != sha256_file(group_path)
    ):
        raise ValueError("group source delta identities disagree")
    target_records = local_group.get("records")
    resolved_records = local_runtime.get("analysis", {}).get(
        "resolved_records"
    )
    if not isinstance(target_records, list) or not isinstance(
        resolved_records, list
    ):
        raise ValueError("group source delta local records are missing")
    group_info = group["group"]
    assert isinstance(group_info, dict)
    source_records = parse_length_prefixed_group(
        source,
        physical_start=int(group_info["physical_start"]),
        entry_count=int(group_info["declared_entry_count"]),
    )
    resolved_ids = {
        str(record["entry_id"])
        for record in resolved_records
        if isinstance(record, dict) and isinstance(record.get("entry_id"), str)
    }
    counts, local_analysis = compare_group_source_records(
        source_records=source_records,
        target_records=target_records,
        runtime_resolved_entry_ids=resolved_ids,
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_group_source_delta(
        source_sha256=EXPECTED_SOURCE_SHA256,
        target_sha256=str(group["target_sha256"]),
        source_group_extract_sha256=sha256_file(group_path),
        source_runtime_context_sha256=sha256_file(runtime_path),
        selector=int(group_info["selector"]),
        record_count=int(group_info["declared_entry_count"]),
        delta=counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-group-source-delta",
        "schema_version": 1,
        "source_sha256": EXPECTED_SOURCE_SHA256,
        "target_sha256": group["target_sha256"],
        "captured_utc": captured_utc,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-source-target-record-bytes-or-per-record-deltas"
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
    print(f"SFKR group source delta: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
