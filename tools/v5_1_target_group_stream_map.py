#!/usr/bin/env python3
"""Map patched group pointers onto one conservative length-record stream.

Pointer values, record boundaries, lengths, ordinals, and ROM bytes remain in
an ignored phone-local report.  The safe receipt publishes alignment counts
only and never declares the stream translation-ready.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_confirmed_group_extract import (
        PUBLISH_RELATIVE_PATH as CONFIRMED_GROUP_PATH,
        parse_length_prefixed_group,
        validate_confirmed_group_extract,
    )
    from .v5_1_consumer import verify_target_identity
    from .v5_1_renderer_output_trace import DEFAULT_ROM, _load_json_object
    from .v5_1_script_group import LOOKUP_TABLE_BASE, LOOKUP_TABLE_END
    from .v5_1_target_group_usage import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_USAGE_PATH,
        validate_target_group_usage,
    )
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from v5_1_confirmed_group_extract import (
        PUBLISH_RELATIVE_PATH as CONFIRMED_GROUP_PATH,
        parse_length_prefixed_group,
        validate_confirmed_group_extract,
    )
    from v5_1_consumer import verify_target_identity
    from v5_1_renderer_output_trace import DEFAULT_ROM, _load_json_object
    from v5_1_script_group import LOOKUP_TABLE_BASE, LOOKUP_TABLE_END
    from v5_1_target_group_usage import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_USAGE_PATH,
        validate_target_group_usage,
    )


ARTIFACT_KIND = "sanitized-v5-1-target-group-stream-map"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_target_group_stream_map.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_target_group_stream_map.json")
MAX_RECORDS = 4096
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_target_group_usage_sha256",
    "source_confirmed_group_extract_sha256",
    "captured_utc",
    "stream",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
STREAM_KEYS = {
    "valid_pointer_count",
    "aligned_pointer_count",
    "unaligned_pointer_count",
    "parsed_record_count",
    "zero_length_record_count",
    "covered_record_byte_count",
    "target_span_reached",
    "confirmed_group_start_aligned",
    "confirmed_selected_record_aligned",
    "all_pointer_anchors_aligned",
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


def _valid_pointer_entries(
    rom: bytes,
    *,
    mapped_bank: int,
) -> list[dict[str, int]]:
    output: list[dict[str, int]] = []
    for selector in range(
        0,
        LOOKUP_TABLE_END - LOOKUP_TABLE_BASE,
        2,
    ):
        lookup_offset = LOOKUP_TABLE_BASE + selector
        pointer = int.from_bytes(
            rom[lookup_offset : lookup_offset + 2],
            "little",
        )
        if not 0x4000 <= pointer < 0x8000:
            continue
        output.append(
            {
                "selector": selector,
                "lookup_offset": lookup_offset,
                "logical_pointer": pointer,
                "physical_pointer":
                    mapped_bank * 0x4000 + (pointer & 0x3FFF),
            }
        )
    return output


def analyze_target_group_stream(
    rom: bytes,
    *,
    mapped_bank: int,
    confirmed_physical_start: int,
    confirmed_selected_ordinal: int,
) -> tuple[dict[str, object], dict[str, object]]:
    pointers = _valid_pointer_entries(rom, mapped_bank=mapped_bank)
    if not pointers:
        raise ValueError("target group stream has no valid pointers")
    confirmed_records = parse_length_prefixed_group(
        rom,
        physical_start=confirmed_physical_start,
        entry_count=confirmed_selected_ordinal + 1,
    )
    selected_record = confirmed_records[-1]
    selected_length_offset = int(selected_record["length_offset"])
    selected_end = int(selected_record["payload_end"])
    starts = [item["physical_pointer"] for item in pointers]
    stream_start = min(starts)
    target_end = max(max(starts) + 1, selected_end)
    bank_start = mapped_bank * 0x4000
    bank_end = bank_start + 0x4000
    if (
        stream_start < bank_start
        or stream_start >= bank_end
        or target_end > bank_end
    ):
        raise ValueError("target group stream span crosses the mapped bank")
    records: list[dict[str, int]] = []
    cursor = stream_start
    while cursor < target_end and len(records) < MAX_RECORDS:
        length = rom[cursor]
        payload_start = cursor + 1
        payload_end = payload_start + length
        if payload_end > bank_end:
            break
        records.append(
            {
                "global_ordinal": len(records),
                "length_offset": cursor,
                "payload_start": payload_start,
                "payload_end": payload_end,
                "record_length_bytes": length,
            }
        )
        cursor = payload_end
    record_starts = {
        item["length_offset"]: item["global_ordinal"]
        for item in records
    }
    aligned = [
        item for item in pointers
        if item["physical_pointer"] in record_starts
    ]
    pointer_map = [
        {
            **item,
            "aligned": item["physical_pointer"] in record_starts,
            "global_ordinal": record_starts.get(
                item["physical_pointer"]
            ),
        }
        for item in pointers
    ]
    selected_aligned = selected_length_offset in record_starts
    group_start_aligned = confirmed_physical_start in record_starts
    all_aligned = len(aligned) == len(pointers)
    safe = {
        "valid_pointer_count": len(pointers),
        "aligned_pointer_count": len(aligned),
        "unaligned_pointer_count": len(pointers) - len(aligned),
        "parsed_record_count": len(records),
        "zero_length_record_count": sum(
            item["record_length_bytes"] == 0 for item in records
        ),
        "covered_record_byte_count": cursor - stream_start,
        "target_span_reached": cursor >= target_end,
        "confirmed_group_start_aligned": group_start_aligned,
        "confirmed_selected_record_aligned": selected_aligned,
        "all_pointer_anchors_aligned": all_aligned,
    }
    local = {
        "mapped_bank": mapped_bank,
        "stream_start": stream_start,
        "target_end": target_end,
        "cursor_end": cursor,
        "pointer_map": pointer_map,
        "records": records,
        "confirmed_physical_start": confirmed_physical_start,
        "confirmed_selected_ordinal": confirmed_selected_ordinal,
        "confirmed_selected_length_offset": selected_length_offset,
        "confirmed_selected_end": selected_end,
    }
    return safe, local


def build_target_group_stream_map(
    *,
    target_sha256: str,
    source_target_group_usage_sha256: str,
    source_confirmed_group_extract_sha256: str,
    stream: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    complete = (
        stream["target_span_reached"] is True
        and stream["confirmed_group_start_aligned"] is True
        and stream["confirmed_selected_record_aligned"] is True
        and stream["all_pointer_anchors_aligned"] is True
    )
    partial = (
        stream["target_span_reached"] is True
        and int(stream["aligned_pointer_count"]) > 0
    )
    status = (
        "target-group-record-stream-aligned"
        if complete
        else "target-group-record-stream-partial"
        if partial
        else "target-group-record-stream-unaligned"
    )
    checkpoint = (
        "extract-target-global-script-prefix"
        if complete
        else "classify-target-pointer-stream-boundaries"
    )
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": target_sha256,
        "source_target_group_usage_sha256":
            source_target_group_usage_sha256,
        "source_confirmed_group_extract_sha256":
            source_confirmed_group_extract_sha256,
        "captured_utc": captured_utc,
        "stream": {
            key: (
                bool(stream[key])
                if key
                in {
                    "target_span_reached",
                    "confirmed_group_start_aligned",
                    "confirmed_selected_record_aligned",
                    "all_pointer_anchors_aligned",
                }
                else int(stream[key])
            )
            for key in STREAM_KEYS
        },
        "local_payload_policy": (
            "pointers-record-boundaries-lengths-ordinals-and-rom-bytes-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": checkpoint,
    }
    validate_target_group_stream_map(value)
    return value


def validate_target_group_stream_map(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("target group stream map fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "target-group-record-stream-aligned",
            "target-group-record-stream-partial",
            "target-group-record-stream-unaligned",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_target_group_usage_sha256"])
        or not _is_sha256(
            value["source_confirmed_group_extract_sha256"]
        )
    ):
        raise ValueError("target group stream map policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("target group stream map timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(
            "target group stream map timestamp is invalid"
        ) from error
    if parsed.tzinfo is None:
        raise ValueError("target group stream timestamp must include UTC")
    stream = value["stream"]
    if not isinstance(stream, dict) or set(stream) != STREAM_KEYS:
        raise ValueError("target group stream fields do not match")
    bool_keys = {
        "target_span_reached",
        "confirmed_group_start_aligned",
        "confirmed_selected_record_aligned",
        "all_pointer_anchors_aligned",
    }
    for key in bool_keys:
        if not isinstance(stream[key], bool):
            raise ValueError(f"target group stream {key} is invalid")
    for key in STREAM_KEYS - bool_keys:
        if not _bounded_int(stream[key], 0, 0x100000):
            raise ValueError(f"target group stream {key} is invalid")
    if (
        stream["aligned_pointer_count"]
        + stream["unaligned_pointer_count"]
        != stream["valid_pointer_count"]
        or stream["zero_length_record_count"]
        > stream["parsed_record_count"]
        or stream["all_pointer_anchors_aligned"]
        is not (
            stream["valid_pointer_count"] > 0
            and stream["unaligned_pointer_count"] == 0
        )
    ):
        raise ValueError("target group stream aggregates are inconsistent")
    complete = (
        stream["target_span_reached"] is True
        and stream["confirmed_group_start_aligned"] is True
        and stream["confirmed_selected_record_aligned"] is True
        and stream["all_pointer_anchors_aligned"] is True
    )
    partial = (
        stream["target_span_reached"] is True
        and stream["aligned_pointer_count"] > 0
    )
    expected_status = (
        "target-group-record-stream-aligned"
        if complete
        else "target-group-record-stream-partial"
        if partial
        else "target-group-record-stream-unaligned"
    )
    expected_checkpoint = (
        "extract-target-global-script-prefix"
        if complete
        else "classify-target-pointer-stream-boundaries"
    )
    if (
        value["status"] != expected_status
        or value["next_checkpoint"] != expected_checkpoint
        or value["local_payload_policy"]
        != "pointers-record-boundaries-lengths-ordinals-and-rom-bytes-local-only"
        or value["translation_build_eligible"] is not False
    ):
        raise ValueError("target group stream result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    usage_path = root / TARGET_GROUP_USAGE_PATH
    confirmed_path = root / CONFIRMED_GROUP_PATH
    if (
        not rom_path.is_file()
        or not usage_path.is_file()
        or not confirmed_path.is_file()
    ):
        if args.if_ready:
            print("Target group stream map is not ready")
            return 0
        raise SystemExit("target group stream map input is missing")
    rom = rom_path.read_bytes()
    verify_target_identity(rom)
    target_sha256 = sha256_file(rom_path)
    usage = _load_json_object(usage_path)
    confirmed = _load_json_object(confirmed_path)
    validate_target_group_usage(usage)
    validate_confirmed_group_extract(confirmed)
    if (
        usage["target_sha256"] != target_sha256
        or confirmed["target_sha256"] != target_sha256
    ):
        raise ValueError("target group stream identity disagrees")
    group = confirmed["group"]
    assert isinstance(group, dict)
    analysis, local_analysis = analyze_target_group_stream(
        rom,
        mapped_bank=int(group["mapped_bank"]),
        confirmed_physical_start=int(group["physical_start"]),
        confirmed_selected_ordinal=int(group["selected_entry_ordinal"]),
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_target_group_stream_map(
        target_sha256=target_sha256,
        source_target_group_usage_sha256=sha256_file(usage_path),
        source_confirmed_group_extract_sha256=sha256_file(confirmed_path),
        stream=analysis,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-target-group-stream-map",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "captured_utc": captured_utc,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-pointers-record-boundaries-lengths-ordinals-or-rom-bytes"
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
    print(f"SFKR target group stream map: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
