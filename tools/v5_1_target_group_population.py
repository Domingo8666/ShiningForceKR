#!/usr/bin/env python3
"""Enumerate every 8-bit-addressable record from each patched group anchor.

Selectors, ordinals, pointers, record boundaries, lengths, hashes, and payload
bytes remain in an ignored phone-local report.  The safe receipt contains only
population and overlap counts.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
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
    from .v5_1_target_group_stream_map import (
        PUBLISH_RELATIVE_PATH as STREAM_MAP_PATH,
        validate_target_group_stream_map,
    )
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
    from v5_1_target_group_stream_map import (
        PUBLISH_RELATIVE_PATH as STREAM_MAP_PATH,
        validate_target_group_stream_map,
    )
    from v5_1_target_group_usage import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_USAGE_PATH,
        validate_target_group_usage,
    )


ARTIFACT_KIND = "sanitized-v5-1-target-group-population"
SCHEMA_VERSION = 1
ADDRESSABLE_RECORD_COUNT = 256
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_target_group_population.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_target_group_population.json")
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_target_group_usage_sha256",
    "source_stream_map_sha256",
    "source_confirmed_group_extract_sha256",
    "captured_utc",
    "population",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
POPULATION_KEYS = {
    "selector_count",
    "addressable_records_per_selector",
    "requested_record_slot_count",
    "parsed_record_slot_count",
    "selectors_reaching_full_addressable_count",
    "selectors_stopped_at_bank_boundary_count",
    "unique_physical_record_count",
    "shared_physical_record_count",
    "overlapping_record_slot_count",
    "zero_length_record_slot_count",
    "maximum_record_bytes",
    "confirmed_selected_record_match",
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


def analyze_target_group_population(
    rom: bytes,
    *,
    mapped_bank: int,
    confirmed_selector: int,
    confirmed_physical_start: int,
    confirmed_selected_ordinal: int,
) -> tuple[dict[str, object], dict[str, object]]:
    pointers = _valid_pointer_entries(rom, mapped_bank=mapped_bank)
    if not pointers:
        raise ValueError("target group population has no valid pointers")
    bank_end = (mapped_bank + 1) * 0x4000
    groups: list[dict[str, object]] = []
    all_records: list[dict[str, object]] = []
    full_count = 0
    stopped_count = 0
    for pointer in pointers:
        cursor = pointer["physical_pointer"]
        records: list[dict[str, object]] = []
        stopped = False
        for ordinal in range(ADDRESSABLE_RECORD_COUNT):
            if cursor >= bank_end:
                stopped = True
                break
            length = rom[cursor]
            payload_start = cursor + 1
            payload_end = payload_start + length
            if payload_end > bank_end:
                stopped = True
                break
            payload = rom[payload_start:payload_end]
            record = {
                "selector": pointer["selector"],
                "ordinal": ordinal,
                "length_offset": cursor,
                "payload_start": payload_start,
                "payload_end": payload_end,
                "record_length_bytes": length,
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "payload_hex": payload.hex().upper(),
            }
            records.append(record)
            all_records.append(record)
            cursor = payload_end
        if len(records) == ADDRESSABLE_RECORD_COUNT:
            full_count += 1
        elif stopped:
            stopped_count += 1
        groups.append(
            {
                **pointer,
                "record_count": len(records),
                "stopped_at_bank_boundary": stopped,
                "cursor_end": cursor,
                "records": records,
            }
        )
    physical_counts = Counter(
        int(record["length_offset"]) for record in all_records
    )
    unique_count = len(physical_counts)
    shared_count = sum(count > 1 for count in physical_counts.values())
    confirmed_records = parse_length_prefixed_group(
        rom,
        physical_start=confirmed_physical_start,
        entry_count=confirmed_selected_ordinal + 1,
    )
    confirmed_record = confirmed_records[-1]
    selected = next(
        (
            record
            for record in all_records
            if (
                record["selector"] == confirmed_selector
                and record["ordinal"] == confirmed_selected_ordinal
            )
        ),
        None,
    )
    confirmed_match = (
        selected is not None
        and int(selected["length_offset"])
        == int(confirmed_record["length_offset"])
        and int(selected["record_length_bytes"])
        == int(confirmed_record["record_length_bytes"])
        and selected["payload_hex"]
        == bytes(confirmed_record["payload"]).hex().upper()
    )
    safe = {
        "selector_count": len(pointers),
        "addressable_records_per_selector": ADDRESSABLE_RECORD_COUNT,
        "requested_record_slot_count":
            len(pointers) * ADDRESSABLE_RECORD_COUNT,
        "parsed_record_slot_count": len(all_records),
        "selectors_reaching_full_addressable_count": full_count,
        "selectors_stopped_at_bank_boundary_count": stopped_count,
        "unique_physical_record_count": unique_count,
        "shared_physical_record_count": shared_count,
        "overlapping_record_slot_count": len(all_records) - unique_count,
        "zero_length_record_slot_count": sum(
            int(record["record_length_bytes"]) == 0
            for record in all_records
        ),
        "maximum_record_bytes": max(
            (
                int(record["record_length_bytes"])
                for record in all_records
            ),
            default=0,
        ),
        "confirmed_selected_record_match": confirmed_match,
    }
    local = {
        "mapped_bank": mapped_bank,
        "bank_end": bank_end,
        "groups": groups,
        "physical_record_slot_counts": [
            {
                "length_offset": offset,
                "slot_count": count,
            }
            for offset, count in sorted(physical_counts.items())
        ],
        "confirmed_selector": confirmed_selector,
        "confirmed_selected_ordinal": confirmed_selected_ordinal,
    }
    return safe, local


def build_target_group_population(
    *,
    target_sha256: str,
    source_target_group_usage_sha256: str,
    source_stream_map_sha256: str,
    source_confirmed_group_extract_sha256: str,
    population: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    complete = (
        population["confirmed_selected_record_match"] is True
        and population["selector_count"] > 0
        and population["selectors_reaching_full_addressable_count"]
        == population["selector_count"]
    )
    bounded = (
        population["confirmed_selected_record_match"] is True
        and population["parsed_record_slot_count"] > 0
        and population["selectors_reaching_full_addressable_count"]
        + population["selectors_stopped_at_bank_boundary_count"]
        == population["selector_count"]
    )
    status = (
        "target-group-addressable-population-enumerated"
        if complete
        else "target-group-addressable-population-bounded"
        if bounded
        else "target-group-addressable-population-unresolved"
    )
    checkpoint = (
        "decode-target-group-population"
        if complete or bounded
        else "resolve-target-group-population-boundaries"
    )
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": target_sha256,
        "source_target_group_usage_sha256":
            source_target_group_usage_sha256,
        "source_stream_map_sha256": source_stream_map_sha256,
        "source_confirmed_group_extract_sha256":
            source_confirmed_group_extract_sha256,
        "captured_utc": captured_utc,
        "population": {
            key: (
                bool(population[key])
                if key == "confirmed_selected_record_match"
                else int(population[key])
            )
            for key in POPULATION_KEYS
        },
        "local_payload_policy": (
            "selectors-ordinals-pointers-record-boundaries-lengths-hashes-and-payloads-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": checkpoint,
    }
    validate_target_group_population(value)
    return value


def validate_target_group_population(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("target group population fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "target-group-addressable-population-enumerated",
            "target-group-addressable-population-bounded",
            "target-group-addressable-population-unresolved",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_target_group_usage_sha256"])
        or not _is_sha256(value["source_stream_map_sha256"])
        or not _is_sha256(
            value["source_confirmed_group_extract_sha256"]
        )
    ):
        raise ValueError("target group population policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("target group population timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(
            "target group population timestamp is invalid"
        ) from error
    if parsed.tzinfo is None:
        raise ValueError("target group population timestamp must include UTC")
    population = value["population"]
    if not isinstance(population, dict) or set(population) != POPULATION_KEYS:
        raise ValueError("target group population counts do not match")
    for key in POPULATION_KEYS - {"confirmed_selected_record_match"}:
        if not _bounded_int(population[key], 0, 0x100000):
            raise ValueError(f"target group population {key} is invalid")
    if not isinstance(population["confirmed_selected_record_match"], bool):
        raise ValueError("target group population confirmation is invalid")
    if (
        population["addressable_records_per_selector"]
        != ADDRESSABLE_RECORD_COUNT
        or population["requested_record_slot_count"]
        != population["selector_count"] * ADDRESSABLE_RECORD_COUNT
        or population["parsed_record_slot_count"]
        > population["requested_record_slot_count"]
        or population["unique_physical_record_count"]
        + population["overlapping_record_slot_count"]
        != population["parsed_record_slot_count"]
        or population["shared_physical_record_count"]
        > population["unique_physical_record_count"]
        or population["zero_length_record_slot_count"]
        > population["parsed_record_slot_count"]
    ):
        raise ValueError("target group population aggregates are inconsistent")
    complete = (
        population["confirmed_selected_record_match"] is True
        and population["selector_count"] > 0
        and population["selectors_reaching_full_addressable_count"]
        == population["selector_count"]
    )
    bounded = (
        population["confirmed_selected_record_match"] is True
        and population["parsed_record_slot_count"] > 0
        and population["selectors_reaching_full_addressable_count"]
        + population["selectors_stopped_at_bank_boundary_count"]
        == population["selector_count"]
    )
    expected_status = (
        "target-group-addressable-population-enumerated"
        if complete
        else "target-group-addressable-population-bounded"
        if bounded
        else "target-group-addressable-population-unresolved"
    )
    expected_checkpoint = (
        "decode-target-group-population"
        if complete or bounded
        else "resolve-target-group-population-boundaries"
    )
    if (
        value["status"] != expected_status
        or value["next_checkpoint"] != expected_checkpoint
        or value["local_payload_policy"]
        != "selectors-ordinals-pointers-record-boundaries-lengths-hashes-and-payloads-local-only"
        or value["translation_build_eligible"] is not False
    ):
        raise ValueError("target group population result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    usage_path = root / TARGET_GROUP_USAGE_PATH
    stream_path = root / STREAM_MAP_PATH
    confirmed_path = root / CONFIRMED_GROUP_PATH
    if (
        not rom_path.is_file()
        or not usage_path.is_file()
        or not stream_path.is_file()
        or not confirmed_path.is_file()
    ):
        if args.if_ready:
            print("Target group population is not ready")
            return 0
        raise SystemExit("target group population input is missing")
    rom = rom_path.read_bytes()
    verify_target_identity(rom)
    target_sha256 = sha256_file(rom_path)
    usage = _load_json_object(usage_path)
    stream = _load_json_object(stream_path)
    confirmed = _load_json_object(confirmed_path)
    validate_target_group_usage(usage)
    validate_target_group_stream_map(stream)
    validate_confirmed_group_extract(confirmed)
    if any(
        source["target_sha256"] != target_sha256
        for source in (usage, stream, confirmed)
    ):
        raise ValueError("target group population identity disagrees")
    group = confirmed["group"]
    assert isinstance(group, dict)
    analysis, local_analysis = analyze_target_group_population(
        rom,
        mapped_bank=int(group["mapped_bank"]),
        confirmed_selector=int(group["selector"]),
        confirmed_physical_start=int(group["physical_start"]),
        confirmed_selected_ordinal=int(group["selected_entry_ordinal"]),
    )
    if analysis["selector_count"] != usage["lookup"]["valid_pointer_count"]:
        raise ValueError("target group population pointer count disagrees")
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_target_group_population(
        target_sha256=target_sha256,
        source_target_group_usage_sha256=sha256_file(usage_path),
        source_stream_map_sha256=sha256_file(stream_path),
        source_confirmed_group_extract_sha256=sha256_file(confirmed_path),
        population=analysis,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-target-group-population",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "captured_utc": captured_utc,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-selectors-ordinals-pointers-record-boundaries-lengths-hashes-or-payloads"
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
    print(f"SFKR target group population: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
