#!/usr/bin/env python3
"""Classify the confirmed active ROM byte before treating it as script data."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_active_ram_register_trace import (
        LOCAL_REPORT_PATH as REGISTER_TRACE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as REGISTER_TRACE_PATH,
        validate_active_ram_register_trace,
    )
    from .v5_1_active_register_rom_source import (
        LOCAL_REPORT_PATH as ROM_SOURCE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as ROM_SOURCE_PATH,
        source_slot,
        validate_active_register_rom_source,
    )
    from .v5_1_active_vram_route import (
        PUBLISH_RELATIVE_PATH as ACTIVE_VRAM_ROUTE_PATH,
        validate_active_vram_route,
    )
    from .v5_1_renderer_output_trace import DEFAULT_ROM
    from .v5_1_runtime_hit_resolver import _parse_trace_line, _read_addresses
    from .v5_1_target_group_population import (
        LOCAL_REPORT_PATH as TARGET_POPULATION_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as TARGET_POPULATION_PATH,
        validate_target_group_population,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_active_ram_register_trace import (
        LOCAL_REPORT_PATH as REGISTER_TRACE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as REGISTER_TRACE_PATH,
        validate_active_ram_register_trace,
    )
    from v5_1_active_register_rom_source import (
        LOCAL_REPORT_PATH as ROM_SOURCE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as ROM_SOURCE_PATH,
        source_slot,
        validate_active_register_rom_source,
    )
    from v5_1_active_vram_route import (
        PUBLISH_RELATIVE_PATH as ACTIVE_VRAM_ROUTE_PATH,
        validate_active_vram_route,
    )
    from v5_1_renderer_output_trace import DEFAULT_ROM
    from v5_1_runtime_hit_resolver import _parse_trace_line, _read_addresses
    from v5_1_target_group_population import (
        LOCAL_REPORT_PATH as TARGET_POPULATION_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as TARGET_POPULATION_PATH,
        validate_target_group_population,
    )


ARTIFACT_KIND = "sanitized-s25u-active-rom-source-role"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_active_rom_source_role.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_active_rom_source_role.json")
COUNT_KEYS = {
    "matching_definition_event_count",
    "matching_read_event_count",
    "unique_logical_read_count",
    "contiguous_logical_span_bytes",
    "forward_sequential_transition_count",
    "source_script_payload_match_count",
    "source_script_length_match_count",
    "source_executed_match_count",
    "target_transfer_byte_count",
    "target_transfer_tile_count",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_active_register_rom_source_sha256",
    "source_register_trace_sha256",
    "source_target_population_sha256",
    "captured_utc",
    "analysis",
    "source_role",
    "script_record_source_confirmed",
    "renderer_asset_source_candidate",
    "baseline_script_bytes_unchanged",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
SOURCE_ROLES = {
    "script-record-payload",
    "script-record-length",
    "executed-code",
    "renderer-source-candidate",
    "unclassified-data",
}


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"active ROM source role input is not an object: {path}")
    return value


def _flatten_records(population_local: dict[str, object]) -> list[dict[str, object]]:
    groups = population_local.get("groups")
    if not isinstance(groups, list):
        raise ValueError("active ROM source role target groups are missing")
    records: list[dict[str, object]] = []
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("records"), list):
            raise ValueError("active ROM source role target group is invalid")
        for record in group["records"]:
            if not isinstance(record, dict):
                raise ValueError("active ROM source role target record is invalid")
            records.append(record)
    return records


def _physical_pc(bank: int, pc: int) -> int:
    if pc < 0x4000:
        return pc
    if pc < 0xC000:
        return bank * 0x4000 + (pc & 0x3FFF)
    return -1


def collect_matching_reads(
    lines: list[str], selected: dict[str, object]
) -> tuple[list[int], set[int], int]:
    expected_bank = int(selected["bank"])
    expected_pc = int(selected["pc"])
    expected_opcodes = str(selected["opcodes_hex"]).lower()
    reads: list[int] = []
    executed: set[int] = set()
    matching_events = 0
    for line in lines:
        parsed = _parse_trace_line(line)
        if parsed is None:
            continue
        bank = int(parsed["bank"])
        pc = int(parsed["pc"])
        physical_pc = _physical_pc(bank, pc)
        if physical_pc >= 0:
            executed.add(physical_pc)
        opcodes = parsed["opcodes"]
        registers = parsed["registers"]
        if (
            bank != expected_bank
            or pc != expected_pc
            or not isinstance(opcodes, bytes)
            or opcodes.hex().lower() != expected_opcodes
            or not isinstance(registers, dict)
        ):
            continue
        matching_events += 1
        typed = {
            key: int(value)
            for key, value in registers.items()
            if isinstance(value, int) and not isinstance(value, bool)
        }
        reads.extend(_read_addresses(opcodes, typed))
    return reads, executed, matching_events


def analyze_source_role(
    *,
    logical_reads: list[int],
    logical_source: int,
    mapped_bank: int,
    physical_source_offset: int,
    target_transfer_count: int,
    records: list[dict[str, object]],
    executed_physical_offsets: set[int],
    matching_definition_event_count: int,
) -> tuple[dict[str, int], dict[str, object]]:
    slot = source_slot(logical_source)
    same_slot_reads = [
        address
        for address in logical_reads
        if 0 <= address < 0xC000 and source_slot(address) == slot
    ]
    unique_reads = sorted(set(same_slot_reads))
    span = unique_reads[-1] - unique_reads[0] + 1 if unique_reads else 0
    sequential = sum(
        int(right == left + 1)
        for left, right in zip(same_slot_reads, same_slot_reads[1:])
    )
    payload_matches: list[dict[str, object]] = []
    length_matches: list[dict[str, object]] = []
    for record in records:
        try:
            length_offset = int(record["length_offset"])
            payload_start = int(record["payload_start"])
            payload_end = int(record["payload_end"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("active ROM source role record bounds are invalid") from error
        if physical_source_offset == length_offset:
            length_matches.append(record)
        if payload_start <= physical_source_offset < payload_end:
            payload_matches.append(record)
    executed_count = int(physical_source_offset in executed_physical_offsets)
    tile_count = (
        target_transfer_count // 32
        if target_transfer_count >= 32 and target_transfer_count % 32 == 0
        else 0
    )
    contiguous = bool(unique_reads) and span == len(unique_reads)
    renderer_candidate = (
        not payload_matches
        and not length_matches
        and not executed_count
        and tile_count > 0
        and len(unique_reads) >= 8
        and contiguous
    )
    if payload_matches:
        role = "script-record-payload"
    elif length_matches:
        role = "script-record-length"
    elif executed_count:
        role = "executed-code"
    elif renderer_candidate:
        role = "renderer-source-candidate"
    else:
        role = "unclassified-data"
    counts = {
        "matching_definition_event_count": matching_definition_event_count,
        "matching_read_event_count": len(same_slot_reads),
        "unique_logical_read_count": len(unique_reads),
        "contiguous_logical_span_bytes": span if contiguous else 0,
        "forward_sequential_transition_count": sequential,
        "source_script_payload_match_count": len(payload_matches),
        "source_script_length_match_count": len(length_matches),
        "source_executed_match_count": executed_count,
        "target_transfer_byte_count": target_transfer_count,
        "target_transfer_tile_count": tile_count,
    }
    local = {
        "logical_reads": same_slot_reads,
        "logical_source": logical_source,
        "mapped_bank": mapped_bank,
        "physical_source_offset": physical_source_offset,
        "payload_matches": payload_matches,
        "length_matches": length_matches,
        "executed_source_match": bool(executed_count),
        "contiguous_unique_reads": contiguous,
    }
    return counts, {"source_role": role, "local": local}


def _next_checkpoint(role: str) -> str:
    return {
        "script-record-payload": "build-structural-script-extractor-from-record",
        "script-record-length": "map-length-field-to-script-consumer",
        "executed-code": "trace-code-data-selector-back-to-decoded-symbol",
        "renderer-source-candidate": "trace-render-source-address-back-to-decoded-symbol",
        "unclassified-data": "capture-contiguous-active-rom-read-block",
    }[role]


def build_active_rom_source_role(
    *,
    target_sha256: str,
    source_active_register_rom_source_sha256: str,
    source_register_trace_sha256: str,
    source_target_population_sha256: str,
    analysis: dict[str, int],
    source_role_name: str,
    captured_utc: str,
) -> dict[str, object]:
    script_confirmed = source_role_name in {
        "script-record-payload", "script-record-length"
    }
    renderer_candidate = source_role_name == "renderer-source-candidate"
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "active-rom-source-role-classified"
            if source_role_name != "unclassified-data"
            else "active-rom-source-role-unresolved"
        ),
        "target_sha256": target_sha256,
        "source_active_register_rom_source_sha256":
            source_active_register_rom_source_sha256,
        "source_register_trace_sha256": source_register_trace_sha256,
        "source_target_population_sha256": source_target_population_sha256,
        "captured_utc": captured_utc,
        "analysis": {key: int(analysis[key]) for key in COUNT_KEYS},
        "source_role": source_role_name,
        "script_record_source_confirmed": script_confirmed,
        "renderer_asset_source_candidate": renderer_candidate,
        "baseline_script_bytes_unchanged": True,
        "local_payload_policy": (
            "addresses-opcodes-registers-record-coordinates-and-ROM-bytes-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": _next_checkpoint(source_role_name),
    }
    validate_active_rom_source_role(value)
    return value


def validate_active_rom_source_role(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("active ROM source role fields do not match")
    role = value.get("source_role")
    if (
        value.get("artifact_kind") != ARTIFACT_KIND
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("status") not in {
            "active-rom-source-role-classified",
            "active-rom-source-role-unresolved",
        }
        or role not in SOURCE_ROLES
        or not _is_sha256(value.get("target_sha256"))
        or not _is_sha256(value.get("source_active_register_rom_source_sha256"))
        or not _is_sha256(value.get("source_register_trace_sha256"))
        or not _is_sha256(value.get("source_target_population_sha256"))
    ):
        raise ValueError("active ROM source role policy is invalid")
    counts = value.get("analysis")
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("active ROM source role counts do not match")
    if any(
        not isinstance(counts[key], int)
        or isinstance(counts[key], bool)
        or counts[key] < 0
        for key in COUNT_KEYS
    ):
        raise ValueError("active ROM source role count is invalid")
    try:
        captured = datetime.fromisoformat(
            str(value["captured_utc"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError("active ROM source role timestamp is invalid") from error
    script_confirmed = role in {"script-record-payload", "script-record-length"}
    renderer_candidate = role == "renderer-source-candidate"
    if (
        captured.tzinfo is None
        or value.get("status")
        != (
            "active-rom-source-role-unresolved"
            if role == "unclassified-data"
            else "active-rom-source-role-classified"
        )
        or value.get("script_record_source_confirmed") is not script_confirmed
        or value.get("renderer_asset_source_candidate") is not renderer_candidate
        or value.get("baseline_script_bytes_unchanged") is not True
        or value.get("translation_build_eligible") is not False
        or value.get("local_payload_policy")
        != "addresses-opcodes-registers-record-coordinates-and-ROM-bytes-local-only"
        or value.get("next_checkpoint") != _next_checkpoint(str(role))
    ):
        raise ValueError("active ROM source role result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    required = {
        "rom": rom_path,
        "trace_safe": root / REGISTER_TRACE_PATH,
        "trace_local": root / REGISTER_TRACE_LOCAL_PATH,
        "source_safe": root / ROM_SOURCE_PATH,
        "source_local": root / ROM_SOURCE_LOCAL_PATH,
        "route_safe": root / ACTIVE_VRAM_ROUTE_PATH,
        "population_safe": root / TARGET_POPULATION_PATH,
        "population_local": root / TARGET_POPULATION_LOCAL_PATH,
    }
    if not all(path.is_file() for path in required.values()):
        if args.if_ready:
            print("Active ROM source role classification is not ready")
            return 0
        raise SystemExit("active ROM source role input is missing")
    trace_safe = _load_object(required["trace_safe"])
    trace_local = _load_object(required["trace_local"])
    source_safe = _load_object(required["source_safe"])
    source_local = _load_object(required["source_local"])
    route_safe = _load_object(required["route_safe"])
    population_safe = _load_object(required["population_safe"])
    population_local = _load_object(required["population_local"])
    validate_active_ram_register_trace(trace_safe)
    validate_active_register_rom_source(source_safe)
    validate_active_vram_route(route_safe)
    validate_target_group_population(population_safe)
    target_sha256 = sha256_file(rom_path)
    if (
        trace_safe.get("target_sha256") != target_sha256
        or source_safe.get("target_sha256") != target_sha256
        or route_safe.get("target_sha256") != target_sha256
        or population_safe.get("target_sha256") != target_sha256
        or source_safe.get("source_register_trace_sha256")
        != sha256_file(required["trace_safe"])
        or source_safe.get("rom_source_confirmed") is not True
    ):
        raise ValueError("active ROM source role identities disagree")
    selected = trace_local.get("analysis", {}).get("selected")
    lines = trace_local.get("raw_trace_lines")
    if not isinstance(selected, dict) or not isinstance(lines, list) or not all(
        isinstance(line, str) for line in lines
    ):
        raise ValueError("active ROM source role trace payload is missing")
    logical_source = int(source_local["logical_source"])
    mapped_bank = int(source_safe["mapped_bank"])
    physical_source_offset = int(source_safe["physical_source_offset"])
    if (
        int(source_local["mapped_bank"]) != mapped_bank
        or int(source_local["physical_source_offset"]) != physical_source_offset
    ):
        raise ValueError("active ROM source role local mapping disagrees")
    reads, executed, matching_events = collect_matching_reads(lines, selected)
    target_transfer_count = int(route_safe["analysis"]["target_transfer_count"])
    records = _flatten_records(population_local)
    counts, local_analysis = analyze_source_role(
        logical_reads=reads,
        logical_source=logical_source,
        mapped_bank=mapped_bank,
        physical_source_offset=physical_source_offset,
        target_transfer_count=target_transfer_count,
        records=records,
        executed_physical_offsets=executed,
        matching_definition_event_count=matching_events,
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    safe = build_active_rom_source_role(
        target_sha256=target_sha256,
        source_active_register_rom_source_sha256=sha256_file(required["source_safe"]),
        source_register_trace_sha256=sha256_file(required["trace_safe"]),
        source_target_population_sha256=sha256_file(required["population_safe"]),
        analysis=counts,
        source_role_name=str(local_analysis["source_role"]),
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-s25u-active-rom-source-role",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "source_active_register_rom_source_sha256":
            sha256_file(required["source_safe"]),
        "captured_utc": captured_utc,
        "analysis": local_analysis["local"],
        "publication_policy": (
            "never-publish-addresses-opcodes-registers-record-coordinates-or-ROM-bytes"
        ),
    }
    publish_path = root / PUBLISH_RELATIVE_PATH
    local_path = root / LOCAL_REPORT_PATH
    publish_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    publish_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"SFKR active ROM source role: {publish_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
