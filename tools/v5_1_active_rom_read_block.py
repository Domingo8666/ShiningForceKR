#!/usr/bin/env python3
"""Bound the active ROM read pattern before choosing an extraction strategy."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_active_register_rom_source import (
        PUBLISH_RELATIVE_PATH as ROM_SOURCE_PATH,
        source_slot,
        validate_active_register_rom_source,
    )
    from .v5_1_active_rom_source_role import (
        LOCAL_REPORT_PATH as SOURCE_ROLE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as SOURCE_ROLE_PATH,
        validate_active_rom_source_role,
    )
    from .v5_1_renderer_output_trace import DEFAULT_ROM
    from .v5_1_target_group_population import (
        LOCAL_REPORT_PATH as TARGET_POPULATION_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as TARGET_POPULATION_PATH,
        validate_target_group_population,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_active_register_rom_source import (
        PUBLISH_RELATIVE_PATH as ROM_SOURCE_PATH,
        source_slot,
        validate_active_register_rom_source,
    )
    from v5_1_active_rom_source_role import (
        LOCAL_REPORT_PATH as SOURCE_ROLE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as SOURCE_ROLE_PATH,
        validate_active_rom_source_role,
    )
    from v5_1_renderer_output_trace import DEFAULT_ROM
    from v5_1_target_group_population import (
        LOCAL_REPORT_PATH as TARGET_POPULATION_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as TARGET_POPULATION_PATH,
        validate_target_group_population,
    )


ARTIFACT_KIND = "sanitized-s25u-active-rom-read-block"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_active_rom_read_block.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_active_rom_read_block.json")
ACCESS_PATTERNS = {
    "script-record-neighborhood-candidate",
    "contiguous-block-candidate",
    "fixed-stride-lookup-candidate",
    "scattered-lookup-candidate",
    "single-source-value",
    "mixed-unresolved",
}
COUNT_KEYS = {
    "read_occurrence_count",
    "unique_logical_read_count",
    "unique_physical_projection_count",
    "physical_projection_byte_span",
    "contiguous_run_count",
    "maximum_contiguous_run_bytes",
    "singleton_run_count",
    "repeated_read_occurrence_count",
    "forward_sequential_transition_count",
    "backward_sequential_transition_count",
    "same_address_transition_count",
    "fixed_stride_bytes",
    "script_record_projection_match_count",
    "script_payload_projection_match_count",
    "script_length_projection_match_count",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_active_rom_source_role_sha256",
    "source_active_register_rom_source_sha256",
    "source_target_population_sha256",
    "captured_utc",
    "analysis",
    "access_pattern",
    "lookup_table_candidate",
    "script_record_neighborhood_candidate",
    "contiguous_block_candidate",
    "mapper_snapshot_projection_only",
    "baseline_script_bytes_unchanged",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"active ROM read block input is not an object: {path}")
    return value


def _flatten_records(population_local: dict[str, object]) -> list[dict[str, object]]:
    analysis = population_local.get("analysis")
    if not isinstance(analysis, dict) or not isinstance(analysis.get("groups"), list):
        raise ValueError("active ROM read block population groups are missing")
    records: list[dict[str, object]] = []
    for group in analysis["groups"]:
        if not isinstance(group, dict) or not isinstance(group.get("records"), list):
            raise ValueError("active ROM read block population group is invalid")
        for record in group["records"]:
            if not isinstance(record, dict):
                raise ValueError("active ROM read block population record is invalid")
            records.append(record)
    return records


def _contiguous_runs(values: list[int]) -> list[list[int]]:
    if not values:
        return []
    runs = [[values[0]]]
    for value in values[1:]:
        if value == runs[-1][-1] + 1:
            runs[-1].append(value)
        else:
            runs.append([value])
    return runs


def _next_checkpoint(pattern: str) -> str:
    return {
        "script-record-neighborhood-candidate":
            "correlate-projected-script-records-with-consumer",
        "contiguous-block-candidate":
            "correlate-contiguous-rom-block-with-vram-output",
        "fixed-stride-lookup-candidate": "trace-active-rom-lookup-index-producer",
        "scattered-lookup-candidate": "trace-active-rom-lookup-index-producer",
        "single-source-value": "trace-single-rom-value-consumer",
        "mixed-unresolved": "capture-register-index-transition",
    }[pattern]


def analyze_active_rom_reads(
    *,
    logical_reads: list[int],
    logical_source: int,
    mapped_bank: int,
    records: list[dict[str, object]],
    rom: bytes,
) -> tuple[dict[str, int], dict[str, object]]:
    if not logical_reads:
        raise ValueError("active ROM read block has no read occurrences")
    slot = source_slot(logical_source)
    if any(source_slot(address) != slot for address in logical_reads):
        raise ValueError("active ROM read block crosses mapper slots")
    physical_reads = [
        mapped_bank * 0x4000 + (address & 0x3FFF)
        for address in logical_reads
    ]
    if any(not 0 <= offset < len(rom) for offset in physical_reads):
        raise ValueError("active ROM read block projection is out of range")
    unique_logical = sorted(set(logical_reads))
    unique_physical = sorted(set(physical_reads))
    runs = _contiguous_runs(unique_physical)
    gaps = [right - left for left, right in zip(unique_physical, unique_physical[1:])]
    fixed_stride = (
        gaps[0]
        if len(gaps) >= 2 and gaps[0] > 1 and len(set(gaps)) == 1
        else 0
    )
    matches: list[dict[str, object]] = []
    payload_match_count = 0
    length_match_count = 0
    for offset in unique_physical:
        for record in records:
            try:
                length_offset = int(record["length_offset"])
                payload_start = int(record["payload_start"])
                payload_end = int(record["payload_end"])
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError("active ROM read block record bounds are invalid") from error
            match_kind = None
            if offset == length_offset:
                length_match_count += 1
                match_kind = "length"
            elif payload_start <= offset < payload_end:
                payload_match_count += 1
                match_kind = "payload"
            if match_kind is not None:
                matches.append({
                    "physical_offset": offset,
                    "match_kind": match_kind,
                    "selector": record.get("selector"),
                    "ordinal": record.get("ordinal"),
                })
    maximum_run = max((len(run) for run in runs), default=0)
    repeated = len(logical_reads) - len(unique_logical)
    if matches:
        pattern = "script-record-neighborhood-candidate"
    elif maximum_run >= 8:
        pattern = "contiguous-block-candidate"
    elif fixed_stride > 0:
        pattern = "fixed-stride-lookup-candidate"
    elif len(unique_logical) >= 3 and repeated > 0:
        pattern = "scattered-lookup-candidate"
    elif len(unique_logical) == 1:
        pattern = "single-source-value"
    else:
        pattern = "mixed-unresolved"
    counts = {
        "read_occurrence_count": len(logical_reads),
        "unique_logical_read_count": len(unique_logical),
        "unique_physical_projection_count": len(unique_physical),
        "physical_projection_byte_span":
            unique_physical[-1] - unique_physical[0] + 1,
        "contiguous_run_count": len(runs),
        "maximum_contiguous_run_bytes": maximum_run,
        "singleton_run_count": sum(len(run) == 1 for run in runs),
        "repeated_read_occurrence_count": repeated,
        "forward_sequential_transition_count": sum(
            right == left + 1 for left, right in zip(logical_reads, logical_reads[1:])
        ),
        "backward_sequential_transition_count": sum(
            right == left - 1 for left, right in zip(logical_reads, logical_reads[1:])
        ),
        "same_address_transition_count": sum(
            right == left for left, right in zip(logical_reads, logical_reads[1:])
        ),
        "fixed_stride_bytes": fixed_stride,
        "script_record_projection_match_count": len(matches),
        "script_payload_projection_match_count": payload_match_count,
        "script_length_projection_match_count": length_match_count,
    }
    occurrences = Counter(logical_reads)
    local = {
        "logical_read_sequence": logical_reads,
        "unique_logical_reads": unique_logical,
        "physical_projection_sequence": physical_reads,
        "unique_physical_projections": unique_physical,
        "physical_projection_runs": [
            {"start": run[0], "end": run[-1], "byte_count": len(run)}
            for run in runs
        ],
        "physical_projection_gaps": gaps,
        "read_occurrences": [
            {"logical_address": address, "count": occurrences[address]}
            for address in unique_logical
        ],
        "projected_rom_values": [
            {"physical_offset": offset, "value": rom[offset]}
            for offset in unique_physical
        ],
        "script_record_projection_matches": matches,
        "projection_basis": "single-confirmed-mapper-snapshot",
    }
    return counts, {"access_pattern": pattern, "local": local}


def build_active_rom_read_block(
    *,
    target_sha256: str,
    source_active_rom_source_role_sha256: str,
    source_active_register_rom_source_sha256: str,
    source_target_population_sha256: str,
    analysis: dict[str, int],
    access_pattern: str,
    captured_utc: str,
) -> dict[str, object]:
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": "active-rom-read-pattern-bounded",
        "target_sha256": target_sha256,
        "source_active_rom_source_role_sha256":
            source_active_rom_source_role_sha256,
        "source_active_register_rom_source_sha256":
            source_active_register_rom_source_sha256,
        "source_target_population_sha256": source_target_population_sha256,
        "captured_utc": captured_utc,
        "analysis": {key: int(analysis[key]) for key in COUNT_KEYS},
        "access_pattern": access_pattern,
        "lookup_table_candidate": access_pattern in {
            "fixed-stride-lookup-candidate", "scattered-lookup-candidate"
        },
        "script_record_neighborhood_candidate":
            access_pattern == "script-record-neighborhood-candidate",
        "contiguous_block_candidate":
            access_pattern == "contiguous-block-candidate",
        "mapper_snapshot_projection_only": True,
        "baseline_script_bytes_unchanged": True,
        "local_payload_policy": (
            "addresses-values-record-coordinates-and-ROM-bytes-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": _next_checkpoint(access_pattern),
    }
    validate_active_rom_read_block(value)
    return value


def validate_active_rom_read_block(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("active ROM read block fields do not match")
    pattern = value.get("access_pattern")
    counts = value.get("analysis")
    if (
        value.get("artifact_kind") != ARTIFACT_KIND
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("status") != "active-rom-read-pattern-bounded"
        or pattern not in ACCESS_PATTERNS
        or not _is_sha256(value.get("target_sha256"))
        or not _is_sha256(value.get("source_active_rom_source_role_sha256"))
        or not _is_sha256(value.get("source_active_register_rom_source_sha256"))
        or not _is_sha256(value.get("source_target_population_sha256"))
        or not isinstance(counts, dict)
        or set(counts) != COUNT_KEYS
    ):
        raise ValueError("active ROM read block policy is invalid")
    if any(
        not isinstance(counts[key], int)
        or isinstance(counts[key], bool)
        or counts[key] < 0
        for key in COUNT_KEYS
    ):
        raise ValueError("active ROM read block count is invalid")
    if (
        counts["read_occurrence_count"] < counts["unique_logical_read_count"]
        or counts["repeated_read_occurrence_count"]
        != counts["read_occurrence_count"] - counts["unique_logical_read_count"]
        or counts["unique_logical_read_count"]
        != counts["unique_physical_projection_count"]
    ):
        raise ValueError("active ROM read block aggregates disagree")
    try:
        captured = datetime.fromisoformat(
            str(value["captured_utc"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError("active ROM read block timestamp is invalid") from error
    if (
        captured.tzinfo is None
        or value.get("lookup_table_candidate")
        is not (pattern in {
            "fixed-stride-lookup-candidate", "scattered-lookup-candidate"
        })
        or value.get("script_record_neighborhood_candidate")
        is not (pattern == "script-record-neighborhood-candidate")
        or value.get("contiguous_block_candidate")
        is not (pattern == "contiguous-block-candidate")
        or value.get("mapper_snapshot_projection_only") is not True
        or value.get("baseline_script_bytes_unchanged") is not True
        or value.get("translation_build_eligible") is not False
        or value.get("local_payload_policy")
        != "addresses-values-record-coordinates-and-ROM-bytes-local-only"
        or value.get("next_checkpoint") != _next_checkpoint(str(pattern))
    ):
        raise ValueError("active ROM read block result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    required = {
        "rom": rom_path,
        "source_safe": root / ROM_SOURCE_PATH,
        "role_safe": root / SOURCE_ROLE_PATH,
        "role_local": root / SOURCE_ROLE_LOCAL_PATH,
        "population_safe": root / TARGET_POPULATION_PATH,
        "population_local": root / TARGET_POPULATION_LOCAL_PATH,
    }
    if not all(path.is_file() for path in required.values()):
        if args.if_ready:
            print("Active ROM read block is not ready")
            return 0
        raise SystemExit("active ROM read block input is missing")
    source_safe = _load_object(required["source_safe"])
    role_safe = _load_object(required["role_safe"])
    role_local = _load_object(required["role_local"])
    population_safe = _load_object(required["population_safe"])
    population_local = _load_object(required["population_local"])
    validate_active_register_rom_source(source_safe)
    validate_active_rom_source_role(role_safe)
    validate_target_group_population(population_safe)
    rom = rom_path.read_bytes()
    target_sha256 = sha256_file(rom_path)
    role_sha256 = sha256_file(required["role_safe"])
    if (
        role_safe.get("source_role") != "unclassified-data"
        or source_safe.get("target_sha256") != target_sha256
        or role_safe.get("target_sha256") != target_sha256
        or population_safe.get("target_sha256") != target_sha256
        or role_safe.get("source_active_register_rom_source_sha256")
        != sha256_file(required["source_safe"])
        or role_safe.get("source_target_population_sha256")
        != sha256_file(required["population_safe"])
        or role_local.get("target_sha256") != target_sha256
        or role_local.get("source_active_register_rom_source_sha256")
        != sha256_file(required["source_safe"])
    ):
        if args.if_ready and role_safe.get("source_role") != "unclassified-data":
            print("Active ROM read block is not required")
            return 0
        raise ValueError("active ROM read block identities disagree")
    local_analysis = role_local.get("analysis")
    if not isinstance(local_analysis, dict):
        raise ValueError("active ROM read block role payload is missing")
    logical_reads = local_analysis.get("logical_reads")
    if not isinstance(logical_reads, list) or not all(
        isinstance(value, int) and not isinstance(value, bool)
        for value in logical_reads
    ):
        raise ValueError("active ROM read block read sequence is invalid")
    logical_source = int(local_analysis["logical_source"])
    mapped_bank = int(local_analysis["mapped_bank"])
    counts, result = analyze_active_rom_reads(
        logical_reads=logical_reads,
        logical_source=logical_source,
        mapped_bank=mapped_bank,
        records=_flatten_records(population_local),
        rom=rom,
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    safe = build_active_rom_read_block(
        target_sha256=target_sha256,
        source_active_rom_source_role_sha256=role_sha256,
        source_active_register_rom_source_sha256=sha256_file(required["source_safe"]),
        source_target_population_sha256=sha256_file(required["population_safe"]),
        analysis=counts,
        access_pattern=str(result["access_pattern"]),
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-s25u-active-rom-read-block",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "source_active_rom_source_role_sha256": role_sha256,
        "captured_utc": captured_utc,
        "analysis": result["local"],
        "publication_policy": (
            "never-publish-addresses-values-record-coordinates-or-ROM-bytes"
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
    print(f"SFKR active ROM read block: {publish_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
