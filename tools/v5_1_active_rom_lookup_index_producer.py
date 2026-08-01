#!/usr/bin/env python3
"""Bound the producer of the address used by the active ROM lookup candidate."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_active_ram_register_trace import (
        LOCAL_REPORT_PATH as REGISTER_TRACE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as REGISTER_TRACE_PATH,
        _defined_registers,
        validate_active_ram_register_trace,
    )
    from .v5_1_active_rom_read_block import (
        LOCAL_REPORT_PATH as READ_BLOCK_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as READ_BLOCK_PATH,
        validate_active_rom_read_block,
    )
    from .v5_1_active_rom_source_role import (
        PUBLISH_RELATIVE_PATH as SOURCE_ROLE_PATH,
        validate_active_rom_source_role,
    )
    from .v5_1_renderer_output_trace import DEFAULT_ROM
    from .v5_1_runtime_hit_resolver import (
        _parse_trace_line,
        _read_addresses,
        _read_operand_kind,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_active_ram_register_trace import (
        LOCAL_REPORT_PATH as REGISTER_TRACE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as REGISTER_TRACE_PATH,
        _defined_registers,
        validate_active_ram_register_trace,
    )
    from v5_1_active_rom_read_block import (
        LOCAL_REPORT_PATH as READ_BLOCK_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as READ_BLOCK_PATH,
        validate_active_rom_read_block,
    )
    from v5_1_active_rom_source_role import (
        PUBLISH_RELATIVE_PATH as SOURCE_ROLE_PATH,
        validate_active_rom_source_role,
    )
    from v5_1_renderer_output_trace import DEFAULT_ROM
    from v5_1_runtime_hit_resolver import (
        _parse_trace_line,
        _read_addresses,
        _read_operand_kind,
    )


ARTIFACT_KIND = "sanitized-s25u-active-rom-lookup-index-producer"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_active_rom_lookup_index_producer.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_active_rom_lookup_index_producer.json"
)
MAX_BACKTRACK_INSTRUCTIONS = 32
PRODUCER_CLASSES = {
    "literal-address-selector-candidate",
    "register-arithmetic-selector-candidate",
    "incremental-cursor-candidate",
    "memory-pointer-selector-candidate",
    "stack-pointer-selector-candidate",
    "split-byte-selector-candidate",
    "mixed-producer-unresolved",
    "producer-not-observed",
    "absolute-read-no-register",
}
COUNT_KEYS = {
    "target_event_count",
    "target_unique_logical_read_count",
    "address_register_candidate_count",
    "matched_predecessor_definition_count",
    "unique_predecessor_instruction_count",
    "maximum_backtrack_instruction_count",
    "literal_pointer_definition_count",
    "arithmetic_pointer_definition_count",
    "incremental_pointer_definition_count",
    "memory_pointer_definition_count",
    "stack_pointer_definition_count",
    "split_pointer_definition_count",
    "unknown_pointer_definition_count",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_active_rom_read_block_sha256",
    "source_active_rom_source_role_sha256",
    "source_register_trace_sha256",
    "captured_utc",
    "analysis",
    "address_operand_kind",
    "producer_class",
    "producer_candidate_bounded",
    "lookup_index_producer_confirmed",
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
        raise ValueError(f"lookup index producer input is not an object: {path}")
    return value


def _operand_register(opcodes: bytes) -> str | None:
    kind = _read_operand_kind(opcodes)
    return {
        "bc-indirect": "bc",
        "de-indirect": "de",
        "hl-indirect": "hl",
        "hl-bit": "hl",
        "block-forward": "hl",
        "block-backward": "hl",
    }.get(kind)


def _register_members(name: str) -> set[str]:
    return {
        "bc": {"b", "c"},
        "de": {"d", "e"},
        "hl": {"h", "l"},
    }[name]


def _definition_members(opcodes: bytes) -> set[str]:
    members = set(_defined_registers(opcodes))
    if not opcodes:
        return members
    first = opcodes[0]
    if first in {0x09, 0x19, 0x29, 0x39}:
        members.update({"h", "l"})
    if first == 0xED and len(opcodes) >= 2:
        members.update({
            0x4B: {"b", "c"},
            0x5B: {"d", "e"},
            0x6B: {"h", "l"},
        }.get(opcodes[1], set()))
    return members


def _definition_category(opcodes: bytes, register: str) -> str:
    if not opcodes:
        return "unknown"
    first = opcodes[0]
    literal = {"bc": 0x01, "de": 0x11, "hl": 0x21}[register]
    increment = {"bc": {0x03, 0x0B}, "de": {0x13, 0x1B}, "hl": {0x23, 0x2B}}[register]
    stack = {"bc": 0xC1, "de": 0xD1, "hl": 0xE1}[register]
    if first == literal:
        return "literal"
    if first in increment:
        return "incremental"
    if register == "hl" and first in {0x09, 0x19, 0x29, 0x39}:
        return "arithmetic"
    if (
        register == "hl" and first == 0x2A
    ) or (
        first == 0xED
        and len(opcodes) >= 2
        and opcodes[1] == {"bc": 0x4B, "de": 0x5B, "hl": 0x6B}[register]
    ):
        return "memory"
    if first == stack:
        return "stack"
    if _definition_members(opcodes) & _register_members(register):
        return "split"
    return "unknown"


def _physical_pc(bank: int, pc: int) -> int:
    if pc < 0x4000:
        return pc
    if pc < 0xC000:
        return bank * 0x4000 + (pc & 0x3FFF)
    return -1


def _producer_class(categories: Counter[str], matched: int, total: int) -> str:
    if total == 0:
        return "producer-not-observed"
    if matched == 0:
        return "producer-not-observed"
    nonzero = [name for name, count in categories.items() if count]
    if matched != total or len(nonzero) != 1:
        return "mixed-producer-unresolved"
    return {
        "literal": "literal-address-selector-candidate",
        "arithmetic": "register-arithmetic-selector-candidate",
        "incremental": "incremental-cursor-candidate",
        "memory": "memory-pointer-selector-candidate",
        "stack": "stack-pointer-selector-candidate",
        "split": "split-byte-selector-candidate",
        "unknown": "mixed-producer-unresolved",
    }[nonzero[0]]


def _next_checkpoint(producer_class: str) -> str:
    return {
        "literal-address-selector-candidate": "map-literal-selector-callers",
        "register-arithmetic-selector-candidate": "trace-lookup-index-operand-producer",
        "incremental-cursor-candidate": "capture-cursor-reset-and-stride",
        "memory-pointer-selector-candidate": "map-pointer-table-source",
        "stack-pointer-selector-candidate": "trace-stack-loaded-pointer-source",
        "split-byte-selector-candidate": "trace-split-pointer-byte-producers",
        "mixed-producer-unresolved": "capture-narrow-target-predecessor-trace",
        "producer-not-observed": "capture-narrow-target-predecessor-trace",
        "absolute-read-no-register": "map-absolute-read-callers",
    }[producer_class]


def analyze_lookup_index_producer(
    *,
    lines: list[str],
    selected: dict[str, object],
) -> tuple[dict[str, int], dict[str, object]]:
    parsed = [value for line in lines if (value := _parse_trace_line(line)) is not None]
    expected_bank = int(selected["bank"])
    expected_pc = int(selected["pc"])
    expected_opcodes = bytes.fromhex(str(selected["opcodes_hex"]))
    operand_kind = _read_operand_kind(expected_opcodes)
    register = _operand_register(expected_opcodes)
    target_events: list[tuple[int, dict[str, object], int]] = []
    for index, event in enumerate(parsed):
        if (
            int(event["bank"]) != expected_bank
            or int(event["pc"]) != expected_pc
            or event["opcodes"] != expected_opcodes
        ):
            continue
        registers = event["registers"]
        if not isinstance(registers, dict):
            continue
        reads = _read_addresses(expected_opcodes, {
            key: int(value)
            for key, value in registers.items()
            if isinstance(value, int) and not isinstance(value, bool)
        })
        if len(reads) == 1:
            target_events.append((index, event, reads[0]))
    if not target_events:
        raise ValueError("lookup index producer target instruction was not observed")
    if register is None:
        counts = {key: 0 for key in COUNT_KEYS}
        counts["target_event_count"] = len(target_events)
        counts["target_unique_logical_read_count"] = len({item[2] for item in target_events})
        return counts, {
            "address_operand_kind": operand_kind,
            "producer_class": "absolute-read-no-register",
            "local": {"target_events": target_events, "predecessors": []},
        }
    members = _register_members(register)
    predecessors: list[dict[str, object]] = []
    categories: Counter[str] = Counter()
    maximum_distance = 0
    for target_index, target, logical_read in target_events:
        found = None
        lower = max(-1, target_index - MAX_BACKTRACK_INSTRUCTIONS - 1)
        for previous_index in range(target_index - 1, lower, -1):
            previous = parsed[previous_index]
            opcodes = previous["opcodes"]
            if not isinstance(opcodes, bytes):
                continue
            if _definition_members(opcodes) & members:
                distance = target_index - previous_index
                category = _definition_category(opcodes, register)
                categories[category] += 1
                maximum_distance = max(maximum_distance, distance)
                found = {
                    "target_logical_read": logical_read,
                    "target_bank": int(target["bank"]),
                    "target_pc": int(target["pc"]),
                    "producer_bank": int(previous["bank"]),
                    "producer_pc": int(previous["pc"]),
                    "producer_physical_pc": _physical_pc(
                        int(previous["bank"]), int(previous["pc"])
                    ),
                    "producer_opcodes_hex": opcodes.hex(),
                    "producer_category": category,
                    "backtrack_instruction_count": distance,
                    "producer_registers_before": previous["registers"],
                    "target_registers": target["registers"],
                }
                break
        if found is not None:
            predecessors.append(found)
    producer_class = _producer_class(
        categories, len(predecessors), len(target_events)
    )
    unique_instructions = {
        (item["producer_physical_pc"], item["producer_opcodes_hex"])
        for item in predecessors
    }
    counts = {
        "target_event_count": len(target_events),
        "target_unique_logical_read_count": len({item[2] for item in target_events}),
        "address_register_candidate_count": 1,
        "matched_predecessor_definition_count": len(predecessors),
        "unique_predecessor_instruction_count": len(unique_instructions),
        "maximum_backtrack_instruction_count": maximum_distance,
        "literal_pointer_definition_count": categories["literal"],
        "arithmetic_pointer_definition_count": categories["arithmetic"],
        "incremental_pointer_definition_count": categories["incremental"],
        "memory_pointer_definition_count": categories["memory"],
        "stack_pointer_definition_count": categories["stack"],
        "split_pointer_definition_count": categories["split"],
        "unknown_pointer_definition_count": categories["unknown"],
    }
    return counts, {
        "address_operand_kind": operand_kind,
        "producer_class": producer_class,
        "local": {
            "address_register": register,
            "target_event_indices": [item[0] for item in target_events],
            "target_logical_read_sequence": [item[2] for item in target_events],
            "predecessors": predecessors,
            "producer_category_counts": dict(categories),
        },
    }


def build_active_rom_lookup_index_producer(
    *,
    target_sha256: str,
    source_active_rom_read_block_sha256: str,
    source_active_rom_source_role_sha256: str,
    source_register_trace_sha256: str,
    analysis: dict[str, int],
    address_operand_kind: str,
    producer_class: str,
    captured_utc: str,
) -> dict[str, object]:
    bounded = producer_class not in {
        "mixed-producer-unresolved", "producer-not-observed"
    }
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": "active-rom-lookup-index-producer-bounded",
        "target_sha256": target_sha256,
        "source_active_rom_read_block_sha256": source_active_rom_read_block_sha256,
        "source_active_rom_source_role_sha256": source_active_rom_source_role_sha256,
        "source_register_trace_sha256": source_register_trace_sha256,
        "captured_utc": captured_utc,
        "analysis": {key: int(analysis[key]) for key in COUNT_KEYS},
        "address_operand_kind": address_operand_kind,
        "producer_class": producer_class,
        "producer_candidate_bounded": bounded,
        "lookup_index_producer_confirmed": False,
        "baseline_script_bytes_unchanged": True,
        "local_payload_policy": (
            "addresses-opcodes-registers-values-and-event-indices-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": _next_checkpoint(producer_class),
    }
    validate_active_rom_lookup_index_producer(value)
    return value


def validate_active_rom_lookup_index_producer(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("lookup index producer fields do not match")
    counts = value.get("analysis")
    producer_class = value.get("producer_class")
    if (
        value.get("artifact_kind") != ARTIFACT_KIND
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("status") != "active-rom-lookup-index-producer-bounded"
        or not _is_sha256(value.get("target_sha256"))
        or not _is_sha256(value.get("source_active_rom_read_block_sha256"))
        or not _is_sha256(value.get("source_active_rom_source_role_sha256"))
        or not _is_sha256(value.get("source_register_trace_sha256"))
        or not isinstance(value.get("address_operand_kind"), str)
        or producer_class not in PRODUCER_CLASSES
        or not isinstance(counts, dict)
        or set(counts) != COUNT_KEYS
    ):
        raise ValueError("lookup index producer policy is invalid")
    if any(
        not isinstance(counts[key], int)
        or isinstance(counts[key], bool)
        or counts[key] < 0
        for key in COUNT_KEYS
    ):
        raise ValueError("lookup index producer count is invalid")
    categorized = sum(
        counts[key]
        for key in COUNT_KEYS
        if key.endswith("_pointer_definition_count")
    )
    if (
        counts["target_event_count"] < counts["matched_predecessor_definition_count"]
        or categorized != counts["matched_predecessor_definition_count"]
    ):
        raise ValueError("lookup index producer aggregates disagree")
    try:
        captured = datetime.fromisoformat(
            str(value["captured_utc"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError("lookup index producer timestamp is invalid") from error
    bounded = producer_class not in {
        "mixed-producer-unresolved", "producer-not-observed"
    }
    if (
        captured.tzinfo is None
        or value.get("producer_candidate_bounded") is not bounded
        or value.get("lookup_index_producer_confirmed") is not False
        or value.get("baseline_script_bytes_unchanged") is not True
        or value.get("local_payload_policy")
        != "addresses-opcodes-registers-values-and-event-indices-local-only"
        or value.get("translation_build_eligible") is not False
        or value.get("next_checkpoint") != _next_checkpoint(str(producer_class))
    ):
        raise ValueError("lookup index producer result is inconsistent")


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
        "role_safe": root / SOURCE_ROLE_PATH,
        "read_safe": root / READ_BLOCK_PATH,
        "read_local": root / READ_BLOCK_LOCAL_PATH,
    }
    if not all(path.is_file() for path in required.values()):
        if args.if_ready:
            print("Active ROM lookup index producer is not ready")
            return 0
        raise SystemExit("active ROM lookup index producer input is missing")
    trace_safe = _load_object(required["trace_safe"])
    trace_local = _load_object(required["trace_local"])
    role_safe = _load_object(required["role_safe"])
    read_safe = _load_object(required["read_safe"])
    read_local = _load_object(required["read_local"])
    validate_active_ram_register_trace(trace_safe)
    validate_active_rom_source_role(role_safe)
    validate_active_rom_read_block(read_safe)
    target_sha256 = sha256_file(rom_path)
    if (
        read_safe.get("target_sha256") != target_sha256
        or trace_safe.get("target_sha256") != target_sha256
        or role_safe.get("target_sha256") != target_sha256
        or read_safe.get("access_pattern") not in {
            "fixed-stride-lookup-candidate", "scattered-lookup-candidate"
        }
        or read_safe.get("source_active_rom_source_role_sha256")
        != sha256_file(required["role_safe"])
        or role_safe.get("source_register_trace_sha256")
        != sha256_file(required["trace_safe"])
        or read_local.get("target_sha256") != target_sha256
        or read_local.get("source_active_rom_source_role_sha256")
        != sha256_file(required["role_safe"])
    ):
        if args.if_ready and read_safe.get("lookup_table_candidate") is not True:
            print("Active ROM lookup index producer is not required")
            return 0
        raise ValueError("active ROM lookup index producer identities disagree")
    selected = trace_local.get("analysis", {}).get("selected")
    lines = trace_local.get("raw_trace_lines")
    if not isinstance(selected, dict) or not isinstance(lines, list) or not all(
        isinstance(line, str) for line in lines
    ):
        raise ValueError("active ROM lookup index producer trace payload is missing")
    counts, result = analyze_lookup_index_producer(lines=lines, selected=selected)
    expected_events = int(read_safe["analysis"]["read_occurrence_count"])
    expected_unique = int(read_safe["analysis"]["unique_logical_read_count"])
    if (
        counts["target_event_count"] != expected_events
        or counts["target_unique_logical_read_count"] != expected_unique
    ):
        raise ValueError("active ROM lookup index producer event population disagrees")
    captured_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    safe = build_active_rom_lookup_index_producer(
        target_sha256=target_sha256,
        source_active_rom_read_block_sha256=sha256_file(required["read_safe"]),
        source_active_rom_source_role_sha256=sha256_file(required["role_safe"]),
        source_register_trace_sha256=sha256_file(required["trace_safe"]),
        analysis=counts,
        address_operand_kind=str(result["address_operand_kind"]),
        producer_class=str(result["producer_class"]),
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-s25u-active-rom-lookup-index-producer",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "source_active_rom_read_block_sha256": sha256_file(required["read_safe"]),
        "captured_utc": captured_utc,
        "analysis": result["local"],
        "publication_policy": (
            "never-publish-addresses-opcodes-registers-values-or-event-indices"
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
    print(f"SFKR active ROM lookup index producer: {publish_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
