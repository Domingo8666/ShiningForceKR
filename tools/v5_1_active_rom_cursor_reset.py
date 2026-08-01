#!/usr/bin/env python3
"""Resolve the reset source and stride of the active ROM cursor candidate."""

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
        validate_active_ram_register_trace,
    )
    from .v5_1_active_rom_lookup_index_producer import (
        LOCAL_REPORT_PATH as LOOKUP_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as LOOKUP_PATH,
        _definition_category,
        _definition_members,
        _operand_register,
        _register_members,
        validate_active_rom_lookup_index_producer,
    )
    from .v5_1_active_rom_read_block import (
        PUBLISH_RELATIVE_PATH as READ_BLOCK_PATH,
        validate_active_rom_read_block,
    )
    from .v5_1_renderer_output_trace import DEFAULT_ROM
    from .v5_1_runtime_hit_resolver import _parse_trace_line, _read_addresses
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_active_ram_register_trace import (
        LOCAL_REPORT_PATH as REGISTER_TRACE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as REGISTER_TRACE_PATH,
        validate_active_ram_register_trace,
    )
    from v5_1_active_rom_lookup_index_producer import (
        LOCAL_REPORT_PATH as LOOKUP_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as LOOKUP_PATH,
        _definition_category,
        _definition_members,
        _operand_register,
        _register_members,
        validate_active_rom_lookup_index_producer,
    )
    from v5_1_active_rom_read_block import (
        PUBLISH_RELATIVE_PATH as READ_BLOCK_PATH,
        validate_active_rom_read_block,
    )
    from v5_1_renderer_output_trace import DEFAULT_ROM
    from v5_1_runtime_hit_resolver import _parse_trace_line, _read_addresses


ARTIFACT_KIND = "sanitized-s25u-active-rom-cursor-reset"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_active_rom_cursor_reset.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_active_rom_cursor_reset.json")
MAX_RESET_BACKTRACK_INSTRUCTIONS = 256
RESET_CLASSES = {
    "literal-reset-fixed-stride-candidate",
    "memory-reset-fixed-stride-candidate",
    "stack-reset-fixed-stride-candidate",
    "split-reset-fixed-stride-candidate",
    "arithmetic-reset-fixed-stride-candidate",
    "mixed-reset-unresolved",
    "reset-outside-trace-window",
}
COUNT_KEYS = {
    "target_event_count",
    "target_unique_logical_read_count",
    "cursor_register_candidate_count",
    "incremental_producer_event_count",
    "positive_stride_event_count",
    "negative_stride_event_count",
    "unique_stride_count",
    "reset_definition_match_count",
    "unique_reset_instruction_count",
    "literal_reset_count",
    "memory_reset_count",
    "stack_reset_count",
    "split_reset_count",
    "arithmetic_reset_count",
    "unknown_reset_count",
    "reset_to_target_projection_match_count",
    "maximum_reset_backtrack_instruction_count",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_active_rom_lookup_index_producer_sha256",
    "source_active_rom_read_block_sha256",
    "source_register_trace_sha256",
    "captured_utc",
    "analysis",
    "reset_class",
    "fixed_stride_candidate",
    "cursor_reset_candidate_bounded",
    "cursor_semantics_confirmed",
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
        raise ValueError(f"cursor reset input is not an object: {path}")
    return value


def _signed_stride(opcodes: bytes, register: str) -> int | None:
    if not opcodes:
        return None
    return {
        "bc": {0x03: 1, 0x0B: -1},
        "de": {0x13: 1, 0x1B: -1},
        "hl": {0x23: 1, 0x2B: -1},
    }[register].get(opcodes[0])


def _literal_pair_value(opcodes: bytes, register: str) -> int | None:
    literal = {"bc": 0x01, "de": 0x11, "hl": 0x21}[register]
    if len(opcodes) >= 3 and opcodes[0] == literal:
        return opcodes[1] | (opcodes[2] << 8)
    return None


def _reset_class(
    categories: Counter[str],
    *,
    reset_count: int,
    target_count: int,
    unique_stride_count: int,
) -> str:
    if reset_count == 0:
        return "reset-outside-trace-window"
    active = [name for name, count in categories.items() if count]
    if reset_count != target_count or unique_stride_count != 1 or len(active) != 1:
        return "mixed-reset-unresolved"
    return {
        "literal": "literal-reset-fixed-stride-candidate",
        "memory": "memory-reset-fixed-stride-candidate",
        "stack": "stack-reset-fixed-stride-candidate",
        "split": "split-reset-fixed-stride-candidate",
        "arithmetic": "arithmetic-reset-fixed-stride-candidate",
        "unknown": "mixed-reset-unresolved",
    }.get(active[0], "mixed-reset-unresolved")


def _next_checkpoint(reset_class: str) -> str:
    return {
        "literal-reset-fixed-stride-candidate": "map-cursor-base-range-to-rom-consumer",
        "memory-reset-fixed-stride-candidate": "trace-cursor-reset-pointer-source",
        "stack-reset-fixed-stride-candidate": "trace-stack-reset-source",
        "split-reset-fixed-stride-candidate": "trace-split-reset-byte-sources",
        "arithmetic-reset-fixed-stride-candidate": "trace-reset-arithmetic-operands",
        "mixed-reset-unresolved": "capture-reset-focused-trace",
        "reset-outside-trace-window": "capture-reset-focused-trace",
    }[reset_class]


def analyze_cursor_reset(
    *,
    lines: list[str],
    selected: dict[str, object],
) -> tuple[dict[str, int], dict[str, object]]:
    parsed = [value for line in lines if (value := _parse_trace_line(line)) is not None]
    expected_bank = int(selected["bank"])
    expected_pc = int(selected["pc"])
    expected_opcodes = bytes.fromhex(str(selected["opcodes_hex"]))
    register = _operand_register(expected_opcodes)
    if register is None:
        raise ValueError("cursor reset target has no supported address register")
    members = _register_members(register)
    target_events: list[tuple[int, int]] = []
    for index, event in enumerate(parsed):
        if (
            int(event["bank"]) != expected_bank
            or int(event["pc"]) != expected_pc
            or event["opcodes"] != expected_opcodes
        ):
            continue
        registers = event.get("registers")
        if not isinstance(registers, dict):
            continue
        reads = _read_addresses(expected_opcodes, {
            key: int(value)
            for key, value in registers.items()
            if isinstance(value, int) and not isinstance(value, bool)
        })
        if len(reads) == 1:
            target_events.append((index, reads[0]))
    if not target_events:
        raise ValueError("cursor reset target instruction was not observed")
    resets: list[dict[str, object]] = []
    strides: list[int] = []
    reset_categories: Counter[str] = Counter()
    maximum_backtrack = 0
    projection_matches = 0
    incremental_events = 0
    for target_index, target_address in target_events:
        producer_index = None
        stride = None
        for previous_index in range(target_index - 1, max(-1, target_index - 33), -1):
            opcodes = parsed[previous_index]["opcodes"]
            if not isinstance(opcodes, bytes):
                continue
            candidate_stride = _signed_stride(opcodes, register)
            if candidate_stride is not None:
                producer_index = previous_index
                stride = candidate_stride
                break
            if _definition_members(opcodes) & members:
                break
        if producer_index is None or stride is None:
            continue
        incremental_events += 1
        strides.append(stride)
        increment_count = 1
        lower = max(-1, producer_index - MAX_RESET_BACKTRACK_INSTRUCTIONS - 1)
        for reset_index in range(producer_index - 1, lower, -1):
            reset_opcodes = parsed[reset_index]["opcodes"]
            if not isinstance(reset_opcodes, bytes):
                continue
            prior_stride = _signed_stride(reset_opcodes, register)
            if prior_stride == stride:
                increment_count += 1
                continue
            if not (_definition_members(reset_opcodes) & members):
                continue
            category = _definition_category(reset_opcodes, register)
            if category == "incremental":
                category = "unknown"
            reset_categories[category] += 1
            distance = target_index - reset_index
            maximum_backtrack = max(maximum_backtrack, distance)
            literal_value = _literal_pair_value(reset_opcodes, register)
            projection_match = (
                literal_value is not None
                and (literal_value + stride * increment_count) & 0xFFFF
                == target_address
            )
            projection_matches += int(projection_match)
            reset_event = parsed[reset_index]
            resets.append({
                "target_logical_read": target_address,
                "stride": stride,
                "increment_count_after_reset": increment_count,
                "reset_bank": int(reset_event["bank"]),
                "reset_pc": int(reset_event["pc"]),
                "reset_opcodes_hex": reset_opcodes.hex(),
                "reset_category": category,
                "reset_registers_before": reset_event["registers"],
                "literal_reset_value": literal_value,
                "literal_projection_match": projection_match,
                "backtrack_instruction_count": distance,
            })
            break
    unique_strides = set(strides)
    reset_class = _reset_class(
        reset_categories,
        reset_count=len(resets),
        target_count=len(target_events),
        unique_stride_count=len(unique_strides),
    )
    unique_reset_instructions = {
        (item["reset_bank"], item["reset_pc"], item["reset_opcodes_hex"])
        for item in resets
    }
    counts = {
        "target_event_count": len(target_events),
        "target_unique_logical_read_count": len({item[1] for item in target_events}),
        "cursor_register_candidate_count": 1,
        "incremental_producer_event_count": incremental_events,
        "positive_stride_event_count": sum(value > 0 for value in strides),
        "negative_stride_event_count": sum(value < 0 for value in strides),
        "unique_stride_count": len(unique_strides),
        "reset_definition_match_count": len(resets),
        "unique_reset_instruction_count": len(unique_reset_instructions),
        "literal_reset_count": reset_categories["literal"],
        "memory_reset_count": reset_categories["memory"],
        "stack_reset_count": reset_categories["stack"],
        "split_reset_count": reset_categories["split"],
        "arithmetic_reset_count": reset_categories["arithmetic"],
        "unknown_reset_count": reset_categories["unknown"],
        "reset_to_target_projection_match_count": projection_matches,
        "maximum_reset_backtrack_instruction_count": maximum_backtrack,
    }
    return counts, {
        "reset_class": reset_class,
        "local": {
            "cursor_register": register,
            "strides": strides,
            "target_logical_read_sequence": [item[1] for item in target_events],
            "reset_category_counts": dict(reset_categories),
            "resets": resets,
        },
    }


def build_active_rom_cursor_reset(
    *,
    target_sha256: str,
    source_active_rom_lookup_index_producer_sha256: str,
    source_active_rom_read_block_sha256: str,
    source_register_trace_sha256: str,
    analysis: dict[str, int],
    reset_class: str,
    captured_utc: str,
) -> dict[str, object]:
    bounded = reset_class not in {
        "mixed-reset-unresolved", "reset-outside-trace-window"
    }
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": "active-rom-cursor-reset-bounded",
        "target_sha256": target_sha256,
        "source_active_rom_lookup_index_producer_sha256":
            source_active_rom_lookup_index_producer_sha256,
        "source_active_rom_read_block_sha256": source_active_rom_read_block_sha256,
        "source_register_trace_sha256": source_register_trace_sha256,
        "captured_utc": captured_utc,
        "analysis": {key: int(analysis[key]) for key in COUNT_KEYS},
        "reset_class": reset_class,
        "fixed_stride_candidate": analysis["unique_stride_count"] == 1,
        "cursor_reset_candidate_bounded": bounded,
        "cursor_semantics_confirmed": False,
        "baseline_script_bytes_unchanged": True,
        "local_payload_policy": (
            "addresses-opcodes-registers-values-strides-and-event-indices-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": _next_checkpoint(reset_class),
    }
    validate_active_rom_cursor_reset(value)
    return value


def validate_active_rom_cursor_reset(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("cursor reset fields do not match")
    counts = value.get("analysis")
    reset_class = value.get("reset_class")
    if (
        value.get("artifact_kind") != ARTIFACT_KIND
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("status") != "active-rom-cursor-reset-bounded"
        or not _is_sha256(value.get("target_sha256"))
        or not _is_sha256(value.get("source_active_rom_lookup_index_producer_sha256"))
        or not _is_sha256(value.get("source_active_rom_read_block_sha256"))
        or not _is_sha256(value.get("source_register_trace_sha256"))
        or reset_class not in RESET_CLASSES
        or not isinstance(counts, dict)
        or set(counts) != COUNT_KEYS
    ):
        raise ValueError("cursor reset policy is invalid")
    if any(
        not isinstance(counts[key], int)
        or isinstance(counts[key], bool)
        or counts[key] < 0
        for key in COUNT_KEYS
    ):
        raise ValueError("cursor reset count is invalid")
    reset_categories = sum(
        counts[key]
        for key in (
            "literal_reset_count",
            "memory_reset_count",
            "stack_reset_count",
            "split_reset_count",
            "arithmetic_reset_count",
            "unknown_reset_count",
        )
    )
    if (
        counts["target_event_count"] < counts["incremental_producer_event_count"]
        or counts["incremental_producer_event_count"]
        != counts["positive_stride_event_count"] + counts["negative_stride_event_count"]
        or counts["reset_definition_match_count"] != reset_categories
        or counts["reset_definition_match_count"]
        < counts["reset_to_target_projection_match_count"]
    ):
        raise ValueError("cursor reset aggregates disagree")
    try:
        captured = datetime.fromisoformat(
            str(value["captured_utc"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError("cursor reset timestamp is invalid") from error
    bounded = reset_class not in {
        "mixed-reset-unresolved", "reset-outside-trace-window"
    }
    if (
        captured.tzinfo is None
        or value.get("fixed_stride_candidate")
        is not (counts["unique_stride_count"] == 1)
        or value.get("cursor_reset_candidate_bounded") is not bounded
        or value.get("cursor_semantics_confirmed") is not False
        or value.get("baseline_script_bytes_unchanged") is not True
        or value.get("local_payload_policy")
        != "addresses-opcodes-registers-values-strides-and-event-indices-local-only"
        or value.get("translation_build_eligible") is not False
        or value.get("next_checkpoint") != _next_checkpoint(str(reset_class))
    ):
        raise ValueError("cursor reset result is inconsistent")


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
        "read_safe": root / READ_BLOCK_PATH,
        "lookup_safe": root / LOOKUP_PATH,
        "lookup_local": root / LOOKUP_LOCAL_PATH,
    }
    if not all(path.is_file() for path in required.values()):
        if args.if_ready:
            print("Active ROM cursor reset is not ready")
            return 0
        raise SystemExit("active ROM cursor reset input is missing")
    trace_safe = _load_object(required["trace_safe"])
    trace_local = _load_object(required["trace_local"])
    read_safe = _load_object(required["read_safe"])
    lookup_safe = _load_object(required["lookup_safe"])
    lookup_local = _load_object(required["lookup_local"])
    validate_active_ram_register_trace(trace_safe)
    validate_active_rom_read_block(read_safe)
    validate_active_rom_lookup_index_producer(lookup_safe)
    target_sha256 = sha256_file(rom_path)
    if (
        trace_safe.get("target_sha256") != target_sha256
        or read_safe.get("target_sha256") != target_sha256
        or lookup_safe.get("target_sha256") != target_sha256
        or lookup_safe.get("producer_class") != "incremental-cursor-candidate"
        or lookup_safe.get("source_active_rom_read_block_sha256")
        != sha256_file(required["read_safe"])
        or lookup_safe.get("source_register_trace_sha256")
        != sha256_file(required["trace_safe"])
        or lookup_local.get("target_sha256") != target_sha256
        or lookup_local.get("source_active_rom_read_block_sha256")
        != sha256_file(required["read_safe"])
    ):
        if args.if_ready and lookup_safe.get("producer_class") != "incremental-cursor-candidate":
            print("Active ROM cursor reset is not required")
            return 0
        raise ValueError("active ROM cursor reset identities disagree")
    selected = trace_local.get("analysis", {}).get("selected")
    lines = trace_local.get("raw_trace_lines")
    if not isinstance(selected, dict) or not isinstance(lines, list) or not all(
        isinstance(line, str) for line in lines
    ):
        raise ValueError("active ROM cursor reset trace payload is missing")
    counts, result = analyze_cursor_reset(lines=lines, selected=selected)
    expected_events = int(lookup_safe["analysis"]["target_event_count"])
    if counts["target_event_count"] != expected_events:
        raise ValueError("active ROM cursor reset event population disagrees")
    captured_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    safe = build_active_rom_cursor_reset(
        target_sha256=target_sha256,
        source_active_rom_lookup_index_producer_sha256=sha256_file(
            required["lookup_safe"]
        ),
        source_active_rom_read_block_sha256=sha256_file(required["read_safe"]),
        source_register_trace_sha256=sha256_file(required["trace_safe"]),
        analysis=counts,
        reset_class=str(result["reset_class"]),
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-s25u-active-rom-cursor-reset",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "source_active_rom_lookup_index_producer_sha256": sha256_file(
            required["lookup_safe"]
        ),
        "captured_utc": captured_utc,
        "analysis": result["local"],
        "publication_policy": (
            "never-publish-addresses-opcodes-registers-values-strides-or-event-indices"
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
    print(f"SFKR active ROM cursor reset: {publish_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
