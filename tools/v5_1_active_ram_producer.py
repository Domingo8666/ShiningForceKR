#!/usr/bin/env python3
"""Trace the Z80 instructions that build the active dialogue RAM buffer.

The source addresses and byte values are consumed only from the ignored local
active-VRAM report.  The publishable artifact contains counts and identities,
never RAM addresses, byte values, opcodes, or writer PCs.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time

try:
    from .patch_io import sha256_file
    from .run_s25u_renderer_probe import (
        ATTRACT_ROUTE_SCHEDULE,
        _decoder_entry_mappings,
    )
    from .run_s25u_runtime_probe import (
        McpStdioClient,
        _default_command,
        _runtime_failure_receipt,
        _step_instruction_and_wait,
        _write_runtime_failure_receipt,
    )
    from .v5_1_active_vram_route import (
        LOCAL_REPORT_PATH as ACTIVE_LOCAL_REPORT_PATH,
        PUBLISH_RELATIVE_PATH as ACTIVE_ROUTE_PATH,
        RAM_REQUIRED_SIZE,
        _read_memory_area,
        _select_ram_area,
        validate_active_vram_route,
    )
    from .v5_1_renderer_output_trace import (
        DEFAULT_ROM,
        REQUIRED_TOOLS,
        _load_json_object,
        _registers,
        _remove_breakpoint,
        _set_execute_breakpoint,
    )
    from .v5_1_test_display_capture import (
        DECODER_ENTRY_LOGICAL,
        DECODER_ENTRY_TRACE_STEPS,
        DECODER_PAYLOAD_READY_LOGICAL,
        DECODER_SKIP_ENDPOINT_LOGICAL,
        _continue_until_breakpoint,
        _set_unlimited_fast_forward,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from run_s25u_renderer_probe import (
        ATTRACT_ROUTE_SCHEDULE,
        _decoder_entry_mappings,
    )
    from run_s25u_runtime_probe import (
        McpStdioClient,
        _default_command,
        _runtime_failure_receipt,
        _step_instruction_and_wait,
        _write_runtime_failure_receipt,
    )
    from v5_1_active_vram_route import (
        LOCAL_REPORT_PATH as ACTIVE_LOCAL_REPORT_PATH,
        PUBLISH_RELATIVE_PATH as ACTIVE_ROUTE_PATH,
        RAM_REQUIRED_SIZE,
        _read_memory_area,
        _select_ram_area,
        validate_active_vram_route,
    )
    from v5_1_renderer_output_trace import (
        DEFAULT_ROM,
        REQUIRED_TOOLS,
        _load_json_object,
        _registers,
        _remove_breakpoint,
        _set_execute_breakpoint,
    )
    from v5_1_test_display_capture import (
        DECODER_ENTRY_LOGICAL,
        DECODER_ENTRY_TRACE_STEPS,
        DECODER_PAYLOAD_READY_LOGICAL,
        DECODER_SKIP_ENDPOINT_LOGICAL,
        _continue_until_breakpoint,
        _set_unlimited_fast_forward,
    )


ARTIFACT_KIND = "sanitized-s25u-active-ram-producer"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_active_ram_producer.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_active_ram_producer.json")
PRODUCER_WATCH_TIMEOUT_SECONDS = 240.0
ENDPOINT_WATCH_TIMEOUT_SECONDS = 15.0
MAX_WRITE_WATCH_HITS = 4096
COUNT_KEYS = {
    "target_transfer_count",
    "target_address_count",
    "nonzero_target_address_count",
    "armed_write_range_count",
    "write_watch_hit_count",
    "parsed_target_write_event_count",
    "observed_target_write_count",
    "producer_covered_address_count",
    "producer_covered_nonzero_address_count",
    "unique_writer_count",
    "dominant_writer_address_count",
    "final_value_match_count",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_active_vram_route_sha256",
    "captured_utc",
    "runtime_entry",
    "analysis",
    "target_values_verified",
    "producer_route_confirmed",
    "baseline_script_bytes_unchanged",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
RUNTIME_ENTRY_KEYS = {
    "physical_start",
    "logical_start",
    "mapped_bank",
    "record_length_bytes",
    "selector_de",
    "entry_ordinal",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _ram_offset(logical_address: int) -> int | None:
    if not 0xC000 <= logical_address <= 0xFFFF:
        return None
    return logical_address & (RAM_REQUIRED_SIZE - 1)


def _source_adjustment(semantics: str) -> int:
    values = {
        "previous-transfer-step": -1,
        "reported-address": 0,
        "next-transfer-step": 1,
    }
    if semantics not in values:
        raise ValueError("active RAM source semantics are unresolved")
    return values[semantics]


def extract_target_values(
    active_route: dict[str, object],
    local_route: dict[str, object],
) -> tuple[dict[int, int], int]:
    """Recover the unique logical RAM bytes proved to feed active VRAM."""

    validate_active_vram_route(active_route)
    if (
        active_route["ram_source_route_confirmed"] is not True
        or active_route["next_checkpoint"]
        != "trace-active-ram-buffer-producer"
    ):
        raise ValueError("active RAM source route is not confirmed")
    if (
        local_route.get("artifact_kind") != "local-s25u-active-vram-route"
        or local_route.get("target_sha256") != active_route["target_sha256"]
    ):
        raise ValueError("local active RAM source identity disagrees")
    analysis = local_route.get("analysis")
    if not isinstance(analysis, dict):
        raise ValueError("local active RAM source analysis is missing")
    adjustment = _source_adjustment(
        str(active_route["ram_source_address_semantics"])
    )
    if analysis.get("selected_source_step_adjustment") != adjustment:
        raise ValueError("local active RAM source adjustment disagrees")
    transfers = analysis.get("ram_source_transfers")
    safe_analysis = active_route["analysis"]
    assert isinstance(safe_analysis, dict)
    expected_transfers = int(safe_analysis["ram_backed_vdp_data_write_count"])
    if not isinstance(transfers, list) or len(transfers) != expected_transfers:
        raise ValueError("local active RAM source transfer count disagrees")
    target_values: dict[int, int] = {}
    for transfer in transfers:
        if not isinstance(transfer, dict):
            raise ValueError("local active RAM source transfer is invalid")
        candidates = transfer.get("candidate_adjustments")
        if not isinstance(candidates, dict):
            raise ValueError("local active RAM source candidates are missing")
        candidate = candidates.get(str(adjustment))
        if not isinstance(candidate, dict):
            raise ValueError("selected local active RAM source is missing")
        logical_address = candidate.get("logical_address")
        value = candidate.get("source_after")
        if (
            not isinstance(logical_address, int)
            or isinstance(logical_address, bool)
            or _ram_offset(logical_address) is None
            or not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= 0xFF
            or candidate.get("source_stable") is not True
            or candidate.get("source_matches_resident_vram") is not True
        ):
            raise ValueError("selected local active RAM source is invalid")
        previous = target_values.get(logical_address)
        if previous is not None and previous != value:
            raise ValueError("active RAM source aliases disagree")
        target_values[logical_address] = value
    if not target_values:
        raise ValueError("active RAM source target is empty")
    return target_values, len(transfers)


def contiguous_address_ranges(addresses: list[int]) -> list[tuple[int, int]]:
    values = sorted(set(addresses))
    if not values:
        return []
    result: list[tuple[int, int]] = []
    start = previous = values[0]
    for address in values[1:]:
        if address != previous + 1:
            result.append((start, previous))
            start = address
        previous = address
    result.append((start, previous))
    return result


def _signed_byte(value: int) -> int:
    return value - 0x100 if value & 0x80 else value


def write_addresses(opcodes: bytes, registers: dict[str, int]) -> list[int]:
    """Return logical destinations for supported Z80 memory-write forms.

    Gearsystem trace registers describe the post-instruction state.  Block
    instructions therefore use the previous DE step, matching the independently
    measured OUTI/OTIR source semantics.
    """

    if not opcodes:
        return []
    first = opcodes[0]
    bc = registers.get("bc", 0) & 0xFFFF
    de = registers.get("de", 0) & 0xFFFF
    hl = registers.get("hl", 0) & 0xFFFF
    sp = registers.get("sp", 0) & 0xFFFF
    if first == 0x02:
        return [bc]
    if first == 0x12:
        return [de]
    if first in {0x08, 0x22} and len(opcodes) >= 3:
        address = opcodes[1] | (opcodes[2] << 8)
        return [address, (address + 1) & 0xFFFF]
    if first == 0x32 and len(opcodes) >= 3:
        return [opcodes[1] | (opcodes[2] << 8)]
    if first in {0x34, 0x35, 0x36, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x77}:
        return [hl]
    if first == 0xCB and len(opcodes) >= 2:
        operation = opcodes[1]
        if operation & 0x07 == 0x06 and operation >> 6 != 1:
            return [hl]
    if first in {0xDD, 0xFD} and len(opcodes) >= 3:
        base = registers.get("ix", 0) if first == 0xDD else registers.get("iy", 0)
        second = opcodes[1]
        if second == 0xCB and len(opcodes) >= 4:
            if opcodes[3] >> 6 != 1:
                return [(base + _signed_byte(opcodes[2])) & 0xFFFF]
        elif second in {0x34, 0x35, 0x36, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x77}:
            return [(base + _signed_byte(opcodes[2])) & 0xFFFF]
    if first == 0xED and len(opcodes) >= 2:
        second = opcodes[1]
        if second in {0x43, 0x53, 0x63, 0x73} and len(opcodes) >= 4:
            address = opcodes[2] | (opcodes[3] << 8)
            return [address, (address + 1) & 0xFFFF]
        if second in {0x67, 0x6F}:
            return [hl]
        if second in {0xA0, 0xB0}:  # LDI / LDIR
            return [(de - 1) & 0xFFFF]
        if second in {0xA8, 0xB8}:  # LDD / LDDR
            return [(de + 1) & 0xFFFF]
        if second in {0xA2, 0xB2}:  # INI / INIR
            return [(hl - 1) & 0xFFFF]
        if second in {0xAA, 0xBA}:  # IND / INDR
            return [(hl + 1) & 0xFFFF]
    if first in {0xC5, 0xD5, 0xE5, 0xF5}:
        return [sp, (sp + 1) & 0xFFFF]
    return []


def _write_operand_kind(opcodes: bytes) -> str:
    if not opcodes:
        return "unknown"
    first = opcodes[0]
    if first in {0x02, 0x12}:
        return "register-indirect-byte"
    if first in {0x08, 0x22, 0x32}:
        return "absolute-store"
    if first in {0x34, 0x35, 0x36, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x77}:
        return "hl-indirect"
    if first == 0xCB:
        return "hl-read-modify-write"
    if first in {0xDD, 0xFD}:
        return "indexed-store"
    if first == 0xED and len(opcodes) >= 2:
        if opcodes[1] in {0xA0, 0xA8, 0xB0, 0xB8}:
            return "block-copy"
        if opcodes[1] in {0xA2, 0xAA, 0xB2, 0xBA}:
            return "block-input"
        return "extended-store"
    if first in {0xC5, 0xD5, 0xE5, 0xF5}:
        return "stack-store"
    return "unknown"


def _supported_write_length(opcodes: bytes) -> int | None:
    if not opcodes:
        return None
    first = opcodes[0]
    if first in {
        0x02,
        0x12,
        0x34,
        0x35,
        0x70,
        0x71,
        0x72,
        0x73,
        0x74,
        0x75,
        0x77,
        0xC5,
        0xD5,
        0xE5,
        0xF5,
    }:
        return 1
    if first == 0x36:
        return 2
    if first in {0x08, 0x22, 0x32}:
        return 3
    if first == 0xCB:
        return 2
    if first in {0xDD, 0xFD} and len(opcodes) >= 2:
        if opcodes[1] == 0xCB:
            return 4
        if opcodes[1] == 0x36:
            return 4
        return 3
    if first == 0xED and len(opcodes) >= 2:
        return 4 if opcodes[1] in {0x43, 0x53, 0x63, 0x73} else 2
    return None


def previous_target_write(
    rom: bytes,
    state: dict[str, object],
    target_addresses: set[int],
) -> dict[str, object] | None:
    """Decode the just-completed write directly from the immutable ROM."""

    physical_end = int(state["physical_pc_after"])
    registers = _registers(state)
    candidates: list[dict[str, object]] = []
    for length in range(1, 5):
        physical_start = physical_end - length
        if not 0 <= physical_start < physical_end <= len(rom):
            continue
        opcodes = rom[physical_start:physical_end]
        if _supported_write_length(opcodes) != length:
            continue
        addresses = [
            address
            for address in write_addresses(opcodes, registers)
            if address in target_addresses
        ]
        if addresses:
            candidates.append(
                {
                    "bank": int(state["executing_bank"]),
                    "pc": (int(state["pc_after"]) - length) & 0xFFFF,
                    "physical_pc": physical_start,
                    "opcodes_hex": opcodes.hex(),
                    "operand_kind": _write_operand_kind(opcodes),
                    "registers": registers,
                    "addresses": addresses,
                }
            )
    return candidates[0] if len(candidates) == 1 else None


def _parse_hex_status(value: object, label: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"[0-9A-Fa-f]+", value) is None:
        raise RuntimeError(f"Gearsystem {label} is not a hex value")
    return int(value, 16)


def _capture_producer_state(
    client: McpStdioClient,
) -> tuple[dict[str, object], dict[str, object]]:
    """Capture only state needed by the write watch.

    Call-stack reconstruction is deliberately excluded: it is unrelated to
    identifying the completed memory-write instruction and can be unavailable
    at a memory breakpoint in Gearsystem.
    """

    status = client.call("debug_get_status")
    z80 = client.call("get_z80_status")
    registers = {
        key.lower(): _parse_hex_status(z80.get(key), key)
        for key in ("AF", "BC", "DE", "HL", "IX", "IY", "SP")
    }
    state: dict[str, object] = {
        "pc_after": _parse_hex_status(status.get("pc"), "pc"),
        "physical_pc_after": _parse_hex_status(
            z80.get("physical_PC"), "physical_PC"
        ),
        "executing_bank": _parse_hex_status(z80.get("bank"), "bank"),
        "registers": registers,
    }
    return state, {
        "status": status,
        "z80": z80,
    }


def analyze_capture(
    *,
    target_values: dict[int, int],
    target_transfer_count: int,
    final_ram: bytes,
    write_ranges: list[tuple[int, int]],
    write_watch_hit_count: int,
    events: list[dict[str, object]],
    latest_writer_event: dict[int, int],
) -> tuple[dict[str, int], dict[str, object]]:
    if len(final_ram) != RAM_REQUIRED_SIZE:
        raise ValueError("active RAM producer final snapshot size disagrees")
    final_values = {
        address: final_ram[_ram_offset(address)]  # type: ignore[index]
        for address in target_values
    }
    final_matches = {
        address
        for address, value in target_values.items()
        if final_values[address] == value
    }
    covered = set(latest_writer_event)
    nonzero = {address for address, value in target_values.items() if value != 0}
    writer_keys: Counter[tuple[int, int, str]] = Counter()
    for address, event_index in latest_writer_event.items():
        event = events[event_index]
        writer = event.get("writer")
        if not isinstance(writer, dict):
            raise ValueError("active RAM producer writer event is invalid")
        writer_keys[
            (
                int(writer["bank"]),
                int(writer["pc"]),
                str(writer["operand_kind"]),
            )
        ] += 1
    counts = {
        "target_transfer_count": target_transfer_count,
        "target_address_count": len(target_values),
        "nonzero_target_address_count": len(nonzero),
        "armed_write_range_count": len(write_ranges),
        "write_watch_hit_count": write_watch_hit_count,
        "parsed_target_write_event_count": len(events),
        "observed_target_write_count": sum(
            len(event.get("addresses", [])) for event in events
        ),
        "producer_covered_address_count": len(covered),
        "producer_covered_nonzero_address_count": len(covered & nonzero),
        "unique_writer_count": len(writer_keys),
        "dominant_writer_address_count": max(writer_keys.values(), default=0),
        "final_value_match_count": len(final_matches),
    }
    local = {
        "target_values": {
            f"0x{address:04X}": value
            for address, value in sorted(target_values.items())
        },
        "final_values": {
            f"0x{address:04X}": value
            for address, value in sorted(final_values.items())
        },
        "final_matching_addresses": [
            f"0x{address:04X}" for address in sorted(final_matches)
        ],
        "latest_writer_event": {
            f"0x{address:04X}": event_index
            for address, event_index in sorted(latest_writer_event.items())
        },
        "writer_groups": [
            {
                "bank": key[0],
                "pc": key[1],
                "operand_kind": key[2],
                "covered_address_count": count,
            }
            for key, count in writer_keys.most_common()
        ],
    }
    return counts, local


def build_active_ram_producer(
    *,
    target_sha256: str,
    source_active_vram_route_sha256: str,
    runtime_entry: dict[str, object],
    analysis: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    target_count = int(analysis["target_address_count"])
    nonzero_count = int(analysis["nonzero_target_address_count"])
    final_verified = (
        target_count > 0
        and int(analysis["final_value_match_count"]) == target_count
    )
    covered_nonzero = int(analysis["producer_covered_nonzero_address_count"])
    confirmed = (
        final_verified
        and nonzero_count > 0
        and covered_nonzero == nonzero_count
        and int(analysis["parsed_target_write_event_count"]) > 0
        and int(analysis["unique_writer_count"]) > 0
    )
    partial = not confirmed and int(analysis["producer_covered_address_count"]) > 0
    status = (
        "active-ram-producer-confirmed"
        if confirmed
        else "active-ram-producer-partial"
        if partial
        else "active-ram-producer-not-observed"
    )
    next_checkpoint = (
        "trace-active-ram-producer-inputs"
        if confirmed
        else "extend-active-ram-producer-watch"
        if partial or final_verified
        else "correct-active-ram-producer-anchor"
    )
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": target_sha256,
        "source_active_vram_route_sha256": source_active_vram_route_sha256,
        "captured_utc": captured_utc,
        "runtime_entry": {key: runtime_entry[key] for key in RUNTIME_ENTRY_KEYS},
        "analysis": {key: int(analysis[key]) for key in COUNT_KEYS},
        "target_values_verified": final_verified,
        "producer_route_confirmed": confirmed,
        "baseline_script_bytes_unchanged": True,
        "local_payload_policy": (
            "ram-addresses-values-opcodes-writer-pcs-and-traces-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": next_checkpoint,
    }
    validate_active_ram_producer(value)
    return value


def validate_active_ram_producer(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("active RAM producer fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"] not in {
            "active-ram-producer-confirmed",
            "active-ram-producer-partial",
            "active-ram-producer-not-observed",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_active_vram_route_sha256"])
    ):
        raise ValueError("active RAM producer policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("active RAM producer timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("active RAM producer timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("active RAM producer timestamp must include UTC")
    runtime = value["runtime_entry"]
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_ENTRY_KEYS:
        raise ValueError("active RAM producer runtime fields do not match")
    counts = value["analysis"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("active RAM producer counts do not match")
    if any(
        not isinstance(counts[key], int)
        or isinstance(counts[key], bool)
        or counts[key] < 0
        for key in COUNT_KEYS
    ):
        raise ValueError("active RAM producer count is invalid")
    target = int(counts["target_address_count"])
    nonzero = int(counts["nonzero_target_address_count"])
    covered = int(counts["producer_covered_address_count"])
    covered_nonzero = int(counts["producer_covered_nonzero_address_count"])
    events = int(counts["parsed_target_write_event_count"])
    writers = int(counts["unique_writer_count"])
    if (
        target > int(counts["target_transfer_count"])
        or nonzero > target
        or covered > target
        or covered_nonzero > min(covered, nonzero)
        or events > int(counts["write_watch_hit_count"])
        or writers > events
        or int(counts["dominant_writer_address_count"]) > covered
        or int(counts["final_value_match_count"]) > target
    ):
        raise ValueError("active RAM producer counts are inconsistent")
    final_verified = target > 0 and int(counts["final_value_match_count"]) == target
    confirmed = (
        final_verified
        and nonzero > 0
        and covered_nonzero == nonzero
        and events > 0
        and writers > 0
    )
    partial = not confirmed and covered > 0
    expected_status = (
        "active-ram-producer-confirmed"
        if confirmed
        else "active-ram-producer-partial"
        if partial
        else "active-ram-producer-not-observed"
    )
    expected_next = (
        "trace-active-ram-producer-inputs"
        if confirmed
        else "extend-active-ram-producer-watch"
        if partial or final_verified
        else "correct-active-ram-producer-anchor"
    )
    if (
        value["status"] != expected_status
        or value["target_values_verified"] is not final_verified
        or value["producer_route_confirmed"] is not confirmed
        or value["baseline_script_bytes_unchanged"] is not True
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"] != expected_next
        or value["local_payload_policy"]
        != "ram-addresses-values-opcodes-writer-pcs-and-traces-local-only"
    ):
        raise ValueError("active RAM producer result is inconsistent")


def _is_current(
    path: Path,
    *,
    target_sha256: str,
    source_sha256: str,
) -> bool:
    if not path.is_file():
        return False
    try:
        value = _load_json_object(path)
        validate_active_ram_producer(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        value["target_sha256"] == target_sha256
        and value["source_active_vram_route_sha256"] == source_sha256
    )


def _set_write_range(client: McpStdioClient, start: int, end: int) -> None:
    client.call(
        "set_breakpoint_range",
        {
            "start_address": f"{start:04X}",
            "end_address": f"{end:04X}",
            "memory_area": "rom_ram",
            "execute": False,
            "read": False,
            "write": True,
        },
    )


def _remove_range(client: McpStdioClient, start: int, end: int) -> None:
    client.call(
        "remove_breakpoint",
        {
            "address": f"{start:04X}",
            "end_address": f"{end:04X}",
            "memory_area": "rom_ram",
        },
    )


def _entry_matches(
    state: dict[str, object],
    *,
    selector_de: int,
    entry_ordinal: int,
) -> bool:
    registers = _registers(state)
    return (
        int(state["pc_after"]) == DECODER_ENTRY_LOGICAL
        and int(state["executing_bank"]) == 0
        and registers.get("de") == selector_de
        and (registers.get("bc", 0) >> 8) == entry_ordinal
    )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    active_path = root / ACTIVE_ROUTE_PATH
    active_local_path = root / ACTIVE_LOCAL_REPORT_PATH
    publish_path = root / PUBLISH_RELATIVE_PATH
    local_path = root / LOCAL_REPORT_PATH
    if not all(path.is_file() for path in (rom_path, active_path, active_local_path)):
        if args.if_ready:
            print("Active RAM producer trace is not ready")
            return 0
        raise SystemExit("active RAM producer input is missing")

    active = _load_json_object(active_path)
    active_local = _load_json_object(active_local_path)
    validate_active_vram_route(active)
    target_sha256 = sha256_file(rom_path)
    active_sha256 = sha256_file(active_path)
    if active["target_sha256"] != target_sha256:
        raise ValueError("active RAM producer ROM identity disagrees")
    target_values, target_transfer_count = extract_target_values(active, active_local)
    if _is_current(
        publish_path,
        target_sha256=target_sha256,
        source_sha256=active_sha256,
    ):
        print("Active RAM producer trace is already current")
        return 0

    runtime = active["runtime_entry"]
    assert isinstance(runtime, dict)
    selector_de = int(runtime["selector_de"])
    entry_ordinal = int(runtime["entry_ordinal"])
    logical_start = int(runtime["logical_start"])
    target_addresses = set(target_values)
    write_ranges = contiguous_address_ranges(list(target_addresses))
    entry_addresses = sorted(
        {int(item["logical_address"]) for item in _decoder_entry_mappings()}
    )
    client = McpStdioClient(_default_command())
    armed_write_ranges: list[tuple[int, int]] = []
    armed_entry_addresses: list[int] = []
    endpoint_armed = False
    fast_forward = False
    selected_state: dict[str, object] | None = None
    ready_state: dict[str, object] | None = None
    events: list[dict[str, object]] = []
    latest_writer_event: dict[int, int] = {}
    write_watch_hit_count = 0
    runtime_stage = "active-ram-producer-mcp-initialize"

    def observe_write(
        state: dict[str, object],
        evidence: dict[str, object],
        *,
        status: dict[str, object],
    ) -> None:
        nonlocal write_watch_hit_count
        write_watch_hit_count += 1
        if write_watch_hit_count > MAX_WRITE_WATCH_HITS:
            raise RuntimeError("active RAM producer write watch saturated")
        writer = previous_target_write(rom, state, target_addresses)
        if writer is None:
            return
        addresses = [int(item) for item in writer["addresses"]]
        event_index = len(events)
        events.append(
            {
                "event_index": event_index,
                "writer": writer,
                "addresses": addresses,
                "state": state,
                "status": status,
            }
        )
        for address in addresses:
            latest_writer_event[address] = event_index

    try:
        rom = rom_path.read_bytes()
        tools = client.initialize()
        missing = sorted(REQUIRED_TOOLS - tools)
        if missing:
            raise RuntimeError(f"Gearsystem MCP tools missing: {missing}")
        runtime_stage = "active-ram-producer-load-media"
        client.call("load_media", {"file_path": str(rom_path)})
        media = client.call("get_media_info")
        if (
            media.get("ready") is not True
            or media.get("is_game_gear") is not True
            or int(media.get("rom_size", 0)) != rom_path.stat().st_size
        ):
            raise RuntimeError("Gearsystem did not load the producer trace ROM")
        client.call("debug_reset")
        client.call("debug_pause")
        areas = client.call("list_memory_areas")
        ram_area = _select_ram_area(areas)
        ram_area_id = int(ram_area["id"])
        client.call("set_trace_log", {"enabled": False})
        for start, end in write_ranges:
            _set_write_range(client, start, end)
            armed_write_ranges.append((start, end))
        for address in entry_addresses:
            _set_execute_breakpoint(client, address)
            armed_entry_addresses.append(address)

        runtime_stage = "active-ram-producer-route-watch"
        if any(button is not None for _, button in ATTRACT_ROUTE_SCHEDULE):
            raise RuntimeError("active RAM producer attract route must be passive")
        _set_unlimited_fast_forward(client, True)
        fast_forward = True
        deadline = time.monotonic() + PRODUCER_WATCH_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            status = _continue_until_breakpoint(
                client,
                min(20.0, max(0.1, deadline - time.monotonic())),
            )
            if status.get("at_breakpoint") is not True:
                continue
            state, evidence = _capture_producer_state(client)
            pc_after = int(state["pc_after"])
            if pc_after in entry_addresses:
                if _entry_matches(
                    state,
                    selector_de=selector_de,
                    entry_ordinal=entry_ordinal,
                ):
                    selected_state = state
                    break
                continue
            observe_write(state, evidence, status=status)
        if selected_state is None:
            raise RuntimeError("active RAM producer target decoder entry was not reached")
        _set_unlimited_fast_forward(client, False)
        fast_forward = False
        for address in armed_entry_addresses:
            _remove_breakpoint(client, address)
        armed_entry_addresses.clear()

        runtime_stage = "active-ram-producer-route-ready"
        for _ in range(DECODER_ENTRY_TRACE_STEPS):
            status = _step_instruction_and_wait(client)
            if status.get("at_breakpoint") is True:
                state, evidence = _capture_producer_state(client)
                observe_write(state, evidence, status=status)
        _set_execute_breakpoint(client, DECODER_SKIP_ENDPOINT_LOGICAL)
        endpoint_armed = True
        endpoint_deadline = time.monotonic() + ENDPOINT_WATCH_TIMEOUT_SECONDS
        endpoint_state: dict[str, object] | None = None
        while time.monotonic() < endpoint_deadline:
            status = _continue_until_breakpoint(
                client,
                min(5.0, max(0.1, endpoint_deadline - time.monotonic())),
            )
            if status.get("at_breakpoint") is not True:
                continue
            state, evidence = _capture_producer_state(client)
            if int(state["pc_after"]) == DECODER_SKIP_ENDPOINT_LOGICAL:
                endpoint_state = state
                break
            observe_write(state, evidence, status=status)
        if endpoint_state is None:
            raise RuntimeError("active RAM producer decoder endpoint was not reached")
        endpoint_registers = _registers(endpoint_state)
        if endpoint_registers.get("hl") != logical_start - 1:
            raise RuntimeError("active RAM producer decoder endpoint disagrees")
        _remove_breakpoint(client, DECODER_SKIP_ENDPOINT_LOGICAL)
        endpoint_armed = False
        status = _step_instruction_and_wait(client)
        ready_state, ready_evidence = _capture_producer_state(client)
        if status.get("at_breakpoint") is True:
            observe_write(ready_state, ready_evidence, status=status)
        ready_registers = _registers(ready_state)
        if (
            int(ready_state["pc_after"]) != DECODER_PAYLOAD_READY_LOGICAL
            or ready_registers.get("hl") != logical_start
        ):
            raise RuntimeError("active RAM producer payload handoff disagrees")
        final_ram = _read_memory_area(
            client,
            area_id=ram_area_id,
            size=RAM_REQUIRED_SIZE,
        )
    except Exception as error:
        receipt = _runtime_failure_receipt(runtime_stage, error, client)
        _write_runtime_failure_receipt(root, receipt)
        raise
    finally:
        if fast_forward:
            try:
                _set_unlimited_fast_forward(client, False)
            except Exception:
                pass
        if endpoint_armed:
            try:
                _remove_breakpoint(client, DECODER_SKIP_ENDPOINT_LOGICAL)
            except Exception:
                pass
        for address in armed_entry_addresses:
            try:
                _remove_breakpoint(client, address)
            except Exception:
                pass
        for start, end in armed_write_ranges:
            try:
                _remove_range(client, start, end)
            except Exception:
                pass
        client.close()

    runtime_stage = "active-ram-producer-artifact"
    counts, local_analysis = analyze_capture(
        target_values=target_values,
        target_transfer_count=target_transfer_count,
        final_ram=final_ram,
        write_ranges=write_ranges,
        write_watch_hit_count=write_watch_hit_count,
        events=events,
        latest_writer_event=latest_writer_event,
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    safe = build_active_ram_producer(
        target_sha256=target_sha256,
        source_active_vram_route_sha256=active_sha256,
        runtime_entry=runtime,
        analysis=counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-s25u-active-ram-producer",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "source_active_vram_route_sha256": active_sha256,
        "captured_utc": captured_utc,
        "runtime_entry": runtime,
        "write_ranges": [
            {"start": start, "end": end} for start, end in write_ranges
        ],
        "selected_state": selected_state,
        "ready_state": ready_state,
        "events": events,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-ram-addresses-values-opcodes-writer-pcs-or-traces"
        ),
    }
    publish_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    publish_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR active RAM producer: {publish_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
