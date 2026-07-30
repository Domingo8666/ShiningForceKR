#!/usr/bin/env python3
"""Trace the bounded renderer output window for the exact visible v5.1 record.

Decoded symbols, raw trace lines, opcodes, and VDP byte values stay in an
ignored local report.  The publishable artifact contains only coordinates,
counts, identities, and promotion-gate booleans.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .run_s25u_runtime_probe import (
        McpStdioClient,
        _capture_state,
        _default_command,
        _runtime_failure_receipt,
        _step_instruction_and_wait,
        _write_runtime_failure_receipt,
    )
    from .run_s25u_renderer_probe import (
        ATTRACT_ROUTE_SCHEDULE,
        _decoder_entry_mappings,
        _probe_decoder_entry,
    )
    from .v5_1_runtime_hit_resolver import _parse_trace_line
    from .v5_1_test_display_capture import (
        DECODER_ENTRY_LOGICAL,
        DECODER_ENTRY_TRACE_STEPS,
        DECODER_PAYLOAD_READY_LOGICAL,
        DECODER_SKIP_ENDPOINT_LOGICAL,
        _continue_until_breakpoint,
        _set_unlimited_fast_forward,
    )
    from .v5_1_visible_script_record import (
        validate_visible_script_roundtrip,
    )
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from run_s25u_runtime_probe import (
        McpStdioClient,
        _capture_state,
        _default_command,
        _runtime_failure_receipt,
        _step_instruction_and_wait,
        _write_runtime_failure_receipt,
    )
    from run_s25u_renderer_probe import (
        ATTRACT_ROUTE_SCHEDULE,
        _decoder_entry_mappings,
        _probe_decoder_entry,
    )
    from v5_1_runtime_hit_resolver import _parse_trace_line
    from v5_1_test_display_capture import (
        DECODER_ENTRY_LOGICAL,
        DECODER_ENTRY_TRACE_STEPS,
        DECODER_PAYLOAD_READY_LOGICAL,
        DECODER_SKIP_ENDPOINT_LOGICAL,
        _continue_until_breakpoint,
        _set_unlimited_fast_forward,
    )
    from v5_1_visible_script_record import validate_visible_script_roundtrip


ARTIFACT_KIND = "sanitized-s25u-renderer-output-trace"
SCHEMA_VERSION = 1
DEFAULT_ROM = Path("build/Final_Conflict_Korean_v5.1.gg")
VISIBLE_ROUNDTRIP_PATH = Path(
    "analysis/device/v5_1_latest_visible_script_roundtrip.json"
)
LOCAL_VISIBLE_RECORD_PATH = Path(
    "analysis/local/v5_1_visible_script_record.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_renderer_output_trace.json"
)
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_renderer_output_trace.json"
)
DECODER_REGISTER_TRACE_PATH = Path(
    "analysis/device/v5_1_latest_decoder_register_trace.json"
)
TRACE_PAGE_SIZE = 1000
TRACE_BUFFER_SIZE = 100000
TRACE_RETURN_TIMEOUT_SECONDS = 15.0
DECODER_OUTPUT_CANDIDATES = {
    0x3411,
    0x3431,
    0x402A,
    0x40D4,
    0x43C2,
}
REQUIRED_TOOLS = {
    "debug_continue",
    "debug_get_status",
    "debug_pause",
    "debug_reset",
    "debug_step_frame",
    "debug_step_into",
    "get_call_stack",
    "get_media_info",
    "get_trace_log",
    "get_z80_status",
    "list_memory_areas",
    "load_media",
    "read_memory",
    "remove_breakpoint",
    "set_breakpoint_range",
    "set_fast_forward_speed",
    "set_trace_log",
    "toggle_fast_forward",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "captured_utc",
    "runtime_entry",
    "decoder_window",
    "renderer_window",
    "consumer_chain_confirmed",
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
DECODER_WINDOW_KEYS = {
    "expected_symbol_count",
    "terminator_count",
    "local_roundtrip_bound",
    "candidate_entry_hit_count",
    "unique_candidate_entry_count",
}
RENDERER_WINDOW_KEYS = {
    "bounded_return_windows",
    "trace_entries_observed",
    "parsed_instruction_count",
    "vdp_data_write_count",
    "vdp_control_write_count",
    "vdp_event_line_count",
    "unique_output_pattern_count",
}
_VDP_EVENT_LINE = re.compile(
    r"^\s*\[IO\]\s+OUT\s+Port:\$(?P<port>BE|BF)"
    r"\s+Value:\$(?P<value>[0-9A-Fa-f]{2})\s*$",
    re.IGNORECASE,
)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _bounded_int(
    value: object,
    minimum: int,
    maximum: int,
) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def validate_renderer_output_trace(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("renderer output trace fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "renderer-output-events-captured",
            "renderer-output-events-not-observed",
        }
    ):
        raise ValueError("renderer output trace policy is invalid")
    if not _is_sha256(value["target_sha256"]):
        raise ValueError("renderer output target must be a lowercase SHA-256")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("renderer output timestamp must be a string")
    try:
        parsed_time = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("renderer output timestamp is invalid") from error
    if parsed_time.tzinfo is None:
        raise ValueError("renderer output timestamp must include UTC")

    runtime = value["runtime_entry"]
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_ENTRY_KEYS:
        raise ValueError("renderer output runtime fields do not match")
    for key, minimum, maximum in (
        ("physical_start", 0, 0x17BFFF),
        ("logical_start", 0x4000, 0x7FFF),
        ("mapped_bank", 0, 0xFF),
        ("record_length_bytes", 1, 0xFF),
        ("selector_de", 0, 0xFFFF),
        ("entry_ordinal", 0, 0xFF),
    ):
        if not _bounded_int(runtime[key], minimum, maximum):
            raise ValueError(f"renderer output {key} is invalid")

    decoder = value["decoder_window"]
    if not isinstance(decoder, dict) or set(decoder) != DECODER_WINDOW_KEYS:
        raise ValueError("renderer output decoder fields do not match")
    for key, minimum, maximum in (
        ("expected_symbol_count", 1, 0x1000),
        ("terminator_count", 1, 0x100),
        ("candidate_entry_hit_count", 0, 0x100000),
        ("unique_candidate_entry_count", 0, len(DECODER_OUTPUT_CANDIDATES)),
    ):
        if not _bounded_int(decoder[key], minimum, maximum):
            raise ValueError(f"renderer output {key} is invalid")
    if (
        decoder["local_roundtrip_bound"] is not True
        or decoder["terminator_count"] != 1
        or decoder["unique_candidate_entry_count"]
        > decoder["candidate_entry_hit_count"]
    ):
        raise ValueError("renderer output decoder evidence is inconsistent")

    renderer = value["renderer_window"]
    if not isinstance(renderer, dict) or set(renderer) != RENDERER_WINDOW_KEYS:
        raise ValueError("renderer output renderer fields do not match")
    for key, minimum, maximum in (
        ("bounded_return_windows", 1, 16),
        ("trace_entries_observed", 0, 0x100000),
        ("parsed_instruction_count", 0, 0x100000),
        ("vdp_data_write_count", 0, 0x100000),
        ("vdp_control_write_count", 0, 0x100000),
        ("vdp_event_line_count", 0, 0x100000),
        ("unique_output_pattern_count", 0, 0x10000),
    ):
        if not _bounded_int(renderer[key], minimum, maximum):
            raise ValueError(f"renderer output {key} is invalid")
    observed = renderer["vdp_data_write_count"] > 0
    if (
        value["consumer_chain_confirmed"] is not observed
        or (
            value["status"] == "renderer-output-events-captured"
        )
        is not observed
    ):
        raise ValueError("renderer output consumer gate is inconsistent")
    if value["local_payload_policy"] != (
        "symbols-opcodes-values-and-raw-trace-local-only"
    ):
        raise ValueError("renderer output local payload policy is invalid")
    if value["translation_build_eligible"] is not False:
        raise ValueError("renderer output trace cannot enable translation builds")
    if value["next_checkpoint"] != (
        "align-decoded-symbols-with-renderer-output-events"
    ):
        raise ValueError("renderer output next checkpoint is inconsistent")


def _out_register_value(
    opcode: int,
    registers: dict[str, int],
) -> int:
    if opcode == 0x41:
        return (registers.get("bc", 0) >> 8) & 0xFF
    if opcode == 0x49:
        return registers.get("bc", 0) & 0xFF
    if opcode == 0x51:
        return (registers.get("de", 0) >> 8) & 0xFF
    if opcode == 0x59:
        return registers.get("de", 0) & 0xFF
    if opcode == 0x61:
        return (registers.get("hl", 0) >> 8) & 0xFF
    if opcode == 0x69:
        return registers.get("hl", 0) & 0xFF
    if opcode == 0x71:
        return 0
    if opcode == 0x79:
        return registers.get("a", 0) & 0xFF
    raise ValueError("not an OUT (C),r opcode")


def _classify_vdp_output(
    parsed: dict[str, object],
) -> dict[str, int] | None:
    opcodes = parsed.get("opcodes")
    registers = parsed.get("registers")
    if not isinstance(opcodes, bytes) or not isinstance(registers, dict):
        return None
    typed_registers = {
        key: int(value)
        for key, value in registers.items()
        if isinstance(value, int) and not isinstance(value, bool)
    }
    if len(opcodes) >= 2 and opcodes[0] == 0xD3:
        port = opcodes[1]
        value = typed_registers.get("a", 0) & 0xFF
    elif (
        len(opcodes) >= 2
        and opcodes[0] == 0xED
        and opcodes[1] in {0x41, 0x49, 0x51, 0x59, 0x61, 0x69, 0x71, 0x79}
    ):
        port = typed_registers.get("bc", 0) & 0xFF
        value = _out_register_value(opcodes[1], typed_registers)
    else:
        return None
    if port not in {0xBE, 0xBF}:
        return None
    return {"port": port, "value": value}


def analyze_trace_lines(
    lines: list[str],
) -> tuple[dict[str, int], dict[str, object]]:
    parsed_count = 0
    candidate_hits: list[int] = []
    outputs: list[dict[str, int]] = []
    io_events: list[dict[str, int]] = []
    for line in lines:
        event_match = _VDP_EVENT_LINE.search(line)
        if event_match is not None:
            io_events.append(
                {
                    "port": int(event_match.group("port"), 16),
                    "value": int(event_match.group("value"), 16),
                }
            )
        parsed = _parse_trace_line(line)
        if parsed is None:
            continue
        parsed_count += 1
        pc = int(parsed["pc"])
        if pc in DECODER_OUTPUT_CANDIDATES:
            candidate_hits.append(pc)
        output = _classify_vdp_output(parsed)
        if output is not None:
            output["pc"] = pc
            output["bank"] = int(parsed["bank"])
            outputs.append(output)
    instruction_data = [
        item for item in outputs if item["port"] == 0xBE
    ]
    instruction_control = [
        item for item in outputs if item["port"] == 0xBF
    ]
    event_data = [
        item for item in io_events if item["port"] == 0xBE
    ]
    event_control = [
        item for item in io_events if item["port"] == 0xBF
    ]
    data = event_data if io_events else instruction_data
    control = event_control if io_events else instruction_control
    patterns = {
        (item["bank"], item["pc"], item["port"])
        for item in outputs
    }
    safe = {
        "trace_entries_observed": len(lines),
        "parsed_instruction_count": parsed_count,
        "vdp_data_write_count": len(data),
        "vdp_control_write_count": len(control),
        "vdp_event_line_count": len(io_events),
        "unique_output_pattern_count": len(patterns),
        "candidate_entry_hit_count": len(candidate_hits),
        "unique_candidate_entry_count": len(set(candidate_hits)),
    }
    local = {
        "raw_trace_lines": lines,
        "candidate_entry_hits": candidate_hits,
        "vdp_outputs": outputs,
        "vdp_io_events": io_events,
    }
    return safe, local


def build_renderer_output_trace(
    *,
    target_sha256: str,
    visible_roundtrip: dict[str, object],
    selector_de: int,
    entry_ordinal: int,
    trace_summary: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    validate_visible_script_roundtrip(visible_roundtrip)
    runtime = visible_roundtrip["runtime_entry"]
    roundtrip = visible_roundtrip["roundtrip"]
    assert isinstance(runtime, dict)
    assert isinstance(roundtrip, dict)
    observed = trace_summary["vdp_data_write_count"] > 0
    safe: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "renderer-output-events-captured"
            if observed
            else "renderer-output-events-not-observed"
        ),
        "target_sha256": target_sha256,
        "captured_utc": captured_utc,
        "runtime_entry": {
            "physical_start": runtime["physical_start"],
            "logical_start": runtime["logical_start"],
            "mapped_bank": runtime["mapped_bank"],
            "record_length_bytes": runtime["record_length_bytes"],
            "selector_de": selector_de,
            "entry_ordinal": entry_ordinal,
        },
        "decoder_window": {
            "expected_symbol_count": roundtrip["decoded_symbol_count"],
            "terminator_count": roundtrip["terminator_count"],
            "local_roundtrip_bound": True,
            "candidate_entry_hit_count": trace_summary[
                "candidate_entry_hit_count"
            ],
            "unique_candidate_entry_count": trace_summary[
                "unique_candidate_entry_count"
            ],
        },
        "renderer_window": {
            "bounded_return_windows": 1,
            "trace_entries_observed": trace_summary[
                "trace_entries_observed"
            ],
            "parsed_instruction_count": trace_summary[
                "parsed_instruction_count"
            ],
            "vdp_data_write_count": trace_summary[
                "vdp_data_write_count"
            ],
            "vdp_control_write_count": trace_summary[
                "vdp_control_write_count"
            ],
            "vdp_event_line_count": trace_summary[
                "vdp_event_line_count"
            ],
            "unique_output_pattern_count": trace_summary[
                "unique_output_pattern_count"
            ],
        },
        "consumer_chain_confirmed": observed,
        "local_payload_policy": (
            "symbols-opcodes-values-and-raw-trace-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": (
            "align-decoded-symbols-with-renderer-output-events"
        ),
    }
    validate_renderer_output_trace(safe)
    return safe


def _set_execute_breakpoint(client: McpStdioClient, address: int) -> None:
    encoded = f"{address:04X}"
    client.call(
        "set_breakpoint_range",
        {
            "start_address": encoded,
            "end_address": encoded,
            "memory_area": "rom_ram",
            "execute": True,
            "read": False,
            "write": False,
        },
    )


def _remove_breakpoint(client: McpStdioClient, address: int) -> None:
    encoded = f"{address:04X}"
    client.call(
        "remove_breakpoint",
        {
            "address": encoded,
            "end_address": encoded,
            "memory_area": "rom_ram",
        },
    )


def _registers(state: dict[str, object]) -> dict[str, int]:
    value = state.get("registers")
    if not isinstance(value, dict):
        raise RuntimeError("Gearsystem returned no Z80 registers")
    return {
        key: int(item)
        for key, item in value.items()
        if isinstance(item, int) and not isinstance(item, bool)
    }


def _parse_hex_word(value: object, field: str) -> int:
    if not isinstance(value, str):
        raise RuntimeError(f"Gearsystem call stack {field} is not a string")
    normalized = value.removeprefix("$").removeprefix("0x")
    if re.fullmatch(r"[0-9A-Fa-f]{1,4}", normalized) is None:
        raise RuntimeError(f"Gearsystem call stack {field} is invalid")
    return int(normalized, 16)


def _outer_return_address(
    call_stack: dict[str, object],
    *,
    current_pc: int,
) -> int:
    stack = call_stack.get("stack")
    if not isinstance(stack, list) or len(stack) < 2:
        raise RuntimeError("renderer output call stack is too shallow")
    # Gearsystem emits the innermost frame first.  The last frame therefore
    # returns only after the complete outer text consumer has finished.
    outer = stack[-1]
    if not isinstance(outer, dict):
        raise RuntimeError("renderer output outer call frame is invalid")
    address = _parse_hex_word(outer.get("return"), "return")
    if address == current_pc:
        raise RuntimeError("renderer output return breakpoint equals current PC")
    return address


def _read_trace_window(
    client: McpStdioClient,
    *,
    start: int,
    end: int,
) -> tuple[list[str], list[dict[str, object]]]:
    if not 0 <= start <= end <= TRACE_BUFFER_SIZE:
        raise RuntimeError("renderer output trace window is outside the buffer")
    lines: list[str] = []
    pages: list[dict[str, object]] = []
    cursor = start
    while cursor < end:
        requested = min(TRACE_PAGE_SIZE, end - cursor)
        payload = client.call(
            "get_trace_log",
            {"start": cursor, "count": requested},
        )
        page_lines = payload.get("lines")
        if not isinstance(page_lines, list) or not all(
            isinstance(line, str) for line in page_lines
        ):
            raise RuntimeError("Gearsystem returned an invalid trace page")
        actual_start = int(payload.get("start", -1))
        actual_count = int(payload.get("count", -1))
        if (
            actual_start != cursor
            or actual_count != len(page_lines)
            or actual_count <= 0
            or actual_count > requested
        ):
            raise RuntimeError("Gearsystem trace page bounds disagree")
        lines.extend(page_lines)
        pages.append(
            {
                "start": actual_start,
                "count": actual_count,
                "total_entries": int(payload.get("total_entries", -1)),
            }
        )
        cursor += actual_count
    return lines, pages


def _trace_to_outer_return(
    client: McpStdioClient,
    *,
    ready_state: dict[str, object],
) -> tuple[list[str], dict[str, object]]:
    call_stack = client.call("get_call_stack")
    return_address = _outer_return_address(
        call_stack,
        current_pc=int(ready_state["pc_after"]),
    )
    return_armed = False
    fast_forward = False
    trace_enabled = False
    trace_start = 0
    trace_end = 0
    try:
        _set_execute_breakpoint(client, return_address)
        return_armed = True
        started = client.call(
            "set_trace_log",
            {
                "enabled": True,
                "cpu_irq": False,
                "vdp_write": True,
                "vdp_status": False,
                "psg": False,
                "ym2413": False,
                "io_port": True,
                "bank_switch": True,
            },
        )
        trace_enabled = True
        trace_start = int(started.get("total_entries", -1))
        if not 0 <= trace_start <= TRACE_BUFFER_SIZE:
            raise RuntimeError("Gearsystem trace start count is invalid")
        _set_unlimited_fast_forward(client, True)
        fast_forward = True
        status = _continue_until_breakpoint(
            client,
            TRACE_RETURN_TIMEOUT_SECONDS,
        )
        if (
            status.get("at_breakpoint") is not True
            or _parse_hex_word(status.get("pc"), "pc") != return_address
        ):
            raise RuntimeError("outer renderer return was not reached")
        _set_unlimited_fast_forward(client, False)
        fast_forward = False
        stopped = client.call("set_trace_log", {"enabled": False})
        trace_enabled = False
        trace_end = int(stopped.get("total_entries", -1))
        if trace_end < trace_start:
            raise RuntimeError("Gearsystem trace buffer wrapped")
        lines, pages = _read_trace_window(
            client,
            start=trace_start,
            end=trace_end,
        )
        local = {
            "call_stack": call_stack,
            "outer_return_address": return_address,
            "trace_start": trace_start,
            "trace_end": trace_end,
            "trace_pages": pages,
        }
        return lines, local
    finally:
        if fast_forward:
            try:
                _set_unlimited_fast_forward(client, False)
            except Exception:
                pass
        if trace_enabled:
            try:
                client.call("set_trace_log", {"enabled": False})
            except Exception:
                pass
        if return_armed:
            try:
                _remove_breakpoint(client, return_address)
            except Exception:
                pass


def _reach_exact_payload(
    client: McpStdioClient,
    *,
    selector_de: int,
    entry_ordinal: int,
    logical_start: int,
    mapped_bank: int,
    progress: dict[str, str] | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    endpoint_armed = False
    selected_state: dict[str, object] | None = None
    ready_state: dict[str, object] | None = None
    try:
        if progress is not None:
            progress["stage"] = "renderer-output-route-watch"
        selected_state, _ = _probe_decoder_entry(
            client,
            _decoder_entry_mappings(),
            schedule=ATTRACT_ROUTE_SCHEDULE,
        )
        if progress is not None:
            progress["stage"] = "renderer-output-route-hunt"
        if selected_state is None:
            raise RuntimeError("exact visible decoder selection was not reached")
        selected_registers = _registers(selected_state)
        if (
            int(selected_state["pc_after"]) != DECODER_ENTRY_LOGICAL
            or selected_registers.get("de") != selector_de
            or (selected_registers.get("bc", 0) >> 8) != entry_ordinal
        ):
            raise RuntimeError(
                "first proven decoder entry is not the visible record"
            )
        if progress is not None:
            progress["stage"] = "renderer-output-route-entry"
        for _ in range(DECODER_ENTRY_TRACE_STEPS):
            _step_instruction_and_wait(client)
        if progress is not None:
            progress["stage"] = "renderer-output-route-endpoint"
        _set_execute_breakpoint(client, DECODER_SKIP_ENDPOINT_LOGICAL)
        endpoint_armed = True
        status = _continue_until_breakpoint(client, 5.0)
        if status.get("at_breakpoint") is not True:
            raise RuntimeError("decoder skip endpoint was not reached")
        endpoint_state, _ = _capture_state(client)
        endpoint_registers = _registers(endpoint_state)
        if (
            int(endpoint_state["pc_after"])
            != DECODER_SKIP_ENDPOINT_LOGICAL
            or int(endpoint_state["slot1_bank"]) != mapped_bank
            or endpoint_registers.get("hl") != logical_start - 1
        ):
            raise RuntimeError("decoder skip endpoint registers disagree")
        _remove_breakpoint(client, DECODER_SKIP_ENDPOINT_LOGICAL)
        endpoint_armed = False
        if progress is not None:
            progress["stage"] = "renderer-output-route-ready"
        _step_instruction_and_wait(client)
        ready_state, _ = _capture_state(client)
        ready_registers = _registers(ready_state)
        if (
            int(ready_state["pc_after"]) != DECODER_PAYLOAD_READY_LOGICAL
            or int(ready_state["slot1_bank"]) != mapped_bank
            or ready_registers.get("hl") != logical_start
        ):
            raise RuntimeError("decoder payload handoff registers disagree")
        return selected_state, ready_state
    finally:
        if endpoint_armed:
            try:
                _remove_breakpoint(client, DECODER_SKIP_ENDPOINT_LOGICAL)
            except Exception:
                pass


def _load_json_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _existing_capture_is_current(
    path: Path,
    target_sha256: str,
) -> bool:
    if not path.is_file():
        return False
    try:
        value = _load_json_object(path)
        validate_renderer_output_trace(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        value["target_sha256"] == target_sha256
        and value["consumer_chain_confirmed"] is True
    )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    visible_path = root / VISIBLE_ROUNDTRIP_PATH
    local_visible_path = root / LOCAL_VISIBLE_RECORD_PATH
    register_trace_path = root / DECODER_REGISTER_TRACE_PATH
    publish_path = root / PUBLISH_RELATIVE_PATH
    prerequisites = (
        rom_path,
        visible_path,
        local_visible_path,
        register_trace_path,
    )
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Renderer output trace is not ready")
            return 0
        raise SystemExit("renderer output trace input is missing")

    visible = _load_json_object(visible_path)
    validate_visible_script_roundtrip(visible)
    local_visible = _load_json_object(local_visible_path)
    register_trace = _load_json_object(register_trace_path)
    target_sha256 = sha256_file(rom_path)
    if target_sha256 != visible["baseline_target_sha256"]:
        raise ValueError("renderer output ROM identity disagrees with roundtrip")
    if local_visible.get("baseline_target_sha256") != target_sha256:
        raise ValueError("local visible record identity disagrees with ROM")
    if register_trace.get("target_sha256") != target_sha256:
        raise ValueError("decoder register trace identity disagrees with ROM")
    selector_de = int(register_trace["selector_de"])
    states = register_trace.get("states")
    if not isinstance(states, list) or not states:
        raise ValueError("decoder register trace has no entry state")
    first_state = states[0]
    if not isinstance(first_state, dict):
        raise ValueError("decoder register entry state is invalid")
    entry_ordinal = int(first_state["bc"]) >> 8
    if _existing_capture_is_current(publish_path, target_sha256):
        print("Renderer output trace is already current")
        return 0

    runtime = visible["runtime_entry"]
    assert isinstance(runtime, dict)
    client = McpStdioClient(_default_command())
    selected_state: dict[str, object] | None = None
    ready_state: dict[str, object] | None = None
    trace_lines: list[str] = []
    local_trace_window: dict[str, object] = {}
    runtime_stage = "renderer-output-mcp-initialize"
    route_progress = {"stage": runtime_stage}
    try:
        tools = client.initialize()
        missing = sorted(REQUIRED_TOOLS - tools)
        if missing:
            raise RuntimeError(f"Gearsystem MCP tools missing: {missing}")
        runtime_stage = "renderer-output-load-media"
        client.call("load_media", {"file_path": str(rom_path)})
        media = client.call("get_media_info")
        if (
            media.get("ready") is not True
            or media.get("is_game_gear") is not True
            or int(media.get("rom_size", 0)) != rom_path.stat().st_size
        ):
            raise RuntimeError("Gearsystem did not load the expected Game Gear ROM")
        client.call("debug_reset")
        client.call("debug_pause")
        client.call("set_trace_log", {"enabled": False})
        runtime_stage = "renderer-output-route-selection"
        selected_state, ready_state = _reach_exact_payload(
            client,
            selector_de=selector_de,
            entry_ordinal=entry_ordinal,
            logical_start=int(runtime["logical_start"]),
            mapped_bank=int(runtime["mapped_bank"]),
            progress=route_progress,
        )
        runtime_stage = "renderer-output-trace-run"
        trace_lines, local_trace_window = _trace_to_outer_return(
            client,
            ready_state=ready_state,
        )
    except Exception as error:
        if runtime_stage == "renderer-output-route-selection":
            runtime_stage = route_progress["stage"]
        receipt = _runtime_failure_receipt(runtime_stage, error, client)
        _write_runtime_failure_receipt(root, receipt)
        raise
    finally:
        client.close()

    runtime_stage = "renderer-output-artifact"
    trace_summary, local_trace = analyze_trace_lines(trace_lines)
    captured_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    safe = build_renderer_output_trace(
        target_sha256=target_sha256,
        visible_roundtrip=visible,
        selector_de=selector_de,
        entry_ordinal=entry_ordinal,
        trace_summary=trace_summary,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-s25u-renderer-output-trace",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "captured_utc": captured_utc,
        "runtime_entry": runtime,
        "expected_symbols_hex": local_visible.get("symbols_hex"),
        "selected_state": selected_state,
        "ready_state": ready_state,
        "trace_window": local_trace_window,
        "trace_analysis": local_trace,
        "publication_policy": (
            "never-publish-symbols-opcodes-values-or-raw-trace"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    publish_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    publish_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote local renderer output trace: {local_path}")
    print(f"Wrote sanitized renderer output trace: {publish_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
