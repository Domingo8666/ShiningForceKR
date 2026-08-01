#!/usr/bin/env python3
"""Trace the short instruction window that defines the active RAM writer value."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time

try:
    from .patch_io import sha256_file
    from .run_s25u_runtime_probe import (
        McpStdioClient,
        _default_command,
        _runtime_failure_receipt,
        _write_runtime_failure_receipt,
    )
    from .v5_1_active_ram_producer import (
        LOCAL_REPORT_PATH as PRODUCER_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as PRODUCER_PATH,
        _capture_producer_state,
        _load_json_object,
        _remove_range,
        _set_write_range,
        previous_target_write,
        validate_active_ram_producer,
    )
    from .v5_1_active_ram_writer_source import (
        LOCAL_REPORT_PATH as WRITER_SOURCE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as WRITER_SOURCE_PATH,
        validate_active_ram_writer_source,
    )
    from .v5_1_renderer_output_trace import (
        TRACE_BUFFER_SIZE,
        _read_trace_window,
    )
    from .v5_1_runtime_hit_resolver import _parse_trace_line, _read_addresses
    from .v5_1_test_display_capture import (
        _continue_until_breakpoint,
        _set_unlimited_fast_forward,
    )
    from .v5_1_renderer_output_trace import (
        DEFAULT_ROM,
        REQUIRED_TOOLS,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from run_s25u_runtime_probe import (
        McpStdioClient,
        _default_command,
        _runtime_failure_receipt,
        _write_runtime_failure_receipt,
    )
    from v5_1_active_ram_producer import (
        LOCAL_REPORT_PATH as PRODUCER_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as PRODUCER_PATH,
        _capture_producer_state,
        _load_json_object,
        _remove_range,
        _set_write_range,
        previous_target_write,
        validate_active_ram_producer,
    )
    from v5_1_active_ram_writer_source import (
        LOCAL_REPORT_PATH as WRITER_SOURCE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as WRITER_SOURCE_PATH,
        validate_active_ram_writer_source,
    )
    from v5_1_renderer_output_trace import TRACE_BUFFER_SIZE, _read_trace_window
    from v5_1_runtime_hit_resolver import _parse_trace_line, _read_addresses
    from v5_1_test_display_capture import (
        _continue_until_breakpoint,
        _set_unlimited_fast_forward,
    )
    from v5_1_renderer_output_trace import (
        DEFAULT_ROM,
        REQUIRED_TOOLS,
    )


ARTIFACT_KIND = "sanitized-s25u-active-ram-register-trace"
SCHEMA_VERSION = 2
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_active_ram_register_trace.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_active_ram_register_trace.json")
WRITER_WATCH_TIMEOUT_SECONDS = 240.0
NEXT_WRITER_TIMEOUT_SECONDS = 15.0
PREDECESSOR_DISTANCE = 8
COUNT_KEYS = {
    "trace_line_count",
    "parsed_trace_line_count",
    "source_definition_candidate_count",
    "memory_definition_candidate_count",
    "immediate_definition_candidate_count",
    "register_definition_candidate_count",
    "arithmetic_definition_candidate_count",
    "unique_definition_pc_count",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_active_ram_writer_sha256",
    "captured_utc",
    "analysis",
    "writer_instance_confirmed",
    "register_definition_confirmed",
    "definition_source_class",
    "baseline_script_bytes_unchanged",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _register_members(name: str) -> set[str]:
    return {
        "af": {"af", "a"},
        "bc": {"bc", "b", "c"},
        "de": {"de", "d", "e"},
        "hl": {"hl", "h", "l"},
        "sp": {"sp"},
    }.get(name, {name})


def _defined_registers(opcodes: bytes) -> set[str]:
    if not opcodes:
        return set()
    first = opcodes[0]
    byte_registers = ("b", "c", "d", "e", "h", "l", "memory", "a")
    if 0x40 <= first <= 0x7F and first != 0x76:
        destination = byte_registers[(first >> 3) & 7]
        return set() if destination == "memory" else {destination}
    if first & 0xC7 in {0x04, 0x05, 0x06}:
        destination = byte_registers[(first >> 3) & 7]
        return set() if destination == "memory" else {destination}
    if first in {0x0A, 0x1A, 0x3A} or 0x80 <= first <= 0xB7:
        return {"a"}
    if first in {0xC6, 0xCE, 0xD6, 0xDE, 0xE6, 0xEE, 0xF6}:
        return {"a"}
    pair = {
        0x01: "bc",
        0x03: "bc",
        0x0B: "bc",
        0x11: "de",
        0x13: "de",
        0x1B: "de",
        0x21: "hl",
        0x23: "hl",
        0x2A: "hl",
        0x2B: "hl",
        0x31: "sp",
        0x33: "sp",
        0x3B: "sp",
        0xC1: "bc",
        0xD1: "de",
        0xE1: "hl",
        0xF1: "af",
    }.get(first)
    return _register_members(pair) if pair is not None else set()


def _definition_kind(opcodes: bytes, registers: dict[str, int]) -> tuple[str, list[int]]:
    reads = _read_addresses(opcodes, registers)
    if reads:
        return "memory", reads
    if not opcodes:
        return "unresolved", []
    first = opcodes[0]
    if first & 0xC7 == 0x06 or first in {0x01, 0x11, 0x21, 0x31, 0x3E}:
        return "immediate", []
    if 0x40 <= first <= 0x7F and first != 0x76:
        return "register", []
    if first in {0x0A, 0x1A, 0x2A, 0x3A}:
        return "memory", reads
    if 0x80 <= first <= 0xB7 or first in {
        0x04, 0x05, 0x0C, 0x0D, 0x14, 0x15, 0x1C, 0x1D,
        0x24, 0x25, 0x2C, 0x2D, 0x3C, 0x3D,
        0xC6, 0xCE, 0xD6, 0xDE, 0xE6, 0xEE, 0xF6,
    }:
        return "arithmetic", []
    return "register", []


def analyze_register_trace(
    lines: list[str], source_register: str
) -> tuple[dict[str, int], dict[str, object]]:
    candidates: list[dict[str, object]] = []
    parsed_count = 0
    for index, line in enumerate(lines):
        parsed = _parse_trace_line(line)
        if parsed is None:
            continue
        parsed_count += 1
        opcodes = parsed["opcodes"]
        registers = parsed["registers"]
        assert isinstance(opcodes, bytes) and isinstance(registers, dict)
        if not (_register_members(source_register) & _defined_registers(opcodes)):
            continue
        typed_registers = {
            key: int(value) for key, value in registers.items() if isinstance(value, int)
        }
        kind, reads = _definition_kind(opcodes, typed_registers)
        candidates.append(
            {
                "trace_index": index,
                "bank": int(parsed["bank"]),
                "pc": int(parsed["pc"]),
                "opcodes_hex": opcodes.hex(),
                "definition_kind": kind,
                "read_addresses": reads,
                "registers": typed_registers,
            }
        )
    kinds = {name: 0 for name in ("memory", "immediate", "register", "arithmetic")}
    for candidate in candidates:
        kind = str(candidate["definition_kind"])
        if kind in kinds:
            kinds[kind] += 1
    counts = {
        "trace_line_count": len(lines),
        "parsed_trace_line_count": parsed_count,
        "source_definition_candidate_count": len(candidates),
        "memory_definition_candidate_count": kinds["memory"],
        "immediate_definition_candidate_count": kinds["immediate"],
        "register_definition_candidate_count": kinds["register"],
        "arithmetic_definition_candidate_count": kinds["arithmetic"],
        "unique_definition_pc_count": len(
            {(int(item["bank"]), int(item["pc"])) for item in candidates}
        ),
    }
    return counts, {"candidates": candidates, "selected": candidates[-1] if candidates else None}


def _definition_source_class(local_analysis: dict[str, object]) -> str:
    selected = local_analysis.get("selected")
    if not isinstance(selected, dict):
        return "unresolved"
    kind = str(selected.get("definition_kind"))
    if kind != "memory":
        return kind if kind in {"immediate", "register", "arithmetic"} else "unresolved"
    reads = selected.get("read_addresses")
    if not isinstance(reads, list) or not reads:
        return "unresolved"
    if all(0xC000 <= int(address) <= 0xFFFF for address in reads):
        return "system-ram"
    if all(0 <= int(address) <= 0xBFFF for address in reads):
        return "rom-window"
    return "unresolved"


def build_active_ram_register_trace(
    *,
    target_sha256: str,
    source_active_ram_writer_sha256: str,
    analysis: dict[str, int],
    writer_instance_confirmed: bool,
    definition_source_class: str,
    captured_utc: str,
) -> dict[str, object]:
    confirmed = (
        writer_instance_confirmed
        and int(analysis["source_definition_candidate_count"]) > 0
        and definition_source_class != "unresolved"
    )
    next_checkpoint = {
        "rom-window": "map-active-register-rom-source",
        "system-ram": "trace-active-register-ram-source",
        "immediate": "map-active-register-immediate-source",
        "register": "trace-active-register-move-source",
        "arithmetic": "trace-active-register-arithmetic-source",
        "unresolved": "extend-active-register-definition-trace",
    }[definition_source_class]
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "active-ram-register-definition-confirmed"
            if confirmed
            else "active-ram-register-definition-unresolved"
        ),
        "target_sha256": target_sha256,
        "source_active_ram_writer_sha256": source_active_ram_writer_sha256,
        "captured_utc": captured_utc,
        "analysis": {key: int(analysis[key]) for key in COUNT_KEYS},
        "writer_instance_confirmed": writer_instance_confirmed,
        "register_definition_confirmed": confirmed,
        "definition_source_class": definition_source_class,
        "baseline_script_bytes_unchanged": True,
        "local_payload_policy": (
            "register-names-addresses-opcodes-pcs-values-and-traces-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": next_checkpoint,
    }
    validate_active_ram_register_trace(value)
    return value


def validate_active_ram_register_trace(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("active RAM register trace fields do not match")
    source_class = value["definition_source_class"]
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"] not in {
            "active-ram-register-definition-confirmed",
            "active-ram-register-definition-unresolved",
        }
        or source_class not in {
            "rom-window", "system-ram", "immediate", "register", "arithmetic", "unresolved"
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_active_ram_writer_sha256"])
    ):
        raise ValueError("active RAM register trace policy is invalid")
    counts = value["analysis"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("active RAM register trace counts do not match")
    if any(not isinstance(counts[key], int) or isinstance(counts[key], bool) or counts[key] < 0 for key in COUNT_KEYS):
        raise ValueError("active RAM register trace count is invalid")
    candidates = int(counts["source_definition_candidate_count"])
    categorized = sum(
        int(counts[key])
        for key in (
            "memory_definition_candidate_count",
            "immediate_definition_candidate_count",
            "register_definition_candidate_count",
            "arithmetic_definition_candidate_count",
        )
    )
    confirmed = value["writer_instance_confirmed"] is True and candidates > 0 and source_class != "unresolved"
    expected_next = {
        "rom-window": "map-active-register-rom-source",
        "system-ram": "trace-active-register-ram-source",
        "immediate": "map-active-register-immediate-source",
        "register": "trace-active-register-move-source",
        "arithmetic": "trace-active-register-arithmetic-source",
        "unresolved": "extend-active-register-definition-trace",
    }[str(source_class)]
    if (
        categorized != candidates
        or candidates > int(counts["parsed_trace_line_count"])
        or int(counts["parsed_trace_line_count"]) > int(counts["trace_line_count"])
        or int(counts["unique_definition_pc_count"]) > candidates
        or value["status"] != ("active-ram-register-definition-confirmed" if confirmed else "active-ram-register-definition-unresolved")
        or value["register_definition_confirmed"] is not confirmed
        or value["baseline_script_bytes_unchanged"] is not True
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"] != expected_next
        or value["local_payload_policy"] != "register-names-addresses-opcodes-pcs-values-and-traces-local-only"
    ):
        raise ValueError("active RAM register trace result is inconsistent")


def _is_current(path: Path, *, target_sha256: str, source_sha256: str) -> bool:
    if not path.is_file():
        return False
    try:
        value = _load_json_object(path)
        validate_active_ram_register_trace(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return value["target_sha256"] == target_sha256 and value["source_active_ram_writer_sha256"] == source_sha256


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    paths = {
        "producer": root / PRODUCER_PATH,
        "producer_local": root / PRODUCER_LOCAL_PATH,
        "writer": root / WRITER_SOURCE_PATH,
        "writer_local": root / WRITER_SOURCE_LOCAL_PATH,
    }
    if not rom_path.is_file() or not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print("Active RAM register definition trace is not ready")
            return 0
        raise SystemExit("active RAM register trace input is missing")
    producer = _load_json_object(paths["producer"])
    producer_local = _load_json_object(paths["producer_local"])
    writer_safe = _load_json_object(paths["writer"])
    writer_local = _load_json_object(paths["writer_local"])
    validate_active_ram_producer(producer)
    validate_active_ram_writer_source(writer_safe)
    target_sha256 = sha256_file(rom_path)
    writer_sha256 = sha256_file(paths["writer"])
    publish_path = root / PUBLISH_RELATIVE_PATH
    local_path = root / LOCAL_REPORT_PATH
    if _is_current(publish_path, target_sha256=target_sha256, source_sha256=writer_sha256):
        print("Active RAM register definition trace is already current")
        return 0
    if writer_safe["writer_source_class"] != "register":
        if args.if_ready:
            print("Active RAM register definition trace is not ready")
            return 0
        raise ValueError("active RAM writer does not use a register source")
    candidates = writer_local.get("analysis", {}).get("candidates", [])
    if not isinstance(candidates, list) or len(candidates) != 1 or not isinstance(candidates[0], dict):
        raise ValueError("active RAM register writer candidate is ambiguous")
    candidate = candidates[0]
    source = candidate.get("source")
    writer = candidate.get("writer")
    if not isinstance(source, dict) or not isinstance(writer, dict) or source.get("kind") != "register":
        raise ValueError("active RAM register source detail is invalid")
    source_register = str(source.get("register"))
    event_index = int(candidate["event_index"])
    latest = producer_local.get("analysis", {}).get("latest_writer_event", {})
    target_values = producer_local.get("analysis", {}).get("target_values", {})
    if not isinstance(latest, dict) or not isinstance(target_values, dict):
        raise ValueError("active RAM register target detail is invalid")
    sentinel_addresses = sorted(int(address, 16) for address, index in latest.items() if int(index) == event_index)
    if len(sentinel_addresses) != 1:
        raise ValueError("active RAM register sentinel is ambiguous")
    sentinel = sentinel_addresses[0]
    expected_value = int(target_values[f"0x{sentinel:04X}"])
    writer_bank = int(writer["bank"])
    writer_physical_pc = int(writer["physical_pc"])
    all_target_addresses = sorted(int(address, 16) for address in target_values)
    prior_addresses = [address for address in all_target_addresses if address < sentinel]
    if not prior_addresses:
        raise ValueError("active RAM register predecessor anchor is unavailable")
    predecessor = prior_addresses[-min(PREDECESSOR_DISTANCE, len(prior_addresses))]
    rom = rom_path.read_bytes()
    client = McpStdioClient(_default_command())
    armed_write_address: int | None = None
    fast_forward = trace_enabled = False
    runtime_stage = "active-ram-register-trace-initialize"
    first_state = second_state = None
    lines: list[str] = []
    local_trace: dict[str, object] = {}
    try:
        tools = client.initialize()
        missing = sorted(REQUIRED_TOOLS - tools)
        if missing:
            raise RuntimeError(f"Gearsystem MCP tools missing: {missing}")
        runtime_stage = "active-ram-register-trace-load-media"
        client.call("load_media", {"file_path": str(rom_path)})
        client.call("debug_reset")
        client.call("debug_pause")
        client.call("set_trace_log", {"enabled": False})
        _set_write_range(client, predecessor, predecessor)
        armed_write_address = predecessor
        runtime_stage = "active-ram-register-trace-writer-watch"
        _set_unlimited_fast_forward(client, True)
        fast_forward = True
        deadline = time.monotonic() + WRITER_WATCH_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            status = _continue_until_breakpoint(client, min(20.0, max(0.1, deadline - time.monotonic())))
            if status.get("at_breakpoint") is not True:
                continue
            state, _ = _capture_producer_state(client)
            observed = previous_target_write(rom, state, {predecessor})
            if observed is not None and int(observed["bank"]) == writer_bank and int(observed["physical_pc"]) == writer_physical_pc:
                first_state = state
                break
        if first_state is None:
            raise RuntimeError("active RAM register writer instance was not reached")
        _set_unlimited_fast_forward(client, False)
        fast_forward = False
        _remove_range(client, predecessor, predecessor)
        armed_write_address = None
        _set_write_range(client, sentinel, sentinel)
        armed_write_address = sentinel
        started = client.call("set_trace_log", {"enabled": True, "cpu_irq": False, "vdp_write": False, "vdp_status": False, "psg": False, "ym2413": False, "io_port": False, "bank_switch": True})
        trace_enabled = True
        trace_start = int(started.get("total_entries", -1))
        if not 0 <= trace_start < TRACE_BUFFER_SIZE:
            raise RuntimeError("active RAM register trace start is invalid")
        runtime_stage = "active-ram-register-trace-short-window"
        status = _continue_until_breakpoint(client, NEXT_WRITER_TIMEOUT_SECONDS)
        if status.get("at_breakpoint") is not True:
            raise RuntimeError("active RAM register target writer was not reached")
        second_state, _ = _capture_producer_state(client)
        observed = previous_target_write(rom, second_state, {sentinel})
        if observed is None or int(observed["bank"]) != writer_bank or int(observed["physical_pc"]) != writer_physical_pc:
            raise RuntimeError("active RAM register target writer identity disagrees")
        stopped = client.call("set_trace_log", {"enabled": False})
        trace_enabled = False
        trace_end = int(stopped.get("total_entries", -1))
        if not trace_start <= trace_end < TRACE_BUFFER_SIZE:
            raise RuntimeError("active RAM register trace window is invalid")
        lines, pages = _read_trace_window(client, start=trace_start, end=trace_end)
        local_trace = {"trace_start": trace_start, "trace_end": trace_end, "trace_pages": pages}
    except Exception as error:
        _write_runtime_failure_receipt(root, _runtime_failure_receipt(runtime_stage, error, client))
        raise
    finally:
        if trace_enabled:
            try: client.call("set_trace_log", {"enabled": False})
            except Exception: pass
        if fast_forward:
            try: _set_unlimited_fast_forward(client, False)
            except Exception: pass
        if armed_write_address is not None:
            try: _remove_range(client, armed_write_address, armed_write_address)
            except Exception: pass
        client.close()
    counts, local_analysis = analyze_register_trace(lines, source_register)
    source_class = _definition_source_class(local_analysis)
    captured_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    safe = build_active_ram_register_trace(target_sha256=target_sha256, source_active_ram_writer_sha256=writer_sha256, analysis=counts, writer_instance_confirmed=True, definition_source_class=source_class, captured_utc=captured_utc)
    local = {"artifact_kind": "local-s25u-active-ram-register-trace", "schema_version": 1, "target_sha256": target_sha256, "source_active_ram_writer_sha256": writer_sha256, "captured_utc": captured_utc, "source_register": source_register, "predecessor_address": predecessor, "sentinel_address": sentinel, "expected_value": expected_value, "writer": writer, "first_state": first_state, "second_state": second_state, "raw_trace_lines": lines, "trace": local_trace, "analysis": local_analysis, "publication_policy": "never-publish-register-names-addresses-opcodes-pcs-values-or-traces"}
    publish_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    publish_path.write_text(json.dumps(safe, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    local_path.write_text(json.dumps(local, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"SFKR active RAM register trace: {publish_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
