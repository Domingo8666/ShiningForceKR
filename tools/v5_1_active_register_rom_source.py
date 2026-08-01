#!/usr/bin/env python3
"""Map the confirmed active writer register read to a physical ROM offset."""

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
        _parse_mapper,
        _runtime_failure_receipt,
        _step_instruction_and_wait,
        _write_runtime_failure_receipt,
    )
    from .v5_1_active_ram_producer import (
        _capture_producer_state,
        _load_json_object,
    )
    from .v5_1_active_ram_register_trace import (
        LOCAL_REPORT_PATH as REGISTER_TRACE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as REGISTER_TRACE_PATH,
        validate_active_ram_register_trace,
    )
    from .v5_1_active_vram_route import _select_ram_area
    from .v5_1_renderer_output_trace import (
        DEFAULT_ROM,
        REQUIRED_TOOLS,
    )
    from .v5_1_test_display_capture import (
        _continue_until_breakpoint,
        _set_unlimited_fast_forward,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from run_s25u_runtime_probe import (
        McpStdioClient,
        _default_command,
        _parse_mapper,
        _runtime_failure_receipt,
        _step_instruction_and_wait,
        _write_runtime_failure_receipt,
    )
    from v5_1_active_ram_producer import _capture_producer_state, _load_json_object
    from v5_1_active_ram_register_trace import (
        LOCAL_REPORT_PATH as REGISTER_TRACE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as REGISTER_TRACE_PATH,
        validate_active_ram_register_trace,
    )
    from v5_1_active_vram_route import _select_ram_area
    from v5_1_renderer_output_trace import (
        DEFAULT_ROM,
        REQUIRED_TOOLS,
    )
    from v5_1_test_display_capture import (
        _continue_until_breakpoint,
        _set_unlimited_fast_forward,
    )


ARTIFACT_KIND = "sanitized-s25u-active-register-rom-source"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_active_register_rom_source.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_active_register_rom_source.json")
WATCH_TIMEOUT_SECONDS = 120.0
COUNT_KEYS = {
    "read_break_hit_count",
    "matching_read_hit_count",
    "logical_read_address_count",
    "physical_source_count",
    "rom_value_match_count",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_register_trace_sha256",
    "captured_utc",
    "analysis",
    "source_slot",
    "mapped_bank",
    "physical_source_offset",
    "rom_source_confirmed",
    "baseline_script_bytes_unchanged",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def source_slot(address: int) -> str:
    if 0 <= address < 0x4000:
        return "slot0"
    if 0x4000 <= address < 0x8000:
        return "slot1"
    if 0x8000 <= address < 0xC000:
        return "slot2"
    raise ValueError("active register source is outside the ROM windows")


def _set_read_breakpoint(client: McpStdioClient, address: int) -> None:
    client.call(
        "set_breakpoint_range",
        {
            "start_address": f"{address:04X}",
            "end_address": f"{address:04X}",
            "memory_area": "rom_ram",
            "execute": False,
            "read": True,
            "write": False,
        },
    )


def _remove_read_breakpoint(client: McpStdioClient, address: int) -> None:
    client.call(
        "remove_breakpoint",
        {
            "address": f"{address:04X}",
            "end_address": f"{address:04X}",
            "memory_area": "rom_ram",
        },
    )


def physical_rom_source(
    address: int,
    *,
    slot0_bank: int,
    slot1_bank: int,
    slot2_bank: int,
    rom_size: int,
) -> tuple[int, int]:
    slot = source_slot(address)
    bank = {"slot0": slot0_bank, "slot1": slot1_bank, "slot2": slot2_bank}[slot]
    offset = bank * 0x4000 + (address & 0x3FFF)
    if not 0 <= offset < rom_size:
        raise ValueError("active register physical ROM source is out of range")
    return bank, offset


def build_active_register_rom_source(
    *,
    target_sha256: str,
    source_register_trace_sha256: str,
    analysis: dict[str, int],
    source_slot_name: str,
    mapped_bank: int,
    physical_source_offset: int,
    captured_utc: str,
) -> dict[str, object]:
    confirmed = (
        int(analysis["matching_read_hit_count"]) == 1
        and int(analysis["logical_read_address_count"]) == 1
        and int(analysis["physical_source_count"]) == 1
        and int(analysis["rom_value_match_count"]) == 1
    )
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "active-register-rom-source-confirmed"
            if confirmed
            else "active-register-rom-source-unresolved"
        ),
        "target_sha256": target_sha256,
        "source_register_trace_sha256": source_register_trace_sha256,
        "captured_utc": captured_utc,
        "analysis": {key: int(analysis[key]) for key in COUNT_KEYS},
        "source_slot": source_slot_name,
        "mapped_bank": mapped_bank,
        "physical_source_offset": physical_source_offset,
        "rom_source_confirmed": confirmed,
        "baseline_script_bytes_unchanged": True,
        "local_payload_policy": (
            "logical-addresses-values-opcodes-registers-and-mapper-bytes-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": (
            "correlate-active-rom-source-with-script-or-font"
            if confirmed
            else "extend-active-register-rom-mapping"
        ),
    }
    validate_active_register_rom_source(value)
    return value


def validate_active_register_rom_source(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("active register ROM source fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"] not in {
            "active-register-rom-source-confirmed",
            "active-register-rom-source-unresolved",
        }
        or value["source_slot"] not in {"slot0", "slot1", "slot2"}
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_register_trace_sha256"])
        or not isinstance(value["mapped_bank"], int)
        or isinstance(value["mapped_bank"], bool)
        or not 0 <= int(value["mapped_bank"]) <= 255
        or not isinstance(value["physical_source_offset"], int)
        or isinstance(value["physical_source_offset"], bool)
        or int(value["physical_source_offset"]) < 0
    ):
        raise ValueError("active register ROM source policy is invalid")
    counts = value["analysis"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("active register ROM source counts do not match")
    if any(not isinstance(counts[key], int) or isinstance(counts[key], bool) or counts[key] < 0 for key in COUNT_KEYS):
        raise ValueError("active register ROM source count is invalid")
    confirmed = (
        int(counts["matching_read_hit_count"]) == 1
        and int(counts["logical_read_address_count"]) == 1
        and int(counts["physical_source_count"]) == 1
        and int(counts["rom_value_match_count"]) == 1
    )
    captured = value["captured_utc"]
    try:
        parsed = datetime.fromisoformat(str(captured).replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("active register ROM source timestamp is invalid") from error
    if (
        parsed.tzinfo is None
        or value["status"] != ("active-register-rom-source-confirmed" if confirmed else "active-register-rom-source-unresolved")
        or value["rom_source_confirmed"] is not confirmed
        or value["baseline_script_bytes_unchanged"] is not True
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"] != ("correlate-active-rom-source-with-script-or-font" if confirmed else "extend-active-register-rom-mapping")
        or value["local_payload_policy"] != "logical-addresses-values-opcodes-registers-and-mapper-bytes-local-only"
    ):
        raise ValueError("active register ROM source result is inconsistent")


def _is_current(path: Path, *, target_sha256: str, source_sha256: str) -> bool:
    if not path.is_file():
        return False
    try:
        value = _load_json_object(path)
        validate_active_register_rom_source(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return value["target_sha256"] == target_sha256 and value["source_register_trace_sha256"] == source_sha256


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    trace_path = root / REGISTER_TRACE_PATH
    trace_local_path = root / REGISTER_TRACE_LOCAL_PATH
    publish_path = root / PUBLISH_RELATIVE_PATH
    local_path = root / LOCAL_REPORT_PATH
    if not all(path.is_file() for path in (rom_path, trace_path, trace_local_path)):
        if args.if_ready:
            print("Active register ROM source mapping is not ready")
            return 0
        raise SystemExit("active register ROM source input is missing")
    trace_safe = _load_json_object(trace_path)
    trace_local = _load_json_object(trace_local_path)
    validate_active_ram_register_trace(trace_safe)
    target_sha256 = sha256_file(rom_path)
    trace_sha256 = sha256_file(trace_path)
    if _is_current(publish_path, target_sha256=target_sha256, source_sha256=trace_sha256):
        print("Active register ROM source mapping is already current")
        return 0
    if trace_safe["definition_source_class"] != "rom-window" or trace_safe["register_definition_confirmed"] is not True:
        if args.if_ready:
            print("Active register ROM source mapping is not ready")
            return 0
        raise ValueError("active register trace does not confirm a ROM read")
    selected = trace_local.get("analysis", {}).get("selected")
    if not isinstance(selected, dict):
        raise ValueError("active register ROM source selection is missing")
    expected_bank = int(selected["bank"])
    expected_pc = int(selected["pc"])
    expected_opcodes = bytes.fromhex(str(selected["opcodes_hex"]))
    expected_reads = [int(address) for address in selected["read_addresses"]]
    if len(expected_reads) != 1:
        raise ValueError("active register ROM source read is ambiguous")
    logical_source = expected_reads[0]
    rom = rom_path.read_bytes()
    client = McpStdioClient(_default_command())
    execute_armed = fast_forward = False
    selected_state = None
    mapper_payload = None
    hit_count = 0
    runtime_stage = "active-register-rom-source-initialize"
    try:
        tools = client.initialize()
        missing = sorted(REQUIRED_TOOLS - tools)
        if missing:
            raise RuntimeError(f"Gearsystem MCP tools missing: {missing}")
        runtime_stage = "active-register-rom-source-load-media"
        client.call("load_media", {"file_path": str(rom_path)})
        client.call("debug_reset")
        client.call("debug_pause")
        client.call("set_trace_log", {"enabled": False})
        areas = client.call("list_memory_areas")
        ram_area = _select_ram_area(areas)
        mapper_offset = int(ram_area["size"]) - 4
        _set_read_breakpoint(client, logical_source)
        execute_armed = True
        _set_unlimited_fast_forward(client, True)
        fast_forward = True
        runtime_stage = "active-register-rom-source-watch"
        deadline = time.monotonic() + WATCH_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            status = _continue_until_breakpoint(client, min(20.0, max(0.1, deadline - time.monotonic())))
            if status.get("at_breakpoint") is not True:
                continue
            hit_count += 1
            state, _ = _capture_producer_state(client)
            registers = state["registers"]
            assert isinstance(registers, dict)
            expected_pc_after = (expected_pc + len(expected_opcodes)) & 0xFFFF
            if int(state["executing_bank"]) == expected_bank and int(state["pc_after"]) == expected_pc_after:
                selected_state = state
                _set_unlimited_fast_forward(client, False)
                fast_forward = False
                _remove_read_breakpoint(client, logical_source)
                execute_armed = False
                _step_instruction_and_wait(client)
                mapper_payload = client.call("read_memory", {"area": int(ram_area["id"]), "offset": f"{mapper_offset:04X}", "size": 4})
                break
        if selected_state is None or mapper_payload is None:
            raise RuntimeError("active register ROM source execution was not reached")
    except Exception as error:
        _write_runtime_failure_receipt(root, _runtime_failure_receipt(runtime_stage, error, client))
        raise
    finally:
        if fast_forward:
            try: _set_unlimited_fast_forward(client, False)
            except Exception: pass
        if execute_armed:
            try: _remove_read_breakpoint(client, logical_source)
            except Exception: pass
        client.close()
    _, slot0, slot1, slot2 = _parse_mapper(mapper_payload.get("data"))
    mapped_bank, physical_offset = physical_rom_source(logical_source, slot0_bank=slot0, slot1_bank=slot1, slot2_bank=slot2, rom_size=len(rom))
    expected_value = int(trace_local.get("expected_value", -1))
    rom_value = rom[physical_offset]
    counts = {"read_break_hit_count": hit_count, "matching_read_hit_count": 1, "logical_read_address_count": 1, "physical_source_count": 1, "rom_value_match_count": int(rom_value == expected_value)}
    captured_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    safe = build_active_register_rom_source(target_sha256=target_sha256, source_register_trace_sha256=trace_sha256, analysis=counts, source_slot_name=source_slot(logical_source), mapped_bank=mapped_bank, physical_source_offset=physical_offset, captured_utc=captured_utc)
    local = {"artifact_kind": "local-s25u-active-register-rom-source", "schema_version": 1, "target_sha256": target_sha256, "source_register_trace_sha256": trace_sha256, "captured_utc": captured_utc, "logical_source": logical_source, "mapped_bank": mapped_bank, "physical_source_offset": physical_offset, "rom_value": rom_value, "expected_value": expected_value, "selected_definition": selected, "selected_state": selected_state, "mapper": mapper_payload, "publication_policy": "never-publish-logical-addresses-values-opcodes-registers-or-mapper-bytes"}
    publish_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    publish_path.write_text(json.dumps(safe, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    local_path.write_text(json.dumps(local, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"SFKR active register ROM source: {publish_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
