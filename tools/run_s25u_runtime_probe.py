#!/usr/bin/env python3
"""Run a ROM-local Gearsystem MCP read-breakpoint experiment on S25U."""

from __future__ import annotations

import argparse
from collections import deque
import json
from pathlib import Path
import subprocess
import threading
from typing import Any

try:
    from .patch_io import sha256_file
    from .v5_1_consumer import verify_target_identity
    from .v5_1_runtime_observation import (
        build_runtime_observation,
        publish_runtime_observation,
        write_runtime_observation,
    )
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from v5_1_consumer import verify_target_identity
    from v5_1_runtime_observation import (
        build_runtime_observation,
        publish_runtime_observation,
        write_runtime_observation,
    )

DEFAULT_ROM = Path("build/Final_Conflict_Korean_v5.1.gg")
DEFAULT_TRACE_PLAN = Path("reports/v5_1_emucap_trace_plan.json")
LOCAL_REPORT = Path("reports/local/v5_1_gearsystem_probe.json")
GEARSYSTEM_COMMAND = (
    "cd /opt/sfkr-gearsystem && "
    "exec ./gearsystem --headless --mcp-stdio"
)
REQUIRED_TOOLS = {
    "controller_button",
    "debug_get_status",
    "debug_pause",
    "debug_reset",
    "debug_step_frame",
    "get_call_stack",
    "get_media_info",
    "get_trace_log",
    "get_z80_status",
    "list_memory_areas",
    "load_media",
    "read_memory",
    "remove_breakpoint",
    "set_breakpoint_range",
    "set_trace_log",
}
INPUT_SCHEDULE: tuple[tuple[int, str | None], ...] = (
    (180, None),
    (60, "start"),
    (120, "1"),
    (120, "1"),
    (120, "1"),
    (120, "1"),
    (120, "1"),
    (120, "1"),
    (120, "1"),
    (120, "1"),
    (120, "1"),
    (120, "1"),
    (120, "1"),
    (120, "1"),
)


def _tool_payload(message: dict[str, object]) -> dict[str, Any]:
    result = message.get("result")
    if not isinstance(result, dict):
        raise RuntimeError("MCP response has no result object")
    if result.get("isError"):
        content = result.get("content")
        raise RuntimeError(f"Gearsystem tool error: {content}")
    content = result.get("content")
    if not isinstance(content, list):
        raise RuntimeError("Gearsystem tool response has no content")
    text = next(
        (
            item.get("text")
            for item in content
            if isinstance(item, dict) and isinstance(item.get("text"), str)
        ),
        None,
    )
    if text is None:
        raise RuntimeError("Gearsystem tool response has no JSON text")
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise RuntimeError("Gearsystem tool payload must be an object")
    return payload


class McpStdioClient:
    def __init__(self, command: list[str]) -> None:
        self._process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        if self._process.stdin is None or self._process.stdout is None:
            raise RuntimeError("failed to open Gearsystem MCP pipes")
        self._stdin = self._process.stdin
        self._stdout = self._process.stdout
        self._next_id = 1
        self.stderr_tail: deque[str] = deque(maxlen=80)
        if self._process.stderr is not None:
            threading.Thread(
                target=self._drain_stderr,
                args=(self._process.stderr,),
                daemon=True,
            ).start()

    def _drain_stderr(self, stream: Any) -> None:
        for line in stream:
            self.stderr_tail.append(line.rstrip())

    def _request(self, method: str, params: dict[str, object]) -> dict[str, object]:
        request_id = self._next_id
        self._next_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        self._stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        self._stdin.flush()
        while True:
            line = self._stdout.readline()
            if not line:
                raise RuntimeError(
                    "Gearsystem MCP stopped before responding; stderr tail: "
                    + " | ".join(self.stderr_tail)
                )
            try:
                response = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(response, dict) and response.get("id") == request_id:
                if "error" in response:
                    raise RuntimeError(f"MCP error: {response['error']}")
                return response

    def initialize(self) -> set[str]:
        self._request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "SFKR-S25U-probe", "version": "1"},
            },
        )
        self._stdin.write(
            '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n'
        )
        self._stdin.flush()
        response = self._request("tools/list", {})
        result = response.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            raise RuntimeError("Gearsystem returned no MCP tool list")
        return {
            item["name"]
            for item in result["tools"]
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }

    def call(self, name: str, arguments: dict[str, object] | None = None) -> dict[str, Any]:
        return _tool_payload(
            self._request(
                "tools/call",
                {"name": name, "arguments": arguments or {}},
            )
        )

    def close(self) -> None:
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=5)


def _watch_ranges(plan: dict[str, object]) -> list[dict[str, int]]:
    if int(plan.get("schema_version", 0)) < 5:
        raise ValueError("trace plan schema 5 or newer is required")
    watch = plan.get("selected_watch")
    if not isinstance(watch, dict):
        raise ValueError("trace plan has no selected watch")
    mappings = watch.get("logical_mappings")
    if not isinstance(mappings, list) or not mappings:
        raise ValueError("trace plan has no logical mappings")
    output: list[dict[str, int]] = []
    for item in mappings:
        if not isinstance(item, dict):
            raise ValueError("logical mapping must be an object")
        mapping = {
            "slot": int(item["slot"]),
            "expected_bank": int(item["bank"]),
            "logical_start": int(item["logical_start"]),
            "logical_end": int(item["logical_end"]),
        }
        if mapping["slot"] not in (0, 1, 2):
            raise ValueError("logical mapping has an invalid slot")
        if not 0 <= mapping["logical_start"] <= mapping["logical_end"] <= 0xFFFF:
            raise ValueError("logical mapping range is invalid")
        output.append(mapping)
    if len({item["slot"] for item in output}) != len(output):
        raise ValueError("logical mapping slots must be unique")
    return output


def _parse_hex(value: object, label: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a hex string")
    return int(value, 16)


def _parse_mapper(data: object) -> tuple[int, int, int, int]:
    if not isinstance(data, str):
        raise ValueError("mapper data must be a hex byte string")
    values = [int(token, 16) for token in data.split()]
    if len(values) != 4 or any(not 0 <= value <= 255 for value in values):
        raise ValueError("mapper snapshot must contain four bytes")
    return values[0], values[1], values[2], values[3]


def _call_stack_depth(payload: dict[str, object]) -> int:
    for key in ("frames", "call_stack", "stack"):
        value = payload.get(key)
        if isinstance(value, list):
            return len(value)
    return 0


def _frames_per_slot() -> int:
    return sum(frames for frames, _ in INPUT_SCHEDULE)


def _capture_hit(
    client: McpStdioClient,
    mapping: dict[str, int],
) -> tuple[dict[str, object], dict[str, object]]:
    status = client.call("debug_get_status")
    z80 = client.call("get_z80_status")
    areas = client.call("list_memory_areas")
    area_list = areas.get("areas")
    if not isinstance(area_list, list):
        raise RuntimeError("Gearsystem returned no memory areas")
    ram = next(
        (
            item
            for item in area_list
            if isinstance(item, dict)
            and item.get("name") == "RAM"
            and isinstance(item.get("id"), int)
            and isinstance(item.get("size"), int)
            and item["size"] >= 0x2000
        ),
        None,
    )
    if ram is None:
        raise RuntimeError("Gearsystem RAM area was not found")
    mapper_offset = int(ram["size"]) - 4
    mapper_payload = client.call(
        "read_memory",
        {
            "area": int(ram["id"]),
            "offset": f"{mapper_offset:04X}",
            "size": 4,
        },
    )
    mapper_control, slot0, slot1, slot2 = _parse_mapper(
        mapper_payload.get("data")
    )
    trace = client.call("get_trace_log", {"count": 256})
    call_stack = client.call("get_call_stack")
    registers = {
        key.lower(): _parse_hex(z80.get(key), key)
        for key in ("AF", "BC", "DE", "HL", "IX", "IY", "SP")
    }
    safe_hit: dict[str, object] = {
        **mapping,
        "pc_after": _parse_hex(status.get("pc"), "pc"),
        "physical_pc_after": _parse_hex(z80.get("physical_PC"), "physical_PC"),
        "executing_bank": _parse_hex(z80.get("bank"), "bank"),
        "mapper_control": mapper_control,
        "slot0_bank": slot0,
        "slot1_bank": slot1,
        "slot2_bank": slot2,
        "registers": registers,
        "trace_entries": int(trace.get("count", len(trace.get("lines", [])))),
        "call_stack_depth": _call_stack_depth(call_stack),
    }
    local_evidence = {
        "status": status,
        "z80": z80,
        "mapper": mapper_payload,
        "trace": trace,
        "call_stack": call_stack,
    }
    return safe_hit, local_evidence


def _probe_slot(
    client: McpStdioClient,
    mapping: dict[str, int],
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    client.call("debug_reset")
    client.call("debug_pause")
    start = f"{mapping['logical_start']:04X}"
    end = f"{mapping['logical_end']:04X}"
    client.call(
        "set_breakpoint_range",
        {
            "start_address": start,
            "end_address": end,
            "memory_area": "rom_ram",
            "execute": False,
            "read": True,
            "write": False,
        },
    )
    try:
        for frames, button in INPUT_SCHEDULE:
            if button is not None:
                client.call(
                    "controller_button",
                    {
                        "player": 1,
                        "button": button,
                        "action": "press_and_release",
                    },
                )
            client.call("debug_step_frame", {"frames": frames})
            status = client.call("debug_get_status")
            if status.get("at_breakpoint") is True:
                return _capture_hit(client, mapping)
    finally:
        try:
            client.call(
                "remove_breakpoint",
                {
                    "address": start,
                    "end_address": end,
                    "memory_area": "rom_ram",
                },
            )
        except RuntimeError:
            pass
    return None, None


def _default_command() -> list[str]:
    return [
        "proot-distro",
        "login",
        "--bind",
        "/storage/emulated/0:/storage/emulated/0",
        "ubuntu",
        "--",
        "bash",
        "-lc",
        GEARSYSTEM_COMMAND,
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    parser.add_argument("--trace-plan", type=Path, default=DEFAULT_TRACE_PLAN)
    parser.add_argument("--publish-safe-observation", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    rom_path = (root / args.rom).resolve() if not args.rom.is_absolute() else args.rom
    plan_path = (
        (root / args.trace_plan).resolve()
        if not args.trace_plan.is_absolute()
        else args.trace_plan
    )
    rom = rom_path.read_bytes()
    verify_target_identity(rom)
    target_sha256 = sha256_file(rom_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if not isinstance(plan, dict):
        raise ValueError("trace plan must be a JSON object")
    if plan.get("source_analysis_sha256") != target_sha256:
        raise ValueError("trace plan and local v5.1 ROM identities do not match")
    ranges = _watch_ranges(plan)

    client = McpStdioClient(_default_command())
    local_result: dict[str, object] = {
        "target_sha256": target_sha256,
        "trace_plan": str(plan_path),
        "rom": str(rom_path),
        "attempts": [],
    }
    slots_attempted: list[int] = []
    safe_hit: dict[str, object] | None = None
    emulator_version = "unknown"
    try:
        tools = client.initialize()
        missing = sorted(REQUIRED_TOOLS - tools)
        if missing:
            raise RuntimeError(f"Gearsystem MCP tools missing: {missing}")
        client.call("load_media", {"file_path": str(rom_path)})
        media = client.call("get_media_info")
        local_result["media"] = media
        if (
            media.get("ready") is not True
            or media.get("is_game_gear") is not True
            or int(media.get("rom_size", 0)) != len(rom)
        ):
            raise RuntimeError("Gearsystem did not load the expected Game Gear ROM")
        emulator_version = str(media.get("emulator_version", "unknown"))
        client.call(
            "set_trace_log",
            {
                "enabled": True,
                "cpu_irq": False,
                "vdp_write": False,
                "vdp_status": False,
                "psg": False,
                "ym2413": False,
                "io_port": False,
                "bank_switch": True,
            },
        )
        for mapping in ranges:
            slots_attempted.append(mapping["slot"])
            hit, evidence = _probe_slot(client, mapping)
            local_result["attempts"].append(
                {
                    "mapping": mapping,
                    "hit": hit,
                    "evidence": evidence,
                }
            )
            if hit is not None:
                safe_hit = hit
                break
    finally:
        local_result["stderr_tail"] = list(client.stderr_tail)
        client.close()

    local_path = root / LOCAL_REPORT
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local_result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    observation = build_runtime_observation(
        target_sha256=target_sha256,
        emulator_version=emulator_version,
        frames_per_slot=_frames_per_slot(),
        slots_attempted=slots_attempted,
        breakpoint_ranges=ranges,
        hit=safe_hit,
    )
    safe_path = write_runtime_observation(root, observation)
    print(
        "SFKR runtime observation: "
        + (
            f"read hit at PC 0x{safe_hit['pc_after']:04X}, slot {safe_hit['slot']}"
            if safe_hit is not None
            else "no read hit in the scripted intro window"
        )
    )
    print(f"Local evidence: {local_path}")
    print(f"Safe observation: {safe_path}")
    if args.publish_safe_observation:
        result = publish_runtime_observation(root, safe_path)
        print(f"Published runtime observation: {result['path']} @ {result['commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
