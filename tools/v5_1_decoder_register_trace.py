#!/usr/bin/env python3
"""Capture a byte-free register trace from the confirmed v5.1 decoder entry."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

try:
    from .patch_io import sha256_file
    from .run_s25u_runtime_probe import (
        REQUIRED_TOOLS,
        McpStdioClient,
        _capture_state,
        _default_command,
        _runtime_failure_receipt,
        _step_instruction_and_wait,
        _write_runtime_failure_receipt,
    )
    from .v5_1_consumer import verify_target_identity
    from .run_s25u_renderer_probe import (
        ATTRACT_ROUTE_SCHEDULE,
        _decoder_entry_mappings,
        _probe_decoder_entry,
    )
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from run_s25u_runtime_probe import (
        REQUIRED_TOOLS,
        McpStdioClient,
        _capture_state,
        _default_command,
        _runtime_failure_receipt,
        _step_instruction_and_wait,
        _write_runtime_failure_receipt,
    )
    from v5_1_consumer import verify_target_identity
    from run_s25u_renderer_probe import (
        ATTRACT_ROUTE_SCHEDULE,
        _decoder_entry_mappings,
        _probe_decoder_entry,
    )

ARTIFACT_KIND = "sanitized-decoder-register-trace"
SCHEMA_VERSION = 1
DEFAULT_ROM = Path("build/Final_Conflict_Korean_v5.1.gg")
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_decoder_register_trace.json"
)
DECODER_ENTRY = 0x33FA
EXPECTED_SELECTOR_DE = 2
TRACE_STEPS = 64
MIN_USEFUL_PARTIAL_STEPS = 8
STATE_KEYS = {
    "pc",
    "af",
    "bc",
    "de",
    "hl",
    "sp",
    "slot0_bank",
    "slot1_bank",
    "slot2_bank",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "target_sha256",
    "status",
    "captured_utc",
    "decoder_entry",
    "selector_de",
    "step_count",
    "states",
    "translation_build_eligible",
    "next_checkpoint",
}


def _safe_state(state: dict[str, object]) -> dict[str, int]:
    registers = state.get("registers")
    if not isinstance(registers, dict):
        raise RuntimeError("decoder trace state has no registers")
    return {
        "pc": int(state["pc_after"]),
        "af": int(registers["af"]),
        "bc": int(registers["bc"]),
        "de": int(registers["de"]),
        "hl": int(registers["hl"]),
        "sp": int(registers["sp"]),
        "slot0_bank": int(state["slot0_bank"]),
        "slot1_bank": int(state["slot1_bank"]),
        "slot2_bank": int(state["slot2_bank"]),
    }


def validate_decoder_register_trace(trace: dict[str, object]) -> None:
    if set(trace) != TOP_LEVEL_KEYS:
        raise ValueError("decoder register trace fields do not match")
    if trace["artifact_kind"] != ARTIFACT_KIND:
        raise ValueError("unexpected decoder register trace kind")
    if trace["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unexpected decoder register trace schema")
    if trace["status"] not in {
        "decoder-register-trace-captured",
        "decoder-register-trace-partial",
    }:
        raise ValueError("decoder register trace is incomplete")
    digest = trace["target_sha256"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(value not in "0123456789abcdef" for value in digest)
    ):
        raise ValueError("decoder register trace target identity is invalid")
    captured = trace["captured_utc"]
    if (
        not isinstance(captured, str)
        or len(captured) != 20
        or not captured.endswith("Z")
    ):
        raise ValueError("decoder register trace timestamp is invalid")
    if trace["decoder_entry"] != DECODER_ENTRY:
        raise ValueError("unexpected decoder entry")
    if trace["selector_de"] != EXPECTED_SELECTOR_DE:
        raise ValueError("unexpected decoder selector")
    states = trace["states"]
    if (
        not isinstance(states, list)
        or not 2 <= len(states) <= TRACE_STEPS + 1
        or trace["step_count"] != len(states) - 1
    ):
        raise ValueError("decoder register trace length is invalid")
    for state in states:
        if not isinstance(state, dict) or set(state) != STATE_KEYS:
            raise ValueError("decoder register state fields do not match")
        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= 0xFFFF
            for value in state.values()
        ):
            raise ValueError("decoder register state value is invalid")
        if any(
            state[key] > 0xFF
            for key in ("slot0_bank", "slot1_bank", "slot2_bank")
        ):
            raise ValueError("decoder mapper bank is invalid")
    if trace["translation_build_eligible"] is not False:
        raise ValueError("register trace cannot approve a translation build")
    if trace["next_checkpoint"] != "resolve-decoder-bc-register-role":
        raise ValueError("unexpected decoder register trace checkpoint")


def _write_trace(root: Path, trace: dict[str, object]) -> Path:
    validate_decoder_register_trace(trace)
    path = root / PUBLISH_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(trace, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
    return path


def decoder_register_trace_needed(root: Path) -> bool:
    diagnostic_path = (
        root / "analysis/device/v5_1_latest_runtime_diagnostic.json"
    )
    target_path = root / DEFAULT_ROM
    if not diagnostic_path.is_file() or not target_path.is_file():
        return False
    try:
        diagnostic = json.loads(
            diagnostic_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return False
    failure = (
        diagnostic.get("runtime_failure")
        if isinstance(diagnostic, dict)
        else None
    )
    if (
        not isinstance(failure, dict)
        or failure.get("failure_stage")
        not in {
            "decoder-register-trace",
            "test-patch-fixed-count-read-range",
        }
    ):
        return False
    trace_path = root / PUBLISH_RELATIVE_PATH
    if not trace_path.is_file():
        return True
    try:
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        if not isinstance(trace, dict):
            return True
        validate_decoder_register_trace(trace)
        return (
            trace["target_sha256"] != sha256_file(target_path)
            or (
                trace["status"] == "decoder-register-trace-partial"
                and int(trace["step_count"]) < MIN_USEFUL_PARTIAL_STEPS
            )
        )
    except (OSError, ValueError, json.JSONDecodeError):
        return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    rom = rom_path.read_bytes()
    verify_target_identity(rom)
    target_sha256 = sha256_file(rom_path)
    states: list[dict[str, int]] = []

    def write_current_trace(status: str) -> Path:
        trace: dict[str, object] = {
            "artifact_kind": ARTIFACT_KIND,
            "schema_version": SCHEMA_VERSION,
            "target_sha256": target_sha256,
            "status": status,
            "captured_utc": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "decoder_entry": DECODER_ENTRY,
            "selector_de": EXPECTED_SELECTOR_DE,
            "step_count": len(states) - 1,
            "states": states,
            "translation_build_eligible": False,
            "next_checkpoint": "resolve-decoder-bc-register-role",
        }
        return _write_trace(root, trace)

    client = McpStdioClient(_default_command())
    stage = "decoder-register-trace"
    try:
        tools = client.initialize()
        missing = sorted(REQUIRED_TOOLS - tools)
        if missing:
            raise RuntimeError(f"Gearsystem MCP tools missing: {missing}")
        client.call("load_media", {"file_path": str(rom_path)})
        media = client.call("get_media_info")
        if (
            media.get("ready") is not True
            or media.get("is_game_gear") is not True
            or int(media.get("rom_size", 0)) != len(rom)
        ):
            raise RuntimeError("Gearsystem did not load the target ROM")
        entry_state, _ = _probe_decoder_entry(
            client,
            _decoder_entry_mappings(),
            schedule=ATTRACT_ROUTE_SCHEDULE,
        )
        if entry_state is None:
            raise RuntimeError("confirmed decoder entry was not reached")
        registers = entry_state.get("registers")
        if (
            int(entry_state["pc_after"]) != DECODER_ENTRY
            or not isinstance(registers, dict)
            or registers.get("de") != EXPECTED_SELECTOR_DE
        ):
            raise RuntimeError("decoder entry selector did not match")

        states.append(_safe_state(entry_state))
        for _ in range(TRACE_STEPS):
            _step_instruction_and_wait(client)
            state, _ = _capture_state(client)
            states.append(_safe_state(state))
        path = write_current_trace("decoder-register-trace-captured")
        print(f"SFKR decoder register trace: {path}")
        return 0
    except Exception as error:
        if len(states) - 1 >= MIN_USEFUL_PARTIAL_STEPS:
            write_current_trace("decoder-register-trace-partial")
        receipt = _runtime_failure_receipt(stage, error, client)
        _write_runtime_failure_receipt(root, receipt)
        raise
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
