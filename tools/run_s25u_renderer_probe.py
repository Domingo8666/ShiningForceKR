#!/usr/bin/env python3
"""Trace verified v5.1 Korean renderer call sites on S25U."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from .patch_io import sha256_file
    from .run_s25u_runtime_probe import (
        MAX_REJECTED_BANK_HITS_PER_SLOT,
        REQUIRED_TOOLS,
        McpStdioClient,
        _capture_state,
        _default_command,
    )
    from .v5_1_consumer import verify_target_identity
    from .v5_1_renderer_observation import (
        build_renderer_observation,
        write_renderer_observation,
    )
    from .v5_1_trace_plan import logical_mapping_hypotheses
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from run_s25u_runtime_probe import (
        MAX_REJECTED_BANK_HITS_PER_SLOT,
        REQUIRED_TOOLS,
        McpStdioClient,
        _capture_state,
        _default_command,
    )
    from v5_1_consumer import verify_target_identity
    from v5_1_renderer_observation import (
        build_renderer_observation,
        write_renderer_observation,
    )
    from v5_1_trace_plan import logical_mapping_hypotheses

DEFAULT_ROM = Path("build/Final_Conflict_Korean_v5.1.gg")
LOCAL_REPORT = Path("reports/local/v5_1_renderer_probe.json")
CONSUMER_RESOLUTION = Path(
    "analysis/device/v5_1_latest_consumer_resolution.json"
)
RENDERER_CALL_SITES = (0x003FD5, 0x03FFB2)
IDLE_FRAME_CHUNKS = (300,) * 40


def _frame_budget() -> int:
    return sum(IDLE_FRAME_CHUNKS)


def _renderer_mappings() -> list[dict[str, int]]:
    output: list[dict[str, int]] = []
    for file_offset in RENDERER_CALL_SITES:
        for item in logical_mapping_hypotheses(file_offset, 1):
            output.append(
                {
                    "call_site_file_offset": file_offset,
                    "slot": int(item["slot"]),
                    "expected_bank": int(item["bank"]),
                    "logical_address": int(item["logical_start"]),
                }
            )
    return output


def _mapped_bank(
    state: dict[str, object],
    mapping: dict[str, int],
) -> int:
    return int(state[f"slot{int(mapping['slot'])}_bank"])


def _renderer_hit_matches(
    state: dict[str, object],
    mapping: dict[str, int],
) -> bool:
    return (
        _mapped_bank(state, mapping) == int(mapping["expected_bank"])
        and int(state["pc_after"]) == int(mapping["logical_address"])
        and int(state["physical_pc_after"])
        == int(mapping["call_site_file_offset"])
    )


def _probe_mappings(
    client: McpStdioClient,
    mappings: list[dict[str, int]],
) -> tuple[
    dict[str, object] | None,
    dict[str, object] | None,
    list[dict[str, int]],
]:
    client.call("debug_reset")
    client.call("debug_pause")
    addresses = [f"{mapping['logical_address']:04X}" for mapping in mappings]
    for address in addresses:
        client.call(
            "set_breakpoint_range",
            {
                "start_address": address,
                "end_address": address,
                "memory_area": "rom_ram",
                "execute": True,
                "read": False,
                "write": False,
            },
        )
    rejected: list[dict[str, int]] = []
    try:
        for frames in IDLE_FRAME_CHUNKS:
            while True:
                client.call("debug_step_frame", {"frames": frames})
                status = client.call("debug_get_status")
                if status.get("at_breakpoint") is not True:
                    break
                state, evidence = _capture_state(client)
                matching = next(
                    (
                        mapping
                        for mapping in mappings
                        if _renderer_hit_matches(state, mapping)
                    ),
                    None,
                )
                if matching is not None:
                    return {**matching, **state}, evidence, rejected
                rejected.append(
                    {
                        "pc_after": int(state["pc_after"]),
                        "physical_pc_after": int(state["physical_pc_after"]),
                        "slot0_bank": int(state["slot0_bank"]),
                        "slot1_bank": int(state["slot1_bank"]),
                        "slot2_bank": int(state["slot2_bank"]),
                    }
                )
                if len(rejected) >= MAX_REJECTED_BANK_HITS_PER_SLOT:
                    return None, None, rejected
    finally:
        for address in addresses:
            try:
                client.call(
                    "remove_breakpoint",
                    {
                        "address": address,
                        "end_address": address,
                        "memory_area": "rom_ram",
                    },
                )
            except RuntimeError:
                pass
    return None, None, rejected


def _consumer_already_confirmed(root: Path) -> bool:
    path = root / CONSUMER_RESOLUTION
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        isinstance(value, dict)
        and value.get("consumer_evidence_confirmed") is True
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    parser.add_argument("--if-needed", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.if_needed and _consumer_already_confirmed(root):
        print("SFKR renderer probe skipped: consumer is already confirmed.")
        return 0

    rom_path = (
        (root / args.rom).resolve()
        if not args.rom.is_absolute()
        else args.rom
    )
    rom = rom_path.read_bytes()
    verify_target_identity(rom)
    target_sha256 = sha256_file(rom_path)
    mappings = _renderer_mappings()
    safe_hit: dict[str, object] | None = None
    emulator_version = "unknown"
    local_result: dict[str, object] = {
        "target_sha256": target_sha256,
        "rom": str(rom_path),
        "call_sites": list(RENDERER_CALL_SITES),
        "attempts": [],
    }

    client = McpStdioClient(_default_command())
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
        hit, evidence, rejected = _probe_mappings(client, mappings)
        safe_hit = hit
        local_result["attempts"].append(
            {
                "route": "cold-boot-idle-attract-introduction",
                "frame_budget": _frame_budget(),
                "mappings": mappings,
                "hit": hit,
                "evidence": evidence,
                "rejected_hits": rejected,
            }
        )
    finally:
        local_result["stderr_tail"] = list(client.stderr_tail)
        client.close()

    local_path = root / LOCAL_REPORT
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local_result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    observation = build_renderer_observation(
        target_sha256=target_sha256,
        emulator_version=emulator_version,
        frame_budget=_frame_budget(),
        mappings_attempted=mappings,
        hit=safe_hit,
    )
    safe_path = write_renderer_observation(root, observation)
    if safe_hit is None:
        print("SFKR renderer hook was not reached during the idle attract intro.")
    else:
        print(
            "SFKR renderer hook reached at "
            f"physical 0x{safe_hit['physical_pc_after']:06X}."
        )
    print(f"Local renderer evidence: {local_path}")
    print(f"Safe renderer observation: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
