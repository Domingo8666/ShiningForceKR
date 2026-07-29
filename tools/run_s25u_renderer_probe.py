#!/usr/bin/env python3
"""Trace verified v5.1 Korean Huffman-vector reads on S25U."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from .patch_io import sha256_file
    from .run_s25u_runtime_probe import (
        REQUIRED_TOOLS,
        McpStdioClient,
        _capture_state,
        _default_command,
        _step_frames_and_wait,
    )
    from .v5_1_consumer import verify_target_identity
    from .v5_1_runtime_hit_resolver import _parse_trace_line, _read_addresses
    from .v5_1_renderer_observation import (
        build_renderer_observation,
        write_renderer_observation,
    )
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from run_s25u_runtime_probe import (
        REQUIRED_TOOLS,
        McpStdioClient,
        _capture_state,
        _default_command,
        _step_frames_and_wait,
    )
    from v5_1_consumer import verify_target_identity
    from v5_1_runtime_hit_resolver import _parse_trace_line, _read_addresses
    from v5_1_renderer_observation import (
        build_renderer_observation,
        write_renderer_observation,
    )

DEFAULT_ROM = Path("build/Final_Conflict_Korean_v5.1.gg")
LOCAL_REPORT = Path("reports/local/v5_1_renderer_probe.json")
CONSUMER_RESOLUTION = Path(
    "analysis/device/v5_1_latest_consumer_resolution.json"
)
HUFFMAN_VECTOR_START = 0x080100
HUFFMAN_VECTOR_END = 0x0802FF
HUFFMAN_VECTOR_BANK = 0x20
TEXT_ROUTE = "cold-boot-start-confirm-story"
TEXT_ROUTE_SCHEDULE: tuple[tuple[int, str | None], ...] = (
    (180, None),
    (240, "start"),
    *((180, "2"),) * 16,
)
ROM_READ_RANGES = ((0x4000, 0x7FFF), (0x8000, 0xBFFF))
MAX_DECODER_READ_HITS = 96
MAX_DECODER_READ_SAMPLES = 64
MAX_REJECTED_VECTOR_HITS = 512


def _frame_budget() -> int:
    return sum(frames for frames, _ in TEXT_ROUTE_SCHEDULE)


def _vector_mappings() -> list[dict[str, int]]:
    return [
        {
            "probe_file_offset": HUFFMAN_VECTOR_START,
            "slot": slot,
            "expected_bank": HUFFMAN_VECTOR_BANK,
            "logical_address": slot * 0x4000 + 0x0100,
        }
        for slot in (1, 2)
    ]


def _vector_read_matches(
    sample: dict[str, object],
    mapping: dict[str, int],
) -> bool:
    logical_access = int(sample["logical_access"])
    physical_file_offset = int(sample["physical_file_offset"])
    mapped_bank = int(sample["mapped_bank"])
    return (
        int(sample["slot"]) == int(mapping["slot"])
        and mapped_bank == int(mapping["expected_bank"])
        and int(mapping["logical_address"])
        <= logical_access
        < int(mapping["logical_address"]) + 0x200
        and physical_file_offset
        == mapped_bank * 0x4000 + (logical_access & 0x3FFF)
        and HUFFMAN_VECTOR_START
        <= physical_file_offset
        <= HUFFMAN_VECTOR_END
    )


def _probe_vector_reads(
    client: McpStdioClient,
    mappings: list[dict[str, int]],
    rom_size: int,
) -> tuple[
    dict[str, object] | None,
    dict[str, object] | None,
    list[dict[str, int]],
]:
    client.call("debug_reset")
    client.call("debug_pause")
    ranges = [
        (
            f"{mapping['logical_address']:04X}",
            f"{mapping['logical_address'] + 0x1FF:04X}",
        )
        for mapping in mappings
    ]
    for start, end in ranges:
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
    rejected: list[dict[str, int]] = []
    try:
        for frames, button in TEXT_ROUTE_SCHEDULE:
            if button is not None:
                client.call(
                    "controller_button",
                    {
                        "player": 1,
                        "button": button,
                        "action": "press_and_release",
                    },
                )
            while True:
                status = _step_frames_and_wait(client, frames)
                if status.get("at_breakpoint") is not True:
                    break
                state, evidence = _capture_state(client)
                sample = _last_rom_read(state, evidence, rom_size)
                matching = next(
                    (
                        mapping
                        for mapping in mappings
                        if sample is not None
                        and _vector_read_matches(sample, mapping)
                    ),
                    None,
                )
                if matching is not None and sample is not None:
                    exact_hit = {
                        "probe_file_offset": int(
                            sample["physical_file_offset"]
                        ),
                        "slot": int(sample["slot"]),
                        "expected_bank": int(sample["mapped_bank"]),
                        "logical_address": int(sample["logical_access"]),
                    }
                    return {**exact_hit, **state}, evidence, rejected
                rejected.append(
                    {
                        "logical_access": (
                            int(sample["logical_access"])
                            if sample is not None
                            else -1
                        ),
                        "physical_file_offset": (
                            int(sample["physical_file_offset"])
                            if sample is not None
                            else -1
                        ),
                        "pc_after": int(state["pc_after"]),
                        "physical_pc_after": int(state["physical_pc_after"]),
                        "slot0_bank": int(state["slot0_bank"]),
                        "slot1_bank": int(state["slot1_bank"]),
                        "slot2_bank": int(state["slot2_bank"]),
                    }
                )
                if len(rejected) >= MAX_REJECTED_VECTOR_HITS:
                    return None, None, rejected
    finally:
        for start, end in ranges:
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
    return None, None, rejected


def _classify_decoder_read(physical_file_offset: int) -> str:
    if 0x80100 <= physical_file_offset < 0x80300:
        return "korean-huffman-vector"
    if 0x80300 <= physical_file_offset < 0x808D3:
        return "korean-huffman-tree"
    if 0x87000 <= physical_file_offset < 0x8730B:
        return "korean-font-runtime"
    if physical_file_offset < 0x80000:
        return "source-region"
    return "extension-other"


def _last_rom_read(
    state: dict[str, object],
    evidence: dict[str, object],
    rom_size: int,
) -> dict[str, object] | None:
    trace = evidence.get("trace")
    z80 = evidence.get("z80")
    if not isinstance(trace, dict) or not isinstance(z80, dict):
        return None
    lines = trace.get("lines")
    if not isinstance(lines, list):
        return None
    for line in reversed(lines):
        if not isinstance(line, str):
            continue
        parsed = _parse_trace_line(line)
        if parsed is None:
            continue
        registers = parsed["registers"]
        if not isinstance(registers, dict):
            continue
        for name in ("IX", "IY"):
            value = z80.get(name)
            if isinstance(value, str):
                registers[name.lower()] = int(value, 16)
        for logical_access in _read_addresses(parsed["opcodes"], registers):
            if not 0x4000 <= logical_access < 0xC000:
                continue
            slot = logical_access // 0x4000
            mapped_bank = int(state[f"slot{slot}_bank"])
            physical = mapped_bank * 0x4000 + (logical_access & 0x3FFF)
            if physical >= rom_size:
                continue
            return {
                "slot": slot,
                "logical_access": logical_access,
                "physical_file_offset": physical,
                "mapped_bank": mapped_bank,
                "instruction_bank": int(parsed["bank"]),
                "instruction_pc": int(parsed["pc"]),
                "pc_after": int(state["pc_after"]),
                "physical_pc_after": int(state["physical_pc_after"]),
                "classification": _classify_decoder_read(physical),
            }
    return None


def _capture_decoder_reads(
    client: McpStdioClient,
    rom_size: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    ranges = [(f"{start:04X}", f"{end:04X}") for start, end in ROM_READ_RANGES]
    for start, end in ranges:
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
    samples: list[dict[str, object]] = []
    local_events: list[dict[str, object]] = []
    seen: set[tuple[int, int, int]] = set()
    try:
        for _ in range(MAX_DECODER_READ_HITS):
            status = _step_frames_and_wait(client, 1)
            if status.get("at_breakpoint") is not True:
                break
            state, evidence = _capture_state(client)
            sample = _last_rom_read(state, evidence, rom_size)
            if sample is None:
                continue
            key = (
                int(sample["physical_file_offset"]),
                int(sample["instruction_bank"]),
                int(sample["instruction_pc"]),
            )
            if key in seen:
                continue
            seen.add(key)
            samples.append(sample)
            local_events.append(
                {
                    "sample": sample,
                    "evidence": evidence,
                }
            )
            if len(samples) >= MAX_DECODER_READ_SAMPLES:
                break
    finally:
        for start, end in ranges:
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
    return samples, local_events


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
    mappings = _vector_mappings()
    safe_hit: dict[str, object] | None = None
    decoder_reads: list[dict[str, object]] = []
    emulator_version = "unknown"
    local_result: dict[str, object] = {
        "target_sha256": target_sha256,
        "rom": str(rom_path),
        "huffman_vector_range": [
            HUFFMAN_VECTOR_START,
            HUFFMAN_VECTOR_END,
        ],
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
        hit, evidence, rejected = _probe_vector_reads(
            client,
            mappings,
            len(rom),
        )
        safe_hit = hit
        local_read_events: list[dict[str, object]] = []
        if safe_hit is not None:
            if evidence is None:
                raise RuntimeError("vector read hit has no trace evidence")
            first_read = _last_rom_read(safe_hit, evidence, len(rom))
            if (
                first_read is None
                or first_read["classification"]
                != "korean-huffman-vector"
            ):
                raise RuntimeError("vector read hit could not be reconstructed")
            following_reads, local_read_events = _capture_decoder_reads(
                client,
                len(rom),
            )
            decoder_reads = [first_read]
            seen_reads = {
                (
                    first_read["physical_file_offset"],
                    first_read["instruction_bank"],
                    first_read["instruction_pc"],
                )
            }
            for item in following_reads:
                key = (
                    item["physical_file_offset"],
                    item["instruction_bank"],
                    item["instruction_pc"],
                )
                if key not in seen_reads:
                    seen_reads.add(key)
                    decoder_reads.append(item)
        local_result["attempts"].append(
            {
                "route": TEXT_ROUTE,
                "frame_budget": _frame_budget(),
                "mappings": mappings,
                "hit": hit,
                "evidence": evidence,
                "rejected_hits": rejected,
                "decoder_read_events": local_read_events,
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
        route=TEXT_ROUTE,
        anchor_kind="huffman-vector-read",
        frame_budget=_frame_budget(),
        mappings_attempted=mappings,
        hit=safe_hit,
        decoder_reads=decoder_reads,
    )
    safe_path = write_renderer_observation(root, observation)
    if safe_hit is None:
        print("SFKR Korean Huffman vector was not read on the story route.")
    else:
        print(
            "SFKR Korean Huffman vector read at "
            f"physical 0x{safe_hit['probe_file_offset']:06X}; "
            f"captured {len(decoder_reads)} unique ROM reads."
        )
    print(f"Local renderer evidence: {local_path}")
    print(f"Safe renderer observation: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
