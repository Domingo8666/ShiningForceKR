#!/usr/bin/env python3
"""Capture the exact VRAM bytes changed by the first dialogue consumer.

This is a baseline-only diagnostic.  It does not rewrite script bytes or copy
candidate font pages.  The goal is to replace speculative ROM-page tests with
one measured boundary: VRAM immediately before and after the confirmed text
consumer returns.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .run_s25u_runtime_probe import McpStdioClient, _default_command
    from .v5_1_renderer_output_trace import (
        DEFAULT_ROM,
        PUBLISH_RELATIVE_PATH as RENDERER_TRACE_PATH,
        REQUIRED_TOOLS,
        _load_json_object,
        _reach_exact_payload,
        _trace_to_outer_return,
        analyze_trace_lines,
        validate_renderer_output_trace,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from run_s25u_runtime_probe import McpStdioClient, _default_command
    from v5_1_renderer_output_trace import (
        DEFAULT_ROM,
        PUBLISH_RELATIVE_PATH as RENDERER_TRACE_PATH,
        REQUIRED_TOOLS,
        _load_json_object,
        _reach_exact_payload,
        _trace_to_outer_return,
        analyze_trace_lines,
        validate_renderer_output_trace,
    )


ARTIFACT_KIND = "sanitized-s25u-active-vram-route"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_active_vram_route.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_active_vram_route.json")
VRAM_MINIMUM_SIZE = 0x4000
MEMORY_READ_CHUNK = 0x400
TILE_BYTES = 32
COUNT_KEYS = {
    "vram_area_size",
    "trace_entry_count",
    "vdp_control_write_count",
    "vdp_data_write_count",
    "resolved_vram_data_write_count",
    "unresolved_vram_data_write_count",
    "unique_vram_destination_count",
    "changed_byte_count",
    "changed_tile_count",
    "written_changed_byte_count",
    "direct_rom_match_tile_count",
    "unique_direct_rom_source_count",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_renderer_trace_sha256",
    "captured_utc",
    "runtime_entry",
    "analysis",
    "active_vram_route_confirmed",
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


def _parse_memory_bytes(data: object, expected_size: int) -> bytes:
    if not isinstance(data, str):
        raise ValueError("memory snapshot must be a hex byte string")
    try:
        result = bytes(int(token, 16) for token in data.split())
    except ValueError as error:
        raise ValueError("memory snapshot contains a non-hex byte") from error
    if len(result) != expected_size:
        raise ValueError("memory snapshot size disagrees")
    return result


def _select_vram_area(payload: dict[str, object]) -> dict[str, object]:
    raw_areas = payload.get("areas")
    if not isinstance(raw_areas, list):
        raise ValueError("memory-area list is missing")
    candidates = []
    for item in raw_areas:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        area_id = item.get("id")
        size = item.get("size")
        if (
            isinstance(name, str)
            and "vram" in name.casefold()
            and isinstance(area_id, int)
            and not isinstance(area_id, bool)
            and isinstance(size, int)
            and not isinstance(size, bool)
            and size >= VRAM_MINIMUM_SIZE
        ):
            candidates.append(item)
    exact = [item for item in candidates if str(item["name"]).casefold() == "vram"]
    selected = exact or candidates
    if len(selected) != 1:
        raise ValueError("exactly one readable VRAM memory area is required")
    return selected[0]


def _read_memory_area(
    client: McpStdioClient,
    *,
    area_id: int,
    size: int,
) -> bytes:
    chunks = []
    for offset in range(0, size, MEMORY_READ_CHUNK):
        length = min(MEMORY_READ_CHUNK, size - offset)
        payload = client.call(
            "read_memory",
            {
                "area": area_id,
                "offset": f"{offset:04X}",
                "size": length,
            },
        )
        chunks.append(_parse_memory_bytes(payload.get("data"), length))
    return b"".join(chunks)


def _contiguous_ranges(offsets: list[int]) -> list[dict[str, int]]:
    if offsets != sorted(set(offsets)):
        raise ValueError("changed VRAM offsets must be sorted and unique")
    if not offsets:
        return []
    result = []
    start = previous = offsets[0]
    for offset in offsets[1:]:
        if offset != previous + 1:
            result.append({"start": start, "end_exclusive": previous + 1})
            start = offset
        previous = offset
    result.append({"start": start, "end_exclusive": previous + 1})
    return result


def replay_vdp_destinations(
    outputs: list[dict[str, int]],
) -> tuple[list[dict[str, int]], dict[str, int]]:
    """Replay the SMS/GG two-byte VDP control latch and data destinations."""

    ordered = sorted(outputs, key=lambda item: int(item["trace_index"]))
    control_first: int | None = None
    write_address: int | None = None
    auto_increment = 1
    destinations = []
    data_count = 0
    control_count = 0
    unresolved = 0
    for item in ordered:
        port = int(item["port"])
        value = item.get("value")
        if port == 0xBF:
            control_count += 1
            if not isinstance(value, int) or isinstance(value, bool):
                control_first = None
                write_address = None
                continue
            value &= 0xFF
            if control_first is None:
                control_first = value
                continue
            low = control_first
            high = value
            control_first = None
            code = high >> 6
            if code == 1:  # VRAM write address
                write_address = ((high & 0x3F) << 8) | low
            elif code == 2:  # VDP register write
                register = high & 0x0F
                if register == 15:
                    auto_increment = low
                write_address = None
            else:
                write_address = None
            continue
        if port != 0xBE:
            continue
        data_count += 1
        if write_address is None:
            unresolved += 1
            continue
        destination = write_address & 0x3FFF
        record = {
            "trace_index": int(item["trace_index"]),
            "address": destination,
        }
        if isinstance(value, int) and not isinstance(value, bool):
            record["value"] = value & 0xFF
        destinations.append(record)
        write_address = (write_address + auto_increment) & 0x3FFF
    return destinations, {
        "vdp_control_write_count": control_count,
        "vdp_data_write_count": data_count,
        "resolved_vram_data_write_count": len(destinations),
        "unresolved_vram_data_write_count": unresolved,
    }


def _rom_occurrences(data: bytes, needle: bytes, limit: int = 64) -> list[int]:
    if not needle or not any(needle):
        return []
    offsets = []
    start = 0
    while len(offsets) < limit:
        found = data.find(needle, start)
        if found < 0:
            break
        offsets.append(found)
        start = found + 1
    return offsets


def analyze_active_vram_route(
    *,
    before: bytes,
    after: bytes,
    outputs: list[dict[str, int]],
    rom: bytes,
) -> tuple[dict[str, int], dict[str, object]]:
    if len(before) != len(after) or len(before) < VRAM_MINIMUM_SIZE:
        raise ValueError("VRAM snapshots are incompatible")
    changed_offsets = [
        index for index, pair in enumerate(zip(before, after)) if pair[0] != pair[1]
    ]
    destinations, output_counts = replay_vdp_destinations(outputs)
    destination_set = {item["address"] for item in destinations}
    changed_tiles = sorted({offset // TILE_BYTES for offset in changed_offsets})
    direct_matches: dict[int, list[int]] = {}
    direct_sources = set()
    for tile in changed_tiles:
        start = tile * TILE_BYTES
        payload = after[start : start + TILE_BYTES]
        matches = _rom_occurrences(rom, payload)
        if matches:
            direct_matches[tile] = matches
            direct_sources.update(matches)
    written_changed = sum(offset in destination_set for offset in changed_offsets)
    safe = {
        "vram_area_size": len(before),
        "trace_entry_count": max(
            (int(item["trace_index"]) for item in outputs), default=-1
        )
        + 1,
        **output_counts,
        "unique_vram_destination_count": len(destination_set),
        "changed_byte_count": len(changed_offsets),
        "changed_tile_count": len(changed_tiles),
        "written_changed_byte_count": written_changed,
        "direct_rom_match_tile_count": len(direct_matches),
        "unique_direct_rom_source_count": len(direct_sources),
    }
    local = {
        "changed_ranges": _contiguous_ranges(changed_offsets),
        "changes": [
            {"offset": offset, "before": before[offset], "after": after[offset]}
            for offset in changed_offsets
        ],
        "changed_tiles": changed_tiles,
        "vram_destinations": destinations,
        "direct_rom_matches": {
            f"0x{tile:03X}": matches for tile, matches in direct_matches.items()
        },
    }
    return safe, local


def build_active_vram_route(
    *,
    target_sha256: str,
    source_renderer_trace_sha256: str,
    runtime_entry: dict[str, object],
    analysis: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    changed = int(analysis["changed_byte_count"])
    written_changed = int(analysis["written_changed_byte_count"])
    resolved = int(analysis["resolved_vram_data_write_count"])
    confirmed = changed > 0 and resolved > 0 and written_changed == changed
    partial = changed > 0 and written_changed > 0
    status = (
        "active-vram-route-confirmed"
        if confirmed
        else "active-vram-route-partial"
        if partial
        else "active-vram-route-not-observed"
    )
    direct_matches = int(analysis["direct_rom_match_tile_count"])
    next_checkpoint = (
        "map-active-vram-tiles-to-rom"
        if confirmed and direct_matches > 0
        else "trace-active-vram-producer"
        if confirmed
        else "extend-active-vram-write-window"
        if partial
        else "correct-renderer-observation-window"
    )
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": target_sha256,
        "source_renderer_trace_sha256": source_renderer_trace_sha256,
        "captured_utc": captured_utc,
        "runtime_entry": {key: runtime_entry[key] for key in RUNTIME_ENTRY_KEYS},
        "analysis": {key: int(analysis[key]) for key in COUNT_KEYS},
        "active_vram_route_confirmed": confirmed,
        "baseline_script_bytes_unchanged": True,
        "local_payload_policy": (
            "vram-addresses-bytes-output-values-and-rom-offsets-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": next_checkpoint,
    }
    validate_active_vram_route(value)
    return value


def validate_active_vram_route(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("active VRAM route fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"] not in {
            "active-vram-route-confirmed",
            "active-vram-route-partial",
            "active-vram-route-not-observed",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_renderer_trace_sha256"])
    ):
        raise ValueError("active VRAM route policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("active VRAM route timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("active VRAM route timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("active VRAM route timestamp must include UTC")
    runtime = value["runtime_entry"]
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_ENTRY_KEYS:
        raise ValueError("active VRAM route runtime fields do not match")
    counts = value["analysis"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("active VRAM route counts do not match")
    if any(
        not isinstance(counts[key], int)
        or isinstance(counts[key], bool)
        or counts[key] < 0
        for key in COUNT_KEYS
    ):
        raise ValueError("active VRAM route count is invalid")
    if counts["vram_area_size"] < VRAM_MINIMUM_SIZE:
        raise ValueError("active VRAM route area is too small")
    if (
        counts["resolved_vram_data_write_count"]
        + counts["unresolved_vram_data_write_count"]
        != counts["vdp_data_write_count"]
        or counts["written_changed_byte_count"] > counts["changed_byte_count"]
        or counts["unique_vram_destination_count"]
        > counts["resolved_vram_data_write_count"]
        or counts["direct_rom_match_tile_count"] > counts["changed_tile_count"]
    ):
        raise ValueError("active VRAM route counts are inconsistent")
    confirmed = (
        counts["changed_byte_count"] > 0
        and counts["resolved_vram_data_write_count"] > 0
        and counts["written_changed_byte_count"] == counts["changed_byte_count"]
    )
    partial = (
        not confirmed
        and counts["changed_byte_count"] > 0
        and counts["written_changed_byte_count"] > 0
    )
    expected_status = (
        "active-vram-route-confirmed"
        if confirmed
        else "active-vram-route-partial"
        if partial
        else "active-vram-route-not-observed"
    )
    expected_next = (
        "map-active-vram-tiles-to-rom"
        if confirmed and counts["direct_rom_match_tile_count"] > 0
        else "trace-active-vram-producer"
        if confirmed
        else "extend-active-vram-write-window"
        if partial
        else "correct-renderer-observation-window"
    )
    if (
        value["status"] != expected_status
        or value["active_vram_route_confirmed"] is not confirmed
        or value["next_checkpoint"] != expected_next
        or value["baseline_script_bytes_unchanged"] is not True
        or value["translation_build_eligible"] is not False
    ):
        raise ValueError("active VRAM route result is inconsistent")
    if value["local_payload_policy"] != (
        "vram-addresses-bytes-output-values-and-rom-offsets-local-only"
    ):
        raise ValueError("active VRAM route local policy is invalid")


def _is_current(
    path: Path,
    *,
    target_sha256: str,
    renderer_sha256: str,
) -> bool:
    if not path.is_file():
        return False
    try:
        value = _load_json_object(path)
        validate_active_vram_route(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        value["target_sha256"] == target_sha256
        and value["source_renderer_trace_sha256"] == renderer_sha256
    )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    renderer_path = root / RENDERER_TRACE_PATH
    publish_path = root / PUBLISH_RELATIVE_PATH
    local_path = root / LOCAL_REPORT_PATH
    if not rom_path.is_file() or not renderer_path.is_file():
        if args.if_ready:
            print("Active VRAM route capture is not ready")
            return 0
        raise SystemExit("active VRAM route input is missing")

    renderer = _load_json_object(renderer_path)
    validate_renderer_output_trace(renderer)
    target_sha256 = sha256_file(rom_path)
    renderer_sha256 = sha256_file(renderer_path)
    if (
        renderer["target_sha256"] != target_sha256
        or renderer["consumer_chain_confirmed"] is not True
    ):
        if args.if_ready:
            print("Active VRAM route waits for the confirmed renderer")
            return 0
        raise ValueError("active VRAM route renderer identity disagrees")
    if _is_current(
        publish_path,
        target_sha256=target_sha256,
        renderer_sha256=renderer_sha256,
    ):
        print("Active VRAM route capture is already current")
        return 0

    client = McpStdioClient(_default_command())
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
            or int(media.get("rom_size", 0)) != rom_path.stat().st_size
        ):
            raise RuntimeError("Gearsystem did not load the expected Game Gear ROM")
        client.call("debug_reset")
        client.call("debug_pause")
        client.call("set_trace_log", {"enabled": False})
        runtime = renderer["runtime_entry"]
        assert isinstance(runtime, dict)
        progress = {"stage": "active-vram-route-selection"}
        selected_state, ready_state = _reach_exact_payload(
            client,
            selector_de=int(runtime["selector_de"]),
            entry_ordinal=int(runtime["entry_ordinal"]),
            logical_start=int(runtime["logical_start"]),
            mapped_bank=int(runtime["mapped_bank"]),
            progress=progress,
        )
        area = _select_vram_area(client.call("list_memory_areas"))
        area_id = int(area["id"])
        area_size = int(area["size"])
        before = _read_memory_area(
            client,
            area_id=area_id,
            size=area_size,
        )
        trace_lines, trace_local = _trace_to_outer_return(
            client,
            ready_state=ready_state,
        )
        after = _read_memory_area(
            client,
            area_id=area_id,
            size=area_size,
        )
    finally:
        client.close()

    _, trace_analysis = analyze_trace_lines(trace_lines)
    outputs = trace_analysis.get("vdp_outputs")
    if not isinstance(outputs, list):
        raise ValueError("active VRAM route trace outputs are missing")
    safe_counts, local_analysis = analyze_active_vram_route(
        before=before,
        after=after,
        outputs=outputs,
        rom=rom_path.read_bytes(),
    )
    safe_counts["trace_entry_count"] = len(trace_lines)
    captured_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    safe = build_active_vram_route(
        target_sha256=target_sha256,
        source_renderer_trace_sha256=renderer_sha256,
        runtime_entry=runtime,
        analysis=safe_counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-s25u-active-vram-route",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "captured_utc": captured_utc,
        "runtime_entry": runtime,
        "vram_area": {
            "id": area_id,
            "name": str(area["name"]),
            "size": area_size,
        },
        "selected_state": selected_state,
        "ready_state": ready_state,
        "trace_capture": trace_local,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-vram-addresses-bytes-output-values-or-rom-offsets"
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
    print(f"SFKR active VRAM route: {publish_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
