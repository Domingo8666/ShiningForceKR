#!/usr/bin/env python3
"""Capture fixed S25U story-route checkpoints without publishing images."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from .patch_io import sha256_file
    from .run_s25u_renderer_probe import (
        DEFAULT_ROM,
        McpStdioClient,
        TEXT_ROUTE,
        _consumer_already_confirmed,
        _default_command,
    )
    from .v5_1_consumer import verify_target_identity
    from .v5_1_route_capture import build_route_capture, write_route_capture
    from .v5_1_test_display_capture import (
        _parse_screenshot,
        _write_bytes_atomic,
    )
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from run_s25u_renderer_probe import (
        DEFAULT_ROM,
        McpStdioClient,
        TEXT_ROUTE,
        _consumer_already_confirmed,
        _default_command,
    )
    from v5_1_consumer import verify_target_identity
    from v5_1_route_capture import build_route_capture, write_route_capture
    from v5_1_test_display_capture import (
        _parse_screenshot,
        _write_bytes_atomic,
    )

LOCAL_REPORT = Path("reports/local/v5_1_story_route_capture.json")
EVIDENCE_DIR = Path("evidence/local/v5_1_story_route")
REQUIRED_CAPTURE_TOOLS = {
    "controller_button",
    "debug_pause",
    "debug_reset",
    "debug_step_frame",
    "get_media_info",
    "get_screenshot",
    "load_media",
}

# A checkpoint label marks the frame that is retained locally. The intermediate
# confirms remain part of the deterministic route but do not create PNG files.
ROUTE_STEPS: tuple[tuple[int, str | None, str | None], ...] = (
    (180, None, "boot-idle"),
    (240, "start", "post-start"),
    (180, "2", "confirm-01"),
    (180, "2", None),
    (180, "2", None),
    (180, "2", "confirm-04"),
    *((180, "2", None),) * 11,
    (180, "2", "confirm-16"),
)


def _frame_budget() -> int:
    return sum(frames for frames, _, _ in ROUTE_STEPS)


def _capture_route(
    client: McpStdioClient,
    evidence_dir: Path,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    safe_captures: list[dict[str, object]] = []
    local_captures: list[dict[str, object]] = []
    frame_total = 0
    input_count = 0
    client.call("debug_reset")
    client.call("debug_pause")
    for frames, button, stage in ROUTE_STEPS:
        if button is not None:
            client.call(
                "controller_button",
                {
                    "player": 1,
                    "button": button,
                    "action": "press_and_release",
                },
            )
            input_count += 1
        client.call("debug_step_frame", {"frames": frames})
        frame_total += frames
        if stage is None:
            continue
        png, metadata = _parse_screenshot(client.call("get_screenshot"))
        filename = f"{len(safe_captures) + 1:02d}_{stage}.png"
        path = evidence_dir / filename
        _write_bytes_atomic(path, png)
        safe_item = {
            "stage": stage,
            "frame_total": frame_total,
            "input_count": input_count,
            **metadata,
        }
        safe_captures.append(safe_item)
        local_captures.append({"file": str(path), **safe_item})
    return safe_captures, local_captures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    parser.add_argument("--if-needed", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.if_needed and _consumer_already_confirmed(root):
        print("SFKR route capture skipped: consumer is already confirmed.")
        return 0

    rom_path = (
        (root / args.rom).resolve()
        if not args.rom.is_absolute()
        else args.rom.resolve()
    )
    rom = rom_path.read_bytes()
    verify_target_identity(rom)
    target_sha256 = sha256_file(rom_path)
    evidence_dir = (root / EVIDENCE_DIR).resolve()
    local_path = (root / LOCAL_REPORT).resolve()
    safe_captures: list[dict[str, object]] = []
    local_captures: list[dict[str, object]] = []
    emulator_version = "unknown"
    local: dict[str, object] = {
        "artifact_kind": "s25u-local-story-route-capture",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "rom": str(rom_path),
        "route": TEXT_ROUTE,
        "captures": local_captures,
    }

    client = McpStdioClient(_default_command())
    try:
        tools = client.initialize()
        missing = sorted(REQUIRED_CAPTURE_TOOLS - tools)
        if missing:
            raise RuntimeError(f"Gearsystem MCP tools missing: {missing}")
        client.call("load_media", {"file_path": str(rom_path)})
        media = client.call("get_media_info")
        local["media"] = media
        if (
            media.get("ready") is not True
            or media.get("is_game_gear") is not True
            or int(media.get("rom_size", 0)) != len(rom)
        ):
            raise RuntimeError("Gearsystem did not load the expected Game Gear ROM")
        emulator_version = str(media.get("emulator_version", "unknown"))
        safe_captures, local_captures = _capture_route(client, evidence_dir)
        local["captures"] = local_captures
    finally:
        local["stderr_tail"] = list(client.stderr_tail)
        client.close()

    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    observation = build_route_capture(
        target_sha256=target_sha256,
        emulator_version=emulator_version,
        route=TEXT_ROUTE,
        frame_budget=_frame_budget(),
        captures=safe_captures,
    )
    safe_path = write_route_capture(root, observation)
    print(
        "SFKR story-route capture: "
        f"{observation['status']} "
        f"({observation['distinct_frame_count']}/{len(safe_captures)} distinct)"
    )
    print(f"Local route evidence: {local_path}")
    print(f"Safe route observation: {safe_path}")
    print(
        "Open in My Files: Internal storage > ShiningForceKR > evidence > "
        "local > v5_1_story_route > 05_confirm-16.png"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

