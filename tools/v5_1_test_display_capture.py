#!/usr/bin/env python3
"""Capture S25U-local cold-boot display evidence for the technical test ROM.

The exact runtime-confirmed compressed entry is watched again in the generated
test ROM.  After that read is observed with the expected mapper bank, several
PNG frames are captured locally for human visual review.  Only path-free hashes
and runtime facts are written to the publishable device artifact.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
import tempfile

try:
    from .patch_io import PatchError, sha256_bytes, sha256_file
    from .run_s25u_runtime_probe import (
        INPUT_SCHEDULE,
        McpStdioClient,
        _capture_state,
        _default_command,
        _step_frames_and_wait,
        _step_instruction_and_wait,
    )
    from .v5_1_decoder_stream_resolution import (
        validate_decoder_stream_resolution,
    )
    from .v5_1_runtime_hit_resolver import validate_consumer_resolution
    from .v5_1_png_pixels import compare_png_pixels
    from .v5_1_test_display_comparison import (
        build_display_comparison,
        prior_automatic_rejections,
        write_display_comparison,
    )
    from .v5_1_test_phrase import TEST_PHRASE
except ImportError:  # direct script execution
    from patch_io import PatchError, sha256_bytes, sha256_file
    from run_s25u_runtime_probe import (
        INPUT_SCHEDULE,
        McpStdioClient,
        _capture_state,
        _default_command,
        _step_frames_and_wait,
        _step_instruction_and_wait,
    )
    from v5_1_decoder_stream_resolution import (
        validate_decoder_stream_resolution,
    )
    from v5_1_runtime_hit_resolver import validate_consumer_resolution
    from v5_1_png_pixels import compare_png_pixels
    from v5_1_test_display_comparison import (
        build_display_comparison,
        prior_automatic_rejections,
        write_display_comparison,
    )
    from v5_1_test_phrase import TEST_PHRASE


ARTIFACT_KIND = "sanitized-s25u-test-display-capture"
SCHEMA_VERSION = 1
DEFAULT_TEST_ROM = Path("build/Final_Conflict_Korean_test_phrase.gg")
DEFAULT_BASELINE_ROM = Path("build/Final_Conflict_Korean_v5.1.gg")
DEFAULT_BUILD_REPORT = Path("reports/local/v5_1_test_patch_build.json")
DEFAULT_RESOLUTION = Path(
    "analysis/device/v5_1_latest_consumer_resolution.json"
)
DEFAULT_STREAM_RESOLUTION = Path(
    "analysis/device/v5_1_latest_decoder_stream_resolution.json"
)
DEFAULT_LOCAL_REPORT = Path(
    "reports/local/v5_1_test_display_capture.json"
)
DEFAULT_EVIDENCE_DIR = Path("evidence/local/v5_1_test_phrase")
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_display_capture.json"
)
CAPTURE_FRAMES_AFTER_HIT = (1, 8, 30, 90)
ATTRACT_CAPTURE_SCHEDULE: tuple[tuple[int, str | None], ...] = (
    *((1_000, None),) * 12,
)
MAX_REJECTED_TARGET_HITS = 64
REQUIRED_TOOLS = {
    "controller_button",
    "debug_get_status",
    "debug_pause",
    "debug_reset",
    "debug_step_frame",
    "get_call_stack",
    "get_media_info",
    "get_screenshot",
    "get_trace_log",
    "get_z80_status",
    "list_memory_areas",
    "load_media",
    "read_memory",
    "remove_breakpoint",
    "set_breakpoint_range",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "purpose",
    "phrase_codepoints",
    "baseline_target_sha256",
    "test_target_sha256",
    "emulator_version",
    "cold_boot",
    "target_read",
    "captures",
    "post_advance_capture",
    "visual_review",
    "translation_build_eligible",
    "next_checkpoint",
}
CAPTURE_STATUSES = {
    "capture-ready-human-review-required",
    "runtime-target-read-not-observed",
}


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_display_capture(capture: dict[str, object]) -> None:
    if set(capture) != TOP_LEVEL_KEYS:
        raise ValueError("display capture top-level fields do not match")
    if capture["artifact_kind"] != ARTIFACT_KIND:
        raise ValueError("unexpected display capture artifact kind")
    if capture["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unexpected display capture schema version")
    if capture["status"] not in CAPTURE_STATUSES:
        raise ValueError("unexpected display capture status")
    if capture["purpose"] != "technical-poc-only":
        raise ValueError("unexpected display capture purpose")
    codepoints = capture["phrase_codepoints"]
    if (
        not isinstance(codepoints, list)
        or codepoints != [f"U+{ord(character):04X}" for character in TEST_PHRASE]
    ):
        raise ValueError("display capture phrase codepoints do not match")
    for key in ("baseline_target_sha256", "test_target_sha256"):
        if not _is_sha256(capture[key]):
            raise ValueError(f"{key} must be a lowercase SHA-256")
    if capture["baseline_target_sha256"] == capture["test_target_sha256"]:
        raise ValueError("baseline and test target identities must differ")
    emulator_version = capture["emulator_version"]
    if (
        not isinstance(emulator_version, str)
        or not 1 <= len(emulator_version) <= 64
        or "/" in emulator_version
        or "\\" in emulator_version
    ):
        raise ValueError("emulator_version must be short and path-free")
    if capture["cold_boot"] is not True:
        raise ValueError("display capture must start from a cold reset")

    target_read = capture["target_read"]
    if not isinstance(target_read, dict) or set(target_read) != {
        "slot",
        "logical_access",
        "expected_bank",
        "mapped_bank",
        "confirmed",
    }:
        raise ValueError("display capture target_read fields do not match")
    for key in ("slot", "logical_access", "expected_bank"):
        value = target_read[key]
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"target_read {key} must be an integer")
    if target_read["slot"] not in {1, 2}:
        raise ValueError("target_read slot must be 1 or 2")
    if not 0 <= target_read["logical_access"] <= 0xFFFF:
        raise ValueError("target_read logical_access is out of range")
    if not 0 <= target_read["expected_bank"] <= 0xFF:
        raise ValueError("target_read expected_bank is out of range")
    mapped_bank = target_read["mapped_bank"]
    if mapped_bank is not None and (
        not isinstance(mapped_bank, int)
        or isinstance(mapped_bank, bool)
        or not 0 <= mapped_bank <= 0xFF
    ):
        raise ValueError("target_read mapped_bank is invalid")
    confirmed = target_read["confirmed"]
    if not isinstance(confirmed, bool):
        raise ValueError("target_read confirmed must be boolean")
    if confirmed != (mapped_bank == target_read["expected_bank"]):
        raise ValueError("target_read confirmation and mapper bank disagree")

    captures = capture["captures"]
    if not isinstance(captures, list):
        raise ValueError("captures must be a list")
    previous_frame = 0
    for item in captures:
        if not isinstance(item, dict) or set(item) != {
            "frame_after_hit",
            "width",
            "height",
            "png_sha256",
        }:
            raise ValueError("capture item fields do not match")
        frame = item["frame_after_hit"]
        width = item["width"]
        height = item["height"]
        if (
            not isinstance(frame, int)
            or isinstance(frame, bool)
            or frame <= previous_frame
        ):
            raise ValueError("capture frames must be strictly increasing")
        if (
            not isinstance(width, int)
            or isinstance(width, bool)
            or not 1 <= width <= 1024
            or not isinstance(height, int)
            or isinstance(height, bool)
            or not 1 <= height <= 1024
        ):
            raise ValueError("capture dimensions are invalid")
        if not _is_sha256(item["png_sha256"]):
            raise ValueError("capture PNG hash is invalid")
        previous_frame = frame

    post_advance = capture["post_advance_capture"]
    if post_advance is not None:
        if not isinstance(post_advance, dict) or set(post_advance) != {
            "button",
            "frames_after_press",
            "width",
            "height",
            "png_sha256",
        }:
            raise ValueError("post-advance capture fields do not match")
        if (
            post_advance["button"] != "1"
            or post_advance["frames_after_press"] != 60
        ):
            raise ValueError("post-advance input sequence is unexpected")
        width = post_advance["width"]
        height = post_advance["height"]
        if (
            not isinstance(width, int)
            or isinstance(width, bool)
            or not 1 <= width <= 1024
            or not isinstance(height, int)
            or isinstance(height, bool)
            or not 1 <= height <= 1024
            or not _is_sha256(post_advance["png_sha256"])
        ):
            raise ValueError("post-advance capture metadata is invalid")
        if not confirmed or not captures:
            raise ValueError(
                "post-advance capture requires confirmed display captures"
            )

    review = capture["visual_review"]
    if not isinstance(review, dict) or review != {
        "required": True,
        "result": None,
        "evidence_storage": "s25u-local-only",
    }:
        raise ValueError("visual review must remain explicitly pending")
    if capture["translation_build_eligible"] is not False:
        raise ValueError("technical display capture must not enable translation build")
    ready = capture["status"] == "capture-ready-human-review-required"
    if ready != (confirmed and bool(captures) and post_advance is not None):
        raise ValueError("display capture status and evidence disagree")
    expected_checkpoint = (
        "human-confirm-first-korean-glyphs-and-ui"
        if ready
        else "repair-test-display-target-reachability"
    )
    if capture["next_checkpoint"] != expected_checkpoint:
        raise ValueError("display capture next checkpoint is inconsistent")


def _parse_screenshot(payload: dict[str, object]) -> tuple[bytes, dict[str, object]]:
    if payload.get("error") is not None:
        raise PatchError(f"Gearsystem screenshot failed: {payload['error']}")
    if payload.get("mimeType") != "image/png":
        raise PatchError("Gearsystem screenshot is not a PNG")
    encoded = payload.get("data")
    width = payload.get("width")
    height = payload.get("height")
    if not isinstance(encoded, str):
        raise PatchError("Gearsystem screenshot has no base64 data")
    try:
        png = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise PatchError("Gearsystem screenshot base64 is invalid") from error
    if len(png) < 24 or png[:8] != b"\x89PNG\r\n\x1a\n" or png[12:16] != b"IHDR":
        raise PatchError("Gearsystem screenshot PNG header is invalid")
    header_width = int.from_bytes(png[16:20], "big")
    header_height = int.from_bytes(png[20:24], "big")
    if not 1 <= header_width <= 1024 or not 1 <= header_height <= 1024:
        raise PatchError("Gearsystem screenshot PNG dimensions are invalid")
    if width is None and height is None:
        width = header_width
        height = header_height
    elif (
        not isinstance(width, int)
        or isinstance(width, bool)
        or not 1 <= width <= 1024
        or not isinstance(height, int)
        or isinstance(height, bool)
        or not 1 <= height <= 1024
    ):
        raise PatchError("Gearsystem screenshot dimensions are invalid")
    elif (header_width, header_height) != (width, height):
        raise PatchError("Gearsystem screenshot dimensions disagree with PNG")
    return png, {
        "width": width,
        "height": height,
        "png_sha256": sha256_bytes(png),
    }


def _absolute(root: Path, path: Path) -> Path:
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _require_within(path: Path, parent: Path, label: str) -> None:
    try:
        path.relative_to(parent.resolve())
    except ValueError as error:
        raise PatchError(f"{label} must stay under {parent}") from error


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PatchError(f"{path.name} must contain a JSON object")
    return value


def _write_bytes_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _build_safe_capture(
    *,
    build_report: dict[str, object],
    resolution: dict[str, object],
    emulator_version: str,
    mapped_bank: int | None,
    captures: list[dict[str, object]],
    post_advance_capture: dict[str, object] | None,
) -> dict[str, object]:
    target_read = resolution["target_read"]
    assert isinstance(target_read, dict)
    expected_bank = int(target_read["expected_bank"])
    confirmed = mapped_bank == expected_bank
    ready = confirmed and bool(captures) and post_advance_capture is not None
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "capture-ready-human-review-required"
            if ready
            else "runtime-target-read-not-observed"
        ),
        "purpose": "technical-poc-only",
        "phrase_codepoints": [
            f"U+{ord(character):04X}" for character in TEST_PHRASE
        ],
        "baseline_target_sha256": build_report["baseline_target_sha256"],
        "test_target_sha256": build_report["test_target_sha256"],
        "emulator_version": emulator_version,
        "cold_boot": True,
        "target_read": {
            "slot": int(target_read["slot"]),
            "logical_access": int(target_read["logical_access"]),
            "expected_bank": expected_bank,
            "mapped_bank": mapped_bank,
            "confirmed": confirmed,
        },
        "captures": captures,
        "post_advance_capture": post_advance_capture,
        "visual_review": {
            "required": True,
            "result": None,
            "evidence_storage": "s25u-local-only",
        },
        "translation_build_eligible": False,
        "next_checkpoint": (
            "human-confirm-first-korean-glyphs-and-ui"
            if ready
            else "repair-test-display-target-reachability"
        ),
    }
    validate_display_capture(safe)
    return safe


def _paired_pixel_comparisons(
    baseline_local: dict[str, object],
    test_local: dict[str, object],
) -> tuple[list[dict[str, object]], dict[str, object] | None]:
    baseline_captures = baseline_local.get("captures")
    test_captures = test_local.get("captures")
    if not isinstance(baseline_captures, list) or not isinstance(test_captures, list):
        return [], None
    baseline_by_frame = {
        int(item["frame_after_hit"]): item
        for item in baseline_captures
        if isinstance(item, dict)
        and isinstance(item.get("frame_after_hit"), int)
        and isinstance(item.get("file"), str)
    }
    test_by_frame = {
        int(item["frame_after_hit"]): item
        for item in test_captures
        if isinstance(item, dict)
        and isinstance(item.get("frame_after_hit"), int)
        and isinstance(item.get("file"), str)
    }
    if (
        not baseline_by_frame
        or set(baseline_by_frame) != set(test_by_frame)
        or set(baseline_by_frame) != set(CAPTURE_FRAMES_AFTER_HIT)
    ):
        return [], None
    comparisons: list[dict[str, object]] = []
    for frame in sorted(baseline_by_frame):
        baseline_item = baseline_by_frame[frame]
        test_item = test_by_frame[frame]
        comparison = compare_png_pixels(
            Path(str(baseline_item["file"])).read_bytes(),
            Path(str(test_item["file"])).read_bytes(),
        )
        comparisons.append(
            {
                "frame_after_hit": frame,
                **comparison,
                "baseline_png_sha256": str(baseline_item["png_sha256"]),
                "test_png_sha256": str(test_item["png_sha256"]),
            }
        )
    baseline_post = baseline_local.get("post_advance_capture")
    test_post = test_local.get("post_advance_capture")
    if (
        not isinstance(baseline_post, dict)
        or not isinstance(baseline_post.get("file"), str)
        or not isinstance(test_post, dict)
        or not isinstance(test_post.get("file"), str)
    ):
        return comparisons, None
    post_comparison = compare_png_pixels(
        Path(str(baseline_post["file"])).read_bytes(),
        Path(str(test_post["file"])).read_bytes(),
    )
    return comparisons, {
        **post_comparison,
        "baseline_png_sha256": str(baseline_post["png_sha256"]),
        "test_png_sha256": str(test_post["png_sha256"]),
    }


def _next_step_text(
    comparison: dict[str, object],
    *,
    evidence_dir: Path,
    root: Path,
) -> str:
    result = comparison["result"]
    if result == "no-visible-pixel-change":
        return (
            "Shining Force KR 다음 할 일\n\n"
            "현재 후보는 기준 화면과 한 픽셀도 다르지 않아 자동 탈락했습니다.\n"
            "자동실행기가 가능한 다음 후보를 계속 확인합니다.\n"
            "지금 사용자가 할 일은 없습니다.\n"
        )
    if result == "visible-pixel-change-human-review-required":
        relative = evidence_dir.relative_to(root)
        base = "내부 저장공간 > ShiningForceKR > " + " > ".join(
            relative.parts
        )
        return (
            "Shining Force KR 다음 할 일\n\n"
            "기준 화면과 시험 화면의 픽셀 차이가 발견됐습니다.\n"
            "아래 PNG 3개를 Codex 대화에 올려주세요.\n\n"
            f"1. {base} > baseline > frame_0090.png\n"
            f"2. {base} > test > frame_0090.png\n"
            f"3. {base} > test > after_advance.png\n\n"
            "ROM 또는 생성 ROM은 올리지 마세요.\n"
        )
    return (
        "Shining Force KR 다음 할 일\n\n"
        "기준 화면과 시험 화면을 완전하게 짝지어 비교하지 못했습니다.\n"
        "reports/AUTOPILOT_STATUS.txt와 이 파일의 글자 내용만 보내주세요.\n"
        "ROM 또는 생성 ROM은 올리지 마세요.\n"
    )


def _target_hit_matches(
    state: dict[str, object],
    target_read: dict[str, object],
) -> bool:
    slot = int(target_read["slot"])
    expected_pc_after = int(target_read["instruction_pc"]) + 1
    return (
        int(state[f"slot{slot}_bank"]) == int(target_read["expected_bank"])
        and abs(int(state["pc_after"]) - expected_pc_after) <= 4
    )


def _capture_display(
    *,
    rom_path: Path,
    rom_size: int,
    target_read: dict[str, object],
    evidence_dir: Path,
    schedule: tuple[tuple[int, str | None], ...] = INPUT_SCHEDULE,
) -> tuple[
    str,
    int | None,
    list[dict[str, object]],
    dict[str, object] | None,
    dict[str, object],
]:
    client = McpStdioClient(_default_command())
    local: dict[str, object] = {
        "rom": str(rom_path),
        "target_read": target_read,
        "captures": [],
    }
    emulator_version = "unknown"
    mapped_bank: int | None = None
    safe_captures: list[dict[str, object]] = []
    safe_post_advance: dict[str, object] | None = None
    start = f"{int(target_read['logical_access']):04X}"
    breakpoint_armed = False

    def arm_breakpoint() -> None:
        nonlocal breakpoint_armed
        client.call(
            "set_breakpoint_range",
            {
                "start_address": start,
                "end_address": start,
                "memory_area": "rom_ram",
                "execute": False,
                "read": True,
                "write": False,
            },
        )
        breakpoint_armed = True

    def disarm_breakpoint() -> None:
        nonlocal breakpoint_armed
        client.call(
            "remove_breakpoint",
            {
                "address": start,
                "end_address": start,
                "memory_area": "rom_ram",
            },
        )
        breakpoint_armed = False

    try:
        tools = client.initialize()
        missing = sorted(REQUIRED_TOOLS - tools)
        if missing:
            raise RuntimeError(f"Gearsystem MCP tools missing: {missing}")
        client.call("load_media", {"file_path": str(rom_path)})
        media = client.call("get_media_info")
        local["media"] = media
        if (
            media.get("ready") is not True
            or media.get("is_game_gear") is not True
            or int(media.get("rom_size", 0)) != rom_size
        ):
            raise RuntimeError("Gearsystem did not load the exact-size test ROM")
        emulator_version = str(media.get("emulator_version", "unknown"))
        client.call("debug_reset")
        client.call("debug_pause")
        arm_breakpoint()
        target_found = False
        rejected_hits: list[dict[str, int]] = []
        for frames, button in schedule:
            if button is not None:
                client.call(
                    "controller_button",
                    {
                        "player": 1,
                        "button": button,
                        "action": "press_and_release",
                    },
                )
            for _ in range(MAX_REJECTED_TARGET_HITS):
                status = _step_frames_and_wait(client, frames)
                if status.get("at_breakpoint") is not True:
                    break
                state, hit_evidence = _capture_state(client)
                slot = int(target_read["slot"])
                candidate_bank = int(state[f"slot{slot}_bank"])
                pc_after = int(state["pc_after"])
                if _target_hit_matches(state, target_read):
                    mapped_bank = candidate_bank
                    local["target_hit"] = state
                    local["target_hit_evidence"] = hit_evidence
                    target_found = True
                    break
                rejected_hits.append(
                    {
                        "mapped_bank": candidate_bank,
                        "pc_after": pc_after,
                        "physical_pc_after": int(state["physical_pc_after"]),
                    }
                )
                disarm_breakpoint()
                _step_instruction_and_wait(client)
                arm_breakpoint()
            if target_found:
                break
        local["rejected_target_hits"] = rejected_hits
        disarm_breakpoint()

        if mapped_bank == int(target_read["expected_bank"]):
            previous = 0
            for frame in CAPTURE_FRAMES_AFTER_HIT:
                _step_frames_and_wait(client, frame - previous)
                png, metadata = _parse_screenshot(client.call("get_screenshot"))
                filename = f"frame_{frame:04d}.png"
                _write_bytes_atomic(evidence_dir / filename, png)
                safe_item = {"frame_after_hit": frame, **metadata}
                safe_captures.append(safe_item)
                local["captures"].append(
                    {"file": str(evidence_dir / filename), **safe_item}
                )
                previous = frame
            client.call(
                "controller_button",
                {
                    "player": 1,
                    "button": "1",
                    "action": "press_and_release",
                },
            )
            _step_frames_and_wait(client, 60)
            png, metadata = _parse_screenshot(client.call("get_screenshot"))
            filename = "after_advance.png"
            _write_bytes_atomic(evidence_dir / filename, png)
            safe_post_advance = {
                "button": "1",
                "frames_after_press": 60,
                **metadata,
            }
            local["post_advance_capture"] = {
                "file": str(evidence_dir / filename),
                **safe_post_advance,
            }
    finally:
        if breakpoint_armed:
            try:
                client.call(
                    "remove_breakpoint",
                    {
                        "address": start,
                        "end_address": start,
                        "memory_area": "rom_ram",
                    },
                )
            except RuntimeError:
                pass
        local["stderr_tail"] = list(client.stderr_tail)
        client.close()
    return (
        emulator_version,
        mapped_bank,
        safe_captures,
        safe_post_advance,
        local,
    )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-rom", type=Path, default=DEFAULT_TEST_ROM)
    parser.add_argument(
        "--baseline-rom",
        type=Path,
        default=DEFAULT_BASELINE_ROM,
    )
    parser.add_argument("--build-report", type=Path, default=DEFAULT_BUILD_REPORT)
    parser.add_argument("--resolution", type=Path, default=DEFAULT_RESOLUTION)
    parser.add_argument(
        "--stream-resolution",
        type=Path,
        default=DEFAULT_STREAM_RESOLUTION,
    )
    parser.add_argument("--local-report", type=Path, default=DEFAULT_LOCAL_REPORT)
    parser.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE_DIR)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()

    rom_path = _absolute(root, args.test_rom)
    baseline_rom_path = _absolute(root, args.baseline_rom)
    build_report_path = _absolute(root, args.build_report)
    resolution_path = _absolute(root, args.resolution)
    stream_resolution_path = _absolute(root, args.stream_resolution)
    local_report_path = _absolute(root, args.local_report)
    evidence_dir = _absolute(root, args.evidence_dir)
    _require_within(rom_path, root / "build", "test ROM")
    _require_within(baseline_rom_path, root / "build", "baseline ROM")
    _require_within(
        local_report_path,
        root / "reports" / "local",
        "display capture report",
    )
    _require_within(
        evidence_dir,
        root / "evidence" / "local",
        "display capture evidence",
    )
    missing = [
        path
        for path in (rom_path, baseline_rom_path, build_report_path)
        if not path.is_file()
    ]
    if not resolution_path.is_file() and not stream_resolution_path.is_file():
        missing.append(resolution_path)
    if missing:
        if args.if_ready:
            print("Display capture not run: the S25U-local test build is not ready.")
            return 0
        raise SystemExit("display capture inputs are missing")

    build_report = _read_json(build_report_path)
    if (
        build_report.get("artifact_kind")
        != "s25u-local-korean-test-patch-build"
        or build_report.get("status")
        != "technical-poc-built-needs-runtime-display-proof"
        or not _is_sha256(build_report.get("baseline_target_sha256"))
        or not _is_sha256(build_report.get("test_target_sha256"))
        or sha256_file(rom_path) != build_report["test_target_sha256"]
        or sha256_file(baseline_rom_path)
        != build_report["baseline_target_sha256"]
    ):
        raise PatchError("S25U-local test build identity or status mismatch")
    if args.evidence_dir == DEFAULT_EVIDENCE_DIR:
        evidence_dir = (
            evidence_dir / str(build_report["test_target_sha256"])[:16]
        )
        _require_within(
            evidence_dir,
            root / "evidence" / "local",
            "display capture evidence",
        )
    resolution: dict[str, object]
    capture_schedule = INPUT_SCHEDULE
    if stream_resolution_path.is_file():
        stream_resolution = _read_json(stream_resolution_path)
        validate_decoder_stream_resolution(stream_resolution)
        selected_index = stream_resolution["selected_stream_index"]
        streams = stream_resolution["streams"]
        if (
            stream_resolution["consumer_evidence_confirmed"] is not True
            or stream_resolution["target_sha256"]
            != build_report["baseline_target_sha256"]
            or not isinstance(selected_index, int)
            or not isinstance(streams, list)
        ):
            raise PatchError(
                "runtime stream resolution does not authorize display capture"
            )
        selected = streams[selected_index]
        assert isinstance(selected, dict)
        logical_access = int(selected["logical_start"])
        expected_bank = int(selected["mapped_bank"])
        resolution = {
            "target_read": {
                "slot": logical_access // 0x4000,
                "logical_access": logical_access,
                "physical_target_byte": int(selected["physical_start"]),
                "instruction_bank": int(selected["instruction_bank"]),
                "instruction_pc": int(selected["instruction_pc"]),
                "pc_after": int(selected["instruction_pc"]) + 1,
                "physical_pc_after": int(selected["instruction_pc"]) + 1,
                "expected_bank": expected_bank,
                "mapped_bank": expected_bank,
            }
        }
        capture_schedule = ATTRACT_CAPTURE_SCHEDULE
    else:
        resolution = _read_json(resolution_path)
        validate_consumer_resolution(resolution)
        if (
            resolution["consumer_evidence_confirmed"] is not True
            or resolution["target_sha256"]
            != build_report["baseline_target_sha256"]
            or not isinstance(resolution["target_read"], dict)
        ):
            raise PatchError(
                "runtime resolution does not authorize display capture"
            )

    (
        baseline_emulator_version,
        baseline_mapped_bank,
        _,
        _,
        baseline_local,
    ) = _capture_display(
        rom_path=baseline_rom_path,
        rom_size=baseline_rom_path.stat().st_size,
        target_read=resolution["target_read"],
        evidence_dir=evidence_dir / "baseline",
        schedule=capture_schedule,
    )
    (
        emulator_version,
        mapped_bank,
        captures,
        post_advance_capture,
        test_local,
    ) = _capture_display(
        rom_path=rom_path,
        rom_size=rom_path.stat().st_size,
        target_read=resolution["target_read"],
        evidence_dir=evidence_dir / "test",
        schedule=capture_schedule,
    )
    if baseline_emulator_version != emulator_version:
        raise PatchError("baseline and test captures used different emulator versions")
    frame_comparisons, post_comparison = _paired_pixel_comparisons(
        baseline_local,
        test_local,
    )
    comparison = build_display_comparison(
        build_report=build_report,
        frame_comparisons=frame_comparisons,
        post_advance_comparison=post_comparison,
        prior_rejected_physical_starts=prior_automatic_rejections(
            root,
            str(build_report["baseline_target_sha256"]),
        ),
    )
    comparison_path = write_display_comparison(root, comparison)
    _write_bytes_atomic(
        root / "reports" / "NEXT_STEP.txt",
        _next_step_text(
            comparison,
            evidence_dir=evidence_dir,
            root=root,
        ).encode("utf-8"),
    )
    local = {
        "baseline": baseline_local,
        "test": test_local,
        "comparison": comparison,
        "baseline_target_reached": (
            baseline_mapped_bank
            == int(resolution["target_read"]["expected_bank"])
        ),
    }
    local.update(
        {
            "artifact_kind": "s25u-local-test-display-capture",
            "schema_version": 1,
            "test_target_sha256": build_report["test_target_sha256"],
            "baseline_target_sha256": build_report["baseline_target_sha256"],
            "cold_boot": True,
        }
    )
    _write_json(local_report_path, local)
    safe = _build_safe_capture(
        build_report=build_report,
        resolution=resolution,
        emulator_version=emulator_version,
        mapped_bank=mapped_bank,
        captures=captures,
        post_advance_capture=post_advance_capture,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    _write_json(safe_path, safe)
    print(
        "SFKR display capture: "
        f"{safe['status']} ({len(captures) + int(post_advance_capture is not None)} "
        "local PNG frame(s))"
    )
    print(
        "SFKR pixel comparison: "
        f"{comparison['result']} ({comparison_path})"
    )
    if captures:
        relative_evidence = evidence_dir.relative_to(root)
        print(
            "Open in My Files: Internal storage > ShiningForceKR > "
            + " > ".join(relative_evidence.parts)
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
