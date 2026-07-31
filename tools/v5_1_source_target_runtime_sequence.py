#!/usr/bin/env python3
"""Capture a bounded runtime sequence after the confirmed dialogue anchor.

The exact selector, ordinals, screenshots, registers, and hit order stay in
ignored phone-local reports.  The publishable receipt contains fixed-schema
counts only.  A consecutive decoder sequence corroborates target play order,
but it does not approve a source pairing or a translation.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

try:
    from .patch_io import PatchError, sha256_file
    from .run_s25u_runtime_probe import (
        McpStdioClient,
        _capture_state,
        _default_command,
        _runtime_failure_receipt,
        _step_frames_and_wait,
        _step_instruction_and_wait,
        _write_runtime_failure_receipt,
    )
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_source_target_anchor import (
        CONFIRMED_ORDINAL,
        CONFIRMED_SELECTOR,
    )
    from .v5_1_source_target_structural_corroboration import (
        PUBLISH_RELATIVE_PATH as STRUCTURAL_CORROBORATION_PATH,
        validate_source_target_structural_corroboration,
    )
    from .v5_1_test_display_capture import (
        ATTRACT_CAPTURE_TIMEOUT_SECONDS,
        ATTRACT_CAPTURE_SCHEDULE,
        DECODER_ENTRY_LOGICAL,
        DEFAULT_BUILD_REPORT,
        DEFAULT_TEST_ROM,
        MAX_REJECTED_TARGET_HITS,
        PUBLISH_RELATIVE_PATH as DISPLAY_CAPTURE_PATH,
        _continue_until_breakpoint,
        _parse_screenshot,
        _set_unlimited_fast_forward,
        _write_bytes_atomic,
        validate_display_capture,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import PatchError, sha256_file
    from run_s25u_runtime_probe import (
        McpStdioClient,
        _capture_state,
        _default_command,
        _runtime_failure_receipt,
        _step_frames_and_wait,
        _step_instruction_and_wait,
        _write_runtime_failure_receipt,
    )
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_source_target_anchor import (
        CONFIRMED_ORDINAL,
        CONFIRMED_SELECTOR,
    )
    from v5_1_source_target_structural_corroboration import (
        PUBLISH_RELATIVE_PATH as STRUCTURAL_CORROBORATION_PATH,
        validate_source_target_structural_corroboration,
    )
    from v5_1_test_display_capture import (
        ATTRACT_CAPTURE_TIMEOUT_SECONDS,
        ATTRACT_CAPTURE_SCHEDULE,
        DECODER_ENTRY_LOGICAL,
        DEFAULT_BUILD_REPORT,
        DEFAULT_TEST_ROM,
        MAX_REJECTED_TARGET_HITS,
        PUBLISH_RELATIVE_PATH as DISPLAY_CAPTURE_PATH,
        _continue_until_breakpoint,
        _parse_screenshot,
        _set_unlimited_fast_forward,
        _write_bytes_atomic,
        validate_display_capture,
    )


ARTIFACT_KIND = "sanitized-v5-1-source-target-runtime-sequence"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_source_target_runtime_sequence.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_source_target_runtime_sequence.json"
)
LOCAL_EVIDENCE_DIR = Path(
    "evidence/local/v5_1_source_target_runtime_sequence"
)
POST_ANCHOR_ENTRY_GOAL = 4
POST_ANCHOR_ATTEMPT_LIMIT = 8
POST_DECODE_CAPTURE_FRAMES = 60
REQUIRED_TOOLS = {
    "controller_button",
    "debug_continue",
    "debug_get_status",
    "debug_pause",
    "debug_reset",
    "debug_step_frame",
    "debug_step_into",
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
    "set_fast_forward_speed",
    "toggle_fast_forward",
}

COUNT_KEYS = {
    "captured_entry_count",
    "post_anchor_entry_count",
    "same_selector_post_anchor_entry_count",
    "different_selector_post_anchor_entry_count",
    "consecutive_same_selector_step_count",
    "nonconsecutive_same_selector_step_count",
    "distinct_screen_hash_count",
    "advance_attempt_count",
}

SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "baseline_target_sha256",
    "test_target_sha256",
    "display_capture_sha256",
    "structural_corroboration_sha256",
    "local_sequence_sha256",
    "captured_utc",
    "runtime_sequence",
    "cold_boot",
    "anchor_reached_once",
    "first_post_anchor_step_consecutive",
    "candidate_pairing_only",
    "human_review_required",
    "hancharacter_contract_mode",
    "local_payload_policy",
    "source_pairing_complete",
    "speaker_assignment_complete",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _bounded_int(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def summarize_runtime_sequence(
    observations: list[dict[str, object]],
    *,
    advance_attempt_count: int,
    confirmed_selector: int = CONFIRMED_SELECTOR,
    confirmed_ordinal: int = CONFIRMED_ORDINAL,
) -> tuple[dict[str, int], str, bool]:
    if not observations:
        raise ValueError("runtime sequence observations are missing")
    if not _bounded_int(advance_attempt_count, 0, POST_ANCHOR_ATTEMPT_LIMIT):
        raise ValueError("runtime sequence advance attempts are invalid")

    screen_hashes: set[str] = set()
    previous_same_selector_ordinal: int | None = None
    post_anchor = 0
    same_selector = 0
    different_selector = 0
    consecutive = 0
    nonconsecutive = 0
    first_post_anchor_step_consecutive = False

    for index, observation in enumerate(observations):
        if not isinstance(observation, dict):
            raise ValueError("runtime sequence observation is invalid")
        selector = observation.get("selector")
        ordinal = observation.get("ordinal")
        png_sha256 = observation.get("png_sha256")
        if (
            not _bounded_int(selector, 0, 0xFFFF)
            or not _bounded_int(ordinal, 0, 0xFF)
            or not _is_sha256(png_sha256)
        ):
            raise ValueError(
                "runtime sequence observation fields are invalid"
            )
        assert isinstance(selector, int)
        assert isinstance(ordinal, int)
        assert isinstance(png_sha256, str)
        screen_hashes.add(png_sha256)
        if index == 0:
            if (
                selector != confirmed_selector
                or ordinal != confirmed_ordinal
            ):
                raise ValueError(
                    "runtime sequence anchor observation disagrees"
                )
            previous_same_selector_ordinal = ordinal
            continue

        post_anchor += 1
        if selector != confirmed_selector:
            different_selector += 1
            continue
        same_selector += 1
        assert previous_same_selector_ordinal is not None
        is_consecutive = ordinal == previous_same_selector_ordinal + 1
        consecutive += int(is_consecutive)
        nonconsecutive += int(not is_consecutive)
        if same_selector == 1:
            first_post_anchor_step_consecutive = is_consecutive
        previous_same_selector_ordinal = ordinal

    counts = {
        "captured_entry_count": len(observations),
        "post_anchor_entry_count": post_anchor,
        "same_selector_post_anchor_entry_count": same_selector,
        "different_selector_post_anchor_entry_count": different_selector,
        "consecutive_same_selector_step_count": consecutive,
        "nonconsecutive_same_selector_step_count": nonconsecutive,
        "distinct_screen_hash_count": len(screen_hashes),
        "advance_attempt_count": advance_attempt_count,
    }
    if (
        same_selector >= 3
        and consecutive == same_selector
        and nonconsecutive == 0
        and first_post_anchor_step_consecutive
    ):
        status = "runtime-sequence-corroboration-ready"
    elif same_selector >= 1:
        status = "runtime-sequence-corroboration-partial"
    else:
        status = "runtime-sequence-corroboration-unresolved"
    return counts, status, first_post_anchor_step_consecutive


def build_source_target_runtime_sequence(
    *,
    baseline_target_sha256: str,
    test_target_sha256: str,
    display_capture_sha256: str,
    structural_corroboration_sha256: str,
    local_sequence_sha256: str,
    runtime_sequence: dict[str, int],
    status: str,
    first_post_anchor_step_consecutive: bool,
    captured_utc: str,
) -> dict[str, object]:
    next_checkpoint = (
        "compare-runtime-sequence-with-source-context"
        if status == "runtime-sequence-corroboration-ready"
        else "capture-additional-runtime-sequence"
    )
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "baseline_target_sha256": baseline_target_sha256,
        "test_target_sha256": test_target_sha256,
        "display_capture_sha256": display_capture_sha256,
        "structural_corroboration_sha256":
            structural_corroboration_sha256,
        "local_sequence_sha256": local_sequence_sha256,
        "captured_utc": captured_utc,
        "runtime_sequence": runtime_sequence,
        "cold_boot": True,
        "anchor_reached_once": True,
        "first_post_anchor_step_consecutive":
            first_post_anchor_step_consecutive,
        "candidate_pairing_only": True,
        "human_review_required": True,
        "hancharacter_contract_mode": "translator_declared",
        "local_payload_policy": (
            "selectors-ordinals-screens-registers-hit-order-and-text-local-only"
        ),
        "source_pairing_complete": False,
        "speaker_assignment_complete": False,
        "translation_build_eligible": False,
        "next_checkpoint": next_checkpoint,
    }
    validate_source_target_runtime_sequence(value)
    return value


def validate_source_target_runtime_sequence(
    value: dict[str, object],
) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError("runtime sequence fields do not match")
    status = value["status"]
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or status
        not in {
            "runtime-sequence-corroboration-ready",
            "runtime-sequence-corroboration-partial",
            "runtime-sequence-corroboration-unresolved",
        }
        or not _is_sha256(value["baseline_target_sha256"])
        or not _is_sha256(value["test_target_sha256"])
        or not _is_sha256(value["display_capture_sha256"])
        or not _is_sha256(value["structural_corroboration_sha256"])
        or not _is_sha256(value["local_sequence_sha256"])
    ):
        raise ValueError("runtime sequence identity is invalid")

    try:
        timestamp = datetime.fromisoformat(
            str(value["captured_utc"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError("runtime sequence timestamp is invalid") from error
    if timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
        raise ValueError("runtime sequence timestamp needs UTC")

    counts = value["runtime_sequence"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("runtime sequence counts do not match")
    captured = counts.get("captured_entry_count")
    if not _bounded_int(captured, 1, POST_ANCHOR_ATTEMPT_LIMIT + 1):
        raise ValueError("runtime sequence capture count is invalid")
    assert isinstance(captured, int)
    for key, count in counts.items():
        if not _bounded_int(count, 0, POST_ANCHOR_ATTEMPT_LIMIT + 1):
            raise ValueError(f"runtime sequence {key} is invalid")
    post_anchor = int(counts["post_anchor_entry_count"])
    same_selector = int(counts["same_selector_post_anchor_entry_count"])
    if (
        captured != post_anchor + 1
        or post_anchor
        != same_selector
        + counts["different_selector_post_anchor_entry_count"]
        or same_selector
        != counts["consecutive_same_selector_step_count"]
        + counts["nonconsecutive_same_selector_step_count"]
        or counts["distinct_screen_hash_count"] > captured
        or counts["advance_attempt_count"] < post_anchor
    ):
        raise ValueError("runtime sequence aggregates are inconsistent")

    first_consecutive = value["first_post_anchor_step_consecutive"]
    expected_ready = (
        same_selector >= 3
        and counts["consecutive_same_selector_step_count"] == same_selector
        and counts["nonconsecutive_same_selector_step_count"] == 0
        and first_consecutive is True
    )
    expected_status = (
        "runtime-sequence-corroboration-ready"
        if expected_ready
        else (
            "runtime-sequence-corroboration-partial"
            if same_selector >= 1
            else "runtime-sequence-corroboration-unresolved"
        )
    )
    expected_checkpoint = (
        "compare-runtime-sequence-with-source-context"
        if expected_status == "runtime-sequence-corroboration-ready"
        else "capture-additional-runtime-sequence"
    )
    if (
        status != expected_status
        or value["cold_boot"] is not True
        or value["anchor_reached_once"] is not True
        or not isinstance(first_consecutive, bool)
        or value["candidate_pairing_only"] is not True
        or value["human_review_required"] is not True
        or value["hancharacter_contract_mode"] != "translator_declared"
        or value["local_payload_policy"]
        != (
            "selectors-ordinals-screens-registers-hit-order-and-text-local-only"
        )
        or value["source_pairing_complete"] is not False
        or value["speaker_assignment_complete"] is not False
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"] != expected_checkpoint
    ):
        raise ValueError("runtime sequence policy is invalid")


def validate_reusable_local_sequence(
    *,
    safe: dict[str, object],
    local: dict[str, object],
    baseline_target_sha256: str,
    test_target_sha256: str,
    local_sequence_sha256: str,
) -> tuple[dict[str, int], str, bool]:
    validate_source_target_runtime_sequence(safe)
    if (
        local.get("artifact_kind")
        != "local-v5-1-source-target-runtime-sequence"
        or local.get("schema_version") != SCHEMA_VERSION
        or local.get("baseline_target_sha256") != baseline_target_sha256
        or local.get("test_target_sha256") != test_target_sha256
        or safe["baseline_target_sha256"] != baseline_target_sha256
        or safe["test_target_sha256"] != test_target_sha256
        or safe["local_sequence_sha256"] != local_sequence_sha256
    ):
        raise ValueError("reusable runtime sequence identity disagrees")
    observations = local.get("observations")
    attempts = local.get("runtime_sequence", {}).get(
        "advance_attempt_count"
    ) if isinstance(local.get("runtime_sequence"), dict) else None
    if not isinstance(observations, list) or not isinstance(attempts, int):
        raise ValueError("reusable runtime sequence payload is missing")
    counts, status, first_consecutive = summarize_runtime_sequence(
        observations,
        advance_attempt_count=attempts,
    )
    if (
        counts != safe["runtime_sequence"]
        or counts != local.get("runtime_sequence")
        or status != safe["status"]
        or first_consecutive
        is not safe["first_post_anchor_step_consecutive"]
    ):
        raise ValueError("reusable runtime sequence evidence disagrees")
    return counts, status, first_consecutive


def _entry_coordinates(state: dict[str, object]) -> tuple[int, int]:
    registers = state.get("registers")
    if not isinstance(registers, dict):
        raise RuntimeError("runtime sequence registers are missing")
    selector = registers.get("de")
    bc = registers.get("bc")
    if (
        not _bounded_int(selector, 0, 0xFFFF)
        or not _bounded_int(bc, 0, 0xFFFF)
    ):
        raise RuntimeError("runtime sequence registers are invalid")
    assert isinstance(selector, int)
    assert isinstance(bc, int)
    return selector, bc >> 8


def _capture_screen(
    client: McpStdioClient,
    path: Path,
) -> dict[str, object]:
    png, metadata = _parse_screenshot(client.call("get_screenshot"))
    _write_bytes_atomic(path, png)
    return {
        "file": str(path),
        **metadata,
    }


def capture_runtime_sequence(
    *,
    rom_path: Path,
    rom_size: int,
    evidence_dir: Path,
) -> tuple[list[dict[str, object]], int, dict[str, object]]:
    client = McpStdioClient(_default_command())
    breakpoint_armed = False
    fast_forward_enabled = False
    local: dict[str, object] = {
        "rom": str(rom_path),
        "hits": [],
        "screens": [],
    }
    observations: list[dict[str, object]] = []
    advance_attempt_count = 0
    entry_address = f"{DECODER_ENTRY_LOGICAL:04X}"

    def arm_breakpoint() -> None:
        nonlocal breakpoint_armed
        client.call(
            "set_breakpoint_range",
            {
                "start_address": entry_address,
                "end_address": entry_address,
                "memory_area": "rom_ram",
                "execute": True,
                "read": False,
                "write": False,
            },
        )
        breakpoint_armed = True

    def disarm_breakpoint() -> None:
        nonlocal breakpoint_armed
        client.call(
            "remove_breakpoint",
            {
                "address": entry_address,
                "end_address": entry_address,
                "memory_area": "rom_ram",
            },
        )
        breakpoint_armed = False

    try:
        tools = client.initialize()
        missing = sorted(REQUIRED_TOOLS - tools)
        if missing:
            raise RuntimeError(
                f"Gearsystem MCP tools missing: {missing}"
            )
        client.call("load_media", {"file_path": str(rom_path)})
        media = client.call("get_media_info")
        local["media"] = media
        if (
            media.get("ready") is not True
            or media.get("is_game_gear") is not True
            or int(media.get("rom_size", 0)) != rom_size
        ):
            raise RuntimeError(
                "Gearsystem did not load the exact-size sequence ROM"
            )
        client.call("debug_reset")
        client.call("debug_pause")
        arm_breakpoint()
        anchor_state: dict[str, object] | None = None
        if any(button is not None for _, button in ATTRACT_CAPTURE_SCHEDULE):
            raise RuntimeError(
                "runtime sequence attract schedule must be passive"
            )
        _set_unlimited_fast_forward(client, True)
        fast_forward_enabled = True
        for _ in range(MAX_REJECTED_TARGET_HITS):
            status = _continue_until_breakpoint(
                client,
                ATTRACT_CAPTURE_TIMEOUT_SECONDS,
            )
            if status.get("at_breakpoint") is not True:
                break
            state, hit_evidence = _capture_state(client)
            selector, ordinal = _entry_coordinates(state)
            local["hits"].append(
                {
                    "phase": "anchor-search",
                    "selector": selector,
                    "ordinal": ordinal,
                    "state": state,
                    "evidence": hit_evidence,
                }
            )
            disarm_breakpoint()
            if (
                selector == CONFIRMED_SELECTOR
                and ordinal == CONFIRMED_ORDINAL
            ):
                anchor_state = state
                break
            _step_instruction_and_wait(client)
            arm_breakpoint()
        _set_unlimited_fast_forward(client, False)
        fast_forward_enabled = False
        if anchor_state is None:
            raise RuntimeError(
                "runtime sequence confirmed anchor was not reached"
            )
        _step_instruction_and_wait(client)
        _step_frames_and_wait(client, POST_DECODE_CAPTURE_FRAMES)
        anchor_screen = _capture_screen(
            client,
            evidence_dir / "anchor.png",
        )
        local["screens"].append(anchor_screen)
        observations.append(
            {
                "selector": CONFIRMED_SELECTOR,
                "ordinal": CONFIRMED_ORDINAL,
                "png_sha256": anchor_screen["png_sha256"],
            }
        )

        same_selector_post_anchor = 0
        while (
            advance_attempt_count < POST_ANCHOR_ATTEMPT_LIMIT
            and same_selector_post_anchor < POST_ANCHOR_ENTRY_GOAL
        ):
            advance_attempt_count += 1
            arm_breakpoint()
            _set_unlimited_fast_forward(client, True)
            fast_forward_enabled = True
            client.call(
                "controller_button",
                {
                    "player": 1,
                    "button": "1",
                    "action": "press_and_release",
                },
            )
            status = _continue_until_breakpoint(client, 4.0)
            _set_unlimited_fast_forward(client, False)
            fast_forward_enabled = False
            if status.get("at_breakpoint") is not True:
                disarm_breakpoint()
                continue
            state, hit_evidence = _capture_state(client)
            selector, ordinal = _entry_coordinates(state)
            local["hits"].append(
                {
                    "phase": "post-anchor",
                    "advance_attempt": advance_attempt_count,
                    "selector": selector,
                    "ordinal": ordinal,
                    "state": state,
                    "evidence": hit_evidence,
                }
            )
            disarm_breakpoint()
            _step_instruction_and_wait(client)
            _step_frames_and_wait(client, POST_DECODE_CAPTURE_FRAMES)
            screen = _capture_screen(
                client,
                evidence_dir / (
                    f"post_anchor_{len(observations):02d}.png"
                ),
            )
            local["screens"].append(screen)
            observations.append(
                {
                    "selector": selector,
                    "ordinal": ordinal,
                    "png_sha256": screen["png_sha256"],
                }
            )
            same_selector_post_anchor += int(
                selector == CONFIRMED_SELECTOR
            )
    except Exception as error:
        receipt = _runtime_failure_receipt(
            "source-target-runtime-sequence",
            error,
            client,
        )
        _write_runtime_failure_receipt(
            Path(__file__).resolve().parents[1],
            receipt,
        )
        raise
    finally:
        if fast_forward_enabled:
            try:
                _set_unlimited_fast_forward(client, False)
            except RuntimeError:
                pass
        if breakpoint_armed:
            try:
                client.call(
                    "remove_breakpoint",
                    {
                        "address": entry_address,
                        "end_address": entry_address,
                        "memory_area": "rom_ram",
                    },
                )
            except RuntimeError:
                pass
        local["stderr_tail"] = list(client.stderr_tail)
        client.close()
    return observations, advance_attempt_count, local


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-rom", type=Path, default=DEFAULT_TEST_ROM)
    parser.add_argument(
        "--build-report",
        type=Path,
        default=DEFAULT_BUILD_REPORT,
    )
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()

    rom_path = (
        args.test_rom
        if args.test_rom.is_absolute()
        else root / args.test_rom
    ).resolve()
    build_report_path = (
        args.build_report
        if args.build_report.is_absolute()
        else root / args.build_report
    ).resolve()
    display_capture_path = root / DISPLAY_CAPTURE_PATH
    structural_path = root / STRUCTURAL_CORROBORATION_PATH
    required = (
        rom_path,
        build_report_path,
        display_capture_path,
        structural_path,
    )
    if not all(path.is_file() for path in required):
        if args.if_ready:
            print("Source-target runtime sequence is not ready")
            return 0
        raise SystemExit("source-target runtime sequence input is missing")
    try:
        rom_path.relative_to((root / "build").resolve())
    except ValueError as error:
        raise PatchError("runtime sequence ROM must stay under build") from error

    build_report = _load_json_object(build_report_path)
    display_capture = _load_json_object(display_capture_path)
    structural = _load_json_object(structural_path)
    validate_display_capture(display_capture)
    validate_source_target_structural_corroboration(structural)
    if (
        build_report.get("artifact_kind")
        != "s25u-local-korean-test-patch-build"
        or build_report.get("status")
        != "technical-poc-built-needs-runtime-display-proof"
        or sha256_file(rom_path) != build_report.get("test_target_sha256")
        or display_capture["test_target_sha256"]
        != build_report.get("test_target_sha256")
        or display_capture["baseline_target_sha256"]
        != build_report.get("baseline_target_sha256")
        or structural["target_sha256"]
        != build_report.get("baseline_target_sha256")
    ):
        raise ValueError("runtime sequence input identity disagrees")

    safe_path = root / PUBLISH_RELATIVE_PATH
    local_path = root / LOCAL_REPORT_PATH
    if safe_path.is_file() and local_path.is_file():
        try:
            existing = _load_json_object(safe_path)
            existing_local = _load_json_object(local_path)
            existing_counts, existing_status, existing_first = (
                validate_reusable_local_sequence(
                    safe=existing,
                    local=existing_local,
                    baseline_target_sha256=str(
                        build_report["baseline_target_sha256"]
                    ),
                    test_target_sha256=str(
                        build_report["test_target_sha256"]
                    ),
                    local_sequence_sha256=sha256_file(local_path),
                )
            )
            current_display_sha256 = sha256_file(display_capture_path)
            current_structural_sha256 = sha256_file(structural_path)
            if (
                existing["display_capture_sha256"]
                == current_display_sha256
                and existing["structural_corroboration_sha256"]
                == current_structural_sha256
            ):
                print(
                    "SFKR source-target runtime sequence: "
                    "reusing matching local capture"
                )
                return 0
            existing_local["display_capture_sha256"] = (
                current_display_sha256
            )
            existing_local["structural_corroboration_sha256"] = (
                current_structural_sha256
            )
            local_path.write_text(
                json.dumps(
                    existing_local,
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            refreshed = build_source_target_runtime_sequence(
                baseline_target_sha256=str(
                    build_report["baseline_target_sha256"]
                ),
                test_target_sha256=str(
                    build_report["test_target_sha256"]
                ),
                display_capture_sha256=current_display_sha256,
                structural_corroboration_sha256=
                    current_structural_sha256,
                local_sequence_sha256=sha256_file(local_path),
                runtime_sequence=existing_counts,
                status=existing_status,
                first_post_anchor_step_consecutive=existing_first,
                captured_utc=str(existing["captured_utc"]),
            )
            safe_path.write_text(
                json.dumps(
                    refreshed,
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            print(
                "SFKR source-target runtime sequence: "
                "refreshed dependencies for matching local capture"
            )
            return 0
        except (OSError, ValueError, json.JSONDecodeError):
            pass

    evidence_dir = (
        root
        / LOCAL_EVIDENCE_DIR
        / str(build_report["test_target_sha256"])[:16]
    )
    evidence_dir.mkdir(parents=True, exist_ok=True)
    observations, advance_attempt_count, local_capture = (
        capture_runtime_sequence(
            rom_path=rom_path,
            rom_size=rom_path.stat().st_size,
            evidence_dir=evidence_dir,
        )
    )
    counts, status, first_consecutive = summarize_runtime_sequence(
        observations,
        advance_attempt_count=advance_attempt_count,
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    local = {
        "artifact_kind": "local-v5-1-source-target-runtime-sequence",
        "schema_version": SCHEMA_VERSION,
        "baseline_target_sha256": build_report[
            "baseline_target_sha256"
        ],
        "test_target_sha256": build_report["test_target_sha256"],
        "display_capture_sha256": sha256_file(display_capture_path),
        "structural_corroboration_sha256": sha256_file(structural_path),
        "captured_utc": captured_utc,
        "runtime_sequence": counts,
        "observations": observations,
        "capture": local_capture,
        "publication_policy": (
            "never-publish-selectors-ordinals-screens-registers-hit-order-or-text"
        ),
    }
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_source_target_runtime_sequence(
        baseline_target_sha256=str(
            build_report["baseline_target_sha256"]
        ),
        test_target_sha256=str(build_report["test_target_sha256"]),
        display_capture_sha256=sha256_file(display_capture_path),
        structural_corroboration_sha256=sha256_file(structural_path),
        local_sequence_sha256=sha256_file(local_path),
        runtime_sequence=counts,
        status=status,
        first_post_anchor_step_consecutive=first_consecutive,
        captured_utc=captured_utc,
    )
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR source-target runtime sequence: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
