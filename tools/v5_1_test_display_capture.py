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
        LOCAL_FAILURE_REPORT,
        McpStdioClient,
        _capture_state,
        _default_command,
        _runtime_failure_receipt,
        _step_frames_and_wait,
        _step_instruction_and_wait,
        _write_runtime_failure_receipt,
        validate_runtime_failure_receipt,
    )
    from .v5_1_decoder_stream_resolution import (
        validate_decoder_stream_resolution,
    )
    from .v5_1_runtime_hit_resolver import validate_consumer_resolution
    from .v5_1_script_group import resolve_group_entry
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
        LOCAL_FAILURE_REPORT,
        McpStdioClient,
        _capture_state,
        _default_command,
        _runtime_failure_receipt,
        _step_frames_and_wait,
        _step_instruction_and_wait,
        _write_runtime_failure_receipt,
        validate_runtime_failure_receipt,
    )
    from v5_1_decoder_stream_resolution import (
        validate_decoder_stream_resolution,
    )
    from v5_1_runtime_hit_resolver import validate_consumer_resolution
    from v5_1_script_group import resolve_group_entry
    from v5_1_png_pixels import compare_png_pixels
    from v5_1_test_display_comparison import (
        build_display_comparison,
        prior_automatic_rejections,
        write_display_comparison,
    )
    from v5_1_test_phrase import TEST_PHRASE


ARTIFACT_KIND = "sanitized-s25u-test-display-capture"
SCHEMA_VERSION = 5
LEGACY_SCHEMA_VERSIONS = {1, 2, 3, 4}
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
DEFAULT_REVIEW_DIR = Path("reports/HUMAN_REVIEW")
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_display_capture.json"
)
CAPTURE_FRAMES_AFTER_HIT = (1, 8, 30, 90)
ATTRACT_CAPTURE_SCHEDULE: tuple[tuple[int, str | None], ...] = (
    *((1_000, None),) * 12,
)
MAX_REJECTED_TARGET_HITS = 64
DECODER_ENTRY_LOGICAL = 0x33FA
LOOKUP_TABLE_BASE = 0x3FE8
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
TOP_LEVEL_KEYS_WITH_SELECTOR = TOP_LEVEL_KEYS | {"entry_selector"}
TOP_LEVEL_KEYS_V4 = TOP_LEVEL_KEYS_WITH_SELECTOR | {"group_entry"}
ENTRY_SELECTOR_KEYS_V2 = {
    "status",
    "lookup_table_base",
    "baseline_selector_offset",
    "test_selector_offset",
    "selectors_match",
    "entry_index",
    "pointer_address",
    "next_pointer_address",
    "target_offset_within_entry",
    "pointer_bounds_target",
}
ENTRY_SELECTOR_KEYS = ENTRY_SELECTOR_KEYS_V2 | {
    "baseline_entry_ordinal",
    "test_entry_ordinal",
    "ordinals_match",
}
GROUP_ENTRY_KEYS_V4 = {
    "status",
    "entry_ordinal",
    "decoded_prefix_entry_count",
    "group_pointer_address",
    "entry_start_bit",
    "entry_end_bit_exclusive",
    "entry_encoded_bits",
    "entry_symbol_count",
    "entry_start_logical_byte",
    "entry_end_logical_byte_inclusive",
    "target_logical_byte",
    "target_within_entry_bytes",
    "prefix_roundtrip_exact",
}
GROUP_ENTRY_KEYS = GROUP_ENTRY_KEYS_V4 | {
    "target_byte_candidates",
    "observed_b_matches_target_candidates",
}
TARGET_BYTE_CANDIDATE_KEYS = {
    "entry_ordinal",
    "entry_start_bit",
    "entry_end_bit_exclusive",
    "entry_encoded_bits",
    "entry_symbol_count",
    "entry_start_logical_byte",
    "entry_end_logical_byte_inclusive",
}
CAPTURE_STATUSES = {
    "capture-ready-human-review-required",
    "runtime-target-read-not-observed",
}
_CURRENT_FAILURE_STAGE = "display-capture-preflight"


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_display_capture(capture: dict[str, object]) -> None:
    schema_version = capture.get("schema_version")
    expected_keys = (
        TOP_LEVEL_KEYS_V4
        if schema_version in {4, SCHEMA_VERSION}
        else (
            TOP_LEVEL_KEYS_WITH_SELECTOR
            if schema_version in {2, 3}
            else TOP_LEVEL_KEYS
        )
    )
    if set(capture) != expected_keys:
        raise ValueError("display capture top-level fields do not match")
    if capture["artifact_kind"] != ARTIFACT_KIND:
        raise ValueError("unexpected display capture artifact kind")
    if schema_version not in LEGACY_SCHEMA_VERSIONS | {SCHEMA_VERSION}:
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

    if schema_version in {2, 3, 4, SCHEMA_VERSION}:
        selector = capture["entry_selector"]
        if selector is not None:
            expected_selector_keys = (
                ENTRY_SELECTOR_KEYS
                if schema_version in {3, 4, SCHEMA_VERSION}
                else ENTRY_SELECTOR_KEYS_V2
            )
            if (
                not isinstance(selector, dict)
                or set(selector) != expected_selector_keys
            ):
                raise ValueError("entry_selector fields do not match")
            if selector["status"] not in {"resolved", "unresolved"}:
                raise ValueError("entry_selector status is invalid")
            if selector["lookup_table_base"] != LOOKUP_TABLE_BASE:
                raise ValueError("entry_selector lookup table base is invalid")
            for key in ("baseline_selector_offset", "test_selector_offset"):
                value = selector[key]
                if value is not None and (
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or not 0 <= value <= 0xFFFF
                ):
                    raise ValueError(f"entry_selector {key} is invalid")
            selectors_match = selector["selectors_match"]
            expected_match = (
                selector["baseline_selector_offset"] is not None
                and selector["baseline_selector_offset"]
                == selector["test_selector_offset"]
            )
            if selectors_match is not expected_match:
                raise ValueError("entry_selector match evidence is inconsistent")
            ordinals_match = True
            if schema_version in {3, 4, SCHEMA_VERSION}:
                for key in ("baseline_entry_ordinal", "test_entry_ordinal"):
                    value = selector[key]
                    if value is not None and (
                        not isinstance(value, int)
                        or isinstance(value, bool)
                        or not 0 <= value <= 0xFF
                    ):
                        raise ValueError(f"entry_selector {key} is invalid")
                ordinals_match = (
                    selector["baseline_entry_ordinal"] is not None
                    and selector["baseline_entry_ordinal"]
                    == selector["test_entry_ordinal"]
                )
                if selector["ordinals_match"] is not ordinals_match:
                    raise ValueError(
                        "entry_selector ordinal evidence is inconsistent"
                    )
            derived_keys = (
                "entry_index",
                "pointer_address",
                "next_pointer_address",
                "target_offset_within_entry",
            )
            if selector["status"] == "resolved":
                if any(
                    not isinstance(selector[key], int)
                    or isinstance(selector[key], bool)
                    for key in derived_keys
                ):
                    raise ValueError("resolved entry_selector values are invalid")
                selector_offset = selector["baseline_selector_offset"]
                assert isinstance(selector_offset, int)
                if (
                    not selectors_match
                    or not ordinals_match
                    or not 0 <= selector_offset <= 0x16
                    or selector_offset % 2
                    or selector["entry_index"] * 2 != selector_offset
                    or selector["pointer_address"]
                    + selector["target_offset_within_entry"]
                    != target_read["logical_access"]
                    or selector["pointer_address"] > target_read["logical_access"]
                    or (
                        schema_version == 4
                        and selector["next_pointer_address"]
                        <= target_read["logical_access"]
                    )
                    or selector["pointer_bounds_target"] is not True
                ):
                    raise ValueError("entry_selector evidence is inconsistent")
            elif (
                any(selector[key] is not None for key in derived_keys)
                or selector["pointer_bounds_target"] is not False
            ):
                raise ValueError("unresolved entry_selector cannot claim a block")
            if not confirmed:
                raise ValueError("entry_selector requires a confirmed target read")

    if schema_version in {4, SCHEMA_VERSION}:
        group_entry = capture["group_entry"]
        if group_entry is not None:
            expected_group_entry_keys = (
                GROUP_ENTRY_KEYS
                if schema_version == SCHEMA_VERSION
                else GROUP_ENTRY_KEYS_V4
            )
            if (
                not isinstance(group_entry, dict)
                or set(group_entry) != expected_group_entry_keys
            ):
                raise ValueError("group_entry fields do not match")
            if group_entry["status"] not in {
                "resolved",
                "target-outside-selected-entry",
            }:
                raise ValueError("group_entry status is invalid")
            for key in (
                "entry_ordinal",
                "decoded_prefix_entry_count",
                "group_pointer_address",
                "entry_start_bit",
                "entry_end_bit_exclusive",
                "entry_encoded_bits",
                "entry_symbol_count",
                "entry_start_logical_byte",
                "entry_end_logical_byte_inclusive",
                "target_logical_byte",
            ):
                value = group_entry[key]
                if (
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value < 0
                ):
                    raise ValueError(f"group_entry {key} is invalid")
            target_within = group_entry["target_within_entry_bytes"]
            expected_within = (
                group_entry["entry_start_logical_byte"]
                <= group_entry["target_logical_byte"]
                <= group_entry["entry_end_logical_byte_inclusive"]
            )
            if (
                group_entry["decoded_prefix_entry_count"]
                != group_entry["entry_ordinal"] + 1
                or not 0 <= group_entry["entry_ordinal"] <= 0xFF
                or group_entry["entry_start_bit"]
                >= group_entry["entry_end_bit_exclusive"]
                or group_entry["entry_encoded_bits"]
                != group_entry["entry_end_bit_exclusive"]
                - group_entry["entry_start_bit"]
                or group_entry["entry_symbol_count"] <= 0
                or target_within is not expected_within
                or group_entry["prefix_roundtrip_exact"] is not True
                or (
                    group_entry["status"] == "resolved"
                    and target_within is not True
                )
                or (
                    group_entry["status"] == "target-outside-selected-entry"
                    and target_within is not False
                )
            ):
                raise ValueError("group_entry evidence is inconsistent")
            selector = capture["entry_selector"]
            if (
                not isinstance(selector, dict)
                or selector.get("status") != "resolved"
                or group_entry["entry_ordinal"]
                != selector.get("baseline_entry_ordinal")
                or group_entry["group_pointer_address"]
                != selector.get("pointer_address")
                or group_entry["target_logical_byte"]
                != target_read["logical_access"]
            ):
                raise ValueError("group_entry and entry_selector disagree")
            if not confirmed:
                raise ValueError("group_entry requires a confirmed target read")
            if schema_version == SCHEMA_VERSION:
                candidates = group_entry["target_byte_candidates"]
                if not isinstance(candidates, list):
                    raise ValueError(
                        "group_entry target candidates must be a list"
                    )
                candidate_ordinals: list[int] = []
                for candidate in candidates:
                    if (
                        not isinstance(candidate, dict)
                        or set(candidate) != TARGET_BYTE_CANDIDATE_KEYS
                    ):
                        raise ValueError(
                            "group_entry target candidate fields do not match"
                        )
                    for key in TARGET_BYTE_CANDIDATE_KEYS:
                        value = candidate[key]
                        if (
                            not isinstance(value, int)
                            or isinstance(value, bool)
                            or value < 0
                        ):
                            raise ValueError(
                                f"group_entry target candidate {key} is invalid"
                            )
                    if (
                        not 0 <= candidate["entry_ordinal"] <= 0xFF
                        or candidate["entry_start_bit"]
                        >= candidate["entry_end_bit_exclusive"]
                        or candidate["entry_encoded_bits"]
                        != candidate["entry_end_bit_exclusive"]
                        - candidate["entry_start_bit"]
                        or candidate["entry_symbol_count"] <= 0
                        or not (
                            candidate["entry_start_logical_byte"]
                            <= group_entry["target_logical_byte"]
                            <= candidate[
                                "entry_end_logical_byte_inclusive"
                            ]
                        )
                        or (
                            candidate_ordinals
                            and candidate["entry_ordinal"]
                            <= candidate_ordinals[-1]
                        )
                    ):
                        raise ValueError(
                            "group_entry target candidate is inconsistent"
                        )
                    candidate_ordinals.append(candidate["entry_ordinal"])
                observed_matches = (
                    group_entry["entry_ordinal"] in candidate_ordinals
                )
                if (
                    not isinstance(
                        group_entry["observed_b_matches_target_candidates"],
                        bool,
                    )
                    or group_entry[
                        "observed_b_matches_target_candidates"
                    ]
                    is not observed_matches
                    or observed_matches is not target_within
                ):
                    raise ValueError(
                        "group_entry target candidate match is inconsistent"
                    )

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
    entry_selector: dict[str, object] | None = None,
    group_entry: dict[str, object] | None = None,
) -> dict[str, object]:
    target_read = resolution["target_read"]
    assert isinstance(target_read, dict)
    expected_bank = int(target_read["expected_bank"])
    confirmed = mapped_bank == expected_bank
    ready = confirmed and bool(captures) and post_advance_capture is not None
    if not confirmed:
        entry_selector = None
        group_entry = None
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
        "entry_selector": entry_selector,
        "group_entry": group_entry,
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
        return (
            "Shining Force KR 다음 할 일\n\n"
            "기준 화면과 시험 화면의 픽셀 차이가 발견됐습니다.\n"
            "내부 저장공간 > ShiningForceKR > reports > HUMAN_REVIEW에서\n"
            "README.txt를 읽고 PNG 3개를 Codex 대화에 올려주세요.\n\n"
            "ROM 또는 생성 ROM은 올리지 마세요.\n"
        )
    return (
        "Shining Force KR 다음 할 일\n\n"
        "기준 화면과 시험 화면을 완전하게 짝지어 비교하지 못했습니다.\n"
        "reports/AUTOPILOT_STATUS.txt와 이 파일의 글자 내용만 보내주세요.\n"
        "ROM 또는 생성 ROM은 올리지 마세요.\n"
    )


def _human_review_item(
    captures: object,
    frame: int,
    label: str,
) -> dict[str, object]:
    if not isinstance(captures, list):
        raise PatchError(f"{label} capture list is missing")
    item = next(
        (
            value
            for value in captures
            if isinstance(value, dict)
            and value.get("frame_after_hit") == frame
        ),
        None,
    )
    if (
        not isinstance(item, dict)
        or not isinstance(item.get("file"), str)
        or not _is_sha256(item.get("png_sha256"))
    ):
        raise PatchError(f"{label} review capture is missing")
    return item


def _copy_verified_review_png(item: dict[str, object], target: Path) -> None:
    source = Path(str(item["file"]))
    data = source.read_bytes()
    if sha256_bytes(data) != item["png_sha256"]:
        raise PatchError("human-review PNG identity mismatch")
    _write_bytes_atomic(target, data)


def _write_human_review_bundle(
    comparison: dict[str, object],
    *,
    baseline_local: dict[str, object],
    test_local: dict[str, object],
    review_dir: Path,
) -> tuple[Path, ...]:
    if comparison.get("result") != "visible-pixel-change-human-review-required":
        return ()
    frames = comparison.get("frame_comparisons")
    if not isinstance(frames, list) or not frames:
        raise PatchError("visible comparison has no review frame")
    selected = max(
        (
            item
            for item in frames
            if isinstance(item, dict)
            and isinstance(item.get("frame_after_hit"), int)
            and isinstance(item.get("changed_pixels"), int)
        ),
        key=lambda item: int(item["changed_pixels"]),
        default=None,
    )
    if not isinstance(selected, dict) or int(selected["changed_pixels"]) <= 0:
        raise PatchError("visible comparison has no changed review frame")
    frame = int(selected["frame_after_hit"])
    baseline_item = _human_review_item(
        baseline_local.get("captures"),
        frame,
        "baseline",
    )
    test_item = _human_review_item(
        test_local.get("captures"),
        frame,
        "test",
    )
    post_item = test_local.get("post_advance_capture")
    if (
        not isinstance(post_item, dict)
        or not isinstance(post_item.get("file"), str)
        or not _is_sha256(post_item.get("png_sha256"))
    ):
        raise PatchError("post-advance review capture is missing")

    review_dir.mkdir(parents=True, exist_ok=True)
    baseline_path = review_dir / "1_BASELINE.png"
    test_path = review_dir / "2_TEST.png"
    post_path = review_dir / "3_AFTER_ADVANCE.png"
    readme_path = review_dir / "README.txt"
    _copy_verified_review_png(baseline_item, baseline_path)
    _copy_verified_review_png(test_item, test_path)
    _copy_verified_review_png(post_item, post_path)
    _write_bytes_atomic(
        readme_path,
        (
            "Shining Force KR 화면 확인\n\n"
            "1_BASELINE.png와 2_TEST.png를 비교하세요.\n"
            "2_TEST.png에 시험 문구 '한다'가 또렷하게 보여야 합니다.\n"
            "초상화, 대화창 테두리와 주변 글자가 깨지지 않아야 합니다.\n"
            "3_AFTER_ADVANCE.png에서는 대사 진행 뒤 화면이 정상이어야 합니다.\n\n"
            "Codex 대화에는 이 폴더의 PNG 3개만 올려주세요.\n"
            "ROM 또는 생성 ROM은 올리지 마세요.\n"
        ).encode("utf-8"),
    )
    return baseline_path, test_path, post_path, readme_path


def _entry_selector_offset(local_capture: dict[str, object]) -> int | None:
    state = local_capture.get("entry_selector_hit")
    if not isinstance(state, dict):
        return None
    registers = state.get("registers")
    if not isinstance(registers, dict):
        return None
    selector_offset = registers.get("de")
    if (
        not isinstance(selector_offset, int)
        or isinstance(selector_offset, bool)
        or not 0 <= selector_offset <= 0xFFFF
    ):
        return None
    return selector_offset


def _entry_ordinal(local_capture: dict[str, object]) -> int | None:
    state = local_capture.get("entry_selector_hit")
    if not isinstance(state, dict):
        return None
    registers = state.get("registers")
    if not isinstance(registers, dict):
        return None
    bc = registers.get("bc")
    if (
        not isinstance(bc, int)
        or isinstance(bc, bool)
        or not 0 <= bc <= 0xFFFF
    ):
        return None
    return bc >> 8


def _static_entry_selector_offset(
    baseline_rom: bytes,
    target_address: int,
) -> int | None:
    if not 0x4000 <= target_address <= 0x7FFF:
        return None
    pointers = [
        int.from_bytes(
            baseline_rom[offset : offset + 2],
            "little",
        )
        for offset in range(LOOKUP_TABLE_BASE, 0x4000, 2)
        if offset + 2 <= len(baseline_rom)
    ]
    starts = sorted({pointer for pointer in pointers if 0x4000 <= pointer <= 0x7FFF})
    start = max(
        (pointer for pointer in starts if pointer <= target_address),
        default=None,
    )
    end = min(
        (pointer for pointer in starts if pointer > target_address),
        default=None,
    )
    if start is None or end is None:
        return None
    index = pointers.index(start)
    return index * 2


def _build_entry_selector_observation(
    *,
    baseline_local: dict[str, object],
    test_local: dict[str, object],
    baseline_rom: bytes,
    target_read: dict[str, object],
) -> dict[str, object] | None:
    if (
        int(target_read.get("instruction_bank", -1)) != 0
        or int(target_read.get("instruction_pc", -1)) != 0x3406
        or int(target_read.get("slot", -1)) != 1
    ):
        return None
    baseline_offset = _entry_selector_offset(baseline_local)
    test_offset = _entry_selector_offset(test_local)
    baseline_ordinal = _entry_ordinal(baseline_local)
    test_ordinal = _entry_ordinal(test_local)
    selectors_match = (
        baseline_offset is not None and baseline_offset == test_offset
    )
    ordinals_match = (
        baseline_ordinal is not None and baseline_ordinal == test_ordinal
    )
    unresolved: dict[str, object] = {
        "status": "unresolved",
        "lookup_table_base": LOOKUP_TABLE_BASE,
        "baseline_selector_offset": baseline_offset,
        "test_selector_offset": test_offset,
        "selectors_match": selectors_match,
        "baseline_entry_ordinal": baseline_ordinal,
        "test_entry_ordinal": test_ordinal,
        "ordinals_match": ordinals_match,
        "entry_index": None,
        "pointer_address": None,
        "next_pointer_address": None,
        "target_offset_within_entry": None,
        "pointer_bounds_target": False,
    }
    if (
        not selectors_match
        or not ordinals_match
        or not isinstance(baseline_offset, int)
        or not 0 <= baseline_offset <= 0x16
        or baseline_offset % 2
    ):
        return unresolved
    selector_offset = baseline_offset
    lookup_table_base = LOOKUP_TABLE_BASE
    pointer_offset = lookup_table_base + selector_offset
    if pointer_offset + 4 > min(len(baseline_rom), 0x4000):
        return unresolved
    pointer_address = int.from_bytes(
        baseline_rom[pointer_offset : pointer_offset + 2],
        "little",
    )
    expected_address = int(target_read["logical_access"])
    next_pointer_offset = pointer_offset + 2
    next_pointer_address = int.from_bytes(
        baseline_rom[next_pointer_offset : next_pointer_offset + 2],
        "little",
    )
    if not (
        0x4000 <= pointer_address <= expected_address <= 0x7FFF
        and 0 <= next_pointer_address <= 0xFFFF
    ):
        return unresolved
    return {
        "status": "resolved",
        "lookup_table_base": lookup_table_base,
        "baseline_selector_offset": selector_offset,
        "test_selector_offset": selector_offset,
        "selectors_match": True,
        "baseline_entry_ordinal": baseline_ordinal,
        "test_entry_ordinal": test_ordinal,
        "ordinals_match": True,
        "entry_index": selector_offset // 2,
        "pointer_address": pointer_address,
        "next_pointer_address": next_pointer_address,
        "target_offset_within_entry": expected_address - pointer_address,
        "pointer_bounds_target": True,
    }


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
    expected_selector_offset: int | None,
    evidence_dir: Path,
    failure_stage: str,
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
    entry_breakpoint_armed = False

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

    def arm_entry_breakpoint() -> None:
        nonlocal entry_breakpoint_armed
        client.call(
            "set_breakpoint_range",
            {
                "start_address": f"{DECODER_ENTRY_LOGICAL:04X}",
                "end_address": f"{DECODER_ENTRY_LOGICAL:04X}",
                "memory_area": "rom_ram",
                "execute": True,
                "read": False,
                "write": False,
            },
        )
        entry_breakpoint_armed = True

    def disarm_entry_breakpoint() -> None:
        nonlocal entry_breakpoint_armed
        client.call(
            "remove_breakpoint",
            {
                "address": f"{DECODER_ENTRY_LOGICAL:04X}",
                "end_address": f"{DECODER_ENTRY_LOGICAL:04X}",
                "memory_area": "rom_ram",
            },
        )
        entry_breakpoint_armed = False

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
        if expected_selector_offset is not None:
            arm_entry_breakpoint()
        target_found = False
        entry_selector_confirmed = expected_selector_offset is None
        local["entry_selector_hits"] = []
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
                if (
                    entry_breakpoint_armed
                    and pc_after == DECODER_ENTRY_LOGICAL
                ):
                    registers = state.get("registers")
                    selector_offset = (
                        registers.get("de")
                        if isinstance(registers, dict)
                        else None
                    )
                    local["entry_selector_hits"].append(
                        {
                            "selector_offset": selector_offset,
                            "pc_after": pc_after,
                        }
                    )
                    if selector_offset == expected_selector_offset:
                        local["entry_selector_hit"] = state
                        local["entry_selector_hit_evidence"] = hit_evidence
                        entry_selector_confirmed = True
                        disarm_entry_breakpoint()
                    else:
                        disarm_entry_breakpoint()
                        _step_instruction_and_wait(client)
                        arm_entry_breakpoint()
                    continue
                if (
                    entry_selector_confirmed
                    and _target_hit_matches(state, target_read)
                ):
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
        if entry_breakpoint_armed:
            disarm_entry_breakpoint()

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
    except Exception as error:
        receipt = _runtime_failure_receipt(failure_stage, error, client)
        _write_runtime_failure_receipt(
            Path(__file__).resolve().parents[1],
            receipt,
        )
        raise
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
        if entry_breakpoint_armed:
            try:
                client.call(
                    "remove_breakpoint",
                    {
                        "address": f"{DECODER_ENTRY_LOGICAL:04X}",
                        "end_address": f"{DECODER_ENTRY_LOGICAL:04X}",
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
    global _CURRENT_FAILURE_STAGE
    _CURRENT_FAILURE_STAGE = "display-capture-preflight"
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
    review_dir = _absolute(root, DEFAULT_REVIEW_DIR)
    _require_within(
        review_dir,
        root / "reports",
        "human review bundle",
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
        built_entry = build_report.get("runtime_entry")
        if (
            isinstance(built_entry, dict)
            and str(built_entry.get("kind", "")).startswith(
                "runtime-group-"
            )
        ):
            selected_entry_probe = built_entry.get("kind") in {
                "runtime-group-selected-entry-candidate",
                "runtime-group-observed-entry",
            }
            logical_access = int(
                built_entry["pointer_address"]
                if selected_entry_probe
                else built_entry[
                    "intermediate_observed_target_logical_address"
                ]
            )
            expected_bank = int(built_entry["pointer_bank"])
            physical_target_byte = int(
                built_entry["target_file_offset"]
                if selected_entry_probe
                else built_entry[
                    "intermediate_observed_target_file_offset"
                ]
            )
            instruction_bank = int(
                built_entry["runtime_instruction_bank"]
            )
            instruction_pc = int(built_entry["runtime_instruction_pc"])
        else:
            logical_access = int(selected["logical_start"])
            expected_bank = int(selected["mapped_bank"])
            physical_target_byte = int(selected["physical_start"])
            instruction_bank = int(selected["instruction_bank"])
            instruction_pc = int(selected["instruction_pc"])
        resolution = {
            "target_read": {
                "slot": logical_access // 0x4000,
                "logical_access": logical_access,
                "physical_target_byte": physical_target_byte,
                "instruction_bank": instruction_bank,
                "instruction_pc": instruction_pc,
                "pc_after": instruction_pc + 1,
                "physical_pc_after": instruction_pc + 1,
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

    baseline_rom = baseline_rom_path.read_bytes()
    built_entry = build_report.get("runtime_entry")
    if (
        isinstance(built_entry, dict)
        and str(built_entry.get("kind", "")).startswith("runtime-group-")
    ):
        group_pointer_address = int(
            built_entry["group_pointer_address"]
        )
        exact_selector_offsets = [
            offset
            for offset in range(0, 0x18, 2)
            if int.from_bytes(
                baseline_rom[
                    LOOKUP_TABLE_BASE
                    + offset : LOOKUP_TABLE_BASE
                    + offset
                    + 2
                ],
                "little",
            )
            == group_pointer_address
        ]
        if len(exact_selector_offsets) != 1:
            raise PatchError(
                "runtime group pointer does not select one lookup anchor"
            )
        expected_selector_offset = exact_selector_offsets[0]
    else:
        expected_selector_offset = _static_entry_selector_offset(
            baseline_rom,
            int(resolution["target_read"]["logical_access"]),
        )
    _CURRENT_FAILURE_STAGE = "baseline-display-capture"
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
        expected_selector_offset=expected_selector_offset,
        evidence_dir=evidence_dir / "baseline",
        failure_stage="baseline-display-capture",
        schedule=capture_schedule,
    )
    _CURRENT_FAILURE_STAGE = "test-display-capture"
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
        expected_selector_offset=expected_selector_offset,
        evidence_dir=evidence_dir / "test",
        failure_stage="test-display-capture",
        schedule=capture_schedule,
    )
    _CURRENT_FAILURE_STAGE = "display-version-check"
    if baseline_emulator_version != emulator_version:
        raise PatchError("baseline and test captures used different emulator versions")
    _CURRENT_FAILURE_STAGE = "display-pixel-comparison"
    frame_comparisons, post_comparison = _paired_pixel_comparisons(
        baseline_local,
        test_local,
    )
    _CURRENT_FAILURE_STAGE = "display-comparison-artifact"
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
    entry_selector = _build_entry_selector_observation(
        baseline_local=baseline_local,
        test_local=test_local,
        baseline_rom=baseline_rom,
        target_read=resolution["target_read"],
    )
    group_entry = None
    if (
        isinstance(entry_selector, dict)
        and entry_selector.get("status") == "resolved"
        and isinstance(entry_selector.get("baseline_selector_offset"), int)
        and isinstance(entry_selector.get("baseline_entry_ordinal"), int)
    ):
        try:
            group_entry = resolve_group_entry(
                baseline_rom,
                selector_offset=int(
                    entry_selector["baseline_selector_offset"]
                ),
                entry_ordinal=int(entry_selector["baseline_entry_ordinal"]),
                target_logical_byte=int(
                    resolution["target_read"]["logical_access"]
                ),
                mapped_bank=int(resolution["target_read"]["expected_bank"]),
            )
        except PatchError:
            group_entry = None
    _write_human_review_bundle(
        comparison,
        baseline_local=baseline_local,
        test_local=test_local,
        review_dir=review_dir,
    )
    _write_bytes_atomic(
        root / "reports" / "NEXT_STEP.txt",
        _next_step_text(
            comparison,
            evidence_dir=evidence_dir,
            root=root,
        ).encode("utf-8"),
    )
    _CURRENT_FAILURE_STAGE = "display-capture-artifact"
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
    _CURRENT_FAILURE_STAGE = "display-capture-local-artifact"
    try:
        _write_json(local_report_path, local)
    except (OSError, TypeError, ValueError):
        pass
    _CURRENT_FAILURE_STAGE = "display-capture-safe-schema"
    safe = _build_safe_capture(
        build_report=build_report,
        resolution=resolution,
        emulator_version=emulator_version,
        mapped_bank=mapped_bank,
        captures=captures,
        post_advance_capture=post_advance_capture,
        entry_selector=entry_selector,
        group_entry=group_entry,
    )
    _CURRENT_FAILURE_STAGE = "display-capture-safe-publish"
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


def _guarded_main() -> int:
    try:
        return main()
    except Exception as error:
        root = Path(__file__).resolve().parents[1]
        failure_path = root / LOCAL_FAILURE_REPORT
        keep_existing = False
        try:
            existing = json.loads(failure_path.read_text(encoding="utf-8"))
            if not isinstance(existing, dict):
                raise ValueError("runtime failure receipt must be an object")
            validate_runtime_failure_receipt(existing)
            keep_existing = True
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        if not keep_existing:
            receipt = _runtime_failure_receipt(
                _CURRENT_FAILURE_STAGE,
                error,
                None,
            )
            _write_runtime_failure_receipt(root, receipt)
        raise


if __name__ == "__main__":
    raise SystemExit(_guarded_main())
