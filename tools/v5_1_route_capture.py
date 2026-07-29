#!/usr/bin/env python3
"""Validate and write a ROM-free, image-free story-route observation."""

from __future__ import annotations

import json
from pathlib import Path
import re

ARTIFACT_KIND = "sanitized-story-route-capture"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_route_capture.json"
)

TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "target_sha256",
    "status",
    "probe",
    "captures",
    "distinct_frame_count",
    "stable_tail",
    "route_state_verified",
    "translation_build_eligible",
    "next_checkpoint",
}
PROBE_KEYS = {
    "emulator",
    "emulator_version",
    "system",
    "route",
    "frame_budget",
}
CAPTURE_KEYS = {
    "stage",
    "frame_total",
    "input_count",
    "width",
    "height",
    "png_sha256",
}
EXPECTED_STAGES = (
    "boot-idle",
    "post-start",
    "confirm-01",
    "confirm-04",
    "confirm-16",
)


def _require_token(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 80
        or "/" in value
        or "\\" in value
    ):
        raise ValueError(f"{label} must be a short path-free token")


def _require_int(
    value: object,
    label: str,
    minimum: int = 0,
    maximum: int | None = None,
) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{label} must be <= {maximum}")


def validate_route_capture(observation: dict[str, object]) -> None:
    if set(observation) != TOP_LEVEL_KEYS:
        raise ValueError("route capture top-level fields do not match")
    if observation["artifact_kind"] != ARTIFACT_KIND:
        raise ValueError("unexpected route capture artifact")
    if observation["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unexpected route capture schema")
    target_sha256 = observation["target_sha256"]
    if (
        not isinstance(target_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", target_sha256) is None
    ):
        raise ValueError("target_sha256 must be a lowercase SHA-256")
    for key in ("status", "next_checkpoint"):
        _require_token(observation[key], key)
    for key in (
        "stable_tail",
        "route_state_verified",
        "translation_build_eligible",
    ):
        if not isinstance(observation[key], bool):
            raise ValueError(f"{key} must be a boolean")
    if observation["route_state_verified"]:
        raise ValueError("image hashes cannot verify a semantic route state")
    if observation["translation_build_eligible"]:
        raise ValueError("route capture cannot enable translation builds")

    probe = observation["probe"]
    if not isinstance(probe, dict) or set(probe) != PROBE_KEYS:
        raise ValueError("route capture probe fields do not match")
    for key in ("emulator", "emulator_version", "system", "route"):
        _require_token(probe[key], f"probe.{key}")
    if probe["system"] != "gamegear":
        raise ValueError("route capture system must be gamegear")
    _require_int(probe["frame_budget"], "probe.frame_budget", 1, 100_000)

    captures = observation["captures"]
    if not isinstance(captures, list) or len(captures) != len(EXPECTED_STAGES):
        raise ValueError("route capture must contain the five fixed stages")
    actual_stages: list[str] = []
    previous_frame = -1
    previous_inputs = -1
    hashes: list[str] = []
    for index, capture in enumerate(captures):
        if not isinstance(capture, dict) or set(capture) != CAPTURE_KEYS:
            raise ValueError(f"captures[{index}] fields do not match")
        _require_token(capture["stage"], f"captures[{index}].stage")
        actual_stages.append(capture["stage"])
        _require_int(
            capture["frame_total"],
            f"captures[{index}].frame_total",
            previous_frame + 1,
            100_000,
        )
        _require_int(
            capture["input_count"],
            f"captures[{index}].input_count",
            previous_inputs,
            64,
        )
        previous_frame = capture["frame_total"]
        previous_inputs = capture["input_count"]
        _require_int(capture["width"], f"captures[{index}].width", 1, 1024)
        _require_int(capture["height"], f"captures[{index}].height", 1, 1024)
        png_sha256 = capture["png_sha256"]
        if (
            not isinstance(png_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", png_sha256) is None
        ):
            raise ValueError(f"captures[{index}].png_sha256 is invalid")
        hashes.append(png_sha256)
    if tuple(actual_stages) != EXPECTED_STAGES:
        raise ValueError("route capture stages are not the fixed sequence")
    if probe["frame_budget"] != captures[-1]["frame_total"]:
        raise ValueError("route capture frame budget disagrees with final capture")

    distinct = observation["distinct_frame_count"]
    _require_int(distinct, "distinct_frame_count", 1, len(EXPECTED_STAGES))
    if distinct != len(set(hashes)):
        raise ValueError("distinct_frame_count disagrees with capture hashes")
    stable_tail = hashes[-1] == hashes[-2]
    if observation["stable_tail"] != stable_tail:
        raise ValueError("stable_tail disagrees with capture hashes")
    expected_status = (
        "stable-tail-human-route-review-required"
        if stable_tail
        else "route-frames-captured-human-review-required"
    )
    expected_checkpoint = (
        "human-identify-stable-route-screen"
        if stable_tail
        else "human-identify-route-screen"
    )
    if observation["status"] != expected_status:
        raise ValueError("route capture status disagrees with hashes")
    if observation["next_checkpoint"] != expected_checkpoint:
        raise ValueError("route capture checkpoint disagrees with hashes")


def build_route_capture(
    *,
    target_sha256: str,
    emulator_version: str,
    route: str,
    frame_budget: int,
    captures: list[dict[str, object]],
) -> dict[str, object]:
    hashes = [str(item["png_sha256"]) for item in captures]
    stable_tail = len(hashes) >= 2 and hashes[-1] == hashes[-2]
    observation: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "target_sha256": target_sha256,
        "status": (
            "stable-tail-human-route-review-required"
            if stable_tail
            else "route-frames-captured-human-review-required"
        ),
        "probe": {
            "emulator": "Gearsystem",
            "emulator_version": emulator_version,
            "system": "gamegear",
            "route": route,
            "frame_budget": frame_budget,
        },
        "captures": captures,
        "distinct_frame_count": len(set(hashes)),
        "stable_tail": stable_tail,
        "route_state_verified": False,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "human-identify-stable-route-screen"
            if stable_tail
            else "human-identify-route-screen"
        ),
    }
    validate_route_capture(observation)
    return observation


def write_route_capture(
    root: Path,
    observation: dict[str, object],
) -> Path:
    validate_route_capture(observation)
    path = root / PUBLISH_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(observation, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path

