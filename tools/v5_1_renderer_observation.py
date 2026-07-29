#!/usr/bin/env python3
"""Validate and write a ROM-free Korean renderer-hook observation."""

from __future__ import annotations

import json
from pathlib import Path
import re

ARTIFACT_KIND = "sanitized-renderer-hook-observation"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_renderer_observation.json"
)

TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "target_sha256",
    "status",
    "probe",
    "hit",
    "renderer_hook_reached",
    "translation_build_eligible",
    "next_checkpoint",
}
PROBE_KEYS = {
    "emulator",
    "emulator_version",
    "system",
    "frames_per_mapping",
    "mappings_attempted",
}
MAPPING_KEYS = {
    "call_site_file_offset",
    "slot",
    "expected_bank",
    "logical_address",
}
HIT_KEYS = MAPPING_KEYS | {
    "pc_after",
    "physical_pc_after",
    "executing_bank",
    "mapper_control",
    "slot0_bank",
    "slot1_bank",
    "slot2_bank",
    "registers",
    "trace_entries",
    "call_stack_depth",
}
REGISTER_KEYS = {
    "af",
    "bc",
    "de",
    "hl",
    "ix",
    "iy",
    "sp",
}


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


def _require_token(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 80
        or "/" in value
        or "\\" in value
    ):
        raise ValueError(f"{label} must be a short path-free token")


def _validate_mapping(value: object, label: str) -> None:
    if not isinstance(value, dict) or set(value) != MAPPING_KEYS:
        raise ValueError(f"{label} fields do not match the safe schema")
    _require_int(
        value["call_site_file_offset"],
        f"{label}.call_site_file_offset",
        0,
        0xFFFFFF,
    )
    _require_int(value["slot"], f"{label}.slot", 0, 2)
    _require_int(value["expected_bank"], f"{label}.expected_bank", 0, 255)
    _require_int(
        value["logical_address"],
        f"{label}.logical_address",
        0,
        0xFFFF,
    )


def validate_renderer_observation(
    observation: dict[str, object],
) -> None:
    if set(observation) != TOP_LEVEL_KEYS:
        raise ValueError("renderer observation top-level fields do not match")
    if observation["artifact_kind"] != ARTIFACT_KIND:
        raise ValueError("unexpected renderer observation artifact")
    if observation["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unexpected renderer observation schema")
    target_sha256 = observation["target_sha256"]
    if (
        not isinstance(target_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", target_sha256) is None
    ):
        raise ValueError("target_sha256 must be a lowercase SHA-256")
    for key in ("status", "next_checkpoint"):
        _require_token(observation[key], key)
    for key in ("renderer_hook_reached", "translation_build_eligible"):
        if not isinstance(observation[key], bool):
            raise ValueError(f"{key} must be a boolean")
    if observation["translation_build_eligible"]:
        raise ValueError("a renderer hook alone cannot enable translation builds")

    probe = observation["probe"]
    if not isinstance(probe, dict) or set(probe) != PROBE_KEYS:
        raise ValueError("renderer probe fields do not match")
    for key in ("emulator", "emulator_version", "system"):
        _require_token(probe[key], key)
    _require_int(probe["frames_per_mapping"], "frames_per_mapping", 1, 100_000)
    mappings = probe["mappings_attempted"]
    if not isinstance(mappings, list) or len(mappings) > 6:
        raise ValueError("mappings_attempted must contain at most six mappings")
    for index, mapping in enumerate(mappings):
        _validate_mapping(mapping, f"mappings_attempted[{index}]")

    hit = observation["hit"]
    if hit is None:
        if observation["renderer_hook_reached"]:
            raise ValueError("renderer_hook_reached requires a hit")
        if observation["status"] != "renderer-hook-not-observed":
            raise ValueError("renderer no-hit status mismatch")
        return
    if observation["renderer_hook_reached"] is not True:
        raise ValueError("renderer hit requires renderer_hook_reached")
    if observation["status"] != "renderer-hook-observed":
        raise ValueError("renderer hit status mismatch")
    if not isinstance(hit, dict) or set(hit) != HIT_KEYS:
        raise ValueError("renderer hit fields do not match")
    _validate_mapping({key: hit[key] for key in MAPPING_KEYS}, "hit")
    for key in (
        "pc_after",
        "physical_pc_after",
        "executing_bank",
        "mapper_control",
        "slot0_bank",
        "slot1_bank",
        "slot2_bank",
        "trace_entries",
        "call_stack_depth",
    ):
        maximum = 0xFFFFFF if key == "physical_pc_after" else 0xFFFF
        if key in {
            "executing_bank",
            "mapper_control",
            "slot0_bank",
            "slot1_bank",
            "slot2_bank",
        }:
            maximum = 255
        _require_int(hit[key], key, 0, maximum)
    registers = hit["registers"]
    if not isinstance(registers, dict) or set(registers) != REGISTER_KEYS:
        raise ValueError("renderer register fields do not match")
    for key, value in registers.items():
        _require_int(value, f"register {key}", 0, 0xFFFF)


def build_renderer_observation(
    *,
    target_sha256: str,
    emulator_version: str,
    frames_per_mapping: int,
    mappings_attempted: list[dict[str, int]],
    hit: dict[str, object] | None,
) -> dict[str, object]:
    observed = hit is not None
    observation: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "target_sha256": target_sha256,
        "status": (
            "renderer-hook-observed"
            if observed
            else "renderer-hook-not-observed"
        ),
        "probe": {
            "emulator": "Gearsystem",
            "emulator_version": emulator_version,
            "system": "gamegear",
            "frames_per_mapping": frames_per_mapping,
            "mappings_attempted": mappings_attempted,
        },
        "hit": hit,
        "renderer_hook_reached": observed,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "resolve-pre-hook-script-state"
            if observed
            else "extend-renderer-input-coverage"
        ),
    }
    validate_renderer_observation(observation)
    return observation


def write_renderer_observation(
    root: Path,
    observation: dict[str, object],
) -> Path:
    validate_renderer_observation(observation)
    path = root.resolve() / PUBLISH_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(observation, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path
