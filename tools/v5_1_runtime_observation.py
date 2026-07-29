#!/usr/bin/env python3
"""Validate and publish a ROM-free Gearsystem runtime observation."""

from __future__ import annotations

import json
from pathlib import Path
import re

try:
    from .v5_1_safe_observation import _git, _normalized_remote
except ImportError:  # direct script execution
    from v5_1_safe_observation import _git, _normalized_remote

ARTIFACT_KIND = "sanitized-runtime-consumer-observation"
SCHEMA_VERSION = 2
FRAME_SYNC = "debug-status-paused"
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_runtime_observation.json"
)
EXPECTED_REMOTE = "github.com/Domingo8666/ShiningForceKR"
DEFAULT_GIT_NAME = "Domingo8666"
DEFAULT_GIT_EMAIL = "145947995+Domingo8666@users.noreply.github.com"

TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "target_sha256",
    "status",
    "probe",
    "hit",
    "read_hit_observed",
    "consumer_evidence_confirmed",
    "translation_build_eligible",
    "next_checkpoint",
}
PROBE_KEYS = {
    "emulator",
    "emulator_version",
    "system",
    "frame_sync",
    "frames_per_slot",
    "slots_attempted",
    "breakpoint_ranges",
}
RANGE_KEYS = {
    "slot",
    "expected_bank",
    "logical_start",
    "logical_end",
}
HIT_KEYS = {
    "slot",
    "expected_bank",
    "logical_start",
    "logical_end",
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
    value: object, label: str, minimum: int = 0, maximum: int | None = None
) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{label} must be <= {maximum}")


def _require_short_token(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 80
        or "/" in value
        or "\\" in value
    ):
        raise ValueError(f"{label} must be a short path-free token")


def _validate_range(item: object, label: str) -> None:
    if not isinstance(item, dict) or set(item) != RANGE_KEYS:
        raise ValueError(f"{label} fields do not match the safe schema")
    _require_int(item["slot"], f"{label}.slot", 0, 2)
    _require_int(item["expected_bank"], f"{label}.expected_bank", 0, 255)
    _require_int(item["logical_start"], f"{label}.logical_start", 0, 0xFFFF)
    _require_int(item["logical_end"], f"{label}.logical_end", 0, 0xFFFF)
    if item["logical_start"] > item["logical_end"]:
        raise ValueError(f"{label} logical range is reversed")


def validate_runtime_observation(observation: dict[str, object]) -> None:
    """Reject paths, byte dumps, decoded text, traces, and unlisted fields."""

    if set(observation) != TOP_LEVEL_KEYS:
        raise ValueError("runtime observation top-level fields do not match")
    if observation["artifact_kind"] != ARTIFACT_KIND:
        raise ValueError("unexpected artifact kind")
    if observation["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unexpected runtime observation schema")
    target_sha256 = observation["target_sha256"]
    if not isinstance(target_sha256, str) or re.fullmatch(
        r"[0-9a-f]{64}", target_sha256
    ) is None:
        raise ValueError("target_sha256 must be a lowercase SHA-256")
    for key in ("status", "next_checkpoint"):
        _require_short_token(observation[key], key)
    for key in (
        "read_hit_observed",
        "consumer_evidence_confirmed",
        "translation_build_eligible",
    ):
        if not isinstance(observation[key], bool):
            raise ValueError(f"{key} must be a boolean")
    if observation["consumer_evidence_confirmed"]:
        raise ValueError("a first range hit alone cannot confirm the consumer")
    if observation["translation_build_eligible"]:
        raise ValueError("a first range hit cannot enable translation builds")

    probe = observation["probe"]
    if not isinstance(probe, dict) or set(probe) != PROBE_KEYS:
        raise ValueError("probe fields do not match the safe schema")
    for key in ("emulator", "emulator_version", "system", "frame_sync"):
        _require_short_token(probe[key], key)
    if probe["frame_sync"] != FRAME_SYNC:
        raise ValueError("runtime probe did not use the completion barrier")
    _require_int(probe["frames_per_slot"], "frames_per_slot", 1, 100_000)
    slots = probe["slots_attempted"]
    if (
        not isinstance(slots, list)
        or len(slots) > 3
        or any(not isinstance(slot, int) or slot not in (0, 1, 2) for slot in slots)
        or len(set(slots)) != len(slots)
    ):
        raise ValueError("slots_attempted must contain unique slot IDs")
    ranges = probe["breakpoint_ranges"]
    if not isinstance(ranges, list) or len(ranges) > 12:
        raise ValueError("breakpoint_ranges must contain at most twelve ranges")
    for index, item in enumerate(ranges):
        _validate_range(item, f"breakpoint_ranges[{index}]")

    hit = observation["hit"]
    if hit is None:
        if observation["read_hit_observed"]:
            raise ValueError("read_hit_observed requires a hit object")
        if observation["status"] != "runtime-read-hit-not-observed":
            raise ValueError("no-hit status mismatch")
        return
    if not observation["read_hit_observed"]:
        raise ValueError("hit object requires read_hit_observed")
    if observation["status"] != "runtime-read-hit-observed":
        raise ValueError("hit status mismatch")
    if not isinstance(hit, dict) or set(hit) != HIT_KEYS:
        raise ValueError("hit fields do not match the safe schema")
    _validate_range({key: hit[key] for key in RANGE_KEYS}, "hit")
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
        maximum = 0xFFFFFF if key == "physical_pc_after" else None
        if key in {
            "executing_bank",
            "mapper_control",
            "slot0_bank",
            "slot1_bank",
            "slot2_bank",
        }:
            maximum = 255
        if key == "pc_after":
            maximum = 0xFFFF
        _require_int(hit[key], key, 0, maximum)
    registers = hit["registers"]
    if not isinstance(registers, dict) or set(registers) != REGISTER_KEYS:
        raise ValueError("register fields do not match the safe schema")
    for key, value in registers.items():
        _require_int(value, f"register {key}", 0, 0xFFFF)


def build_runtime_observation(
    *,
    target_sha256: str,
    emulator_version: str,
    frames_per_slot: int,
    slots_attempted: list[int],
    breakpoint_ranges: list[dict[str, int]],
    hit: dict[str, object] | None,
) -> dict[str, object]:
    observed = hit is not None
    observation: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "target_sha256": target_sha256,
        "status": (
            "runtime-read-hit-observed"
            if observed
            else "runtime-read-hit-not-observed"
        ),
        "probe": {
            "emulator": "Gearsystem",
            "emulator_version": emulator_version,
            "system": "gamegear",
            "frame_sync": FRAME_SYNC,
            "frames_per_slot": frames_per_slot,
            "slots_attempted": slots_attempted,
            "breakpoint_ranges": breakpoint_ranges,
        },
        "hit": hit,
        "read_hit_observed": observed,
        "consumer_evidence_confirmed": False,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "connect-hit-pc-to-selected-entry-and-bounded-decode"
            if observed
            else "extend-runtime-input-coverage"
        ),
    }
    validate_runtime_observation(observation)
    return observation


def write_runtime_observation(
    root: Path, observation: dict[str, object]
) -> Path:
    validate_runtime_observation(observation)
    path = root.resolve() / PUBLISH_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(observation, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def publish_runtime_observation(
    root: Path, observation_path: Path
) -> dict[str, object]:
    """Commit only the fixed, validated ROM-free runtime observation."""

    root = root.resolve()
    expected = root / PUBLISH_RELATIVE_PATH
    actual = observation_path.resolve()
    if actual != expected:
        raise ValueError(f"runtime observation path must be {expected}")
    observation = json.loads(actual.read_text(encoding="utf-8"))
    if not isinstance(observation, dict):
        raise ValueError("runtime observation must be a JSON object")
    validate_runtime_observation(observation)

    top = Path(_git(root, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    if top != root:
        raise ValueError("repository root does not match the requested root")
    branch = _git(root, "branch", "--show-current").stdout.strip()
    if branch != "main":
        raise ValueError("runtime observation may only be published from main")
    remote = _normalized_remote(_git(root, "remote", "get-url", "origin").stdout)
    if EXPECTED_REMOTE not in remote:
        raise ValueError("origin is not the canonical ShiningForceKR repository")

    relative = str(PUBLISH_RELATIVE_PATH).replace("\\", "/")
    porcelain = _git(root, "status", "--porcelain").stdout.splitlines()
    unrelated = [
        line
        for line in porcelain
        if line[3:].replace("\\", "/") != relative
    ]
    if unrelated:
        raise ValueError("refusing to publish with unrelated working tree changes")
    changed = any(
        line[3:].replace("\\", "/") == relative for line in porcelain
    )
    if changed:
        if not _git(root, "config", "user.name").stdout.strip():
            _git(root, "config", "user.name", DEFAULT_GIT_NAME)
        if not _git(root, "config", "user.email").stdout.strip():
            _git(root, "config", "user.email", DEFAULT_GIT_EMAIL)
        _git(root, "add", "--", relative)
        _git(
            root,
            "commit",
            "-m",
            "Record sanitized S25U runtime observation",
            "--",
            relative,
        )
    _git(root, "push", "origin", "HEAD:main")
    return {
        "changed": changed,
        "commit": _git(root, "rev-parse", "HEAD").stdout.strip(),
        "path": relative,
    }
