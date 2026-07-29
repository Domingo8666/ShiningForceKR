#!/usr/bin/env python3
"""Validate and write a ROM-free Korean text-engine observation."""

from __future__ import annotations

import json
from pathlib import Path
import re

ARTIFACT_KIND = "sanitized-text-engine-observation"
SCHEMA_VERSION = 4
FRAME_SYNC = "debug-status-paused"
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
    "decoder_reads",
    "renderer_hook_reached",
    "text_decoder_reached",
    "translation_build_eligible",
    "next_checkpoint",
}
PROBE_KEYS = {
    "emulator",
    "emulator_version",
    "system",
    "frame_sync",
    "route",
    "anchor_kind",
    "frame_budget",
    "mappings_attempted",
}
MAPPING_KEYS = {
    "probe_file_offset",
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
DECODER_READ_KEYS = {
    "slot",
    "logical_access",
    "physical_file_offset",
    "mapped_bank",
    "instruction_bank",
    "instruction_pc",
    "pc_after",
    "physical_pc_after",
    "classification",
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
        value["probe_file_offset"],
        f"{label}.probe_file_offset",
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
    for key in (
        "renderer_hook_reached",
        "text_decoder_reached",
        "translation_build_eligible",
    ):
        if not isinstance(observation[key], bool):
            raise ValueError(f"{key} must be a boolean")
    if observation["renderer_hook_reached"]:
        raise ValueError("decoder-entry observation cannot prove renderer hook reach")
    if observation["translation_build_eligible"]:
        raise ValueError("a text-engine observation cannot enable translation builds")

    probe = observation["probe"]
    if not isinstance(probe, dict) or set(probe) != PROBE_KEYS:
        raise ValueError("renderer probe fields do not match")
    for key in (
        "emulator",
        "emulator_version",
        "system",
        "frame_sync",
        "route",
        "anchor_kind",
    ):
        _require_token(probe[key], key)
    if probe["frame_sync"] != FRAME_SYNC:
        raise ValueError("renderer probe did not use the completion barrier")
    if probe["anchor_kind"] not in {
        "text-decoder-entry",
        "huffman-vector-read",
    }:
        raise ValueError("unexpected text-engine probe anchor")
    _require_int(probe["frame_budget"], "frame_budget", 1, 100_000)
    mappings = probe["mappings_attempted"]
    if not isinstance(mappings, list) or len(mappings) > 6:
        raise ValueError("mappings_attempted must contain at most six mappings")
    for index, mapping in enumerate(mappings):
        _validate_mapping(mapping, f"mappings_attempted[{index}]")
    vector_anchor = probe["anchor_kind"] == "huffman-vector-read"
    if vector_anchor:
        expected_mappings = {
            (0x80100, 1, 0x20, 0x4100),
            (0x80100, 2, 0x20, 0x8100),
        }
        actual_mappings = {
            (
                item["probe_file_offset"],
                item["slot"],
                item["expected_bank"],
                item["logical_address"],
            )
            for item in mappings
        }
        if actual_mappings != expected_mappings:
            raise ValueError("Huffman-vector probe mappings do not match")

    reads = observation["decoder_reads"]
    if not isinstance(reads, list) or len(reads) > 64:
        raise ValueError("decoder_reads must contain at most 64 samples")
    for index, item in enumerate(reads):
        if not isinstance(item, dict) or set(item) != DECODER_READ_KEYS:
            raise ValueError(f"decoder_reads[{index}] fields do not match")
        _require_int(item["slot"], f"decoder_reads[{index}].slot", 1, 2)
        _require_int(
            item["logical_access"],
            f"decoder_reads[{index}].logical_access",
            0x4000,
            0xBFFF,
        )
        if item["logical_access"] // 0x4000 != item["slot"]:
            raise ValueError("decoder read logical address and slot disagree")
        _require_int(
            item["physical_file_offset"],
            f"decoder_reads[{index}].physical_file_offset",
            0,
            0x17BFFF,
        )
        _require_int(
            item["mapped_bank"],
            f"decoder_reads[{index}].mapped_bank",
            0,
            0x5E,
        )
        expected_physical = (
            item["mapped_bank"] * 0x4000
            + (item["logical_access"] & 0x3FFF)
        )
        if item["physical_file_offset"] != expected_physical:
            raise ValueError("decoder read physical address and mapper bank disagree")
        for key in ("instruction_bank", "instruction_pc", "pc_after"):
            _require_int(item[key], f"decoder_reads[{index}].{key}", 0, 0xFFFF)
        _require_int(
            item["physical_pc_after"],
            f"decoder_reads[{index}].physical_pc_after",
            0,
            0x17BFFF,
        )
        _require_token(
            item["classification"],
            f"decoder_reads[{index}].classification",
        )

    hit = observation["hit"]
    if hit is None:
        if observation["text_decoder_reached"]:
            raise ValueError("text_decoder_reached requires a hit")
        if reads:
            raise ValueError("decoder reads require a decoder-entry hit")
        if observation["status"] != "text-decoder-not-observed":
            raise ValueError("text decoder no-hit status mismatch")
        return
    if observation["text_decoder_reached"] is not True:
        raise ValueError("decoder hit requires text_decoder_reached")
    if observation["status"] != "text-decoder-observed":
        raise ValueError("text decoder hit status mismatch")
    if not isinstance(hit, dict) or set(hit) != HIT_KEYS:
        raise ValueError("renderer hit fields do not match")
    _validate_mapping({key: hit[key] for key in MAPPING_KEYS}, "hit")
    if vector_anchor:
        logical_access = hit["logical_address"]
        physical_file_offset = hit["probe_file_offset"]
        mapped_bank = hit["expected_bank"]
        if (
            hit["slot"] not in {1, 2}
            or mapped_bank != 0x20
            or not (
                hit["slot"] * 0x4000 + 0x0100
                <= logical_access
                <= hit["slot"] * 0x4000 + 0x02FF
            )
            or physical_file_offset
            != mapped_bank * 0x4000 + (logical_access & 0x3FFF)
            or not 0x80100 <= physical_file_offset <= 0x802FF
        ):
            raise ValueError("Huffman-vector hit does not match mapper evidence")
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
    route: str,
    anchor_kind: str,
    frame_budget: int,
    mappings_attempted: list[dict[str, int]],
    hit: dict[str, object] | None,
    decoder_reads: list[dict[str, object]],
) -> dict[str, object]:
    observed = hit is not None
    observation: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "target_sha256": target_sha256,
        "status": (
            "text-decoder-observed"
            if observed
            else "text-decoder-not-observed"
        ),
        "probe": {
            "emulator": "Gearsystem",
            "emulator_version": emulator_version,
            "system": "gamegear",
            "frame_sync": FRAME_SYNC,
            "route": route,
            "anchor_kind": anchor_kind,
            "frame_budget": frame_budget,
            "mappings_attempted": mappings_attempted,
        },
        "hit": hit,
        "decoder_reads": decoder_reads,
        "renderer_hook_reached": False,
        "text_decoder_reached": observed,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "resolve-decoder-rom-reads"
            if observed and decoder_reads
            else "extend-decoder-read-capture"
            if observed
            else "extend-story-route-or-resolve-decoder-entry"
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
