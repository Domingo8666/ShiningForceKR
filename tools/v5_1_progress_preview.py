#!/usr/bin/env python3
"""Publish one build-bound S25U screenshot for automatic progress reports."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile


ARTIFACT_KIND = "sanitized-s25u-progress-preview"
SCHEMA_VERSION = 1
PUBLISH_RECEIPT_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_progress_preview.json"
)
PUBLISH_IMAGE_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_progress_preview.png"
)
RECEIPT_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "purpose",
    "baseline_target_sha256",
    "test_target_sha256",
    "capture_png_sha256",
    "preview_png_sha256",
    "width",
    "height",
    "frame_after_hit",
    "auto_continue",
    "human_review_required",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _png_metadata(data: bytes) -> tuple[int, int, str]:
    if (
        len(data) < 24
        or data[:8] != b"\x89PNG\r\n\x1a\n"
        or data[12:16] != b"IHDR"
    ):
        raise ValueError("progress preview is not a PNG")
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    if not 1 <= width <= 1024 or not 1 <= height <= 1024:
        raise ValueError("progress preview dimensions are invalid")
    return width, height, hashlib.sha256(data).hexdigest()


def validate_progress_preview(receipt: dict[str, object]) -> None:
    if set(receipt) != RECEIPT_KEYS:
        raise ValueError("progress preview receipt fields do not match")
    if (
        receipt["artifact_kind"] != ARTIFACT_KIND
        or receipt["schema_version"] != SCHEMA_VERSION
        or receipt["status"] != "progress-preview-ready"
        or receipt["purpose"] != "technical-poc-progress-report"
        or receipt["auto_continue"] is not True
        or receipt["human_review_required"] is not True
        or receipt["next_checkpoint"]
        != "human-confirm-first-korean-glyphs-and-ui"
    ):
        raise ValueError("progress preview receipt policy is invalid")
    if not all(
        _is_sha256(receipt[key])
        for key in (
            "baseline_target_sha256",
            "test_target_sha256",
            "capture_png_sha256",
            "preview_png_sha256",
        )
    ):
        raise ValueError("progress preview identities are invalid")
    if receipt["capture_png_sha256"] != receipt["preview_png_sha256"]:
        raise ValueError("progress preview PNG identity is not exact")
    for key in ("width", "height", "frame_after_hit"):
        value = receipt[key]
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value <= 0
        ):
            raise ValueError(f"progress preview {key} is invalid")
    if int(receipt["width"]) > 1024 or int(receipt["height"]) > 1024:
        raise ValueError("progress preview dimensions are too large")


def load_validated_progress_image(
    root: Path,
    receipt: dict[str, object],
) -> Path:
    validate_progress_preview(receipt)
    image_path = (root / PUBLISH_IMAGE_RELATIVE_PATH).resolve()
    try:
        image_path.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError("progress preview path escaped the repository") from error
    data = image_path.read_bytes()
    width, height, digest = _png_metadata(data)
    if (
        width != receipt["width"]
        or height != receipt["height"]
        or digest != receipt["preview_png_sha256"]
    ):
        raise ValueError("progress preview PNG and receipt disagree")
    return image_path


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


def _write_json_atomic(path: Path, value: dict[str, object]) -> None:
    rendered = (
        json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    _write_bytes_atomic(path, rendered)


def write_progress_preview(
    root: Path,
    safe_capture: dict[str, object],
    local_capture: dict[str, object],
) -> dict[str, object] | None:
    """Copy the latest pre-advance test frame into the safe progress channel."""

    if safe_capture.get("status") != "capture-ready-human-review-required":
        return None
    safe_frames = safe_capture.get("captures")
    local_frames = local_capture.get("captures")
    if not isinstance(safe_frames, list) or not safe_frames:
        return None
    if not isinstance(local_frames, list):
        raise ValueError("local progress capture list is missing")
    safe_frame = max(
        safe_frames,
        key=lambda item: int(item["frame_after_hit"]),
    )
    local_frame = next(
        (
            item
            for item in local_frames
            if item.get("frame_after_hit") == safe_frame["frame_after_hit"]
            and item.get("png_sha256") == safe_frame["png_sha256"]
        ),
        None,
    )
    if not isinstance(local_frame, dict) or not isinstance(
        local_frame.get("file"), str
    ):
        raise ValueError("matching local progress frame is missing")

    root = root.resolve()
    source = Path(str(local_frame["file"])).resolve()
    evidence_root = (root / "evidence" / "local").resolve()
    try:
        source.relative_to(evidence_root)
    except ValueError as error:
        raise ValueError("progress source must stay in local evidence") from error
    data = source.read_bytes()
    width, height, digest = _png_metadata(data)
    if (
        width != safe_frame["width"]
        or height != safe_frame["height"]
        or digest != safe_frame["png_sha256"]
    ):
        raise ValueError("local progress frame and safe capture disagree")

    receipt: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": "progress-preview-ready",
        "purpose": "technical-poc-progress-report",
        "baseline_target_sha256": safe_capture["baseline_target_sha256"],
        "test_target_sha256": safe_capture["test_target_sha256"],
        "capture_png_sha256": digest,
        "preview_png_sha256": digest,
        "width": width,
        "height": height,
        "frame_after_hit": int(safe_frame["frame_after_hit"]),
        "auto_continue": True,
        "human_review_required": True,
        "next_checkpoint": "human-confirm-first-korean-glyphs-and-ui",
    }
    validate_progress_preview(receipt)
    _write_bytes_atomic(root / PUBLISH_IMAGE_RELATIVE_PATH, data)
    _write_json_atomic(root / PUBLISH_RECEIPT_RELATIVE_PATH, receipt)
    return receipt
