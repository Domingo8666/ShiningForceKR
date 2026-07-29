#!/usr/bin/env python3
"""Validate sanitized human review of an S25U test-display capture."""

from __future__ import annotations

import json
from pathlib import Path
import re


ARTIFACT_KIND = "sanitized-s25u-test-display-review"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_display_review.json"
)
RESULTS = {
    "phrase-visible-pass",
    "phrase-absent-fail",
    "ambiguous",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "baseline_target_sha256",
    "test_target_sha256",
    "capture_png_sha256s",
    "reviewed_stream",
    "rejected_physical_starts",
    "result",
    "observations",
    "translation_build_eligible",
    "next_checkpoint",
}
OBSERVATION_KEYS = {
    "test_phrase_visible",
    "surrounding_text_readable",
    "portrait_intact",
    "dialogue_box_intact",
    "post_advance_cleared",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def validate_display_review(review: dict[str, object]) -> None:
    if set(review) != TOP_LEVEL_KEYS:
        raise ValueError("display review top-level fields do not match")
    if review["artifact_kind"] != ARTIFACT_KIND:
        raise ValueError("unexpected display review artifact kind")
    if review["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unexpected display review schema version")
    for key in ("baseline_target_sha256", "test_target_sha256"):
        if not _is_sha256(review[key]):
            raise ValueError(f"{key} must be a lowercase SHA-256")
    if review["baseline_target_sha256"] == review["test_target_sha256"]:
        raise ValueError("baseline and test target identities must differ")

    hashes = review["capture_png_sha256s"]
    if (
        not isinstance(hashes, list)
        or not 1 <= len(hashes) <= 16
        or any(not _is_sha256(value) for value in hashes)
        or len(set(hashes)) != len(hashes)
    ):
        raise ValueError("capture PNG identities are invalid")

    stream = review["reviewed_stream"]
    if not isinstance(stream, dict) or set(stream) != {
        "physical_start",
        "logical_start",
        "mapped_bank",
    }:
        raise ValueError("reviewed stream fields do not match")
    for key, maximum in (
        ("physical_start", 0x17BFFF),
        ("logical_start", 0xFFFF),
        ("mapped_bank", 0xFF),
    ):
        value = stream[key]
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= maximum
        ):
            raise ValueError(f"reviewed stream {key} is invalid")
    rejected = review["rejected_physical_starts"]
    if (
        not isinstance(rejected, list)
        or len(rejected) > 64
        or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= 0x17BFFF
            for value in rejected
        )
        or rejected != sorted(set(rejected))
    ):
        raise ValueError("rejected stream coordinates are invalid")

    result = review["result"]
    if result not in RESULTS:
        raise ValueError("unexpected display review result")
    observations = review["observations"]
    if not isinstance(observations, dict) or set(observations) != OBSERVATION_KEYS:
        raise ValueError("display review observation fields do not match")
    if any(
        value is not None and not isinstance(value, bool)
        for value in observations.values()
    ):
        raise ValueError("display review observations must be boolean or null")

    phrase_visible = observations["test_phrase_visible"]
    if result == "phrase-visible-pass" and phrase_visible is not True:
        raise ValueError("passing review must visibly confirm the test phrase")
    if result == "phrase-absent-fail" and phrase_visible is not False:
        raise ValueError("failed review must record that the phrase is absent")
    if (
        result == "phrase-absent-fail"
        and stream["physical_start"] not in rejected
    ):
        raise ValueError("failed review must reject the reviewed stream")
    if result == "ambiguous" and phrase_visible is not None:
        raise ValueError("ambiguous review must leave phrase visibility unknown")
    if review["translation_build_eligible"] is not False:
        raise ValueError("display review cannot enable translation builds")

    expected_checkpoint = {
        "phrase-visible-pass": "resolve-exact-visible-entry-and-expand-poc",
        "phrase-absent-fail": "try-next-runtime-observed-stream",
        "ambiguous": "recapture-test-display-for-human-review",
    }[result]
    if review["next_checkpoint"] != expected_checkpoint:
        raise ValueError("display review next checkpoint is inconsistent")


def write_display_review(
    root: Path,
    review: dict[str, object],
) -> Path:
    validate_display_review(review)
    path = root.resolve() / PUBLISH_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(review, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path
