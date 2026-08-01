#!/usr/bin/env python3
"""Build a ROM-free receipt for the first translated runtime screen review."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path


ARTIFACT_KIND = (
    "sanitized-v5-1-first-context-translation-runtime-visual-review"
)
SCHEMA_VERSION = 2
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/"
    "v5_1_latest_first_context_translation_visual_review.json"
)
COUNT_KEYS = {
    "expected_screen_count",
    "reviewed_screen_count",
    "missing_dialogue_screen_count",
    "corrupted_text_screen_count",
    "wrong_context_screen_count",
}
SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "runtime_capture_sha256",
    "test_target_sha256",
    "review_evidence_sha256",
    "captured_utc",
    "review",
    "review_evidence_kind",
    "human_visual_review_complete",
    "runtime_layout_confirmed",
    "source_and_target_text_local_only",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return timestamp.utcoffset() == timezone.utc.utcoffset(timestamp)


def build_first_context_translation_visual_review(
    *,
    runtime_capture_sha256: str,
    test_target_sha256: str,
    review_evidence_sha256: str,
    review: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    expected = review["expected_screen_count"]
    reviewed = review["reviewed_screen_count"]
    failures = sum(
        review[key]
        for key in (
            "missing_dialogue_screen_count",
            "corrupted_text_screen_count",
            "wrong_context_screen_count",
        )
    )
    complete = expected >= 4 and reviewed == expected
    passed = complete and failures == 0
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "first-context-translation-runtime-visual-pass"
            if passed
            else "first-context-translation-runtime-visual-fail"
            if complete
            else "first-context-translation-runtime-visual-incomplete"
        ),
        "runtime_capture_sha256": runtime_capture_sha256,
        "test_target_sha256": test_target_sha256,
        "review_evidence_sha256": review_evidence_sha256,
        "captured_utc": captured_utc,
        "review": review,
        "review_evidence_kind": "user-supplied-runtime-review-screenshots",
        "human_visual_review_complete": complete,
        "runtime_layout_confirmed": passed,
        "source_and_target_text_local_only": True,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "expand-approved-translation-scope"
            if passed
            else "repair-runtime-codec-and-recapture-first-context"
            if complete
            else "complete-first-context-runtime-visual-review"
        ),
    }
    validate_first_context_translation_visual_review(value)
    return value


def validate_first_context_translation_visual_review(
    value: dict[str, object],
) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError("first context visual review fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or not _is_sha256(value["runtime_capture_sha256"])
        or not _is_sha256(value["test_target_sha256"])
        or not _is_sha256(value["review_evidence_sha256"])
        or not _is_utc_timestamp(value["captured_utc"])
        or value["review_evidence_kind"]
        != "user-supplied-runtime-review-screenshots"
    ):
        raise ValueError("first context visual review identity is invalid")
    review = value["review"]
    if (
        not isinstance(review, dict)
        or set(review) != COUNT_KEYS
        or any(
            not isinstance(count, int)
            or isinstance(count, bool)
            or not 0 <= count <= 100
            for count in review.values()
        )
    ):
        raise ValueError("first context visual review counts do not match")
    expected = review["expected_screen_count"]
    reviewed = review["reviewed_screen_count"]
    failures = sum(
        review[key]
        for key in (
            "missing_dialogue_screen_count",
            "corrupted_text_screen_count",
            "wrong_context_screen_count",
        )
    )
    complete = expected >= 4 and reviewed == expected
    passed = complete and failures == 0
    expected_status = (
        "first-context-translation-runtime-visual-pass"
        if passed
        else "first-context-translation-runtime-visual-fail"
        if complete
        else "first-context-translation-runtime-visual-incomplete"
    )
    expected_checkpoint = (
        "expand-approved-translation-scope"
        if passed
        else "repair-runtime-codec-and-recapture-first-context"
        if complete
        else "complete-first-context-runtime-visual-review"
    )
    if (
        value["status"] != expected_status
        or value["human_visual_review_complete"] is not complete
        or value["runtime_layout_confirmed"] is not passed
        or value["source_and_target_text_local_only"] is not True
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"] != expected_checkpoint
    ):
        raise ValueError("first context visual review result is inconsistent")


def write_first_context_translation_visual_review(
    root: Path,
    value: dict[str, object],
) -> Path:
    validate_first_context_translation_visual_review(value)
    path = root / PUBLISH_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path
