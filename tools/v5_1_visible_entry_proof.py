#!/usr/bin/env python3
"""Bind the proven Hangul screen to one exact runtime script record."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

try:
    from .v5_1_test_display_capture import validate_display_capture
    from .v5_1_test_display_comparison import validate_display_comparison
    from .v5_1_test_display_review import validate_display_review
except ImportError:  # direct script execution
    from v5_1_test_display_capture import validate_display_capture
    from v5_1_test_display_comparison import validate_display_comparison
    from v5_1_test_display_review import validate_display_review


ARTIFACT_KIND = "sanitized-s25u-visible-entry-proof"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_visible_entry_proof.json"
)
DEFAULT_BUILD_REPORT = Path("reports/local/v5_1_test_patch_build.json")
DEFAULT_CAPTURE = Path("analysis/device/v5_1_latest_display_capture.json")
DEFAULT_COMPARISON = Path(
    "analysis/device/v5_1_latest_display_comparison.json"
)
DEFAULT_REVIEW = Path("analysis/device/v5_1_latest_display_review.json")

TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "purpose",
    "baseline_target_sha256",
    "test_target_sha256",
    "phrase_codepoints",
    "runtime_entry",
    "display_proof",
    "translation_build_eligible",
    "next_checkpoint",
}
RUNTIME_ENTRY_KEYS = {
    "kind",
    "selection_basis",
    "physical_start",
    "logical_start",
    "mapped_bank",
    "group_pointer_address",
    "length_prefix_logical_address",
    "record_length_bytes",
    "skipped_record_count",
    "symbol_count",
    "encoded_bits",
    "roundtrip_exact",
}
DISPLAY_PROOF_KEYS = {
    "capture_png_sha256",
    "new_technical_marker_matches",
    "review_result",
    "phrase_visible",
    "surrounding_text_readable",
    "portrait_intact",
    "dialogue_box_intact",
}


class VisibleEntryProofNotReady(ValueError):
    """The current artifacts do not yet describe the same passing build."""


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _bounded_int(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def validate_visible_entry_proof(proof: dict[str, object]) -> None:
    if set(proof) != TOP_LEVEL_KEYS:
        raise ValueError("visible entry proof top-level fields do not match")
    if (
        proof["artifact_kind"] != ARTIFACT_KIND
        or proof["schema_version"] != SCHEMA_VERSION
        or proof["status"] != "exact-visible-entry-confirmed"
        or proof["purpose"] != "technical-poc-only"
    ):
        raise ValueError("visible entry proof policy is invalid")
    for key in ("baseline_target_sha256", "test_target_sha256"):
        if not _is_sha256(proof[key]):
            raise ValueError(f"{key} must be a lowercase SHA-256")
    if proof["baseline_target_sha256"] == proof["test_target_sha256"]:
        raise ValueError("visible entry proof target identities must differ")
    if proof["phrase_codepoints"] != ["U+D55C", "U+B2E4"]:
        raise ValueError("visible entry proof phrase is not the approved marker")

    entry = proof["runtime_entry"]
    if not isinstance(entry, dict) or set(entry) != RUNTIME_ENTRY_KEYS:
        raise ValueError("visible entry proof runtime fields do not match")
    if (
        entry["kind"] != "runtime-length-prefixed-entry"
        or entry["selection_basis"]
        != "decoder-register-proven-length-prefixed-skip-loop"
        or entry["roundtrip_exact"] is not True
    ):
        raise ValueError("visible entry proof runtime policy is invalid")
    for key, minimum, maximum in (
        ("physical_start", 0, 0x17BFFF),
        ("logical_start", 0x4000, 0x7FFF),
        ("mapped_bank", 0, 0xFF),
        ("group_pointer_address", 0x4000, 0x7FFF),
        ("length_prefix_logical_address", 0x4000, 0x7FFF),
        ("record_length_bytes", 1, 0xFF),
        ("skipped_record_count", 0, 0xFF),
        ("symbol_count", 1, 0x1000),
        ("encoded_bits", 1, 0x7FFF),
    ):
        if not _bounded_int(entry[key], minimum, maximum):
            raise ValueError(f"visible entry proof {key} is invalid")
    if int(entry["encoded_bits"]) > int(entry["record_length_bytes"]) * 8:
        raise ValueError("visible entry proof exceeds its record boundary")
    if int(entry["length_prefix_logical_address"]) + 1 != int(
        entry["logical_start"]
    ):
        raise ValueError("visible entry proof length prefix is inconsistent")

    display = proof["display_proof"]
    if not isinstance(display, dict) or set(display) != DISPLAY_PROOF_KEYS:
        raise ValueError("visible entry display proof fields do not match")
    if (
        not _is_sha256(display["capture_png_sha256"])
        or not _bounded_int(
            display["new_technical_marker_matches"], 1, 0x100
        )
        or display["review_result"] != "phrase-visible-pass"
        or display["phrase_visible"] is not True
        or display["surrounding_text_readable"] is not True
        or display["portrait_intact"] is not True
        or display["dialogue_box_intact"] is not True
    ):
        raise ValueError("visible entry display proof is incomplete")
    if proof["translation_build_eligible"] is not False:
        raise ValueError("visible entry proof cannot enable translation builds")
    if (
        proof["next_checkpoint"]
        != "expand-poc-to-multiple-visible-glyphs"
    ):
        raise ValueError("visible entry proof next checkpoint is inconsistent")


def build_visible_entry_proof(
    build_report: dict[str, object],
    capture: dict[str, object],
    comparison: dict[str, object],
    review: dict[str, object],
) -> dict[str, object]:
    validate_display_capture(capture)
    validate_display_comparison(comparison)
    validate_display_review(review)

    if (
        build_report.get("artifact_kind")
        != "s25u-local-korean-test-patch-build"
        or build_report.get("status")
        != "technical-poc-built-needs-runtime-display-proof"
        or build_report.get("purpose") != "technical-poc-only"
        or build_report.get("phrase") != "한다"
    ):
        raise ValueError("local test build report policy is invalid")
    baseline = build_report.get("baseline_target_sha256")
    test = build_report.get("test_target_sha256")
    if not _is_sha256(baseline) or not _is_sha256(test):
        raise ValueError("local test build identities are invalid")
    if any(
        artifact.get("baseline_target_sha256") != baseline
        or artifact.get("test_target_sha256") != test
        for artifact in (capture, comparison, review)
    ):
        raise VisibleEntryProofNotReady(
            "display artifacts do not belong to the current test build"
        )

    runtime = build_report.get("runtime_entry")
    original = build_report.get("original_entry")
    if (
        not isinstance(runtime, dict)
        or runtime.get("kind") != "runtime-length-prefixed-entry"
        or runtime.get("selection_basis")
        != "decoder-register-proven-length-prefixed-skip-loop"
        or not isinstance(original, dict)
        or original.get("roundtrip_exact") is not True
    ):
        raise ValueError("local test build runtime record is not proven")
    post_capture = capture.get("post_advance_capture")
    post_comparison = comparison.get("post_advance_comparison")
    observations = review.get("observations")
    reviewed_stream = review.get("reviewed_stream")
    compared_stream = comparison.get("compared_stream")
    if (
        capture.get("status") != "capture-ready-human-review-required"
        or not isinstance(post_capture, dict)
        or comparison.get("result")
        != "technical-marker-detected-human-review-required"
        or not isinstance(post_comparison, dict)
        or not isinstance(observations, dict)
        or review.get("result") != "phrase-visible-pass"
        or not isinstance(reviewed_stream, dict)
        or not isinstance(compared_stream, dict)
    ):
        raise VisibleEntryProofNotReady(
            "passing post-advance display evidence is not ready"
        )
    if (
        post_comparison.get("test_png_sha256")
        != post_capture.get("png_sha256")
        or int(post_comparison.get("new_technical_marker_matches", 0)) < 1
        or observations.get("test_phrase_visible") is not True
        or reviewed_stream != compared_stream
        or reviewed_stream.get("physical_start")
        != runtime.get("target_file_offset")
        or reviewed_stream.get("logical_start")
        != runtime.get("pointer_address")
        or reviewed_stream.get("mapped_bank") != runtime.get("pointer_bank")
    ):
        raise VisibleEntryProofNotReady(
            "runtime record and visible marker evidence do not agree"
        )

    proof: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": "exact-visible-entry-confirmed",
        "purpose": "technical-poc-only",
        "baseline_target_sha256": baseline,
        "test_target_sha256": test,
        "phrase_codepoints": ["U+D55C", "U+B2E4"],
        "runtime_entry": {
            "kind": runtime["kind"],
            "selection_basis": runtime["selection_basis"],
            "physical_start": runtime["target_file_offset"],
            "logical_start": runtime["pointer_address"],
            "mapped_bank": runtime["pointer_bank"],
            "group_pointer_address": runtime["group_pointer_address"],
            "length_prefix_logical_address": runtime[
                "length_prefix_logical_address"
            ],
            "record_length_bytes": runtime["record_length_bytes"],
            "skipped_record_count": runtime["skipped_record_count"],
            "symbol_count": original["symbol_count"],
            "encoded_bits": original["encoded_bits"],
            "roundtrip_exact": original["roundtrip_exact"],
        },
        "display_proof": {
            "capture_png_sha256": post_capture["png_sha256"],
            "new_technical_marker_matches": post_comparison[
                "new_technical_marker_matches"
            ],
            "review_result": review["result"],
            "phrase_visible": observations["test_phrase_visible"],
            "surrounding_text_readable": observations[
                "surrounding_text_readable"
            ],
            "portrait_intact": observations["portrait_intact"],
            "dialogue_box_intact": observations["dialogue_box_intact"],
        },
        "translation_build_eligible": False,
        "next_checkpoint": "expand-poc-to-multiple-visible-glyphs",
    }
    validate_visible_entry_proof(proof)
    return proof


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-report", type=Path, default=DEFAULT_BUILD_REPORT)
    parser.add_argument("--capture", type=Path, default=DEFAULT_CAPTURE)
    parser.add_argument("--comparison", type=Path, default=DEFAULT_COMPARISON)
    parser.add_argument("--review", type=Path, default=DEFAULT_REVIEW)
    parser.add_argument("--output", type=Path, default=PUBLISH_RELATIVE_PATH)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()

    paths = [
        root / args.build_report,
        root / args.capture,
        root / args.comparison,
        root / args.review,
    ]
    if any(not path.is_file() for path in paths):
        if args.if_ready:
            print("Visible entry proof is not ready: required artifact missing")
            return 0
        raise SystemExit("visible entry proof input is missing")
    try:
        proof = build_visible_entry_proof(
            *(_read_json(path) for path in paths)
        )
    except VisibleEntryProofNotReady as error:
        if args.if_ready:
            print(f"Visible entry proof is not ready: {error}")
            return 0
        raise

    output = (root / args.output).resolve()
    output.relative_to(root.resolve())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(proof, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote exact visible entry proof: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
