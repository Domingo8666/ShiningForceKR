#!/usr/bin/env python3
"""Prove the four-glyph PoC in the published S25U progress frame."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

try:
    from .v5_1_poc_expansion import (
        EXPANSION_GLYPHS,
        EXPANSION_PHRASE,
        build_expanded_phrase_plan,
    )
    from .v5_1_progress_preview import (
        PUBLISH_IMAGE_RELATIVE_PATH,
        PUBLISH_RECEIPT_RELATIVE_PATH,
        load_validated_progress_image,
        validate_progress_preview,
    )
    from .v5_1_test_display_capture import (
        find_ink_mask_sequence,
        validate_display_capture,
    )
    from .v5_1_test_display_comparison import validate_display_comparison
    from .v5_1_test_display_review import validate_display_review
    from .v5_1_visible_entry_proof import validate_visible_entry_proof
except ImportError:  # direct script execution
    from v5_1_poc_expansion import (
        EXPANSION_GLYPHS,
        EXPANSION_PHRASE,
        build_expanded_phrase_plan,
    )
    from v5_1_progress_preview import (
        PUBLISH_IMAGE_RELATIVE_PATH,
        PUBLISH_RECEIPT_RELATIVE_PATH,
        load_validated_progress_image,
        validate_progress_preview,
    )
    from v5_1_test_display_capture import (
        find_ink_mask_sequence,
        validate_display_capture,
    )
    from v5_1_test_display_comparison import validate_display_comparison
    from v5_1_test_display_review import validate_display_review
    from v5_1_visible_entry_proof import validate_visible_entry_proof


ARTIFACT_KIND = "sanitized-s25u-poc-expansion-proof"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_poc_expansion_proof.json"
)
VISIBLE_ENTRY_PROOF_PATH = Path(
    "analysis/device/v5_1_latest_visible_entry_proof.json"
)
CAPTURE_PATH = Path("analysis/device/v5_1_latest_display_capture.json")
COMPARISON_PATH = Path(
    "analysis/device/v5_1_latest_display_comparison.json"
)
REVIEW_PATH = Path("analysis/device/v5_1_latest_display_review.json")
PATCH_PATH = Path("patch/Final_Conflict_Japan_to_Korean_v5.1.bps")

TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "purpose",
    "baseline_target_sha256",
    "test_target_sha256",
    "source_visible_entry_test_sha256",
    "phrase_codepoints",
    "runtime_entry",
    "display_proof",
    "translation_build_eligible",
    "next_checkpoint",
}
RUNTIME_KEYS = {
    "physical_start",
    "logical_start",
    "mapped_bank",
    "record_length_bytes",
    "original_encoded_bits",
    "replacement_encoded_bits",
    "roundtrip_exact",
}
DISPLAY_KEYS = {
    "capture_png_sha256",
    "width",
    "height",
    "frame_after_hit",
    "exact_phrase_matches",
    "exact_phrase_coordinate",
    "baseline_suffix_marker_matches",
    "test_suffix_marker_matches",
    "post_advance_changed_pixels",
    "surrounding_text_readable",
    "portrait_intact",
    "dialogue_box_intact",
}


class ExpansionProofNotReady(ValueError):
    """The current safe artifacts do not yet form a passing expansion set."""


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


def validate_poc_expansion_proof(proof: dict[str, object]) -> None:
    if set(proof) != TOP_LEVEL_KEYS:
        raise ValueError("PoC expansion proof top-level fields do not match")
    if (
        proof["artifact_kind"] != ARTIFACT_KIND
        or proof["schema_version"] != SCHEMA_VERSION
        or proof["status"] != "expanded-poc-visible-pass"
        or proof["purpose"] != "technical-poc-expanded-visible-entry"
    ):
        raise ValueError("PoC expansion proof policy is invalid")
    for key in (
        "baseline_target_sha256",
        "test_target_sha256",
        "source_visible_entry_test_sha256",
    ):
        if not _is_sha256(proof[key]):
            raise ValueError(f"{key} must be a lowercase SHA-256")
    if len(
        {
            proof["baseline_target_sha256"],
            proof["test_target_sha256"],
            proof["source_visible_entry_test_sha256"],
        }
    ) != 3:
        raise ValueError("PoC expansion build identities must be distinct")
    expected_codepoints = [
        f"U+{ord(character):04X}" for character in EXPANSION_PHRASE
    ]
    if proof["phrase_codepoints"] != expected_codepoints:
        raise ValueError("PoC expansion phrase codepoints are invalid")

    runtime = proof["runtime_entry"]
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_KEYS:
        raise ValueError("PoC expansion runtime fields do not match")
    for key, minimum, maximum in (
        ("physical_start", 0, 0x17BFFF),
        ("logical_start", 0x4000, 0x7FFF),
        ("mapped_bank", 0, 0xFF),
        ("record_length_bytes", 1, 0xFF),
        ("original_encoded_bits", 1, 0x7FFF),
        ("replacement_encoded_bits", 1, 0x7FFF),
    ):
        if not _bounded_int(runtime[key], minimum, maximum):
            raise ValueError(f"PoC expansion {key} is invalid")
    if (
        runtime["original_encoded_bits"] != runtime["replacement_encoded_bits"]
        or int(runtime["replacement_encoded_bits"])
        > int(runtime["record_length_bytes"]) * 8
        or runtime["roundtrip_exact"] is not True
    ):
        raise ValueError("PoC expansion runtime boundary is inconsistent")

    display = proof["display_proof"]
    if not isinstance(display, dict) or set(display) != DISPLAY_KEYS:
        raise ValueError("PoC expansion display fields do not match")
    for key, minimum, maximum in (
        ("width", 1, 1024),
        ("height", 1, 1024),
        ("frame_after_hit", 1, 1_000_000),
        ("exact_phrase_matches", 1, 0x100),
        ("baseline_suffix_marker_matches", 0, 0x100),
        ("test_suffix_marker_matches", 1, 0x100),
        ("post_advance_changed_pixels", 1, 1024 * 1024),
    ):
        if not _bounded_int(display[key], minimum, maximum):
            raise ValueError(f"PoC expansion display {key} is invalid")
    coordinate = display["exact_phrase_coordinate"]
    if (
        not isinstance(coordinate, dict)
        or set(coordinate) != {"x", "y"}
        or not _bounded_int(coordinate["x"], 0, int(display["width"]) - 1)
        or not _bounded_int(coordinate["y"], 0, int(display["height"]) - 1)
        or int(coordinate["x"]) + 8 * len(EXPANSION_PHRASE)
        > int(display["width"])
        or int(coordinate["y"]) + 8 > int(display["height"])
        or not _is_sha256(display["capture_png_sha256"])
        or display["exact_phrase_matches"] != 1
        or display["baseline_suffix_marker_matches"] != 0
        or display["surrounding_text_readable"] is not True
        or display["portrait_intact"] is not True
        or display["dialogue_box_intact"] is not True
    ):
        raise ValueError("PoC expansion display evidence is incomplete")
    if proof["translation_build_eligible"] is not False:
        raise ValueError("PoC expansion proof cannot enable translation builds")
    if (
        proof["next_checkpoint"]
        != "extract-and-roundtrip-visible-script-record"
    ):
        raise ValueError("PoC expansion next checkpoint is inconsistent")


def build_poc_expansion_proof(
    root: Path,
    patch: bytes,
    visible_entry: dict[str, object],
    capture: dict[str, object],
    comparison: dict[str, object],
    review: dict[str, object],
    preview: dict[str, object],
) -> dict[str, object]:
    root = root.resolve()
    validate_visible_entry_proof(visible_entry)
    validate_display_capture(capture)
    validate_display_comparison(comparison)
    validate_display_review(review)
    validate_progress_preview(preview)

    baseline = capture["baseline_target_sha256"]
    test = capture["test_target_sha256"]
    if (
        baseline != visible_entry["baseline_target_sha256"]
        or test == visible_entry["test_target_sha256"]
        or any(
            artifact.get("baseline_target_sha256") != baseline
            or artifact.get("test_target_sha256") != test
            for artifact in (comparison, review, preview)
        )
        or capture["status"] != "capture-ready-human-review-required"
        or comparison["result"]
        != "technical-marker-detected-human-review-required"
        or review["result"] != "phrase-visible-pass"
    ):
        raise ExpansionProofNotReady(
            "expanded capture, comparison, and review are not synchronized"
        )
    post_capture = capture["post_advance_capture"]
    post_comparison = comparison["post_advance_comparison"]
    observations = review["observations"]
    if (
        not isinstance(post_capture, dict)
        or not isinstance(post_comparison, dict)
        or post_capture["png_sha256"] != preview["capture_png_sha256"]
        or post_capture["png_sha256"]
        != post_comparison["test_png_sha256"]
        or post_comparison["baseline_technical_marker_matches"] != 0
        or int(post_comparison["test_technical_marker_matches"]) < 1
        or observations["test_phrase_visible"] is not True
        or observations["surrounding_text_readable"] is not True
        or observations["portrait_intact"] is not True
        or observations["dialogue_box_intact"] is not True
    ):
        raise ExpansionProofNotReady(
            "expanded post-advance screen evidence is incomplete"
        )

    runtime = visible_entry["runtime_entry"]
    assert isinstance(runtime, dict)
    plan = build_expanded_phrase_plan(
        patch,
        int(runtime["encoded_bits"]),
        visible_entry,
    )
    encoding = plan["encoding"]
    assert isinstance(encoding, dict)
    image_path = load_validated_progress_image(root, preview)
    masks = tuple(
        EXPANSION_GLYPHS[character].ink_mask
        for character in EXPANSION_PHRASE
    )
    matches = find_ink_mask_sequence(image_path.read_bytes(), masks)
    if len(matches) != 1:
        raise ExpansionProofNotReady(
            "the exact four-glyph sequence is not unique in the progress frame"
        )
    x, y = matches[0]

    proof: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": "expanded-poc-visible-pass",
        "purpose": "technical-poc-expanded-visible-entry",
        "baseline_target_sha256": baseline,
        "test_target_sha256": test,
        "source_visible_entry_test_sha256": visible_entry[
            "test_target_sha256"
        ],
        "phrase_codepoints": plan["phrase_codepoints"],
        "runtime_entry": {
            "physical_start": runtime["physical_start"],
            "logical_start": runtime["logical_start"],
            "mapped_bank": runtime["mapped_bank"],
            "record_length_bytes": runtime["record_length_bytes"],
            "original_encoded_bits": runtime["encoded_bits"],
            "replacement_encoded_bits": encoding["encoded_bits"],
            "roundtrip_exact": encoding["roundtrip_exact"],
        },
        "display_proof": {
            "capture_png_sha256": preview["capture_png_sha256"],
            "width": preview["width"],
            "height": preview["height"],
            "frame_after_hit": preview["frame_after_hit"],
            "exact_phrase_matches": len(matches),
            "exact_phrase_coordinate": {"x": x, "y": y},
            "baseline_suffix_marker_matches": post_comparison[
                "baseline_technical_marker_matches"
            ],
            "test_suffix_marker_matches": post_comparison[
                "test_technical_marker_matches"
            ],
            "post_advance_changed_pixels": post_comparison[
                "changed_pixels"
            ],
            "surrounding_text_readable": observations[
                "surrounding_text_readable"
            ],
            "portrait_intact": observations["portrait_intact"],
            "dialogue_box_intact": observations["dialogue_box_intact"],
        },
        "translation_build_eligible": False,
        "next_checkpoint": "extract-and-roundtrip-visible-script-record",
    }
    validate_poc_expansion_proof(proof)
    return proof


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = (
        root / VISIBLE_ENTRY_PROOF_PATH,
        root / CAPTURE_PATH,
        root / COMPARISON_PATH,
        root / REVIEW_PATH,
        root / PUBLISH_RECEIPT_RELATIVE_PATH,
        root / PUBLISH_IMAGE_RELATIVE_PATH,
        root / PATCH_PATH,
    )
    if any(not path.is_file() for path in paths):
        if args.if_ready:
            print("Expanded PoC proof is not ready: required artifact missing")
            return 0
        raise SystemExit("expanded PoC proof input is missing")
    try:
        proof = build_poc_expansion_proof(
            root,
            (root / PATCH_PATH).read_bytes(),
            _read_json(root / VISIBLE_ENTRY_PROOF_PATH),
            _read_json(root / CAPTURE_PATH),
            _read_json(root / COMPARISON_PATH),
            _read_json(root / REVIEW_PATH),
            _read_json(root / PUBLISH_RECEIPT_RELATIVE_PATH),
        )
    except ExpansionProofNotReady as error:
        if args.if_ready:
            print(f"Expanded PoC proof is not ready: {error}")
            return 0
        raise
    output = root / PUBLISH_RELATIVE_PATH
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(proof, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote expanded PoC screen proof: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
