from __future__ import annotations

import copy
import unittest

from tools.v5_1_visible_entry_proof import (
    build_visible_entry_proof,
    validate_visible_entry_proof,
)


def sample_inputs() -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    baseline = "1" * 64
    test = "2" * 64
    png = "3" * 64
    build = {
        "artifact_kind": "s25u-local-korean-test-patch-build",
        "schema_version": 1,
        "status": "technical-poc-built-needs-runtime-display-proof",
        "purpose": "technical-poc-only",
        "phrase": "한다",
        "baseline_target_sha256": baseline,
        "test_target_sha256": test,
        "runtime_entry": {
            "kind": "runtime-length-prefixed-entry",
            "selection_basis": (
                "decoder-register-proven-length-prefixed-skip-loop"
            ),
            "target_file_offset": 0x20913,
            "pointer_bank": 8,
            "pointer_address": 0x4913,
            "group_pointer_address": 0x43DE,
            "length_prefix_logical_address": 0x4912,
            "record_length_bytes": 9,
            "skipped_record_count": 2,
        },
        "original_entry": {
            "encoded_bits": 67,
            "encoded_bytes": 9,
            "roundtrip_exact": True,
            "symbol_count": 14,
            "terminator_count": 1,
        },
    }
    capture = {
        "artifact_kind": "sanitized-s25u-test-display-capture",
        "schema_version": 6,
        "status": "capture-ready-human-review-required",
        "purpose": "technical-poc-only",
        "phrase_codepoints": ["U+D55C", "U+B2E4"],
        "baseline_target_sha256": baseline,
        "test_target_sha256": test,
        "emulator_version": "3.9.14",
        "cold_boot": True,
        "target_read": {
            "slot": 1,
            "logical_access": 0x4913,
            "expected_bank": 8,
            "mapped_bank": 8,
            "confirmed": True,
            "confirmation_basis": "decoder-selection-endpoint",
        },
        "entry_selector": None,
        "group_entry": None,
        "captures": [
            {
                "frame_after_hit": 1,
                "width": 160,
                "height": 144,
                "png_sha256": "4" * 64,
            }
        ],
        "post_advance_capture": {
            "button": "1",
            "frames_after_press": 60,
            "width": 160,
            "height": 144,
            "png_sha256": png,
        },
        "visual_review": {
            "required": True,
            "result": None,
            "evidence_storage": "s25u-local-only",
        },
        "translation_build_eligible": False,
        "next_checkpoint": "human-confirm-first-korean-glyphs-and-ui",
    }
    stream = {
        "physical_start": 0x20913,
        "logical_start": 0x4913,
        "mapped_bank": 8,
    }
    comparison = {
        "artifact_kind": "sanitized-s25u-test-display-comparison",
        "schema_version": 2,
        "baseline_target_sha256": baseline,
        "test_target_sha256": test,
        "compared_stream": stream,
        "frame_comparisons": [
            {
                "frame_after_hit": 30,
                "width": 160,
                "height": 144,
                "total_pixels": 23040,
                "changed_pixels": 0,
                "difference_bounds": None,
                "baseline_pixel_sha256": "8" * 64,
                "test_pixel_sha256": "8" * 64,
                "baseline_technical_marker_matches": 0,
                "test_technical_marker_matches": 0,
                "new_technical_marker_matches": 0,
                "baseline_png_sha256": "9" * 64,
                "test_png_sha256": "9" * 64,
            }
        ],
        "post_advance_comparison": {
            "width": 160,
            "height": 144,
            "total_pixels": 23040,
            "changed_pixels": 100,
            "difference_bounds": {
                "left": 1,
                "top": 2,
                "right_exclusive": 30,
                "bottom_exclusive": 40,
            },
            "baseline_pixel_sha256": "5" * 64,
            "test_pixel_sha256": "6" * 64,
            "baseline_technical_marker_matches": 0,
            "test_technical_marker_matches": 1,
            "new_technical_marker_matches": 1,
            "baseline_png_sha256": "7" * 64,
            "test_png_sha256": png,
        },
        "result": "technical-marker-detected-human-review-required",
        "automatic_rejected_physical_starts": [],
        "translation_build_eligible": False,
        "next_checkpoint": "human-review-technical-marker",
    }
    review = {
        "artifact_kind": "sanitized-s25u-test-display-review",
        "schema_version": 1,
        "baseline_target_sha256": baseline,
        "test_target_sha256": test,
        "capture_png_sha256s": ["4" * 64, png],
        "reviewed_stream": stream,
        "rejected_physical_starts": [],
        "result": "phrase-visible-pass",
        "observations": {
            "test_phrase_visible": True,
            "surrounding_text_readable": True,
            "portrait_intact": True,
            "dialogue_box_intact": True,
            "post_advance_cleared": False,
        },
        "translation_build_eligible": False,
        "next_checkpoint": "resolve-exact-visible-entry-and-expand-poc",
    }
    return build, capture, comparison, review


class VisibleEntryProofTests(unittest.TestCase):
    def test_builds_exact_visible_entry_proof(self) -> None:
        proof = build_visible_entry_proof(*sample_inputs())
        validate_visible_entry_proof(proof)
        self.assertEqual(
            proof["status"],
            "exact-visible-entry-confirmed",
        )
        self.assertEqual(
            proof["runtime_entry"]["record_length_bytes"],
            9,
        )
        self.assertEqual(
            proof["display_proof"]["new_technical_marker_matches"],
            1,
        )

    def test_rejects_runtime_and_screen_coordinate_disagreement(self) -> None:
        build, capture, comparison, review = sample_inputs()
        review = copy.deepcopy(review)
        review["reviewed_stream"]["logical_start"] += 1
        comparison["compared_stream"] = review["reviewed_stream"]
        with self.assertRaisesRegex(ValueError, "do not agree"):
            build_visible_entry_proof(
                build,
                capture,
                comparison,
                review,
            )

    def test_rejects_screen_without_new_marker(self) -> None:
        build, capture, comparison, review = sample_inputs()
        comparison = copy.deepcopy(comparison)
        comparison["post_advance_comparison"][
            "new_technical_marker_matches"
        ] = 0
        comparison["post_advance_comparison"][
            "test_technical_marker_matches"
        ] = 0
        comparison["result"] = "technical-marker-absent-auto-rejected"
        comparison["automatic_rejected_physical_starts"] = [0x20913]
        comparison["next_checkpoint"] = "try-next-runtime-observed-stream"
        with self.assertRaisesRegex(ValueError, "not ready"):
            build_visible_entry_proof(
                build,
                capture,
                comparison,
                review,
            )


if __name__ == "__main__":
    unittest.main()
