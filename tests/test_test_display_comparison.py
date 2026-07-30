from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from tools.v5_1_test_display_comparison import (
    build_display_comparison,
    prior_automatic_rejections,
    validate_display_comparison,
    write_display_comparison,
)


def build_report() -> dict[str, object]:
    return {
        "baseline_target_sha256": "1" * 64,
        "test_target_sha256": "2" * 64,
        "runtime_entry": {
            "target_file_offset": 0x20473,
            "pointer_address": 0x4473,
            "pointer_bank": 8,
        },
    }


def pixel_comparison(
    changed_pixels: int,
    *,
    baseline_markers: int = 0,
    test_markers: int = 0,
    new_markers: int = 0,
) -> dict[str, object]:
    return {
        "width": 160,
        "height": 144,
        "total_pixels": 23_040,
        "changed_pixels": changed_pixels,
        "difference_bounds": (
            None
            if changed_pixels == 0
            else {
                "left": 10,
                "top": 100,
                "right_exclusive": 20,
                "bottom_exclusive": 120,
            }
        ),
        "baseline_png_sha256": "3" * 64,
        "test_png_sha256": "4" * 64,
        "baseline_pixel_sha256": "5" * 64,
        "test_pixel_sha256": (
            "5" * 64 if changed_pixels == 0 else "6" * 64
        ),
        "baseline_technical_marker_matches": baseline_markers,
        "test_technical_marker_matches": test_markers,
        "new_technical_marker_matches": new_markers,
    }


class TestDisplayComparisonTests(unittest.TestCase):
    def test_exact_no_change_is_an_automatic_rejection(self) -> None:
        frame = {"frame_after_hit": 30, **pixel_comparison(0)}
        comparison = build_display_comparison(
            build_report=build_report(),
            frame_comparisons=[frame],
            post_advance_comparison=pixel_comparison(0),
            prior_rejected_physical_starts={0x203DE},
        )
        validate_display_comparison(comparison)
        self.assertEqual(
            comparison["result"],
            "technical-marker-absent-auto-rejected",
        )
        self.assertEqual(
            comparison["automatic_rejected_physical_starts"],
            [0x203DE, 0x20473],
        )

    def test_visible_change_without_exact_marker_is_auto_rejected(self) -> None:
        comparison = build_display_comparison(
            build_report=build_report(),
            frame_comparisons=[
                {"frame_after_hit": 30, **pixel_comparison(1)}
            ],
            post_advance_comparison=pixel_comparison(0),
            prior_rejected_physical_starts={0x203DE},
        )
        self.assertEqual(
            comparison["result"],
            "technical-marker-absent-auto-rejected",
        )
        self.assertEqual(
            comparison["automatic_rejected_physical_starts"],
            [0x203DE, 0x20473],
        )

    def test_new_exact_marker_requires_human_review(self) -> None:
        comparison = build_display_comparison(
            build_report=build_report(),
            frame_comparisons=[
                {
                    "frame_after_hit": 30,
                    **pixel_comparison(
                        20,
                        test_markers=1,
                        new_markers=1,
                    ),
                }
            ],
            post_advance_comparison=pixel_comparison(0),
            prior_rejected_physical_starts={0x203DE},
        )
        self.assertEqual(
            comparison["result"],
            "technical-marker-detected-human-review-required",
        )
        self.assertEqual(
            comparison["automatic_rejected_physical_starts"],
            [0x203DE],
        )

    def test_post_advance_marker_is_not_auto_rejected(self) -> None:
        comparison = build_display_comparison(
            build_report=build_report(),
            frame_comparisons=[
                {"frame_after_hit": 30, **pixel_comparison(0)}
            ],
            post_advance_comparison=pixel_comparison(
                12,
                test_markers=1,
                new_markers=1,
            ),
            prior_rejected_physical_starts={0x20473},
        )
        self.assertEqual(
            comparison["result"],
            "technical-marker-detected-human-review-required",
        )
        self.assertNotIn(
            0x20473,
            comparison["automatic_rejected_physical_starts"],
        )

    def test_incomplete_pair_cannot_reject_the_stream(self) -> None:
        comparison = build_display_comparison(
            build_report=build_report(),
            frame_comparisons=[],
            post_advance_comparison=None,
        )
        self.assertEqual(comparison["result"], "comparison-unavailable")
        self.assertEqual(comparison["automatic_rejected_physical_starts"], [])

    def test_prior_rejections_are_loaded_only_for_the_same_baseline(self) -> None:
        comparison = build_display_comparison(
            build_report=build_report(),
            frame_comparisons=[
                {"frame_after_hit": 30, **pixel_comparison(0)}
            ],
            post_advance_comparison=pixel_comparison(0),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_display_comparison(root, comparison)
            self.assertEqual(
                prior_automatic_rejections(root, "1" * 64),
                {0x20473},
            )
            self.assertEqual(
                prior_automatic_rejections(root, "9" * 64),
                set(),
            )

    def test_changed_pixels_require_bounds(self) -> None:
        comparison = build_display_comparison(
            build_report=build_report(),
            frame_comparisons=[
                {"frame_after_hit": 30, **pixel_comparison(1)}
            ],
            post_advance_comparison=pixel_comparison(0),
        )
        broken = copy.deepcopy(comparison)
        broken["frame_comparisons"][0]["difference_bounds"] = None
        with self.assertRaisesRegex(ValueError, "require bounds"):
            validate_display_comparison(broken)


if __name__ == "__main__":
    unittest.main()
