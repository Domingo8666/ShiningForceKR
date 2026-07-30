from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_target_group_expanded_glyphs import (  # noqa: E402
    build_target_group_expanded_glyphs,
    validate_target_group_expanded_glyphs,
)


class TargetGroupExpandedGlyphTests(unittest.TestCase):
    def test_builds_safe_no_override_result(self) -> None:
        artifact = build_target_group_expanded_glyphs(
            target_sha256="1" * 64,
            source_population_decode_sha256="2" * 64,
            source_font_reference_sha256="3" * 64,
            unmatched={
                "occurrence_count": 1104,
                "distinct_glyph_count": 100,
                "in_range_distinct_count": 98,
                "out_of_range_distinct_count": 2,
                "out_of_range_occurrence_count": 4,
                "unique_nearest_distinct_count": 60,
                "tied_nearest_distinct_count": 38,
                "distance_zero_distinct_count": 0,
                "distance_one_distinct_count": 0,
                "distance_two_distinct_count": 0,
                "distance_three_or_four_distinct_count": 2,
                "distance_over_four_distinct_count": 96,
                "high_confidence_distinct_count": 0,
                "high_confidence_occurrence_count": 0,
            },
            captured_utc="2026-07-30T17:10:00Z",
        )
        validate_target_group_expanded_glyphs(artifact)
        self.assertEqual(
            artifact["status"],
            "expanded-glyphs-require-non-hangul-classification",
        )

    def test_rejects_local_coordinates(self) -> None:
        artifact = build_target_group_expanded_glyphs(
            target_sha256="1" * 64,
            source_population_decode_sha256="2" * 64,
            source_font_reference_sha256="3" * 64,
            unmatched={
                "occurrence_count": 0,
                "distinct_glyph_count": 0,
                "in_range_distinct_count": 0,
                "out_of_range_distinct_count": 0,
                "out_of_range_occurrence_count": 0,
                "unique_nearest_distinct_count": 0,
                "tied_nearest_distinct_count": 0,
                "distance_zero_distinct_count": 0,
                "distance_one_distinct_count": 0,
                "distance_two_distinct_count": 0,
                "distance_three_or_four_distinct_count": 0,
                "distance_over_four_distinct_count": 0,
                "high_confidence_distinct_count": 0,
                "high_confidence_occurrence_count": 0,
            },
            captured_utc="2026-07-30T17:10:00Z",
        )
        unsafe = deepcopy(artifact)
        unsafe["glyph_coordinates"] = [[1, 2]]
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_target_group_expanded_glyphs(unsafe)


if __name__ == "__main__":
    unittest.main()
