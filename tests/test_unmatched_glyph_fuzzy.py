from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_unmatched_glyph_fuzzy import (  # noqa: E402
    build_unmatched_glyph_fuzzy,
    mask_distance,
    nearest_glyphs,
    validate_unmatched_glyph_fuzzy,
)


class UnmatchedGlyphFuzzyTests(unittest.TestCase):
    def test_uses_pixel_distance_and_a_unique_margin(self) -> None:
        target = (0, 0, 0, 0x18, 0x18, 0, 0, 0)
        glyphs = {
            0xAC00: (0, 0, 0, 0x18, 0x10, 0, 0, 0),
            0xB098: (0, 0, 0, 0x7E, 0x42, 0, 0, 0),
        }
        result = nearest_glyphs(target, glyphs)
        self.assertEqual(result["best_distance"], 1)
        self.assertEqual(result["best_codepoints"], [0xAC00])
        self.assertTrue(result["high_confidence"])
        self.assertEqual(mask_distance(target, target), 0)

    def test_rejects_a_tied_nearest_glyph(self) -> None:
        target = (0,) * 8
        glyphs = {
            0xAC00: (1, 0, 0, 0, 0, 0, 0, 0),
            0xB098: (2, 0, 0, 0, 0, 0, 0, 0),
        }
        result = nearest_glyphs(target, glyphs)
        self.assertEqual(len(result["best_codepoints"]), 2)
        self.assertFalse(result["high_confidence"])

    def test_builds_safe_counts_and_rejects_unicode_leakage(self) -> None:
        artifact = build_unmatched_glyph_fuzzy(
            target_sha256="1" * 64,
            source_text_candidate_sha256="2" * 64,
            source_font_reference_sha256="3" * 64,
            unmatched={
                "occurrence_count": 10,
                "distinct_glyph_count": 5,
                "unique_nearest_distinct_count": 4,
                "tied_nearest_distinct_count": 1,
                "distance_zero_distinct_count": 0,
                "distance_one_distinct_count": 1,
                "distance_two_distinct_count": 1,
                "distance_three_or_four_distinct_count": 1,
                "distance_over_four_distinct_count": 2,
                "high_confidence_distinct_count": 2,
                "high_confidence_occurrence_count": 6,
            },
            captured_utc="2026-07-30T17:00:00Z",
        )
        validate_unmatched_glyph_fuzzy(artifact)
        self.assertEqual(
            artifact["status"],
            "unmatched-glyph-high-confidence-overrides-ready",
        )
        for field, value in (
            ("glyph_coordinates", [[1, 2]]),
            ("codepoints", ["U+AC00"]),
            ("characters", ["가"]),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_unmatched_glyph_fuzzy(unsafe)


if __name__ == "__main__":
    unittest.main()
