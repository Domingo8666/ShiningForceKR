from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_target_group_non_hangul_glyphs import (  # noqa: E402
    build_target_group_non_hangul_glyphs,
    classify_exact_non_hangul,
    validate_target_group_non_hangul_glyphs,
)


class TargetGroupNonHangulGlyphTests(unittest.TestCase):
    def test_keeps_only_unique_exact_non_hangul_matches(self) -> None:
        local_glyphs = [
            {
                "page": 1,
                "symbol": 2,
                "occurrence_count": 3,
                "mask_rows_hex": ["01"] * 8,
            },
            {
                "page": 1,
                "symbol": 3,
                "occurrence_count": 2,
                "mask_rows_hex": ["02"] * 8,
            },
            {
                "page": 1,
                "symbol": 4,
                "occurrence_count": 1,
                "mask_rows_hex": ["03"] * 8,
            },
            {
                "page": 1,
                "symbol": 5,
                "occurrence_count": 4,
                "mask_rows_hex": ["04"] * 8,
            },
            {
                "page": 99,
                "symbol": 6,
                "occurrence_count": 5,
                "status": "outside-font-page-range",
            },
        ]
        reference = {
            ord("Z"): (1,) * 8,
            ord("B"): (2,) * 8,
            ord("C"): (2,) * 8,
            ord("한"): (3,) * 8,
            ord("Ａ"): (4,) * 8,
            ord("A"): (4,) * 8,
        }
        counts, local = classify_exact_non_hangul(
            local_glyphs=deepcopy(local_glyphs),
            reference_glyphs=reference,
        )
        self.assertEqual(counts["occurrence_count"], 15)
        self.assertEqual(counts["unique_exact_distinct_count"], 1)
        self.assertEqual(counts["unique_exact_occurrence_count"], 3)
        self.assertEqual(counts["equivalent_exact_distinct_count"], 1)
        self.assertEqual(counts["equivalent_exact_occurrence_count"], 4)
        self.assertEqual(counts["ambiguous_exact_distinct_count"], 1)
        self.assertEqual(counts["unmatched_distinct_count"], 1)
        self.assertEqual(counts["outside_font_range_distinct_count"], 1)
        self.assertEqual(
            local["exact_non_hangul_overrides"][0]["character"],
            "Z",
        )
        self.assertEqual(
            local["exact_non_hangul_overrides"][1]["character"],
            "A",
        )
        self.assertEqual(
            local["exact_non_hangul_overrides"][1]["resolution_source"],
            "exact-non-hangul-nfkc-equivalent",
        )

    def test_builds_safe_counts_without_characters(self) -> None:
        classification = {
            "occurrence_count": 15,
            "distinct_glyph_count": 5,
            "in_range_distinct_count": 4,
            "outside_font_range_distinct_count": 1,
            "unique_exact_distinct_count": 1,
            "unique_exact_occurrence_count": 3,
            "equivalent_exact_distinct_count": 1,
            "equivalent_exact_occurrence_count": 4,
            "ambiguous_exact_distinct_count": 1,
            "ambiguous_exact_occurrence_count": 2,
            "unmatched_distinct_count": 1,
            "unmatched_occurrence_count": 6,
            "eligible_reference_glyph_count": 100,
        }
        artifact = build_target_group_non_hangul_glyphs(
            target_sha256="1" * 64,
            source_expanded_glyphs_sha256="2" * 64,
            source_font_reference_sha256="3" * 64,
            classification=classification,
            captured_utc="2026-07-31T00:00:00Z",
        )
        validate_target_group_non_hangul_glyphs(artifact)
        self.assertEqual(
            artifact["status"],
            "exact-non-hangul-overrides-ready",
        )
        self.assertNotIn("characters", artifact)
        self.assertFalse(artifact["translation_build_eligible"])


if __name__ == "__main__":
    unittest.main()
