from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_runtime_context_glyph_candidates import (  # noqa: E402
    analyze_runtime_context_glyph_candidates,
    build_runtime_context_glyph_candidates,
    validate_runtime_context_glyph_candidates,
)


def _demand(*coordinates: tuple[int, int]) -> dict:
    return {
        "rows": [
            {
                "unresolved": [
                    {"page": page, "symbol": symbol}
                    for page, symbol in coordinates
                ]
            }
        ],
        "distinct_glyphs": [
            {"page": page, "symbol": symbol}
            for page, symbol in sorted(set(coordinates))
        ],
    }


class RuntimeContextGlyphCandidatesTests(unittest.TestCase):
    def test_cross_references_unique_tied_out_of_range_and_missing(
        self,
    ) -> None:
        counts, local = analyze_runtime_context_glyph_candidates(
            _demand((1, 2), (1, 2), (1, 3), (9, 4), (2, 5)),
            {
                "glyphs": [
                    {
                        "page": 1,
                        "symbol": 2,
                        "best_codepoints": [ord("가")],
                        "best_distance": 2,
                        "distance_margin": 3,
                        "high_confidence": True,
                    },
                    {
                        "page": 1,
                        "symbol": 3,
                        "best_codepoints": [ord("나"), ord("다")],
                        "best_distance": 5,
                        "distance_margin": 1,
                        "high_confidence": False,
                    },
                    {
                        "page": 9,
                        "symbol": 4,
                        "status": "outside-font-page-range",
                    },
                ]
            },
        )
        self.assertEqual(counts["demanded_occurrence_count"], 5)
        self.assertEqual(counts["demanded_distinct_glyph_count"], 4)
        self.assertEqual(counts["missing_fuzzy_distinct_count"], 1)
        self.assertEqual(counts["out_of_range_distinct_count"], 1)
        self.assertEqual(counts["unique_nearest_occurrence_count"], 2)
        self.assertEqual(counts["tied_nearest_distinct_count"], 1)
        self.assertEqual(counts["distance_two_distinct_count"], 1)
        self.assertEqual(counts["distance_over_four_distinct_count"], 1)
        self.assertEqual(counts["high_confidence_occurrence_count"], 2)
        self.assertFalse(local["automatic_character_selection_allowed"])

    def test_rejects_disagreement_between_rows_and_distinct_glyphs(
        self,
    ) -> None:
        demand = _demand((1, 2))
        demand["distinct_glyphs"] = [{"page": 1, "symbol": 3}]
        with self.assertRaisesRegex(ValueError, "coordinates disagree"):
            analyze_runtime_context_glyph_candidates(
                demand, {"glyphs": []}
            )

    def test_builds_fixed_safe_receipt_without_candidate_payload(
        self,
    ) -> None:
        counts, _ = analyze_runtime_context_glyph_candidates(
            _demand((1, 2)),
            {
                "glyphs": [
                    {
                        "page": 1,
                        "symbol": 2,
                        "best_codepoints": [ord("가")],
                        "best_distance": 7,
                        "distance_margin": 2,
                        "high_confidence": False,
                    }
                ]
            },
        )
        artifact = build_runtime_context_glyph_candidates(
            target_sha256="1" * 64,
            runtime_context_glyph_demand_sha256="2" * 64,
            target_group_expanded_glyphs_sha256="3" * 64,
            local_candidates_sha256="4" * 64,
            candidates=counts,
            captured_utc="2026-07-31T04:00:00Z",
        )
        validate_runtime_context_glyph_candidates(artifact)
        self.assertEqual(
            artifact["next_checkpoint"],
            "analyze-runtime-context-glyph-transform",
        )
        self.assertFalse(artifact["automatic_character_selection_allowed"])
        self.assertFalse(artifact["translation_build_eligible"])
        unsafe = deepcopy(artifact)
        unsafe["characters"] = ["가"]
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_runtime_context_glyph_candidates(unsafe)


if __name__ == "__main__":
    unittest.main()
