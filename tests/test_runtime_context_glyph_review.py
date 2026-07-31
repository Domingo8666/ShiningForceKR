from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_runtime_context_glyph_review import (  # noqa: E402
    build_runtime_context_glyph_review,
    build_runtime_glyph_review_rows,
    render_runtime_glyph_review_html,
    validate_runtime_context_glyph_review,
)


class RuntimeContextGlyphReviewTests(unittest.TestCase):
    def test_builds_contextual_cards_without_publishing_payload(self) -> None:
        counts, cards = build_runtime_glyph_review_rows(
            {
                "rows": [
                    {
                        "source_text": "synthetic source",
                        "speaker": "a",
                        "target_text": "synthetic target",
                        "quality_tier": "glyph-recovery",
                        "unresolved": [
                            {"page": 1, "symbol": 2},
                            {"page": 1, "symbol": 3},
                        ],
                    }
                ]
            },
            {
                "glyphs": [
                    {
                        "page": 1,
                        "symbol": 2,
                        "fuzzy": {
                            "mask_rows_hex": ["00"] * 8,
                            "best_characters": ["가"],
                            "best_codepoints": [ord("가")],
                            "best_distance": 7,
                            "distance_margin": 1,
                        },
                        "non_hangul": {
                            "status": "ambiguous-exact-non-hangul",
                            "candidate_characters": ["-", "−"],
                            "candidate_codepoints": [ord("-"), ord("−")],
                        },
                    },
                    {
                        "page": 1,
                        "symbol": 3,
                        "fuzzy": {
                            "mask_rows_hex": ["FF"] * 8,
                            "best_characters": ["나"],
                            "best_codepoints": [ord("나")],
                            "best_distance": 8,
                            "distance_margin": 1,
                        },
                        "non_hangul": {
                            "status": "unmatched",
                            "candidate_characters": [],
                            "candidate_codepoints": [],
                        },
                    },
                ]
            },
        )
        self.assertEqual(counts["glyph_card_count"], 2)
        self.assertEqual(
            counts["ambiguous_exact_non_hangul_card_count"], 1
        )
        self.assertEqual(counts["unmatched_non_hangul_card_count"], 1)
        html = render_runtime_glyph_review_html(
            cards=cards, captured_utc="2026-07-31T05:00:00Z"
        )
        self.assertIn("synthetic source", html)
        self.assertIn("스크린샷", html)

    def test_builds_and_validates_fixed_safe_receipt(self) -> None:
        review = {
            "glyph_card_count": 2,
            "glyph_occurrence_count": 2,
            "source_context_occurrence_count": 2,
            "unique_exact_non_hangul_card_count": 0,
            "equivalent_exact_non_hangul_card_count": 0,
            "ambiguous_exact_non_hangul_card_count": 1,
            "unmatched_non_hangul_card_count": 1,
            "out_of_range_non_hangul_card_count": 0,
            "missing_non_hangul_card_count": 0,
            "maximum_exact_candidate_count": 2,
            "maximum_fuzzy_candidate_count": 1,
        }
        artifact = build_runtime_context_glyph_review(
            target_sha256="1" * 64,
            runtime_context_glyph_demand_sha256="2" * 64,
            runtime_context_glyph_candidates_sha256="3" * 64,
            local_review_packet_sha256="4" * 64,
            review=review,
            captured_utc="2026-07-31T05:00:00Z",
        )
        validate_runtime_context_glyph_review(artifact)
        self.assertFalse(artifact["automatic_character_selection_allowed"])
        self.assertFalse(artifact["translation_build_eligible"])
        unsafe = deepcopy(artifact)
        unsafe["cards"] = [{"character": "가"}]
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_runtime_context_glyph_review(unsafe)


if __name__ == "__main__":
    unittest.main()
