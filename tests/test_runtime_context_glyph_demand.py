from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_runtime_context_glyph_demand import (  # noqa: E402
    analyze_runtime_context_glyph_demand,
    build_runtime_context_glyph_demand,
    validate_runtime_context_glyph_demand,
)


def _pair(tokens: list[dict]) -> dict:
    return {
        "source_text": "synthetic",
        "speaker": "a",
        "target_record": {
            "tokens": tokens,
            "translation_text": "가상",
            "quality_tier": "glyph-recovery",
        },
    }


class RuntimeContextGlyphDemandTests(unittest.TestCase):
    def test_classifies_single_ambiguous_and_unmatched_candidates(
        self,
    ) -> None:
        pairs = [
            _pair(
                [
                    {"kind": "glyph", "text": "가"},
                    {
                        "kind": "glyph",
                        "page": 1,
                        "symbol": 2,
                        "text": "unresolved",
                        "characters": ["나"],
                    },
                    {
                        "kind": "glyph",
                        "page": 1,
                        "symbol": 3,
                        "characters": ["다", "라"],
                    },
                    {
                        "kind": "glyph",
                        "page": 1,
                        "symbol": 4,
                        "characters": [],
                    },
                ]
            )
        ]
        counts, local = analyze_runtime_context_glyph_demand(pairs)
        self.assertEqual(
            counts["unresolved_glyph_occurrence_count"],
            3,
        )
        self.assertEqual(counts["single_candidate_occurrence_count"], 1)
        self.assertEqual(
            counts["ambiguous_candidate_occurrence_count"],
            1,
        )
        self.assertEqual(counts["unmatched_occurrence_count"], 1)
        self.assertFalse(local["automatic_character_selection_allowed"])

    def test_counts_a_fully_readable_entry(self) -> None:
        counts, _ = analyze_runtime_context_glyph_demand(
            [_pair([{"kind": "glyph", "text": "가"}])]
        )
        self.assertEqual(
            counts["human_translation_review_ready_entry_count"],
            1,
        )
        self.assertEqual(counts["glyph_blocked_entry_count"], 0)

    def test_builds_fixed_safe_receipt_without_glyph_payload(self) -> None:
        counts, _ = analyze_runtime_context_glyph_demand(
            [_pair([{"kind": "glyph", "text": "가"}])]
        )
        artifact = build_runtime_context_glyph_demand(
            target_sha256="1" * 64,
            runtime_context_sha256="2" * 64,
            source_section_projection_sha256="3" * 64,
            runtime_sequence_sha256="4" * 64,
            local_demand_sha256="5" * 64,
            demand=counts,
            captured_utc="2026-07-31T03:00:00Z",
        )
        validate_runtime_context_glyph_demand(artifact)
        self.assertTrue(artifact["glyph_recovery_complete"])
        self.assertFalse(artifact["automatic_character_selection_allowed"])
        self.assertFalse(artifact["translation_build_eligible"])
        unsafe = deepcopy(artifact)
        unsafe["characters"] = ["가"]
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_runtime_context_glyph_demand(unsafe)


if __name__ == "__main__":
    unittest.main()
