from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_runtime_context_glyph_preservation import (  # noqa: E402
    EXPECTED_TARGET_SHA256,
    analyze_runtime_glyph_preservation,
    build_runtime_context_glyph_preservation,
    validate_runtime_context_glyph_preservation,
)


def _card(page: int, symbol: int, rows: list[str]) -> dict:
    return {
        "page": page,
        "symbol": symbol,
        "occurrence_count": 1,
        "mask_rows_hex": rows,
    }


class RuntimeContextGlyphPreservationTests(unittest.TestCase):
    def test_classifies_blank_marker_and_symbol_without_unicode(self) -> None:
        counts, records = analyze_runtime_glyph_preservation(
            [
                _card(1, 2, ["00"] * 8),
                _card(1, 3, ["00"] * 7 + ["01"]),
                _card(1, 4, ["18", "18", "7E", "3C", "18", "7E", "00", "00"]),
            ]
        )
        self.assertEqual(counts["blank_cell_distinct_count"], 1)
        self.assertEqual(counts["one_pixel_marker_distinct_count"], 1)
        self.assertEqual(counts["visual_symbol_distinct_count"], 1)
        self.assertEqual(
            counts["preserve_original_glyph_distinct_count"], 3
        )
        self.assertEqual(counts["unicode_character_assignment_count"], 0)
        self.assertTrue(
            all(record["unicode_character"] is None for record in records)
        )

    def test_rejects_duplicate_coordinates(self) -> None:
        card = _card(1, 2, ["00"] * 8)
        with self.assertRaisesRegex(ValueError, "duplicated"):
            analyze_runtime_glyph_preservation([card, deepcopy(card)])

    def test_builds_fixed_safe_preservation_receipt(self) -> None:
        counts, _ = analyze_runtime_glyph_preservation(
            [
                _card(1, 2, ["00"] * 8),
                _card(1, 3, ["00"] * 7 + ["01"]),
                _card(1, 4, ["18", "18", "7E", "3C", "18", "7E", "00", "00"]),
            ]
        )
        artifact = build_runtime_context_glyph_preservation(
            target_sha256=EXPECTED_TARGET_SHA256,
            runtime_context_glyph_candidates_sha256="1" * 64,
            runtime_context_glyph_review_sha256="2" * 64,
            local_preservation_sha256="3" * 64,
            preservation=counts,
            captured_utc="2026-07-31T06:00:00Z",
        )
        validate_runtime_context_glyph_preservation(artifact)
        self.assertTrue(artifact["human_visual_review_complete"])
        self.assertTrue(artifact["original_glyph_tokens_preserved"])
        self.assertFalse(artifact["automatic_character_selection_allowed"])
        self.assertFalse(artifact["translation_build_eligible"])
        unsafe = deepcopy(artifact)
        unsafe["characters"] = ["가"]
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_runtime_context_glyph_preservation(unsafe)


if __name__ == "__main__":
    unittest.main()
