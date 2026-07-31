from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_first_context_translation_review import (  # noqa: E402
    build_first_context_review_rows,
    build_first_context_translation_review,
    first_context_review_batch_sha256,
    render_first_context_translation_review_html,
    validate_first_context_translation_review,
)


def _row(index: int, speaker: str) -> dict:
    return {
        "mapping_status": "unique",
        "source_section_index": 3,
        "source_line_index": 10 + index,
        "source_text": f"synthetic source {index}",
        "speaker": speaker,
    }


class FirstContextTranslationReviewTests(unittest.TestCase):
    def test_builds_four_consecutive_human_translation_cards(self) -> None:
        counts, rows = build_first_context_review_rows(
            [_row(index, "a" if index < 2 else "b") for index in range(4)]
        )
        self.assertEqual(counts["context_entry_count"], 4)
        self.assertEqual(counts["consecutive_source_line_step_count"], 3)
        self.assertEqual(counts["distinct_speaker_count"], 2)
        self.assertEqual(counts["translation_draft_entry_count"], 0)
        self.assertTrue(all(row["translation_draft"] is None for row in rows))
        html = render_first_context_translation_review_html(
            rows=rows, captured_utc="2026-07-31T07:00:00Z"
        )
        self.assertIn("synthetic source 0", html)
        self.assertIn("스크롤 캡처가 아닌 일반 스크린샷", html)

    def test_rejects_nonconsecutive_rows(self) -> None:
        rows = [_row(0, "a"), _row(2, "a")]
        with self.assertRaisesRegex(ValueError, "not consecutive"):
            build_first_context_review_rows(rows)

    def test_builds_fixed_safe_receipt_without_source_or_translation(self) -> None:
        counts, rows = build_first_context_review_rows(
            [_row(index, "a" if index < 2 else "b") for index in range(4)]
        )
        counts["preserved_non_text_glyph_occurrence_count"] = 5
        batch_sha256 = first_context_review_batch_sha256(rows)
        artifact = build_first_context_translation_review(
            target_sha256="1" * 64,
            review_batch_sha256=batch_sha256,
            source_target_runtime_context_sha256="2" * 64,
            runtime_context_glyph_preservation_sha256="3" * 64,
            local_review_packet_sha256="4" * 64,
            review=counts,
            captured_utc="2026-07-31T07:00:00Z",
        )
        validate_first_context_translation_review(artifact)
        self.assertTrue(artifact["context_pairing_complete"])
        self.assertFalse(
            artifact["translation_generated_by_mechanical_stage"]
        )
        self.assertFalse(artifact["translation_build_eligible"])
        self.assertEqual(artifact["review_batch_sha256"], batch_sha256)
        unsafe = deepcopy(artifact)
        unsafe["source_text"] = "raw"
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_first_context_translation_review(unsafe)


if __name__ == "__main__":
    unittest.main()
