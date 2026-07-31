from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_first_context_translation_visual_review import (  # noqa: E402
    build_first_context_translation_visual_review,
    validate_first_context_translation_visual_review,
)
import json


class FirstContextTranslationVisualReviewTests(unittest.TestCase):
    def test_records_user_visible_failure_without_private_paths(self) -> None:
        value = build_first_context_translation_visual_review(
            runtime_capture_sha256="a" * 64,
            review_evidence_sha256="b" * 64,
            review={
                "expected_screen_count": 5,
                "reviewed_screen_count": 5,
                "missing_dialogue_screen_count": 1,
                "corrupted_text_screen_count": 2,
                "wrong_context_screen_count": 1,
            },
            captured_utc="2026-07-31T12:00:00Z",
        )
        self.assertEqual(
            value["status"],
            "first-context-translation-runtime-visual-fail",
        )
        self.assertFalse(value["runtime_layout_confirmed"])
        self.assertFalse(value["translation_build_eligible"])
        unsafe = deepcopy(value)
        unsafe["screenshot_path"] = "private.png"
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_first_context_translation_visual_review(unsafe)

    def test_four_screens_cannot_complete_a_five_screen_review(self) -> None:
        value = build_first_context_translation_visual_review(
            runtime_capture_sha256="a" * 64,
            review_evidence_sha256="b" * 64,
            review={
                "expected_screen_count": 5,
                "reviewed_screen_count": 4,
                "missing_dialogue_screen_count": 0,
                "corrupted_text_screen_count": 0,
                "wrong_context_screen_count": 0,
            },
            captured_utc="2026-07-31T12:00:00Z",
        )
        self.assertEqual(
            value["status"],
            "first-context-translation-runtime-visual-incomplete",
        )
        self.assertFalse(value["human_visual_review_complete"])

    def test_published_review_matches_current_safe_schema(self) -> None:
        path = (
            ROOT
            / "analysis/device/"
            / "v5_1_latest_first_context_translation_visual_review.json"
        )
        value = json.loads(path.read_text(encoding="utf-8"))
        validate_first_context_translation_visual_review(value)
        self.assertEqual(
            value["status"],
            "first-context-translation-runtime-visual-fail",
        )
        self.assertFalse(value["runtime_layout_confirmed"])


if __name__ == "__main__":
    unittest.main()
