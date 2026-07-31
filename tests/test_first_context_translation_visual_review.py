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


class FirstContextTranslationVisualReviewTests(unittest.TestCase):
    def test_records_user_visible_failure_without_private_paths(self) -> None:
        value = build_first_context_translation_visual_review(
            runtime_capture_sha256="a" * 64,
            review_evidence_sha256="b" * 64,
            review={
                "reviewed_screen_count": 4,
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


if __name__ == "__main__":
    unittest.main()
