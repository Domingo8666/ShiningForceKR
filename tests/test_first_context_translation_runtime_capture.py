from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_first_context_translation_runtime_capture import (  # noqa: E402
    build_first_context_translation_runtime_capture,
    validate_first_context_translation_runtime_capture,
)


class FirstContextTranslationRuntimeCaptureTests(unittest.TestCase):
    def _counts(self) -> dict[str, int]:
        return {
            "captured_entry_count": 4,
            "post_anchor_entry_count": 3,
            "same_selector_post_anchor_entry_count": 3,
            "different_selector_post_anchor_entry_count": 0,
            "consecutive_same_selector_step_count": 3,
            "nonconsecutive_same_selector_step_count": 0,
            "distinct_screen_hash_count": 4,
            "advance_attempt_count": 8,
            "runtime_initial_context_observation_count": 4,
            "runtime_initial_context_distinct_count": 1,
        }

    def _build(
        self,
        counts: dict[str, int],
        *,
        expected_entry_count: int = 4,
    ) -> dict[str, object]:
        return build_first_context_translation_runtime_capture(
            baseline_target_sha256="a" * 64,
            test_target_sha256="b" * 64,
            first_context_translation_test_build_sha256="c" * 64,
            source_runtime_sequence_sha256="d" * 64,
            local_capture_sha256="e" * 64,
            expected_entry_count=expected_entry_count,
            runtime_sequence=counts,
            captured_utc="2026-07-31T10:00:00Z",
        )

    def test_builds_ready_capture_receipt(self) -> None:
        value = self._build(self._counts())
        self.assertEqual(
            value["status"],
            "first-context-translation-runtime-capture-ready",
        )
        self.assertTrue(value["target_entry_sequence_confirmed"])
        self.assertTrue(value["human_visual_review_required"])
        self.assertFalse(value["runtime_layout_confirmed"])

    def test_incomplete_sequence_stays_blocked(self) -> None:
        counts = self._counts()
        counts["distinct_screen_hash_count"] = 3
        value = self._build(counts)
        self.assertEqual(
            value["status"],
            "first-context-translation-runtime-capture-incomplete",
        )
        self.assertFalse(value["target_entry_sequence_confirmed"])
        self.assertFalse(value["translation_build_eligible"])

    def test_accepts_consecutive_post_translation_regression_screen(
        self,
    ) -> None:
        counts = self._counts()
        counts.update(
            {
                "captured_entry_count": 5,
                "post_anchor_entry_count": 4,
                "same_selector_post_anchor_entry_count": 4,
                "consecutive_same_selector_step_count": 4,
                "distinct_screen_hash_count": 5,
                "advance_attempt_count": 7,
                "runtime_initial_context_observation_count": 5,
            }
        )
        value = self._build(counts, expected_entry_count=5)
        self.assertEqual(
            value["status"],
            "first-context-translation-runtime-capture-ready",
        )
        self.assertTrue(value["target_entry_sequence_confirmed"])

    def test_rejects_partial_capture_for_five_approved_entries(self) -> None:
        value = self._build(self._counts(), expected_entry_count=5)
        self.assertEqual(
            value["status"],
            "first-context-translation-runtime-capture-incomplete",
        )
        self.assertFalse(value["target_entry_sequence_confirmed"])

    def test_rejects_unexpected_private_screen_data(self) -> None:
        value = self._build(self._counts())
        unsafe = deepcopy(value)
        unsafe["screens"] = [{"file": "capture.png"}]
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_first_context_translation_runtime_capture(unsafe)


if __name__ == "__main__":
    unittest.main()
