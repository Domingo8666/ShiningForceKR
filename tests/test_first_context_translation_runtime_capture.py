from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_first_context_translation_runtime_capture import (  # noqa: E402
    CONFIRMED_ORDINAL,
    CONFIRMED_SELECTOR,
    LOCAL_REVIEW_PATH,
    RUNTIME_CAPTURE_POLICY_VERSION,
    _write_review,
    build_first_context_translation_runtime_capture,
    reusable_runtime_capture_policy_matches,
    select_target_runtime_sequence,
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

    def test_filters_interleaved_decoder_screens_from_review_sequence(
        self,
    ) -> None:
        observations = [
            {"selector": CONFIRMED_SELECTOR, "ordinal": CONFIRMED_ORDINAL},
            {"selector": CONFIRMED_SELECTOR + 1, "ordinal": 0},
            {"selector": CONFIRMED_SELECTOR, "ordinal": CONFIRMED_ORDINAL + 1},
            {"selector": CONFIRMED_SELECTOR, "ordinal": CONFIRMED_ORDINAL + 2},
        ]
        screens = [{"file": f"screen-{index}.png"} for index in range(4)]
        selected_observations, selected_screens = select_target_runtime_sequence(
            observations=observations,
            screenshots=screens,
            expected_entry_count=3,
        )
        self.assertEqual(
            [row["ordinal"] for row in selected_observations],
            [
                CONFIRMED_ORDINAL,
                CONFIRMED_ORDINAL + 1,
                CONFIRMED_ORDINAL + 2,
            ],
        )
        self.assertEqual(
            [screen["file"] for screen in selected_screens],
            ["screen-0.png", "screen-2.png", "screen-3.png"],
        )

    def test_keeps_same_selector_screens_for_separate_sequence_validation(
        self,
    ) -> None:
        observations = [
            {"selector": CONFIRMED_SELECTOR, "ordinal": CONFIRMED_ORDINAL},
            {"selector": CONFIRMED_SELECTOR, "ordinal": CONFIRMED_ORDINAL + 7},
        ]
        screens = [{"file": "anchor.png"}, {"file": "later.png"}]
        selected_observations, selected_screens = select_target_runtime_sequence(
            observations=observations,
            screenshots=screens,
            expected_entry_count=2,
        )
        self.assertEqual(len(selected_observations), 2)
        self.assertEqual(len(selected_screens), 2)

    def test_writes_partial_review_with_expected_total(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            screenshots = [
                {"file": str(root / "capture" / f"screen-{index}.png")}
                for index in range(2)
            ]
            _write_review(
                root=root,
                translations=[f"번역 {index}" for index in range(5)],
                screenshots=screenshots,
            )
            document = (root / LOCAL_REVIEW_PATH).read_text(encoding="utf-8")
            self.assertIn("캡처된 목표 화면: 2/5", document)
            self.assertIn("대사 2/5", document)
            self.assertNotIn("대사 3/5", document)

    def test_rejects_capture_from_older_runtime_policy(self) -> None:
        self.assertFalse(reusable_runtime_capture_policy_matches({}))
        self.assertFalse(
            reusable_runtime_capture_policy_matches(
                {
                    "capture_policy_version":
                        RUNTIME_CAPTURE_POLICY_VERSION - 1,
                    "capture_attempt_limit": 20,
                }
            )
        )
        self.assertTrue(
            reusable_runtime_capture_policy_matches(
                {
                    "capture_policy_version": RUNTIME_CAPTURE_POLICY_VERSION,
                    "capture_attempt_limit": 20,
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
