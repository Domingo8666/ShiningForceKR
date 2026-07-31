from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_source_target_runtime_sequence import (  # noqa: E402
    build_source_target_runtime_sequence,
    summarize_runtime_sequence,
    validate_reusable_local_sequence,
    validate_source_target_runtime_sequence,
)


def _observation(selector: int, ordinal: int, digest: str) -> dict:
    return {
        "selector": selector,
        "ordinal": ordinal,
        "png_sha256": digest * 64,
    }


class SourceTargetRuntimeSequenceTests(unittest.TestCase):
    def test_accepts_three_consecutive_post_anchor_entries(self) -> None:
        observations = [
            _observation(2, 147, "1"),
            _observation(2, 148, "2"),
            _observation(2, 149, "3"),
            _observation(2, 150, "4"),
        ]
        counts, status, first = summarize_runtime_sequence(
            observations,
            advance_attempt_count=3,
        )
        self.assertEqual(
            status,
            "runtime-sequence-corroboration-ready",
        )
        self.assertTrue(first)
        self.assertEqual(
            counts["consecutive_same_selector_step_count"],
            3,
        )

    def test_reports_partial_for_a_nonconsecutive_step(self) -> None:
        counts, status, first = summarize_runtime_sequence(
            [
                _observation(2, 147, "1"),
                _observation(2, 149, "2"),
            ],
            advance_attempt_count=1,
        )
        self.assertEqual(
            status,
            "runtime-sequence-corroboration-partial",
        )
        self.assertFalse(first)
        self.assertEqual(
            counts["nonconsecutive_same_selector_step_count"],
            1,
        )

    def test_counts_other_selector_without_exposing_coordinates(self) -> None:
        counts, status, first = summarize_runtime_sequence(
            [
                _observation(2, 147, "1"),
                _observation(4, 1, "2"),
            ],
            advance_attempt_count=1,
        )
        self.assertEqual(
            status,
            "runtime-sequence-corroboration-unresolved",
        )
        self.assertFalse(first)
        self.assertEqual(
            counts["different_selector_post_anchor_entry_count"],
            1,
        )

    def test_builds_fixed_candidate_only_safe_receipt(self) -> None:
        counts, status, first = summarize_runtime_sequence(
            [
                _observation(2, 147, "1"),
                _observation(2, 148, "2"),
            ],
            advance_attempt_count=1,
        )
        artifact = build_source_target_runtime_sequence(
            baseline_target_sha256="1" * 64,
            test_target_sha256="2" * 64,
            display_capture_sha256="3" * 64,
            structural_corroboration_sha256="4" * 64,
            local_sequence_sha256="5" * 64,
            runtime_sequence=counts,
            status=status,
            first_post_anchor_step_consecutive=first,
            captured_utc="2026-07-31T01:00:00Z",
        )
        validate_source_target_runtime_sequence(artifact)
        self.assertFalse(artifact["source_pairing_complete"])
        self.assertFalse(artifact["translation_build_eligible"])
        unsafe = deepcopy(artifact)
        unsafe["ordinal"] = 148
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_source_target_runtime_sequence(unsafe)

    def test_rejects_wrong_anchor(self) -> None:
        with self.assertRaisesRegex(ValueError, "anchor observation"):
            summarize_runtime_sequence(
                [_observation(2, 146, "1")],
                advance_attempt_count=0,
            )

    def test_reuses_capture_when_only_dependency_receipt_changes(
        self,
    ) -> None:
        observations = [
            _observation(2, 147, "1"),
            _observation(2, 148, "2"),
            _observation(2, 149, "3"),
            _observation(2, 150, "4"),
        ]
        counts, status, first = summarize_runtime_sequence(
            observations,
            advance_attempt_count=3,
        )
        safe = build_source_target_runtime_sequence(
            baseline_target_sha256="1" * 64,
            test_target_sha256="2" * 64,
            display_capture_sha256="3" * 64,
            structural_corroboration_sha256="4" * 64,
            local_sequence_sha256="5" * 64,
            runtime_sequence=counts,
            status=status,
            first_post_anchor_step_consecutive=first,
            captured_utc="2026-07-31T01:00:00Z",
        )
        local = {
            "artifact_kind":
                "local-v5-1-source-target-runtime-sequence",
            "schema_version": 1,
            "baseline_target_sha256": "1" * 64,
            "test_target_sha256": "2" * 64,
            "runtime_sequence": counts,
            "observations": observations,
        }
        reused = validate_reusable_local_sequence(
            safe=safe,
            local=local,
            baseline_target_sha256="1" * 64,
            test_target_sha256="2" * 64,
            local_sequence_sha256="5" * 64,
        )
        self.assertEqual(reused, (counts, status, first))


if __name__ == "__main__":
    unittest.main()
