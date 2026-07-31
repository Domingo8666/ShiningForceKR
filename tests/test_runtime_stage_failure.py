from __future__ import annotations

import unittest

from tools.run_s25u_runtime_probe import validate_runtime_failure_receipt
from tools.v5_1_runtime_stage_failure import (
    build_first_context_runtime_capture_failure,
    build_stage_failure_receipt,
    validate_first_context_runtime_capture_failure,
)


class RuntimeStageFailureTests(unittest.TestCase):
    def test_pipeline_substage_receipt_is_sanitized(self) -> None:
        receipt = build_stage_failure_receipt("test-display-capture")
        self.assertEqual(
            receipt,
            {
                "schema_version": 1,
                "failure_stage": "test-display-capture",
                "failure_kind": "runtime-error",
                "mcp_method": None,
            },
        )
        self.assertNotIn("/", str(receipt))
        self.assertNotIn("\\", str(receipt))
        validate_runtime_failure_receipt(receipt)

    def test_baseline_capture_is_a_distinct_safe_stage(self) -> None:
        receipt = build_stage_failure_receipt("baseline-display-capture")
        self.assertEqual(receipt["failure_stage"], "baseline-display-capture")
        validate_runtime_failure_receipt(receipt)

    def test_display_postprocessing_stages_are_safe(self) -> None:
        for stage in (
            "display-capture-preflight",
            "display-version-check",
            "display-pixel-comparison",
            "display-comparison-artifact",
            "display-capture-artifact",
        ):
            with self.subTest(stage=stage):
                receipt = build_stage_failure_receipt(stage)
                self.assertEqual(receipt["failure_stage"], stage)
                validate_runtime_failure_receipt(receipt)

    def test_test_patch_diagnostics_are_safe(self) -> None:
        for stage in (
            "test-patch-fixed-count-roundtrip",
            "test-patch-fixed-count-read-range",
            "test-patch-no-marker-candidate",
            "test-patch-marker-encoding",
            "test-patch-marker-roundtrip",
        ):
            with self.subTest(stage=stage):
                receipt = build_stage_failure_receipt(stage)
                self.assertEqual(receipt["failure_stage"], stage)
                validate_runtime_failure_receipt(receipt)

    def test_unknown_pipeline_substage_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_stage_failure_receipt("unknown-stage")

    def test_runtime_capture_failure_is_safe_to_publish(self) -> None:
        runtime_failure = {
            "schema_version": 1,
            "failure_stage": "source-target-runtime-sequence",
            "failure_kind": "mcp-timeout",
            "mcp_method": "debug_get_status",
        }
        value = build_first_context_runtime_capture_failure(
            pipeline_stage="first-context-translation-runtime-capture",
            runtime_failure=runtime_failure,
            captured_utc="2026-08-01T01:00:00Z",
        )
        self.assertEqual(value["failure_kind"], "mcp-timeout")
        self.assertEqual(value["mcp_method"], "debug_get_status")
        self.assertNotIn("/", str(value))
        self.assertNotIn("\\", str(value))
        validate_first_context_runtime_capture_failure(value)


if __name__ == "__main__":
    unittest.main()
