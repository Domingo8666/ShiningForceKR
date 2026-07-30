from __future__ import annotations

import unittest

from tools.run_s25u_runtime_probe import validate_runtime_failure_receipt
from tools.v5_1_runtime_stage_failure import build_stage_failure_receipt


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


if __name__ == "__main__":
    unittest.main()
