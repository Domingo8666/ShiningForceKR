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

    def test_unknown_pipeline_substage_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_stage_failure_receipt("unknown-stage")


if __name__ == "__main__":
    unittest.main()
