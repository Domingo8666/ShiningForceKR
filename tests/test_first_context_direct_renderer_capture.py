from __future__ import annotations

import copy
import unittest

from tools.v5_1_first_context_direct_renderer_capture import (
    validate_first_context_direct_renderer_capture,
)


class FirstContextDirectRendererCaptureTests(unittest.TestCase):
    def test_accepts_safe_capture_receipt(self) -> None:
        value = {
            "artifact_kind": "sanitized-v5-1-first-context-direct-renderer-capture",
            "schema_version": 1,
            "status": "direct-renderer-first-screen-captured",
            "baseline_target_sha256": "a" * 64,
            "test_target_sha256": "b" * 64,
            "first_context_translation_test_build_sha256": "c" * 64,
            "local_encoding_sha256": "d" * 64,
            "capture_png_sha256": "e" * 64,
            "captured_utc": "2026-08-02T00:00:00Z",
            "runtime_entry": {"selector": 2, "ordinal": 147},
            "direct_renderer_first_row_confirmed": True,
            "cold_boot": True,
            "human_visual_review_required": True,
            "translation_build_eligible": False,
            "next_checkpoint": "human-verify-first-direct-renderer-dialogue-screen",
        }
        validate_first_context_direct_renderer_capture(value)
        invalid = copy.deepcopy(value)
        invalid["direct_renderer_first_row_confirmed"] = False
        with self.assertRaises(ValueError):
            validate_first_context_direct_renderer_capture(invalid)


if __name__ == "__main__":
    unittest.main()
