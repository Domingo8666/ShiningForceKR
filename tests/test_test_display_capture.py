from __future__ import annotations

import base64
import copy
import unittest

from tools.patch_io import PatchError, sha256_bytes
from tools.v5_1_test_display_capture import (
    _build_safe_capture,
    _parse_screenshot,
    validate_display_capture,
)


PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC"
    "AAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def build_report() -> dict[str, object]:
    return {
        "baseline_target_sha256": "1" * 64,
        "test_target_sha256": "2" * 64,
    }


def resolution() -> dict[str, object]:
    return {
        "target_read": {
            "slot": 2,
            "logical_access": 0x8123,
            "expected_bank": 0x2A,
        }
    }


class TestDisplayCaptureTests(unittest.TestCase):
    def test_png_payload_is_verified_before_hashing(self) -> None:
        png, metadata = _parse_screenshot(
            {
                "mimeType": "image/png",
                "data": base64.b64encode(PNG_1X1).decode("ascii"),
                "width": 1,
                "height": 1,
            }
        )
        self.assertEqual(png, PNG_1X1)
        self.assertEqual(metadata["width"], 1)
        self.assertEqual(metadata["height"], 1)
        self.assertEqual(metadata["png_sha256"], sha256_bytes(PNG_1X1))

    def test_malformed_or_mismatched_png_fails_closed(self) -> None:
        with self.assertRaisesRegex(PatchError, "PNG header"):
            _parse_screenshot(
                {
                    "mimeType": "image/png",
                    "data": base64.b64encode(b"not a png").decode("ascii"),
                    "width": 1,
                    "height": 1,
                }
            )
        with self.assertRaisesRegex(PatchError, "dimensions disagree"):
            _parse_screenshot(
                {
                    "mimeType": "image/png",
                    "data": base64.b64encode(PNG_1X1).decode("ascii"),
                    "width": 2,
                    "height": 1,
                }
            )

    def test_confirmed_target_read_requires_local_visual_review(self) -> None:
        capture = _build_safe_capture(
            build_report=build_report(),
            resolution=resolution(),
            emulator_version="3.9.14",
            mapped_bank=0x2A,
            captures=[
                {
                    "frame_after_hit": 30,
                    "width": 160,
                    "height": 144,
                    "png_sha256": "3" * 64,
                }
            ],
        )
        self.assertEqual(
            capture["status"],
            "capture-ready-human-review-required",
        )
        self.assertTrue(capture["target_read"]["confirmed"])
        self.assertIsNone(capture["visual_review"]["result"])
        self.assertFalse(capture["translation_build_eligible"])
        validate_display_capture(capture)

    def test_missing_runtime_read_does_not_claim_capture_success(self) -> None:
        capture = _build_safe_capture(
            build_report=build_report(),
            resolution=resolution(),
            emulator_version="3.9.14",
            mapped_bank=None,
            captures=[],
        )
        self.assertEqual(
            capture["status"],
            "runtime-target-read-not-observed",
        )
        self.assertFalse(capture["target_read"]["confirmed"])
        validate_display_capture(capture)

    def test_inconsistent_ready_state_is_rejected(self) -> None:
        capture = _build_safe_capture(
            build_report=build_report(),
            resolution=resolution(),
            emulator_version="3.9.14",
            mapped_bank=0x2A,
            captures=[
                {
                    "frame_after_hit": 30,
                    "width": 160,
                    "height": 144,
                    "png_sha256": "3" * 64,
                }
            ],
        )
        broken = copy.deepcopy(capture)
        broken["captures"] = []
        with self.assertRaisesRegex(ValueError, "status and evidence"):
            validate_display_capture(broken)


if __name__ == "__main__":
    unittest.main()
