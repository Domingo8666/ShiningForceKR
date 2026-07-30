from __future__ import annotations

import base64
from pathlib import Path
import tempfile
import unittest

from tools.v5_1_progress_preview import (
    PUBLISH_IMAGE_RELATIVE_PATH,
    PUBLISH_RECEIPT_RELATIVE_PATH,
    load_validated_progress_image,
    validate_progress_preview,
    write_progress_preview,
)


PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC"
    "AAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


class ProgressPreviewTests(unittest.TestCase):
    def test_writes_exact_build_bound_preview_and_keeps_automation_running(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "evidence/local/v5_1_test_phrase/test/frame_0090.png"
            source.parent.mkdir(parents=True)
            source.write_bytes(PNG_1X1)
            digest = (
                "431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460"
            )
            safe_capture = {
                "status": "capture-ready-human-review-required",
                "baseline_target_sha256": "1" * 64,
                "test_target_sha256": "2" * 64,
                "captures": [
                    {
                        "frame_after_hit": 90,
                        "width": 1,
                        "height": 1,
                        "png_sha256": digest,
                    }
                ],
            }
            local_capture = {
                "captures": [
                    {
                        "file": str(source),
                        "frame_after_hit": 90,
                        "width": 1,
                        "height": 1,
                        "png_sha256": digest,
                    }
                ]
            }
            receipt = write_progress_preview(root, safe_capture, local_capture)
            self.assertIsNotNone(receipt)
            assert receipt is not None
            validate_progress_preview(receipt)
            self.assertTrue(receipt["auto_continue"])
            self.assertEqual(
                load_validated_progress_image(root, receipt),
                root / PUBLISH_IMAGE_RELATIVE_PATH,
            )
            self.assertTrue((root / PUBLISH_RECEIPT_RELATIVE_PATH).is_file())

    def test_does_not_publish_before_a_real_capture_is_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIsNone(
                write_progress_preview(
                    root,
                    {
                        "status": "runtime-target-read-not-observed",
                        "captures": [],
                    },
                    {"captures": []},
                )
            )
            self.assertFalse((root / PUBLISH_IMAGE_RELATIVE_PATH).exists())


if __name__ == "__main__":
    unittest.main()
