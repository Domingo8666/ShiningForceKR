from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from tools.v5_1_test_display_review import (
    validate_display_review,
    write_display_review,
)


def failed_review() -> dict[str, object]:
    return {
        "artifact_kind": "sanitized-s25u-test-display-review",
        "schema_version": 1,
        "baseline_target_sha256": "1" * 64,
        "test_target_sha256": "2" * 64,
        "capture_png_sha256s": ["3" * 64, "4" * 64],
        "reviewed_stream": {
            "physical_start": 0x203DE,
            "logical_start": 0x43DE,
            "mapped_bank": 8,
        },
        "rejected_physical_starts": [0x203DE],
        "result": "phrase-absent-fail",
        "observations": {
            "test_phrase_visible": False,
            "surrounding_text_readable": True,
            "portrait_intact": True,
            "dialogue_box_intact": True,
            "post_advance_cleared": True,
        },
        "translation_build_eligible": False,
        "next_checkpoint": "try-next-runtime-observed-stream",
    }


class TestDisplayReviewTests(unittest.TestCase):
    def test_failed_review_is_safe_and_writable(self) -> None:
        review = failed_review()
        validate_display_review(review)
        with tempfile.TemporaryDirectory() as directory:
            path = write_display_review(Path(directory), review)
            self.assertTrue(path.is_file())

    def test_failed_review_requires_absent_phrase(self) -> None:
        review = copy.deepcopy(failed_review())
        review["observations"]["test_phrase_visible"] = True
        with self.assertRaisesRegex(ValueError, "phrase is absent"):
            validate_display_review(review)

    def test_review_never_promotes_translation_build(self) -> None:
        review = failed_review()
        review["translation_build_eligible"] = True
        with self.assertRaisesRegex(ValueError, "cannot enable"):
            validate_display_review(review)


if __name__ == "__main__":
    unittest.main()
