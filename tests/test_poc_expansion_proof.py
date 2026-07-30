from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from tools.v5_1_poc_expansion_proof import (
    build_poc_expansion_proof,
    validate_poc_expansion_proof,
)


ROOT = Path(__file__).resolve().parents[1]


def read_json(relative: str) -> dict[str, object]:
    value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


class PocExpansionProofTests(unittest.TestCase):
    def test_builds_from_the_published_four_glyph_frame(self) -> None:
        proof = build_poc_expansion_proof(
            ROOT,
            (
                ROOT
                / "patch"
                / "Final_Conflict_Japan_to_Korean_v5.1.bps"
            ).read_bytes(),
            read_json(
                "analysis/device/v5_1_latest_visible_entry_proof.json"
            ),
            read_json("analysis/device/v5_1_latest_display_capture.json"),
            read_json(
                "analysis/device/v5_1_latest_display_comparison.json"
            ),
            read_json("analysis/device/v5_1_latest_display_review.json"),
            read_json(
                "analysis/device/v5_1_latest_progress_preview.json"
            ),
        )
        validate_poc_expansion_proof(proof)
        self.assertEqual(proof["display_proof"]["exact_phrase_matches"], 1)
        self.assertEqual(
            proof["display_proof"]["exact_phrase_coordinate"],
            {"x": 24, "y": 112},
        )
        self.assertEqual(
            proof["next_checkpoint"],
            "extract-and-roundtrip-visible-script-record",
        )

    def test_rejects_a_non_unique_exact_phrase(self) -> None:
        proof = build_poc_expansion_proof(
            ROOT,
            (
                ROOT
                / "patch"
                / "Final_Conflict_Japan_to_Korean_v5.1.bps"
            ).read_bytes(),
            read_json(
                "analysis/device/v5_1_latest_visible_entry_proof.json"
            ),
            read_json("analysis/device/v5_1_latest_display_capture.json"),
            read_json(
                "analysis/device/v5_1_latest_display_comparison.json"
            ),
            read_json("analysis/device/v5_1_latest_display_review.json"),
            read_json(
                "analysis/device/v5_1_latest_progress_preview.json"
            ),
        )
        proof = copy.deepcopy(proof)
        proof["display_proof"]["exact_phrase_matches"] = 2
        with self.assertRaisesRegex(ValueError, "incomplete"):
            validate_poc_expansion_proof(proof)


if __name__ == "__main__":
    unittest.main()
