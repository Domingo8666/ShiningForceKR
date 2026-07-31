from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_source_target_structural_corroboration import (  # noqa: E402
    analyze_structural_corroboration,
    build_source_target_structural_corroboration,
    validate_source_target_structural_corroboration,
)


def _pair(index: int, speaker: str | None, controls: list[int]) -> dict:
    tokens = [
        {"kind": "control", "symbol": symbol}
        for symbol in controls
    ]
    tokens.append({"kind": "glyph", "text": "가"})
    tokens.append({"kind": "terminator"})
    return {
        "pair_index": index,
        "speaker": speaker,
        "target_record": {"tokens": tokens},
    }


class SourceTargetStructuralCorroborationTests(unittest.TestCase):
    def test_finds_repeated_transition_and_speaker_corroboration(self) -> None:
        pairs = [
            _pair(0, "a", [1]),
            _pair(1, "a", [1]),
            _pair(2, "b", [2]),
            _pair(3, "b", [2]),
            _pair(4, "b", [2]),
            _pair(5, "a", [1]),
            _pair(6, "a", [1]),
        ]
        counts, local = analyze_structural_corroboration(pairs)
        self.assertTrue(local["structural_corroboration_found"])
        self.assertEqual(counts["source_speaker_transition_count"], 2)
        self.assertEqual(
            counts["target_control_signature_transition_count"],
            2,
        )
        self.assertEqual(counts["coincident_transition_count"], 2)
        self.assertEqual(
            counts["speaker_pure_repeat_supported_signature_count"],
            2,
        )

    def test_reports_insufficient_evidence_without_controls(self) -> None:
        pairs = [
            _pair(0, "a", []),
            _pair(1, "b", []),
            _pair(2, "a", []),
        ]
        counts, local = analyze_structural_corroboration(pairs)
        self.assertFalse(local["structural_corroboration_found"])
        self.assertEqual(counts["pair_with_target_control_count"], 0)
        self.assertEqual(
            counts["distinct_target_control_signature_count"],
            1,
        )

    def test_builds_candidate_only_safe_receipt(self) -> None:
        counts, local = analyze_structural_corroboration(
            [
                _pair(0, "a", []),
                _pair(1, "b", []),
            ]
        )
        artifact = build_source_target_structural_corroboration(
            target_sha256="1" * 64,
            source_section_projection_sha256="2" * 64,
            local_analysis_sha256="3" * 64,
            corroboration=counts,
            structural_corroboration_found=bool(
                local["structural_corroboration_found"]
            ),
            captured_utc="2026-07-31T00:00:00Z",
        )
        validate_source_target_structural_corroboration(artifact)
        self.assertEqual(
            artifact["status"],
            "structural-corroboration-insufficient",
        )
        self.assertFalse(artifact["source_pairing_complete"])
        self.assertFalse(artifact["translation_build_eligible"])
        unsafe = deepcopy(artifact)
        unsafe["speaker"] = "must remain local"
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_source_target_structural_corroboration(unsafe)

    def test_rejects_unknown_target_token_kind(self) -> None:
        pair = _pair(0, "a", [])
        pair["target_record"]["tokens"].append({"kind": "unknown"})
        with self.assertRaisesRegex(ValueError, "token kind"):
            analyze_structural_corroboration([pair])


if __name__ == "__main__":
    unittest.main()
