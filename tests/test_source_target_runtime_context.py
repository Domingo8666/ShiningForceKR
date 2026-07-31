from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_source_target_runtime_context import (  # noqa: E402
    build_source_target_runtime_context,
    map_runtime_context,
    validate_source_target_runtime_context,
)


def _observation(ordinal: int, digest: str) -> dict:
    return {
        "selector": 2,
        "ordinal": ordinal,
        "png_sha256": digest * 64,
    }


def _pair(ordinal: int, line: int, speaker: str | None) -> dict:
    return {
        "target_selector": 2,
        "target_ordinal": ordinal,
        "source_section_index": 3,
        "source_line_index": line,
        "source_text": f"source {line}",
        "speaker": speaker,
        "pairing_basis": "single-anchor-relative-offset",
        "target_record": {
            "translation_text": f"대상 {line}",
            "quality_tier": "translation-ready",
        },
    }


class SourceTargetRuntimeContextTests(unittest.TestCase):
    def test_maps_four_runtime_entries_to_one_consecutive_source_window(
        self,
    ) -> None:
        observations = [
            _observation(147, "1"),
            _observation(148, "2"),
            _observation(149, "3"),
            _observation(150, "4"),
        ]
        pairs = [
            _pair(147, 10, "a"),
            _pair(148, 11, "a"),
            _pair(149, 12, "b"),
            _pair(150, 13, None),
        ]
        counts, local = map_runtime_context(
            observations=observations,
            pairs=pairs,
        )
        self.assertTrue(
            local["runtime_context_window_pairing_complete"]
        )
        self.assertEqual(
            counts["uniquely_mapped_runtime_entry_count"],
            4,
        )
        self.assertEqual(
            counts["consecutive_source_line_step_count"],
            3,
        )
        self.assertEqual(counts["distinct_speaker_count"], 2)

    def test_reports_an_unmapped_runtime_entry(self) -> None:
        counts, local = map_runtime_context(
            observations=[
                _observation(147, "1"),
                _observation(148, "2"),
            ],
            pairs=[_pair(147, 10, "a")],
        )
        self.assertFalse(
            local["runtime_context_window_pairing_complete"]
        )
        self.assertEqual(counts["unmapped_runtime_entry_count"], 1)

    def test_builds_fixed_window_only_safe_receipt(self) -> None:
        counts, local = map_runtime_context(
            observations=[
                _observation(147, "1"),
                _observation(148, "2"),
                _observation(149, "3"),
                _observation(150, "4"),
            ],
            pairs=[
                _pair(147, 10, "a"),
                _pair(148, 11, "a"),
                _pair(149, 12, "b"),
                _pair(150, 13, None),
            ],
        )
        artifact = build_source_target_runtime_context(
            target_sha256="1" * 64,
            source_section_projection_sha256="2" * 64,
            runtime_sequence_sha256="3" * 64,
            local_context_sha256="4" * 64,
            context=counts,
            runtime_context_window_pairing_complete=bool(
                local["runtime_context_window_pairing_complete"]
            ),
            captured_utc="2026-07-31T02:00:00Z",
        )
        validate_source_target_runtime_context(artifact)
        self.assertTrue(
            artifact["runtime_context_window_pairing_complete"]
        )
        self.assertFalse(artifact["source_pairing_complete"])
        self.assertFalse(artifact["translation_build_eligible"])
        unsafe = deepcopy(artifact)
        unsafe["source_text"] = "must remain local"
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_source_target_runtime_context(unsafe)


if __name__ == "__main__":
    unittest.main()
