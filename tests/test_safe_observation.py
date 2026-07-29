from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.v5_1_safe_observation import (
    PUBLISH_RELATIVE_PATH,
    build_safe_observation,
    compact_summary,
    validate_safe_observation,
    write_safe_observation,
)
from tools.v5_1_trace_plan import build_trace_plan


def synthetic_trace_plan() -> dict[str, object]:
    rom = bytearray(b"\xFF" * 0x10000)
    rom[0x200:0x208] = bytes.fromhex("3e0032fdff217d0b")
    consumer = {
        "input": {"sha256": "a" * 64},
        "pointer_table_candidates": {
            "ranked_triplet_runs": [
                {
                    "file_offset": 0x0B7D,
                    "end_exclusive": 0x0B7D + 12 * 3,
                    "format": "bank_addr_le",
                    "entries": 12,
                    "score": 100.0,
                    "unique_target_ratio": 0.8,
                    "monotonic_ratio": 0.9,
                    "original_512k_target_ratio": 1.0,
                    "decode_probe": {
                        "attempted": 12,
                        "bounded_terminations": 10,
                        "termination_ratio": 0.8333,
                        "median_symbols": 24.0,
                    },
                },
                {
                    "file_offset": 0x0B7C,
                    "end_exclusive": 0x0B7C + 12 * 3,
                    "format": "addr_le_bank",
                    "entries": 12,
                    "score": 90.0,
                    "unique_target_ratio": 0.75,
                    "monotonic_ratio": 0.85,
                    "original_512k_target_ratio": 1.0,
                    "decode_probe": {
                        "attempted": 12,
                        "bounded_terminations": 9,
                        "termination_ratio": 0.75,
                        "median_symbols": 20.0,
                    },
                }
            ],
            "ranked_pair_runs": [],
        },
    }
    return build_trace_plan(bytes(rom), consumer)


class SafeObservationTests(unittest.TestCase):
    def test_whitelist_omits_raw_text_paths_and_reference_examples(self) -> None:
        plan = synthetic_trace_plan()
        selected = plan["selected_hypothesis"]
        self.assertIsNotNone(selected)
        selected["raw_bytes"] = "DO_NOT_SHARE_RAW_BYTES"
        selected["decoded_text"] = "DO_NOT_SHARE_DECODED_TEXT"
        selected["local_path"] = "/storage/emulated/0/ROM/private.gg"

        observation = build_safe_observation(plan)
        encoded = json.dumps(observation)
        self.assertNotIn("DO_NOT_SHARE", encoded)
        self.assertNotIn("/storage/", encoded)
        self.assertNotIn("examples", encoded)
        self.assertFalse(observation["consumer_evidence_confirmed"])
        self.assertFalse(observation["translation_build_eligible"])

        selected_safe = observation["ranked_hypotheses"][0]
        self.assertEqual(selected_safe["file_offset"], 0x0B7D)
        self.assertEqual(selected_safe["mapper_coupled_pointer_load_count"], 1)
        self.assertEqual(selected_safe["decode_probe"]["bounded_terminations"], 10)
        self.assertEqual(len(observation["selected_alignment_cluster"]), 2)
        self.assertEqual(observation["selected_watch"]["file_start"], 0x0B7C)
        self.assertIn("selected=0x000B7D", compact_summary(observation))
        self.assertIn("alignments=2", compact_summary(observation))

    def test_schema_rejects_extra_fields(self) -> None:
        observation = build_safe_observation(synthetic_trace_plan())
        observation["raw_bytes"] = "not allowed"
        with self.assertRaises(ValueError):
            validate_safe_observation(observation)

    def test_writer_uses_only_fixed_analysis_path(self) -> None:
        observation = build_safe_observation(synthetic_trace_plan())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_safe_observation(root, observation)
            self.assertEqual(path, root / PUBLISH_RELATIVE_PATH)
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded, observation)


if __name__ == "__main__":
    unittest.main()
