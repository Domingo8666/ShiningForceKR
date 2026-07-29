from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.v5_1_runtime_observation import (
    PUBLISH_RELATIVE_PATH,
    build_runtime_observation,
    validate_runtime_observation,
    write_runtime_observation,
)


def ranges() -> list[dict[str, int]]:
    return [
        {
            "slot": 0,
            "expected_bank": 0,
            "logical_start": 0x0B7A,
            "logical_end": 0x0C2E,
        },
        {
            "slot": 1,
            "expected_bank": 0,
            "logical_start": 0x4B7A,
            "logical_end": 0x4C2E,
        },
        {
            "slot": 2,
            "expected_bank": 0,
            "logical_start": 0x8B7A,
            "logical_end": 0x8C2E,
        },
    ]


def hit() -> dict[str, object]:
    return {
        **ranges()[1],
        "pc_after": 0x8123,
        "physical_pc_after": 0x88123,
        "executing_bank": 0x22,
        "mapper_control": 0,
        "slot0_bank": 0,
        "slot1_bank": 0,
        "slot2_bank": 0x22,
        "registers": {
            "af": 0x1200,
            "bc": 0x4B7B,
            "de": 0x9000,
            "hl": 0x4B7B,
            "ix": 0,
            "iy": 0,
            "sp": 0xDFF0,
        },
        "trace_entries": 256,
        "call_stack_depth": 4,
    }


class RuntimeObservationTests(unittest.TestCase):
    def test_hit_observation_contains_only_fixed_aggregate_fields(self) -> None:
        observation = build_runtime_observation(
            target_sha256="a" * 64,
            emulator_version="3.9.14",
            frames_per_slot=1800,
            slots_attempted=[0, 1],
            breakpoint_ranges=ranges(),
            hit=hit(),
        )
        encoded = json.dumps(observation)
        self.assertTrue(observation["read_hit_observed"])
        self.assertFalse(observation["consumer_evidence_confirmed"])
        self.assertFalse(observation["translation_build_eligible"])
        self.assertNotIn("trace_lines", encoded)
        self.assertNotIn("decoded_text", encoded)
        self.assertNotIn("file_path", encoded)

    def test_no_hit_observation_keeps_promotion_gate_closed(self) -> None:
        observation = build_runtime_observation(
            target_sha256="b" * 64,
            emulator_version="3.9.14",
            frames_per_slot=1800,
            slots_attempted=[0, 1, 2],
            breakpoint_ranges=ranges(),
            hit=None,
        )
        self.assertEqual(
            observation["status"], "runtime-read-hit-not-observed"
        )
        self.assertIsNone(observation["hit"])
        validate_runtime_observation(observation)

    def test_multiple_ranked_candidate_ranges_are_safe(self) -> None:
        candidate_ranges = ranges() + [
            {
                "slot": 1,
                "expected_bank": 6,
                "logical_start": 0x427D,
                "logical_end": 0x42E8,
            },
            {
                "slot": 2,
                "expected_bank": 6,
                "logical_start": 0x827D,
                "logical_end": 0x82E8,
            },
        ]
        observation = build_runtime_observation(
            target_sha256="e" * 64,
            emulator_version="3.9.14",
            frames_per_slot=1800,
            slots_attempted=[0, 1, 2],
            breakpoint_ranges=candidate_ranges,
            hit=None,
        )
        validate_runtime_observation(observation)
        self.assertEqual(len(observation["probe"]["breakpoint_ranges"]), 5)

    def test_schema_rejects_raw_extra_fields(self) -> None:
        observation = build_runtime_observation(
            target_sha256="c" * 64,
            emulator_version="3.9.14",
            frames_per_slot=1800,
            slots_attempted=[0],
            breakpoint_ranges=ranges(),
            hit=hit(),
        )
        observation["trace_lines"] = ["ROM bytes"]
        with self.assertRaises(ValueError):
            validate_runtime_observation(observation)

    def test_writer_uses_fixed_device_path(self) -> None:
        observation = build_runtime_observation(
            target_sha256="d" * 64,
            emulator_version="3.9.14",
            frames_per_slot=1800,
            slots_attempted=[0],
            breakpoint_ranges=ranges(),
            hit=None,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_runtime_observation(root, observation)
            self.assertEqual(path, root / PUBLISH_RELATIVE_PATH)
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")), observation
            )


if __name__ == "__main__":
    unittest.main()
