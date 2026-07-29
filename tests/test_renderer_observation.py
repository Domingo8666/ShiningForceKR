from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.v5_1_renderer_observation import (
    PUBLISH_RELATIVE_PATH,
    build_renderer_observation,
    validate_renderer_observation,
    write_renderer_observation,
)


def mappings() -> list[dict[str, int]]:
    return [
        {
            "call_site_file_offset": 0x3FD5,
            "slot": 0,
            "expected_bank": 0,
            "logical_address": 0x3FD5,
        },
        {
            "call_site_file_offset": 0x3FD5,
            "slot": 1,
            "expected_bank": 0,
            "logical_address": 0x7FD5,
        },
    ]


def hit() -> dict[str, object]:
    return {
        **mappings()[0],
        "pc_after": 0x3FD5,
        "physical_pc_after": 0x3FD5,
        "executing_bank": 0,
        "mapper_control": 0,
        "slot0_bank": 0,
        "slot1_bank": 1,
        "slot2_bank": 2,
        "registers": {
            "af": 0x1200,
            "bc": 0x4000,
            "de": 0x8000,
            "hl": 0xC000,
            "ix": 0,
            "iy": 0,
            "sp": 0xDFF0,
        },
        "trace_entries": 256,
        "call_stack_depth": 3,
    }


class RendererObservationTests(unittest.TestCase):
    def test_renderer_hit_contains_only_safe_fixed_fields(self) -> None:
        observation = build_renderer_observation(
            target_sha256="a" * 64,
            emulator_version="3.9.14",
            frame_budget=12_000,
            mappings_attempted=mappings(),
            hit=hit(),
        )
        validate_renderer_observation(observation)
        encoded = json.dumps(observation)
        self.assertTrue(observation["renderer_hook_reached"])
        self.assertFalse(observation["translation_build_eligible"])
        self.assertNotIn("trace_lines", encoded)
        self.assertNotIn("decoded_text", encoded)
        self.assertNotIn("file_path", encoded)

    def test_no_hit_keeps_promotion_gate_closed(self) -> None:
        observation = build_renderer_observation(
            target_sha256="b" * 64,
            emulator_version="3.9.14",
            frame_budget=12_000,
            mappings_attempted=mappings(),
            hit=None,
        )
        self.assertEqual(
            observation["status"],
            "renderer-hook-not-observed",
        )
        validate_renderer_observation(observation)

    def test_writer_uses_fixed_device_path(self) -> None:
        observation = build_renderer_observation(
            target_sha256="c" * 64,
            emulator_version="3.9.14",
            frame_budget=12_000,
            mappings_attempted=[],
            hit=None,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_renderer_observation(root, observation)
            self.assertEqual(path, root / PUBLISH_RELATIVE_PATH)
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                observation,
            )


if __name__ == "__main__":
    unittest.main()
