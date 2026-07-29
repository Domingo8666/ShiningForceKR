from __future__ import annotations

import unittest

import tools.run_mobile_pipeline  # regression: pipeline must parse and import
from tools.v5_1_trace_plan import (
    build_trace_plan,
    logical_mapping_hypotheses,
    to_korean_summary,
)


def synthetic_consumer() -> dict[str, object]:
    return {
        "input": {"sha256": "synthetic"},
        "pointer_table_candidates": {
            "ranked_triplet_runs": [
                {
                    "file_offset": 0x0B7D,
                    "end_exclusive": 0x0B7D + 12 * 3,
                    "format": "bank_addr_le",
                    "entries": 12,
                    "score": 100.0,
                }
            ],
            "ranked_pair_runs": [],
        },
    }


class TracePlanTests(unittest.TestCase):
    def test_bank_zero_candidate_has_three_bus_hypotheses(self) -> None:
        mappings = logical_mapping_hypotheses(0x0B7D, 36)
        self.assertEqual([item["slot"] for item in mappings], [0, 1, 2])
        self.assertEqual(
            [item["logical_start"] for item in mappings],
            [0x0B7D, 0x4B7D, 0x8B7D],
        )

    def test_nonzero_bank_cannot_replace_fixed_first_1k(self) -> None:
        mappings = logical_mapping_hypotheses(0x4100, 8)
        self.assertEqual([item["slot"] for item in mappings], [1, 2])

    def test_reference_shape_prioritizes_and_builds_emucap_args(self) -> None:
        rom = bytearray(b"\xFF" * 0x10000)
        rom[0x200:0x205] = bytes.fromhex("3e00217d0b")
        plan = build_trace_plan(bytes(rom), synthetic_consumer())
        selected = plan["selected_hypothesis"]
        self.assertIsNotNone(selected)
        self.assertEqual(selected["file_offset"], 0x0B7D)
        self.assertEqual(selected["reference_shape_count"], 1)

        steps = plan["emucap"]["before_resume"]
        self.assertEqual(steps[0], {"tool": "set_trace", "args": {"enabled": True}})
        breakpoints = steps[1:]
        self.assertEqual(len(breakpoints), 3)
        self.assertEqual(
            [item["args"]["start"] for item in breakpoints],
            [0x0B7D, 0x4B7D, 0x8B7D],
        )
        self.assertTrue(all(item["args"]["kind"] == "read" for item in breakpoints))
        self.assertTrue(
            all(item["args"]["snapshot"] == ["smsMemory:65532:4"] for item in breakpoints)
        )
        self.assertFalse(plan["consumer_evidence_confirmed"])
        self.assertIn("0x000B7D", to_korean_summary(plan))


if __name__ == "__main__":
    unittest.main()
