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
        self.assertEqual(selected["pointer_load_shape_count"], 1)
        self.assertEqual(selected["control_flow_shape_count"], 0)
        self.assertEqual(selected["bank_coupled_pointer_load_count"], 1)
        self.assertEqual(plan["schema_version"], 2)

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


    def test_generic_slot_base_calls_do_not_promote_a_data_table(self) -> None:
        rom = bytearray(b"ÿ" * 0x20000)
        for index in range(20):
            at = 0x200 + index * 3
            rom[at:at + 3] = bytes.fromhex("cd0040")
        for index in range(20):
            at = 0x300 + index * 3
            rom[at:at + 3] = bytes.fromhex("cd0080")

        consumer = {
            "input": {"sha256": "synthetic"},
            "pointer_table_candidates": {
                "ranked_triplet_runs": [
                    {
                        "file_offset": 0x0B7D,
                        "end_exclusive": 0x0B7D + 12 * 3,
                        "format": "bank_addr_le",
                        "entries": 12,
                        "score": 300.0,
                    }
                ],
                "ranked_pair_runs": [
                    {
                        "file_offset": 0x010000,
                        "end_exclusive": 0x010000 + 190 * 2,
                        "format": "addr_le_bank_unresolved",
                        "entries": 190,
                        "score": 250.0,
                    }
                ],
            },
        }
        plan = build_trace_plan(bytes(rom), consumer)
        self.assertEqual(plan["selected_hypothesis"]["file_offset"], 0x0B7D)

        generic = next(
            item
            for item in plan["ranked_consumer_hypotheses"]
            if item["file_offset"] == 0x010000
        )
        self.assertEqual(generic["pointer_load_shape_count"], 0)
        self.assertEqual(generic["control_flow_shape_count"], 40)
        self.assertTrue(generic["generic_slot_base_discounted"])
        self.assertEqual(generic["combined_candidate_score"], 170.0)


if __name__ == "__main__":
    unittest.main()
