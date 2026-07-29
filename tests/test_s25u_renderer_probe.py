from __future__ import annotations

import unittest
from unittest.mock import patch

from tools.run_s25u_renderer_probe import (
    _classify_decoder_read,
    _decoder_mappings,
    _frame_budget,
    _last_rom_read,
    _probe_hit_matches,
    _probe_mappings,
)


class S25URendererProbeTests(unittest.TestCase):
    def test_idle_attract_route_uses_one_reset_and_all_breakpoints(self) -> None:
        mappings = _decoder_mappings()

        class FakeClient:
            def __init__(self) -> None:
                self.calls: list[tuple[str, dict[str, object]]] = []

            def call(
                self,
                name: str,
                arguments: dict[str, object] | None = None,
            ) -> dict[str, object]:
                self.calls.append((name, arguments or {}))
                if name == "debug_get_status":
                    return {"at_breakpoint": True}
                return {}

        client = FakeClient()
        expected = mappings[-1]
        state = {
            "pc_after": expected["logical_address"],
            "physical_pc_after": expected["probe_file_offset"],
            "slot0_bank": 0,
            "slot1_bank": 1,
            "slot2_bank": expected["expected_bank"],
        }
        with patch(
            "tools.run_s25u_renderer_probe._capture_state",
            return_value=(state, {"trace": "local-only"}),
        ):
            hit, evidence, rejected = _probe_mappings(client, mappings)

        self.assertEqual(hit["probe_file_offset"], 0x3411)
        self.assertEqual(evidence, {"trace": "local-only"})
        self.assertEqual(rejected, [])
        self.assertEqual(
            [name for name, _ in client.calls].count("debug_reset"),
            1,
        )
        self.assertEqual(
            [name for name, _ in client.calls].count("set_breakpoint_range"),
            3,
        )
        self.assertEqual(
            [name for name, _ in client.calls].count("remove_breakpoint"),
            3,
        )
        self.assertNotIn("controller_button", [name for name, _ in client.calls])
        self.assertEqual(_frame_budget(), 12_000)

    def test_decoder_entry_expands_to_three_mapper_hypotheses(self) -> None:
        mappings = _decoder_mappings()
        self.assertEqual(len(mappings), 3)
        self.assertEqual(
            {item["probe_file_offset"] for item in mappings},
            {0x3411},
        )
        self.assertEqual(
            [
                item
                for item in mappings
                if item["slot"] == 2
            ][0],
            {
                "probe_file_offset": 0x3411,
                "slot": 2,
                "expected_bank": 0,
                "logical_address": 0xB411,
            },
        )

    def test_execute_hit_requires_logical_physical_and_mapper_match(self) -> None:
        mapping = {
            "probe_file_offset": 0x3411,
            "slot": 2,
            "expected_bank": 0,
            "logical_address": 0xB411,
        }
        state = {
            "pc_after": 0xB411,
            "physical_pc_after": 0x3411,
            "slot0_bank": 0,
            "slot1_bank": 1,
            "slot2_bank": 0,
        }
        self.assertTrue(_probe_hit_matches(state, mapping))
        state["slot2_bank"] = 0x10
        self.assertFalse(_probe_hit_matches(state, mapping))
        state["slot2_bank"] = 0
        state["physical_pc_after"] = 0x43FB2
        self.assertFalse(_probe_hit_matches(state, mapping))

    def test_last_rom_read_uses_live_mapper_bank(self) -> None:
        state = {
            "pc_after": 0x3421,
            "physical_pc_after": 0x3421,
            "slot0_bank": 0,
            "slot1_bank": 0x20,
            "slot2_bank": 2,
        }
        evidence = {
            "z80": {"IX": "0000", "IY": "0000"},
            "trace": {
                "lines": [
                    "00:3420 A:00 BC:0000 DE:0000 HL:4100 SP:DFF0  LD A,(HL)  7E"
                ]
            },
        }
        sample = _last_rom_read(state, evidence, 0x17C000)
        self.assertIsNotNone(sample)
        assert sample is not None
        self.assertEqual(sample["physical_file_offset"], 0x80100)
        self.assertEqual(sample["classification"], "korean-huffman-vector")

    def test_decoder_read_classification_distinguishes_runtime_layers(self) -> None:
        self.assertEqual(
            _classify_decoder_read(0x80300),
            "korean-huffman-tree",
        )
        self.assertEqual(_classify_decoder_read(0x10000), "source-region")


if __name__ == "__main__":
    unittest.main()
