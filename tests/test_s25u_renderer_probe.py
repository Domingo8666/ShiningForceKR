from __future__ import annotations

import unittest
from unittest.mock import patch

from tools.run_s25u_renderer_probe import (
    TEXT_ROUTE_SCHEDULE,
    _classify_decoder_read,
    _frame_budget,
    _last_rom_read,
    _probe_vector_reads,
    _vector_mappings,
    _vector_read_matches,
)


class S25URendererProbeTests(unittest.TestCase):
    def test_story_route_uses_start_then_confirm_and_all_breakpoints(self) -> None:
        mappings = _vector_mappings()

        class FakeClient:
            def __init__(self) -> None:
                self.calls: list[tuple[str, dict[str, object]]] = []
                self.step_requests = 0
                self.break_on_step = 180 + 240 + 3

            def call(
                self,
                name: str,
                arguments: dict[str, object] | None = None,
            ) -> dict[str, object]:
                self.calls.append((name, arguments or {}))
                if name == "debug_step_frame":
                    self.step_requests += 1
                if name == "debug_get_status":
                    return {
                        "at_breakpoint": (
                            self.step_requests >= self.break_on_step
                        ),
                        "paused": self.step_requests < self.break_on_step,
                    }
                return {}

        client = FakeClient()
        expected = mappings[-1]
        state = {
            "pc_after": 0x3456,
            "physical_pc_after": 0x3456,
            "slot0_bank": 0,
            "slot1_bank": 1,
            "slot2_bank": expected["expected_bank"],
        }
        sample = {
            "slot": 2,
            "logical_access": 0x8100,
            "physical_file_offset": 0x80100,
            "mapped_bank": 0x20,
        }
        with patch(
            "tools.run_s25u_renderer_probe._capture_state",
            return_value=(state, {"trace": "local-only"}),
        ), patch(
            "tools.run_s25u_renderer_probe._last_rom_read",
            return_value=sample,
        ):
            hit, evidence, rejected = _probe_vector_reads(
                client,
                mappings,
                0x17C000,
            )

        self.assertEqual(hit["probe_file_offset"], 0x80100)
        self.assertEqual(hit["logical_address"], 0x8100)
        self.assertEqual(evidence, {"trace": "local-only"})
        self.assertEqual(rejected, [])
        self.assertEqual(
            [name for name, _ in client.calls].count("debug_reset"),
            1,
        )
        self.assertEqual(
            [name for name, _ in client.calls].count("set_breakpoint_range"),
            2,
        )
        self.assertEqual(
            [name for name, _ in client.calls].count("remove_breakpoint"),
            2,
        )
        controller_calls = [
            arguments
            for name, arguments in client.calls
            if name == "controller_button"
        ]
        self.assertEqual(controller_calls[0]["button"], "start")
        self.assertTrue(
            all(item["button"] == "2" for item in controller_calls[1:])
        )
        self.assertNotIn("1", [item["button"] for item in controller_calls])
        self.assertEqual(_frame_budget(), 3_300)

    def test_story_route_has_one_start_and_multiple_confirm_inputs(self) -> None:
        buttons = [
            button
            for _, button in TEXT_ROUTE_SCHEDULE
            if button is not None
        ]
        self.assertEqual(buttons[0], "start")
        self.assertEqual(buttons.count("start"), 1)
        self.assertGreaterEqual(buttons.count("2"), 8)
        self.assertNotIn("1", buttons)

    def test_vector_range_expands_to_two_switchable_slot_mappings(self) -> None:
        mappings = _vector_mappings()
        self.assertEqual(len(mappings), 2)
        self.assertEqual(
            {item["probe_file_offset"] for item in mappings},
            {0x80100},
        )
        self.assertEqual(
            [
                item
                for item in mappings
                if item["slot"] == 2
            ][0],
            {
                "probe_file_offset": 0x80100,
                "slot": 2,
                "expected_bank": 0x20,
                "logical_address": 0x8100,
            },
        )

    def test_vector_read_requires_range_slot_and_mapper_match(self) -> None:
        mapping = {
            "probe_file_offset": 0x80100,
            "slot": 2,
            "expected_bank": 0x20,
            "logical_address": 0x8100,
        }
        sample = {
            "slot": 2,
            "logical_access": 0x8123,
            "physical_file_offset": 0x80123,
            "mapped_bank": 0x20,
        }
        self.assertTrue(_vector_read_matches(sample, mapping))
        sample["mapped_bank"] = 0x10
        self.assertFalse(_vector_read_matches(sample, mapping))
        sample["mapped_bank"] = 0x20
        sample["physical_file_offset"] = 0x100123
        self.assertFalse(_vector_read_matches(sample, mapping))
        sample["physical_file_offset"] = 0x80123
        sample["logical_access"] = 0x8100
        self.assertFalse(_vector_read_matches(sample, mapping))

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
