from __future__ import annotations

import unittest
from unittest.mock import patch

from tools.run_s25u_renderer_probe import (
    _frame_budget,
    _probe_mappings,
    _renderer_hit_matches,
    _renderer_mappings,
)


class S25URendererProbeTests(unittest.TestCase):
    def test_idle_attract_route_uses_one_reset_and_all_breakpoints(self) -> None:
        mappings = _renderer_mappings()

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
            "physical_pc_after": expected["call_site_file_offset"],
            "slot0_bank": 0,
            "slot1_bank": 1,
            "slot2_bank": expected["expected_bank"],
        }
        with patch(
            "tools.run_s25u_renderer_probe._capture_state",
            return_value=(state, {"trace": "local-only"}),
        ):
            hit, evidence, rejected = _probe_mappings(client, mappings)

        self.assertEqual(hit["call_site_file_offset"], 0x3FFB2)
        self.assertEqual(evidence, {"trace": "local-only"})
        self.assertEqual(rejected, [])
        self.assertEqual(
            [name for name, _ in client.calls].count("debug_reset"),
            1,
        )
        self.assertEqual(
            [name for name, _ in client.calls].count("set_breakpoint_range"),
            6,
        )
        self.assertEqual(
            [name for name, _ in client.calls].count("remove_breakpoint"),
            6,
        )
        self.assertNotIn("controller_button", [name for name, _ in client.calls])
        self.assertEqual(_frame_budget(), 12_000)

    def test_verified_call_sites_expand_to_six_mapper_hypotheses(self) -> None:
        mappings = _renderer_mappings()
        self.assertEqual(len(mappings), 6)
        self.assertEqual(
            {item["call_site_file_offset"] for item in mappings},
            {0x3FD5, 0x3FFB2},
        )
        self.assertEqual(
            [
                item
                for item in mappings
                if item["call_site_file_offset"] == 0x3FFB2
                and item["slot"] == 2
            ][0],
            {
                "call_site_file_offset": 0x3FFB2,
                "slot": 2,
                "expected_bank": 0x0F,
                "logical_address": 0xBFB2,
            },
        )

    def test_execute_hit_requires_logical_physical_and_mapper_match(self) -> None:
        mapping = {
            "call_site_file_offset": 0x3FFB2,
            "slot": 2,
            "expected_bank": 0x0F,
            "logical_address": 0xBFB2,
        }
        state = {
            "pc_after": 0xBFB2,
            "physical_pc_after": 0x3FFB2,
            "slot0_bank": 0,
            "slot1_bank": 1,
            "slot2_bank": 0x0F,
        }
        self.assertTrue(_renderer_hit_matches(state, mapping))
        state["slot2_bank"] = 0x10
        self.assertFalse(_renderer_hit_matches(state, mapping))
        state["slot2_bank"] = 0x0F
        state["physical_pc_after"] = 0x43FB2
        self.assertFalse(_renderer_hit_matches(state, mapping))


if __name__ == "__main__":
    unittest.main()
