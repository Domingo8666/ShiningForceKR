from __future__ import annotations

import unittest

from tools.run_s25u_renderer_probe import (
    _renderer_hit_matches,
    _renderer_mappings,
)


class S25URendererProbeTests(unittest.TestCase):
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
