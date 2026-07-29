from __future__ import annotations

import unittest

from tools.run_s25u_runtime_probe import (
    _call_stack_depth,
    _frames_per_slot,
    _parse_mapper,
    _tool_payload,
    _watch_ranges,
)


class S25URuntimeProbeTests(unittest.TestCase):
    def test_watch_ranges_require_trace_schema_five(self) -> None:
        plan = {
            "schema_version": 5,
            "selected_watch": {
                "logical_mappings": [
                    {
                        "slot": 1,
                        "bank": 0,
                        "logical_start": 0x4B7A,
                        "logical_end": 0x4C2E,
                    }
                ]
            },
        }
        self.assertEqual(
            _watch_ranges(plan),
            [
                {
                    "slot": 1,
                    "expected_bank": 0,
                    "logical_start": 0x4B7A,
                    "logical_end": 0x4C2E,
                }
            ],
        )
        plan["schema_version"] = 4
        with self.assertRaises(ValueError):
            _watch_ranges(plan)

    def test_mcp_tool_payload_is_json_only(self) -> None:
        message = {
            "result": {
                "content": [{"type": "text", "text": '{"pc":"8123"}'}],
                "isError": False,
            }
        }
        self.assertEqual(_tool_payload(message), {"pc": "8123"})

    def test_mapper_snapshot_is_exactly_four_bytes(self) -> None:
        self.assertEqual(_parse_mapper("00 01 02 03"), (0, 1, 2, 3))
        with self.assertRaises(ValueError):
            _parse_mapper("00 01 02")

    def test_call_stack_depth_and_frame_budget(self) -> None:
        self.assertEqual(_call_stack_depth({"frames": [{}, {}, {}]}), 3)
        self.assertGreater(_frames_per_slot(), 1000)


if __name__ == "__main__":
    unittest.main()
