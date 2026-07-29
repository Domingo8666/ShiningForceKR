from __future__ import annotations

import unittest

from tools.run_s25u_runtime_probe import (
    _call_stack_depth,
    _frames_per_slot,
    _last_candidate_access,
    _mapping_bank_matches,
    _matching_target_candidate,
    _parse_mapper,
    _probe_slot,
    _target_candidates,
    _tool_payload,
    _watch_ranges,
)


class _FakeProbeClient:
    def __init__(self, mapper_snapshots: list[str]) -> None:
        self.mapper_snapshots = iter(mapper_snapshots)
        self.calls: list[str] = []

    def call(
        self, name: str, arguments: dict[str, object] | None = None
    ) -> dict[str, object]:
        self.calls.append(name)
        if name == "debug_get_status":
            return {"at_breakpoint": True, "pc": "031C"}
        if name == "get_z80_status":
            return {
                "physical_PC": "031C",
                "bank": "00",
                "AF": "0044",
                "BC": "0F83",
                "DE": "8B7D",
                "HL": "8B7C",
                "IX": "FFFF",
                "IY": "FFFF",
                "SP": "DEFF",
            }
        if name == "list_memory_areas":
            return {"areas": [{"name": "RAM", "id": 1, "size": 0x2000}]}
        if name == "read_memory":
            return {"data": next(self.mapper_snapshots)}
        if name == "get_trace_log":
            return {"count": 1, "lines": []}
        if name == "get_call_stack":
            return {"frames": []}
        return {}


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

    def test_probe_rejects_wrong_slot_bank_and_keeps_searching(self) -> None:
        mapping = {
            "slot": 2,
            "expected_bank": 0,
            "logical_start": 0x8B7A,
            "logical_end": 0x8C2E,
        }
        client = _FakeProbeClient(["08 00 01 02", "08 00 01 00"])
        hit, evidence, rejected = _probe_slot(client, mapping)
        self.assertIsNotNone(hit)
        self.assertIsNotNone(evidence)
        assert hit is not None
        self.assertTrue(_mapping_bank_matches(hit, mapping))
        self.assertEqual(hit["slot2_bank"], 0)
        self.assertEqual(
            rejected,
            [
                {
                    "slot": 2,
                    "expected_bank": 0,
                    "mapped_bank": 2,
                    "pc_after": 0x031C,
                    "physical_pc_after": 0x031C,
                }
            ],
        )
        self.assertEqual(client.calls.count("debug_step_frame"), 2)

    def test_probe_does_not_publish_a_mismatched_hit(self) -> None:
        mapping = {
            "slot": 2,
            "expected_bank": 0,
            "logical_start": 0x8B7A,
            "logical_end": 0x8C2E,
        }
        client = _FakeProbeClient(["08 00 01 02"])
        hit, evidence, rejected = _probe_slot(
            client, mapping, max_rejected_bank_hits=1
        )
        self.assertIsNone(hit)
        self.assertIsNone(evidence)
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["mapped_bank"], 2)

    def test_call_stack_depth_and_frame_budget(self) -> None:
        self.assertEqual(_call_stack_depth({"frames": [{}, {}, {}]}), 3)
        self.assertGreater(_frames_per_slot(), 1000)

    def test_target_candidate_requires_matching_mapper_bank(self) -> None:
        rom = bytearray(b"\xFF" * 0x10000)
        rom[0x100:0x103] = bytes.fromhex("02 00 80")
        plan = {
            "selected_alignment_cluster": [
                {
                    "file_offset": 0x100,
                    "end_exclusive": 0x103,
                    "entries": 1,
                    "format": "bank_addr_le",
                }
            ]
        }
        candidates = _target_candidates(bytes(rom), plan, 0x100)
        self.assertEqual(len(candidates), 1)
        evidence = {
            "trace": {
                "lines": [
                    "02:8123  A:42  BC:0000  DE:0000  HL:8000  SP:DFF0  "
                    "sZyhxpnc  LD A,(HL)                7E "
                ]
            },
            "z80": {"IX": "0000", "IY": "0000"},
        }
        access = _last_candidate_access(evidence, candidates)
        self.assertIsNotNone(access)
        trace_record, logical_access = access
        self.assertEqual(trace_record, {"bank": 2, "pc": 0x8123})
        self.assertEqual(logical_access, 0x8000)
        state = {"slot1_bank": 1, "slot2_bank": 2}
        self.assertEqual(
            _matching_target_candidate(candidates, logical_access, state),
            candidates[0],
        )
        state["slot2_bank"] = 3
        self.assertIsNone(
            _matching_target_candidate(candidates, logical_access, state)
        )


if __name__ == "__main__":
    unittest.main()
