from __future__ import annotations

import unittest
from unittest.mock import patch

from tools.run_s25u_runtime_probe import (
    INPUT_SCHEDULE,
    _call_stack_depth,
    _frame_step_timeout_seconds,
    _frames_per_slot,
    _last_candidate_access,
    _mapping_bank_matches,
    _matching_target_candidate,
    _instruction_fetch_like,
    _parse_mapper,
    _probe_slot,
    _runtime_failure_receipt,
    _runtime_candidate_groups,
    _target_candidates,
    _tool_payload,
    _step_frames_and_wait,
    _step_instruction_and_wait,
    _watch_ranges,
    validate_runtime_failure_receipt,
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


class _FakeInstructionFetchClient:
    def __init__(self) -> None:
        self.phase = 0
        self.calls: list[str] = []

    def call(
        self, name: str, arguments: dict[str, object] | None = None
    ) -> dict[str, object]:
        self.calls.append(name)
        if name == "debug_step_into":
            self.phase = 1
            return {}
        if name == "debug_get_status":
            return {
                "paused": True,
                "at_breakpoint": self.phase != 1 or self.calls[-2] != "debug_step_into",
                "pc": "031C" if self.phase else "0B7B",
            }
        if name == "get_z80_status":
            return {
                "physical_PC": "031C" if self.phase else "0B7B",
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
            return {"data": "08 00 00 00"}
        if name == "get_trace_log":
            return {"count": 1, "lines": []}
        if name == "get_call_stack":
            return {"frames": []}
        return {}


class S25URuntimeProbeTests(unittest.TestCase):
    def test_frame_step_waits_for_paused_completion_barrier(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.statuses = iter(
                    (
                        {"paused": False, "at_breakpoint": False},
                        {"paused": True, "at_breakpoint": False},
                        {"paused": False, "at_breakpoint": False},
                        {"paused": True, "at_breakpoint": False},
                    )
                )
                self.calls: list[str] = []

            def call(
                self,
                name: str,
                arguments: dict[str, object] | None = None,
            ) -> dict[str, object]:
                self.calls.append(name)
                if name == "debug_get_status":
                    return next(self.statuses)
                return {}

        client = FakeClient()
        with patch("tools.run_s25u_runtime_probe.time.sleep"):
            status = _step_frames_and_wait(client, 2)
        self.assertTrue(status["paused"])
        self.assertEqual(client.calls[0], "debug_step_frame")
        self.assertEqual(client.calls.count("debug_step_frame"), 2)
        self.assertEqual(client.calls.count("debug_get_status"), 4)

    def test_frame_step_timeout_is_bounded_per_single_frame(self) -> None:
        self.assertEqual(_frame_step_timeout_seconds(1), 5.0)
        self.assertEqual(_frame_step_timeout_seconds(240), 6.8)
        self.assertEqual(_frame_step_timeout_seconds(1000), 22.0)
        with self.assertRaises(ValueError):
            _frame_step_timeout_seconds(0)

    def test_frame_step_stops_early_on_breakpoint(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.calls: list[str] = []

            def call(
                self,
                name: str,
                arguments: dict[str, object] | None = None,
            ) -> dict[str, object]:
                self.calls.append(name)
                if name == "debug_get_status":
                    return {"paused": True, "at_breakpoint": True}
                return {}

        client = FakeClient()
        status = _step_frames_and_wait(client, 180)
        self.assertTrue(status["at_breakpoint"])
        self.assertEqual(client.calls.count("debug_step_frame"), 1)

    def test_instruction_step_waits_for_paused_completion_barrier(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.statuses = iter(({"paused": False}, {"paused": True}))
                self.calls: list[str] = []

            def call(
                self,
                name: str,
                arguments: dict[str, object] | None = None,
            ) -> dict[str, object]:
                self.calls.append(name)
                if name == "debug_get_status":
                    return next(self.statuses)
                return {}

        client = FakeClient()
        with patch("tools.run_s25u_runtime_probe.time.sleep"):
            status = _step_instruction_and_wait(client)
        self.assertTrue(status["paused"])
        self.assertEqual(client.calls[0], "debug_step_into")
        self.assertEqual(client.calls.count("debug_get_status"), 2)

    def test_runtime_probe_follows_confirmed_story_route(self) -> None:
        self.assertEqual(INPUT_SCHEDULE[:2], ((180, None), (240, "start")))
        self.assertEqual(INPUT_SCHEDULE[2:], ((180, "2"),) * 16)

    def test_long_route_does_not_enable_full_cpu_trace(self) -> None:
        source = __import__("inspect").getsource(
            __import__(
                "tools.run_s25u_runtime_probe",
                fromlist=["main"],
            ).main
        )
        self.assertIn('"set_trace_log"', source)
        self.assertIn('"enabled": False', source)
        self.assertNotIn('"enabled": True', source)

    def test_runtime_failure_receipt_is_path_free_and_method_scoped(self) -> None:
        class FakeClient:
            last_request_method = "debug_step_frame"
            last_tool_name = "debug_step_frame"

        receipt = _runtime_failure_receipt(
            "candidate-probe",
            RuntimeError(
                "Gearsystem MCP timed out during tools/call; "
                "stderr tail: /private/path"
            ),
            FakeClient(),  # type: ignore[arg-type]
        )
        self.assertEqual(
            receipt,
            {
                "schema_version": 1,
                "failure_stage": "candidate-probe",
                "failure_kind": "mcp-timeout",
                "mcp_method": "debug_step_frame",
            },
        )
        self.assertNotIn("/", str(receipt))
        validate_runtime_failure_receipt(receipt)

    def test_runtime_failure_receipt_distinguishes_frame_barrier_timeout(
        self,
    ) -> None:
        class FakeClient:
            last_request_method = "tools/call"
            last_tool_name = "debug_get_status"

        receipt = _runtime_failure_receipt(
            "candidate-probe",
            RuntimeError(
                "Gearsystem frame step did not finish within 180 frames"
            ),
            FakeClient(),  # type: ignore[arg-type]
        )
        self.assertEqual(receipt["failure_kind"], "frame-step-timeout")
        self.assertEqual(receipt["mcp_method"], "debug_get_status")

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

    def test_mcp_tool_payload_accepts_json_text(self) -> None:
        message = {
            "result": {
                "content": [{"type": "text", "text": '{"pc":"8123"}'}],
                "isError": False,
            }
        }
        self.assertEqual(_tool_payload(message), {"pc": "8123"})

    def test_mcp_tool_payload_accepts_image_content(self) -> None:
        message = {
            "result": {
                "content": [
                    {
                        "type": "image",
                        "data": "aW1hZ2U=",
                        "mimeType": "image/png",
                    }
                ],
                "isError": False,
            }
        }
        self.assertEqual(
            _tool_payload(message),
            {"data": "aW1hZ2U=", "mimeType": "image/png"},
        )

    def test_next_runtime_groups_skip_the_exhausted_selected_extent(self) -> None:
        def candidate(
            offset: int,
            entries: int,
            format_name: str,
            family: str = "triplet",
        ) -> dict[str, object]:
            return {
                "family": family,
                "format": format_name,
                "entry_width": 3 if family == "triplet" else 2,
                "file_offset": offset,
                "end_exclusive": offset + entries * (3 if family == "triplet" else 2),
                "entries": entries,
                "full_decode_probe": {"bounded_terminations": entries},
            }

        plan = {
            "schema_version": 5,
            "ranked_consumer_hypotheses": [
                candidate(0x0B7B, 60, "addr_le_bank"),
                candidate(0x0B7A, 60, "bank_addr_le"),
                candidate(0x10000, 190, "addr_le_bank_unresolved", "pair"),
                candidate(0x1827D, 36, "bank_addr_le"),
                candidate(0x42599, 20, "bank_addr_le"),
            ],
        }
        exhausted = {
            (0, 0, 0x0B7A, 0x0C2E),
            (1, 0, 0x4B7A, 0x4C2E),
            (2, 0, 0x8B7A, 0x8C2E),
        }
        groups = _runtime_candidate_groups(plan, exhausted)
        self.assertEqual([item["rank"] for item in groups], [4, 5])
        self.assertEqual(groups[0]["watch"]["file_start"], 0x1827D)
        self.assertEqual(groups[1]["watch"]["file_start"], 0x42599)
        self.assertEqual(
            sum(len(item["mappings"]) for item in groups),
            5,
        )

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

    def test_execution_inside_watch_is_not_a_data_read(self) -> None:
        mapping = {
            "slot": 0,
            "expected_bank": 0,
            "logical_start": 0x0B7A,
            "logical_end": 0x0C2E,
        }
        hit = {
            "physical_pc_after": 0x0B7B,
        }
        self.assertTrue(_instruction_fetch_like(hit, mapping))
        hit["physical_pc_after"] = 0x031C
        self.assertFalse(_instruction_fetch_like(hit, mapping))

    def test_probe_steps_past_instruction_fetch_and_keeps_searching(self) -> None:
        mapping = {
            "slot": 0,
            "expected_bank": 0,
            "logical_start": 0x0B7A,
            "logical_end": 0x0C2E,
        }
        client = _FakeInstructionFetchClient()
        hit, evidence, rejected = _probe_slot(client, mapping)
        self.assertIsNotNone(hit)
        self.assertIsNotNone(evidence)
        assert hit is not None
        self.assertEqual(hit["physical_pc_after"], 0x031C)
        self.assertEqual(rejected[0]["rejection_kind"], "instruction-fetch-like")
        self.assertEqual(client.calls.count("debug_step_into"), 1)
        self.assertEqual(client.calls.count("set_breakpoint_range"), 2)
        self.assertEqual(client.calls.count("remove_breakpoint"), 2)

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
