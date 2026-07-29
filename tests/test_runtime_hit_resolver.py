from __future__ import annotations

import unittest
from unittest.mock import patch

from tools.v5_1_runtime_hit_resolver import (
    _alignment_pointer,
    _alignment_resolutions,
    _candidate_access_is_valid,
    _parse_trace_line,
    _read_addresses,
    build_consumer_resolution,
    validate_consumer_resolution,
)


TRACE_LINE = (
    "00:000C  A:42  BC:0000  DE:0000  HL:0100  SP:DFF0  "
    "sZyhxpnc  LD A,(HL)                7E "
)


class RuntimeHitResolverTests(unittest.TestCase):
    def test_trace_line_resolves_exact_hl_read(self) -> None:
        parsed = _parse_trace_line(TRACE_LINE)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["bank"], 0)
        self.assertEqual(parsed["pc"], 0x000C)
        self.assertEqual(
            _read_addresses(parsed["opcodes"], parsed["registers"]),
            [0x0100],
        )

    def test_indexed_and_absolute_reads_are_bounded(self) -> None:
        registers = {"ix": 0x4000, "iy": 0x8000, "hl": 0}
        self.assertEqual(
            _read_addresses(bytes.fromhex("dd 7e fe"), registers),
            [0x3FFE],
        )
        self.assertEqual(
            _read_addresses(bytes.fromhex("3a 7b 4b"), registers),
            [0x4B7B],
        )
        self.assertEqual(_read_addresses(b"\x00", registers), [])

    @patch(
        "tools.v5_1_runtime_hit_resolver.decode_symbols",
        return_value=([1, 2, 3], 0),
    )
    def test_alignment_entry_has_only_aggregate_decode_result(
        self, _decode: object
    ) -> None:
        rom = bytearray(b"\xFF" * 0x10000)
        rom[0x100:0x103] = bytes.fromhex("00 40 01")
        plan = {
            "selected_alignment_cluster": [
                {
                    "file_offset": 0x100,
                    "end_exclusive": 0x106,
                    "entries": 2,
                    "format": "addr_le_bank",
                }
            ]
        }
        result = _alignment_resolutions(
            bytes(rom), plan, 0x100, {}
        )
        pointer = _alignment_pointer(
            bytes(rom), plan["selected_alignment_cluster"][0], 0x100
        )
        self.assertIsNotNone(pointer)
        self.assertEqual(pointer["pointer_address"], 0x4000)
        self.assertEqual(pointer["pointer_bank"], 1)
        self.assertEqual(result[0]["entry_index"], 0)
        self.assertEqual(result[0]["target_file_offset"], 0x4000)
        self.assertTrue(result[0]["bounded_decode"])
        self.assertEqual(result[0]["symbol_count"], 3)
        self.assertNotIn("entry_bytes", result[0])
        self.assertNotIn("symbols", result[0])

    def test_table_hit_alone_keeps_resolution_ambiguous(self) -> None:
        plan = {
            "selected_watch": {"file_start": 0x100},
        }
        hit = {
            "slot": 1,
            "expected_bank": 0,
            "logical_start": 0x4100,
            "logical_end": 0x4105,
            "pc_after": 0x2000,
            "physical_pc_after": 0x2000,
            "slot0_bank": 0,
            "slot1_bank": 0,
            "slot2_bank": 2,
        }
        alignment = {
            "format": "addr_le_bank",
            "alignment_file_offset": 0x100,
            "entry_index": 0,
            "entry_byte_index": 0,
            "target_file_offset": 0x4000,
            "bounded_decode": True,
            "symbol_count": 3,
            "roundtrip_exact": True,
            "encoded_bits": 5,
        }
        resolution = build_consumer_resolution(
            target_sha256="a" * 64,
            plan=plan,
            hit=hit,
            trace_record={"bank": 0, "pc": 0x1000},
            logical_access=0x4100,
            alignments=[alignment],
        )
        self.assertFalse(resolution["consumer_evidence_confirmed"])
        self.assertFalse(resolution["translation_build_eligible"])
        self.assertIsNone(resolution["selected_entry_index"])
        self.assertIsNone(resolution["target_read"])
        validate_consumer_resolution(resolution)

    def test_target_read_selects_runtime_confirmed_alignment(self) -> None:
        plan = {"selected_watch": {"file_start": 0x100}}
        hit = {
            "slot": 1,
            "expected_bank": 0,
            "logical_start": 0x4100,
            "logical_end": 0x4105,
            "pc_after": 0x2000,
            "physical_pc_after": 0x2000,
            "slot0_bank": 0,
            "slot1_bank": 0,
            "slot2_bank": 2,
        }
        alignment = {
            "format": "bank_addr_le",
            "alignment_file_offset": 0x100,
            "entry_index": 0,
            "entry_byte_index": 0,
            "target_file_offset": 0x8000,
            "bounded_decode": True,
            "symbol_count": 3,
            "roundtrip_exact": True,
            "encoded_bits": 5,
        }
        followup = {
            "matching_candidate": {
                "format": "bank_addr_le",
                "alignment_file_offset": 0x100,
                "entry_index": 0,
                "entry_byte_index": 0,
                "pointer_bank": 2,
                "pointer_address": 0x8000,
                "target_slot": 2,
                "target_file_offset": 0x8000,
            },
            "logical_access": 0x8000,
            "trace_record": {"bank": 0, "pc": 0x1234},
            "hit": {
                "pc_after": 0x1235,
                "physical_pc_after": 0x1235,
                "slot0_bank": 0,
                "slot1_bank": 1,
                "slot2_bank": 2,
            },
        }
        resolution = build_consumer_resolution(
            target_sha256="a" * 64,
            plan=plan,
            hit=hit,
            trace_record={"bank": 0, "pc": 0x1000},
            logical_access=0x4100,
            alignments=[alignment],
            target_followup=followup,
        )
        self.assertTrue(resolution["consumer_evidence_confirmed"])
        self.assertFalse(resolution["translation_build_eligible"])
        self.assertEqual(resolution["selected_alignment_format"], "bank_addr_le")
        self.assertEqual(resolution["selected_entry_index"], 0)
        self.assertEqual(resolution["target_read"]["mapped_bank"], 2)
        self.assertTrue(
            _candidate_access_is_valid(0x8000, 2, 2, 0x8000, 2)
        )
        self.assertFalse(
            _candidate_access_is_valid(0x8000, 2, 2, 0x8000, 3)
        )
        validate_consumer_resolution(resolution)


if __name__ == "__main__":
    unittest.main()
