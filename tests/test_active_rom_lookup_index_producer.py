from __future__ import annotations

import unittest

from tools.v5_1_active_rom_lookup_index_producer import (
    analyze_lookup_index_producer,
    build_active_rom_lookup_index_producer,
    validate_active_rom_lookup_index_producer,
)


def _line(bank: int, pc: int, hl: int, opcodes: str) -> str:
    return (
        f"{bank:02X}:{pc:04X} A:00 BC:0000 DE:0000 "
        f"HL:{hl:04X} SP:DFF0  {opcodes}"
    )


class ActiveRomLookupIndexProducerTests(unittest.TestCase):
    def test_finds_literal_address_selector_before_each_target_read(self) -> None:
        lines: list[str] = []
        for offset in (0x6AC9, 0x6ACE, 0x6AD5):
            lines.extend([
                _line(1, 0x5000, 0, f"21 {offset & 0xFF:02X} {offset >> 8:02X}"),
                _line(1, 0x5003, offset, "7E"),
            ])
        counts, result = analyze_lookup_index_producer(
            lines=lines,
            selected={"bank": 1, "pc": 0x5003, "opcodes_hex": "7e"},
        )
        self.assertEqual(result["producer_class"], "literal-address-selector-candidate")
        self.assertEqual(result["address_operand_kind"], "hl-indirect")
        self.assertEqual(counts["target_event_count"], 3)
        self.assertEqual(counts["literal_pointer_definition_count"], 3)
        self.assertEqual(counts["matched_predecessor_definition_count"], 3)

    def test_finds_register_arithmetic_selector(self) -> None:
        lines = [
            _line(1, 0x5100, 0x6000, "19"),
            _line(1, 0x5101, 0x6AC9, "7E"),
            _line(1, 0x5100, 0x6000, "19"),
            _line(1, 0x5101, 0x6ACE, "7E"),
        ]
        counts, result = analyze_lookup_index_producer(
            lines=lines,
            selected={"bank": 1, "pc": 0x5101, "opcodes_hex": "7e"},
        )
        self.assertEqual(
            result["producer_class"], "register-arithmetic-selector-candidate"
        )
        self.assertEqual(counts["arithmetic_pointer_definition_count"], 2)

    def test_keeps_missing_predecessor_unresolved(self) -> None:
        counts, result = analyze_lookup_index_producer(
            lines=[_line(1, 0x5200, 0x6AC9, "7E")],
            selected={"bank": 1, "pc": 0x5200, "opcodes_hex": "7e"},
        )
        self.assertEqual(result["producer_class"], "producer-not-observed")
        self.assertEqual(counts["matched_predecessor_definition_count"], 0)

    def test_builds_and_validates_sanitized_artifact(self) -> None:
        analysis = {
            "target_event_count": 46,
            "target_unique_logical_read_count": 8,
            "address_register_candidate_count": 1,
            "matched_predecessor_definition_count": 46,
            "unique_predecessor_instruction_count": 1,
            "maximum_backtrack_instruction_count": 2,
            "literal_pointer_definition_count": 0,
            "arithmetic_pointer_definition_count": 46,
            "incremental_pointer_definition_count": 0,
            "memory_pointer_definition_count": 0,
            "stack_pointer_definition_count": 0,
            "split_pointer_definition_count": 0,
            "unknown_pointer_definition_count": 0,
        }
        value = build_active_rom_lookup_index_producer(
            target_sha256="a" * 64,
            source_active_rom_read_block_sha256="b" * 64,
            source_active_rom_source_role_sha256="c" * 64,
            source_register_trace_sha256="d" * 64,
            analysis=analysis,
            address_operand_kind="hl-indirect",
            producer_class="register-arithmetic-selector-candidate",
            captured_utc="2026-08-02T00:00:00Z",
        )
        validate_active_rom_lookup_index_producer(value)
        self.assertTrue(value["producer_candidate_bounded"])
        self.assertFalse(value["lookup_index_producer_confirmed"])


if __name__ == "__main__":
    unittest.main()
