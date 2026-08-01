from __future__ import annotations

import unittest

from tools.v5_1_active_rom_cursor_reset import (
    analyze_cursor_reset,
    build_active_rom_cursor_reset,
    validate_active_rom_cursor_reset,
)


def _line(bank: int, pc: int, bc: int, opcodes: str) -> str:
    return (
        f"{bank:02X}:{pc:04X} A:00 BC:{bc:04X} DE:0000 "
        f"HL:0000 SP:DFF0  {opcodes}"
    )


class ActiveRomCursorResetTests(unittest.TestCase):
    def test_resolves_literal_reset_and_positive_stride(self) -> None:
        lines: list[str] = []
        for base in (0x6AC8, 0x6ACD, 0x6AD4):
            lines.extend([
                _line(1, 0x5000, 0, f"01 {base & 0xFF:02X} {base >> 8:02X}"),
                _line(1, 0x5003, base, "03"),
                _line(1, 0x5004, base + 1, "00"),
                _line(1, 0x5005, base + 1, "0A"),
            ])
        counts, result = analyze_cursor_reset(
            lines=lines,
            selected={"bank": 1, "pc": 0x5005, "opcodes_hex": "0a"},
        )
        self.assertEqual(result["reset_class"], "literal-reset-fixed-stride-candidate")
        self.assertEqual(counts["positive_stride_event_count"], 3)
        self.assertEqual(counts["literal_reset_count"], 3)
        self.assertEqual(counts["reset_to_target_projection_match_count"], 3)

    def test_reports_reset_outside_trace_window(self) -> None:
        lines = [
            _line(1, 0x5003, 0x6AC8, "03"),
            _line(1, 0x5005, 0x6AC9, "0A"),
        ]
        counts, result = analyze_cursor_reset(
            lines=lines,
            selected={"bank": 1, "pc": 0x5005, "opcodes_hex": "0a"},
        )
        self.assertEqual(result["reset_class"], "reset-outside-trace-window")
        self.assertEqual(counts["incremental_producer_event_count"], 1)
        self.assertEqual(counts["reset_definition_match_count"], 0)

    def test_builds_and_validates_sanitized_artifact(self) -> None:
        analysis = {
            "target_event_count": 46,
            "target_unique_logical_read_count": 8,
            "cursor_register_candidate_count": 1,
            "incremental_producer_event_count": 46,
            "positive_stride_event_count": 46,
            "negative_stride_event_count": 0,
            "unique_stride_count": 1,
            "reset_definition_match_count": 46,
            "unique_reset_instruction_count": 1,
            "literal_reset_count": 46,
            "memory_reset_count": 0,
            "stack_reset_count": 0,
            "split_reset_count": 0,
            "arithmetic_reset_count": 0,
            "unknown_reset_count": 0,
            "reset_to_target_projection_match_count": 46,
            "maximum_reset_backtrack_instruction_count": 8,
        }
        value = build_active_rom_cursor_reset(
            target_sha256="a" * 64,
            source_active_rom_lookup_index_producer_sha256="b" * 64,
            source_active_rom_read_block_sha256="c" * 64,
            source_register_trace_sha256="d" * 64,
            analysis=analysis,
            reset_class="literal-reset-fixed-stride-candidate",
            captured_utc="2026-08-02T00:00:00Z",
        )
        validate_active_rom_cursor_reset(value)
        self.assertTrue(value["fixed_stride_candidate"])
        self.assertFalse(value["cursor_semantics_confirmed"])


if __name__ == "__main__":
    unittest.main()
