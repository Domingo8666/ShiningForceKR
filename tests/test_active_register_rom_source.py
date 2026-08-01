from __future__ import annotations

import unittest

from tools.v5_1_active_register_rom_source import (
    build_active_register_rom_source,
    instruction_breakpoint_matches,
    physical_rom_source,
    physical_source_region,
    source_slot,
    validate_active_register_rom_source,
)


class ActiveRegisterRomSourceTests(unittest.TestCase):
    def test_maps_all_three_mapper_windows(self) -> None:
        self.assertEqual(source_slot(0x1234), "slot0")
        self.assertEqual(source_slot(0x5678), "slot1")
        self.assertEqual(source_slot(0x9ABC), "slot2")
        self.assertEqual(
            physical_rom_source(
                0x9ABC,
                slot0_bank=0,
                slot1_bank=1,
                slot2_bank=8,
                rom_size=0x40000,
            ),
            (8, 8 * 0x4000 + 0x1ABC),
        )

    def test_validates_a_confirmed_physical_rom_source(self) -> None:
        safe = build_active_register_rom_source(
            target_sha256="a" * 64,
            source_register_trace_sha256="b" * 64,
            analysis={
                "read_break_hit_count": 3,
                "matching_read_hit_count": 1,
                "logical_read_address_count": 1,
                "physical_source_count": 1,
                "rom_value_match_count": 1,
            },
            source_slot_name="slot2",
            mapped_bank=8,
            physical_source_offset=0x21ABC,
            captured_utc="2026-08-01T00:00:00Z",
        )
        validate_active_register_rom_source(safe)
        self.assertTrue(safe["rom_source_confirmed"])
        self.assertEqual(safe["source_region"], "original-rom")
        self.assertEqual(
            safe["next_checkpoint"],
            "correlate-original-rom-source-with-script-table",
        )

    def test_classifies_known_korean_engine_regions(self) -> None:
        self.assertEqual(physical_source_region(0x80100), "korean-huffman-vector")
        self.assertEqual(physical_source_region(0x80300), "korean-huffman-tree")
        self.assertEqual(
            physical_source_region(0x87000),
            "korean-font-runtime-primary",
        )
        self.assertEqual(physical_source_region(0x87400), "korean-font-page-map")
        self.assertEqual(
            physical_source_region(0x87A00),
            "korean-font-runtime-secondary",
        )
        self.assertEqual(physical_source_region(0x88000), "korean-font-data")

    def test_accepts_pre_and_post_instruction_breakpoint_pc(self) -> None:
        for observed_pc in (0x4567, 0x4569):
            with self.subTest(observed_pc=observed_pc):
                self.assertTrue(
                    instruction_breakpoint_matches(
                        {"executing_bank": 0x21, "pc_after": observed_pc},
                        expected_bank=0x21,
                        expected_pc=0x4567,
                        instruction_size=2,
                    )
                )
        self.assertFalse(
            instruction_breakpoint_matches(
                {"executing_bank": 0x20, "pc_after": 0x4567},
                expected_bank=0x21,
                expected_pc=0x4567,
                instruction_size=2,
            )
        )


if __name__ == "__main__":
    unittest.main()
