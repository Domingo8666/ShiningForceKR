from __future__ import annotations

import unittest

from tools.v5_1_active_register_rom_source import (
    build_active_register_rom_source,
    physical_rom_source,
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
                "execute_break_hit_count": 3,
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
        self.assertEqual(
            safe["next_checkpoint"],
            "correlate-active-rom-source-with-script-or-font",
        )


if __name__ == "__main__":
    unittest.main()
