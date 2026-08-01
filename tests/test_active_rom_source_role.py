from __future__ import annotations

import unittest

from tools.v5_1_active_rom_source_role import (
    analyze_source_role,
    build_active_rom_source_role,
    validate_active_rom_source_role,
)


class ActiveRomSourceRoleTests(unittest.TestCase):
    def test_classifies_a_script_payload_before_renderer_data(self) -> None:
        counts, result = analyze_source_role(
            logical_reads=list(range(0x6AC0, 0x6AE0)),
            logical_source=0x6AC9,
            mapped_bank=1,
            physical_source_offset=0x6AC9,
            target_transfer_count=192,
            records=[{
                "length_offset": 0x6ABF,
                "payload_start": 0x6AC0,
                "payload_end": 0x6AE0,
            }],
            executed_physical_offsets=set(),
            matching_definition_event_count=32,
        )
        self.assertEqual(result["source_role"], "script-record-payload")
        self.assertEqual(counts["source_script_payload_match_count"], 1)

    def test_classifies_contiguous_tile_sized_renderer_source(self) -> None:
        counts, result = analyze_source_role(
            logical_reads=list(range(0x6A80, 0x6B40)),
            logical_source=0x6AC9,
            mapped_bank=1,
            physical_source_offset=0x6AC9,
            target_transfer_count=192,
            records=[],
            executed_physical_offsets=set(),
            matching_definition_event_count=192,
        )
        self.assertEqual(result["source_role"], "renderer-source-candidate")
        self.assertEqual(counts["target_transfer_tile_count"], 6)
        safe = build_active_rom_source_role(
            target_sha256="a" * 64,
            source_active_register_rom_source_sha256="b" * 64,
            source_register_trace_sha256="c" * 64,
            source_target_population_sha256="d" * 64,
            analysis=counts,
            source_role_name=str(result["source_role"]),
            captured_utc="2026-08-02T00:00:00Z",
        )
        validate_active_rom_source_role(safe)
        self.assertTrue(safe["renderer_asset_source_candidate"])
        self.assertFalse(safe["script_record_source_confirmed"])

    def test_executed_source_is_not_treated_as_text(self) -> None:
        _, result = analyze_source_role(
            logical_reads=[0x6AC9],
            logical_source=0x6AC9,
            mapped_bank=1,
            physical_source_offset=0x6AC9,
            target_transfer_count=192,
            records=[],
            executed_physical_offsets={0x6AC9},
            matching_definition_event_count=1,
        )
        self.assertEqual(result["source_role"], "executed-code")


if __name__ == "__main__":
    unittest.main()
