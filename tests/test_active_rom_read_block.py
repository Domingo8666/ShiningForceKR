from __future__ import annotations

import unittest

from tools.v5_1_active_rom_read_block import (
    analyze_active_rom_reads,
    build_active_rom_read_block,
    validate_active_rom_read_block,
)


class ActiveRomReadBlockTests(unittest.TestCase):
    def test_classifies_repeated_scattered_reads_as_lookup_candidate(self) -> None:
        reads = [0x6AC9, 0x6AD1, 0x6AE5, 0x6AF0] * 3
        counts, result = analyze_active_rom_reads(
            logical_reads=reads,
            logical_source=0x6AC9,
            mapped_bank=1,
            records=[],
            rom=bytes(range(256)) * 256,
        )
        self.assertEqual(result["access_pattern"], "scattered-lookup-candidate")
        self.assertEqual(counts["read_occurrence_count"], 12)
        self.assertEqual(counts["unique_logical_read_count"], 4)
        safe = build_active_rom_read_block(
            target_sha256="a" * 64,
            source_active_rom_source_role_sha256="b" * 64,
            source_active_register_rom_source_sha256="c" * 64,
            source_target_population_sha256="d" * 64,
            analysis=counts,
            access_pattern=str(result["access_pattern"]),
            captured_utc="2026-08-02T00:00:00Z",
        )
        validate_active_rom_read_block(safe)
        self.assertTrue(safe["lookup_table_candidate"])

    def test_prioritizes_projected_script_record_matches(self) -> None:
        counts, result = analyze_active_rom_reads(
            logical_reads=[0x6AC9, 0x6AD1, 0x6AC9],
            logical_source=0x6AC9,
            mapped_bank=1,
            records=[{
                "length_offset": 0x6AC8,
                "payload_start": 0x6AC9,
                "payload_end": 0x6ACA,
            }],
            rom=bytes(range(256)) * 256,
        )
        self.assertEqual(
            result["access_pattern"], "script-record-neighborhood-candidate"
        )
        self.assertEqual(counts["script_payload_projection_match_count"], 1)

    def test_classifies_a_fixed_stride_table(self) -> None:
        counts, result = analyze_active_rom_reads(
            logical_reads=[0x6AC0, 0x6AC4, 0x6AC8, 0x6ACC] * 2,
            logical_source=0x6AC0,
            mapped_bank=1,
            records=[],
            rom=bytes(range(256)) * 256,
        )
        self.assertEqual(result["access_pattern"], "fixed-stride-lookup-candidate")
        self.assertEqual(counts["fixed_stride_bytes"], 4)

    def test_classifies_a_contiguous_block(self) -> None:
        _, result = analyze_active_rom_reads(
            logical_reads=list(range(0x6AC0, 0x6AD0)),
            logical_source=0x6AC0,
            mapped_bank=1,
            records=[],
            rom=bytes(range(256)) * 256,
        )
        self.assertEqual(result["access_pattern"], "contiguous-block-candidate")


if __name__ == "__main__":
    unittest.main()
