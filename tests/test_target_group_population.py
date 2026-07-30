from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_script_group import LOOKUP_TABLE_BASE  # noqa: E402
from tools.v5_1_target_group_population import (  # noqa: E402
    ADDRESSABLE_RECORD_COUNT,
    analyze_target_group_population,
    build_target_group_population,
    validate_target_group_population,
)


class TargetGroupPopulationTests(unittest.TestCase):
    def test_enumerates_all_addressable_slots_and_deduplicates(self) -> None:
        rom = bytearray(0x24000)
        rom[LOOKUP_TABLE_BASE : LOOKUP_TABLE_BASE + 4] = bytes(
            (0x00, 0x40, 0x03, 0x40)
        )
        start = 8 * 0x4000
        safe, local = analyze_target_group_population(
            bytes(rom),
            mapped_bank=8,
            confirmed_selector=0,
            confirmed_physical_start=start,
            confirmed_selected_ordinal=2,
        )
        self.assertEqual(safe["selector_count"], 2)
        self.assertEqual(
            safe["parsed_record_slot_count"],
            2 * ADDRESSABLE_RECORD_COUNT,
        )
        self.assertEqual(
            safe["unique_physical_record_count"],
            ADDRESSABLE_RECORD_COUNT + 3,
        )
        self.assertTrue(safe["confirmed_selected_record_match"])
        self.assertEqual(len(local["groups"]), 2)

    def test_builds_safe_receipt_and_rejects_payloads(self) -> None:
        artifact = build_target_group_population(
            target_sha256="1" * 64,
            source_target_group_usage_sha256="2" * 64,
            source_stream_map_sha256="3" * 64,
            source_confirmed_group_extract_sha256="4" * 64,
            population={
                "selector_count": 8,
                "addressable_records_per_selector": 256,
                "requested_record_slot_count": 2048,
                "parsed_record_slot_count": 2048,
                "selectors_reaching_full_addressable_count": 8,
                "selectors_stopped_at_bank_boundary_count": 0,
                "unique_physical_record_count": 900,
                "shared_physical_record_count": 600,
                "overlapping_record_slot_count": 1148,
                "zero_length_record_slot_count": 0,
                "maximum_record_bytes": 32,
                "confirmed_selected_record_match": True,
            },
            captured_utc="2026-07-30T16:40:00Z",
        )
        validate_target_group_population(artifact)
        self.assertEqual(
            artifact["status"],
            "target-group-addressable-population-enumerated",
        )
        for field, local_value in (
            ("payload_hex", "AABB"),
            ("record_boundaries", [0x20000]),
            ("selectors", [0, 2]),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = local_value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_target_group_population(unsafe)


if __name__ == "__main__":
    unittest.main()
