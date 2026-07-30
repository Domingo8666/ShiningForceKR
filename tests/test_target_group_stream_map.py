from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_script_group import LOOKUP_TABLE_BASE  # noqa: E402
from tools.v5_1_target_group_stream_map import (  # noqa: E402
    analyze_target_group_stream,
    build_target_group_stream_map,
    validate_target_group_stream_map,
)


class TargetGroupStreamMapTests(unittest.TestCase):
    def test_aligns_lookup_anchors_in_one_record_stream(self) -> None:
        rom = bytearray(0x24000)
        rom[LOOKUP_TABLE_BASE : LOOKUP_TABLE_BASE + 4] = bytes(
            (0x00, 0x40, 0x03, 0x40)
        )
        start = 8 * 0x4000
        rom[start : start + 9] = bytes(
            (2, 0xAA, 0xBB, 1, 0xCC, 3, 0xDD, 0xEE, 0xFF)
        )
        safe, local = analyze_target_group_stream(
            bytes(rom),
            mapped_bank=8,
            confirmed_physical_start=start + 3,
            confirmed_selected_ordinal=1,
        )
        self.assertEqual(safe["valid_pointer_count"], 2)
        self.assertEqual(safe["aligned_pointer_count"], 2)
        self.assertTrue(safe["confirmed_group_start_aligned"])
        self.assertTrue(safe["confirmed_selected_record_aligned"])
        self.assertEqual(
            local["pointer_map"][1]["global_ordinal"],
            1,
        )

    def test_builds_safe_receipt_and_rejects_boundaries(self) -> None:
        artifact = build_target_group_stream_map(
            target_sha256="1" * 64,
            source_target_group_usage_sha256="2" * 64,
            source_confirmed_group_extract_sha256="3" * 64,
            stream={
                "valid_pointer_count": 8,
                "aligned_pointer_count": 8,
                "unaligned_pointer_count": 0,
                "parsed_record_count": 500,
                "zero_length_record_count": 0,
                "covered_record_byte_count": 8000,
                "target_span_reached": True,
                "confirmed_group_start_aligned": True,
                "confirmed_selected_record_aligned": True,
                "all_pointer_anchors_aligned": True,
            },
            captured_utc="2026-07-30T16:30:00Z",
        )
        validate_target_group_stream_map(artifact)
        self.assertEqual(
            artifact["status"],
            "target-group-record-stream-aligned",
        )
        for field, local_value in (
            ("pointers", [0x401E]),
            ("record_boundaries", [0x2001E]),
            ("lengths", [12, 4]),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = local_value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_target_group_stream_map(unsafe)


if __name__ == "__main__":
    unittest.main()
