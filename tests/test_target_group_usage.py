from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_decoder_register_trace import DECODER_ENTRY  # noqa: E402
from tools.v5_1_script_group import LOOKUP_TABLE_BASE  # noqa: E402
from tools.v5_1_target_group_usage import (  # noqa: E402
    analyze_target_group_usage,
    build_target_group_usage,
    validate_target_group_usage,
)


class TargetGroupUsageTests(unittest.TestCase):
    def test_collects_conservative_immediate_call_candidates(self) -> None:
        rom = bytearray(0x5000)
        rom[LOOKUP_TABLE_BASE : LOOKUP_TABLE_BASE + 4] = bytes(
            (0x20, 0x40, 0xDE, 0x43)
        )
        call = bytes((0xCD, DECODER_ENTRY & 0xFF, DECODER_ENTRY >> 8))
        rom[0x100:0x109] = bytes(
            (0x01, 0x02, 0x05, 0x11, 0x00, 0x00)
        ) + call
        rom[0x200:0x209] = bytes(
            (0x01, 0x03, 0x09, 0x11, 0x02, 0x00)
        ) + call
        counts, local = analyze_target_group_usage(bytes(rom))
        self.assertEqual(counts["valid_pointer_count"], 2)
        self.assertEqual(counts["decoder_call_signature_count"], 2)
        self.assertEqual(counts["calls_with_both_candidates_count"], 2)
        self.assertEqual(counts["unique_selector_candidate_count"], 2)
        self.assertEqual(
            counts["lookup_selectors_without_call_evidence_count"],
            0,
        )
        self.assertEqual(local["selector_candidates"], [0, 2])

    def test_builds_safe_counts_and_rejects_pointer_leakage(self) -> None:
        artifact = build_target_group_usage(
            target_sha256="1" * 64,
            source_group_extract_sha256="2" * 64,
            lookup={
                "slot_count": 12,
                "valid_pointer_count": 2,
                "unique_pointer_count": 2,
                "duplicate_pointer_count": 0,
            },
            static_usage={
                "decoder_call_signature_count": 3,
                "calls_with_selector_candidate_count": 2,
                "calls_with_ordinal_candidate_count": 3,
                "calls_with_both_candidates_count": 2,
                "unique_selector_candidate_count": 2,
                "lookup_selectors_with_call_evidence_count": 2,
                "lookup_selectors_without_call_evidence_count": 0,
            },
            captured_utc="2026-07-30T20:00:00Z",
        )
        validate_target_group_usage(artifact)
        self.assertEqual(
            artifact["status"],
            "target-group-static-usage-complete",
        )
        for field, value in (
            ("pointers", [0x401E]),
            ("call_offsets", [0x100]),
            ("selector_candidates", [0, 2]),
            ("nearby_hex", "010205110200CDFA33"),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_target_group_usage(unsafe)


if __name__ == "__main__":
    unittest.main()
