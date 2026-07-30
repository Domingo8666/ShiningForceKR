from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_decoder_caller_resolution import (  # noqa: E402
    analyze_decoder_caller,
    build_decoder_caller_resolution,
    validate_decoder_caller_resolution,
)
from tools.v5_1_script_group import LOOKUP_TABLE_BASE  # noqa: E402


class DecoderCallerResolutionTests(unittest.TestCase):
    def test_resolves_containing_routine_and_scans_callers(self) -> None:
        rom = bytearray(0x5000)
        rom[LOOKUP_TABLE_BASE : LOOKUP_TABLE_BASE + 4] = bytes(
            (0x20, 0x40, 0xDE, 0x43)
        )
        routine = 0x3000
        rom[0x100:0x103] = bytes(
            (0xCD, routine & 0xFF, routine >> 8)
        )
        for offset, ordinal, selector in (
            (0x200, 5, 0),
            (0x300, 9, 2),
        ):
            rom[offset : offset + 9] = bytes(
                (
                    0x01,
                    0x02,
                    ordinal,
                    0x11,
                    selector,
                    0x00,
                    0xCD,
                    routine & 0xFF,
                    routine >> 8,
                )
            )
        probe = {
            "attempts": [
                {
                    "hit": {"pc_after": 0x33FA},
                    "evidence": {
                        "call_stack": {
                            "stack": [
                                {
                                    "function": "$3000",
                                    "source": "$0100",
                                    "return": "$0103",
                                }
                            ]
                        }
                    },
                }
            ]
        }
        safe, local = analyze_decoder_caller(bytes(rom), probe)
        self.assertTrue(
            safe["stack"]["containing_routine_resolved"]
        )
        self.assertEqual(
            safe["caller_scan"]["routine_call_signature_count"],
            3,
        )
        self.assertEqual(
            safe["caller_scan"][
                "lookup_selectors_with_call_evidence_count"
            ],
            2,
        )
        self.assertEqual(local["selector_candidates"], [0, 2])

    def test_uses_emulator_function_field_for_banked_return_frame(self) -> None:
        rom = bytearray(0x5000)
        rom[LOOKUP_TABLE_BASE : LOOKUP_TABLE_BASE + 2] = bytes(
            (0x20, 0x40)
        )
        probe = {
            "attempts": [
                {
                    "hit": {"pc_after": 0x33FA},
                    "evidence": {
                        "call_stack": {
                            "stack": [
                                {
                                    "function": "$3000",
                                    "source": "$8000",
                                    "return": "$8003",
                                }
                            ]
                        }
                    },
                }
            ]
        }
        safe, local = analyze_decoder_caller(bytes(rom), probe)
        self.assertTrue(
            safe["stack"]["containing_routine_resolved"]
        )
        self.assertEqual(safe["stack"]["direct_call_frame_count"], 0)
        self.assertEqual(local["selected_containing_routine"], 0x3000)

    def test_builds_safe_receipt_and_rejects_local_leakage(self) -> None:
        artifact = build_decoder_caller_resolution(
            target_sha256="1" * 64,
            source_target_group_usage_sha256="2" * 64,
            source_renderer_probe_sha256="3" * 64,
            stack={
                "depth": 3,
                "parsed_return_count": 3,
                "direct_call_frame_count": 2,
                "containing_routine_candidate_count": 1,
                "containing_routine_resolved": True,
            },
            caller_scan={
                "lookup_selector_count": 8,
                "routine_call_signature_count": 12,
                "calls_with_selector_candidate_count": 8,
                "calls_with_ordinal_candidate_count": 10,
                "calls_with_both_candidates_count": 8,
                "unique_selector_candidate_count": 8,
                "lookup_selectors_with_call_evidence_count": 8,
                "lookup_selectors_without_call_evidence_count": 0,
            },
            captured_utc="2026-07-30T16:20:00Z",
        )
        validate_decoder_caller_resolution(artifact)
        self.assertEqual(
            artifact["status"],
            "decoder-caller-static-usage-complete",
        )
        for field, local_value in (
            ("return_addresses", [0x103]),
            ("routine_address", 0x3000),
            ("nearby_hex", "010205110000CD0030"),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = local_value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_decoder_caller_resolution(unsafe)


if __name__ == "__main__":
    unittest.main()
