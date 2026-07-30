from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_source_record_pairing import (  # noqa: E402
    analyze_source_record_pairing,
    build_source_record_pairing,
    validate_source_record_pairing,
)


class SourceRecordPairingTests(unittest.TestCase):
    def test_pairs_consistently_terminated_source_symbols_by_ordinal(self) -> None:
        counts, local = analyze_source_record_pairing(
            source_records=[
                {"ordinal": 0, "payload": b"\x10\x11\xC9"},
                {"ordinal": 1, "payload": b"\x12\xC9"},
                {"ordinal": 2, "payload": b"\x13\x14\xC9"},
            ],
            target_records=[
                {
                    "entry_id": "group-02/002",
                    "ordinal": 2,
                    "translation_text": "가",
                    "unicode_complete": True,
                    "unresolved_glyph_count": 0,
                    "tokens": [],
                },
                {
                    "entry_id": "group-02/000",
                    "ordinal": 0,
                    "translation_text": "나",
                    "unicode_complete": True,
                    "unresolved_glyph_count": 0,
                    "tokens": [],
                },
            ],
        )
        self.assertEqual(counts["dominant_final_symbol_record_count"], 3)
        self.assertEqual(counts["distinct_final_symbol_count"], 1)
        self.assertEqual(counts["ordinal_pair_count"], 2)
        self.assertEqual(counts["source_body_symbol_count"], 5)
        self.assertEqual(
            local["records"][0]["source_symbols_hex"],
            ["0x13", "0x14"],
        )

    def test_builds_safe_pairing_and_rejects_text_leakage(self) -> None:
        artifact = build_source_record_pairing(
            source_sha256="1" * 64,
            target_sha256="2" * 64,
            source_group_extract_sha256="3" * 64,
            source_group_delta_sha256="4" * 64,
            source_target_corpus_sha256="5" * 64,
            local_paired_corpus_sha256="6" * 64,
            selector=2,
            source_record_count=3,
            target_candidate_record_count=2,
            pairing={
                "source_nonempty_record_count": 3,
                "distinct_final_symbol_count": 1,
                "dominant_final_symbol_record_count": 3,
                "records_with_internal_dominant_symbol_count": 0,
                "source_total_payload_byte_count": 8,
                "source_body_symbol_count": 5,
                "source_distinct_body_symbol_count": 5,
                "ordinal_pair_count": 2,
                "unpaired_target_record_count": 0,
                "duplicate_target_ordinal_count": 0,
            },
            captured_utc="2026-07-30T19:30:00Z",
        )
        validate_source_record_pairing(artifact)
        self.assertTrue(artifact["source_symbol_pairing_complete"])
        self.assertFalse(artifact["source_unicode_pairing_complete"])
        for field, value in (
            ("source_symbols_hex", ["0x10"]),
            ("terminator", "0xC9"),
            ("source_text", "待て"),
            ("translation_text", "기다려라"),
            ("speaker_id", "hero"),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_source_record_pairing(unsafe)


if __name__ == "__main__":
    unittest.main()
