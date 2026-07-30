from copy import deepcopy
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_target_group_population_decode import (  # noqa: E402
    build_target_group_population_decode,
    deduplicate_population_records,
    validate_target_group_population_decode,
)


class TargetGroupPopulationDecodeTests(unittest.TestCase):
    def test_deduplicates_aliases_and_tracks_confirmed_record(self) -> None:
        payload = bytes((0xAA, 0xBB))
        digest = hashlib.sha256(payload).hexdigest()
        local = {
            "analysis": {
                "groups": [
                    {
                        "records": [
                            {
                                "selector": 0,
                                "ordinal": 1,
                                "length_offset": 100,
                                "record_length_bytes": 2,
                                "payload_hex": "AABB",
                                "payload_sha256": digest,
                            },
                            {
                                "selector": 2,
                                "ordinal": 147,
                                "length_offset": 100,
                                "record_length_bytes": 2,
                                "payload_hex": "AABB",
                                "payload_sha256": digest,
                            },
                        ]
                    }
                ]
            }
        }
        records, confirmed = deduplicate_population_records(local)
        self.assertEqual(len(records), 1)
        self.assertEqual(len(records[0]["aliases"]), 2)
        self.assertEqual(confirmed, records[0]["entry_id"])

    def test_builds_safe_receipt_and_rejects_text(self) -> None:
        artifact = build_target_group_population_decode(
            target_sha256="1" * 64,
            source_population_sha256="2" * 64,
            source_visible_mapping_sha256="3" * 64,
            source_font_catalog_sha256="4" * 64,
            decode={
                "unique_population_record_count": 837,
                "nonempty_record_count": 800,
                "zero_length_record_count": 37,
                "records_with_exact_roundtrip_count": 300,
                "records_without_exact_roundtrip_count": 500,
                "candidate_context_decode_count": 500,
                "candidate_symbol_stream_count": 400,
                "valid_text_stream_count": 250,
                "unique_best_text_record_count": 200,
                "ambiguous_best_text_record_count": 20,
                "no_valid_text_record_count": 80,
                "selected_visible_glyph_count": 2000,
                "selected_unique_glyph_count": 1800,
                "selected_ambiguous_glyph_count": 100,
                "selected_unmatched_glyph_count": 100,
                "selected_page_select_count": 220,
                "confirmed_selected_quality_match": True,
            },
            captured_utc="2026-07-30T16:50:00Z",
        )
        validate_target_group_population_decode(artifact)
        self.assertEqual(
            artifact["status"],
            "target-group-population-text-partially-resolved",
        )
        for field, local_value in (
            ("text", "기다려라"),
            ("symbols", [1, 2]),
            ("contexts", [0xC9]),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = local_value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_target_group_population_decode(unsafe)


if __name__ == "__main__":
    unittest.main()
