from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_group_text_candidate_resolution import (  # noqa: E402
    build_group_text_candidate_resolution,
    resolve_group_text_candidates,
    validate_group_text_candidate_resolution,
)


class GroupTextCandidateResolutionTests(unittest.TestCase):
    def test_deduplicates_contexts_and_selects_mappable_text(self) -> None:
        correct = ["0x5F", "0x02", "0x02", "0x02", "0xC9"]
        records = [
            {
                "entry_id": "group-02/000",
                "ordinal": 0,
                "candidate_decodes": [
                    {
                        "initial_context_hex": "0x04",
                        "symbols_hex": correct,
                    },
                    {
                        "initial_context_hex": "0x09",
                        "symbols_hex": ["0x02", "0xC9"],
                    },
                ],
            },
            {
                "entry_id": "group-02/001",
                "ordinal": 1,
                "candidate_decodes": [
                    {
                        "initial_context_hex": "0x04",
                        "symbols_hex": correct,
                    },
                    {
                        "initial_context_hex": "0x09",
                        "symbols_hex": correct,
                    },
                ],
            },
            {
                "entry_id": "group-02/002",
                "ordinal": 2,
                "candidate_decodes": [
                    {
                        "initial_context_hex": "0x04",
                        "symbols_hex": ["0x02", "0xC9"],
                    }
                ],
            },
        ]
        catalog = [
            {
                "page": 0,
                "symbol": 0x02,
                "codepoints": [0xAC00],
                "characters": ["가"],
            }
        ]
        safe, local = resolve_group_text_candidates(
            records=records,
            catalog_entries=catalog,
            candidate_pages=[0],
        )
        self.assertEqual(safe["unique_best_record_count"], 2)
        self.assertEqual(safe["no_valid_text_record_count"], 1)
        self.assertEqual(safe["candidate_context_decode_count"], 5)
        self.assertEqual(safe["candidate_symbol_stream_count"], 4)
        self.assertEqual(len(local["resolved_records"]), 2)
        self.assertEqual(
            local["records"][1]["selected_context_count"],
            2,
        )

    def test_builds_safe_partial_result_and_rejects_stream_leakage(self) -> None:
        artifact = build_group_text_candidate_resolution(
            target_sha256="1" * 64,
            source_context_resolution_sha256="2" * 64,
            source_group_delta_sha256="3" * 64,
            source_visible_mapping_sha256="4" * 64,
            source_font_catalog_sha256="5" * 64,
            selector=2,
            record_count=3,
            resolution={
                "candidate_context_decode_count": 5,
                "candidate_symbol_stream_count": 4,
                "valid_text_stream_count": 2,
                "unique_best_record_count": 2,
                "ambiguous_best_record_count": 0,
                "no_valid_text_record_count": 1,
                "selected_visible_glyph_count": 2,
                "selected_unique_glyph_count": 2,
                "selected_ambiguous_glyph_count": 0,
                "selected_unmatched_glyph_count": 0,
                "selected_page_select_count": 2,
            },
            captured_utc="2026-07-30T16:30:00Z",
        )
        validate_group_text_candidate_resolution(artifact)
        self.assertEqual(
            artifact["status"],
            "group-text-candidates-partially-resolved",
        )
        for field, value in (
            ("symbols_hex", ["0x02", "0xC9"]),
            ("candidate_pages", [0, 4]),
            ("decoded_text", "가"),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_group_text_candidate_resolution(unsafe)


if __name__ == "__main__":
    unittest.main()
