from __future__ import annotations

import copy
import unittest

from tools.v5_1_first_context_translated_glyph_route import (
    analyze_translated_glyph_route,
    build_first_context_translated_glyph_route,
    validate_first_context_translated_glyph_route,
)


class FirstContextTranslatedGlyphRouteTests(unittest.TestCase):
    def test_confirms_direct_vram_tile_to_symbol_alignment(self) -> None:
        tile_hash = "a" * 64
        local_vram = {
            "analysis": {
                "changed_custom_glyph_matches": [
                    {"tile_index": 0x35, "tile_sha256": tile_hash}
                ]
            }
        }
        local_encoding = {
            "character_assignments": [
                {
                    "row_index": 1,
                    "page": 240,
                    "symbol": 0x35,
                    "tile_sha256": tile_hash,
                },
                {
                    "row_index": 2,
                    "page": 241,
                    "symbol": 0x36,
                    "tile_sha256": tile_hash,
                },
            ]
        }
        counts, local = analyze_translated_glyph_route(local_vram, local_encoding)
        self.assertEqual(counts["match_with_slot_alignment_count"], 1)
        self.assertEqual(counts["uniquely_aligned_match_count"], 1)
        self.assertEqual(counts["aligned_candidate_page_count"], 1)
        self.assertEqual(local["aligned_pages"], [240])
        self.assertEqual(local["pairing_method"], "direct-vram-tile-hash-pairs")
        value = build_first_context_translated_glyph_route(
            baseline_target_sha256="1" * 64,
            test_target_sha256="2" * 64,
            source_translated_vram_diff_sha256="3" * 64,
            source_local_encoding_sha256="4" * 64,
            local_route_sha256="5" * 64,
            analysis=counts,
            captured_utc="2026-08-02T00:00:00Z",
        )
        validate_first_context_translated_glyph_route(value)
        self.assertTrue(value["direct_glyph_slot_alignment_confirmed"])
        self.assertTrue(value["single_font_page_candidate_confirmed"])
        self.assertTrue(value["first_row_candidate_observed"])

    def test_recovers_old_one_to_one_capture_without_rerunning_emulator(self) -> None:
        hash_a = "a" * 64
        hash_b = "b" * 64
        local_vram = {
            "analysis": {
                "changed_custom_glyph_match_tiles": [0x35, 0x36],
                "changed_custom_glyph_hashes": [hash_b, hash_a],
            }
        }
        local_encoding = {
            "character_assignments": [
                {
                    "row_index": 1,
                    "page": 240,
                    "symbol": 0x35,
                    "tile_sha256": hash_a,
                },
                {
                    "row_index": 1,
                    "page": 240,
                    "symbol": 0x36,
                    "tile_sha256": hash_b,
                },
            ]
        }
        counts, local = analyze_translated_glyph_route(local_vram, local_encoding)
        self.assertEqual(counts["match_with_slot_alignment_count"], 2)
        self.assertEqual(counts["uniquely_aligned_match_count"], 2)
        self.assertEqual(
            local["pairing_method"],
            "unique-slot-constrained-legacy-pairs",
        )

    def test_rejects_an_inconsistent_safe_conclusion(self) -> None:
        counts = {
            "confirmed_vram_match_count": 1,
            "assignment_candidate_count": 0,
            "slot_aligned_candidate_count": 0,
            "match_with_slot_alignment_count": 0,
            "uniquely_aligned_match_count": 0,
            "aligned_candidate_page_count": 0,
            "aligned_candidate_row_count": 0,
            "first_row_aligned_candidate_count": 0,
        }
        value = build_first_context_translated_glyph_route(
            baseline_target_sha256="1" * 64,
            test_target_sha256="2" * 64,
            source_translated_vram_diff_sha256="3" * 64,
            source_local_encoding_sha256="4" * 64,
            local_route_sha256="5" * 64,
            analysis=counts,
            captured_utc="2026-08-02T00:00:00Z",
        )
        invalid = copy.deepcopy(value)
        invalid["direct_glyph_slot_alignment_confirmed"] = True
        with self.assertRaises(ValueError):
            validate_first_context_translated_glyph_route(invalid)


if __name__ == "__main__":
    unittest.main()
