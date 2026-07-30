from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import unittest

from tools.patch_io import BPSSparseTarget, PatchError, extract_bps_target_literals
from tools.v5_1_test_phrase import (
    TEST_GLYPHS,
    TEST_PHRASE,
    build_length_preserving_test_phrase_plan,
    build_test_phrase_plan,
    font_tile_offset,
    page_select_symbols,
    length_preserving_symbols,
    symbols_for_text,
    validate_glyphs,
)


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patch" / "Final_Conflict_Japan_to_Korean_v5.1.bps"


class TestPhraseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.patch = PATCH.read_bytes()
        cls.sparse = extract_bps_target_literals(cls.patch)

    def test_approved_phrase_has_deterministic_font_symbols(self) -> None:
        self.assertEqual(TEST_PHRASE, "한다")
        self.assertEqual(page_select_symbols(6), [0x5F, 0x02, 0x08])
        self.assertEqual(
            symbols_for_text(TEST_PHRASE),
            [0x5F, 0x02, 0x08, 0x11, 0x04],
        )
        self.assertEqual(font_tile_offset(6, 0x11), 0x08DA20)
        self.assertEqual(font_tile_offset(6, 0x04), 0x08D880)

    def test_unknown_character_fails_closed(self) -> None:
        with self.assertRaisesRegex(PatchError, "no approved test glyph"):
            symbols_for_text("한글")

    def test_invalid_font_coordinates_fail_closed(self) -> None:
        with self.assertRaises(PatchError):
            font_tile_offset(244, 0x02)
        with self.assertRaises(PatchError):
            font_tile_offset(0, 0x21)

    def test_glyph_hash_mismatch_fails_closed(self) -> None:
        glyphs = dict(TEST_GLYPHS)
        glyphs["한"] = replace(glyphs["한"], tile_sha256="0" * 64)
        with self.assertRaisesRegex(PatchError, "tile identity mismatch"):
            validate_glyphs(self.sparse, glyphs=glyphs)

    def test_glyph_ink_mask_mismatch_fails_closed(self) -> None:
        glyphs = dict(TEST_GLYPHS)
        glyphs["한"] = replace(
            glyphs["한"],
            ink_mask=(0,) * 8,
        )
        with self.assertRaisesRegex(PatchError, "ink mask mismatch"):
            validate_glyphs(self.sparse, glyphs=glyphs)

    def test_unknown_font_byte_fails_closed(self) -> None:
        glyph = TEST_GLYPHS["한"]
        offset = font_tile_offset(glyph.page, glyph.symbol)
        known = bytearray(self.sparse.known)
        known[offset] = 0
        sparse = BPSSparseTarget(
            report=self.sparse.report,
            data=self.sparse.data,
            known=bytes(known),
        )
        with self.assertRaisesRegex(PatchError, "not source-independent"):
            validate_glyphs(sparse)

    def test_plan_roundtrips_exact_korean_huffman_bits(self) -> None:
        plan = build_test_phrase_plan(self.patch)
        self.assertEqual(plan["status"], "verified-static-non-build-eligible")
        self.assertEqual(plan["purpose"], "technical-poc-only")
        self.assertEqual(
            plan["encoding"]["symbols"],
            [0x5F, 0x02, 0x08, 0x11, 0x04, 0xC9],
        )
        self.assertEqual(plan["encoding"]["encoded_bits"], 31)
        self.assertEqual(plan["encoding"]["encoded_hex"], "ea512d10")
        self.assertTrue(plan["encoding"]["roundtrip_exact"])
        self.assertFalse(plan["translation_build_eligible"])
        self.assertFalse(plan["checks"]["rom_read"])
        self.assertFalse(plan["checks"]["rom_written"])

    def test_unapproved_free_text_is_rejected(self) -> None:
        with self.assertRaisesRegex(PatchError, "only the approved"):
            build_test_phrase_plan(self.patch, "다한")

    def test_exact_106_bit_phrase_uses_only_safe_page_padding(self) -> None:
        plan = build_length_preserving_test_phrase_plan(self.patch, 106)
        self.assertEqual(
            plan["status"],
            "verified-static-exact-length-non-build-eligible",
        )
        self.assertEqual(plan["encoding"]["encoded_bits"], 106)
        self.assertEqual(
            plan["encoding"]["symbols"],
            [
                0x5F, 0x02, 0x02,
                0x5F, 0x02, 0x02,
                0x5F, 0x02, 0x02,
                0x5F, 0x02, 0x08,
                0x11, 0x04,
                0x5F, 0x02, 0x08,
                0xC9,
            ],
        )
        self.assertEqual(
            plan["encoding"]["encoded_hex"],
            "ea4a95d4a95d4a95d512d32d4400",
        )
        self.assertTrue(plan["encoding"]["length_preserving"])
        self.assertTrue(plan["encoding"]["page_select_only_padding"])
        self.assertEqual(plan["encoding"]["final_selected_page"], 6)

    def test_impossible_exact_length_fails_closed(self) -> None:
        with self.assertRaisesRegex(PatchError, "no display-equivalent"):
            build_length_preserving_test_phrase_plan(self.patch, 32)

    def test_exact_87_bit_runtime_stream_phrase_is_deterministic(self) -> None:
        plan = build_length_preserving_test_phrase_plan(self.patch, 87)
        self.assertEqual(plan["encoding"]["encoded_bits"], 87)
        self.assertEqual(
            plan["encoding"]["encoded_hex"],
            "ea4a95d4a95d539d512d10",
        )
        self.assertEqual(plan["encoding"]["final_selected_page"], 6)

    def test_exact_106_bit_selected_group_phrase_is_deterministic(self) -> None:
        plan = build_length_preserving_test_phrase_plan(self.patch, 106)
        self.assertEqual(plan["encoding"]["encoded_bits"], 106)
        self.assertEqual(
            plan["encoding"]["encoded_hex"],
            "ea4a95d4a95d4a95d512d32d4400",
        )
        self.assertEqual(plan["encoding"]["final_selected_page"], 6)

    def test_exact_200_bit_observed_entry_phrase_is_deterministic(self) -> None:
        plan = build_length_preserving_test_phrase_plan(self.patch, 200)
        self.assertEqual(plan["encoding"]["encoded_bits"], 200)
        self.assertEqual(
            plan["encoding"]["encoded_hex"],
            (
                "ea4a95d4a95db82baf6fe63dbf98f6fe63dbf98f6fe6"
                "289688"
            ),
        )
        self.assertEqual(plan["encoding"]["final_selected_page"], 6)

    def test_exact_length_rejects_invalid_budget(self) -> None:
        with self.assertRaisesRegex(PatchError, "safe search range"):
            build_length_preserving_test_phrase_plan(self.patch, 0)


if __name__ == "__main__":
    unittest.main()
