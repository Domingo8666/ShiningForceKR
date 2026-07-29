from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import unittest

from tools.patch_io import BPSSparseTarget, PatchError, extract_bps_target_literals
from tools.v5_1_test_phrase import (
    TEST_GLYPHS,
    TEST_PHRASE,
    build_test_phrase_plan,
    font_tile_offset,
    page_select_symbols,
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
        self.assertEqual(page_select_symbols(27), [0x5F, 0x03, 0x0D])
        self.assertEqual(
            symbols_for_text(TEST_PHRASE),
            [0x5F, 0x03, 0x0D, 0x1F, 0x04],
        )
        self.assertEqual(font_tile_offset(27, 0x1F), 0x0A27E0)
        self.assertEqual(font_tile_offset(27, 0x04), 0x0A2480)

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
            [0x5F, 0x03, 0x0D, 0x1F, 0x04, 0xC9],
        )
        self.assertEqual(plan["encoding"]["encoded_bits"], 39)
        self.assertEqual(plan["encoding"]["encoded_hex"], "eab98fcf10")
        self.assertTrue(plan["encoding"]["roundtrip_exact"])
        self.assertFalse(plan["translation_build_eligible"])
        self.assertFalse(plan["checks"]["rom_read"])
        self.assertFalse(plan["checks"]["rom_written"])

    def test_unapproved_free_text_is_rejected(self) -> None:
        with self.assertRaisesRegex(PatchError, "only the approved"):
            build_test_phrase_plan(self.patch, "다한")


if __name__ == "__main__":
    unittest.main()
