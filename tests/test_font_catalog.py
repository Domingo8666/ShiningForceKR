from __future__ import annotations

import unittest

from tools.patch_io import PatchError
from tools.v5_1_font_catalog import (
    _parse_bdf_glyphs,
    match_masks,
    tile_ink_mask,
)


class FontCatalogTests(unittest.TestCase):
    def test_bdf_parser_keeps_only_glyphs_that_fit_eight_pixels(self) -> None:
        glyphs = _parse_bdf_glyphs(
            """
STARTCHAR small
ENCODING 33
BBX 1 2 0 0
BITMAP
80
80
ENDCHAR
STARTCHAR empty
ENCODING 32
BBX 0 0 0 0
BITMAP
ENDCHAR
STARTCHAR wide
ENCODING 1000
BBX 9 1 0 0
BITMAP
FF80
ENDCHAR
""".splitlines()
        )
        self.assertEqual(glyphs[33], (0, 0, 0, 0, 0, 0, 0x80, 0x80))
        self.assertEqual(glyphs[32], (0,) * 8)
        self.assertNotIn(1000, glyphs)

    def test_game_gear_tile_planes_collapse_to_ink_mask(self) -> None:
        tile = bytes(
            value
            for row in (
                (0xFF, 0xFF, 0xFF, 0xFF),
                (0xEF, 0xFF, 0xFF, 0xFF),
                *((0xFF, 0xFF, 0xFF, 0xFF),) * 6,
            )
            for value in row
        )
        self.assertEqual(
            tile_ink_mask(tile),
            (0x00, 0x10, 0, 0, 0, 0, 0, 0),
        )

    def test_tile_size_fails_closed(self) -> None:
        with self.assertRaisesRegex(PatchError, "32 bytes"):
            tile_ink_mask(b"\x00")

    def test_exact_and_ambiguous_matches_are_separate(self) -> None:
        masks = [
            (6, 4, (1,) * 8, "a" * 64),
            (6, 5, (2,) * 8, "b" * 64),
            (6, 6, (3,) * 8, "c" * 64),
        ]
        glyphs = {
            0xAC00: (1,) * 8,
            0xAC01: (2,) * 8,
            0xAC02: (2,) * 8,
        }
        entries, summary = match_masks(masks, glyphs)
        self.assertEqual(
            [entry["status"] for entry in entries],
            ["unique", "ambiguous", "unmatched"],
        )
        self.assertEqual(summary["unique_matches"], 1)
        self.assertEqual(summary["ambiguous_matches"], 1)
        self.assertEqual(summary["unmatched_tiles"], 1)
        self.assertEqual(summary["distinct_unique_codepoints"], 1)


if __name__ == "__main__":
    unittest.main()
