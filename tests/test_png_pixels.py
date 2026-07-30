from __future__ import annotations

import struct
import unittest
import zlib

from tools.patch_io import PatchError
from tools.v5_1_png_pixels import (
    DEFAULT_TEXT_INK_RGBA,
    compare_png_pixels,
    decode_png_rgba,
    find_ink_mask_sequence,
)


def chunk(kind: bytes, data: bytes) -> bytes:
    checksum = zlib.crc32(kind)
    checksum = zlib.crc32(data, checksum) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", checksum)


def rgba_png(width: int, height: int, pixels: bytes) -> bytes:
    if len(pixels) != width * height * 4:
        raise ValueError("pixel payload has the wrong size")
    rows = b"".join(
        b"\x00" + pixels[row * width * 4 : (row + 1) * width * 4]
        for row in range(height)
    )
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(
            b"IHDR",
            struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0),
        )
        + chunk(b"IDAT", zlib.compress(rows))
        + chunk(b"IEND", b"")
    )


class PngPixelTests(unittest.TestCase):
    def test_normalizes_and_compares_visible_rgba_pixels(self) -> None:
        baseline = rgba_png(
            2,
            2,
            bytes(
                (
                    0,
                    0,
                    0,
                    255,
                    255,
                    0,
                    0,
                    255,
                    0,
                    255,
                    0,
                    255,
                    0,
                    0,
                    255,
                    255,
                )
            ),
        )
        changed = bytearray(decode_png_rgba(baseline).rgba)
        changed[12:16] = bytes((255, 255, 255, 255))
        result = compare_png_pixels(baseline, rgba_png(2, 2, bytes(changed)))
        self.assertEqual(result["changed_pixels"], 1)
        self.assertEqual(
            result["difference_bounds"],
            {
                "left": 1,
                "top": 1,
                "right_exclusive": 2,
                "bottom_exclusive": 2,
            },
        )

    def test_identical_pixels_have_no_bounds(self) -> None:
        png = rgba_png(1, 1, bytes((10, 20, 30, 255)))
        result = compare_png_pixels(png, png)
        self.assertEqual(result["changed_pixels"], 0)
        self.assertIsNone(result["difference_bounds"])
        self.assertEqual(
            result["baseline_pixel_sha256"],
            result["test_pixel_sha256"],
        )

    def test_corrupt_chunk_crc_fails_closed(self) -> None:
        png = bytearray(rgba_png(1, 1, bytes((10, 20, 30, 255))))
        png[-1] ^= 1
        with self.assertRaisesRegex(PatchError, "CRC"):
            decode_png_rgba(bytes(png))

    def test_bounded_zero_padding_after_iend_is_ignored(self) -> None:
        png = rgba_png(1, 1, bytes((10, 20, 30, 255)))
        plain = decode_png_rgba(png)
        padded = decode_png_rgba(png + b"\x00\x00")
        self.assertEqual(padded, plain)

    def test_nonzero_or_excessive_trailing_data_fails_closed(self) -> None:
        png = rgba_png(1, 1, bytes((10, 20, 30, 255)))
        for trailing in (b"\x00\x01", b"\x00" * 17):
            with self.subTest(trailing=trailing):
                with self.assertRaisesRegex(PatchError, "trailing data"):
                    decode_png_rgba(png + trailing)

    def test_finds_exact_adjacent_ink_masks(self) -> None:
        masks = (
            (0x00, 0x44, 0xFC, 0x96, 0x64, 0x04, 0x40, 0x7C),
            (0x00, 0xF4, 0x84, 0x84, 0x86, 0x84, 0xF4, 0x04),
        )
        width = 24
        height = 12
        pixels = bytearray(bytes((0, 0, 170, 255)) * width * height)
        left = 3
        top = 2
        for glyph_index, mask in enumerate(masks):
            for row_index, row in enumerate(mask):
                for column in range(8):
                    if not row & (1 << (7 - column)):
                        continue
                    pixel = (
                        (top + row_index) * width
                        + left
                        + glyph_index * 8
                        + column
                    )
                    pixels[pixel * 4 : pixel * 4 + 4] = DEFAULT_TEXT_INK_RGBA
        png = rgba_png(width, height, bytes(pixels))
        self.assertEqual(
            find_ink_mask_sequence(png, masks),
            [(left, top)],
        )

    def test_ink_mask_search_rejects_malformed_masks(self) -> None:
        png = rgba_png(8, 8, bytes((0, 0, 0, 255)) * 64)
        with self.assertRaisesRegex(PatchError, "arguments"):
            find_ink_mask_sequence(png, ((0,),))


if __name__ == "__main__":
    unittest.main()
