from __future__ import annotations

import struct
import unittest
import zlib

from tools.patch_io import PatchError
from tools.v5_1_png_pixels import compare_png_pixels, decode_png_rgba


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


if __name__ == "__main__":
    unittest.main()
