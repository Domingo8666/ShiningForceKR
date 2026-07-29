#!/usr/bin/env python3
"""Decode small non-interlaced PNG screenshots and compare visible pixels.

The S25U runtime tools intentionally avoid optional image libraries.  This
module supports the 8-bit PNG color types emitted by emulator screenshots and
returns normalized RGBA pixels so PNG metadata or compression differences do
not affect the comparison.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
import zlib

try:
    from .patch_io import PatchError
except ImportError:  # direct script execution
    from patch_io import PatchError


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
CHANNELS_BY_COLOR_TYPE = {
    0: 1,  # grayscale
    2: 3,  # RGB
    3: 1,  # indexed
    4: 2,  # grayscale + alpha
    6: 4,  # RGBA
}


@dataclass(frozen=True)
class PixelImage:
    width: int
    height: int
    rgba: bytes

    @property
    def pixel_sha256(self) -> str:
        return hashlib.sha256(self.rgba).hexdigest()


def _paeth(left: int, above: int, upper_left: int) -> int:
    estimate = left + above - upper_left
    left_distance = abs(estimate - left)
    above_distance = abs(estimate - above)
    upper_left_distance = abs(estimate - upper_left)
    if left_distance <= above_distance and left_distance <= upper_left_distance:
        return left
    if above_distance <= upper_left_distance:
        return above
    return upper_left


def _unfilter_scanlines(
    payload: bytes,
    *,
    width: int,
    height: int,
    bytes_per_pixel: int,
) -> bytes:
    stride = width * bytes_per_pixel
    expected = height * (stride + 1)
    if len(payload) != expected:
        raise PatchError("PNG decompressed size does not match its dimensions")
    output = bytearray(height * stride)
    source_offset = 0
    for row in range(height):
        filter_type = payload[source_offset]
        source_offset += 1
        if filter_type not in {0, 1, 2, 3, 4}:
            raise PatchError("PNG uses an unsupported scanline filter")
        row_offset = row * stride
        previous_offset = row_offset - stride
        for column in range(stride):
            raw = payload[source_offset + column]
            left = (
                output[row_offset + column - bytes_per_pixel]
                if column >= bytes_per_pixel
                else 0
            )
            above = output[previous_offset + column] if row else 0
            upper_left = (
                output[previous_offset + column - bytes_per_pixel]
                if row and column >= bytes_per_pixel
                else 0
            )
            if filter_type == 0:
                value = raw
            elif filter_type == 1:
                value = raw + left
            elif filter_type == 2:
                value = raw + above
            elif filter_type == 3:
                value = raw + ((left + above) // 2)
            else:
                value = raw + _paeth(left, above, upper_left)
            output[row_offset + column] = value & 0xFF
        source_offset += stride
    return bytes(output)


def decode_png_rgba(png: bytes) -> PixelImage:
    if not isinstance(png, bytes) or not png.startswith(PNG_SIGNATURE):
        raise PatchError("PNG signature is invalid")
    offset = len(PNG_SIGNATURE)
    width = height = bit_depth = color_type = None
    palette: bytes | None = None
    transparency: bytes | None = None
    compressed = bytearray()
    saw_end = False
    while offset < len(png):
        if offset + 12 > len(png):
            raise PatchError("PNG chunk header is truncated")
        length = struct.unpack(">I", png[offset : offset + 4])[0]
        chunk_type = png[offset + 4 : offset + 8]
        data_start = offset + 8
        data_end = data_start + length
        crc_end = data_end + 4
        if crc_end > len(png):
            raise PatchError("PNG chunk data is truncated")
        chunk_data = png[data_start:data_end]
        expected_crc = struct.unpack(">I", png[data_end:crc_end])[0]
        actual_crc = zlib.crc32(chunk_type)
        actual_crc = zlib.crc32(chunk_data, actual_crc) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise PatchError("PNG chunk CRC mismatch")
        if chunk_type == b"IHDR":
            if width is not None or length != 13:
                raise PatchError("PNG IHDR is invalid")
            (
                width,
                height,
                bit_depth,
                color_type,
                compression,
                filter_method,
                interlace,
            ) = struct.unpack(">IIBBBBB", chunk_data)
            if (
                not 1 <= width <= 1024
                or not 1 <= height <= 1024
                or bit_depth != 8
                or color_type not in CHANNELS_BY_COLOR_TYPE
                or compression != 0
                or filter_method != 0
                or interlace != 0
            ):
                raise PatchError("PNG format is outside the supported screenshot profile")
        elif chunk_type == b"PLTE":
            palette = bytes(chunk_data)
        elif chunk_type == b"tRNS":
            transparency = bytes(chunk_data)
        elif chunk_type == b"IDAT":
            compressed.extend(chunk_data)
        elif chunk_type == b"IEND":
            if length != 0:
                raise PatchError("PNG IEND is invalid")
            saw_end = True
            offset = crc_end
            break
        offset = crc_end
    if (
        not saw_end
        or offset != len(png)
        or width is None
        or height is None
        or bit_depth is None
        or color_type is None
        or not compressed
    ):
        raise PatchError("PNG structure is incomplete")
    try:
        filtered = zlib.decompress(bytes(compressed))
    except zlib.error as error:
        raise PatchError("PNG image data cannot be decompressed") from error
    channels = CHANNELS_BY_COLOR_TYPE[color_type]
    raw = _unfilter_scanlines(
        filtered,
        width=width,
        height=height,
        bytes_per_pixel=channels,
    )
    rgba = bytearray(width * height * 4)
    if color_type == 3:
        if palette is None or len(palette) == 0 or len(palette) % 3:
            raise PatchError("indexed PNG palette is invalid")
        palette_entries = len(palette) // 3
        for index, palette_index in enumerate(raw):
            if palette_index >= palette_entries:
                raise PatchError("indexed PNG pixel exceeds its palette")
            source = palette_index * 3
            destination = index * 4
            rgba[destination : destination + 3] = palette[source : source + 3]
            rgba[destination + 3] = (
                transparency[palette_index]
                if transparency is not None
                and palette_index < len(transparency)
                else 0xFF
            )
    else:
        for index in range(width * height):
            source = index * channels
            destination = index * 4
            if color_type == 0:
                gray = raw[source]
                rgba[destination : destination + 4] = bytes(
                    (gray, gray, gray, 0xFF)
                )
            elif color_type == 2:
                rgba[destination : destination + 3] = raw[source : source + 3]
                rgba[destination + 3] = 0xFF
            elif color_type == 4:
                gray, alpha = raw[source : source + 2]
                rgba[destination : destination + 4] = bytes(
                    (gray, gray, gray, alpha)
                )
            else:
                rgba[destination : destination + 4] = raw[source : source + 4]
    return PixelImage(width=width, height=height, rgba=bytes(rgba))


def compare_png_pixels(baseline_png: bytes, test_png: bytes) -> dict[str, object]:
    baseline = decode_png_rgba(baseline_png)
    test = decode_png_rgba(test_png)
    if (baseline.width, baseline.height) != (test.width, test.height):
        raise PatchError("baseline and test screenshot dimensions differ")
    changed_pixels = 0
    minimum_x = baseline.width
    minimum_y = baseline.height
    maximum_x = maximum_y = -1
    for pixel in range(baseline.width * baseline.height):
        offset = pixel * 4
        if baseline.rgba[offset : offset + 4] == test.rgba[offset : offset + 4]:
            continue
        changed_pixels += 1
        x = pixel % baseline.width
        y = pixel // baseline.width
        minimum_x = min(minimum_x, x)
        minimum_y = min(minimum_y, y)
        maximum_x = max(maximum_x, x)
        maximum_y = max(maximum_y, y)
    bounds = (
        None
        if changed_pixels == 0
        else {
            "left": minimum_x,
            "top": minimum_y,
            "right_exclusive": maximum_x + 1,
            "bottom_exclusive": maximum_y + 1,
        }
    )
    return {
        "width": baseline.width,
        "height": baseline.height,
        "total_pixels": baseline.width * baseline.height,
        "changed_pixels": changed_pixels,
        "difference_bounds": bounds,
        "baseline_pixel_sha256": baseline.pixel_sha256,
        "test_pixel_sha256": test.pixel_sha256,
    }
