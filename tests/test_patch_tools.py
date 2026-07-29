from __future__ import annotations

import unittest
import zlib

from tools.patch_io import PatchError, apply_bps, apply_ips, inspect_bps, parse_ips
from tools.sfgfc_huffman import (
    BANK_BASE,
    CANDIDATE_END_SYMBOL,
    VECTOR_OFFSET,
    VECTOR_SIZE,
    build_ips_overlay,
    decode_symbols,
    load_trees,
    render_basic,
)


def bps_varint(value: int) -> bytes:
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value == 0:
            output.append(byte | 0x80)
            return bytes(output)
        output.append(byte)
        value -= 1


def bps_signed(value: int) -> int:
    return (abs(value) << 1) | (1 if value < 0 else 0)


def make_bps(source: bytes, target: bytes, actions: bytes) -> bytes:
    body = b"BPS1" + bps_varint(len(source)) + bps_varint(len(target)) + bps_varint(0) + actions
    body += (zlib.crc32(source) & 0xFFFFFFFF).to_bytes(4, "little")
    body += (zlib.crc32(target) & 0xFFFFFFFF).to_bytes(4, "little")
    return body + (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")


def ips_record(offset: int, payload: bytes) -> bytes:
    return offset.to_bytes(3, "big") + len(payload).to_bytes(2, "big") + payload


class PatchIOTests(unittest.TestCase):
    def test_bps_all_four_action_types(self) -> None:
        source = b"abcdef"
        target = b"abcXYefabc"
        actions = b"".join(
            [
                bps_varint(((3 - 1) << 2) | 0),
                bps_varint(((2 - 1) << 2) | 1),
                b"XY",
                bps_varint(((2 - 1) << 2) | 2),
                bps_varint(bps_signed(4)),
                bps_varint(((3 - 1) << 2) | 3),
                bps_varint(bps_signed(0)),
            ]
        )
        patch = make_bps(source, target, actions)
        report = inspect_bps(patch)
        self.assertEqual(report.action_counts, (1, 1, 1, 1))
        self.assertEqual(apply_bps(source, patch), target)

    def test_bps_rejects_wrong_source(self) -> None:
        source = b"abc"
        target = b"abc"
        patch = make_bps(source, target, bps_varint(((3 - 1) << 2) | 0))
        with self.assertRaises(PatchError):
            apply_bps(b"abd", patch)

    def test_ips_literal_rle_and_truncate(self) -> None:
        patch = (
            b"PATCH"
            + ips_record(1, b"XY")
            + (4).to_bytes(3, "big")
            + b"\x00\x00\x00\x03Z"
            + b"EOF"
            + (6).to_bytes(3, "big")
        )
        parsed = parse_ips(patch)
        self.assertEqual(len(parsed.records), 2)
        self.assertTrue(parsed.records[1].is_rle)
        self.assertEqual(apply_ips(b"abcdef", patch), b"aXYdZZ")


class HuffmanTests(unittest.TestCase):
    def test_sparse_ips_tree_and_candidate_decode(self) -> None:
        vector = bytearray(b"\xFF" * VECTOR_SIZE)
        structure_offset = 0x29E80
        pointer = 0x4000 | (structure_offset - BANK_BASE)
        at = CANDIDATE_END_SYMBOL * 2
        vector[at : at + 2] = pointer.to_bytes(2, "little")

        patch = b"PATCH"
        patch += ips_record(VECTOR_OFFSET, bytes(vector))
        patch += ips_record(structure_offset - 2, bytes([CANDIDATE_END_SYMBOL, 0x0C, 0x60]))
        patch += ips_record(0x30000, b"\x40")
        patch += b"EOF"

        data, known = build_ips_overlay(patch)
        trees = load_trees(data, known)
        symbols, bits = decode_symbols(data, known, trees, 0x30000)
        self.assertEqual(symbols, [0x0C, CANDIDATE_END_SYMBOL])
        self.assertEqual(bits, 2)
        self.assertEqual(render_basic(symbols), "A<END>")


if __name__ == "__main__":
    unittest.main()
