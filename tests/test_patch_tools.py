from __future__ import annotations

import unittest
import zlib
from pathlib import Path

from tools.patch_io import (
    PatchError,
    apply_bps,
    apply_ips,
    extract_bps_target_literals,
    inspect_bps,
    parse_ips,
)
from tools.sfgfc_huffman import (
    BANK_BASE,
    CANDIDATE_END_SYMBOL,
    VECTOR_OFFSET,
    VECTOR_SIZE,
    build_ips_overlay,
    decode_symbols,
    load_trees,
    load_trees_at,
    render_basic,
)
from tools.v5_1_engine import analyze_patch


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

        sparse = extract_bps_target_literals(patch)
        self.assertEqual(sparse.data[3:5], b"XY")
        self.assertEqual(sparse.known, b"\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00")

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
        for previous_symbol in (CANDIDATE_END_SYMBOL, 0x0C):
            at = previous_symbol * 2
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


class KoreanEngineTests(unittest.TestCase):
    def test_v5_1_literal_extension_layout(self) -> None:
        root = Path(__file__).resolve().parents[1]
        patch = (root / "patch" / "Final_Conflict_Japan_to_Korean_v5.1.bps").read_bytes()
        result = analyze_patch(patch)

        self.assertEqual(result["status"], "verified-static")
        self.assertEqual(result["patch"]["extension_known_without_source"], 0xFC000)
        self.assertEqual(result["huffman"]["vector_file_offset"], 0x80100)
        self.assertEqual(result["huffman"]["populated_trees"], 51)
        self.assertEqual(result["huffman"]["empty_trees"], 205)
        self.assertEqual(result["huffman"]["tree_data_start"], 0x80300)
        self.assertEqual(result["huffman"]["tree_data_end_exclusive"], 0x808D3)
        self.assertEqual(result["font_runtime"]["page_map_entries"], 244)
        self.assertEqual(len(result["font_runtime"]["full_0x3000_payload_banks"]), 60)
        self.assertFalse(result["checkpoints"]["translation_build_eligible"])


if __name__ == "__main__":
    unittest.main()
