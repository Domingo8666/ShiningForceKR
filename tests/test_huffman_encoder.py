from __future__ import annotations

import unittest

from tools.patch_io import PatchError
from tools.sfgfc_huffman import (
    CANDIDATE_END_SYMBOL,
    HuffmanNode,
    ParsedTree,
    decode_symbol_count,
    decode_symbol_entries,
    decode_symbols,
    encode_symbol_count,
    encode_symbol_entries,
    encode_symbols,
)


def tree(previous: int, left: int, right: int) -> ParsedTree:
    return ParsedTree(
        previous_symbol=previous,
        pointer=0,
        structure_offset=0,
        structure_bits=3,
        leaf_count=2,
        symbol_offset=0,
        root=HuffmanNode(
            left=HuffmanNode(symbol=left),
            right=HuffmanNode(symbol=right),
        ),
    )


class HuffmanEncoderTests(unittest.TestCase):
    def test_context_sequence_roundtrips_exact_bits(self) -> None:
        end = CANDIDATE_END_SYMBOL
        trees = {
            end: tree(end, 0x10, end),
            0x10: tree(0x10, 0x11, end),
            0x11: tree(0x11, end, 0x10),
        }
        symbols = [0x10, 0x11, end]
        encoded, bits = encode_symbols(trees, symbols)
        self.assertEqual(bits, 3)
        self.assertEqual(encoded, b"\x00")
        decoded, decoded_bits = decode_symbols(
            encoded,
            b"\x01",
            trees,
            0,
            max_symbols=8,
            max_bytes=1,
        )
        self.assertEqual(decoded, symbols)
        self.assertEqual(decoded_bits, bits)

    def test_missing_terminator_is_rejected(self) -> None:
        end = CANDIDATE_END_SYMBOL
        trees = {end: tree(end, 0x10, end)}
        with self.assertRaises(PatchError):
            encode_symbols(trees, [0x10])

    def test_duplicate_leaf_symbol_is_not_encoded_ambiguously(self) -> None:
        end = CANDIDATE_END_SYMBOL
        trees = {end: tree(end, end, end)}
        with self.assertRaises(PatchError):
            encode_symbols(trees, [end])

    def test_consecutive_entries_share_bits_without_byte_padding(self) -> None:
        end = CANDIDATE_END_SYMBOL
        trees = {
            end: tree(end, 0x10, end),
            0x10: tree(0x10, 0x10, end),
        }
        entries = [[0x10, end], [end]]
        encoded, bits = encode_symbol_entries(trees, entries)
        self.assertEqual(bits, 3)
        self.assertEqual(encoded, b"\x60")
        decoded, decoded_bits = decode_symbol_entries(
            encoded,
            b"\x01",
            trees,
            0,
            len(entries),
            max_symbols_per_entry=8,
            max_total_bytes=1,
        )
        self.assertEqual(decoded, entries)
        self.assertEqual(decoded_bits, bits)

    def test_fixed_count_block_keeps_context_across_terminator(self) -> None:
        end = CANDIDATE_END_SYMBOL
        trees = {
            end: tree(end, 0x10, end),
            0x10: tree(0x10, end, 0x11),
        }
        symbols = [0x10, end, 0x10, end]
        encoded, bits = encode_symbol_count(trees, symbols)
        self.assertEqual(bits, 4)
        self.assertEqual(encoded, b"\x00")
        decoded, decoded_bits = decode_symbol_count(
            encoded,
            b"\x01",
            trees,
            0,
            len(symbols),
            max_bytes=1,
        )
        self.assertEqual(decoded, symbols)
        self.assertEqual(decoded_bits, bits)

    def test_fixed_count_limits_fail_closed(self) -> None:
        end = CANDIDATE_END_SYMBOL
        trees = {end: tree(end, end, 0x10)}
        with self.assertRaisesRegex(PatchError, "between 0 and 4096"):
            decode_symbol_count(b"\x00", b"\x01", trees, 0, 4097)
        with self.assertRaisesRegex(PatchError, "exceeds 4096"):
            encode_symbol_count(trees, [end] * 4097)

    def test_consecutive_entry_limits_fail_closed(self) -> None:
        end = CANDIDATE_END_SYMBOL
        trees = {end: tree(end, end, 0x10)}
        with self.assertRaisesRegex(PatchError, "between 0 and 256"):
            decode_symbol_entries(b"\x00", b"\x01", trees, 0, 257)
        with self.assertRaisesRegex(PatchError, "every Huffman group entry"):
            encode_symbol_entries(trees, [[0x10]])


if __name__ == "__main__":
    unittest.main()
