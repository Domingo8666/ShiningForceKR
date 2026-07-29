from __future__ import annotations

import unittest

from tools.patch_io import PatchError
from tools.sfgfc_huffman import (
    CANDIDATE_END_SYMBOL,
    HuffmanNode,
    ParsedTree,
    decode_symbols,
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


if __name__ == "__main__":
    unittest.main()
