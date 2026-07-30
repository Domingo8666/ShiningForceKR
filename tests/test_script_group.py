from __future__ import annotations

import unittest

from tools.patch_io import PatchError
from tools.sfgfc_huffman import (
    CANDIDATE_END_SYMBOL,
    HuffmanNode,
    ParsedTree,
)
from tools.v5_1_script_group import resolve_group_entry_with_trees


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


class ScriptGroupTests(unittest.TestCase):
    def test_b_ordinal_selects_an_unpadded_entry(self) -> None:
        end = CANDIDATE_END_SYMBOL
        trees = {
            end: tree(end, 0x10, end),
            0x10: tree(0x10, 0x10, end),
        }
        resolution = resolve_group_entry_with_trees(
            b"\x60",
            b"\x01",
            trees,
            group_physical_start=0,
            group_pointer_address=0x4000,
            entry_ordinal=1,
            target_logical_byte=0x4000,
        )
        self.assertEqual(resolution["status"], "resolved")
        self.assertEqual(resolution["decoded_prefix_entry_count"], 2)
        self.assertEqual(resolution["entry_start_bit"], 2)
        self.assertEqual(resolution["entry_end_bit_exclusive"], 3)
        self.assertEqual(resolution["entry_encoded_bits"], 1)
        self.assertTrue(resolution["prefix_roundtrip_exact"])

    def test_target_outside_selected_entry_is_not_resolved(self) -> None:
        end = CANDIDATE_END_SYMBOL
        trees = {
            end: tree(end, 0x10, end),
            0x10: tree(0x10, 0x10, end),
        }
        resolution = resolve_group_entry_with_trees(
            b"\x00\x60",
            b"\x01\x01",
            trees,
            group_physical_start=1,
            group_pointer_address=0x4100,
            entry_ordinal=0,
            target_logical_byte=0x4000,
        )
        self.assertEqual(
            resolution["status"],
            "target-outside-selected-entry",
        )
        self.assertFalse(resolution["target_within_entry_bytes"])

    def test_out_of_range_ordinal_fails_closed(self) -> None:
        with self.assertRaisesRegex(PatchError, "ordinal"):
            resolve_group_entry_with_trees(
                b"\x00",
                b"\x01",
                {},
                group_physical_start=0,
                group_pointer_address=0x4000,
                entry_ordinal=256,
                target_logical_byte=0x4000,
            )


if __name__ == "__main__":
    unittest.main()
