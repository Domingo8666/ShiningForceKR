from __future__ import annotations

import unittest

from tools.patch_io import PatchError
from tools.v5_1_consumer import (
    find_literal_references,
    find_pair_tables,
    find_triplet_tables,
    mapper_file_offset,
    verify_target_identity,
)


class ConsumerCandidateTests(unittest.TestCase):
    def test_mapper_candidate_coordinates(self) -> None:
        self.assertEqual(mapper_file_offset(2, 0x4000, 0x14000), 0x8000)
        self.assertEqual(mapper_file_offset(2, 0x8008, 0x14000), 0x8008)
        self.assertIsNone(mapper_file_offset(9, 0x4000, 0x14000))
        self.assertIsNone(mapper_file_offset(2, 0x2000, 0x14000))

    def test_exact_literal_shapes_are_candidate_only(self) -> None:
        rom = bytearray(b"\xFF" * 0x200)
        rom[0x20:0x25] = bytes.fromhex("3e20210041")
        rom[0x40:0x45] = bytes.fromhex("3e21cd0070")
        refs = find_literal_references(bytes(rom))
        self.assertEqual(refs["korean_tree_vector"]["candidate_count"], 1)
        self.assertTrue(
            refs["korean_tree_vector"]["examples"][0]["nearby_ld_a_bank_literal"]
        )
        self.assertEqual(refs["korean_runtime_primary"]["candidate_count"], 1)

    def test_bank_address_triplet_run_is_ranked(self) -> None:
        rom = bytearray(b"\xFF" * 0x14000)
        start = 0x101
        for index in range(12):
            at = start + index * 3
            address = 0x4000 + index * 4
            rom[at:at + 3] = bytes((2, address & 0xFF, address >> 8))
        ranked, found = find_triplet_tables(bytes(rom))
        self.assertGreaterEqual(found, 1)
        match = next(item for item in ranked if item["file_offset"] == start)
        self.assertEqual(match["format"], "bank_addr_le")
        self.assertEqual(match["entries"], 12)
        self.assertFalse(match["decode_probe"]["bounded_terminations"])

    def test_conservative_pair_run_keeps_slot_boundary(self) -> None:
        rom = bytearray(b"\xFF" * 0x400)
        start = 0x80
        for index in range(12):
            address = 0x4000 + index * 0x10
            at = start + index * 2
            rom[at:at + 2] = address.to_bytes(2, "little")
        ranked, found = find_pair_tables(bytes(rom))
        self.assertGreaterEqual(found, 1)
        self.assertEqual(ranked[0]["file_offset"], start)
        self.assertEqual(ranked[0]["logical_slot"], 1)

    def test_identity_guard_rejects_unrelated_data(self) -> None:
        with self.assertRaises(PatchError):
            verify_target_identity(b"not a v5.1 ROM")


if __name__ == "__main__":
    unittest.main()
