from __future__ import annotations

import unittest

from tools.patch_io import PatchError, sha256_bytes
from tools.v5_1_test_patch import (
    plan_in_place_write,
    select_runtime_entry,
)


def confirmed_resolution(target_sha256: str) -> dict[str, object]:
    return {
        "artifact_kind": "sanitized-runtime-consumer-resolution",
        "schema_version": 2,
        "target_sha256": target_sha256,
        "status": "consumer-entry-resolved",
        "hit": {
            "slot": 1,
            "logical_access": 0x4100,
            "physical_table_byte": 0x100,
            "instruction_bank": 0,
            "instruction_pc": 0x1234,
            "pc_after": 0x1235,
            "physical_pc_after": 0x1235,
            "expected_bank": 0,
            "mapped_bank": 0,
        },
        "alignment_resolutions": [
            {
                "format": "bank_addr_le",
                "alignment_file_offset": 0x100,
                "entry_index": 0,
                "entry_byte_index": 0,
                "target_file_offset": 0x8000,
                "bounded_decode": True,
                "symbol_count": 4,
                "roundtrip_exact": True,
                "encoded_bits": 48,
            }
        ],
        "target_read": {
            "slot": 2,
            "logical_access": 0x8000,
            "physical_target_byte": 0x8000,
            "instruction_bank": 0,
            "instruction_pc": 0x2345,
            "pc_after": 0x2346,
            "physical_pc_after": 0x2346,
            "expected_bank": 2,
            "mapped_bank": 2,
        },
        "selected_alignment_format": "bank_addr_le",
        "selected_entry_index": 0,
        "consumer_evidence_confirmed": True,
        "translation_build_eligible": False,
        "next_checkpoint": "identify-intro-line-and-build-test-translation",
    }


def trace_plan(target_sha256: str) -> dict[str, object]:
    return {
        "source_analysis_sha256": target_sha256,
        "selected_alignment_cluster": [
            {
                "file_offset": 0x100,
                "end_exclusive": 0x106,
                "entries": 2,
                "format": "bank_addr_le",
            }
        ],
    }


class TestPatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.baseline = bytearray(b"\xFF" * 0x10000)
        self.baseline[0x100:0x106] = bytes.fromhex(
            "02 00 80 03 00 80"
        )

    def test_runtime_entry_is_rederived_from_the_confirmed_table(self) -> None:
        baseline = bytes(self.baseline)
        digest = sha256_bytes(baseline)
        selected = select_runtime_entry(
            baseline,
            confirmed_resolution(digest),
            trace_plan(digest),
        )
        self.assertEqual(selected["format"], "bank_addr_le")
        self.assertEqual(selected["entry_index"], 0)
        self.assertEqual(selected["target_file_offset"], 0x8000)
        self.assertEqual(selected["pointer_bank"], 2)
        self.assertEqual(selected["pointer_address"], 0x8000)
        self.assertEqual(selected["target_alias_count"], 1)
        self.assertEqual(selected["next_target_file_offset"], 0xC000)

    def test_runtime_selected_fallback_table_is_accepted(self) -> None:
        baseline = bytes(self.baseline)
        digest = sha256_bytes(baseline)
        plan = trace_plan(digest)
        plan["selected_alignment_cluster"] = [
            {
                "file_offset": 0x200,
                "end_exclusive": 0x206,
                "entries": 2,
                "format": "bank_addr_le",
            }
        ]
        plan["ranked_consumer_hypotheses"] = [
            {
                "file_offset": 0x100,
                "end_exclusive": 0x106,
                "entries": 2,
                "format": "bank_addr_le",
            }
        ]
        selected = select_runtime_entry(
            baseline,
            confirmed_resolution(digest),
            plan,
        )
        self.assertEqual(selected["alignment_file_offset"], 0x100)
        self.assertEqual(selected["target_file_offset"], 0x8000)

    def test_shared_target_is_rejected(self) -> None:
        self.baseline[0x103:0x106] = bytes.fromhex("02 00 80")
        baseline = bytes(self.baseline)
        digest = sha256_bytes(baseline)
        with self.assertRaisesRegex(PatchError, "shared or missing"):
            select_runtime_entry(
                baseline,
                confirmed_resolution(digest),
                trace_plan(digest),
            )

    def test_target_identity_mismatch_is_rejected(self) -> None:
        baseline = bytes(self.baseline)
        digest = sha256_bytes(baseline)
        resolution = confirmed_resolution("0" * 64)
        with self.assertRaisesRegex(PatchError, "identity mismatch"):
            select_runtime_entry(
                baseline,
                resolution,
                trace_plan(digest),
            )

    def test_ambiguous_resolution_is_rejected(self) -> None:
        baseline = bytes(self.baseline)
        digest = sha256_bytes(baseline)
        resolution = confirmed_resolution(digest)
        resolution.update(
            {
                "status": "runtime-hit-entry-ambiguous",
                "target_read": None,
                "selected_alignment_format": None,
                "selected_entry_index": None,
                "consumer_evidence_confirmed": False,
                "next_checkpoint": "collect-additional-runtime-read-hits",
            }
        )
        with self.assertRaisesRegex(PatchError, "not confirmed"):
            select_runtime_entry(
                baseline,
                resolution,
                trace_plan(digest),
            )

    def test_in_place_plan_respects_bit_and_neighbor_boundaries(self) -> None:
        baseline = bytes(range(64))
        planned = plan_in_place_write(
            baseline,
            target_offset=16,
            original_bits=48,
            replacement=bytes.fromhex("EA B9 8F CF 10"),
            replacement_bits=39,
            next_target_offset=24,
        )
        self.assertEqual(planned.offset, 16)
        self.assertEqual(planned.end_exclusive, 21)
        self.assertEqual(planned.allowed_end_exclusive, 22)
        self.assertEqual(planned.before, baseline[16:21])

    def test_larger_replacement_or_tight_neighbor_fails_closed(self) -> None:
        baseline = bytes(range(64))
        with self.assertRaisesRegex(PatchError, "bit budget"):
            plan_in_place_write(
                baseline,
                target_offset=16,
                original_bits=38,
                replacement=bytes.fromhex("EA B9 8F CF 10"),
                replacement_bits=39,
                next_target_offset=None,
            )
        with self.assertRaisesRegex(PatchError, "byte boundary"):
            plan_in_place_write(
                baseline,
                target_offset=16,
                original_bits=48,
                replacement=bytes.fromhex("EA B9 8F CF 10"),
                replacement_bits=39,
                next_target_offset=20,
            )


if __name__ == "__main__":
    unittest.main()
