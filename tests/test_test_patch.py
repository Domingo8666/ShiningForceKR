from __future__ import annotations

import unittest

from tools.patch_io import PatchError, sha256_bytes
from tools.v5_1_test_patch import (
    classify_test_patch_failure,
    mark_all_count_preserving_entries,
    plan_in_place_write,
    plan_unpadded_entry_prefix_write,
    select_runtime_decode_block,
    select_runtime_entry,
    select_runtime_group_entry,
    select_runtime_length_prefixed_entry,
    select_runtime_stream,
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


def confirmed_stream_resolution(target_sha256: str) -> dict[str, object]:
    return {
        "artifact_kind": "sanitized-runtime-decoder-stream-resolution",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "status": "decoder-stream-resolved",
        "streams": [
            {
                "physical_start": 0x8000,
                "logical_start": 0x4000,
                "mapped_bank": 2,
                "instruction_bank": 0,
                "instruction_pc": 0x3406,
                "operand_kind": "hl-indirect",
                "decoded_end_exclusive": 0x8006,
                "next_stream_start": 0x8010,
                "symbol_count": 12,
                "encoded_bits": 48,
                "roundtrip_exact": True,
            },
            {
                "physical_start": 0x8010,
                "logical_start": 0x4010,
                "mapped_bank": 2,
                "instruction_bank": 0,
                "instruction_pc": 0x3406,
                "operand_kind": "hl-indirect",
                "decoded_end_exclusive": 0x8016,
                "next_stream_start": None,
                "symbol_count": 12,
                "encoded_bits": 48,
                "roundtrip_exact": True,
            },
        ],
        "selected_stream_index": 0,
        "huffman_vector_read_count": 2,
        "huffman_tree_read_count": 8,
        "consumer_evidence_confirmed": True,
        "translation_build_eligible": False,
        "next_checkpoint": "build-runtime-selected-test-phrase",
    }


def confirmed_group_capture(target_sha256: str) -> dict[str, object]:
    return {
        "artifact_kind": "sanitized-s25u-test-display-capture",
        "schema_version": 4,
        "baseline_target_sha256": target_sha256,
        "target_read": {
            "expected_bank": 2,
        },
        "entry_selector": {
            "status": "resolved",
            "baseline_entry_ordinal": 0,
            "pointer_address": 0x4000,
        },
        "group_entry": {
            "status": "resolved",
            "entry_ordinal": 0,
            "group_pointer_address": 0x4000,
            "entry_start_bit": 2,
            "entry_end_bit_exclusive": 3,
            "entry_encoded_bits": 1,
            "entry_symbol_count": 1,
            "entry_start_logical_byte": 0x4000,
            "entry_end_logical_byte_inclusive": 0x4000,
            "target_logical_byte": 0x4000,
            "prefix_roundtrip_exact": True,
        },
    }


def confirmed_selected_group_capture(target_sha256: str) -> dict[str, object]:
    capture = confirmed_group_capture(target_sha256)
    capture["schema_version"] = 5
    capture["target_read"]["logical_access"] = 0x4000
    capture["entry_selector"]["baseline_entry_ordinal"] = 1
    capture["group_entry"].update(
        {
            "status": "target-outside-selected-entry",
            "entry_ordinal": 1,
            "entry_start_bit": 10,
            "entry_end_bit_exclusive": 18,
            "entry_encoded_bits": 8,
            "entry_start_logical_byte": 0x4001,
            "entry_end_logical_byte_inclusive": 0x4002,
            "target_logical_byte": 0x4000,
            "observed_b_matches_target_candidates": False,
            "target_byte_candidates": [
                {
                    "entry_ordinal": 0,
                    "entry_start_bit": 2,
                    "entry_end_bit_exclusive": 10,
                    "entry_encoded_bits": 8,
                    "entry_symbol_count": 2,
                    "entry_start_logical_byte": 0x4000,
                    "entry_end_logical_byte_inclusive": 0x4001,
                }
            ],
        }
    )
    return capture


def confirmed_decode_block_capture(target_sha256: str) -> dict[str, object]:
    return {
        "artifact_kind": "sanitized-s25u-test-display-capture",
        "schema_version": 5,
        "baseline_target_sha256": target_sha256,
        "target_read": {
            "logical_access": 0x4000,
            "expected_bank": 2,
            "confirmed": True,
        },
        "entry_selector": {
            "status": "resolved",
            "baseline_selector_offset": 2,
            "test_selector_offset": 2,
            "selectors_match": True,
            "baseline_entry_ordinal": 3,
            "test_entry_ordinal": 3,
            "ordinals_match": True,
            "pointer_address": 0x4000,
            "next_pointer_address": 0x4020,
        },
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

    def test_runtime_decoder_stream_is_selected_without_a_guessed_table(
        self,
    ) -> None:
        baseline = bytes(self.baseline)
        selected = select_runtime_stream(
            baseline,
            confirmed_stream_resolution(sha256_bytes(baseline)),
        )
        self.assertEqual(selected["kind"], "runtime-decoder-stream")
        self.assertEqual(selected["target_file_offset"], 0x8000)
        self.assertEqual(selected["next_target_file_offset"], 0x8010)
        self.assertEqual(selected["runtime_instruction_pc"], 0x3406)

    def test_runtime_group_entry_replaces_intermediate_read_candidate(self) -> None:
        baseline = bytes(self.baseline)
        digest = sha256_bytes(baseline)
        selected = select_runtime_group_entry(
            baseline,
            confirmed_group_capture(digest),
            confirmed_stream_resolution(digest),
        )
        self.assertEqual(selected["kind"], "runtime-group-entry")
        self.assertEqual(selected["target_file_offset"], 0x8000)
        self.assertEqual(selected["pointer_address"], 0x4000)
        self.assertEqual(selected["group_entry_start_bit"], 2)
        self.assertEqual(selected["runtime_encoded_bits"], 1)

    def test_runtime_group_entry_uses_unique_read_containing_entry(self) -> None:
        baseline = bytes(self.baseline)
        digest = sha256_bytes(baseline)
        selected = select_runtime_group_entry(
            baseline,
            confirmed_selected_group_capture(digest),
            confirmed_stream_resolution(digest),
        )
        self.assertEqual(
            selected["kind"],
            "runtime-group-observed-entry",
        )
        self.assertEqual(
            selected["selection_basis"],
            "unique-runtime-read-containing-entry",
        )
        self.assertEqual(selected["target_file_offset"], 0x8000)
        self.assertEqual(selected["pointer_address"], 0x4000)
        self.assertEqual(selected["group_entry_ordinal"], 0)
        self.assertEqual(selected["decoder_entry_b_ordinal"], 1)
        self.assertEqual(
            selected["intermediate_observed_target_file_offset"],
            0x8000,
        )

    def test_runtime_decode_block_uses_pointer_and_incremented_b_count(
        self,
    ) -> None:
        baseline = bytes(self.baseline)
        digest = sha256_bytes(baseline)
        selected = select_runtime_decode_block(
            baseline,
            confirmed_decode_block_capture(digest),
            confirmed_stream_resolution(digest),
        )
        self.assertEqual(selected["kind"], "runtime-decoder-block")
        self.assertEqual(selected["target_file_offset"], 0x8000)
        self.assertEqual(selected["next_target_file_offset"], 0x8020)
        self.assertEqual(selected["decoder_entry_b_before_increment"], 3)
        self.assertEqual(selected["runtime_symbol_count"], 4)

    def test_register_trace_selects_length_prefixed_payload(self) -> None:
        baseline = bytearray(0x24000)
        pointer = 0x43DE
        physical = 8 * 0x4000 + (pointer - 0x4000)
        cursor = physical
        for _ in range(147):
            baseline[cursor] = 1
            baseline[cursor + 1] = 0xAA
            cursor += 2
        baseline[cursor] = 5
        digest = sha256_bytes(bytes(baseline))
        pcs = (
            0x33FA,
            0x33FD,
            0x33FE,
            0x33FF,
            0x3400,
            0x3401,
            0x3402,
            0x3403,
            0x3409,
            0x3406,
            0x3407,
            0x3408,
            0x3409,
            0x3406,
        )
        states = [
            {
                "pc": pc,
                "af": 0,
                "bc": 0x9302,
                "de": 2,
                "hl": pointer,
                "sp": 0xDFF0,
                "slot0_bank": 0,
                "slot1_bank": 8,
                "slot2_bank": 6,
            }
            for pc in pcs
        ]
        states[1]["hl"] = 0x3FE8
        states[2]["hl"] = 0x3FEA
        states[4]["hl"] = 0x3FEB
        states[5]["hl"] = 0x43EB
        states[7]["bc"] = 0x9402
        states[8]["bc"] = 0x9402
        states[10]["de"] = 1
        states[11]["de"] = 1
        states[11]["hl"] = pointer + 1
        states[12]["de"] = 1
        states[12]["hl"] = pointer + 2
        states[13]["de"] = 1
        states[13]["hl"] = pointer + 2
        states[13]["bc"] = 0x9202
        trace = {
            "artifact_kind": "sanitized-decoder-register-trace",
            "schema_version": 2,
            "target_sha256": digest,
            "status": "decoder-register-trace-captured",
            "captured_utc": "2026-07-30T05:10:25Z",
            "decoder_entry": 0x33FA,
            "selector_de": 2,
            "step_count": len(states) - 1,
            "states": states,
            "post_skip_state": {
                **states[-1],
                "pc": 0x340B,
                "bc": 2,
                "hl": pointer + (cursor - physical),
            },
            "post_skip_step_count": 0,
            "post_skip_states": [
                {
                    **states[-1],
                    "pc": 0x340B,
                    "bc": 2,
                    "hl": pointer + (cursor - physical),
                }
            ],
            "translation_build_eligible": False,
            "next_checkpoint": "resolve-decoder-bc-register-role",
        }
        capture = {
            "baseline_target_sha256": digest,
            "entry_selector": {
                "status": "resolved",
                "selectors_match": True,
                "ordinals_match": True,
                "baseline_selector_offset": 2,
                "pointer_address": pointer,
            },
            "target_read": {
                "confirmed": True,
                "expected_bank": 8,
            },
        }
        selected = select_runtime_length_prefixed_entry(
            bytes(baseline),
            capture,
            trace,
        )
        self.assertEqual(selected["skipped_record_count"], 147)
        self.assertEqual(selected["length_prefix_file_offset"], cursor)
        self.assertEqual(selected["target_file_offset"], cursor + 1)
        self.assertEqual(selected["record_length_bytes"], 5)

    def test_all_compatible_entries_receive_count_preserving_marker(
        self,
    ) -> None:
        end = 0xC9
        marker = [0x5F, 0x02, 0x08, 0x11, 0x04, end]
        symbols = [
            1,
            2,
            3,
            4,
            5,
            end,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            end,
        ]
        replaced, indexes = mark_all_count_preserving_entries(
            symbols,
            marker,
        )
        self.assertEqual(indexes, [0, 1])
        self.assertEqual(replaced[:6], marker)
        self.assertEqual(replaced[6:15], marker[:3] + marker)
        self.assertEqual(len(replaced), len(symbols))
        self.assertEqual(
            [index for index, value in enumerate(replaced) if value == end],
            [5, 14],
        )

    def test_marker_rejects_a_block_without_compatible_entry(self) -> None:
        marker = [0x5F, 0x02, 0x08, 0x11, 0x04, 0xC9]
        with self.assertRaisesRegex(PatchError, "no marker-compatible"):
            mark_all_count_preserving_entries(
                [1, 2, 3, 4, 5, 6, 0xC9],
                marker,
            )

    def test_fixed_block_failures_publish_only_safe_tokens(self) -> None:
        cases = {
            "fixed-output decoder block decode failed": (
                "test-patch-fixed-count-roundtrip"
            ),
            "fixed-output decoder block no-change roundtrip is not exact": (
                "test-patch-fixed-count-roundtrip"
            ),
            "observed decoder read is outside the fixed-output block": (
                "test-patch-fixed-count-read-range"
            ),
            "fixed-output block has no marker-compatible entry": (
                "test-patch-no-marker-candidate"
            ),
            "fixed-output marker block encoding failed": (
                "test-patch-marker-encoding"
            ),
            "fixed-output marker block roundtrip mismatch": (
                "test-patch-marker-roundtrip"
            ),
        }
        for message, token in cases.items():
            with self.subTest(message=message):
                self.assertEqual(
                    classify_test_patch_failure(PatchError(message)),
                    token,
                )
        self.assertEqual(
            classify_test_patch_failure(PatchError("private local detail")),
            "test-patch",
        )

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

    def test_unpadded_entry_prefix_write_preserves_boundary_bits(self) -> None:
        baseline = bytes([0xAA, 0x55])
        planned = plan_unpadded_entry_prefix_write(
            baseline,
            group_physical_start=0,
            entry_start_bit=2,
            original_bits=10,
            replacement=b"\xF0",
            replacement_bits=4,
        )
        self.assertEqual(planned.offset, 0)
        self.assertEqual(planned.before, b"\xAA")
        self.assertEqual(planned.after, b"\xBE")
        self.assertEqual(planned.allowed_end_exclusive, 1)

    def test_unpadded_entry_prefix_write_fails_closed(self) -> None:
        with self.assertRaisesRegex(PatchError, "group entry budget"):
            plan_unpadded_entry_prefix_write(
                b"\x00\x00",
                group_physical_start=0,
                entry_start_bit=0,
                original_bits=3,
                replacement=b"\xF0",
                replacement_bits=4,
            )
        with self.assertRaisesRegex(PatchError, "outside the ROM"):
            plan_unpadded_entry_prefix_write(
                b"\x00",
                group_physical_start=1,
                entry_start_bit=0,
                original_bits=1,
                replacement=b"\x00",
                replacement_bits=1,
            )


if __name__ == "__main__":
    unittest.main()
