from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import unittest

from tools.sfgfc_huffman import CANDIDATE_END_SYMBOL
from tools.v5_1_first_context_consumer_trace import (
    analyze_vector_contexts_from_trace,
    build_first_context_consumer_trace,
    extract_vector_contexts_from_trace,
    summarize_consumer_contexts,
    validate_first_context_consumer_trace,
    vector_context_from_physical,
)
from tools.run_s25u_renderer_probe import HUFFMAN_VECTOR_START  # noqa: E402


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64
TRACE_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "v5_1_first_context_consumer_trace.py"
).read_text(encoding="utf-8")


class FirstContextConsumerTraceTests(unittest.TestCase):
    def test_vector_breakpoints_stay_armed_across_samples(self) -> None:
        capture_source = TRACE_SOURCE.split("def _capture_contexts(", 1)[1]
        capture_source = capture_source.split("def _main()", 1)[0]
        capture_lines = [line.strip() for line in capture_source.splitlines()]
        self.assertEqual(capture_lines.count("arm_vectors()"), 1)
        self.assertEqual(capture_lines.count("disarm_vectors()"), 1)
        self.assertIn("MAX_VECTOR_READ_HITS = 20", TRACE_SOURCE)

    def test_maps_either_vector_byte_to_its_context(self) -> None:
        self.assertEqual(vector_context_from_physical(HUFFMAN_VECTOR_START), 0)
        self.assertEqual(vector_context_from_physical(HUFFMAN_VECTOR_START + 1), 0)
        self.assertEqual(
            vector_context_from_physical(HUFFMAN_VECTOR_START + 0x1FF),
            0xFF,
        )
        self.assertIsNone(
            vector_context_from_physical(HUFFMAN_VECTOR_START + 0x200)
        )

    def test_extracts_vector_contexts_from_continuous_trace(self) -> None:
        lines = [
            "08:5000 A:20 BC:0000 DE:0000 HL:0000 SP:DFF0  32 FF FF",
            "08:5003 A:00 BC:0000 DE:0000 HL:8100 SP:DFF0  7E",
            "08:5004 A:00 BC:0000 DE:0000 HL:8101 SP:DFF0  7E",
            "08:5005 A:00 BC:0000 DE:0000 HL:8102 SP:DFF0  7E",
        ]
        self.assertEqual(
            extract_vector_contexts_from_trace(
                lines,
                initial_slot1_bank=8,
                initial_slot2_bank=6,
                initial_ix=0,
                initial_iy=0,
            ),
            [0, 1],
        )

    def test_tracks_index_register_load_for_vector_read(self) -> None:
        lines = [
            "08:5000 A:20 BC:0000 DE:0000 HL:0000 SP:DFF0  32 FF FF",
            "08:5003 A:00 BC:0000 DE:0000 HL:0000 SP:DFF0  DD 21 00 81",
            "08:5007 A:00 BC:0000 DE:0000 HL:0000 SP:DFF0  DD 7E 00",
        ]
        self.assertEqual(
            extract_vector_contexts_from_trace(
                lines,
                initial_slot1_bank=8,
                initial_slot2_bank=6,
                initial_ix=0xFFFF,
                initial_iy=0xFFFF,
            ),
            [0],
        )

    def test_reports_sanitized_continuous_trace_diagnostics(self) -> None:
        lines = [
            "not an instruction",
            "08:5000 A:20 BC:0000 DE:0000 HL:0000 SP:DFF0  32 FF FF",
            "08:5003 A:00 BC:0000 DE:0000 HL:0000 SP:DFF0  DD 21 00 81",
            "08:5007 A:00 BC:0000 DE:0000 HL:0000 SP:DFF0  DD 7E 00",
        ]
        contexts, diagnostics = analyze_vector_contexts_from_trace(
            lines,
            initial_slot1_bank=8,
            initial_slot2_bank=6,
            initial_ix=0xFFFF,
            initial_iy=0xFFFF,
        )
        self.assertEqual(contexts, [0])
        self.assertEqual(
            diagnostics,
            {
                "trace_line_count": 4,
                "parsed_instruction_count": 3,
                "supported_read_count": 1,
                "indexed_read_instruction_count": 1,
                "index_immediate_load_count": 1,
                "mapper_write_count": 1,
                "logical_vector_window_read_count": 1,
                "mapped_vector_read_count": 1,
            },
        )

    def test_rejects_invalid_trace_mapper_state(self) -> None:
        with self.assertRaisesRegex(ValueError, "mapper bank"):
            extract_vector_contexts_from_trace(
                [],
                initial_slot1_bank=-1,
                initial_slot2_bank=6,
                initial_ix=0,
                initial_iy=0,
            )

    def test_exact_context_sequence_observes_clean_terminator_stop(self) -> None:
        symbols = [0x5F, 0x12, 0x34, CANDIDATE_END_SYMBOL]
        counts, prefix, first_post, direct = summarize_consumer_contexts(
            observed_contexts=[CANDIDATE_END_SYMBOL, 0x5F, 0x12, 0x34],
            initial_context=CANDIDATE_END_SYMBOL,
            expected_symbols=symbols,
        )
        self.assertTrue(prefix)
        self.assertFalse(first_post)
        self.assertFalse(direct)
        self.assertEqual(counts["post_terminator_context_count"], 0)

    def test_terminator_context_after_full_prefix_proves_overread(self) -> None:
        symbols = [0x5F, 0x12, 0x34, CANDIDATE_END_SYMBOL]
        counts, prefix, first_post, direct = summarize_consumer_contexts(
            observed_contexts=[
                CANDIDATE_END_SYMBOL,
                0x5F,
                0x12,
                0x34,
                CANDIDATE_END_SYMBOL,
            ],
            initial_context=CANDIDATE_END_SYMBOL,
            expected_symbols=symbols,
        )
        self.assertTrue(prefix)
        self.assertTrue(first_post)
        self.assertTrue(direct)
        self.assertEqual(counts["post_terminator_context_count"], 1)

    def test_mismatch_is_inconclusive(self) -> None:
        symbols = [0x5F, 0x12, CANDIDATE_END_SYMBOL]
        counts, prefix, first_post, direct = summarize_consumer_contexts(
            observed_contexts=[CANDIDATE_END_SYMBOL, 0x77],
            initial_context=CANDIDATE_END_SYMBOL,
            expected_symbols=symbols,
        )
        self.assertFalse(prefix)
        self.assertFalse(first_post)
        self.assertFalse(direct)
        self.assertEqual(counts["expected_context_prefix_match_count"], 1)

    def _receipt(self) -> dict[str, object]:
        symbols = [0x5F, 0x12, CANDIDATE_END_SYMBOL]
        counts, prefix, first_post, direct = summarize_consumer_contexts(
            observed_contexts=[
                CANDIDATE_END_SYMBOL,
                0x5F,
                0x12,
                CANDIDATE_END_SYMBOL,
            ],
            initial_context=CANDIDATE_END_SYMBOL,
            expected_symbols=symbols,
        )
        return build_first_context_consumer_trace(
            baseline_target_sha256=SHA_A,
            test_target_sha256=SHA_B,
            first_context_translation_test_build_sha256=SHA_C,
            first_context_translation_runtime_capture_sha256=SHA_D,
            first_context_translation_visual_review_sha256=SHA_E,
            local_trace_sha256=SHA_F,
            captured_utc=datetime.now(timezone.utc).isoformat().replace(
                "+00:00", "Z"
            ),
            trace=counts,
            expected_context_prefix_complete=prefix,
            first_post_terminator_context_is_terminator=first_post,
            direct_terminator_overread_confirmed=direct,
        )

    def test_safe_receipt_records_direct_overread(self) -> None:
        receipt = self._receipt()
        self.assertEqual(
            receipt["status"], "consumer-terminator-overread-confirmed"
        )
        self.assertEqual(
            receipt["next_checkpoint"], "resolve-record-consumer-boundary"
        )
        validate_first_context_consumer_trace(receipt)

    def test_safe_receipt_rejects_context_value_leak(self) -> None:
        receipt = deepcopy(self._receipt())
        receipt["observed_contexts"] = [CANDIDATE_END_SYMBOL]
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_first_context_consumer_trace(receipt)

    def test_safe_receipt_rejects_inconsistent_overread(self) -> None:
        receipt = deepcopy(self._receipt())
        receipt["trace"]["post_terminator_context_count"] = 0
        with self.assertRaisesRegex(ValueError, "counts do not match"):
            validate_first_context_consumer_trace(receipt)


if __name__ == "__main__":
    unittest.main()
