from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import unittest

from tools.sfgfc_huffman import CANDIDATE_END_SYMBOL
from tools.v5_1_first_context_consumer_trace import (
    build_first_context_consumer_trace,
    summarize_consumer_contexts,
    validate_first_context_consumer_trace,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64


class FirstContextConsumerTraceTests(unittest.TestCase):
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
