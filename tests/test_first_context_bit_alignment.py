from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import unittest

from tools.sfgfc_huffman import HuffmanNode, ParsedTree
from tools.v5_1_first_context_bit_alignment import (
    build_first_context_bit_alignment,
    summarize_expected_bit_alignment,
    validate_first_context_bit_alignment,
)


def _tree(previous: int, symbol: int, code_length: int) -> ParsedTree:
    if code_length <= 0:
        raise ValueError("positive code length required")
    target = HuffmanNode(symbol=symbol)
    node = target
    for depth in range(code_length):
        node = HuffmanNode(
            left=node,
            right=HuffmanNode(symbol=(symbol + depth + 1) & 0xFF),
        )
    return ParsedTree(
        previous_symbol=previous,
        pointer=0,
        structure_offset=0,
        structure_bits=0,
        leaf_count=code_length + 1,
        symbol_offset=0,
        root=node,
    )


class FirstContextBitAlignmentTests(unittest.TestCase):
    def test_classifies_first_mismatch_at_byte_crossing(self) -> None:
        initial = 0xC9
        symbols = [0x5F, 0x12, 0x34, 0xC9]
        trees = {
            initial: _tree(initial, symbols[0], 4),
            symbols[0]: _tree(symbols[0], symbols[1], 3),
            symbols[1]: _tree(symbols[1], symbols[2], 2),
            symbols[2]: _tree(symbols[2], symbols[3], 1),
        }
        analysis, mismatch, crosses, ends = summarize_expected_bit_alignment(
            trees=trees,
            expected_symbols=symbols,
            initial_context=initial,
            observed_contexts=[initial, symbols[0], symbols[1], 0x77],
        )
        self.assertTrue(mismatch)
        self.assertTrue(crosses)
        self.assertFalse(ends)
        self.assertEqual(analysis["context_prefix_match_count"], 3)
        self.assertEqual(analysis["confirmed_symbol_count"], 2)
        self.assertEqual(analysis["confirmed_prefix_bit_count"], 7)
        self.assertEqual(analysis["confirmed_prefix_bit_modulo_8"], 7)
        self.assertEqual(analysis["next_expected_code_bit_count"], 2)

    def test_safe_receipt_contains_counts_not_context_values(self) -> None:
        analysis = {
            "expected_context_count": 4,
            "observed_context_count": 12,
            "context_prefix_match_count": 3,
            "confirmed_symbol_count": 2,
            "confirmed_prefix_bit_count": 7,
            "confirmed_prefix_bit_modulo_8": 7,
            "next_expected_code_bit_count": 2,
        }
        receipt = build_first_context_bit_alignment(
            baseline_target_sha256="a" * 64,
            test_target_sha256="b" * 64,
            consumer_trace_sha256="c" * 64,
            local_consumer_trace_sha256="d" * 64,
            local_encoding_sha256="e" * 64,
            test_build_sha256="f" * 64,
            captured_utc=datetime.now(timezone.utc).isoformat().replace(
                "+00:00", "Z"
            ),
            analysis=analysis,
            context_mismatch_observed=True,
            next_expected_code_crosses_byte_boundary=True,
            next_expected_code_ends_on_byte_boundary=False,
        )
        self.assertEqual(
            receipt["status"],
            "consumer-context-divergence-crosses-byte-boundary",
        )
        self.assertEqual(
            receipt["next_checkpoint"],
            "trace-runtime-huffman-byte-reload",
        )
        validate_first_context_bit_alignment(receipt)
        leaked = deepcopy(receipt)
        leaked["observed_contexts"] = [0xC9]
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_first_context_bit_alignment(leaked)


if __name__ == "__main__":
    unittest.main()
