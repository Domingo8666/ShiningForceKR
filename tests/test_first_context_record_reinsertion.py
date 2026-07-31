from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_first_context_record_reinsertion import (  # noqa: E402
    build_first_context_record_reinsertion,
    build_reinsertion_rows,
    summarize_reinsertion_rows,
    validate_first_context_record_reinsertion,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
STAMP = "2026-07-31T12:00:00Z"


class FirstContextRecordReinsertionTests(unittest.TestCase):
    def _rows(self) -> tuple[bytearray, list, list, list]:
        target = bytearray(100)
        offsets = [10, 30, 50, 70]
        lengths = [8, 7, 6, 5]
        context_rows = []
        projection_pairs = []
        encoding_rows = []
        for index, (offset, length) in enumerate(
            zip(offsets, lengths),
            start=1,
        ):
            target[offset] = length
            context_rows.append(
                {
                    "mapping_status": "unique",
                    "source_section_index": index,
                    "source_line_index": index + 10,
                }
            )
            projection_pairs.append(
                {
                    "source_section_index": index,
                    "source_line_index": index + 10,
                    "target_record": {
                        "length_offset": offset,
                        "record_length_bytes": length,
                        "aliases": [{"selector": index, "ordinal": index}],
                    },
                }
            )
            payload = bytes(range(index, index + 3))
            encoding_rows.append(
                {
                    "review_index": index,
                    "encoded_hex": payload.hex().upper(),
                    "encoded_bits": 20,
                    "encoded_bytes": len(payload),
                }
            )
        return target, context_rows, projection_pairs, encoding_rows

    def test_confirms_four_distinct_in_place_records(self) -> None:
        target, contexts, projections, encodings = self._rows()
        rows = build_reinsertion_rows(
            target=bytes(target),
            context_rows=contexts,
            projection_pairs=projections,
            encoding_rows=encodings,
        )
        counts = summarize_reinsertion_rows(rows)
        self.assertEqual(counts["in_place_fit_entry_count"], 4)
        self.assertEqual(counts["overflow_entry_count"], 0)
        self.assertEqual(counts["distinct_target_record_count"], 4)

    def test_builds_safe_plan_without_private_record_data(self) -> None:
        target, contexts, projections, encodings = self._rows()
        counts = summarize_reinsertion_rows(
            build_reinsertion_rows(
                target=bytes(target),
                context_rows=contexts,
                projection_pairs=projections,
                encoding_rows=encodings,
            )
        )
        safe = build_first_context_record_reinsertion(
            target_sha256=SHA_A,
            review_batch_sha256=SHA_B,
            first_context_translation_encoding_sha256=SHA_C,
            local_reinsertion_sha256=SHA_D,
            capacity=counts,
            captured_utc=STAMP,
        )
        self.assertEqual(
            safe["status"],
            "first-context-record-reinsertion-plan-ready",
        )
        self.assertTrue(safe["record_storage_capacity_confirmed"])
        self.assertFalse(safe["translation_build_eligible"])
        unsafe = deepcopy(safe)
        unsafe["record_offset"] = 10
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_first_context_record_reinsertion(unsafe)


if __name__ == "__main__":
    unittest.main()
