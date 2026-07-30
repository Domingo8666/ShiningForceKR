from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_group_context_resolution import (  # noqa: E402
    build_group_context_resolution,
    classify_context_candidates,
    validate_group_context_resolution,
)


def _records() -> list[dict[str, object]]:
    return [
        {"entry_id": "group-02/000", "ordinal": 0},
        {"entry_id": "group-02/001", "ordinal": 1},
        {"entry_id": "group-02/002", "ordinal": 2},
    ]


class GroupContextResolutionTests(unittest.TestCase):
    def test_finds_one_context_shared_by_every_record(self) -> None:
        valid = {
            ("group-02/000", 4),
            ("group-02/000", 9),
            ("group-02/001", 4),
            ("group-02/002", 4),
            ("group-02/002", 9),
        }

        def try_decode(
            record: dict[str, object],
            context: int,
        ) -> tuple[list[int], int] | None:
            if (record["entry_id"], context) not in valid:
                return None
            return [int(record["ordinal"]) + 1, 0xC9], 7

        safe, local = classify_context_candidates(
            _records(),
            [4, 9],
            try_decode,
        )
        self.assertEqual(safe["common_context_count"], 1)
        self.assertEqual(safe["best_context_exact_entry_count"], 3)
        self.assertEqual(safe["records_with_one_candidate"], 1)
        self.assertEqual(len(local["resolved_records"]), 3)
        self.assertNotIn("common_contexts_hex", safe)

    def test_reports_when_context_choice_cannot_resolve_the_group(self) -> None:
        def try_decode(
            record: dict[str, object],
            context: int,
        ) -> tuple[list[int], int] | None:
            ordinal = int(record["ordinal"])
            if (ordinal == 0 and context == 4) or (
                ordinal > 0 and context == 9
            ):
                return [ordinal + 1, 0xC9], 8
            return None

        safe, local = classify_context_candidates(
            _records(),
            [4, 9],
            try_decode,
        )
        self.assertEqual(safe["common_context_count"], 0)
        self.assertEqual(safe["best_context_exact_entry_count"], 2)
        self.assertEqual(safe["remaining_unresolved_count"], 3)
        self.assertEqual(local["resolved_records"], [])

    def test_builds_safe_aggregate_and_rejects_context_leakage(self) -> None:
        artifact = build_group_context_resolution(
            target_sha256="1" * 64,
            source_group_extract_sha256="2" * 64,
            selector=2,
            record_count=3,
            context_test={
                "available_context_count": 2,
                "canonical_context_exact_entry_count": 2,
                "records_with_zero_candidates": 0,
                "records_with_one_candidate": 1,
                "records_with_multiple_candidates": 2,
                "total_candidate_matches": 5,
                "maximum_candidates_per_record": 2,
                "best_context_exact_entry_count": 3,
                "best_context_tie_count": 1,
                "common_context_count": 1,
                "resolved_entry_count": 3,
                "remaining_unresolved_count": 0,
            },
            captured_utc="2026-07-30T15:00:00Z",
        )
        validate_group_context_resolution(artifact)
        self.assertEqual(
            artifact["status"],
            "group-initial-context-unique",
        )
        for field, value in (
            ("common_contexts_hex", ["0x04"]),
            ("symbols_hex", ["0x02", "0xC9"]),
            ("decoded_text", "테스트"),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_group_context_resolution(unsafe)


if __name__ == "__main__":
    unittest.main()
