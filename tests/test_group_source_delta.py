from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_group_source_delta import (  # noqa: E402
    build_group_source_delta,
    compare_group_source_records,
    validate_group_source_delta,
)


class GroupSourceDeltaTests(unittest.TestCase):
    def test_separates_resolved_and_unresolved_source_identity(self) -> None:
        source_records = [
            {
                "ordinal": 0,
                "record_length_bytes": 1,
                "payload": b"\xAA",
            },
            {
                "ordinal": 1,
                "record_length_bytes": 2,
                "payload": b"\xBB\xCC",
            },
            {
                "ordinal": 2,
                "record_length_bytes": 1,
                "payload": b"\xDD",
            },
        ]
        target_records = [
            {
                "entry_id": "group-02/000",
                "ordinal": 0,
                "record_length_bytes": 1,
                "encoded_hex": "11",
            },
            {
                "entry_id": "group-02/001",
                "ordinal": 1,
                "record_length_bytes": 2,
                "encoded_hex": "BBCC",
            },
            {
                "entry_id": "group-02/002",
                "ordinal": 2,
                "record_length_bytes": 1,
                "encoded_hex": "DD",
            },
        ]
        safe, local = compare_group_source_records(
            source_records=source_records,
            target_records=target_records,
            runtime_resolved_entry_ids={"group-02/000"},
        )
        self.assertEqual(safe["changed_entry_count"], 1)
        self.assertEqual(safe["runtime_resolved_changed_count"], 1)
        self.assertEqual(safe["runtime_unresolved_unchanged_count"], 2)
        self.assertNotIn("source_encoded_hex", safe)
        self.assertIn("source_encoded_hex", local["records"][0])

    def test_builds_safe_mixed_delta_and_rejects_raw_bytes(self) -> None:
        artifact = build_group_source_delta(
            source_sha256="1" * 64,
            target_sha256="2" * 64,
            source_group_extract_sha256="3" * 64,
            source_runtime_context_sha256="4" * 64,
            selector=2,
            record_count=3,
            delta={
                "source_parsed_entry_count": 3,
                "target_parsed_entry_count": 3,
                "unchanged_entry_count": 2,
                "changed_entry_count": 1,
                "same_length_entry_count": 3,
                "different_length_entry_count": 0,
                "runtime_resolved_unchanged_count": 0,
                "runtime_resolved_changed_count": 1,
                "runtime_unresolved_unchanged_count": 1,
                "runtime_unresolved_changed_count": 1,
                "source_total_record_bytes": 4,
                "target_total_record_bytes": 4,
            },
            captured_utc="2026-07-30T16:00:00Z",
        )
        validate_group_source_delta(artifact)
        self.assertEqual(
            artifact["status"],
            "runtime-unresolved-records-mixed-source-delta",
        )
        for field, value in (
            ("source_encoded_hex", "AABB"),
            ("target_encoded_hex", "CCDD"),
            ("record_deltas", [True, False]),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_group_source_delta(unsafe)


if __name__ == "__main__":
    unittest.main()
