from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_confirmed_group_extract import (  # noqa: E402
    build_confirmed_group_extract,
    parse_length_prefixed_group,
    validate_confirmed_group_extract,
)


def _layout() -> dict[str, object]:
    return {
        "selector": 2,
        "mapped_bank": 8,
        "logical_start": 0x43DE,
        "physical_start": 0x203DE,
        "declared_entry_count": 3,
        "selected_entry_ordinal": 2,
        "selected_record_matches": True,
    }


def _roundtrip() -> dict[str, object]:
    return {
        "parsed_entry_count": 3,
        "decoded_entry_count": 3,
        "roundtrip_exact_entry_count": 3,
        "terminator_exact_entry_count": 3,
        "zero_length_entry_count": 0,
        "decode_failed_entry_count": 0,
        "unresolved_entry_count": 0,
        "total_record_bytes": 9,
        "total_decoded_symbols": 12,
        "total_encoded_bits": 67,
        "maximum_record_bytes": 4,
    }


class ConfirmedGroupExtractTests(unittest.TestCase):
    def test_parses_the_declared_length_prefixed_population(self) -> None:
        rom = bytes([2, 0xAA, 0xBB, 1, 0xCC, 3, 1, 2, 3])
        records = parse_length_prefixed_group(
            rom,
            physical_start=0,
            entry_count=3,
        )
        self.assertEqual(
            [
                (
                    record["payload_start"],
                    record["record_length_bytes"],
                    record["payload"],
                )
                for record in records
            ],
            [
                (1, 2, bytes([0xAA, 0xBB])),
                (4, 1, bytes([0xCC])),
                (6, 3, bytes([1, 2, 3])),
            ],
        )

    def test_preserves_zero_length_and_rejects_truncated_records(self) -> None:
        records = parse_length_prefixed_group(
            bytes([0, 1, 0xAA]),
            physical_start=0,
            entry_count=2,
        )
        self.assertEqual(records[0]["record_length_bytes"], 0)
        self.assertEqual(records[0]["payload"], b"")
        with self.assertRaisesRegex(ValueError, "record length"):
            parse_length_prefixed_group(
                bytes([3, 1]),
                physical_start=0,
                entry_count=1,
            )

    def test_builds_a_complete_safe_group_receipt(self) -> None:
        artifact = build_confirmed_group_extract(
            target_sha256="1" * 64,
            source_register_trace_sha256="2" * 64,
            source_visible_roundtrip_sha256="3" * 64,
            layout=_layout(),
            roundtrip=_roundtrip(),
            captured_utc="2026-07-30T14:00:00Z",
        )
        validate_confirmed_group_extract(artifact)
        self.assertEqual(
            artifact["status"],
            "confirmed-group-roundtrip-pass",
        )
        self.assertFalse(artifact["translation_build_eligible"])

    def test_rejects_local_encoded_bytes_or_symbols(self) -> None:
        artifact = build_confirmed_group_extract(
            target_sha256="1" * 64,
            source_register_trace_sha256="2" * 64,
            source_visible_roundtrip_sha256="3" * 64,
            layout=_layout(),
            roundtrip=_roundtrip(),
            captured_utc="2026-07-30T14:00:00Z",
        )
        for field, value in (
            ("encoded_hex", "AABB"),
            ("symbols_hex", ["0x02"]),
            ("decoded_text", "테스트"),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_confirmed_group_extract(unsafe)


if __name__ == "__main__":
    unittest.main()
