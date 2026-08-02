from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_first_context_translation_test_build import (  # noqa: E402
    build_first_context_translation_test_build,
    build_translation_writes,
    validate_first_context_translation_test_build,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
STAMP = "2026-07-31T13:00:00Z"


class FirstContextTranslationTestBuildTests(unittest.TestCase):
    @staticmethod
    def _target_with_group() -> tuple[bytes, list[tuple[int, int, int]]]:
        target = bytearray(range(100))
        cursor = 40
        records = []
        for ordinal, length in enumerate((2, 3, 4, 3)):
            length_offset = cursor
            target[cursor] = length
            cursor += 1
            payload_start = cursor
            for index in range(length):
                target[cursor + index] = 0x20 + ordinal * 8 + index
            cursor += length
            records.append((length_offset, payload_start, cursor))
        return bytes(target), records

    def test_combines_font_and_fixed_length_record_writes(self) -> None:
        target, records = self._target_with_group()
        length_offset, payload_start, payload_end = records[3]
        font_payload = b"\xFE\xFD"
        font_overlay = (
            b"PATCH"
            + (5).to_bytes(3, "big")
            + len(font_payload).to_bytes(2, "big")
            + font_payload
            + b"EOF"
        )
        writes, font_count, record_count = build_translation_writes(
            target=target,
            font_overlay=font_overlay,
            reinsertion_rows=[
                {
                    "review_index": 1,
                    "target_selector": 7,
                    "target_ordinal": 3,
                    "alias_keys": [(7, 3)],
                    "length_offset": length_offset,
                    "payload_start": payload_start,
                    "payload_end": payload_end,
                    "encoded_payload_hex": "AABBCC",
                    "encoded_payload_bits": 24,
                    "fits_in_place": True,
                }
            ],
            group_selector=7,
            group_physical_start=40,
            declared_group_entry_count=4,
        )
        self.assertEqual(font_count, 1)
        self.assertEqual(record_count, 1)
        self.assertEqual(len(writes), 2)
        record_write = next(
            write for write in writes if "record" in write.writer
        )
        self.assertEqual(record_write.offset, payload_start)
        self.assertEqual(record_write.after, b"\xAA\xBB\xCC")

    def test_writes_non_tail_record_without_moving_next_record(self) -> None:
        target, records = self._target_with_group()
        length_offset, payload_start, payload_end = records[2]
        next_length_offset, _, _ = records[3]
        writes, font_count, record_count = build_translation_writes(
            target=target,
            font_overlay=b"PATCHEOF",
            reinsertion_rows=[{
                "review_index": 1,
                "target_selector": 7,
                "target_ordinal": 2,
                "alias_keys": [(7, 1)],
                "length_offset": length_offset,
                "payload_start": payload_start,
                "payload_end": payload_end,
                "encoded_payload_hex": "AABBCCDD",
                "encoded_payload_bits": 32,
                "fits_in_place": True,
            }],
            group_selector=7,
            group_physical_start=40,
            declared_group_entry_count=4,
        )
        self.assertEqual(font_count, 0)
        self.assertEqual(record_count, 1)
        self.assertEqual(len(writes), 1)
        record_write = writes[0]
        self.assertEqual(record_write.offset, payload_start)
        self.assertEqual(record_write.allowed_end_exclusive, payload_end)
        self.assertLess(record_write.allowed_end_exclusive, next_length_offset + 1)
        self.assertEqual(record_write.after, b"\xAA\xBB\xCC\xDD")

    def test_compacts_only_the_confirmed_terminal_record(self) -> None:
        target, records = self._target_with_group()
        length_offset, payload_start, payload_end = records[-1]
        writes, font_count, record_count = build_translation_writes(
            target=target,
            font_overlay=b"PATCHEOF",
            reinsertion_rows=[{
                "review_index": 1,
                "target_selector": 7,
                "target_ordinal": 3,
                "alias_keys": [(7, 3)],
                "length_offset": length_offset,
                "payload_start": payload_start,
                "payload_end": payload_end,
                "encoded_payload_hex": "AABB",
                "encoded_payload_bits": 16,
                "fits_in_place": True,
                "compact_terminal_record": True,
            }],
            group_selector=7,
            group_physical_start=40,
            declared_group_entry_count=4,
        )
        self.assertEqual(font_count, 0)
        self.assertEqual(record_count, 1)
        self.assertEqual(len(writes), 2)
        length_write = next(write for write in writes if "length" in write.writer)
        payload_write = next(
            write for write in writes
            if write.writer == "first-context-record-001"
        )
        self.assertEqual(length_write.offset, length_offset)
        self.assertEqual(length_write.before, b"\x03")
        self.assertEqual(length_write.after, b"\x02")
        self.assertEqual(payload_write.offset, payload_start)
        self.assertEqual(payload_write.after, b"\xAA\xBB")
        self.assertEqual(payload_write.allowed_end_exclusive, payload_end)
        self.assertTrue(all(
            not (write.offset <= payload_start + 2 < write.offset + len(write.after))
            for write in writes
        ))
        self.assertEqual(target[payload_start + 2], 0x3A)

    def test_preserves_unused_bits_after_a_short_terminated_prefix(self) -> None:
        target, records = self._target_with_group()
        length_offset, payload_start, payload_end = records[0]
        writes, _, record_count = build_translation_writes(
            target=target,
            font_overlay=b"PATCHEOF",
            reinsertion_rows=[{
                "review_index": 1,
                "target_selector": 7,
                "target_ordinal": 0,
                "alias_keys": [(7, 0)],
                "length_offset": length_offset,
                "payload_start": payload_start,
                "payload_end": payload_end,
                "encoded_payload_hex": "E0",
                "encoded_payload_bits": 3,
                "fits_in_place": True,
            }],
            group_selector=7,
            group_physical_start=40,
            declared_group_entry_count=4,
        )
        self.assertEqual(record_count, 1)
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0].offset, payload_start)
        self.assertEqual(writes[0].after, b"\xE0")
        self.assertEqual(writes[0].allowed_end_exclusive, payload_end)
        self.assertEqual(target[payload_start + 1], 0x21)

    def test_builds_safe_static_verification_receipt(self) -> None:
        verification = {
            "context_entry_count": 4,
            "record_write_count": 4,
            "font_write_count": 40,
            "write_count": 44,
            "changed_byte_count": 800,
            "record_length_field_verified_count": 4,
            "record_length_changed_count": 0,
            "decoded_roundtrip_entry_count": 4,
            "decoded_failure_entry_count": 0,
            "record_suffix_preserved_entry_count": 4,
            "font_glyph_assignment_count": 55,
            "font_glyph_verified_count": 55,
            "encoded_length_exact_count": 4,
        }
        safe = build_first_context_translation_test_build(
            baseline_target_sha256=SHA_A,
            test_target_sha256=SHA_B,
            test_overlay_sha256=SHA_C,
            first_context_record_reinsertion_sha256=SHA_D,
            local_build_sha256=SHA_E,
            verification=verification,
            captured_utc=STAMP,
        )
        self.assertEqual(
            safe["status"],
            "first-context-translation-static-build-ready",
        )
        self.assertTrue(safe["static_translation_build_confirmed"])
        self.assertTrue(safe["record_length_fields_verified"])
        self.assertFalse(safe["translation_build_eligible"])
        non_exact = deepcopy(verification)
        non_exact["encoded_length_exact_count"] = 3
        non_exact_safe = build_first_context_translation_test_build(
            baseline_target_sha256=SHA_A,
            test_target_sha256=SHA_B,
            test_overlay_sha256=SHA_C,
            first_context_record_reinsertion_sha256=SHA_D,
            local_build_sha256=SHA_E,
            verification=non_exact,
            captured_utc=STAMP,
        )
        self.assertTrue(non_exact_safe["static_translation_build_confirmed"])
        self.assertEqual(
            non_exact_safe["status"],
            "first-context-translation-static-build-ready",
        )
        unsafe = deepcopy(safe)
        unsafe["record_offsets"] = [1, 2, 3, 4]
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_first_context_translation_test_build(unsafe)


if __name__ == "__main__":
    unittest.main()
