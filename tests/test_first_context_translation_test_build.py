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
    def test_combines_font_and_fixed_length_record_writes(self) -> None:
        target = bytes(range(100))
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
                    "length_offset": 49,
                    "payload_start": 50,
                    "payload_end": 56,
                    "encoded_payload_hex": "AABBCC",
                    "fits_in_place": True,
                }
            ],
        )
        self.assertEqual(font_count, 1)
        self.assertEqual(record_count, 1)
        self.assertEqual(len(writes), 2)
        record_write = next(
            write for write in writes if "record" in write.writer
        )
        self.assertEqual(record_write.offset, 49)
        self.assertEqual(record_write.after[:4], b"\x03\xAA\xBB\xCC")
        self.assertEqual(record_write.after[4:], target[53:56])

    def test_builds_safe_static_verification_receipt(self) -> None:
        verification = {
            "context_entry_count": 4,
            "record_write_count": 4,
            "font_write_count": 40,
            "write_count": 44,
            "changed_byte_count": 800,
            "record_length_field_verified_count": 4,
            "record_length_changed_count": 4,
            "decoded_roundtrip_entry_count": 4,
            "decoded_failure_entry_count": 0,
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
