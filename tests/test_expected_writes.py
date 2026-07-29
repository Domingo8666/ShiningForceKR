from __future__ import annotations

import unittest

from tools.expected_writes import (
    ExpectedWrite,
    apply_expected_writes,
    audit_expected_writes,
    expected_writes_to_ips,
    validate_expected_writes,
)
from tools.patch_io import PatchError, apply_ips


def write(
    offset: int,
    before: bytes,
    after: bytes,
    *,
    allowed_start: int = 0,
    allowed_end: int = 16,
) -> ExpectedWrite:
    return ExpectedWrite(
        writer="test-phrase",
        purpose="replace one verified compressed entry",
        offset=offset,
        before=before,
        after=after,
        allowed_start=allowed_start,
        allowed_end_exclusive=allowed_end,
    )


class ExpectedWritesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = bytes(range(16))

    def test_all_writes_validate_before_one_output_is_applied(self) -> None:
        writes = [
            write(2, b"\x02\x03", b"\xA2\xA3"),
            write(8, b"\x08", b"\xA8"),
        ]
        target, report = apply_expected_writes(self.source, writes)
        self.assertEqual(target[2:4], b"\xA2\xA3")
        self.assertEqual(target[8], 0xA8)
        self.assertEqual(report["write_count"], 2)
        self.assertEqual(report["changed_byte_count"], 3)
        self.assertEqual(report["changed_start"], 2)
        self.assertEqual(report["changed_end_exclusive"], 9)

    def test_unexpected_source_bytes_fail_closed(self) -> None:
        with self.assertRaisesRegex(PatchError, "source bytes mismatch"):
            apply_expected_writes(
                self.source,
                [write(2, b"\xFF\x03", b"\xA2\xA3")],
            )

    def test_overlaps_and_allowed_range_violations_fail_closed(self) -> None:
        with self.assertRaisesRegex(PatchError, "overlap"):
            validate_expected_writes(
                self.source,
                [
                    write(2, b"\x02\x03", b"\xA2\xA3"),
                    write(3, b"\x03\x04", b"\xB3\xB4"),
                ],
            )
        with self.assertRaisesRegex(PatchError, "allowed range"):
            validate_expected_writes(
                self.source,
                [
                    write(
                        2,
                        b"\x02\x03",
                        b"\xA2\xA3",
                        allowed_start=3,
                        allowed_end=8,
                    )
                ],
            )

    def test_noop_empty_and_size_change_writes_fail_closed(self) -> None:
        for candidate in (
            write(2, b"\x02", b"\x02"),
            write(2, b"", b""),
            write(2, b"\x02", b"\xA2\xA3"),
        ):
            with self.assertRaises(PatchError):
                validate_expected_writes(self.source, [candidate])

    def test_unexplained_final_diff_is_rejected(self) -> None:
        planned = [write(2, b"\x02", b"\xA2")]
        target, _ = apply_expected_writes(self.source, planned)
        corrupted = bytearray(target)
        corrupted[9] ^= 0xFF
        with self.assertRaisesRegex(PatchError, "does not equal"):
            audit_expected_writes(self.source, bytes(corrupted), planned)

    def test_ips_overlay_reproduces_the_audited_target(self) -> None:
        writes = [
            write(2, b"\x02\x03", b"\xA2\xA3"),
            write(8, b"\x08", b"\xA8"),
        ]
        target, _ = apply_expected_writes(self.source, writes)
        validated = validate_expected_writes(self.source, writes)
        overlay = expected_writes_to_ips(validated)
        self.assertEqual(apply_ips(self.source, overlay), target)

    def test_ips_limits_fail_closed(self) -> None:
        with self.assertRaisesRegex(PatchError, "EOF marker"):
            expected_writes_to_ips(
                [
                    ExpectedWrite(
                        writer="x",
                        purpose="x",
                        offset=0x454F46,
                        before=b"\x00",
                        after=b"\x01",
                        allowed_start=0,
                        allowed_end_exclusive=0x454F47,
                    )
                ]
            )


if __name__ == "__main__":
    unittest.main()
