#!/usr/bin/env python3
"""Plan, validate, apply, and audit fixed-size image writes.

Every write is checked against the same immutable input before any output is
changed.  Overlaps, out-of-range coordinates, unexpected source bytes, and
unexplained final differences are hard failures.
"""

from __future__ import annotations

from dataclasses import dataclass

try:
    from .patch_io import PatchError
except ImportError:  # direct script execution
    from patch_io import PatchError


@dataclass(frozen=True)
class ExpectedWrite:
    writer: str
    purpose: str
    offset: int
    before: bytes
    after: bytes
    allowed_start: int
    allowed_end_exclusive: int

    @property
    def end_exclusive(self) -> int:
        return self.offset + len(self.after)


def _validate_text(value: str, label: str) -> None:
    if not value or len(value) > 120 or any(ord(char) < 0x20 for char in value):
        raise PatchError(f"{label} must be non-empty printable text")


def validate_expected_writes(
    source: bytes, writes: list[ExpectedWrite]
) -> list[ExpectedWrite]:
    if not writes:
        raise PatchError("expected-write plan is empty")
    ordered = sorted(writes, key=lambda item: (item.offset, item.end_exclusive))
    previous_end = -1
    for write in ordered:
        _validate_text(write.writer, "writer")
        _validate_text(write.purpose, "purpose")
        if write.offset < 0:
            raise PatchError("expected-write offset must not be negative")
        if not 0 <= write.allowed_start <= write.allowed_end_exclusive <= len(source):
            raise PatchError("expected-write allowed range is invalid")
        if not write.before or len(write.before) != len(write.after):
            raise PatchError("expected-write before/after sizes must match and be nonzero")
        if not (
            write.allowed_start
            <= write.offset
            < write.end_exclusive
            <= write.allowed_end_exclusive
        ):
            raise PatchError("expected-write exceeds its allowed range")
        if write.end_exclusive > len(source):
            raise PatchError("expected-write exceeds the immutable input")
        if source[write.offset : write.end_exclusive] != write.before:
            raise PatchError(
                f"expected source bytes mismatch at 0x{write.offset:06X}"
            )
        if write.before == write.after:
            raise PatchError("expected-write does not change any bytes")
        if write.offset < previous_end:
            raise PatchError("expected-write ranges overlap")
        previous_end = write.end_exclusive
    return ordered


def audit_expected_writes(
    source: bytes,
    target: bytes,
    writes: list[ExpectedWrite],
) -> dict[str, object]:
    ordered = validate_expected_writes(source, writes)
    if len(target) != len(source):
        raise PatchError("fixed-size expected-write output length changed")

    ownership: dict[int, str] = {}
    planned_changed: set[int] = set()
    for write in ordered:
        for index, (before, after) in enumerate(zip(write.before, write.after)):
            offset = write.offset + index
            if before != after:
                planned_changed.add(offset)
                ownership[offset] = write.writer

    actual_changed = {
        offset
        for offset, (before, after) in enumerate(zip(source, target))
        if before != after
    }
    if actual_changed != planned_changed:
        missing = sorted(planned_changed - actual_changed)
        unexplained = sorted(actual_changed - planned_changed)
        raise PatchError(
            "final diff does not equal the expected-write plan "
            f"(missing={len(missing)}, unexplained={len(unexplained)})"
        )
    for write in ordered:
        if target[write.offset : write.end_exclusive] != write.after:
            raise PatchError(
                f"final bytes mismatch at 0x{write.offset:06X}"
            )
    return {
        "status": "expected-writes-audited",
        "source_size": len(source),
        "target_size": len(target),
        "write_count": len(ordered),
        "changed_byte_count": len(actual_changed),
        "changed_start": min(actual_changed),
        "changed_end_exclusive": max(actual_changed) + 1,
        "writers": sorted(set(ownership.values())),
    }


def apply_expected_writes(
    source: bytes, writes: list[ExpectedWrite]
) -> tuple[bytes, dict[str, object]]:
    ordered = validate_expected_writes(source, writes)
    target = bytearray(source)
    for write in ordered:
        target[write.offset : write.end_exclusive] = write.after
    result = bytes(target)
    return result, audit_expected_writes(source, result, ordered)


def expected_writes_to_ips(writes: list[ExpectedWrite]) -> bytes:
    """Serialize already validated fixed-size writes as an IPS overlay.

    Callers must validate against the immutable input first.  The IPS output
    deliberately has no truncate/extend footer.
    """

    output = bytearray(b"PATCH")
    for write in sorted(writes, key=lambda item: item.offset):
        if not 0 <= write.offset <= 0xFFFFFF:
            raise PatchError("IPS write offset exceeds 24 bits")
        if write.offset == 0x454F46:
            raise PatchError("IPS write offset collides with EOF marker")
        if len(write.after) > 0xFFFF:
            raise PatchError("IPS literal record exceeds 65535 bytes")
        output.extend(write.offset.to_bytes(3, "big"))
        output.extend(len(write.after).to_bytes(2, "big"))
        output.extend(write.after)
    output.extend(b"EOF")
    return bytes(output)
