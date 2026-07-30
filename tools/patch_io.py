#!/usr/bin/env python3
"""Strict BPS and IPS readers used by the ShiningForceKR analysis tools.

The module deliberately keeps ROM data out of the repository.  Callers provide a
local source image and receive bytes or an explicitly requested output file.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import zlib


class PatchError(ValueError):
    """Raised when a patch is malformed or does not match its source."""


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_bps_varint(value: int) -> bytes:
    if value < 0:
        raise PatchError("BPS variable-length integer cannot be negative")
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value == 0:
            output.append(byte | 0x80)
            return bytes(output)
        output.append(byte)
        value -= 1


def _read_bps_varint(data: bytes, position: int, limit: int) -> tuple[int, int]:
    result = 0
    shift = 1
    while True:
        if position >= limit:
            raise PatchError("truncated BPS variable-length integer")
        value = data[position]
        position += 1
        result += (value & 0x7F) * shift
        if value & 0x80:
            return result, position
        shift <<= 7
        result += shift
        if shift > (1 << 63):
            raise PatchError("BPS variable-length integer is too large")


def _decode_bps_signed(value: int) -> int:
    magnitude = value >> 1
    return -magnitude if value & 1 else magnitude


@dataclass(frozen=True)
class BPSReport:
    source_size: int
    target_size: int
    metadata: bytes
    action_count: int
    action_counts: tuple[int, int, int, int]
    action_bytes: tuple[int, int, int, int]
    source_crc32: int
    target_crc32: int
    patch_crc32: int


def create_bps(
    source: bytes,
    target: bytes,
    *,
    metadata: bytes = b"",
) -> bytes:
    """Create a deterministic, audit-friendly BPS patch."""

    if not isinstance(metadata, bytes):
        raise PatchError("BPS metadata must be bytes")
    body = bytearray(b"BPS1")
    body.extend(_write_bps_varint(len(source)))
    body.extend(_write_bps_varint(len(target)))
    body.extend(_write_bps_varint(len(metadata)))
    body.extend(metadata)

    position = 0
    while position < len(target):
        source_read = (
            position < len(source) and target[position] == source[position]
        )
        end = position + 1
        if source_read:
            while (
                end < len(target)
                and end < len(source)
                and target[end] == source[end]
            ):
                end += 1
            action = 0
        else:
            while end < len(target) and not (
                end < len(source) and target[end] == source[end]
            ):
                end += 1
            action = 1
        length = end - position
        body.extend(_write_bps_varint(((length - 1) << 2) | action))
        if action == 1:
            body.extend(target[position:end])
        position = end

    body.extend(crc32(source).to_bytes(4, "little"))
    body.extend(crc32(target).to_bytes(4, "little"))
    body.extend(crc32(body).to_bytes(4, "little"))
    patch = bytes(body)
    report = inspect_bps(patch)
    if (
        report.source_size != len(source)
        or report.target_size != len(target)
        or report.metadata != metadata
        or apply_bps(source, patch) != target
    ):
        raise PatchError("generated BPS failed independent reapplication")
    return patch


def inspect_bps(patch: bytes) -> BPSReport:
    if len(patch) < 16 or patch[:4] != b"BPS1":
        raise PatchError("not a BPS1 patch")
    footer = len(patch) - 12
    expected_patch_crc = int.from_bytes(patch[-4:], "little")
    actual_patch_crc = crc32(patch[:-4])
    if actual_patch_crc != expected_patch_crc:
        raise PatchError(
            f"BPS patch CRC mismatch: expected {expected_patch_crc:08x}, "
            f"got {actual_patch_crc:08x}"
        )

    position = 4
    source_size, position = _read_bps_varint(patch, position, footer)
    target_size, position = _read_bps_varint(patch, position, footer)
    metadata_size, position = _read_bps_varint(patch, position, footer)
    if position + metadata_size > footer:
        raise PatchError("truncated BPS metadata")
    metadata = patch[position : position + metadata_size]
    position += metadata_size

    output_size = 0
    counts = [0, 0, 0, 0]
    byte_counts = [0, 0, 0, 0]
    while output_size < target_size:
        instruction, position = _read_bps_varint(patch, position, footer)
        action = instruction & 3
        length = (instruction >> 2) + 1
        if output_size + length > target_size:
            raise PatchError("BPS action exceeds declared target size")
        counts[action] += 1
        byte_counts[action] += length
        if action == 1:
            if position + length > footer:
                raise PatchError("truncated BPS TargetRead data")
            position += length
        elif action in (2, 3):
            _, position = _read_bps_varint(patch, position, footer)
        output_size += length

    if position != footer:
        raise PatchError("unexpected bytes between BPS actions and footer")
    return BPSReport(
        source_size=source_size,
        target_size=target_size,
        metadata=metadata,
        action_count=sum(counts),
        action_counts=tuple(counts),
        action_bytes=tuple(byte_counts),
        source_crc32=int.from_bytes(patch[-12:-8], "little"),
        target_crc32=int.from_bytes(patch[-8:-4], "little"),
        patch_crc32=expected_patch_crc,
    )


@dataclass(frozen=True)
class BPSSparseTarget:
    """BPS target bytes plus a mask identifying source-independent bytes.

    A mask byte is one only when the corresponding target byte can be recovered
    from the patch without possessing the copyrighted source image.
    """

    report: BPSReport
    data: bytes
    known: bytes


def extract_bps_target_literals(patch: bytes) -> BPSSparseTarget:
    """Reconstruct every target byte that is derivable from the BPS alone.

    SourceRead and SourceCopy output remains unknown. TargetRead is known, and
    TargetCopy propagates the known/unknown state byte by byte so overlapping
    copies retain normal BPS semantics. The patch CRC and action stream are
    validated by inspect_bps first.
    """

    report = inspect_bps(patch)
    footer = len(patch) - 12
    position = 4
    _, position = _read_bps_varint(patch, position, footer)
    _, position = _read_bps_varint(patch, position, footer)
    metadata_size, position = _read_bps_varint(patch, position, footer)
    position += metadata_size

    output = bytearray()
    known = bytearray()
    source_relative = 0
    target_relative = 0
    while len(output) < report.target_size:
        instruction, position = _read_bps_varint(patch, position, footer)
        action = instruction & 3
        length = (instruction >> 2) + 1
        if len(output) + length > report.target_size:
            raise PatchError("BPS action exceeds declared target size")

        if action == 0:  # SourceRead
            output.extend(b"\x00" * length)
            known.extend(b"\x00" * length)
        elif action == 1:  # TargetRead
            if position + length > footer:
                raise PatchError("truncated BPS TargetRead data")
            output.extend(patch[position : position + length])
            known.extend(b"\x01" * length)
            position += length
        elif action == 2:  # SourceCopy
            encoded, position = _read_bps_varint(patch, position, footer)
            source_relative += _decode_bps_signed(encoded)
            if source_relative < 0 or source_relative + length > report.source_size:
                raise PatchError("BPS SourceCopy exceeds source")
            output.extend(b"\x00" * length)
            known.extend(b"\x00" * length)
            source_relative += length
        else:  # TargetCopy
            encoded, position = _read_bps_varint(patch, position, footer)
            target_relative += _decode_bps_signed(encoded)
            if target_relative < 0:
                raise PatchError("BPS TargetCopy has a negative source offset")
            for _ in range(length):
                if target_relative >= len(output):
                    raise PatchError("BPS TargetCopy reads beyond produced target")
                output.append(output[target_relative])
                known.append(known[target_relative])
                target_relative += 1

    return BPSSparseTarget(report=report, data=bytes(output), known=bytes(known))


def apply_bps(source: bytes, patch: bytes) -> bytes:
    report = inspect_bps(patch)
    if len(source) != report.source_size:
        raise PatchError(
            f"BPS source size mismatch: expected {report.source_size}, got {len(source)}"
        )
    actual_source_crc = crc32(source)
    if actual_source_crc != report.source_crc32:
        raise PatchError(
            f"BPS source CRC mismatch: expected {report.source_crc32:08x}, "
            f"got {actual_source_crc:08x}"
        )

    footer = len(patch) - 12
    position = 4
    _, position = _read_bps_varint(patch, position, footer)
    _, position = _read_bps_varint(patch, position, footer)
    metadata_size, position = _read_bps_varint(patch, position, footer)
    position += metadata_size

    output = bytearray()
    source_relative = 0
    target_relative = 0
    while len(output) < report.target_size:
        instruction, position = _read_bps_varint(patch, position, footer)
        action = instruction & 3
        length = (instruction >> 2) + 1
        if len(output) + length > report.target_size:
            raise PatchError("BPS action exceeds declared target size")

        if action == 0:  # SourceRead at the current target offset
            start = len(output)
            end = start + length
            if end > len(source):
                raise PatchError("BPS SourceRead exceeds source")
            output.extend(source[start:end])
        elif action == 1:  # TargetRead literal bytes
            if position + length > footer:
                raise PatchError("truncated BPS TargetRead data")
            output.extend(patch[position : position + length])
            position += length
        elif action == 2:  # SourceCopy from a relative source cursor
            encoded, position = _read_bps_varint(patch, position, footer)
            source_relative += _decode_bps_signed(encoded)
            if source_relative < 0 or source_relative + length > len(source):
                raise PatchError("BPS SourceCopy exceeds source")
            output.extend(source[source_relative : source_relative + length])
            source_relative += length
        else:  # TargetCopy, bytewise because overlapping copies are legal
            encoded, position = _read_bps_varint(patch, position, footer)
            target_relative += _decode_bps_signed(encoded)
            if target_relative < 0:
                raise PatchError("BPS TargetCopy has a negative source offset")
            for _ in range(length):
                if target_relative >= len(output):
                    raise PatchError("BPS TargetCopy reads beyond produced target")
                output.append(output[target_relative])
                target_relative += 1

    actual_target_crc = crc32(output)
    if actual_target_crc != report.target_crc32:
        raise PatchError(
            f"BPS target CRC mismatch: expected {report.target_crc32:08x}, "
            f"got {actual_target_crc:08x}"
        )
    return bytes(output)


@dataclass(frozen=True)
class IPSRecord:
    offset: int
    data: bytes
    is_rle: bool = False


@dataclass(frozen=True)
class IPSPatch:
    records: tuple[IPSRecord, ...]
    final_size: int | None = None


def parse_ips(patch: bytes) -> IPSPatch:
    if not patch.startswith(b"PATCH"):
        raise PatchError("not an IPS patch")
    position = 5
    records: list[IPSRecord] = []
    while True:
        if position + 3 > len(patch):
            raise PatchError("truncated IPS record offset")
        marker = patch[position : position + 3]
        position += 3
        if marker == b"EOF":
            break
        offset = int.from_bytes(marker, "big")
        if position + 2 > len(patch):
            raise PatchError("truncated IPS record length")
        size = int.from_bytes(patch[position : position + 2], "big")
        position += 2
        if size:
            if position + size > len(patch):
                raise PatchError("truncated IPS literal record")
            payload = patch[position : position + size]
            position += size
            records.append(IPSRecord(offset, payload, False))
        else:
            if position + 3 > len(patch):
                raise PatchError("truncated IPS RLE record")
            run_length = int.from_bytes(patch[position : position + 2], "big")
            value = patch[position + 2]
            position += 3
            if run_length == 0:
                raise PatchError("zero-length IPS RLE record")
            records.append(IPSRecord(offset, bytes([value]) * run_length, True))

    remaining = len(patch) - position
    if remaining not in (0, 3):
        raise PatchError("unexpected data after IPS EOF marker")
    final_size = int.from_bytes(patch[position:], "big") if remaining == 3 else None
    return IPSPatch(tuple(records), final_size)


def apply_ips(source: bytes, patch: bytes) -> bytes:
    parsed = parse_ips(patch)
    target = bytearray(source)
    for record in parsed.records:
        end = record.offset + len(record.data)
        if end > len(target):
            target.extend(b"\x00" * (end - len(target)))
        target[record.offset:end] = record.data
    if parsed.final_size is not None:
        if parsed.final_size < len(target):
            del target[parsed.final_size:]
        elif parsed.final_size > len(target):
            target.extend(b"\x00" * (parsed.final_size - len(target)))
    return bytes(target)
