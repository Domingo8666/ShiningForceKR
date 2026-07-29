#!/usr/bin/env python3
"""Verify the clean ROM, apply v5.1 BPS, and record a reproducible diff map."""

from __future__ import annotations

import argparse
from pathlib import Path
from datetime import datetime, timezone

try:
    from .patch_io import apply_bps, inspect_bps, sha256_bytes
except ImportError:  # direct script execution
    from patch_io import apply_bps, inspect_bps, sha256_bytes

EXPECTED_SOURCE_SIZE = 524288
EXPECTED_SOURCE_SHA256 = "4705256cc1a242aab7fea170369eb64723f796e27c6edfe0f93a674a8ba00f42"
EXPECTED_SOURCE_CRC32 = 0x6019FE5E
EXPECTED_PATCH_SHA256 = "7f92221afc8dc4b13712776d7eeca3571b9896fd746cefbc44b5a5806501633b"
EXPECTED_PATCH_SIZE = 1080753
EXPECTED_TARGET_SIZE = 1556480
EXPECTED_TARGET_CRC32 = 0x23BAC434


def differing_ranges(source: bytes, target: bytes) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    comparable = min(len(source), len(target))
    start: int | None = None
    for offset in range(comparable):
        changed = source[offset] != target[offset]
        if changed and start is None:
            start = offset
        elif not changed and start is not None:
            ranges.append((start, offset))
            start = None
    if start is not None:
        ranges.append((start, comparable))
    if len(target) > comparable:
        ranges.append((comparable, len(target)))
    return ranges


def bank_rows(source: bytes, target: bytes, bank_size: int = 0x4000) -> list[tuple[int, int, int, int]]:
    rows = []
    for start in range(0, len(target), bank_size):
        end = min(start + bank_size, len(target))
        changed = 0
        for offset in range(start, end):
            if offset >= len(source) or target[offset] != source[offset]:
                changed += 1
        rows.append((start // bank_size, start, end, changed))
    return rows


def make_report(source: bytes, target: bytes, patch: bytes, source_path: Path) -> str:
    report = inspect_bps(patch)
    ranges = differing_ranges(source, target)
    changed_in_source = sum(1 for index, value in enumerate(source) if target[index] != value)
    extension = max(0, len(target) - len(source))
    lines = [
        "# v5.1 BPS mobile verification report",
        "",
        f"Generated (UTC): {datetime.now(timezone.utc).isoformat()}",
        f"Local source name: {source_path.name}",
        "",
        "## Identities",
        "",
        "| Item | Size | SHA-256 / CRC32 |",
        "|---|---:|---|",
        f"| Clean source | {len(source)} | SHA-256 {sha256_bytes(source)}; CRC32 {report.source_crc32:08x} |",
        f"| v5.1 BPS | {len(patch)} | SHA-256 {sha256_bytes(patch)}; CRC32 {report.patch_crc32:08x} |",
        f"| Built target | {len(target)} | SHA-256 {sha256_bytes(target)}; CRC32 {report.target_crc32:08x} |",
        "",
        "## BPS structure",
        "",
        f"- Actions: {report.action_count}",
        f"- Action counts (SourceRead, TargetRead, SourceCopy, TargetCopy): {report.action_counts}",
        f"- Output bytes by action: {report.action_bytes}",
        f"- Changed bytes inside original 512 KiB: {changed_in_source}",
        f"- Literal extension after 0x80000: {extension} bytes",
        f"- Contiguous difference ranges: {len(ranges)}",
        "",
        "## 16 KiB bank map",
        "",
        "| Bank | File range | Changed/new bytes |",
        "|---:|---:|---:|",
    ]
    for bank, start, end, changed in bank_rows(source, target):
        lines.append(f"| {bank:02X} | 0x{start:06X}..0x{end:06X} | {changed} |")

    lines += ["", "## Difference ranges", ""]
    shown = ranges if len(ranges) <= 120 else ranges[:100] + ranges[-20:]
    if len(shown) != len(ranges):
        lines.append(f"First 100 and last 20 of {len(ranges)} ranges are shown.")
        lines.append("")
    for start, end in shown:
        lines.append(f"- 0x{start:06X}..0x{end:06X} ({end - start} bytes)")
    lines.append("")
    lines.append("Generated ROMs remain local and must not be committed.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", type=Path, required=True, help="clean Japanese ROM in Android local storage")
    parser.add_argument(
        "--patch",
        type=Path,
        default=root / "patch" / "Final_Conflict_Japan_to_Korean_v5.1.bps",
    )
    parser.add_argument("--output", type=Path, help="optional local built ROM path under build/")
    parser.add_argument("--report", type=Path, help="optional Markdown report path")
    args = parser.parse_args()

    source = args.rom.read_bytes()
    patch = args.patch.read_bytes()
    if len(source) != EXPECTED_SOURCE_SIZE or sha256_bytes(source) != EXPECTED_SOURCE_SHA256:
        raise SystemExit("clean ROM identity mismatch; refusing to patch")
    if len(patch) != EXPECTED_PATCH_SIZE or sha256_bytes(patch) != EXPECTED_PATCH_SHA256:
        raise SystemExit("v5.1 BPS identity mismatch; refusing to patch")

    info = inspect_bps(patch)
    if (
        info.source_crc32 != EXPECTED_SOURCE_CRC32
        or info.target_size != EXPECTED_TARGET_SIZE
        or info.target_crc32 != EXPECTED_TARGET_CRC32
    ):
        raise SystemExit("v5.1 BPS header/footer identity mismatch")
    target = apply_bps(source, patch)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(target)
        print(f"Built local ROM: {args.output}")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(make_report(source, target, patch, args.rom), encoding="utf-8")
        print(f"Wrote report: {args.report}")

    print(f"Source SHA-256: {sha256_bytes(source)}")
    print(f"Target SHA-256: {sha256_bytes(target)}")
    print(f"Target CRC32: {info.target_crc32:08x}")
    if not args.output and not args.report:
        print("Verification complete; no files were written.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
