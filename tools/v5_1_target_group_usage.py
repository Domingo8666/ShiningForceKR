#!/usr/bin/env python3
"""Classify static target-ROM uses of the patched script-group selector.

Call offsets, lookup pointers, immediate values, nearby bytes, and per-call
evidence remain in an ignored phone-local report.  The safe receipt publishes
only structural coverage counts.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_confirmed_group_extract import (
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        validate_confirmed_group_extract,
    )
    from .v5_1_consumer import verify_target_identity
    from .v5_1_decoder_register_trace import DECODER_ENTRY
    from .v5_1_renderer_output_trace import DEFAULT_ROM, _load_json_object
    from .v5_1_script_group import LOOKUP_TABLE_BASE, LOOKUP_TABLE_END
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from v5_1_confirmed_group_extract import (
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        validate_confirmed_group_extract,
    )
    from v5_1_consumer import verify_target_identity
    from v5_1_decoder_register_trace import DECODER_ENTRY
    from v5_1_renderer_output_trace import DEFAULT_ROM, _load_json_object
    from v5_1_script_group import LOOKUP_TABLE_BASE, LOOKUP_TABLE_END


ARTIFACT_KIND = "sanitized-v5-1-target-group-usage"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_target_group_usage.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_target_group_usage.json")
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_group_extract_sha256",
    "captured_utc",
    "lookup",
    "static_usage",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
LOOKUP_KEYS = {
    "slot_count",
    "valid_pointer_count",
    "unique_pointer_count",
    "duplicate_pointer_count",
}
USAGE_KEYS = {
    "decoder_call_signature_count",
    "calls_with_selector_candidate_count",
    "calls_with_ordinal_candidate_count",
    "calls_with_both_candidates_count",
    "unique_selector_candidate_count",
    "lookup_selectors_with_call_evidence_count",
    "lookup_selectors_without_call_evidence_count",
}
CALL_SIGNATURE = bytes((0xCD, DECODER_ENTRY & 0xFF, DECODER_ENTRY >> 8))
BACKWARD_WINDOW = 24


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _bounded_int(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _last_immediate(
    rom: bytes,
    *,
    start: int,
    end: int,
    opcode: int,
) -> tuple[int, int] | None:
    result: tuple[int, int] | None = None
    for offset in range(start, max(start, end - 2)):
        if rom[offset] == opcode and offset + 3 <= end:
            value = int.from_bytes(rom[offset + 1 : offset + 3], "little")
            result = (offset, value)
    return result


def analyze_target_group_usage(
    rom: bytes,
) -> tuple[dict[str, int], dict[str, object]]:
    pointers: list[dict[str, object]] = []
    pointer_values: list[int] = []
    for selector_offset in range(
        0,
        LOOKUP_TABLE_END - LOOKUP_TABLE_BASE,
        2,
    ):
        at = LOOKUP_TABLE_BASE + selector_offset
        pointer = int.from_bytes(rom[at : at + 2], "little")
        valid = 0x4000 <= pointer < 0x8000
        pointers.append(
            {
                "selector_offset": selector_offset,
                "lookup_offset": at,
                "pointer": pointer,
                "valid": valid,
            }
        )
        if valid:
            pointer_values.append(pointer)
    valid_selectors = {
        int(item["selector_offset"])
        for item in pointers
        if item["valid"] is True
    }
    calls: list[dict[str, object]] = []
    cursor = 0
    while True:
        call_offset = rom.find(CALL_SIGNATURE, cursor)
        if call_offset < 0:
            break
        before = max(0, call_offset - BACKWARD_WINDOW)
        de_load = _last_immediate(
            rom,
            start=before,
            end=call_offset,
            opcode=0x11,
        )
        bc_load = _last_immediate(
            rom,
            start=before,
            end=call_offset,
            opcode=0x01,
        )
        selector_candidate = (
            int(de_load[1])
            if de_load is not None and de_load[1] in valid_selectors
            else None
        )
        ordinal_candidate = (
            int(bc_load[1]) >> 8 if bc_load is not None else None
        )
        calls.append(
            {
                "call_offset": call_offset,
                "window_start": before,
                "nearby_hex": rom[before : call_offset + 3].hex().upper(),
                "de_load_offset": de_load[0] if de_load else None,
                "de_immediate": de_load[1] if de_load else None,
                "selector_candidate": selector_candidate,
                "bc_load_offset": bc_load[0] if bc_load else None,
                "bc_immediate": bc_load[1] if bc_load else None,
                "entry_ordinal_candidate": ordinal_candidate,
            }
        )
        cursor = call_offset + 1
    selector_candidates = {
        int(call["selector_candidate"])
        for call in calls
        if call["selector_candidate"] is not None
    }
    both_count = sum(
        int(
            call["selector_candidate"] is not None
            and call["entry_ordinal_candidate"] is not None
        )
        for call in calls
    )
    lookup_counts = {
        "slot_count": (LOOKUP_TABLE_END - LOOKUP_TABLE_BASE) // 2,
        "valid_pointer_count": len(pointer_values),
        "unique_pointer_count": len(set(pointer_values)),
        "duplicate_pointer_count": len(pointer_values)
        - len(set(pointer_values)),
    }
    usage_counts = {
        "decoder_call_signature_count": len(calls),
        "calls_with_selector_candidate_count": sum(
            int(call["selector_candidate"] is not None) for call in calls
        ),
        "calls_with_ordinal_candidate_count": sum(
            int(call["entry_ordinal_candidate"] is not None) for call in calls
        ),
        "calls_with_both_candidates_count": both_count,
        "unique_selector_candidate_count": len(selector_candidates),
        "lookup_selectors_with_call_evidence_count": len(
            valid_selectors & selector_candidates
        ),
        "lookup_selectors_without_call_evidence_count": len(
            valid_selectors - selector_candidates
        ),
    }
    local = {
        "lookup_entries": pointers,
        "calls": calls,
        "selector_candidates": sorted(selector_candidates),
        "uncovered_valid_selectors": sorted(
            valid_selectors - selector_candidates
        ),
    }
    return {**lookup_counts, **usage_counts}, local


def build_target_group_usage(
    *,
    target_sha256: str,
    source_group_extract_sha256: str,
    lookup: dict[str, object],
    static_usage: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    valid = int(lookup["valid_pointer_count"])
    covered = int(
        static_usage["lookup_selectors_with_call_evidence_count"]
    )
    calls = int(static_usage["decoder_call_signature_count"])
    complete = valid > 0 and covered == valid
    status = (
        "target-group-static-usage-complete"
        if complete
        else "target-group-static-usage-partial"
        if calls > 0
        else "target-group-static-calls-not-found"
    )
    checkpoint = (
        "enumerate-target-group-entry-populations"
        if complete
        else "trace-uncovered-target-group-selectors"
        if calls > 0
        else "locate-target-group-call-forms"
    )
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": target_sha256,
        "source_group_extract_sha256": source_group_extract_sha256,
        "captured_utc": captured_utc,
        "lookup": {
            key: int(lookup[key])
            for key in LOOKUP_KEYS
        },
        "static_usage": {
            key: int(static_usage[key])
            for key in USAGE_KEYS
        },
        "local_payload_policy": (
            "pointers-call-offsets-immediates-nearby-bytes-and-selectors-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": checkpoint,
    }
    validate_target_group_usage(safe)
    return safe


def validate_target_group_usage(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("target group usage fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "target-group-static-usage-complete",
            "target-group-static-usage-partial",
            "target-group-static-calls-not-found",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_group_extract_sha256"])
    ):
        raise ValueError("target group usage policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("target group usage timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("target group usage timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("target group usage timestamp must include UTC")
    lookup = value["lookup"]
    usage = value["static_usage"]
    if not isinstance(lookup, dict) or set(lookup) != LOOKUP_KEYS:
        raise ValueError("target group usage lookup fields do not match")
    if not isinstance(usage, dict) or set(usage) != USAGE_KEYS:
        raise ValueError("target group usage static fields do not match")
    for key in LOOKUP_KEYS:
        if not _bounded_int(lookup[key], 0, 0x100):
            raise ValueError(f"target group usage {key} is invalid")
    for key in USAGE_KEYS:
        if not _bounded_int(usage[key], 0, 0x100000):
            raise ValueError(f"target group usage {key} is invalid")
    if (
        lookup["valid_pointer_count"]
        > lookup["slot_count"]
        or lookup["unique_pointer_count"]
        + lookup["duplicate_pointer_count"]
        != lookup["valid_pointer_count"]
        or usage["lookup_selectors_with_call_evidence_count"]
        + usage["lookup_selectors_without_call_evidence_count"]
        != lookup["valid_pointer_count"]
        or usage["lookup_selectors_with_call_evidence_count"]
        > usage["unique_selector_candidate_count"]
    ):
        raise ValueError("target group usage aggregates are inconsistent")
    valid = int(lookup["valid_pointer_count"])
    covered = int(usage["lookup_selectors_with_call_evidence_count"])
    calls = int(usage["decoder_call_signature_count"])
    complete = valid > 0 and covered == valid
    expected_status = (
        "target-group-static-usage-complete"
        if complete
        else "target-group-static-usage-partial"
        if calls > 0
        else "target-group-static-calls-not-found"
    )
    expected_checkpoint = (
        "enumerate-target-group-entry-populations"
        if complete
        else "trace-uncovered-target-group-selectors"
        if calls > 0
        else "locate-target-group-call-forms"
    )
    if (
        value["status"] != expected_status
        or value["next_checkpoint"] != expected_checkpoint
        or value["local_payload_policy"]
        != "pointers-call-offsets-immediates-nearby-bytes-and-selectors-local-only"
        or value["translation_build_eligible"] is not False
    ):
        raise ValueError("target group usage result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    group_path = root / GROUP_EXTRACT_PATH
    if not rom_path.is_file() or not group_path.is_file():
        if args.if_ready:
            print("Target group usage is not ready")
            return 0
        raise SystemExit("target group usage input is missing")
    rom = rom_path.read_bytes()
    verify_target_identity(rom)
    group = _load_json_object(group_path)
    validate_confirmed_group_extract(group)
    target_sha256 = sha256_file(rom_path)
    if group["target_sha256"] != target_sha256:
        raise ValueError("target group usage identity disagrees")
    counts, local_analysis = analyze_target_group_usage(rom)
    lookup = {key: counts[key] for key in LOOKUP_KEYS}
    usage = {key: counts[key] for key in USAGE_KEYS}
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_target_group_usage(
        target_sha256=target_sha256,
        source_group_extract_sha256=sha256_file(group_path),
        lookup=lookup,
        static_usage=usage,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-target-group-usage",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "captured_utc": captured_utc,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-pointers-call-offsets-immediates-nearby-bytes-or-selectors"
        ),
    }
    safe_path = root / PUBLISH_RELATIVE_PATH
    local_path = root / LOCAL_REPORT_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR target group usage: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
