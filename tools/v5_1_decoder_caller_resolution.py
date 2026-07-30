#!/usr/bin/env python3
"""Resolve the containing decoder routine from phone-local call-stack evidence.

Raw stack frames, return addresses, routine addresses, call offsets, immediate
values, and nearby bytes remain in an ignored local report.  The published
receipt contains aggregate coverage counts only.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_consumer import verify_target_identity
    from .v5_1_decoder_register_trace import DECODER_ENTRY
    from .v5_1_renderer_output_trace import DEFAULT_ROM, _load_json_object
    from .v5_1_script_group import LOOKUP_TABLE_BASE, LOOKUP_TABLE_END
    from .v5_1_target_group_usage import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_USAGE_PATH,
        validate_target_group_usage,
    )
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from v5_1_consumer import verify_target_identity
    from v5_1_decoder_register_trace import DECODER_ENTRY
    from v5_1_renderer_output_trace import DEFAULT_ROM, _load_json_object
    from v5_1_script_group import LOOKUP_TABLE_BASE, LOOKUP_TABLE_END
    from v5_1_target_group_usage import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_USAGE_PATH,
        validate_target_group_usage,
    )


ARTIFACT_KIND = "sanitized-v5-1-decoder-caller-resolution"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_decoder_caller_resolution.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_decoder_caller_resolution.json"
)
RENDERER_PROBE_PATH = Path("reports/local/v5_1_renderer_probe.json")
DIRECT_CALL_OPCODES = {
    0xC4,
    0xCC,
    0xCD,
    0xD4,
    0xDC,
    0xE4,
    0xEC,
    0xF4,
    0xFC,
}
BACKWARD_WINDOW = 48
MAX_ROUTINE_DISTANCE = 0x800
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_target_group_usage_sha256",
    "source_renderer_probe_sha256",
    "captured_utc",
    "stack",
    "caller_scan",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
STACK_KEYS = {
    "depth",
    "parsed_return_count",
    "direct_call_frame_count",
    "containing_routine_candidate_count",
    "containing_routine_resolved",
}
CALLER_KEYS = {
    "lookup_selector_count",
    "routine_call_signature_count",
    "calls_with_selector_candidate_count",
    "calls_with_ordinal_candidate_count",
    "calls_with_both_candidates_count",
    "unique_selector_candidate_count",
    "lookup_selectors_with_call_evidence_count",
    "lookup_selectors_without_call_evidence_count",
}


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


def _parse_hex_word(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    normalized = value.removeprefix("$").removeprefix("0x")
    if re.fullmatch(r"[0-9A-Fa-f]{1,4}", normalized) is None:
        return None
    return int(normalized, 16)


def _stack_frames(probe: dict[str, object]) -> list[dict[str, object]]:
    attempts = probe.get("attempts")
    if not isinstance(attempts, list):
        return []
    for attempt in attempts:
        if not isinstance(attempt, dict) or attempt.get("hit") is None:
            continue
        evidence = attempt.get("evidence")
        if not isinstance(evidence, dict):
            continue
        call_stack = evidence.get("call_stack")
        if not isinstance(call_stack, dict):
            continue
        for key in ("stack", "frames", "call_stack"):
            frames = call_stack.get(key)
            if isinstance(frames, list):
                return [
                    frame for frame in frames if isinstance(frame, dict)
                ]
    return []


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
            result = (
                offset,
                int.from_bytes(rom[offset + 1 : offset + 3], "little"),
            )
    return result


def _valid_selectors(rom: bytes) -> set[int]:
    output: set[int] = set()
    for selector in range(
        0,
        LOOKUP_TABLE_END - LOOKUP_TABLE_BASE,
        2,
    ):
        at = LOOKUP_TABLE_BASE + selector
        pointer = int.from_bytes(rom[at : at + 2], "little")
        if 0x4000 <= pointer < 0x8000:
            output.add(selector)
    return output


def _routine_candidates(
    rom: bytes,
    frames: list[dict[str, object]],
) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for frame_index, frame in enumerate(frames):
        function = _parse_hex_word(frame.get("function"))
        source = _parse_hex_word(frame.get("source"))
        return_address = _parse_hex_word(frame.get("return"))
        direct_call = False
        opcode: int | None = None
        call_offset: int | None = None
        call_target: int | None = None
        if (
            return_address is None
            or return_address < 3
            or return_address > 0x4000
        ):
            pass
        else:
            call_offset = return_address - 3
            opcode = rom[call_offset]
            if opcode in DIRECT_CALL_OPCODES:
                call_target = int.from_bytes(
                    rom[call_offset + 1 : return_address],
                    "little",
                )
                direct_call = True
        target = function if function is not None else call_target
        if target is None:
            continue
        output.append(
            {
                "frame_index": frame_index,
                "source": source,
                "return_address": return_address,
                "call_offset": call_offset,
                "opcode": opcode,
                "target": target,
                "stack_function": function,
                "direct_call_target": call_target,
                "direct_call_confirmed": direct_call,
            }
        )
    return output


def _select_containing_routine(
    candidates: list[dict[str, object]],
) -> int | None:
    plausible = {
        int(item["target"])
        for item in candidates
        if (
            int(item["target"]) <= DECODER_ENTRY
            and DECODER_ENTRY - int(item["target"])
            <= MAX_ROUTINE_DISTANCE
        )
    }
    if not plausible:
        return None
    return min(plausible, key=lambda target: DECODER_ENTRY - target)


def _scan_calls(
    rom: bytes,
    *,
    target: int,
    valid_selectors: set[int],
) -> list[dict[str, object]]:
    signatures = {
        bytes((opcode, target & 0xFF, target >> 8))
        for opcode in DIRECT_CALL_OPCODES
    }
    calls: list[dict[str, object]] = []
    for call_offset in range(0, len(rom) - 2):
        if rom[call_offset : call_offset + 3] not in signatures:
            continue
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
        selector = (
            de_load[1]
            if de_load is not None and de_load[1] in valid_selectors
            else None
        )
        ordinal = bc_load[1] >> 8 if bc_load is not None else None
        calls.append(
            {
                "call_offset": call_offset,
                "nearby_hex": rom[before : call_offset + 3].hex().upper(),
                "de_load_offset": de_load[0] if de_load else None,
                "de_immediate": de_load[1] if de_load else None,
                "selector_candidate": selector,
                "bc_load_offset": bc_load[0] if bc_load else None,
                "bc_immediate": bc_load[1] if bc_load else None,
                "entry_ordinal_candidate": ordinal,
            }
        )
    return calls


def analyze_decoder_caller(
    rom: bytes,
    probe: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    frames = _stack_frames(probe)
    candidates = _routine_candidates(rom, frames)
    routine = _select_containing_routine(candidates)
    selectors = _valid_selectors(rom)
    calls = (
        _scan_calls(rom, target=routine, valid_selectors=selectors)
        if routine is not None
        else []
    )
    selector_candidates = {
        int(call["selector_candidate"])
        for call in calls
        if call["selector_candidate"] is not None
    }
    safe = {
        "stack": {
            "depth": len(frames),
            "parsed_return_count": sum(
                _parse_hex_word(frame.get("return")) is not None
                for frame in frames
            ),
            "direct_call_frame_count": sum(
                item["direct_call_confirmed"] is True
                for item in candidates
            ),
            "containing_routine_candidate_count": len(
                {
                    int(item["target"])
                    for item in candidates
                    if (
                        int(item["target"]) <= DECODER_ENTRY
                        and DECODER_ENTRY - int(item["target"])
                        <= MAX_ROUTINE_DISTANCE
                    )
                }
            ),
            "containing_routine_resolved": routine is not None,
        },
        "caller_scan": {
            "lookup_selector_count": len(selectors),
            "routine_call_signature_count": len(calls),
            "calls_with_selector_candidate_count": sum(
                call["selector_candidate"] is not None for call in calls
            ),
            "calls_with_ordinal_candidate_count": sum(
                call["entry_ordinal_candidate"] is not None for call in calls
            ),
            "calls_with_both_candidates_count": sum(
                call["selector_candidate"] is not None
                and call["entry_ordinal_candidate"] is not None
                for call in calls
            ),
            "unique_selector_candidate_count": len(selector_candidates),
            "lookup_selectors_with_call_evidence_count": len(
                selectors & selector_candidates
            ),
            "lookup_selectors_without_call_evidence_count": len(
                selectors - selector_candidates
            ),
        },
    }
    local = {
        "call_stack_frames": frames,
        "routine_candidates": candidates,
        "selected_containing_routine": routine,
        "caller_signatures": calls,
        "selector_candidates": sorted(selector_candidates),
        "uncovered_valid_selectors": sorted(selectors - selector_candidates),
    }
    return safe, local


def build_decoder_caller_resolution(
    *,
    target_sha256: str,
    source_target_group_usage_sha256: str,
    source_renderer_probe_sha256: str,
    stack: dict[str, object],
    caller_scan: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    resolved = stack["containing_routine_resolved"] is True
    valid = int(caller_scan["lookup_selector_count"])
    covered = int(
        caller_scan["lookup_selectors_with_call_evidence_count"]
    )
    calls = int(caller_scan["routine_call_signature_count"])
    complete = resolved and valid > 0 and covered == valid
    status = (
        "decoder-caller-static-usage-complete"
        if complete
        else "decoder-caller-static-usage-partial"
        if resolved and calls > 0
        else "decoder-caller-resolved-no-static-calls"
        if resolved
        else "decoder-caller-routine-unresolved"
    )
    checkpoint = (
        "enumerate-target-group-entry-populations"
        if complete
        else "trace-uncovered-target-group-selectors"
        if resolved and calls > 0
        else "trace-containing-decoder-routine-entry"
        if resolved
        else "capture-decoder-containing-call-frame"
    )
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": target_sha256,
        "source_target_group_usage_sha256":
            source_target_group_usage_sha256,
        "source_renderer_probe_sha256": source_renderer_probe_sha256,
        "captured_utc": captured_utc,
        "stack": {
            key: stack[key]
            for key in STACK_KEYS
        },
        "caller_scan": {
            key: int(caller_scan[key])
            for key in CALLER_KEYS
        },
        "local_payload_policy": (
            "stack-returns-routine-addresses-call-offsets-immediates-and-bytes-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": checkpoint,
    }
    validate_decoder_caller_resolution(value)
    return value


def validate_decoder_caller_resolution(
    value: dict[str, object],
) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("decoder caller resolution fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "decoder-caller-static-usage-complete",
            "decoder-caller-static-usage-partial",
            "decoder-caller-resolved-no-static-calls",
            "decoder-caller-routine-unresolved",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_target_group_usage_sha256"])
        or not _is_sha256(value["source_renderer_probe_sha256"])
    ):
        raise ValueError("decoder caller resolution policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("decoder caller resolution timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(
            "decoder caller resolution timestamp is invalid"
        ) from error
    if parsed.tzinfo is None:
        raise ValueError("decoder caller timestamp must include UTC")
    stack = value["stack"]
    caller = value["caller_scan"]
    if not isinstance(stack, dict) or set(stack) != STACK_KEYS:
        raise ValueError("decoder caller stack fields do not match")
    if not isinstance(caller, dict) or set(caller) != CALLER_KEYS:
        raise ValueError("decoder caller scan fields do not match")
    for key in STACK_KEYS - {"containing_routine_resolved"}:
        if not _bounded_int(stack[key], 0, 0x1000):
            raise ValueError(f"decoder caller {key} is invalid")
    if not isinstance(stack["containing_routine_resolved"], bool):
        raise ValueError("decoder caller resolved flag is invalid")
    for key in CALLER_KEYS:
        if not _bounded_int(caller[key], 0, 0x100000):
            raise ValueError(f"decoder caller {key} is invalid")
    if (
        caller["lookup_selectors_with_call_evidence_count"]
        + caller["lookup_selectors_without_call_evidence_count"]
        != caller["lookup_selector_count"]
        or caller["lookup_selectors_with_call_evidence_count"]
        > caller["unique_selector_candidate_count"]
        or stack["direct_call_frame_count"]
        > stack["parsed_return_count"]
    ):
        raise ValueError("decoder caller aggregates are inconsistent")
    resolved = stack["containing_routine_resolved"] is True
    valid = int(caller["lookup_selector_count"])
    covered = int(caller["lookup_selectors_with_call_evidence_count"])
    calls = int(caller["routine_call_signature_count"])
    complete = resolved and valid > 0 and covered == valid
    expected_status = (
        "decoder-caller-static-usage-complete"
        if complete
        else "decoder-caller-static-usage-partial"
        if resolved and calls > 0
        else "decoder-caller-resolved-no-static-calls"
        if resolved
        else "decoder-caller-routine-unresolved"
    )
    expected_checkpoint = (
        "enumerate-target-group-entry-populations"
        if complete
        else "trace-uncovered-target-group-selectors"
        if resolved and calls > 0
        else "trace-containing-decoder-routine-entry"
        if resolved
        else "capture-decoder-containing-call-frame"
    )
    if (
        value["status"] != expected_status
        or value["next_checkpoint"] != expected_checkpoint
        or value["local_payload_policy"]
        != "stack-returns-routine-addresses-call-offsets-immediates-and-bytes-local-only"
        or value["translation_build_eligible"] is not False
    ):
        raise ValueError("decoder caller result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    usage_path = root / TARGET_GROUP_USAGE_PATH
    probe_path = root / RENDERER_PROBE_PATH
    if (
        not rom_path.is_file()
        or not usage_path.is_file()
        or not probe_path.is_file()
    ):
        if args.if_ready:
            print("Decoder caller resolution is not ready")
            return 0
        raise SystemExit("decoder caller resolution input is missing")
    rom = rom_path.read_bytes()
    verify_target_identity(rom)
    target_sha256 = sha256_file(rom_path)
    usage = _load_json_object(usage_path)
    validate_target_group_usage(usage)
    if usage["target_sha256"] != target_sha256:
        raise ValueError("decoder caller target identity disagrees")
    probe = _load_json_object(probe_path)
    if probe.get("target_sha256") != target_sha256:
        raise ValueError("decoder caller probe identity disagrees")
    analysis, local_analysis = analyze_decoder_caller(rom, probe)
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_decoder_caller_resolution(
        target_sha256=target_sha256,
        source_target_group_usage_sha256=sha256_file(usage_path),
        source_renderer_probe_sha256=sha256_file(probe_path),
        stack=analysis["stack"],
        caller_scan=analysis["caller_scan"],
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-decoder-caller-resolution",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "captured_utc": captured_utc,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-stack-returns-routine-addresses-call-offsets-immediates-or-bytes"
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
    print(f"SFKR decoder caller resolution: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
