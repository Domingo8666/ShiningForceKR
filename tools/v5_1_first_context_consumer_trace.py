#!/usr/bin/env python3
"""Trace whether the first translated record is decoded past its terminator.

Exact contexts and symbols remain in an ignored local report.  The publishable
receipt contains only fixed-schema counts and booleans.  This is a diagnostic
gate: it never approves a translation build.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

try:
    from .patch_io import sha256_file
    from .run_s25u_renderer_probe import (
        HUFFMAN_VECTOR_START,
        _last_rom_read,
    )
    from .run_s25u_runtime_probe import (
        McpStdioClient,
        _capture_state,
        _default_command,
        _runtime_failure_receipt,
        _step_instruction_and_wait,
        _write_runtime_failure_receipt,
    )
    from .v5_1_first_context_translation_encoding import (
        CANDIDATE_END_SYMBOL,
        LOCAL_REPORT_PATH as LOCAL_ENCODING_PATH,
    )
    from .v5_1_first_context_translation_runtime_capture import (
        PUBLISH_RELATIVE_PATH as RUNTIME_CAPTURE_PATH,
        TEST_ROM_PATH,
        validate_first_context_translation_runtime_capture,
    )
    from .v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TEST_BUILD_PATH,
        validate_first_context_translation_test_build,
    )
    from .v5_1_first_context_translation_visual_review import (
        PUBLISH_RELATIVE_PATH as VISUAL_REVIEW_PATH,
        validate_first_context_translation_visual_review,
    )
    from .v5_1_font_transfer_source import (
        _mapped_bank_for_address,
        _physical_address,
        _write_a_address,
    )
    from .v5_1_runtime_hit_resolver import _parse_trace_line, _read_addresses
    from .v5_1_source_target_anchor import (
        CONFIRMED_ORDINAL,
        CONFIRMED_SELECTOR,
    )
    from .v5_1_source_target_runtime_sequence import (
        ATTRACT_CAPTURE_SCHEDULE,
        ATTRACT_CAPTURE_TIMEOUT_SECONDS,
        DECODER_ENTRY_LOGICAL,
        MAX_REJECTED_TARGET_HITS,
        REQUIRED_TOOLS,
        _entry_coordinates,
    )
    from .v5_1_test_display_capture import _continue_until_breakpoint
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from run_s25u_renderer_probe import HUFFMAN_VECTOR_START, _last_rom_read
    from run_s25u_runtime_probe import (
        McpStdioClient,
        _capture_state,
        _default_command,
        _runtime_failure_receipt,
        _step_instruction_and_wait,
        _write_runtime_failure_receipt,
    )
    from v5_1_first_context_translation_encoding import (
        CANDIDATE_END_SYMBOL,
        LOCAL_REPORT_PATH as LOCAL_ENCODING_PATH,
    )
    from v5_1_first_context_translation_runtime_capture import (
        PUBLISH_RELATIVE_PATH as RUNTIME_CAPTURE_PATH,
        TEST_ROM_PATH,
        validate_first_context_translation_runtime_capture,
    )
    from v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TEST_BUILD_PATH,
        validate_first_context_translation_test_build,
    )
    from v5_1_first_context_translation_visual_review import (
        PUBLISH_RELATIVE_PATH as VISUAL_REVIEW_PATH,
        validate_first_context_translation_visual_review,
    )
    from v5_1_font_transfer_source import (
        _mapped_bank_for_address,
        _physical_address,
        _write_a_address,
    )
    from v5_1_runtime_hit_resolver import _parse_trace_line, _read_addresses
    from v5_1_source_target_anchor import (
        CONFIRMED_ORDINAL,
        CONFIRMED_SELECTOR,
    )
    from v5_1_source_target_runtime_sequence import (
        ATTRACT_CAPTURE_SCHEDULE,
        ATTRACT_CAPTURE_TIMEOUT_SECONDS,
        DECODER_ENTRY_LOGICAL,
        MAX_REJECTED_TARGET_HITS,
        REQUIRED_TOOLS,
        _entry_coordinates,
    )
    from v5_1_test_display_capture import _continue_until_breakpoint


ARTIFACT_KIND = "sanitized-v5-1-first-context-consumer-trace"
SCHEMA_VERSION = 2
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_consumer_trace.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_first_context_consumer_trace.json"
)
MAX_VECTOR_READ_HITS = 128
FIRST_VECTOR_TIMEOUT_SECONDS = 4.0
NEXT_VECTOR_TIMEOUT_SECONDS = 0.75
VECTOR_LOGICAL_RANGES = ((0x4100, 0x42FF), (0x8100, 0x82FF))
TRACE_COUNT_KEYS = {
    "planned_decode_count",
    "expected_context_count",
    "observed_context_count",
    "expected_context_prefix_match_count",
    "post_terminator_context_count",
    "initial_context_match_count",
    "trace_line_count",
    "parsed_instruction_count",
    "supported_read_count",
    "indexed_read_instruction_count",
    "index_immediate_load_count",
    "mapper_write_count",
    "logical_vector_window_read_count",
    "mapped_vector_read_count",
}
TRACE_DIAGNOSTIC_COUNT_KEYS = {
    "trace_line_count",
    "parsed_instruction_count",
    "supported_read_count",
    "indexed_read_instruction_count",
    "index_immediate_load_count",
    "mapper_write_count",
    "logical_vector_window_read_count",
    "mapped_vector_read_count",
}
SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "baseline_target_sha256",
    "test_target_sha256",
    "first_context_translation_test_build_sha256",
    "first_context_translation_runtime_capture_sha256",
    "first_context_translation_visual_review_sha256",
    "local_trace_sha256",
    "captured_utc",
    "anchor_reached",
    "trace",
    "expected_context_prefix_complete",
    "first_post_terminator_context_is_terminator",
    "direct_terminator_overread_confirmed",
    "cold_boot",
    "source_and_target_text_local_only",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return timestamp.utcoffset() == timezone.utc.utcoffset(timestamp)


def summarize_consumer_contexts(
    *,
    observed_contexts: list[int],
    initial_context: int,
    expected_symbols: list[int],
) -> tuple[dict[str, int], bool, bool, bool]:
    """Compare runtime vector contexts with one planned symbol sequence."""

    if not 0 <= initial_context <= 0xFF:
        raise ValueError("consumer trace initial context is invalid")
    if (
        not expected_symbols
        or expected_symbols[-1] != CANDIDATE_END_SYMBOL
        or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= 0xFF
            for value in expected_symbols
        )
    ):
        raise ValueError("consumer trace expected symbols are invalid")
    if any(
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 0xFF
        for value in observed_contexts
    ):
        raise ValueError("consumer trace observed contexts are invalid")

    # One vector is selected by the incoming context for each decoded symbol.
    # A decoder that stops after producing the terminator therefore performs no
    # vector read with the terminator itself as the next context.
    expected_contexts = [initial_context, *expected_symbols[:-1]]
    prefix_matches = 0
    for observed, expected in zip(observed_contexts, expected_contexts):
        if observed != expected:
            break
        prefix_matches += 1
    prefix_complete = prefix_matches == len(expected_contexts)
    post_count = max(0, len(observed_contexts) - len(expected_contexts))
    first_post_is_terminator = (
        prefix_complete
        and post_count > 0
        and observed_contexts[len(expected_contexts)]
        == CANDIDATE_END_SYMBOL
    )
    direct_overread = prefix_complete and first_post_is_terminator
    counts = {
        "planned_decode_count": len(expected_symbols),
        "expected_context_count": len(expected_contexts),
        "observed_context_count": len(observed_contexts),
        "expected_context_prefix_match_count": prefix_matches,
        "post_terminator_context_count": post_count,
        "initial_context_match_count": int(
            bool(observed_contexts) and observed_contexts[0] == initial_context
        ),
        "trace_line_count": len(observed_contexts),
        "parsed_instruction_count": len(observed_contexts),
        "supported_read_count": len(observed_contexts),
        "indexed_read_instruction_count": 0,
        "index_immediate_load_count": 0,
        "mapper_write_count": 0,
        "logical_vector_window_read_count": len(observed_contexts),
        "mapped_vector_read_count": len(observed_contexts),
    }
    return counts, prefix_complete, first_post_is_terminator, direct_overread


def build_first_context_consumer_trace(
    *,
    baseline_target_sha256: str,
    test_target_sha256: str,
    first_context_translation_test_build_sha256: str,
    first_context_translation_runtime_capture_sha256: str,
    first_context_translation_visual_review_sha256: str,
    local_trace_sha256: str,
    captured_utc: str,
    trace: dict[str, int],
    expected_context_prefix_complete: bool,
    first_post_terminator_context_is_terminator: bool,
    direct_terminator_overread_confirmed: bool,
) -> dict[str, object]:
    if direct_terminator_overread_confirmed:
        status = "consumer-terminator-overread-confirmed"
        checkpoint = "resolve-record-consumer-boundary"
    elif expected_context_prefix_complete:
        status = "consumer-terminator-stop-observed"
        checkpoint = "trace-renderer-postdecode-consumer"
    else:
        status = "consumer-context-trace-inconclusive"
        checkpoint = "repair-consumer-trace-alignment"
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "baseline_target_sha256": baseline_target_sha256,
        "test_target_sha256": test_target_sha256,
        "first_context_translation_test_build_sha256":
            first_context_translation_test_build_sha256,
        "first_context_translation_runtime_capture_sha256":
            first_context_translation_runtime_capture_sha256,
        "first_context_translation_visual_review_sha256":
            first_context_translation_visual_review_sha256,
        "local_trace_sha256": local_trace_sha256,
        "captured_utc": captured_utc,
        "anchor_reached": True,
        "trace": trace,
        "expected_context_prefix_complete": expected_context_prefix_complete,
        "first_post_terminator_context_is_terminator":
            first_post_terminator_context_is_terminator,
        "direct_terminator_overread_confirmed":
            direct_terminator_overread_confirmed,
        "cold_boot": True,
        "source_and_target_text_local_only": True,
        "translation_build_eligible": False,
        "next_checkpoint": checkpoint,
    }
    validate_first_context_consumer_trace(value)
    return value


def validate_first_context_consumer_trace(value: dict[str, object]) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError("first context consumer trace fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or not all(
            _is_sha256(value[key])
            for key in (
                "baseline_target_sha256",
                "test_target_sha256",
                "first_context_translation_test_build_sha256",
                "first_context_translation_runtime_capture_sha256",
                "first_context_translation_visual_review_sha256",
                "local_trace_sha256",
            )
        )
        or value["baseline_target_sha256"] == value["test_target_sha256"]
        or not _is_utc_timestamp(value["captured_utc"])
    ):
        raise ValueError("first context consumer trace identity is invalid")
    trace = value["trace"]
    if (
        not isinstance(trace, dict)
        or set(trace) != TRACE_COUNT_KEYS
        or any(
            not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
            for count in trace.values()
        )
        or any(
            trace[key] > MAX_VECTOR_READ_HITS
            for key in TRACE_COUNT_KEYS - TRACE_DIAGNOSTIC_COUNT_KEYS
        )
        or any(
            trace[key] > 200_000 for key in TRACE_DIAGNOSTIC_COUNT_KEYS
        )
        or trace["planned_decode_count"] <= 0
        or trace["expected_context_count"] != trace["planned_decode_count"]
        or trace["expected_context_prefix_match_count"]
        > min(trace["expected_context_count"], trace["observed_context_count"])
        or trace["post_terminator_context_count"]
        != max(
            0,
            trace["observed_context_count"] - trace["expected_context_count"],
        )
        or trace["initial_context_match_count"] not in {0, 1}
        or trace["parsed_instruction_count"] > trace["trace_line_count"]
        or trace["indexed_read_instruction_count"]
        > trace["parsed_instruction_count"]
        or trace["index_immediate_load_count"]
        > trace["parsed_instruction_count"]
        or trace["mapper_write_count"] > trace["parsed_instruction_count"]
        or trace["logical_vector_window_read_count"]
        > trace["supported_read_count"]
        or trace["mapped_vector_read_count"]
        > trace["logical_vector_window_read_count"]
        or trace["mapped_vector_read_count"]
        != trace["observed_context_count"]
    ):
        raise ValueError("first context consumer trace counts do not match")
    prefix_complete = (
        trace["expected_context_prefix_match_count"]
        == trace["expected_context_count"]
    )
    first_post = value["first_post_terminator_context_is_terminator"]
    direct = value["direct_terminator_overread_confirmed"]
    if not isinstance(first_post, bool) or not isinstance(direct, bool):
        raise ValueError("first context consumer trace result is invalid")
    if first_post and trace["post_terminator_context_count"] <= 0:
        raise ValueError("first context consumer trace overread is inconsistent")
    if direct != (prefix_complete and first_post):
        raise ValueError("first context consumer trace overread is inconsistent")
    expected_status = (
        "consumer-terminator-overread-confirmed"
        if direct
        else "consumer-terminator-stop-observed"
        if prefix_complete
        else "consumer-context-trace-inconclusive"
    )
    expected_checkpoint = (
        "resolve-record-consumer-boundary"
        if direct
        else "trace-renderer-postdecode-consumer"
        if prefix_complete
        else "repair-consumer-trace-alignment"
    )
    if (
        value["status"] != expected_status
        or value["expected_context_prefix_complete"] is not prefix_complete
        or value["anchor_reached"] is not True
        or value["cold_boot"] is not True
        or value["source_and_target_text_local_only"] is not True
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"] != expected_checkpoint
    ):
        raise ValueError("first context consumer trace result is inconsistent")


def _load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def first_context_consumer_trace_needed(root: Path) -> bool:
    paths = {
        "rom": root / TEST_ROM_PATH,
        "build": root / TEST_BUILD_PATH,
        "runtime": root / RUNTIME_CAPTURE_PATH,
        "review": root / VISUAL_REVIEW_PATH,
        "encoding": root / LOCAL_ENCODING_PATH,
    }
    if any(not path.is_file() for path in paths.values()):
        return False
    try:
        build = _load_json(paths["build"])
        runtime = _load_json(paths["runtime"])
        review = _load_json(paths["review"])
        validate_first_context_translation_test_build(build)
        validate_first_context_translation_runtime_capture(runtime)
        validate_first_context_translation_visual_review(review)
        if (
            review["status"]
            != "first-context-translation-runtime-visual-fail"
            or review["test_target_sha256"] != runtime["test_target_sha256"]
            or runtime["test_target_sha256"] != build["test_target_sha256"]
            or sha256_file(paths["rom"]) != build["test_target_sha256"]
        ):
            return False
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    safe_path = root / PUBLISH_RELATIVE_PATH
    if not safe_path.is_file():
        return True
    try:
        existing = _load_json(safe_path)
        validate_first_context_consumer_trace(existing)
        return not (
            existing["test_target_sha256"] == build["test_target_sha256"]
            and existing["first_context_translation_runtime_capture_sha256"]
            == sha256_file(paths["runtime"])
            and existing["first_context_translation_visual_review_sha256"]
            == sha256_file(paths["review"])
        )
    except (OSError, ValueError, json.JSONDecodeError):
        return True


def analyze_vector_contexts_from_trace(
    lines: list[str],
    *,
    initial_slot1_bank: int,
    initial_slot2_bank: int,
    initial_ix: int,
    initial_iy: int,
) -> tuple[list[int], dict[str, int]]:
    """Recover every Huffman context lookup from one complete consumer trace.

    Breakpoint-per-read sampling can resume in the middle of a two-byte vector
    lookup and lose the next lookup.  A continuous trace to the outer consumer
    return preserves the original instruction stream and mapper transitions.
    """

    slot1_bank = initial_slot1_bank
    slot2_bank = initial_slot2_bank
    if not 0 <= slot1_bank <= 0xFF or not 0 <= slot2_bank <= 0xFF:
        raise ValueError("consumer trace initial mapper bank is invalid")
    if not 0 <= initial_ix <= 0xFFFF or not 0 <= initial_iy <= 0xFFFF:
        raise ValueError("consumer trace initial index register is invalid")

    contexts: list[int] = []
    parsed_instruction_count = 0
    supported_read_count = 0
    indexed_read_instruction_count = 0
    index_immediate_load_count = 0
    mapper_write_count = 0
    logical_vector_window_read_count = 0
    ix: int | None = initial_ix
    iy: int | None = initial_iy
    for line in lines:
        parsed = _parse_trace_line(line)
        if parsed is None:
            continue
        parsed_instruction_count += 1
        opcodes = parsed["opcodes"]
        raw_registers = parsed["registers"]
        assert isinstance(opcodes, bytes)
        assert isinstance(raw_registers, dict)
        registers = {
            key: int(value)
            for key, value in raw_registers.items()
            if isinstance(value, int) and not isinstance(value, bool)
        }
        if ix is not None:
            registers["ix"] = ix
        if iy is not None:
            registers["iy"] = iy

        read_addresses = _read_addresses(opcodes, registers)
        supported_read_count += len(read_addresses)
        if read_addresses and opcodes and opcodes[0] in {0xDD, 0xFD}:
            indexed_read_instruction_count += 1
        for logical in read_addresses:
            if 0x4100 <= logical < 0x4300 or 0x8100 <= logical < 0x8300:
                logical_vector_window_read_count += 1
            bank = _mapped_bank_for_address(
                logical,
                slot1_bank,
                slot2_bank,
            )
            if bank is None:
                continue
            physical = _physical_address(bank, logical)
            if (
                HUFFMAN_VECTOR_START
                <= physical
                < HUFFMAN_VECTOR_START + 0x200
                and (physical - HUFFMAN_VECTOR_START) % 2 == 0
            ):
                contexts.append((physical - HUFFMAN_VECTOR_START) // 2)

        write_address = _write_a_address(opcodes, registers)
        if write_address in {0xFFFE, 0xFFFF}:
            mapper_write_count += 1
            mapped_bank = registers.get("a", 0) & 0xFF
            if write_address == 0xFFFE:
                slot1_bank = mapped_bank
            else:
                slot2_bank = mapped_bank

        if opcodes and opcodes[0] in {0xDD, 0xFD} and len(opcodes) >= 2:
            current = ix if opcodes[0] == 0xDD else iy
            second = opcodes[1]
            updated = current
            if second == 0x21 and len(opcodes) >= 4:
                index_immediate_load_count += 1
                updated = opcodes[2] | (opcodes[3] << 8)
            elif second == 0x23 and current is not None:
                updated = (current + 1) & 0xFFFF
            elif second == 0x2B and current is not None:
                updated = (current - 1) & 0xFFFF
            elif second == 0x09 and current is not None:
                updated = (current + registers.get("bc", 0)) & 0xFFFF
            elif second == 0x19 and current is not None:
                updated = (current + registers.get("de", 0)) & 0xFFFF
            elif second == 0x29 and current is not None:
                updated = (current * 2) & 0xFFFF
            elif second == 0x39 and current is not None:
                updated = (current + registers.get("sp", 0)) & 0xFFFF
            elif second in {0x2A, 0xE1, 0xE3}:
                # The trace omits memory/stack values.  Stay fail-closed until a
                # later immediate load makes this index value observable again.
                updated = None
            if opcodes[0] == 0xDD:
                ix = updated
            else:
                iy = updated

    diagnostics = {
        "trace_line_count": len(lines),
        "parsed_instruction_count": parsed_instruction_count,
        "supported_read_count": supported_read_count,
        "indexed_read_instruction_count": indexed_read_instruction_count,
        "index_immediate_load_count": index_immediate_load_count,
        "mapper_write_count": mapper_write_count,
        "logical_vector_window_read_count": logical_vector_window_read_count,
        "mapped_vector_read_count": len(contexts),
    }
    return contexts, diagnostics


def extract_vector_contexts_from_trace(
    lines: list[str],
    *,
    initial_slot1_bank: int,
    initial_slot2_bank: int,
    initial_ix: int,
    initial_iy: int,
) -> list[int]:
    contexts, _ = analyze_vector_contexts_from_trace(
        lines,
        initial_slot1_bank=initial_slot1_bank,
        initial_slot2_bank=initial_slot2_bank,
        initial_ix=initial_ix,
        initial_iy=initial_iy,
    )
    return contexts


def _capture_contexts(
    *, rom_path: Path, rom_size: int
) -> tuple[list[int], dict[str, object]]:
    client = McpStdioClient(_default_command())
    entry_address = f"{DECODER_ENTRY_LOGICAL:04X}"
    vector_ranges = [
        (f"{start:04X}", f"{end:04X}")
        for start, end in VECTOR_LOGICAL_RANGES
    ]
    entry_armed = False
    vector_armed = False
    local: dict[str, object] = {"anchor_hits": [], "vector_events": []}

    def arm_entry() -> None:
        nonlocal entry_armed
        client.call(
            "set_breakpoint_range",
            {
                "start_address": entry_address,
                "end_address": entry_address,
                "memory_area": "rom_ram",
                "execute": True,
                "read": False,
                "write": False,
            },
        )
        entry_armed = True

    def disarm_entry() -> None:
        nonlocal entry_armed
        if entry_armed:
            client.call(
                "remove_breakpoint",
                {
                    "address": entry_address,
                    "end_address": entry_address,
                    "memory_area": "rom_ram",
                },
            )
            entry_armed = False

    def arm_vectors() -> None:
        nonlocal vector_armed
        for start, end in vector_ranges:
            client.call(
                "set_breakpoint_range",
                {
                    "start_address": start,
                    "end_address": end,
                    "memory_area": "rom_ram",
                    "execute": False,
                    "read": True,
                    "write": False,
                },
            )
        vector_armed = True

    def disarm_vectors() -> None:
        nonlocal vector_armed
        if not vector_armed:
            return
        for start, end in vector_ranges:
            try:
                client.call(
                    "remove_breakpoint",
                    {
                        "address": start,
                        "end_address": end,
                        "memory_area": "rom_ram",
                    },
                )
            except RuntimeError:
                pass
        vector_armed = False

    contexts: list[int] = []
    try:
        tools = client.initialize()
        missing = sorted(REQUIRED_TOOLS - tools)
        if missing:
            raise RuntimeError(f"Gearsystem MCP tools missing: {missing}")
        client.call("load_media", {"file_path": str(rom_path)})
        media = client.call("get_media_info")
        if (
            media.get("ready") is not True
            or media.get("is_game_gear") is not True
            or int(media.get("rom_size", 0)) != rom_size
        ):
            raise RuntimeError("Gearsystem did not load the consumer trace ROM")
        local["media"] = media
        client.call("debug_reset")
        client.call("debug_pause")
        if any(button is not None for _, button in ATTRACT_CAPTURE_SCHEDULE):
            raise RuntimeError("consumer trace attract schedule must be passive")
        arm_entry()
        anchor_timeout = max(ATTRACT_CAPTURE_TIMEOUT_SECONDS, 240.0)
        anchor_reached = False
        anchor_state: dict[str, object] | None = None
        for _ in range(MAX_REJECTED_TARGET_HITS):
            status = _continue_until_breakpoint(client, anchor_timeout)
            if status.get("at_breakpoint") is not True:
                break
            state, evidence = _capture_state(client)
            selector, ordinal = _entry_coordinates(state)
            local["anchor_hits"].append(
                {
                    "selector": selector,
                    "ordinal": ordinal,
                    "state": state,
                    "evidence": evidence,
                }
            )
            disarm_entry()
            if selector == CONFIRMED_SELECTOR and ordinal == CONFIRMED_ORDINAL:
                anchor_reached = True
                anchor_state = state
                break
            _step_instruction_and_wait(client)
            arm_entry()
        if not anchor_reached or anchor_state is None:
            raise RuntimeError("consumer trace confirmed anchor was not reached")

        client.call(
            "set_trace_log",
            {
                "enabled": True,
                "cpu_irq": False,
                "vdp_write": False,
                "vdp_status": False,
                "psg": False,
                "ym2413": False,
                "io_port": False,
                "bank_switch": True,
            },
        )
        diagnostic_lines: list[str] = []
        for hit_index in range(MAX_VECTOR_READ_HITS):
            arm_vectors()
            status = _continue_until_breakpoint(
                client,
                FIRST_VECTOR_TIMEOUT_SECONDS
                if hit_index == 0
                else NEXT_VECTOR_TIMEOUT_SECONDS,
            )
            if status.get("at_breakpoint") is not True:
                break
            state, evidence = _capture_state(client)
            trace = evidence.get("trace")
            if isinstance(trace, dict):
                lines = trace.get("lines")
                if isinstance(lines, list):
                    diagnostic_lines.extend(
                        line for line in lines if isinstance(line, str)
                    )
            sample = _last_rom_read(state, evidence, rom_size)
            event: dict[str, object] = {
                "state": state,
                "evidence": evidence,
                "sample": sample,
            }
            if sample is not None:
                physical = sample.get("physical_file_offset")
                if (
                    sample.get("classification")
                    == "korean-huffman-vector"
                    and isinstance(physical, int)
                    and not isinstance(physical, bool)
                    and HUFFMAN_VECTOR_START
                    <= physical
                    < HUFFMAN_VECTOR_START + 0x200
                    and (physical - HUFFMAN_VECTOR_START) % 2 == 0
                ):
                    context = (physical - HUFFMAN_VECTOR_START) // 2
                    contexts.append(context)
                    event["context"] = context
            local["vector_events"].append(event)
            disarm_vectors()
            # Read breakpoints are reported after the memory instruction has
            # completed.  Re-arming and continuing resumes at the following
            # instruction; stepping here would skip a possible next lookup.

        _, trace_diagnostics = analyze_vector_contexts_from_trace(
            diagnostic_lines,
            initial_slot1_bank=int(anchor_state["slot1_bank"]),
            initial_slot2_bank=int(anchor_state["slot2_bank"]),
            initial_ix=int(anchor_state["registers"]["ix"]),
            initial_iy=int(anchor_state["registers"]["iy"]),
        )
        trace_diagnostics["logical_vector_window_read_count"] = max(
            trace_diagnostics["logical_vector_window_read_count"],
            len(contexts),
        )
        trace_diagnostics["mapped_vector_read_count"] = len(contexts)
        local["sampling_mode"] = "post-read-breakpoint-no-extra-step"
        local["trace_diagnostics"] = trace_diagnostics
        local["raw_trace_lines"] = diagnostic_lines
        local["observed_contexts"] = contexts
        return contexts, local
    except Exception as error:
        receipt = _runtime_failure_receipt(
            "candidate-probe",
            error,
            client,
        )
        _write_runtime_failure_receipt(
            Path(__file__).resolve().parents[1],
            receipt,
        )
        raise
    finally:
        try:
            disarm_entry()
        except RuntimeError:
            pass
        disarm_vectors()
        try:
            client.call(
                "set_trace_log",
                {
                    "enabled": False,
                    "cpu_irq": False,
                    "vdp_write": False,
                    "vdp_status": False,
                    "psg": False,
                    "ym2413": False,
                    "io_port": False,
                    "bank_switch": True,
                },
            )
        except RuntimeError:
            pass
        client.close()


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-needed", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.if_needed and not first_context_consumer_trace_needed(root):
        print("SFKR first context consumer trace: not needed")
        return 0

    paths = {
        "rom": root / TEST_ROM_PATH,
        "build": root / TEST_BUILD_PATH,
        "runtime": root / RUNTIME_CAPTURE_PATH,
        "review": root / VISUAL_REVIEW_PATH,
        "encoding": root / LOCAL_ENCODING_PATH,
    }
    if any(not path.is_file() for path in paths.values()):
        raise FileNotFoundError("first context consumer trace input is missing")
    build = _load_json(paths["build"])
    runtime = _load_json(paths["runtime"])
    review = _load_json(paths["review"])
    encoding = _load_json(paths["encoding"])
    validate_first_context_translation_test_build(build)
    validate_first_context_translation_runtime_capture(runtime)
    validate_first_context_translation_visual_review(review)
    rows = encoding.get("rows")
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        raise ValueError("first context consumer trace encoding rows are missing")
    first_row = rows[0]
    expected_symbols = first_row.get("symbols")
    initial_context = first_row.get("initial_context")
    if not isinstance(expected_symbols, list) or not isinstance(initial_context, int):
        raise ValueError("first context consumer trace encoding row is invalid")
    if (
        review["status"] != "first-context-translation-runtime-visual-fail"
        or review["test_target_sha256"] != runtime["test_target_sha256"]
        or runtime["test_target_sha256"] != build["test_target_sha256"]
        or sha256_file(paths["rom"]) != build["test_target_sha256"]
    ):
        raise ValueError("first context consumer trace identity disagrees")

    observed_contexts, local_capture = _capture_contexts(
        rom_path=paths["rom"], rom_size=paths["rom"].stat().st_size
    )
    counts, prefix_complete, first_post, direct = summarize_consumer_contexts(
        observed_contexts=observed_contexts,
        initial_context=initial_context,
        expected_symbols=expected_symbols,
    )
    trace_diagnostics = local_capture.get("trace_diagnostics")
    if (
        not isinstance(trace_diagnostics, dict)
        or set(trace_diagnostics) != TRACE_DIAGNOSTIC_COUNT_KEYS
        or any(
            not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
            for count in trace_diagnostics.values()
        )
    ):
        raise ValueError("consumer trace diagnostics are invalid")
    counts.update(trace_diagnostics)
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    local = {
        "artifact_kind": "local-v5-1-first-context-consumer-trace",
        "schema_version": SCHEMA_VERSION,
        "test_target_sha256": build["test_target_sha256"],
        "captured_utc": captured_utc,
        "initial_context": initial_context,
        "expected_symbols": expected_symbols,
        "observed_contexts": observed_contexts,
        "capture": local_capture,
        "publication_policy": (
            "never-publish-symbols-context-values-registers-hit-order-or-text"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_first_context_consumer_trace(
        baseline_target_sha256=str(build["baseline_target_sha256"]),
        test_target_sha256=str(build["test_target_sha256"]),
        first_context_translation_test_build_sha256=sha256_file(paths["build"]),
        first_context_translation_runtime_capture_sha256=sha256_file(
            paths["runtime"]
        ),
        first_context_translation_visual_review_sha256=sha256_file(
            paths["review"]
        ),
        local_trace_sha256=sha256_file(local_path),
        captured_utc=captured_utc,
        trace=counts,
        expected_context_prefix_complete=prefix_complete,
        first_post_terminator_context_is_terminator=first_post,
        direct_terminator_overread_confirmed=direct,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR first context consumer trace: {safe_path}")
    return 0


def main() -> int:
    return _main()


if __name__ == "__main__":
    raise SystemExit(main())
