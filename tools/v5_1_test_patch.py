#!/usr/bin/env python3
"""Build an S25U-local technical Korean display test image when gates pass.

The clean Japanese ROM is always the immutable input.  The tracked v5.1 BPS is
applied in memory, a schema-v2 runtime-confirmed entry is independently checked,
and one in-place phrase replacement is planned as an Expected Write.  No output
is created unless every gate and the final diff audit passes.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile

try:
    from .analyze_v5_1 import (
        EXPECTED_SOURCE_SHA256,
        EXPECTED_SOURCE_SIZE,
    )
    from .expected_writes import (
        ExpectedWrite,
        apply_expected_writes,
        expected_writes_to_ips,
        validate_expected_writes,
    )
    from .patch_io import PatchError, apply_bps, apply_ips, sha256_bytes
    from .sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbol_count,
        decode_symbols,
        encode_symbol_count,
        encode_symbols,
        load_trees_at,
    )
    from .v5_1_consumer import verify_target_identity
    from .v5_1_decoder_register_trace import (
        validate_decoder_register_trace,
    )
    from .v5_1_decoder_stream_resolution import (
        validate_decoder_stream_resolution,
    )
    from .v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
    from .v5_1_runtime_hit_resolver import (
        _alignment_pointer,
        validate_consumer_resolution,
    )
    from .v5_1_poc_expansion import build_expanded_phrase_plan
    from .v5_1_test_phrase import (
        build_test_phrase_plan,
        build_length_preserving_test_phrase_plan,
    )
    from .v5_1_visible_entry_proof import validate_visible_entry_proof
except ImportError:  # direct script execution
    from analyze_v5_1 import EXPECTED_SOURCE_SHA256, EXPECTED_SOURCE_SIZE
    from expected_writes import (
        ExpectedWrite,
        apply_expected_writes,
        expected_writes_to_ips,
        validate_expected_writes,
    )
    from patch_io import PatchError, apply_bps, apply_ips, sha256_bytes
    from sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbol_count,
        decode_symbols,
        encode_symbol_count,
        encode_symbols,
        load_trees_at,
    )
    from v5_1_consumer import verify_target_identity
    from v5_1_decoder_register_trace import validate_decoder_register_trace
    from v5_1_decoder_stream_resolution import (
        validate_decoder_stream_resolution,
    )
    from v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
    from v5_1_runtime_hit_resolver import (
        _alignment_pointer,
        validate_consumer_resolution,
    )
    from v5_1_poc_expansion import build_expanded_phrase_plan
    from v5_1_test_phrase import (
        build_test_phrase_plan,
        build_length_preserving_test_phrase_plan,
    )
    from v5_1_visible_entry_proof import validate_visible_entry_proof


DEFAULT_PATCH = Path("patch/Final_Conflict_Japan_to_Korean_v5.1.bps")
DEFAULT_RESOLUTION = Path(
    "analysis/device/v5_1_latest_consumer_resolution.json"
)
DEFAULT_STREAM_RESOLUTION = Path(
    "analysis/device/v5_1_latest_decoder_stream_resolution.json"
)
DEFAULT_REGISTER_TRACE = Path(
    "analysis/device/v5_1_latest_decoder_register_trace.json"
)
DEFAULT_GROUP_RESOLUTION = Path(
    "analysis/evidence/v5_1_confirmed_group_capture.json"
)
DEFAULT_VISIBLE_ENTRY_PROOF = Path(
    "analysis/device/v5_1_latest_visible_entry_proof.json"
)
DEFAULT_TRACE_PLAN = Path("reports/v5_1_emucap_trace_plan.json")
DEFAULT_OUTPUT_ROM = Path("build/Final_Conflict_Korean_test_phrase.gg")
DEFAULT_OUTPUT_IPS = Path(
    "build/Final_Conflict_Korean_test_phrase_overlay.ips"
)
DEFAULT_REPORT = Path("reports/local/v5_1_test_patch_build.json")
DEFAULT_FAILURE_TOKEN = Path(
    "reports/local/v5_1_test_patch_failure_token.txt"
)
MAX_ENTRY_SYMBOLS = 256
MAX_ENTRY_BYTES = 256

TEST_PATCH_FAILURE_TOKENS = {
    "fixed-output decoder block decode failed": (
        "test-patch-fixed-count-roundtrip"
    ),
    "fixed-output decoder block re-encode failed": (
        "test-patch-fixed-count-roundtrip"
    ),
    "fixed-output decoder block no-change roundtrip is not exact": (
        "test-patch-fixed-count-roundtrip"
    ),
    "observed decoder read is outside the fixed-output block": (
        "test-patch-fixed-count-read-range"
    ),
    "fixed-output block has no marker-compatible entry": (
        "test-patch-no-marker-candidate"
    ),
    "fixed-output marker block encoding failed": (
        "test-patch-marker-encoding"
    ),
    "fixed-output marker block roundtrip mismatch": (
        "test-patch-marker-roundtrip"
    ),
}


def classify_test_patch_failure(error: PatchError) -> str:
    """Reduce a local build exception to a path-free published token."""

    return TEST_PATCH_FAILURE_TOKENS.get(str(error), "test-patch")


def _selected_resolution(
    resolution: dict[str, object],
) -> dict[str, object]:
    validate_consumer_resolution(resolution)
    if resolution["consumer_evidence_confirmed"] is not True:
        raise PatchError("runtime consumer evidence is not confirmed")
    selected_format = resolution["selected_alignment_format"]
    selected_index = resolution["selected_entry_index"]
    matches = [
        item
        for item in resolution["alignment_resolutions"]
        if item["format"] == selected_format
        and item["entry_index"] == selected_index
    ]
    if len(matches) != 1:
        raise PatchError("runtime resolution does not select exactly one entry")
    selected = matches[0]
    if (
        selected["target_file_offset"] is None
        or selected["bounded_decode"] is not True
        or selected["roundtrip_exact"] is not True
        or selected["encoded_bits"] is None
    ):
        raise PatchError("selected runtime entry lacks exact bounded roundtrip")
    return selected


def _selected_table(
    trace_plan: dict[str, object],
    selected: dict[str, object],
) -> dict[str, object]:
    cluster = trace_plan.get("selected_alignment_cluster")
    ranked = trace_plan.get("ranked_consumer_hypotheses")
    candidates = [
        item
        for collection in (cluster, ranked)
        if isinstance(collection, list)
        for item in collection
        if isinstance(item, dict)
    ]
    matches = [
        item
        for item in candidates
        if item.get("format") == selected["format"]
        and item.get("file_offset") == selected["alignment_file_offset"]
    ]
    matches = list(
        {
            (
                int(item["file_offset"]),
                int(item["end_exclusive"]),
                int(item["entries"]),
                str(item["format"]),
            ): item
            for item in matches
        }.values()
    )
    if len(matches) != 1:
        raise PatchError("trace plan does not contain one runtime-selected table")
    table = matches[0]
    entries = table.get("entries")
    end_exclusive = table.get("end_exclusive")
    if (
        not isinstance(entries, int)
        or isinstance(entries, bool)
        or entries <= 0
        or not isinstance(end_exclusive, int)
        or isinstance(end_exclusive, bool)
        or end_exclusive != int(table["file_offset"]) + entries * 3
    ):
        raise PatchError("selected table dimensions are invalid")
    if not 0 <= int(selected["entry_index"]) < entries:
        raise PatchError("selected entry index is outside the table")
    return table


def select_runtime_entry(
    baseline: bytes,
    resolution: dict[str, object],
    trace_plan: dict[str, object],
) -> dict[str, object]:
    selected = _selected_resolution(resolution)
    baseline_sha256 = sha256_bytes(baseline)
    if resolution["target_sha256"] != baseline_sha256:
        raise PatchError("runtime resolution target identity mismatch")
    if trace_plan.get("source_analysis_sha256") != baseline_sha256:
        raise PatchError("trace plan target identity mismatch")
    table = _selected_table(trace_plan, selected)
    table_start = int(table["file_offset"])
    entry_index = int(selected["entry_index"])
    pointer = _alignment_pointer(
        baseline,
        table,
        table_start + entry_index * 3,
    )
    if pointer is None:
        raise PatchError("selected table entry does not decode as a pointer")
    if pointer["target_file_offset"] != selected["target_file_offset"]:
        raise PatchError("runtime and table target offsets disagree")

    targets: list[int] = []
    for index in range(int(table["entries"])):
        candidate = _alignment_pointer(
            baseline,
            table,
            table_start + index * 3,
        )
        if (
            candidate is not None
            and candidate["target_file_offset"] is not None
        ):
            targets.append(int(candidate["target_file_offset"]))
    selected_target = int(selected["target_file_offset"])
    if targets.count(selected_target) != 1:
        raise PatchError("selected compressed target is shared or missing")
    next_targets = [target for target in targets if target > selected_target]
    return {
        "kind": "lookup-entry",
        "format": selected["format"],
        "alignment_file_offset": int(selected["alignment_file_offset"]),
        "entry_index": entry_index,
        "target_file_offset": selected_target,
        "pointer_bank": int(pointer["pointer_bank"]),
        "pointer_address": int(pointer["pointer_address"]),
        "table_entries": int(table["entries"]),
        "target_alias_count": 1,
        "next_target_file_offset": min(next_targets) if next_targets else None,
        "all_target_offsets": targets,
    }


def select_runtime_stream(
    baseline: bytes,
    resolution: dict[str, object],
) -> dict[str, object]:
    validate_decoder_stream_resolution(resolution)
    if resolution["consumer_evidence_confirmed"] is not True:
        raise PatchError("runtime decoder stream evidence is not confirmed")
    if resolution["target_sha256"] != sha256_bytes(baseline):
        raise PatchError("runtime stream target identity mismatch")
    selected_index = resolution["selected_stream_index"]
    streams = resolution["streams"]
    assert isinstance(selected_index, int) and isinstance(streams, list)
    selected = streams[selected_index]
    assert isinstance(selected, dict)
    targets = [int(item["physical_start"]) for item in streams]
    selected_target = int(selected["physical_start"])
    if targets.count(selected_target) != 1:
        raise PatchError("runtime-selected stream is shared or missing")
    return {
        "kind": "runtime-decoder-stream",
        "target_file_offset": selected_target,
        "pointer_bank": int(selected["mapped_bank"]),
        "pointer_address": int(selected["logical_start"]),
        "target_alias_count": 1,
        "next_target_file_offset": (
            None
            if selected["next_stream_start"] is None
            else int(selected["next_stream_start"])
        ),
        "runtime_instruction_bank": int(selected["instruction_bank"]),
        "runtime_instruction_pc": int(selected["instruction_pc"]),
        "runtime_operand_kind": str(selected["operand_kind"]),
        "runtime_symbol_count": int(selected["symbol_count"]),
        "runtime_encoded_bits": int(selected["encoded_bits"]),
        "all_target_offsets": targets,
    }


def select_runtime_group_entry(
    baseline: bytes,
    capture: dict[str, object],
    stream_resolution: dict[str, object],
) -> dict[str, object]:
    """Select the one bounded group entry containing the observed ROM read.

    The decoder-entry B register is retained as evidence, but it is not treated
    as an entry selector when it disagrees with the uniquely bounded entry
    containing the runtime read.  A prior experiment that interpreted B as a
    skip count never read the predicted entry start, so the direct read wins.
    """

    stream = select_runtime_stream(baseline, stream_resolution)
    if (
        capture.get("artifact_kind")
        != "sanitized-s25u-test-display-capture"
        or capture.get("schema_version") not in {4, 5}
        or capture.get("baseline_target_sha256") != sha256_bytes(baseline)
    ):
        raise PatchError("runtime group resolution identity mismatch")
    selector = capture.get("entry_selector")
    group = capture.get("group_entry")
    if (
        not isinstance(selector, dict)
        or selector.get("status") != "resolved"
        or not isinstance(group, dict)
        or group.get("prefix_roundtrip_exact") is not True
        or selector.get("baseline_entry_ordinal") != group.get("entry_ordinal")
        or selector.get("pointer_address") != group.get("group_pointer_address")
        or stream["pointer_bank"] != capture["target_read"]["expected_bank"]
    ):
        raise PatchError("runtime group resolution evidence is inconsistent")

    pointer_address = int(group["group_pointer_address"])
    observed_target_logical = int(stream["pointer_address"])
    candidates = group.get("target_byte_candidates")
    if not isinstance(candidates, list):
        candidates = []
    selected_range = group
    direct_selection = (
        group.get("status") == "resolved"
        and (
            not candidates
            or (
                group.get("observed_b_matches_target_candidates") is True
                and len(candidates) == 1
                and isinstance(candidates[0], dict)
                and int(candidates[0]["entry_ordinal"])
                == int(group["entry_ordinal"])
            )
        )
    )
    observed_entry = (
        group.get("status") == "target-outside-selected-entry"
        and group.get("observed_b_matches_target_candidates") is False
        and len(candidates) == 1
        and isinstance(candidates[0], dict)
        and int(candidates[0]["entry_ordinal"]) < int(group["entry_ordinal"])
        and int(candidates[0]["entry_end_bit_exclusive"])
        <= int(group["entry_start_bit"])
    )
    if direct_selection:
        selection_basis = "runtime-b-and-target-agree"
        kind = "runtime-group-entry"
    elif observed_entry:
        selected_range = candidates[0]
        selection_basis = "unique-runtime-read-containing-entry"
        kind = "runtime-group-observed-entry"
    else:
        raise PatchError(
            "runtime read does not distinguish one bounded group entry"
        )

    entry_start_bit = int(selected_range["entry_start_bit"])
    entry_end_bit = int(selected_range["entry_end_bit_exclusive"])
    entry_bits = int(selected_range["entry_encoded_bits"])
    entry_ordinal = int(selected_range["entry_ordinal"])
    mapped_bank = int(stream["pointer_bank"])
    if (
        not 0x4000 <= pointer_address < 0x8000
        or not 0 <= entry_ordinal <= 0xFF
        or entry_start_bit < 0
        or entry_end_bit <= entry_start_bit
        or entry_bits != entry_end_bit - entry_start_bit
    ):
        raise PatchError("runtime group entry boundaries are invalid")

    group_physical_start = (
        mapped_bank * 0x4000 + (pointer_address - 0x4000)
    )
    expected_intermediate_target = (
        group_physical_start
        + (observed_target_logical - pointer_address)
    )
    if (
        not pointer_address <= observed_target_logical < 0x8000
        or expected_intermediate_target != int(stream["target_file_offset"])
    ):
        raise PatchError("runtime stream does not belong to the resolved group")
    if direct_selection:
        if not (
            int(selected_range["entry_start_logical_byte"])
            <= observed_target_logical
            <= int(selected_range["entry_end_logical_byte_inclusive"])
        ):
            raise PatchError(
                "runtime read is outside the directly selected group entry"
            )
    else:
        if not (
            int(selected_range["entry_start_logical_byte"])
            <= observed_target_logical
            <= int(selected_range["entry_end_logical_byte_inclusive"])
        ):
            raise PatchError(
                "runtime read is not inside the uniquely bounded group entry"
            )
    target_file_offset = group_physical_start + entry_start_bit // 8
    target_logical_address = pointer_address + entry_start_bit // 8
    if (
        target_file_offset < 0
        or target_file_offset >= len(baseline)
        or target_logical_address
        != int(selected_range["entry_start_logical_byte"])
        or pointer_address
        + (entry_end_bit - 1) // 8
        != int(selected_range["entry_end_logical_byte_inclusive"])
    ):
        raise PatchError("runtime group entry byte boundaries disagree")

    return {
        "kind": kind,
        "selection_basis": selection_basis,
        "target_file_offset": target_file_offset,
        "pointer_bank": mapped_bank,
        "pointer_address": target_logical_address,
        "group_pointer_address": pointer_address,
        "group_physical_start": group_physical_start,
        "group_entry_ordinal": entry_ordinal,
        "decoder_entry_b_ordinal": int(group["entry_ordinal"]),
        "group_entry_start_bit": entry_start_bit,
        "group_entry_end_bit_exclusive": entry_end_bit,
        "group_entry_start_bit_in_byte": entry_start_bit & 7,
        "target_alias_count": 1,
        "next_target_file_offset": None,
        "runtime_instruction_bank": int(stream["runtime_instruction_bank"]),
        "runtime_instruction_pc": int(stream["runtime_instruction_pc"]),
        "runtime_operand_kind": str(stream["runtime_operand_kind"]),
        "runtime_symbol_count": int(selected_range["entry_symbol_count"]),
        "runtime_encoded_bits": entry_bits,
        "intermediate_observed_target_file_offset": int(
            stream["target_file_offset"]
        ),
        "intermediate_observed_target_logical_address": (
            observed_target_logical
        ),
        "all_target_offsets": [target_file_offset],
    }


def select_runtime_decode_block(
    baseline: bytes,
    capture: dict[str, object],
    stream_resolution: dict[str, object],
) -> dict[str, object]:
    """Select the fixed-output block proven by the decoder prologue and reads.

    The patched prologue loads a group pointer from ``0x3FE8 + DE`` and
    increments B before entering the decoder.  B is therefore tested as an
    output-count-minus-one hypothesis, not as a string ordinal.  The later
    no-change fixed-count roundtrip and observed interior read must both agree
    before a test write is allowed.
    """

    stream = select_runtime_stream(baseline, stream_resolution)
    if (
        capture.get("artifact_kind")
        != "sanitized-s25u-test-display-capture"
        or capture.get("schema_version") not in {4, 5}
        or capture.get("baseline_target_sha256") != sha256_bytes(baseline)
    ):
        raise PatchError("runtime decode-block identity mismatch")
    selector = capture.get("entry_selector")
    target_read = capture.get("target_read")
    if (
        not isinstance(selector, dict)
        or selector.get("status") != "resolved"
        or selector.get("selectors_match") is not True
        or selector.get("ordinals_match") is not True
        or not isinstance(target_read, dict)
        or target_read.get("confirmed") is not True
    ):
        raise PatchError("runtime decode-block selector evidence is incomplete")

    pointer_address = int(selector["pointer_address"])
    next_pointer_address = int(selector["next_pointer_address"])
    b_before_increment = int(selector["baseline_entry_ordinal"])
    mapped_bank = int(stream["pointer_bank"])
    observed_target_logical = int(stream["pointer_address"])
    if (
        selector.get("test_entry_ordinal") != b_before_increment
        or not 0 <= b_before_increment <= 0xFF
        or not 0x4000 <= pointer_address < next_pointer_address <= 0x8000
        or not pointer_address <= observed_target_logical < next_pointer_address
        or int(target_read["expected_bank"]) != mapped_bank
    ):
        raise PatchError("runtime decode-block pointer/count evidence disagrees")

    group_physical_start = (
        mapped_bank * 0x4000 + (pointer_address - 0x4000)
    )
    next_group_physical_start = (
        mapped_bank * 0x4000 + (next_pointer_address - 0x4000)
    )
    expected_observed_target = (
        group_physical_start + observed_target_logical - pointer_address
    )
    if (
        expected_observed_target != int(stream["target_file_offset"])
        or not 0 <= group_physical_start < next_group_physical_start <= len(baseline)
    ):
        raise PatchError("runtime decode-block physical mapping disagrees")

    return {
        "kind": "runtime-decoder-block",
        "selection_basis": "decoder-prologue-pointer-and-fixed-output-count",
        "target_file_offset": group_physical_start,
        "pointer_bank": mapped_bank,
        "pointer_address": pointer_address,
        "group_pointer_address": pointer_address,
        "next_pointer_address": next_pointer_address,
        "group_physical_start": group_physical_start,
        "next_group_physical_start": next_group_physical_start,
        "decoder_entry_b_before_increment": b_before_increment,
        "runtime_symbol_count": b_before_increment + 1,
        "target_alias_count": 1,
        "next_target_file_offset": next_group_physical_start,
        "runtime_instruction_bank": int(stream["runtime_instruction_bank"]),
        "runtime_instruction_pc": int(stream["runtime_instruction_pc"]),
        "runtime_operand_kind": str(stream["runtime_operand_kind"]),
        "intermediate_observed_target_file_offset": int(
            stream["target_file_offset"]
        ),
        "intermediate_observed_target_logical_address": (
            observed_target_logical
        ),
        "all_target_offsets": [group_physical_start],
    }


def select_runtime_length_prefixed_entry(
    baseline: bytes,
    capture: dict[str, object],
    register_trace: dict[str, object],
) -> dict[str, object]:
    """Resolve B as a count of byte-length-prefixed records to skip."""

    validate_decoder_register_trace(register_trace)
    if (
        capture.get("baseline_target_sha256") != sha256_bytes(baseline)
        or register_trace.get("target_sha256") != sha256_bytes(baseline)
    ):
        raise PatchError("runtime length-table identity mismatch")
    selector = capture.get("entry_selector")
    target_read = capture.get("target_read")
    if (
        not isinstance(selector, dict)
        or selector.get("status") != "resolved"
        or selector.get("selectors_match") is not True
        or selector.get("ordinals_match") is not True
        or not isinstance(target_read, dict)
        or target_read.get("confirmed") is not True
    ):
        raise PatchError("runtime length-table selector evidence is incomplete")

    states = register_trace["states"]
    assert isinstance(states, list)
    expected_pcs = (
        0x33FA,
        0x33FD,
        0x33FE,
        0x33FF,
        0x3400,
        0x3401,
        0x3402,
        0x3403,
        0x3409,
        0x3406,
        0x3407,
        0x3408,
        0x3409,
        0x3406,
    )
    if len(states) < len(expected_pcs) or tuple(
        int(state["pc"]) for state in states[: len(expected_pcs)]
    ) != expected_pcs:
        raise PatchError("runtime length-table control flow is incomplete")

    entry = states[0]
    group_pointer_state = states[6]
    incremented_state = states[7]
    first_loop_state = states[9]
    first_length_state = states[10]
    first_increment_state = states[11]
    first_advance_state = states[12]
    second_loop_state = states[13]
    bc = int(entry["bc"])
    skip_count = bc >> 8
    selector_offset = bc & 0xFF
    pointer_address = int(selector["pointer_address"])
    first_length = int(first_length_state["de"]) & 0xFF
    if (
        int(entry["de"]) != selector_offset
        or selector_offset != int(selector["baseline_selector_offset"])
        or int(group_pointer_state["hl"]) != pointer_address
        or (int(incremented_state["bc"]) >> 8) != skip_count + 1
        or (int(first_loop_state["bc"]) >> 8) != skip_count
        or int(first_increment_state["hl"]) != pointer_address + 1
        or int(first_advance_state["hl"])
        != pointer_address + 1 + first_length
        or (int(second_loop_state["bc"]) >> 8) != skip_count - 1
    ):
        raise PatchError("runtime length-table register semantics disagree")

    mapped_bank = int(target_read["expected_bank"])
    group_physical_start = (
        mapped_bank * 0x4000 + (pointer_address - 0x4000)
    )
    cursor = group_physical_start
    record_offsets: list[int] = []
    for _ in range(skip_count):
        if not 0 <= cursor < len(baseline):
            raise PatchError("runtime length-table record is outside the ROM")
        record_offsets.append(cursor)
        length = baseline[cursor]
        cursor += 1 + length
    post_skip_state = register_trace["post_skip_state"]
    assert isinstance(post_skip_state, dict)
    expected_post_skip_logical = (
        pointer_address + (cursor - group_physical_start)
    )
    if (
        int(post_skip_state["pc"]) != 0x340B
        or (int(post_skip_state["bc"]) >> 8) != 0
        or int(post_skip_state["hl"]) != expected_post_skip_logical
    ):
        raise PatchError("runtime skip-loop endpoint disagrees")
    if (
        baseline[group_physical_start] != first_length
        or not 0 <= cursor < len(baseline)
    ):
        raise PatchError("runtime length-table static bytes disagree")
    record_length = baseline[cursor]
    payload_start = cursor + 1
    payload_end = payload_start + record_length
    if (
        record_length <= 0
        or payload_end > len(baseline)
        or payload_end > (mapped_bank + 1) * 0x4000
    ):
        raise PatchError("runtime selected record boundary is invalid")
    payload_logical = 0x4000 + (payload_start & 0x3FFF)
    return {
        "kind": "runtime-length-prefixed-entry",
        "selection_basis": "decoder-register-proven-length-prefixed-skip-loop",
        "target_file_offset": payload_start,
        "pointer_bank": mapped_bank,
        "pointer_address": payload_logical,
        "group_pointer_address": pointer_address,
        "group_physical_start": group_physical_start,
        "length_prefix_file_offset": cursor,
        "length_prefix_logical_address": payload_logical - 1,
        "record_length_bytes": record_length,
        "skipped_record_count": skip_count,
        "target_alias_count": 1,
        "next_target_file_offset": payload_end,
        "runtime_instruction_bank": 0,
        "runtime_instruction_pc": -1,
        "runtime_operand_kind": "hl-indirect",
        "all_target_offsets": [payload_start],
    }


def mark_all_count_preserving_entries(
    symbols: list[int],
    marker_symbols: list[int],
    *,
    end_symbol: int = CANDIDATE_END_SYMBOL,
) -> tuple[list[int], list[int]]:
    """Replace every compatible terminated entry without moving its offsets.

    A compatible entry has room for the six-symbol marker and any remaining
    symbols can be filled with complete, non-drawing page-select triplets.
    Entry lengths and terminator positions stay unchanged, so every decoded
    offset in the fixed-size output block is preserved.
    """

    if (
        len(marker_symbols) < 4
        or marker_symbols[-1] != end_symbol
        or len(marker_symbols[:3]) != 3
    ):
        raise PatchError("technical marker sequence is invalid")
    result = list(symbols)
    modified: list[int] = []
    start = 0
    entry_index = 0
    for index, symbol in enumerate(symbols):
        if symbol != end_symbol:
            continue
        length = index - start + 1
        padding = length - len(marker_symbols)
        if padding >= 0 and padding % 3 == 0:
            replacement = marker_symbols[:3] * (padding // 3) + marker_symbols
            if len(replacement) != length:
                raise AssertionError("count-preserving marker length mismatch")
            result[start : index + 1] = replacement
            modified.append(entry_index)
        start = index + 1
        entry_index += 1
    if not modified:
        raise PatchError("fixed-output block has no marker-compatible entry")
    return result, modified


def _bits_equal(left: bytes, right: bytes, bits: int) -> bool:
    return all(
        ((left[index >> 3] >> (7 - (index & 7))) & 1)
        == ((right[index >> 3] >> (7 - (index & 7))) & 1)
        for index in range(bits)
    )


def _check_nearby_preceding_entries(
    baseline: bytes,
    trees: dict[int, object],
    selected_target: int,
    target_offsets: list[int],
) -> None:
    known = bytes((1,)) * len(baseline)
    nearby = sorted(
        {
            target
            for target in target_offsets
            if 0 < selected_target - target < MAX_ENTRY_BYTES
        }
    )
    for target in nearby:
        try:
            _, bits = decode_symbols(
                baseline,
                known,
                trees,
                target,
                initial_symbol=CANDIDATE_END_SYMBOL,
                end_symbol=CANDIDATE_END_SYMBOL,
                max_symbols=MAX_ENTRY_SYMBOLS,
                max_bytes=MAX_ENTRY_BYTES,
            )
        except PatchError as error:
            raise PatchError(
                "nearby preceding entry cannot prove non-overlap"
            ) from error
        if target + (bits + 7) // 8 > selected_target:
            raise PatchError("selected target overlaps a preceding entry")


def plan_in_place_write(
    baseline: bytes,
    *,
    target_offset: int,
    original_bits: int,
    replacement: bytes,
    replacement_bits: int,
    next_target_offset: int | None,
) -> ExpectedWrite:
    if original_bits <= 0 or replacement_bits <= 0:
        raise PatchError("entry bit lengths must be positive")
    if replacement_bits > original_bits:
        raise PatchError("test phrase exceeds the verified in-place bit budget")
    original_end = target_offset + (original_bits + 7) // 8
    replacement_end = target_offset + len(replacement)
    allowed_end = (
        original_end
        if next_target_offset is None
        else min(original_end, next_target_offset)
    )
    if replacement_end > allowed_end:
        raise PatchError("test phrase exceeds the verified byte boundary")
    return ExpectedWrite(
        writer="v5_1_test_phrase",
        purpose="replace one runtime-confirmed compressed entry in place",
        offset=target_offset,
        before=baseline[target_offset:replacement_end],
        after=replacement,
        allowed_start=target_offset,
        allowed_end_exclusive=allowed_end,
    )


def plan_unpadded_entry_prefix_write(
    baseline: bytes,
    *,
    group_physical_start: int,
    entry_start_bit: int,
    original_bits: int,
    replacement: bytes,
    replacement_bits: int,
) -> ExpectedWrite:
    """Replace a selected entry prefix at its exact non-byte-aligned bit."""

    if original_bits <= 0 or replacement_bits <= 0:
        raise PatchError("entry bit lengths must be positive")
    if replacement_bits > original_bits:
        raise PatchError("test phrase exceeds the verified group entry budget")
    if len(replacement) * 8 < replacement_bits:
        raise PatchError("replacement byte string is shorter than its bit count")
    absolute_start_bit = group_physical_start * 8 + entry_start_bit
    absolute_end_bit = absolute_start_bit + replacement_bits
    write_start = absolute_start_bit // 8
    write_end = (absolute_end_bit + 7) // 8
    if (
        group_physical_start < 0
        or entry_start_bit < 0
        or write_start < 0
        or write_end > len(baseline)
    ):
        raise PatchError("group entry prefix write is outside the ROM")
    after = bytearray(baseline[write_start:write_end])
    bit_offset = absolute_start_bit - write_start * 8
    for index in range(replacement_bits):
        value = (replacement[index >> 3] >> (7 - (index & 7))) & 1
        target_index = bit_offset + index
        byte_index = target_index >> 3
        mask = 1 << (7 - (target_index & 7))
        if value:
            after[byte_index] |= mask
        else:
            after[byte_index] &= ~mask
    return ExpectedWrite(
        writer="v5_1_test_phrase",
        purpose=(
            "replace the exact bit-aligned prefix of one runtime-selected "
            "continuous Huffman entry"
        ),
        offset=write_start,
        before=baseline[write_start:write_end],
        after=bytes(after),
        allowed_start=write_start,
        allowed_end_exclusive=write_end,
    )


def build_test_patch(
    source: bytes,
    patch: bytes,
    resolution: dict[str, object],
    trace_plan: dict[str, object],
    *,
    stream_resolution: dict[str, object] | None = None,
    group_resolution: dict[str, object] | None = None,
    register_trace: dict[str, object] | None = None,
    visible_entry_proof: dict[str, object] | None = None,
) -> tuple[bytes, bytes, dict[str, object]]:
    if (
        len(source) != EXPECTED_SOURCE_SIZE
        or sha256_bytes(source) != EXPECTED_SOURCE_SHA256
    ):
        raise PatchError("clean Japanese source ROM identity mismatch")

    baseline = apply_bps(source, patch)
    verify_target_identity(baseline)
    runtime_entry = (
        select_runtime_length_prefixed_entry(
            baseline,
            group_resolution,
            register_trace,
        )
        if group_resolution is not None and register_trace is not None
        else (
            select_runtime_stream(baseline, stream_resolution)
            if stream_resolution is not None
            else select_runtime_entry(
            baseline,
            resolution,
            trace_plan,
        )
        )
    )

    known = bytes((1,)) * len(baseline)
    trees = load_trees_at(
        baseline,
        known,
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )
    target_offset = int(runtime_entry["target_file_offset"])
    if runtime_entry["kind"] == "runtime-length-prefixed-entry":
        record_length = int(runtime_entry["record_length_bytes"])
        original_symbols, original_bits = decode_symbols(
            baseline,
            known,
            trees,
            target_offset,
            initial_symbol=CANDIDATE_END_SYMBOL,
            end_symbol=CANDIDATE_END_SYMBOL,
            max_symbols=MAX_ENTRY_SYMBOLS,
            max_bytes=record_length,
        )
        original_encoded, reencoded_bits = encode_symbols(
            trees,
            original_symbols,
            initial_symbol=CANDIDATE_END_SYMBOL,
            end_symbol=CANDIDATE_END_SYMBOL,
            max_bits=record_length * 8,
        )
        if reencoded_bits != original_bits or not _bits_equal(
            baseline[target_offset:],
            original_encoded,
            original_bits,
        ):
            raise PatchError(
                "length-prefixed entry no-change roundtrip is not exact"
            )
        runtime_entry["runtime_symbol_count"] = len(original_symbols)
        runtime_entry["runtime_encoded_bits"] = original_bits
    elif runtime_entry["kind"] == "runtime-decoder-block":
        block_capacity_bytes = (
            int(runtime_entry["next_group_physical_start"]) - target_offset
        )
        try:
            original_symbols, original_bits = decode_symbol_count(
                baseline,
                known,
                trees,
                target_offset,
                int(runtime_entry["runtime_symbol_count"]),
                initial_symbol=CANDIDATE_END_SYMBOL,
                max_bytes=block_capacity_bytes,
            )
        except PatchError as error:
            raise PatchError(
                "fixed-output decoder block decode failed"
            ) from error
        try:
            original_encoded, reencoded_bits = encode_symbol_count(
                trees,
                original_symbols,
                initial_symbol=CANDIDATE_END_SYMBOL,
                max_bits=block_capacity_bytes * 8,
            )
        except PatchError as error:
            raise PatchError(
                "fixed-output decoder block re-encode failed"
            ) from error
        if reencoded_bits != original_bits or not _bits_equal(
            baseline[target_offset:],
            original_encoded,
            original_bits,
        ):
            raise PatchError(
                "fixed-output decoder block no-change roundtrip is not exact"
            )
        observed_target = int(
            runtime_entry["intermediate_observed_target_file_offset"]
        )
        if not (
            target_offset
            <= observed_target
            < target_offset + (original_bits + 7) // 8
        ):
            raise PatchError(
                "observed decoder read is outside the fixed-output block"
            )

        phrase_plan = build_test_phrase_plan(patch)
        encoding = phrase_plan["encoding"]
        assert isinstance(encoding, dict)
        marker_symbols = [int(value) for value in encoding["symbols"]]
        replacement_symbols, modified_entries = (
            mark_all_count_preserving_entries(
                original_symbols,
                marker_symbols,
            )
        )
        try:
            replacement, replacement_bits = encode_symbol_count(
                trees,
                replacement_symbols,
                initial_symbol=CANDIDATE_END_SYMBOL,
                max_bits=block_capacity_bytes * 8,
            )
        except PatchError as error:
            raise PatchError(
                "fixed-output marker block encoding failed"
            ) from error
        decoded_replacement, decoded_replacement_bits = decode_symbol_count(
            replacement,
            bytes((1,)) * len(replacement),
            trees,
            0,
            len(replacement_symbols),
            initial_symbol=CANDIDATE_END_SYMBOL,
            max_bytes=len(replacement),
        )
        if (
            decoded_replacement != replacement_symbols
            or decoded_replacement_bits != replacement_bits
        ):
            raise PatchError("fixed-output marker block roundtrip mismatch")
        runtime_entry["runtime_encoded_bits"] = original_bits
        runtime_entry["replacement_encoded_bits"] = replacement_bits
        runtime_entry["modified_terminated_entry_count"] = len(
            modified_entries
        )
        runtime_entry["modified_terminated_entry_indexes"] = modified_entries
        expected_write = plan_unpadded_entry_prefix_write(
            baseline,
            group_physical_start=target_offset,
            entry_start_bit=0,
            original_bits=block_capacity_bytes * 8,
            replacement=replacement,
            replacement_bits=replacement_bits,
        )
    elif str(runtime_entry["kind"]).startswith("runtime-group-"):
        original_symbols = [None] * int(runtime_entry["runtime_symbol_count"])
        original_bits = int(runtime_entry["runtime_encoded_bits"])
    else:
        original_symbols, original_bits = decode_symbols(
            baseline,
            known,
            trees,
            target_offset,
            initial_symbol=CANDIDATE_END_SYMBOL,
            end_symbol=CANDIDATE_END_SYMBOL,
            max_symbols=MAX_ENTRY_SYMBOLS,
            max_bytes=MAX_ENTRY_BYTES,
        )
        original_encoded, reencoded_bits = encode_symbols(
            trees,
            original_symbols,
            initial_symbol=CANDIDATE_END_SYMBOL,
            end_symbol=CANDIDATE_END_SYMBOL,
            max_bits=MAX_ENTRY_BYTES * 8,
        )
        if reencoded_bits != original_bits or not _bits_equal(
            baseline[target_offset:],
            original_encoded,
            original_bits,
        ):
            raise PatchError("selected entry no-change roundtrip is not exact")

        _check_nearby_preceding_entries(
            baseline,
            trees,
            target_offset,
            list(runtime_entry["all_target_offsets"]),
        )
    if (
        runtime_entry["kind"] != "runtime-decoder-block"
        and original_bits != int(runtime_entry["runtime_encoded_bits"])
    ):
        raise PatchError("runtime and rebuilt entry bit lengths disagree")
    if runtime_entry["kind"] != "runtime-decoder-block":
        if visible_entry_proof is not None:
            validate_visible_entry_proof(visible_entry_proof)
            proof_entry = visible_entry_proof["runtime_entry"]
            assert isinstance(proof_entry, dict)
            if (
                runtime_entry["kind"] != "runtime-length-prefixed-entry"
                or visible_entry_proof["baseline_target_sha256"]
                != sha256_bytes(baseline)
                or proof_entry["physical_start"] != target_offset
                or proof_entry["logical_start"]
                != runtime_entry["pointer_address"]
                or proof_entry["mapped_bank"] != runtime_entry["pointer_bank"]
                or proof_entry["record_length_bytes"]
                != runtime_entry["record_length_bytes"]
                or proof_entry["encoded_bits"] != original_bits
            ):
                raise PatchError(
                    "visible entry proof and rebuilt runtime entry disagree"
                )
            phrase_plan = build_expanded_phrase_plan(
                patch,
                original_bits,
                visible_entry_proof,
            )
        else:
            phrase_plan = build_length_preserving_test_phrase_plan(
                patch,
                original_bits,
            )
        encoding = phrase_plan["encoding"]
        assert isinstance(encoding, dict)
        replacement = bytes.fromhex(str(encoding["encoded_hex"]))
        replacement_bits = int(encoding["encoded_bits"])
        expected_write = plan_unpadded_entry_prefix_write(
            baseline,
            group_physical_start=(
                int(runtime_entry["group_physical_start"])
                if str(runtime_entry["kind"]).startswith("runtime-group-")
                else target_offset
            ),
            entry_start_bit=(
                int(runtime_entry["group_entry_start_bit"])
                if str(runtime_entry["kind"]).startswith("runtime-group-")
                else 0
            ),
            original_bits=original_bits,
            replacement=replacement,
            replacement_bits=replacement_bits,
        )
    validated = validate_expected_writes(baseline, [expected_write])
    target, audit = apply_expected_writes(baseline, validated)
    overlay = expected_writes_to_ips(validated)
    if apply_ips(baseline, overlay) != target:
        raise PatchError("IPS overlay does not reproduce the audited test image")

    report = {
        "artifact_kind": "s25u-local-korean-test-patch-build",
        "schema_version": 1,
        "status": "technical-poc-built-needs-runtime-display-proof",
        "purpose": phrase_plan["purpose"],
        "phrase": phrase_plan["phrase"],
        "source_sha256": sha256_bytes(source),
        "baseline_target_sha256": sha256_bytes(baseline),
        "test_target_sha256": sha256_bytes(target),
        "runtime_entry": {
            key: value
            for key, value in runtime_entry.items()
            if key != "all_target_offsets"
        },
        "original_entry": {
            "encoded_bits": original_bits,
            "encoded_bytes": (original_bits + 7) // 8,
            "roundtrip_exact": True,
            "symbol_count": len(original_symbols),
            "terminator_count": original_symbols.count(
                CANDIDATE_END_SYMBOL
            ),
        },
        "replacement": {
            "encoded_bits": replacement_bits,
            "encoded_bytes": len(replacement),
            "encoded_sha256": sha256_bytes(replacement),
            "bit_start_in_first_byte": (
                int(runtime_entry["group_entry_start_bit_in_byte"])
                if str(runtime_entry["kind"]).startswith("runtime-group-")
                else 0
            ),
            "technical_tail_policy": (
                "preserve-unread-tail-within-next-pointer-extent"
                if runtime_entry["kind"] == "runtime-decoder-block"
                else "exact-entry-length"
            ),
        },
        "expected_write_audit": audit,
        "overlay": {
            "format": "IPS",
            "size": len(overlay),
            "sha256": sha256_bytes(overlay),
            "applies_to_sha256": sha256_bytes(baseline),
            "result_sha256": sha256_bytes(target),
        },
        "header_checksum_write": "not-planned-unproven-consumer",
        "translation_build_eligible": False,
        "next_checkpoint": "cold-boot-and-confirm-korean-glyphs-on-screen",
    }
    return target, overlay, report


def _absolute(root: Path, path: Path) -> Path:
    candidate = path if path.is_absolute() else root / path
    return candidate.resolve()


def _require_within(path: Path, parent: Path, label: str) -> None:
    try:
        path.relative_to(parent.resolve())
    except ValueError as error:
        raise PatchError(f"{label} must stay under {parent}") from error


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PatchError(f"{path.name} must contain a JSON object")
    return value


def _write_outputs(
    output_rom: Path,
    output_ips: Path,
    report_path: Path,
    target: bytes,
    overlay: bytes,
    report: dict[str, object],
) -> None:
    destinations = (output_rom, output_ips, report_path)
    if len({path.resolve() for path in destinations}) != len(destinations):
        raise PatchError("test output paths must be distinct")
    for destination in destinations:
        destination.parent.mkdir(parents=True, exist_ok=True)
    common_parent = output_rom.parent
    with tempfile.TemporaryDirectory(
        prefix=".sfkr-test-build-",
        dir=common_parent,
    ) as temporary:
        temporary_root = Path(temporary)
        staged_rom = temporary_root / "test.gg"
        staged_ips = temporary_root / "overlay.ips"
        staged_report = temporary_root / "report.json"
        staged_rom.write_bytes(target)
        staged_ips.write_bytes(overlay)
        staged_report.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if sha256_bytes(staged_rom.read_bytes()) != report["test_target_sha256"]:
            raise PatchError("staged test ROM identity mismatch")
        if sha256_bytes(staged_ips.read_bytes()) != report["overlay"]["sha256"]:
            raise PatchError("staged IPS identity mismatch")
        os.replace(staged_rom, output_rom)
        os.replace(staged_ips, output_ips)
        os.replace(staged_report, report_path)


def _write_failure_token(path: Path, token: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(token + "\n", encoding="ascii")
    os.replace(temporary, path)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-rom", type=Path, required=True)
    parser.add_argument("--patch", type=Path, default=DEFAULT_PATCH)
    parser.add_argument("--resolution", type=Path, default=DEFAULT_RESOLUTION)
    parser.add_argument(
        "--stream-resolution",
        type=Path,
        default=DEFAULT_STREAM_RESOLUTION,
    )
    parser.add_argument(
        "--register-trace",
        type=Path,
        default=DEFAULT_REGISTER_TRACE,
    )
    parser.add_argument(
        "--group-resolution",
        type=Path,
        default=DEFAULT_GROUP_RESOLUTION,
    )
    parser.add_argument(
        "--visible-entry-proof",
        type=Path,
        default=DEFAULT_VISIBLE_ENTRY_PROOF,
    )
    parser.add_argument("--trace-plan", type=Path, default=DEFAULT_TRACE_PLAN)
    parser.add_argument("--output-rom", type=Path, default=DEFAULT_OUTPUT_ROM)
    parser.add_argument("--output-ips", type=Path, default=DEFAULT_OUTPUT_IPS)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument(
        "--failure-token",
        type=Path,
        default=DEFAULT_FAILURE_TOKEN,
    )
    parser.add_argument(
        "--if-ready",
        action="store_true",
        help="return success without outputs when runtime evidence is absent",
    )
    args = parser.parse_args()

    resolution_path = _absolute(root, args.resolution)
    stream_resolution_path = _absolute(root, args.stream_resolution)
    register_trace_path = _absolute(root, args.register_trace)
    group_resolution_path = _absolute(root, args.group_resolution)
    visible_entry_proof_path = _absolute(root, args.visible_entry_proof)
    stream_resolution: dict[str, object] | None = None
    register_trace: dict[str, object] | None = None
    group_resolution: dict[str, object] | None = None
    visible_entry_proof: dict[str, object] | None = None
    if stream_resolution_path.exists():
        candidate = _read_json(stream_resolution_path)
        validate_decoder_stream_resolution(candidate)
        if candidate["consumer_evidence_confirmed"] is True:
            stream_resolution = candidate
    if register_trace_path.exists():
        candidate = _read_json(register_trace_path)
        validate_decoder_register_trace(candidate)
        if int(candidate["step_count"]) >= 13:
            register_trace = candidate
    if group_resolution_path.exists():
        candidate = _read_json(group_resolution_path)
        if (
            candidate.get("artifact_kind")
            == "sanitized-s25u-test-display-capture"
            and candidate.get("schema_version") in {4, 5}
            and isinstance(candidate.get("group_entry"), dict)
            and candidate["group_entry"].get("status")
            in {"resolved", "target-outside-selected-entry"}
            and candidate["group_entry"].get("prefix_roundtrip_exact") is True
        ):
            group_resolution = candidate
    if visible_entry_proof_path.exists():
        candidate = _read_json(visible_entry_proof_path)
        validate_visible_entry_proof(candidate)
        if candidate["status"] == "exact-visible-entry-confirmed":
            visible_entry_proof = candidate
    if stream_resolution is None and not resolution_path.exists():
        if args.if_ready:
            print("Test patch not built: runtime consumer resolution is absent.")
            return 0
        raise SystemExit("runtime consumer resolution is absent")
    resolution = (
        _read_json(resolution_path)
        if resolution_path.exists()
        else {}
    )
    if stream_resolution is None:
        validate_consumer_resolution(resolution)
    if (
        stream_resolution is None
        and resolution["consumer_evidence_confirmed"] is not True
    ):
        if args.if_ready:
            print("Test patch not built: runtime consumer evidence is ambiguous.")
            return 0
        raise SystemExit("runtime consumer evidence is ambiguous")

    source_path = _absolute(root, args.source_rom)
    output_rom = _absolute(root, args.output_rom)
    output_ips = _absolute(root, args.output_ips)
    report_path = _absolute(root, args.report)
    failure_token_path = _absolute(root, args.failure_token)
    _require_within(
        failure_token_path,
        root / "reports" / "local",
        "failure token",
    )
    failure_token_path.unlink(missing_ok=True)
    if source_path in {output_rom, output_ips, report_path}:
        raise SystemExit("refusing to overwrite the clean source ROM")
    _require_within(output_rom, root / "build", "test ROM output")
    _require_within(output_ips, root / "build", "IPS output")
    _require_within(report_path, root / "reports" / "local", "build report")

    try:
        target, overlay, report = build_test_patch(
            source_path.read_bytes(),
            _absolute(root, args.patch).read_bytes(),
            resolution,
            _read_json(_absolute(root, args.trace_plan)),
            stream_resolution=stream_resolution,
            group_resolution=group_resolution,
            register_trace=register_trace,
            visible_entry_proof=visible_entry_proof,
        )
        _write_outputs(
            output_rom,
            output_ips,
            report_path,
            target,
            overlay,
            report,
        )
    except PatchError as error:
        token = classify_test_patch_failure(error)
        _write_failure_token(failure_token_path, token)
        print(f"Test patch blocked: {token}.")
        return 1
    print(f"Built S25U-local test ROM: {output_rom}")
    print(f"Built S25U-local IPS overlay: {output_ips}")
    print(f"Build report: {report_path}")
    print("The technical PoC still requires cold-boot screen verification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
