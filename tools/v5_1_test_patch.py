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
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from .v5_1_consumer import verify_target_identity
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
    from .v5_1_test_phrase import (
        build_length_preserving_test_phrase_plan,
        build_test_phrase_plan,
    )
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
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from v5_1_consumer import verify_target_identity
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
    from v5_1_test_phrase import (
        build_length_preserving_test_phrase_plan,
        build_test_phrase_plan,
    )


DEFAULT_PATCH = Path("patch/Final_Conflict_Japan_to_Korean_v5.1.bps")
DEFAULT_RESOLUTION = Path(
    "analysis/device/v5_1_latest_consumer_resolution.json"
)
DEFAULT_STREAM_RESOLUTION = Path(
    "analysis/device/v5_1_latest_decoder_stream_resolution.json"
)
DEFAULT_GROUP_RESOLUTION = Path(
    "analysis/device/v5_1_latest_display_capture.json"
)
DEFAULT_TRACE_PLAN = Path("reports/v5_1_emucap_trace_plan.json")
DEFAULT_OUTPUT_ROM = Path("build/Final_Conflict_Korean_test_phrase.gg")
DEFAULT_OUTPUT_IPS = Path(
    "build/Final_Conflict_Korean_test_phrase_overlay.ips"
)
DEFAULT_REPORT = Path("reports/local/v5_1_test_patch_build.json")
MAX_ENTRY_SYMBOLS = 256
MAX_ENTRY_BYTES = 256


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
    """Select the unique unpadded entry containing the observed stream read."""

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
    if isinstance(candidates, list):
        if (
            len(candidates) != 1
            or not isinstance(candidates[0], dict)
            or int(group["target_logical_byte"]) != observed_target_logical
        ):
            raise PatchError(
                "runtime target read does not select one group entry"
            )
        selected_range = candidates[0]
        selection_basis = "unique-runtime-target-byte-candidate"
        kind = "runtime-group-target-candidate"
    else:
        selected_range = group
        selection_basis = "legacy-b-selected-entry"
        kind = "runtime-group-entry"

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
        not pointer_address
        <= observed_target_logical
        <= int(selected_range["entry_end_logical_byte_inclusive"])
        or expected_intermediate_target != int(stream["target_file_offset"])
    ):
        raise PatchError("runtime stream does not belong to the resolved group")
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
) -> tuple[bytes, bytes, dict[str, object]]:
    if (
        len(source) != EXPECTED_SOURCE_SIZE
        or sha256_bytes(source) != EXPECTED_SOURCE_SHA256
    ):
        raise PatchError("clean Japanese source ROM identity mismatch")

    baseline = apply_bps(source, patch)
    verify_target_identity(baseline)
    runtime_entry = (
        select_runtime_group_entry(
            baseline,
            group_resolution,
            stream_resolution,
        )
        if group_resolution is not None and stream_resolution is not None
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
    if str(runtime_entry["kind"]).startswith("runtime-group-"):
        original_symbols = [None] * int(runtime_entry["runtime_symbol_count"])
        original_bits = int(runtime_entry["runtime_encoded_bits"])
        phrase_plan = build_length_preserving_test_phrase_plan(
            patch,
            original_bits,
        )
    else:
        phrase_plan = build_test_phrase_plan(patch)
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
    encoding = phrase_plan["encoding"]
    assert isinstance(encoding, dict)
    replacement = bytes.fromhex(str(encoding["encoded_hex"]))
    replacement_bits = int(encoding["encoded_bits"])
    expected_write = (
        plan_unpadded_entry_prefix_write(
            baseline,
            group_physical_start=int(
                runtime_entry["group_physical_start"]
            ),
            entry_start_bit=int(runtime_entry["group_entry_start_bit"]),
            original_bits=original_bits,
            replacement=replacement,
            replacement_bits=replacement_bits,
        )
        if str(runtime_entry["kind"]).startswith("runtime-group-")
        else plan_in_place_write(
            baseline,
            target_offset=target_offset,
            original_bits=original_bits,
            replacement=replacement,
            replacement_bits=replacement_bits,
            next_target_offset=(
                None
                if runtime_entry["next_target_file_offset"] is None
                else int(runtime_entry["next_target_file_offset"])
            ),
        )
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
                "exact-entry-length"
                if str(runtime_entry["kind"]).startswith("runtime-group-")
                else "byte-aligned-entry"
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
        "--group-resolution",
        type=Path,
        default=DEFAULT_GROUP_RESOLUTION,
    )
    parser.add_argument("--trace-plan", type=Path, default=DEFAULT_TRACE_PLAN)
    parser.add_argument("--output-rom", type=Path, default=DEFAULT_OUTPUT_ROM)
    parser.add_argument("--output-ips", type=Path, default=DEFAULT_OUTPUT_IPS)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument(
        "--if-ready",
        action="store_true",
        help="return success without outputs when runtime evidence is absent",
    )
    args = parser.parse_args()

    resolution_path = _absolute(root, args.resolution)
    stream_resolution_path = _absolute(root, args.stream_resolution)
    group_resolution_path = _absolute(root, args.group_resolution)
    stream_resolution: dict[str, object] | None = None
    group_resolution: dict[str, object] | None = None
    if stream_resolution_path.exists():
        candidate = _read_json(stream_resolution_path)
        validate_decoder_stream_resolution(candidate)
        if candidate["consumer_evidence_confirmed"] is True:
            stream_resolution = candidate
    if group_resolution_path.exists():
        candidate = _read_json(group_resolution_path)
        if (
            candidate.get("artifact_kind")
            == "sanitized-s25u-test-display-capture"
            and candidate.get("schema_version") in {4, 5}
            and isinstance(candidate.get("group_entry"), dict)
            and candidate["group_entry"].get("prefix_roundtrip_exact") is True
        ):
            group_resolution = candidate
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
    if source_path in {output_rom, output_ips, report_path}:
        raise SystemExit("refusing to overwrite the clean source ROM")
    _require_within(output_rom, root / "build", "test ROM output")
    _require_within(output_ips, root / "build", "IPS output")
    _require_within(report_path, root / "reports" / "local", "build report")

    target, overlay, report = build_test_patch(
        source_path.read_bytes(),
        _absolute(root, args.patch).read_bytes(),
        resolution,
        _read_json(_absolute(root, args.trace_plan)),
        stream_resolution=stream_resolution,
        group_resolution=group_resolution,
    )
    _write_outputs(
        output_rom,
        output_ips,
        report_path,
        target,
        overlay,
        report,
    )
    print(f"Built S25U-local test ROM: {output_rom}")
    print(f"Built S25U-local IPS overlay: {output_ips}")
    print(f"Build report: {report_path}")
    print("The technical PoC still requires cold-boot screen verification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
