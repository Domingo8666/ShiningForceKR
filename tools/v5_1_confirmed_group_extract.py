#!/usr/bin/env python3
"""Extract and roundtrip the complete confirmed 148-record dialogue group.

Encoded bytes and decoded symbols remain in an ignored phone-local report.
Only structural counts, coordinates, identities, and gate results are safe to
publish.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

try:
    from .patch_io import PatchError, sha256_file
    from .sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from .v5_1_consumer import verify_target_identity
    from .v5_1_decoder_register_trace import (
        PUBLISH_RELATIVE_PATH as REGISTER_TRACE_PATH,
        validate_decoder_register_trace,
    )
    from .v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
    from .v5_1_renderer_output_trace import DEFAULT_ROM, _load_json_object
    from .v5_1_visible_script_record import (
        PUBLISH_RELATIVE_PATH as VISIBLE_ROUNDTRIP_PATH,
        _bits_equal,
        validate_visible_script_roundtrip,
    )
except ImportError:  # direct script execution
    from patch_io import PatchError, sha256_file
    from sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from v5_1_consumer import verify_target_identity
    from v5_1_decoder_register_trace import (
        PUBLISH_RELATIVE_PATH as REGISTER_TRACE_PATH,
        validate_decoder_register_trace,
    )
    from v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
    from v5_1_renderer_output_trace import DEFAULT_ROM, _load_json_object
    from v5_1_visible_script_record import (
        PUBLISH_RELATIVE_PATH as VISIBLE_ROUNDTRIP_PATH,
        _bits_equal,
        validate_visible_script_roundtrip,
    )


ARTIFACT_KIND = "sanitized-v5-1-confirmed-group-extract"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_confirmed_group_extract.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_confirmed_group_extract.json")
GROUP_CURSOR_PC = 0x3402
GROUP_COUNT_PC = 0x3403
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_register_trace_sha256",
    "source_visible_roundtrip_sha256",
    "captured_utc",
    "group",
    "roundtrip",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
GROUP_KEYS = {
    "selector",
    "mapped_bank",
    "logical_start",
    "physical_start",
    "declared_entry_count",
    "selected_entry_ordinal",
    "selected_record_matches",
}
ROUNDTRIP_KEYS = {
    "parsed_entry_count",
    "decoded_entry_count",
    "roundtrip_exact_entry_count",
    "terminator_exact_entry_count",
    "zero_length_entry_count",
    "decode_failed_entry_count",
    "unresolved_entry_count",
    "total_record_bytes",
    "total_decoded_symbols",
    "total_encoded_bits",
    "maximum_record_bytes",
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


def resolve_confirmed_group_layout(
    register_trace: dict[str, object],
    visible_roundtrip: dict[str, object],
) -> dict[str, int]:
    validate_decoder_register_trace(register_trace)
    validate_visible_script_roundtrip(visible_roundtrip)
    states = register_trace["states"]
    assert isinstance(states, list)
    cursor_index = next(
        (
            index
            for index, state in enumerate(states)
            if isinstance(state, dict) and state.get("pc") == GROUP_CURSOR_PC
        ),
        None,
    )
    if cursor_index is None or cursor_index + 1 >= len(states):
        raise ValueError("confirmed group cursor state is missing")
    cursor_state = states[cursor_index]
    count_state = states[cursor_index + 1]
    if (
        not isinstance(cursor_state, dict)
        or not isinstance(count_state, dict)
        or count_state.get("pc") != GROUP_COUNT_PC
    ):
        raise ValueError("confirmed group count state is missing")
    mapped_bank = int(cursor_state["slot1_bank"])
    logical_start = int(cursor_state["hl"])
    declared_count = int(count_state["bc"]) >> 8
    selected_ordinal = int(states[0]["bc"]) >> 8
    if (
        not 0x4000 <= logical_start <= 0x7FFF
        or not 1 <= declared_count <= 0xFF
        or selected_ordinal != declared_count - 1
    ):
        raise ValueError("confirmed group register roles are inconsistent")
    physical_start = mapped_bank * 0x4000 + (logical_start & 0x3FFF)
    runtime = visible_roundtrip["runtime_entry"]
    assert isinstance(runtime, dict)
    if int(runtime["mapped_bank"]) != mapped_bank:
        raise ValueError("confirmed group and visible record banks disagree")
    return {
        "selector": int(register_trace["selector_de"]),
        "mapped_bank": mapped_bank,
        "logical_start": logical_start,
        "physical_start": physical_start,
        "declared_entry_count": declared_count,
        "selected_entry_ordinal": selected_ordinal,
        "selected_physical_start": int(runtime["physical_start"]),
        "selected_record_length": int(runtime["record_length_bytes"]),
    }


def parse_length_prefixed_group(
    rom: bytes,
    *,
    physical_start: int,
    entry_count: int,
) -> list[dict[str, object]]:
    if (
        not 0 <= physical_start < len(rom)
        or not 1 <= entry_count <= 0xFF
    ):
        raise ValueError("confirmed group bounds are invalid")
    records: list[dict[str, object]] = []
    cursor = physical_start
    for ordinal in range(entry_count):
        if cursor >= len(rom):
            raise ValueError("confirmed group length byte is outside the ROM")
        length = rom[cursor]
        payload_start = cursor + 1
        payload_end = payload_start + length
        if payload_end > len(rom):
            raise ValueError("confirmed group record length is invalid")
        records.append(
            {
                "ordinal": ordinal,
                "length_offset": cursor,
                "payload_start": payload_start,
                "payload_end": payload_end,
                "record_length_bytes": length,
                "payload": rom[payload_start:payload_end],
            }
        )
        cursor = payload_end
    return records


def extract_confirmed_group(
    *,
    rom: bytes,
    register_trace: dict[str, object],
    visible_roundtrip: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    verify_target_identity(rom)
    layout = resolve_confirmed_group_layout(
        register_trace,
        visible_roundtrip,
    )
    records = parse_length_prefixed_group(
        rom,
        physical_start=layout["physical_start"],
        entry_count=layout["declared_entry_count"],
    )
    selected = records[layout["selected_entry_ordinal"]]
    selected_matches = (
        int(selected["payload_start"]) == layout["selected_physical_start"]
        and int(selected["record_length_bytes"])
        == layout["selected_record_length"]
    )
    if not selected_matches:
        raise ValueError("confirmed group does not reach the visible record")

    known = bytes([1]) * len(rom)
    trees = load_trees_at(
        rom,
        known,
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )
    local_records: list[dict[str, object]] = []
    roundtrip_count = 0
    terminator_count = 0
    zero_length_count = 0
    decode_failed_count = 0
    total_symbols = 0
    total_bits = 0
    for record in records:
        start = int(record["payload_start"])
        length = int(record["record_length_bytes"])
        payload = record["payload"]
        assert isinstance(payload, bytes)
        symbols: list[int] = []
        encoded_bits = 0
        bit_exact = False
        exact_terminator = False
        decode_error: str | None = None
        if length == 0:
            zero_length_count += 1
            decode_error = "zero-length-runtime-or-empty-record"
        else:
            try:
                symbols, encoded_bits = decode_symbols(
                    rom,
                    known,
                    trees,
                    start,
                    initial_symbol=CANDIDATE_END_SYMBOL,
                    end_symbol=CANDIDATE_END_SYMBOL,
                    max_symbols=0x1000,
                    max_bytes=length,
                )
                reencoded, reencoded_bits = encode_symbols(
                    trees,
                    symbols,
                    initial_symbol=CANDIDATE_END_SYMBOL,
                    end_symbol=CANDIDATE_END_SYMBOL,
                    max_bits=length * 8,
                )
                bit_exact = (
                    encoded_bits == reencoded_bits
                    and _bits_equal(payload, reencoded, encoded_bits)
                )
                exact_terminator = (
                    symbols.count(CANDIDATE_END_SYMBOL) == 1
                )
                if not bit_exact or not exact_terminator:
                    decode_error = "no-change-roundtrip-mismatch"
                    decode_failed_count += 1
            except PatchError as error:
                decode_error = type(error).__name__
                decode_failed_count += 1
        roundtrip_count += int(bit_exact)
        terminator_count += int(exact_terminator)
        total_symbols += len(symbols)
        total_bits += encoded_bits
        local_records.append(
            {
                "entry_id": (
                    f"group-{layout['selector']:02X}/"
                    f"{int(record['ordinal']):03d}"
                ),
                "ordinal": int(record["ordinal"]),
                "length_offset": int(record["length_offset"]),
                "payload_start": start,
                "record_length_bytes": length,
                "encoded_hex": payload.hex().upper(),
                "encoded_sha256": hashlib.sha256(payload).hexdigest(),
                "symbols_hex": [f"0x{symbol:02X}" for symbol in symbols],
                "symbol_stream_sha256": hashlib.sha256(
                    bytes(symbols)
                ).hexdigest(),
                "encoded_bits": encoded_bits,
                "roundtrip_exact": bit_exact,
                "terminator_exact": exact_terminator,
                "classification": (
                    "decoded-roundtrip"
                    if bit_exact and exact_terminator
                    else "unresolved"
                ),
                "decode_error": decode_error,
            }
        )

    unresolved_count = zero_length_count + decode_failed_count
    safe_counts = {
        "parsed_entry_count": len(records),
        "decoded_entry_count": len(local_records),
        "roundtrip_exact_entry_count": roundtrip_count,
        "terminator_exact_entry_count": terminator_count,
        "zero_length_entry_count": zero_length_count,
        "decode_failed_entry_count": decode_failed_count,
        "unresolved_entry_count": unresolved_count,
        "total_record_bytes": sum(
            int(record["record_length_bytes"]) for record in records
        ),
        "total_decoded_symbols": total_symbols,
        "total_encoded_bits": total_bits,
        "maximum_record_bytes": max(
            int(record["record_length_bytes"]) for record in records
        ),
    }
    local = {
        "layout": layout,
        "records": local_records,
    }
    return safe_counts, local


def build_confirmed_group_extract(
    *,
    target_sha256: str,
    source_register_trace_sha256: str,
    source_visible_roundtrip_sha256: str,
    layout: dict[str, int],
    roundtrip: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    entry_count = int(layout["declared_entry_count"])
    complete = all(
        int(roundtrip[key]) == entry_count
        for key in (
            "parsed_entry_count",
            "decoded_entry_count",
            "roundtrip_exact_entry_count",
            "terminator_exact_entry_count",
        )
    ) and (
        int(roundtrip["unresolved_entry_count"]) == 0
        and bool(layout["selected_record_matches"])
    )
    population_enumerated = (
        int(roundtrip["parsed_entry_count"]) == entry_count
        and bool(layout["selected_record_matches"])
    )
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "confirmed-group-roundtrip-pass"
            if complete
            else "confirmed-group-population-enumerated-with-unresolved"
            if population_enumerated
            else "confirmed-group-roundtrip-incomplete"
        ),
        "target_sha256": target_sha256,
        "source_register_trace_sha256": source_register_trace_sha256,
        "source_visible_roundtrip_sha256": (
            source_visible_roundtrip_sha256
        ),
        "captured_utc": captured_utc,
        "group": {
            key: layout[key]
            for key in GROUP_KEYS
        },
        "roundtrip": {
            key: int(roundtrip[key])
            for key in ROUNDTRIP_KEYS
        },
        "local_payload_policy": (
            "encoded-bytes-symbols-codepoints-and-text-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": (
            "map-confirmed-group-glyphs-to-unicode"
            if complete
            else "classify-confirmed-group-unresolved-records"
            if population_enumerated
            else "repair-confirmed-group-extraction"
        ),
    }
    validate_confirmed_group_extract(safe)
    return safe


def validate_confirmed_group_extract(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("confirmed group extract fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "confirmed-group-roundtrip-pass",
            "confirmed-group-population-enumerated-with-unresolved",
            "confirmed-group-roundtrip-incomplete",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "source_register_trace_sha256",
                "source_visible_roundtrip_sha256",
            )
        )
    ):
        raise ValueError("confirmed group extract policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("confirmed group timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("confirmed group timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("confirmed group timestamp must include UTC")

    group = value["group"]
    if not isinstance(group, dict) or set(group) != GROUP_KEYS:
        raise ValueError("confirmed group layout fields do not match")
    for key, minimum, maximum in (
        ("selector", 0, 0xFFFF),
        ("mapped_bank", 0, 0xFF),
        ("logical_start", 0x4000, 0x7FFF),
        ("physical_start", 0, 0x17BFFF),
        ("declared_entry_count", 1, 0xFF),
        ("selected_entry_ordinal", 0, 0xFE),
    ):
        if not _bounded_int(group[key], minimum, maximum):
            raise ValueError(f"confirmed group {key} is invalid")
    if (
        group["selected_record_matches"] is not True
        or group["selected_entry_ordinal"]
        != group["declared_entry_count"] - 1
    ):
        raise ValueError("confirmed group selected record is inconsistent")

    roundtrip = value["roundtrip"]
    if not isinstance(roundtrip, dict) or set(roundtrip) != ROUNDTRIP_KEYS:
        raise ValueError("confirmed group roundtrip fields do not match")
    for key in ROUNDTRIP_KEYS:
        minimum = (
            1
            if key
            in {
                "parsed_entry_count",
                "total_record_bytes",
                "total_decoded_symbols",
                "total_encoded_bits",
                "maximum_record_bytes",
            }
            else 0
        )
        if not _bounded_int(roundtrip[key], minimum, 0x1000000):
            raise ValueError(f"confirmed group {key} is invalid")
    count = int(group["declared_entry_count"])
    population_enumerated = roundtrip["parsed_entry_count"] == count
    complete = population_enumerated and all(
        roundtrip[key] == count
        for key in (
            "parsed_entry_count",
            "decoded_entry_count",
            "roundtrip_exact_entry_count",
            "terminator_exact_entry_count",
        )
    ) and roundtrip["unresolved_entry_count"] == 0
    if (
        roundtrip["zero_length_entry_count"]
        + roundtrip["decode_failed_entry_count"]
        != roundtrip["unresolved_entry_count"]
    ):
        raise ValueError("confirmed group unresolved counts are inconsistent")
    expected_status = (
        "confirmed-group-roundtrip-pass"
        if complete
        else "confirmed-group-population-enumerated-with-unresolved"
        if population_enumerated
        else "confirmed-group-roundtrip-incomplete"
    )
    expected_checkpoint = (
        "map-confirmed-group-glyphs-to-unicode"
        if complete
        else "classify-confirmed-group-unresolved-records"
        if population_enumerated
        else "repair-confirmed-group-extraction"
    )
    if (
        value["status"] != expected_status
        or value["next_checkpoint"] != expected_checkpoint
    ):
        raise ValueError("confirmed group result is inconsistent")
    if value["local_payload_policy"] != (
        "encoded-bytes-symbols-codepoints-and-text-local-only"
    ):
        raise ValueError("confirmed group local policy is invalid")
    if value["translation_build_eligible"] is not False:
        raise ValueError("confirmed group cannot enable release builds")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    register_path = root / REGISTER_TRACE_PATH
    visible_path = root / VISIBLE_ROUNDTRIP_PATH
    prerequisites = (rom_path, register_path, visible_path)
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Confirmed group extraction is not ready")
            return 0
        raise SystemExit("confirmed group extraction input is missing")

    register_trace = _load_json_object(register_path)
    visible_roundtrip = _load_json_object(visible_path)
    target_sha256 = sha256_file(rom_path)
    if (
        register_trace.get("target_sha256") != target_sha256
        or visible_roundtrip.get("baseline_target_sha256") != target_sha256
    ):
        raise ValueError("confirmed group target identities disagree")
    safe_counts, local_analysis = extract_confirmed_group(
        rom=rom_path.read_bytes(),
        register_trace=register_trace,
        visible_roundtrip=visible_roundtrip,
    )
    layout = local_analysis["layout"]
    assert isinstance(layout, dict)
    safe_layout = {
        **layout,
        "selected_record_matches": True,
    }
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_confirmed_group_extract(
        target_sha256=target_sha256,
        source_register_trace_sha256=sha256_file(register_path),
        source_visible_roundtrip_sha256=sha256_file(visible_path),
        layout=safe_layout,
        roundtrip=safe_counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-confirmed-group-extract",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "captured_utc": captured_utc,
        **local_analysis,
        "publication_policy": (
            "never-publish-encoded-bytes-symbols-codepoints-or-text"
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
    print(f"SFKR confirmed group extract: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
