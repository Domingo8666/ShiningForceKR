#!/usr/bin/env python3
"""Probe the clean source group's Huffman codec without publishing its text.

The clean ROM, candidate contexts, symbol streams, and per-record data remain
phone-local.  The safe receipt reports only aggregate structural evidence.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

try:
    from .analyze_v5_1 import EXPECTED_SOURCE_SHA256, EXPECTED_SOURCE_SIZE
    from .patch_io import PatchError, sha256_bytes, sha256_file
    from .sfgfc_huffman import (
        BANK_BASE,
        CANDIDATE_END_SYMBOL,
        VECTOR_ENTRIES,
        VECTOR_OFFSET,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from .v5_1_confirmed_group_extract import (
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        parse_length_prefixed_group,
        validate_confirmed_group_extract,
    )
    from .v5_1_group_source_delta import (
        PUBLISH_RELATIVE_PATH as SOURCE_DELTA_PATH,
        validate_group_source_delta,
    )
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_visible_script_record import _bits_equal
except ImportError:  # direct script execution
    from analyze_v5_1 import EXPECTED_SOURCE_SHA256, EXPECTED_SOURCE_SIZE
    from patch_io import PatchError, sha256_bytes, sha256_file
    from sfgfc_huffman import (
        BANK_BASE,
        CANDIDATE_END_SYMBOL,
        VECTOR_ENTRIES,
        VECTOR_OFFSET,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from v5_1_confirmed_group_extract import (
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        parse_length_prefixed_group,
        validate_confirmed_group_extract,
    )
    from v5_1_group_source_delta import (
        PUBLISH_RELATIVE_PATH as SOURCE_DELTA_PATH,
        validate_group_source_delta,
    )
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_visible_script_record import _bits_equal


ARTIFACT_KIND = "sanitized-v5-1-source-group-codec-probe"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_source_group_codec_probe.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_source_group_codec_probe.json")
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "source_sha256",
    "target_sha256",
    "source_group_extract_sha256",
    "source_group_delta_sha256",
    "captured_utc",
    "group",
    "codec_probe",
    "local_payload_policy",
    "source_pairing_complete",
    "translation_build_eligible",
    "next_checkpoint",
}
GROUP_KEYS = {"selector", "record_count"}
PROBE_KEYS = {
    "vector_parse_succeeded",
    "populated_context_count",
    "zero_length_record_count",
    "attempted_record_count",
    "candidate_context_roundtrip_count",
    "candidate_symbol_stream_count",
    "canonical_context_roundtrip_record_count",
    "records_with_any_roundtrip_count",
    "records_with_unique_stream_count",
    "records_with_multiple_streams_count",
    "records_without_roundtrip_count",
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


def probe_source_group_codec(
    *,
    source: bytes,
    records: list[dict[str, object]],
) -> tuple[dict[str, object], dict[str, object]]:
    if not records or len(records) > 0xFF:
        raise ValueError("source codec probe record population is invalid")
    known = bytes([1]) * len(source)
    try:
        trees = load_trees_at(
            source,
            known,
            VECTOR_OFFSET,
            BANK_BASE,
            VECTOR_ENTRIES,
        )
    except PatchError as error:
        counts = {
            "vector_parse_succeeded": False,
            "populated_context_count": 0,
            "zero_length_record_count": sum(
                int(int(record["record_length_bytes"]) == 0)
                for record in records
            ),
            "attempted_record_count": 0,
            "candidate_context_roundtrip_count": 0,
            "candidate_symbol_stream_count": 0,
            "canonical_context_roundtrip_record_count": 0,
            "records_with_any_roundtrip_count": 0,
            "records_with_unique_stream_count": 0,
            "records_with_multiple_streams_count": 0,
            "records_without_roundtrip_count": len(records),
        }
        return counts, {
            "vector_error": type(error).__name__,
            "records": [],
        }
    if not trees:
        raise ValueError("source codec probe found no populated contexts")

    zero_length = 0
    attempted = 0
    context_roundtrips = 0
    stream_count = 0
    canonical_roundtrips = 0
    any_roundtrip = 0
    unique_stream = 0
    multiple_streams = 0
    no_roundtrip = 0
    local_records: list[dict[str, object]] = []
    for record in records:
        ordinal = record.get("ordinal")
        start = record.get("payload_start")
        length = record.get("record_length_bytes")
        payload = record.get("payload")
        if (
            not isinstance(ordinal, int)
            or not isinstance(start, int)
            or not isinstance(length, int)
            or not isinstance(payload, bytes)
            or len(payload) != length
        ):
            raise ValueError("source codec probe record is invalid")
        streams: dict[bytes, dict[str, object]] = {}
        if length == 0:
            zero_length += 1
        else:
            attempted += 1
            for initial_context in sorted(trees):
                try:
                    symbols, encoded_bits = decode_symbols(
                        source,
                        known,
                        trees,
                        start,
                        initial_symbol=initial_context,
                        end_symbol=CANDIDATE_END_SYMBOL,
                        max_symbols=0x400,
                        max_bytes=length,
                    )
                    encoded, reencoded_bits = encode_symbols(
                        trees,
                        symbols,
                        initial_symbol=initial_context,
                        end_symbol=CANDIDATE_END_SYMBOL,
                        max_bits=length * 8,
                    )
                except PatchError:
                    continue
                if (
                    encoded_bits != reencoded_bits
                    or symbols.count(CANDIDATE_END_SYMBOL) != 1
                    or not _bits_equal(payload, encoded, encoded_bits)
                ):
                    continue
                context_roundtrips += 1
                key = bytes(symbols)
                candidate = streams.setdefault(
                    key,
                    {
                        "symbol_stream_sha256": hashlib.sha256(key).hexdigest(),
                        "symbols_hex": [
                            f"0x{symbol:02X}" for symbol in symbols
                        ],
                        "encoded_bits": encoded_bits,
                        "initial_contexts_hex": [],
                    },
                )
                contexts = candidate["initial_contexts_hex"]
                assert isinstance(contexts, list)
                contexts.append(f"0x{initial_context:02X}")
                if initial_context == CANDIDATE_END_SYMBOL:
                    canonical_roundtrips += 1
        record_stream_count = len(streams)
        stream_count += record_stream_count
        any_roundtrip += int(record_stream_count > 0)
        unique_stream += int(record_stream_count == 1)
        multiple_streams += int(record_stream_count > 1)
        no_roundtrip += int(record_stream_count == 0)
        local_records.append(
            {
                "entry_id": f"source-group/{ordinal:03d}",
                "ordinal": ordinal,
                "record_length_bytes": length,
                "source_encoded_sha256": hashlib.sha256(payload).hexdigest(),
                "candidate_stream_count": record_stream_count,
                "candidate_streams": list(streams.values()),
            }
        )
    counts = {
        "vector_parse_succeeded": True,
        "populated_context_count": len(trees),
        "zero_length_record_count": zero_length,
        "attempted_record_count": attempted,
        "candidate_context_roundtrip_count": context_roundtrips,
        "candidate_symbol_stream_count": stream_count,
        "canonical_context_roundtrip_record_count": canonical_roundtrips,
        "records_with_any_roundtrip_count": any_roundtrip,
        "records_with_unique_stream_count": unique_stream,
        "records_with_multiple_streams_count": multiple_streams,
        "records_without_roundtrip_count": no_roundtrip,
    }
    return counts, {"vector_error": None, "records": local_records}


def build_source_group_codec_probe(
    *,
    source_sha256: str,
    target_sha256: str,
    source_group_extract_sha256: str,
    source_group_delta_sha256: str,
    selector: int,
    record_count: int,
    codec_probe: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    vector_ok = codec_probe["vector_parse_succeeded"] is True
    all_have_unique = (
        vector_ok
        and int(codec_probe["records_with_unique_stream_count"])
        == record_count
    )
    status = (
        "source-group-codec-unique-streams-complete"
        if all_have_unique
        else "source-group-codec-candidates-partial"
        if vector_ok
        else "source-group-codec-vector-unusable"
    )
    next_checkpoint = (
        "pair-source-and-target-streams-by-ordinal"
        if all_have_unique
        else "resolve-source-symbol-stream-candidates"
        if vector_ok
        else "locate-clean-source-huffman-vector"
    )
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "source_sha256": source_sha256,
        "target_sha256": target_sha256,
        "source_group_extract_sha256": source_group_extract_sha256,
        "source_group_delta_sha256": source_group_delta_sha256,
        "captured_utc": captured_utc,
        "group": {
            "selector": selector,
            "record_count": record_count,
        },
        "codec_probe": {
            key: codec_probe[key]
            for key in PROBE_KEYS
        },
        "local_payload_policy": (
            "source-bytes-contexts-symbols-codepoints-and-text-local-only"
        ),
        "source_pairing_complete": False,
        "translation_build_eligible": False,
        "next_checkpoint": next_checkpoint,
    }
    validate_source_group_codec_probe(safe)
    return safe


def validate_source_group_codec_probe(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("source group codec probe fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "source-group-codec-unique-streams-complete",
            "source-group-codec-candidates-partial",
            "source-group-codec-vector-unusable",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "source_sha256",
                "target_sha256",
                "source_group_extract_sha256",
                "source_group_delta_sha256",
            )
        )
    ):
        raise ValueError("source group codec probe policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("source group codec probe timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("source group codec probe timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("source group codec probe timestamp must include UTC")
    group = value["group"]
    if not isinstance(group, dict) or set(group) != GROUP_KEYS:
        raise ValueError("source group codec probe group fields do not match")
    if (
        not _bounded_int(group["selector"], 0, 0xFFFF)
        or not _bounded_int(group["record_count"], 1, 0xFF)
    ):
        raise ValueError("source group codec probe group is invalid")
    probe = value["codec_probe"]
    if not isinstance(probe, dict) or set(probe) != PROBE_KEYS:
        raise ValueError("source group codec probe counts do not match")
    if not isinstance(probe["vector_parse_succeeded"], bool):
        raise ValueError("source group codec probe vector result is invalid")
    count = int(group["record_count"])
    for key in PROBE_KEYS - {"vector_parse_succeeded"}:
        maximum = 0x1000000 if "candidate_" in key else count
        if key == "populated_context_count":
            maximum = 0x100
        if not _bounded_int(probe[key], 0, maximum):
            raise ValueError(f"source group codec probe {key} is invalid")
    if (
        probe["zero_length_record_count"]
        + probe["attempted_record_count"] != count
        or probe["records_with_any_roundtrip_count"]
        + probe["records_without_roundtrip_count"] != count
        or probe["records_with_unique_stream_count"]
        + probe["records_with_multiple_streams_count"]
        != probe["records_with_any_roundtrip_count"]
    ):
        raise ValueError("source group codec probe aggregates are inconsistent")
    vector_ok = probe["vector_parse_succeeded"] is True
    all_have_unique = (
        vector_ok and probe["records_with_unique_stream_count"] == count
    )
    expected_status = (
        "source-group-codec-unique-streams-complete"
        if all_have_unique
        else "source-group-codec-candidates-partial"
        if vector_ok
        else "source-group-codec-vector-unusable"
    )
    expected_checkpoint = (
        "pair-source-and-target-streams-by-ordinal"
        if all_have_unique
        else "resolve-source-symbol-stream-candidates"
        if vector_ok
        else "locate-clean-source-huffman-vector"
    )
    if (
        value["status"] != expected_status
        or value["next_checkpoint"] != expected_checkpoint
        or value["local_payload_policy"]
        != "source-bytes-contexts-symbols-codepoints-and-text-local-only"
        or value["source_pairing_complete"] is not False
        or value["translation_build_eligible"] is not False
    ):
        raise ValueError("source group codec probe result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-rom", type=Path, required=True)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    source_path = (
        args.source_rom
        if args.source_rom.is_absolute()
        else root / args.source_rom
    )
    group_path = root / GROUP_EXTRACT_PATH
    delta_path = root / SOURCE_DELTA_PATH
    prerequisites = (source_path, group_path, delta_path)
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Source group codec probe is not ready")
            return 0
        raise SystemExit("source group codec probe input is missing")
    source = source_path.read_bytes()
    if (
        len(source) != EXPECTED_SOURCE_SIZE
        or sha256_bytes(source) != EXPECTED_SOURCE_SHA256
    ):
        raise ValueError("source group codec probe clean ROM identity mismatch")
    group = _load_json_object(group_path)
    delta = _load_json_object(delta_path)
    validate_confirmed_group_extract(group)
    validate_group_source_delta(delta)
    group_info = group["group"]
    delta_group = delta["group"]
    assert isinstance(group_info, dict)
    assert isinstance(delta_group, dict)
    if (
        delta["source_sha256"] != EXPECTED_SOURCE_SHA256
        or delta["target_sha256"] != group["target_sha256"]
        or delta["source_group_extract_sha256"] != sha256_file(group_path)
        or delta_group["selector"] != group_info["selector"]
        or delta_group["record_count"] != group_info["declared_entry_count"]
    ):
        raise ValueError("source group codec probe identities disagree")
    records = parse_length_prefixed_group(
        source,
        physical_start=int(group_info["physical_start"]),
        entry_count=int(group_info["declared_entry_count"]),
    )
    counts, local_analysis = probe_source_group_codec(
        source=source,
        records=records,
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_source_group_codec_probe(
        source_sha256=EXPECTED_SOURCE_SHA256,
        target_sha256=str(group["target_sha256"]),
        source_group_extract_sha256=sha256_file(group_path),
        source_group_delta_sha256=sha256_file(delta_path),
        selector=int(group_info["selector"]),
        record_count=int(group_info["declared_entry_count"]),
        codec_probe=counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-source-group-codec-probe",
        "schema_version": 1,
        "source_sha256": EXPECTED_SOURCE_SHA256,
        "target_sha256": group["target_sha256"],
        "captured_utc": captured_utc,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-source-bytes-contexts-symbols-codepoints-or-text"
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
    print(f"SFKR source group codec probe: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
