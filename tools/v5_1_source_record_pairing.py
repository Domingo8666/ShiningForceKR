#!/usr/bin/env python3
"""Pair clean-source record symbols with provisional target text by ordinal.

Source bytes, symbols, terminator values, target text, tokens, and per-record
metadata stay in ignored phone-local JSON/JSONL files.  The safe receipt
publishes only structural counts and hashes.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

try:
    from .analyze_v5_1 import EXPECTED_SOURCE_SHA256, EXPECTED_SOURCE_SIZE
    from .patch_io import sha256_bytes, sha256_file
    from .v5_1_confirmed_group_extract import (
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        parse_length_prefixed_group,
        validate_confirmed_group_extract,
    )
    from .v5_1_group_script_corpus import (
        LOCAL_REPORT_PATH as TARGET_CORPUS_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as TARGET_CORPUS_PATH,
        validate_group_script_corpus,
    )
    from .v5_1_group_source_delta import (
        PUBLISH_RELATIVE_PATH as SOURCE_DELTA_PATH,
        validate_group_source_delta,
    )
    from .v5_1_renderer_output_trace import _load_json_object
except ImportError:  # direct script execution
    from analyze_v5_1 import EXPECTED_SOURCE_SHA256, EXPECTED_SOURCE_SIZE
    from patch_io import sha256_bytes, sha256_file
    from v5_1_confirmed_group_extract import (
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        parse_length_prefixed_group,
        validate_confirmed_group_extract,
    )
    from v5_1_group_script_corpus import (
        LOCAL_REPORT_PATH as TARGET_CORPUS_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as TARGET_CORPUS_PATH,
        validate_group_script_corpus,
    )
    from v5_1_group_source_delta import (
        PUBLISH_RELATIVE_PATH as SOURCE_DELTA_PATH,
        validate_group_source_delta,
    )
    from v5_1_renderer_output_trace import _load_json_object


ARTIFACT_KIND = "sanitized-v5-1-source-record-pairing"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_source_record_pairing.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_source_record_pairing.json")
LOCAL_JSONL_PATH = Path("reports/local/v5_1_source_record_pairing.jsonl")
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "source_sha256",
    "target_sha256",
    "source_group_extract_sha256",
    "source_group_delta_sha256",
    "source_target_corpus_sha256",
    "local_paired_corpus_sha256",
    "captured_utc",
    "group",
    "pairing",
    "hancharacter_contract_mode",
    "source_symbol_pairing_complete",
    "source_unicode_pairing_complete",
    "speaker_assignment_complete",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
GROUP_KEYS = {
    "selector",
    "source_record_count",
    "target_candidate_record_count",
}
PAIRING_KEYS = {
    "source_nonempty_record_count",
    "distinct_final_symbol_count",
    "dominant_final_symbol_record_count",
    "records_with_internal_dominant_symbol_count",
    "source_total_payload_byte_count",
    "source_body_symbol_count",
    "source_distinct_body_symbol_count",
    "ordinal_pair_count",
    "unpaired_target_record_count",
    "duplicate_target_ordinal_count",
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


def analyze_source_record_pairing(
    *,
    source_records: list[dict[str, object]],
    target_records: list[dict[str, object]],
) -> tuple[dict[str, int], dict[str, object]]:
    if not source_records or len(source_records) > 0xFF:
        raise ValueError("source record pairing population is invalid")
    payloads: list[bytes] = []
    source_by_ordinal: dict[int, bytes] = {}
    for expected_ordinal, record in enumerate(source_records):
        ordinal = record.get("ordinal")
        payload = record.get("payload")
        if (
            ordinal != expected_ordinal
            or not isinstance(payload, bytes)
            or ordinal in source_by_ordinal
        ):
            raise ValueError("source record pairing source record is invalid")
        payloads.append(payload)
        source_by_ordinal[ordinal] = payload
    final_counts = Counter(payload[-1] for payload in payloads if payload)
    dominant_final = (
        final_counts.most_common(1)[0][0] if final_counts else None
    )
    dominant_count = (
        int(final_counts[dominant_final])
        if dominant_final is not None
        else 0
    )
    internal_count = (
        sum(
            int(dominant_final in payload[:-1])
            for payload in payloads
            if payload and dominant_final is not None
        )
        if dominant_final is not None
        else 0
    )
    body_symbols: list[int] = []
    for payload in payloads:
        body = (
            payload[:-1]
            if payload
            and dominant_final is not None
            and payload[-1] == dominant_final
            else payload
        )
        body_symbols.extend(body)

    seen_target_ordinals: set[int] = set()
    duplicate_target_ordinals = 0
    paired: list[dict[str, object]] = []
    for target in target_records:
        if not isinstance(target, dict):
            raise ValueError("source record pairing target record is invalid")
        ordinal = target.get("ordinal")
        if not isinstance(ordinal, int):
            raise ValueError("source record pairing target ordinal is invalid")
        if ordinal in seen_target_ordinals:
            duplicate_target_ordinals += 1
            continue
        seen_target_ordinals.add(ordinal)
        source_payload = source_by_ordinal.get(ordinal)
        if source_payload is None:
            continue
        source_body = (
            source_payload[:-1]
            if source_payload
            and dominant_final is not None
            and source_payload[-1] == dominant_final
            else source_payload
        )
        paired.append(
            {
                "entry_id": target.get("entry_id"),
                "ordinal": ordinal,
                "speaker_id": None,
                "source_text": None,
                "source_symbols_hex": [
                    f"0x{symbol:02X}" for symbol in source_body
                ],
                "source_record_terminator_consistent": bool(
                    source_payload
                    and dominant_final is not None
                    and source_payload[-1] == dominant_final
                ),
                "translation_text": target.get("translation_text"),
                "translation_unicode_complete": target.get(
                    "unicode_complete"
                ),
                "translation_unresolved_glyph_count": target.get(
                    "unresolved_glyph_count"
                ),
                "translation_tokens": target.get("tokens"),
            }
        )
    target_count = len(target_records)
    counts = {
        "source_nonempty_record_count": sum(bool(payload) for payload in payloads),
        "distinct_final_symbol_count": len(final_counts),
        "dominant_final_symbol_record_count": dominant_count,
        "records_with_internal_dominant_symbol_count": internal_count,
        "source_total_payload_byte_count": sum(map(len, payloads)),
        "source_body_symbol_count": len(body_symbols),
        "source_distinct_body_symbol_count": len(set(body_symbols)),
        "ordinal_pair_count": len(paired),
        "unpaired_target_record_count": target_count - len(paired),
        "duplicate_target_ordinal_count": duplicate_target_ordinals,
    }
    local = {
        "dominant_final_symbol_hex": (
            f"0x{dominant_final:02X}"
            if dominant_final is not None
            else None
        ),
        "final_symbol_counts": {
            f"0x{symbol:02X}": count
            for symbol, count in sorted(final_counts.items())
        },
        "records": paired,
    }
    return counts, local


def build_source_record_pairing(
    *,
    source_sha256: str,
    target_sha256: str,
    source_group_extract_sha256: str,
    source_group_delta_sha256: str,
    source_target_corpus_sha256: str,
    local_paired_corpus_sha256: str,
    selector: int,
    source_record_count: int,
    target_candidate_record_count: int,
    pairing: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    complete = (
        int(pairing["source_nonempty_record_count"]) == source_record_count
        and int(pairing["distinct_final_symbol_count"]) == 1
        and int(pairing["dominant_final_symbol_record_count"])
        == source_record_count
        and int(pairing["records_with_internal_dominant_symbol_count"]) == 0
        and int(pairing["ordinal_pair_count"]) == target_candidate_record_count
        and int(pairing["unpaired_target_record_count"]) == 0
        and int(pairing["duplicate_target_ordinal_count"]) == 0
    )
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "source-record-symbol-pairing-complete"
            if complete
            else "source-record-structure-ambiguous"
        ),
        "source_sha256": source_sha256,
        "target_sha256": target_sha256,
        "source_group_extract_sha256": source_group_extract_sha256,
        "source_group_delta_sha256": source_group_delta_sha256,
        "source_target_corpus_sha256": source_target_corpus_sha256,
        "local_paired_corpus_sha256": local_paired_corpus_sha256,
        "captured_utc": captured_utc,
        "group": {
            "selector": selector,
            "source_record_count": source_record_count,
            "target_candidate_record_count": target_candidate_record_count,
        },
        "pairing": {
            key: int(pairing[key])
            for key in PAIRING_KEYS
        },
        "hancharacter_contract_mode": "translator_declared",
        "source_symbol_pairing_complete": complete,
        "source_unicode_pairing_complete": False,
        "speaker_assignment_complete": False,
        "local_payload_policy": (
            "source-symbols-terminators-target-text-tokens-and-speakers-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": (
            "map-source-symbols-to-japanese-unicode"
            if complete
            else "classify-source-record-boundaries"
        ),
    }
    validate_source_record_pairing(safe)
    return safe


def validate_source_record_pairing(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("source record pairing fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "source-record-symbol-pairing-complete",
            "source-record-structure-ambiguous",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "source_sha256",
                "target_sha256",
                "source_group_extract_sha256",
                "source_group_delta_sha256",
                "source_target_corpus_sha256",
                "local_paired_corpus_sha256",
            )
        )
    ):
        raise ValueError("source record pairing policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("source record pairing timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("source record pairing timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("source record pairing timestamp must include UTC")
    group = value["group"]
    if not isinstance(group, dict) or set(group) != GROUP_KEYS:
        raise ValueError("source record pairing group fields do not match")
    if (
        not _bounded_int(group["selector"], 0, 0xFFFF)
        or not _bounded_int(group["source_record_count"], 1, 0xFF)
        or not _bounded_int(
            group["target_candidate_record_count"],
            1,
            group["source_record_count"],
        )
    ):
        raise ValueError("source record pairing group is invalid")
    pairing = value["pairing"]
    if not isinstance(pairing, dict) or set(pairing) != PAIRING_KEYS:
        raise ValueError("source record pairing counts do not match")
    source_count = int(group["source_record_count"])
    target_count = int(group["target_candidate_record_count"])
    for key in PAIRING_KEYS:
        maximum = (
            0x1000000
            if "byte_count" in key or "symbol_count" in key
            else target_count
            if "target" in key
            or "pair_count" in key
            or "duplicate" in key
            else source_count
        )
        if not _bounded_int(pairing[key], 0, maximum):
            raise ValueError(f"source record pairing {key} is invalid")
    if (
        pairing["ordinal_pair_count"]
        + pairing["unpaired_target_record_count"] != target_count
    ):
        raise ValueError("source record pairing aggregates are inconsistent")
    complete = (
        pairing["source_nonempty_record_count"] == source_count
        and pairing["distinct_final_symbol_count"] == 1
        and pairing["dominant_final_symbol_record_count"] == source_count
        and pairing["records_with_internal_dominant_symbol_count"] == 0
        and pairing["ordinal_pair_count"] == target_count
        and pairing["unpaired_target_record_count"] == 0
        and pairing["duplicate_target_ordinal_count"] == 0
    )
    if (
        value["status"]
        != (
            "source-record-symbol-pairing-complete"
            if complete
            else "source-record-structure-ambiguous"
        )
        or value["hancharacter_contract_mode"] != "translator_declared"
        or value["source_symbol_pairing_complete"] is not complete
        or value["source_unicode_pairing_complete"] is not False
        or value["speaker_assignment_complete"] is not False
        or value["local_payload_policy"]
        != "source-symbols-terminators-target-text-tokens-and-speakers-local-only"
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != (
            "map-source-symbols-to-japanese-unicode"
            if complete
            else "classify-source-record-boundaries"
        )
    ):
        raise ValueError("source record pairing result is inconsistent")


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
    corpus_path = root / TARGET_CORPUS_PATH
    corpus_local_path = root / TARGET_CORPUS_LOCAL_PATH
    prerequisites = (
        source_path,
        group_path,
        delta_path,
        corpus_path,
        corpus_local_path,
    )
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Source record pairing is not ready")
            return 0
        raise SystemExit("source record pairing input is missing")
    source = source_path.read_bytes()
    if (
        len(source) != EXPECTED_SOURCE_SIZE
        or sha256_bytes(source) != EXPECTED_SOURCE_SHA256
    ):
        raise ValueError("source record pairing clean ROM identity mismatch")
    group = _load_json_object(group_path)
    delta = _load_json_object(delta_path)
    corpus = _load_json_object(corpus_path)
    corpus_local = _load_json_object(corpus_local_path)
    validate_confirmed_group_extract(group)
    validate_group_source_delta(delta)
    validate_group_script_corpus(corpus)
    group_info = group["group"]
    corpus_group = corpus["group"]
    assert isinstance(group_info, dict)
    assert isinstance(corpus_group, dict)
    if (
        delta["source_sha256"] != EXPECTED_SOURCE_SHA256
        or delta["target_sha256"] != group["target_sha256"]
        or delta["source_group_extract_sha256"] != sha256_file(group_path)
        or corpus["target_sha256"] != group["target_sha256"]
        or corpus_group["selector"] != group_info["selector"]
        or corpus_local.get("target_sha256") != group["target_sha256"]
        or corpus_local.get("jsonl_sha256") != corpus["local_corpus_sha256"]
    ):
        raise ValueError("source record pairing identities disagree")
    target_records = corpus_local.get("records")
    if not isinstance(target_records, list):
        raise ValueError("source record pairing target corpus is missing")
    source_records = parse_length_prefixed_group(
        source,
        physical_start=int(group_info["physical_start"]),
        entry_count=int(group_info["declared_entry_count"]),
    )
    counts, local_analysis = analyze_source_record_pairing(
        source_records=source_records,
        target_records=target_records,
    )
    paired_records = local_analysis["records"]
    assert isinstance(paired_records, list)
    jsonl_bytes = (
        "\n".join(
            json.dumps(record, ensure_ascii=False, sort_keys=True)
            for record in paired_records
        )
        + "\n"
    ).encode("utf-8")
    local_paired_corpus_sha256 = hashlib.sha256(jsonl_bytes).hexdigest()
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_source_record_pairing(
        source_sha256=EXPECTED_SOURCE_SHA256,
        target_sha256=str(group["target_sha256"]),
        source_group_extract_sha256=sha256_file(group_path),
        source_group_delta_sha256=sha256_file(delta_path),
        source_target_corpus_sha256=sha256_file(corpus_path),
        local_paired_corpus_sha256=local_paired_corpus_sha256,
        selector=int(group_info["selector"]),
        source_record_count=len(source_records),
        target_candidate_record_count=len(target_records),
        pairing=counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-source-record-pairing",
        "schema_version": 1,
        "source_sha256": EXPECTED_SOURCE_SHA256,
        "target_sha256": group["target_sha256"],
        "captured_utc": captured_utc,
        "analysis": local_analysis,
        "jsonl_sha256": local_paired_corpus_sha256,
        "publication_policy": (
            "never-publish-source-symbols-terminators-target-text-tokens-or-speakers"
        ),
    }
    safe_path = root / PUBLISH_RELATIVE_PATH
    local_path = root / LOCAL_REPORT_PATH
    jsonl_path = root / LOCAL_JSONL_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    jsonl_path.write_bytes(jsonl_bytes)
    print(f"SFKR source record pairing: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
