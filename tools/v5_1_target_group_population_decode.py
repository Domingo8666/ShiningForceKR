#!/usr/bin/env python3
"""Roundtrip-decode and text-rank the deduplicated target group population.

Record coordinates, selectors, ordinals, payloads, contexts, symbols, pages,
codepoints, tokens, and text remain in ignored phone-local reports.  The safe
receipt publishes aggregate decode and quality counts only.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_group_context_resolution import analyze_group_contexts
    from .v5_1_group_text_candidate_resolution import (
        resolve_group_text_candidates,
    )
    from .v5_1_renderer_output_trace import DEFAULT_ROM, _load_json_object
    from .v5_1_target_group_population import (
        LOCAL_REPORT_PATH as LOCAL_POPULATION_PATH,
        PUBLISH_RELATIVE_PATH as POPULATION_PATH,
        validate_target_group_population,
    )
    from .v5_1_visible_unicode_mapping import (
        LOCAL_FONT_CATALOG_PATH,
        LOCAL_REPORT_PATH as LOCAL_VISIBLE_MAPPING_PATH,
        PUBLISH_RELATIVE_PATH as VISIBLE_MAPPING_PATH,
        validate_visible_unicode_mapping,
    )
    from .v5_1_consumer import verify_target_identity
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from v5_1_group_context_resolution import analyze_group_contexts
    from v5_1_group_text_candidate_resolution import (
        resolve_group_text_candidates,
    )
    from v5_1_renderer_output_trace import DEFAULT_ROM, _load_json_object
    from v5_1_target_group_population import (
        LOCAL_REPORT_PATH as LOCAL_POPULATION_PATH,
        PUBLISH_RELATIVE_PATH as POPULATION_PATH,
        validate_target_group_population,
    )
    from v5_1_visible_unicode_mapping import (
        LOCAL_FONT_CATALOG_PATH,
        LOCAL_REPORT_PATH as LOCAL_VISIBLE_MAPPING_PATH,
        PUBLISH_RELATIVE_PATH as VISIBLE_MAPPING_PATH,
        validate_visible_unicode_mapping,
    )
    from v5_1_consumer import verify_target_identity


ARTIFACT_KIND = "sanitized-v5-1-target-group-population-decode"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_target_group_population_decode.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_target_group_population_decode.json"
)
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_population_sha256",
    "source_visible_mapping_sha256",
    "source_font_catalog_sha256",
    "captured_utc",
    "decode",
    "quality_inference_only",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
DECODE_KEYS = {
    "unique_population_record_count",
    "nonempty_record_count",
    "zero_length_record_count",
    "records_with_exact_roundtrip_count",
    "records_without_exact_roundtrip_count",
    "candidate_context_decode_count",
    "candidate_symbol_stream_count",
    "valid_text_stream_count",
    "unique_best_text_record_count",
    "ambiguous_best_text_record_count",
    "no_valid_text_record_count",
    "selected_visible_glyph_count",
    "selected_unique_glyph_count",
    "selected_ambiguous_glyph_count",
    "selected_unmatched_glyph_count",
    "selected_page_select_count",
    "confirmed_selected_quality_match",
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


def deduplicate_population_records(
    local_population: dict[str, object],
    *,
    confirmed_selector: int = 2,
    confirmed_ordinal: int = 147,
) -> tuple[list[dict[str, object]], str | None]:
    analysis = local_population.get("analysis")
    if not isinstance(analysis, dict):
        raise ValueError("population decode local analysis is missing")
    groups = analysis.get("groups")
    if not isinstance(groups, list):
        raise ValueError("population decode groups are missing")
    by_offset: dict[int, dict[str, object]] = {}
    for group in groups:
        if not isinstance(group, dict):
            raise ValueError("population decode group is invalid")
        records = group.get("records")
        if not isinstance(records, list):
            raise ValueError("population decode records are missing")
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("population decode record is invalid")
            offset = record.get("length_offset")
            selector = record.get("selector")
            ordinal = record.get("ordinal")
            length = record.get("record_length_bytes")
            payload = record.get("payload_hex")
            digest = record.get("payload_sha256")
            if (
                not isinstance(offset, int)
                or not isinstance(selector, int)
                or not isinstance(ordinal, int)
                or not isinstance(length, int)
                or not isinstance(payload, str)
                or re.fullmatch(r"(?:[0-9A-F]{2})*", payload) is None
                or len(payload) != length * 2
                or not _is_sha256(digest)
            ):
                raise ValueError("population decode record fields are invalid")
            existing = by_offset.get(offset)
            if existing is None:
                by_offset[offset] = {
                    "length_offset": offset,
                    "record_length_bytes": length,
                    "encoded_hex": payload,
                    "payload_sha256": digest,
                    "aliases": [
                        {
                            "selector": selector,
                            "ordinal": ordinal,
                        }
                    ],
                }
            else:
                if (
                    existing["record_length_bytes"] != length
                    or existing["encoded_hex"] != payload
                    or existing["payload_sha256"] != digest
                ):
                    raise ValueError(
                        "population decode duplicate payload disagrees"
                    )
                aliases = existing["aliases"]
                assert isinstance(aliases, list)
                aliases.append(
                    {
                        "selector": selector,
                        "ordinal": ordinal,
                    }
                )
    output: list[dict[str, object]] = []
    confirmed_entry_id: str | None = None
    for index, record in enumerate(
        sorted(by_offset.values(), key=lambda item: int(item["length_offset"]))
    ):
        entry_id = f"population-record-{index:04d}"
        aliases = record["aliases"]
        assert isinstance(aliases, list)
        if any(
            alias.get("selector") == confirmed_selector
            and alias.get("ordinal") == confirmed_ordinal
            for alias in aliases
            if isinstance(alias, dict)
        ):
            confirmed_entry_id = entry_id
        output.append(
            {
                **record,
                "entry_id": entry_id,
                "ordinal": index,
            }
        )
    return output, confirmed_entry_id


def build_target_group_population_decode(
    *,
    target_sha256: str,
    source_population_sha256: str,
    source_visible_mapping_sha256: str,
    source_font_catalog_sha256: str,
    decode: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    unique = int(decode["unique_best_text_record_count"])
    nonempty = int(decode["nonempty_record_count"])
    status = (
        "target-group-population-text-fully-resolved"
        if nonempty > 0 and unique == nonempty
        else "target-group-population-text-partially-resolved"
        if unique > 0
        else "target-group-population-text-unresolved"
    )
    checkpoint = (
        "assemble-expanded-target-script-corpus"
        if unique > 0
        else "trace-additional-target-group-contexts"
    )
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": target_sha256,
        "source_population_sha256": source_population_sha256,
        "source_visible_mapping_sha256":
            source_visible_mapping_sha256,
        "source_font_catalog_sha256": source_font_catalog_sha256,
        "captured_utc": captured_utc,
        "decode": {
            key: (
                bool(decode[key])
                if key == "confirmed_selected_quality_match"
                else int(decode[key])
            )
            for key in DECODE_KEYS
        },
        "quality_inference_only": True,
        "local_payload_policy": (
            "selectors-ordinals-records-payloads-contexts-symbols-pages-codepoints-tokens-and-text-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": checkpoint,
    }
    validate_target_group_population_decode(value)
    return value


def validate_target_group_population_decode(
    value: dict[str, object],
) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("target population decode fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "target-group-population-text-fully-resolved",
            "target-group-population-text-partially-resolved",
            "target-group-population-text-unresolved",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "source_population_sha256",
                "source_visible_mapping_sha256",
                "source_font_catalog_sha256",
            )
        )
    ):
        raise ValueError("target population decode policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("target population decode timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(
            "target population decode timestamp is invalid"
        ) from error
    if parsed.tzinfo is None:
        raise ValueError("target population decode timestamp needs UTC")
    decode = value["decode"]
    if not isinstance(decode, dict) or set(decode) != DECODE_KEYS:
        raise ValueError("target population decode counts do not match")
    for key in DECODE_KEYS - {"confirmed_selected_quality_match"}:
        if not _bounded_int(decode[key], 0, 0x1000000):
            raise ValueError(f"target population decode {key} is invalid")
    if not isinstance(decode["confirmed_selected_quality_match"], bool):
        raise ValueError("target population decode confirmation is invalid")
    if (
        decode["nonempty_record_count"]
        + decode["zero_length_record_count"]
        != decode["unique_population_record_count"]
        or decode["records_with_exact_roundtrip_count"]
        + decode["records_without_exact_roundtrip_count"]
        != decode["nonempty_record_count"]
        or decode["unique_best_text_record_count"]
        + decode["ambiguous_best_text_record_count"]
        + decode["no_valid_text_record_count"]
        != decode["records_with_exact_roundtrip_count"]
    ):
        raise ValueError(
            "target population decode aggregates are inconsistent"
        )
    unique = int(decode["unique_best_text_record_count"])
    nonempty = int(decode["nonempty_record_count"])
    expected_status = (
        "target-group-population-text-fully-resolved"
        if nonempty > 0 and unique == nonempty
        else "target-group-population-text-partially-resolved"
        if unique > 0
        else "target-group-population-text-unresolved"
    )
    expected_checkpoint = (
        "assemble-expanded-target-script-corpus"
        if unique > 0
        else "trace-additional-target-group-contexts"
    )
    if (
        value["status"] != expected_status
        or value["next_checkpoint"] != expected_checkpoint
        or value["quality_inference_only"] is not True
        or value["local_payload_policy"]
        != "selectors-ordinals-records-payloads-contexts-symbols-pages-codepoints-tokens-and-text-local-only"
        or value["translation_build_eligible"] is not False
    ):
        raise ValueError("target population decode result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    population_path = root / POPULATION_PATH
    local_population_path = root / LOCAL_POPULATION_PATH
    visible_path = root / VISIBLE_MAPPING_PATH
    local_visible_path = root / LOCAL_VISIBLE_MAPPING_PATH
    catalog_path = root / LOCAL_FONT_CATALOG_PATH
    prerequisites = (
        rom_path,
        population_path,
        local_population_path,
        visible_path,
        local_visible_path,
        catalog_path,
    )
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Target group population decode is not ready")
            return 0
        raise SystemExit("target group population decode input is missing")
    rom = rom_path.read_bytes()
    verify_target_identity(rom)
    target_sha256 = sha256_file(rom_path)
    population = _load_json_object(population_path)
    local_population = _load_json_object(local_population_path)
    visible = _load_json_object(visible_path)
    local_visible = _load_json_object(local_visible_path)
    catalog = _load_json_object(catalog_path)
    validate_target_group_population(population)
    validate_visible_unicode_mapping(visible)
    if (
        population["target_sha256"] != target_sha256
        or visible["target_sha256"] != target_sha256
        or local_population.get("target_sha256") != target_sha256
        or local_visible.get("target_sha256") != target_sha256
        or catalog.get("artifact_kind")
        != "local-v5-1-galmuri7-font-catalog"
        or catalog.get("status") != "verified-static-local-analysis"
    ):
        raise ValueError("target population decode identities disagree")
    records, confirmed_entry_id = deduplicate_population_records(
        local_population
    )
    if len(records) != population["population"]["unique_physical_record_count"]:
        raise ValueError("target population decode unique count disagrees")
    nonempty_records = [
        record
        for record in records
        if int(record["record_length_bytes"]) > 0
    ]
    context_counts, context_local = analyze_group_contexts(
        rom=rom,
        records=nonempty_records,
    )
    context_records = context_local["records"]
    assert isinstance(context_records, list)
    exact_records = [
        record
        for record in context_records
        if (
            isinstance(record, dict)
            and isinstance(record.get("candidate_decodes"), list)
            and bool(record["candidate_decodes"])
        )
    ]
    candidates = local_visible.get("mapping", {}).get(
        "initial_page_candidates"
    )
    entries = catalog.get("entries")
    if not isinstance(candidates, list) or not isinstance(entries, list):
        raise ValueError("target population decode font inputs are missing")
    candidate_pages = sorted(
        int(item["page"])
        for item in candidates
        if isinstance(item, dict) and isinstance(item.get("page"), int)
    )
    if exact_records:
        quality_counts, quality_local = resolve_group_text_candidates(
            records=exact_records,
            catalog_entries=entries,
            candidate_pages=candidate_pages,
        )
    else:
        quality_counts = {
            "candidate_context_decode_count": 0,
            "candidate_symbol_stream_count": 0,
            "valid_text_stream_count": 0,
            "unique_best_record_count": 0,
            "ambiguous_best_record_count": 0,
            "no_valid_text_record_count": 0,
            "selected_visible_glyph_count": 0,
            "selected_unique_glyph_count": 0,
            "selected_ambiguous_glyph_count": 0,
            "selected_unmatched_glyph_count": 0,
            "selected_page_select_count": 0,
        }
        quality_local = {"records": [], "resolved_records": []}
    quality_records = quality_local["records"]
    assert isinstance(quality_records, list)
    confirmed_quality = any(
        isinstance(record, dict)
        and record.get("entry_id") == confirmed_entry_id
        and record.get("status") == "unique-best-text-stream"
        for record in quality_records
    )
    decode = {
        "unique_population_record_count": len(records),
        "nonempty_record_count": len(nonempty_records),
        "zero_length_record_count": len(records) - len(nonempty_records),
        "records_with_exact_roundtrip_count": len(exact_records),
        "records_without_exact_roundtrip_count":
            len(nonempty_records) - len(exact_records),
        "candidate_context_decode_count":
            quality_counts["candidate_context_decode_count"],
        "candidate_symbol_stream_count":
            quality_counts["candidate_symbol_stream_count"],
        "valid_text_stream_count":
            quality_counts["valid_text_stream_count"],
        "unique_best_text_record_count":
            quality_counts["unique_best_record_count"],
        "ambiguous_best_text_record_count":
            quality_counts["ambiguous_best_record_count"],
        "no_valid_text_record_count":
            quality_counts["no_valid_text_record_count"],
        "selected_visible_glyph_count":
            quality_counts["selected_visible_glyph_count"],
        "selected_unique_glyph_count":
            quality_counts["selected_unique_glyph_count"],
        "selected_ambiguous_glyph_count":
            quality_counts["selected_ambiguous_glyph_count"],
        "selected_unmatched_glyph_count":
            quality_counts["selected_unmatched_glyph_count"],
        "selected_page_select_count":
            quality_counts["selected_page_select_count"],
        "confirmed_selected_quality_match": confirmed_quality,
    }
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_target_group_population_decode(
        target_sha256=target_sha256,
        source_population_sha256=sha256_file(population_path),
        source_visible_mapping_sha256=sha256_file(visible_path),
        source_font_catalog_sha256=sha256_file(catalog_path),
        decode=decode,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-target-group-population-decode",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "captured_utc": captured_utc,
        "confirmed_entry_id": confirmed_entry_id,
        "records": records,
        "context_analysis": {
            "counts": context_counts,
            "local": context_local,
        },
        "quality_analysis": quality_local,
        "publication_policy": (
            "never-publish-selectors-ordinals-records-payloads-contexts-symbols-pages-codepoints-tokens-or-text"
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
    print(f"SFKR target group population decode: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
