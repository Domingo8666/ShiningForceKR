#!/usr/bin/env python3
"""Resolve group symbol streams by page-control and font-coverage quality.

Candidate contexts, symbol streams, pages, codepoints, and text remain in an
ignored phone-local report.  The safe artifact publishes aggregate resolution
counts only; quality inference never makes a record build-eligible.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_confirmed_group_unicode import _catalog_index
    from .v5_1_group_context_resolution import (
        LOCAL_REPORT_PATH as LOCAL_CONTEXT_PATH,
        PUBLISH_RELATIVE_PATH as CONTEXT_RESOLUTION_PATH,
        validate_group_context_resolution,
    )
    from .v5_1_group_source_delta import (
        PUBLISH_RELATIVE_PATH as SOURCE_DELTA_PATH,
        validate_group_source_delta,
    )
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_visible_unicode_mapping import (
        LOCAL_FONT_CATALOG_PATH,
        LOCAL_REPORT_PATH as LOCAL_VISIBLE_MAPPING_PATH,
        PUBLISH_RELATIVE_PATH as VISIBLE_MAPPING_PATH,
        _map_visible_symbols_with_page,
        validate_visible_unicode_mapping,
    )
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from v5_1_confirmed_group_unicode import _catalog_index
    from v5_1_group_context_resolution import (
        LOCAL_REPORT_PATH as LOCAL_CONTEXT_PATH,
        PUBLISH_RELATIVE_PATH as CONTEXT_RESOLUTION_PATH,
        validate_group_context_resolution,
    )
    from v5_1_group_source_delta import (
        PUBLISH_RELATIVE_PATH as SOURCE_DELTA_PATH,
        validate_group_source_delta,
    )
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_visible_unicode_mapping import (
        LOCAL_FONT_CATALOG_PATH,
        LOCAL_REPORT_PATH as LOCAL_VISIBLE_MAPPING_PATH,
        PUBLISH_RELATIVE_PATH as VISIBLE_MAPPING_PATH,
        _map_visible_symbols_with_page,
        validate_visible_unicode_mapping,
    )


ARTIFACT_KIND = "sanitized-v5-1-group-text-candidate-resolution"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_group_text_candidate_resolution.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_group_text_candidate_resolution.json"
)
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_context_resolution_sha256",
    "source_group_delta_sha256",
    "source_visible_mapping_sha256",
    "source_font_catalog_sha256",
    "captured_utc",
    "group",
    "resolution",
    "quality_inference_only",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
GROUP_KEYS = {
    "selector",
    "record_count",
}
RESOLUTION_KEYS = {
    "candidate_context_decode_count",
    "candidate_symbol_stream_count",
    "valid_text_stream_count",
    "unique_best_record_count",
    "ambiguous_best_record_count",
    "no_valid_text_record_count",
    "selected_visible_glyph_count",
    "selected_unique_glyph_count",
    "selected_ambiguous_glyph_count",
    "selected_unmatched_glyph_count",
    "selected_page_select_count",
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


def _symbols(candidate: dict[str, object]) -> list[int]:
    raw = candidate.get("symbols_hex")
    if not isinstance(raw, list) or not all(
        isinstance(item, str)
        and re.fullmatch(r"0x[0-9A-Fa-f]{2}", item) is not None
        for item in raw
    ):
        raise ValueError("group text candidate symbols are invalid")
    return [int(item, 16) for item in raw]


def resolve_group_text_candidates(
    *,
    records: list[dict[str, object]],
    catalog_entries: list[dict[str, object]],
    candidate_pages: list[int],
) -> tuple[dict[str, int], dict[str, object]]:
    if (
        not records
        or not candidate_pages
        or candidate_pages != sorted(set(candidate_pages))
    ):
        raise ValueError("group text candidate inputs are invalid")
    catalog = _catalog_index(catalog_entries)
    context_decode_count = 0
    symbol_stream_count = 0
    valid_stream_count = 0
    unique_best = 0
    ambiguous_best = 0
    no_valid = 0
    selected_totals = {
        "visible_glyph_count": 0,
        "unique_glyph_count": 0,
        "ambiguous_glyph_count": 0,
        "unmatched_glyph_count": 0,
        "page_select_count": 0,
    }
    local_records: list[dict[str, object]] = []
    resolved_records: list[dict[str, object]] = []

    for record in records:
        if not isinstance(record, dict):
            raise ValueError("group text candidate record is invalid")
        candidates = record.get("candidate_decodes")
        if not isinstance(candidates, list) or not candidates:
            raise ValueError("group text candidate decodes are missing")
        context_decode_count += len(candidates)
        streams: dict[tuple[int, ...], dict[str, object]] = {}
        for candidate in candidates:
            if not isinstance(candidate, dict):
                raise ValueError("group text context candidate is invalid")
            symbols = tuple(_symbols(candidate))
            stream = streams.setdefault(
                symbols,
                {
                    "symbols": list(symbols),
                    "context_count": 0,
                    "context_hex": [],
                },
            )
            stream["context_count"] = int(stream["context_count"]) + 1
            stream["context_hex"].append(candidate.get("initial_context_hex"))
        symbol_stream_count += len(streams)

        scored: list[dict[str, object]] = []
        for stream in streams.values():
            symbols = stream["symbols"]
            assert isinstance(symbols, list)
            page_trials: list[dict[str, object]] = []
            for initial_page in candidate_pages:
                try:
                    safe, local = _map_visible_symbols_with_page(
                        symbols,
                        catalog,
                        initial_page,
                    )
                except ValueError:
                    continue
                visible = int(safe["visible_glyph_count"])
                page_selects = int(safe["page_select_count"])
                if visible == 0 or page_selects == 0:
                    continue
                score = (
                    int(safe["unmatched_glyph_count"]),
                    int(safe["ambiguous_glyph_count"]),
                    -int(safe["unique_glyph_count"]),
                    int(safe["control_symbol_count"]),
                    len(symbols),
                )
                page_trials.append(
                    {
                        "initial_page": initial_page,
                        "score": list(score),
                        "safe": safe,
                        "tokens": local["tokens"],
                    }
                )
            if not page_trials:
                continue
            best_score = min(tuple(trial["score"]) for trial in page_trials)
            best_pages = [
                trial
                for trial in page_trials
                if tuple(trial["score"]) == best_score
            ]
            selected_page = min(
                best_pages,
                key=lambda trial: int(trial["initial_page"]),
            )
            scored.append(
                {
                    **stream,
                    "score": list(best_score),
                    "best_page_count": len(best_pages),
                    "selected_page_trial": selected_page,
                }
            )
        valid_stream_count += len(scored)
        if not scored:
            no_valid += 1
            local_records.append(
                {
                    "entry_id": record.get("entry_id"),
                    "ordinal": record.get("ordinal"),
                    "status": "no-valid-text-stream",
                    "candidate_context_count": len(candidates),
                    "candidate_symbol_stream_count": len(streams),
                }
            )
            continue
        best_score = min(tuple(item["score"]) for item in scored)
        best_streams = [
            item for item in scored if tuple(item["score"]) == best_score
        ]
        if len(best_streams) != 1:
            ambiguous_best += 1
            local_records.append(
                {
                    "entry_id": record.get("entry_id"),
                    "ordinal": record.get("ordinal"),
                    "status": "ambiguous-best-text-stream",
                    "candidate_context_count": len(candidates),
                    "candidate_symbol_stream_count": len(streams),
                    "best_stream_count": len(best_streams),
                    "best_score": list(best_score),
                }
            )
            continue
        unique_best += 1
        selected = best_streams[0]
        page_trial = selected["selected_page_trial"]
        safe_mapping = page_trial["safe"]
        for key in selected_totals:
            selected_totals[key] += int(safe_mapping[key])
        symbols = selected["symbols"]
        symbol_bytes = bytes(int(value) for value in symbols)
        resolved_records.append(
            {
                "entry_id": record.get("entry_id"),
                "ordinal": record.get("ordinal"),
                "symbols_hex": [
                    f"0x{int(value):02X}" for value in symbols
                ],
                "symbol_stream_sha256": hashlib.sha256(
                    symbol_bytes
                ).hexdigest(),
                "mapping": safe_mapping,
                "tokens": page_trial["tokens"],
                "quality_inferred": True,
            }
        )
        local_records.append(
            {
                "entry_id": record.get("entry_id"),
                "ordinal": record.get("ordinal"),
                "status": "unique-best-text-stream",
                "candidate_context_count": len(candidates),
                "candidate_symbol_stream_count": len(streams),
                "selected_context_count": selected["context_count"],
                "selected_contexts_hex": selected["context_hex"],
                "selected_initial_page": page_trial["initial_page"],
                "selected_score": selected["score"],
            }
        )

    safe_counts = {
        "candidate_context_decode_count": context_decode_count,
        "candidate_symbol_stream_count": symbol_stream_count,
        "valid_text_stream_count": valid_stream_count,
        "unique_best_record_count": unique_best,
        "ambiguous_best_record_count": ambiguous_best,
        "no_valid_text_record_count": no_valid,
        "selected_visible_glyph_count": selected_totals[
            "visible_glyph_count"
        ],
        "selected_unique_glyph_count": selected_totals[
            "unique_glyph_count"
        ],
        "selected_ambiguous_glyph_count": selected_totals[
            "ambiguous_glyph_count"
        ],
        "selected_unmatched_glyph_count": selected_totals[
            "unmatched_glyph_count"
        ],
        "selected_page_select_count": selected_totals[
            "page_select_count"
        ],
    }
    local = {
        "records": local_records,
        "resolved_records": resolved_records,
    }
    return safe_counts, local


def build_group_text_candidate_resolution(
    *,
    target_sha256: str,
    source_context_resolution_sha256: str,
    source_group_delta_sha256: str,
    source_visible_mapping_sha256: str,
    source_font_catalog_sha256: str,
    selector: int,
    record_count: int,
    resolution: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    unique = int(resolution["unique_best_record_count"])
    status = (
        "group-text-candidates-fully-resolved"
        if unique == record_count
        else "group-text-candidates-partially-resolved"
        if unique > 0
        else "group-text-candidates-unresolved"
    )
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": target_sha256,
        "source_context_resolution_sha256": (
            source_context_resolution_sha256
        ),
        "source_group_delta_sha256": source_group_delta_sha256,
        "source_visible_mapping_sha256": source_visible_mapping_sha256,
        "source_font_catalog_sha256": source_font_catalog_sha256,
        "captured_utc": captured_utc,
        "group": {
            "selector": selector,
            "record_count": record_count,
        },
        "resolution": {
            key: int(resolution[key])
            for key in RESOLUTION_KEYS
        },
        "quality_inference_only": True,
        "local_payload_policy": (
            "contexts-symbols-pages-codepoints-tokens-and-text-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": (
            "assemble-provisional-target-script-corpus"
            if unique > 0
            else "trace-additional-group-entry-contexts"
        ),
    }
    validate_group_text_candidate_resolution(safe)
    return safe


def validate_group_text_candidate_resolution(
    value: dict[str, object],
) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("group text candidate fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "group-text-candidates-fully-resolved",
            "group-text-candidates-partially-resolved",
            "group-text-candidates-unresolved",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "source_context_resolution_sha256",
                "source_group_delta_sha256",
                "source_visible_mapping_sha256",
                "source_font_catalog_sha256",
            )
        )
    ):
        raise ValueError("group text candidate policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("group text candidate timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("group text candidate timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("group text candidate timestamp must include UTC")
    group = value["group"]
    if not isinstance(group, dict) or set(group) != GROUP_KEYS:
        raise ValueError("group text candidate group fields do not match")
    if (
        not _bounded_int(group["selector"], 0, 0xFFFF)
        or not _bounded_int(group["record_count"], 1, 0xFF)
    ):
        raise ValueError("group text candidate group is invalid")
    resolution = value["resolution"]
    if not isinstance(resolution, dict) or set(resolution) != RESOLUTION_KEYS:
        raise ValueError("group text candidate counts do not match")
    count = int(group["record_count"])
    for key in RESOLUTION_KEYS:
        if not _bounded_int(resolution[key], 0, 0x1000000):
            raise ValueError(f"group text candidate {key} is invalid")
    unique = int(resolution["unique_best_record_count"])
    ambiguous = int(resolution["ambiguous_best_record_count"])
    no_valid = int(resolution["no_valid_text_record_count"])
    if (
        unique + ambiguous + no_valid != count
        or resolution["selected_unique_glyph_count"]
        + resolution["selected_ambiguous_glyph_count"]
        + resolution["selected_unmatched_glyph_count"]
        != resolution["selected_visible_glyph_count"]
    ):
        raise ValueError("group text candidate aggregates are inconsistent")
    expected_status = (
        "group-text-candidates-fully-resolved"
        if unique == count
        else "group-text-candidates-partially-resolved"
        if unique > 0
        else "group-text-candidates-unresolved"
    )
    if (
        value["status"] != expected_status
        or value["quality_inference_only"] is not True
        or value["local_payload_policy"]
        != "contexts-symbols-pages-codepoints-tokens-and-text-local-only"
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != (
            "assemble-provisional-target-script-corpus"
            if unique > 0
            else "trace-additional-group-entry-contexts"
        )
    ):
        raise ValueError("group text candidate result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    context_path = root / CONTEXT_RESOLUTION_PATH
    local_context_path = root / LOCAL_CONTEXT_PATH
    delta_path = root / SOURCE_DELTA_PATH
    visible_path = root / VISIBLE_MAPPING_PATH
    local_visible_path = root / LOCAL_VISIBLE_MAPPING_PATH
    catalog_path = root / LOCAL_FONT_CATALOG_PATH
    prerequisites = (
        context_path,
        local_context_path,
        delta_path,
        visible_path,
        local_visible_path,
        catalog_path,
    )
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Group text candidate resolution is not ready")
            return 0
        raise SystemExit("group text candidate input is missing")
    context = _load_json_object(context_path)
    local_context = _load_json_object(local_context_path)
    delta = _load_json_object(delta_path)
    visible = _load_json_object(visible_path)
    local_visible = _load_json_object(local_visible_path)
    catalog = _load_json_object(catalog_path)
    validate_group_context_resolution(context)
    validate_group_source_delta(delta)
    validate_visible_unicode_mapping(visible)
    if (
        context["target_sha256"] != delta["target_sha256"]
        or context["target_sha256"] != visible["target_sha256"]
        or delta["source_group_extract_sha256"]
        != context["source_group_extract_sha256"]
        or local_context.get("target_sha256")
        != context["target_sha256"]
        or local_visible.get("target_sha256")
        != context["target_sha256"]
        or catalog.get("artifact_kind")
        != "local-v5-1-galmuri7-font-catalog"
        or catalog.get("status") != "verified-static-local-analysis"
    ):
        raise ValueError("group text candidate identities disagree")
    records = local_context.get("analysis", {}).get("records")
    candidates = local_visible.get("mapping", {}).get(
        "initial_page_candidates"
    )
    entries = catalog.get("entries")
    if (
        not isinstance(records, list)
        or not isinstance(candidates, list)
        or not isinstance(entries, list)
    ):
        raise ValueError("group text candidate local data is missing")
    candidate_pages = sorted(
        int(item["page"])
        for item in candidates
        if isinstance(item, dict) and isinstance(item.get("page"), int)
    )
    counts, local_analysis = resolve_group_text_candidates(
        records=records,
        catalog_entries=entries,
        candidate_pages=candidate_pages,
    )
    group = context["group"]
    assert isinstance(group, dict)
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_group_text_candidate_resolution(
        target_sha256=str(context["target_sha256"]),
        source_context_resolution_sha256=sha256_file(context_path),
        source_group_delta_sha256=sha256_file(delta_path),
        source_visible_mapping_sha256=sha256_file(visible_path),
        source_font_catalog_sha256=sha256_file(catalog_path),
        selector=int(group["selector"]),
        record_count=int(group["record_count"]),
        resolution=counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-group-text-candidate-resolution",
        "schema_version": 1,
        "target_sha256": context["target_sha256"],
        "captured_utc": captured_utc,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-contexts-symbols-pages-codepoints-tokens-or-text"
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
    print(f"SFKR group text candidates: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
