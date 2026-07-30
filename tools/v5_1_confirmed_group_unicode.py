#!/usr/bin/env python3
"""Use the confirmed dialogue group to narrow its implicit font page.

Raw symbols, candidate pages, codepoints, characters, tokens, and reconstructed
text remain in an ignored phone-local report.  Coverage is a narrowing signal,
not a substitute for the runtime font-page check.
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
        LOCAL_REPORT_PATH as LOCAL_GROUP_PATH,
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        validate_confirmed_group_extract,
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
    from v5_1_confirmed_group_extract import (
        LOCAL_REPORT_PATH as LOCAL_GROUP_PATH,
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        validate_confirmed_group_extract,
    )
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_visible_unicode_mapping import (
        LOCAL_FONT_CATALOG_PATH,
        LOCAL_REPORT_PATH as LOCAL_VISIBLE_MAPPING_PATH,
        PUBLISH_RELATIVE_PATH as VISIBLE_MAPPING_PATH,
        _map_visible_symbols_with_page,
        validate_visible_unicode_mapping,
    )


ARTIFACT_KIND = "sanitized-v5-1-confirmed-group-unicode"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_confirmed_group_unicode.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_confirmed_group_unicode.json")
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_group_extract_sha256",
    "source_visible_mapping_sha256",
    "source_font_catalog_sha256",
    "captured_utc",
    "group",
    "mapping",
    "coverage_narrowing_only",
    "runtime_initial_page_confirmed",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
GROUP_KEYS = {
    "selector",
    "record_count",
}
MAPPING_KEYS = {
    "candidate_page_count_before",
    "candidate_page_count_after",
    "best_candidate_bank_count",
    "visible_glyph_count",
    "unique_glyph_count",
    "ambiguous_glyph_count",
    "unmatched_glyph_count",
    "control_symbol_count",
    "terminator_count",
    "page_select_count",
    "records_with_page_select",
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


def _catalog_index(
    catalog_entries: list[dict[str, object]],
) -> dict[tuple[int, int], dict[str, object]]:
    catalog: dict[tuple[int, int], dict[str, object]] = {}
    for entry in catalog_entries:
        if not isinstance(entry, dict):
            raise ValueError("confirmed group font catalog entry is invalid")
        page = entry.get("page")
        symbol = entry.get("symbol")
        if not isinstance(page, int) or not isinstance(symbol, int):
            raise ValueError("confirmed group font catalog coordinate is invalid")
        catalog[(page, symbol)] = entry
    return catalog


def _symbols_from_record(record: dict[str, object]) -> list[int]:
    raw = record.get("symbols_hex")
    if not isinstance(raw, list) or not all(
        isinstance(item, str)
        and re.fullmatch(r"0x[0-9A-Fa-f]{2}", item) is not None
        for item in raw
    ):
        raise ValueError("confirmed group symbol stream is invalid")
    return [int(item, 16) for item in raw]


def _local_text(tokens: list[dict[str, object]]) -> str:
    parts: list[str] = []
    for token in tokens:
        kind = token.get("kind")
        if kind == "glyph":
            characters = token.get("characters")
            if isinstance(characters, list) and len(characters) == 1:
                parts.append(str(characters[0]))
            else:
                parts.append("�")
        elif kind == "control":
            parts.append(f"[CTRL:{int(token['symbol']):02X}]")
        elif kind == "page-select":
            parts.append("[PAGE]")
    return "".join(parts)


def analyze_confirmed_group_unicode(
    *,
    records: list[dict[str, object]],
    catalog_entries: list[dict[str, object]],
    candidate_pages: list[int],
) -> tuple[dict[str, object], dict[str, object]]:
    if (
        not records
        or not candidate_pages
        or candidate_pages != sorted(set(candidate_pages))
        or any(not 0 <= page < 244 for page in candidate_pages)
    ):
        raise ValueError("confirmed group Unicode inputs are invalid")
    catalog = _catalog_index(catalog_entries)
    trials: list[dict[str, object]] = []
    for initial_page in candidate_pages:
        totals = {
            "visible_glyph_count": 0,
            "unique_glyph_count": 0,
            "ambiguous_glyph_count": 0,
            "unmatched_glyph_count": 0,
            "control_symbol_count": 0,
            "terminator_count": 0,
            "page_select_count": 0,
            "records_with_page_select": 0,
        }
        local_records: list[dict[str, object]] = []
        for record in records:
            symbols = _symbols_from_record(record)
            safe_record, local_record = _map_visible_symbols_with_page(
                symbols,
                catalog,
                initial_page,
            )
            for key in (
                "visible_glyph_count",
                "unique_glyph_count",
                "ambiguous_glyph_count",
                "unmatched_glyph_count",
                "control_symbol_count",
                "terminator_count",
                "page_select_count",
            ):
                totals[key] += int(safe_record[key])
            totals["records_with_page_select"] += int(
                int(safe_record["page_select_count"]) > 0
            )
            tokens = local_record["tokens"]
            assert isinstance(tokens, list)
            local_records.append(
                {
                    "entry_id": record.get("entry_id"),
                    "tokens": tokens,
                    "text": _local_text(tokens),
                    "mapping": safe_record,
                }
            )
        score = (
            totals["unmatched_glyph_count"],
            totals["ambiguous_glyph_count"],
            -totals["unique_glyph_count"],
        )
        trials.append(
            {
                "initial_page": initial_page,
                "font_bank": 0x22 + initial_page // 4,
                "score": list(score),
                "totals": totals,
                "records": local_records,
            }
        )
    best_score = min(tuple(trial["score"]) for trial in trials)
    best = [
        trial
        for trial in trials
        if tuple(trial["score"]) == best_score
    ]
    selected = min(best, key=lambda trial: int(trial["initial_page"]))
    safe_counts = {
        "candidate_page_count_before": len(candidate_pages),
        "candidate_page_count_after": len(best),
        "best_candidate_bank_count": len(
            {int(trial["font_bank"]) for trial in best}
        ),
        **selected["totals"],
    }
    local = {
        "candidate_pages_before": candidate_pages,
        "candidate_pages_after": sorted(
            int(trial["initial_page"]) for trial in best
        ),
        "selected_coverage_trial": selected,
        "trials": trials,
    }
    return safe_counts, local


def build_confirmed_group_unicode(
    *,
    target_sha256: str,
    source_group_extract_sha256: str,
    source_visible_mapping_sha256: str,
    source_font_catalog_sha256: str,
    selector: int,
    record_count: int,
    mapping: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    before = int(mapping["candidate_page_count_before"])
    after = int(mapping["candidate_page_count_after"])
    status = (
        "group-font-page-coverage-unique"
        if after == 1
        else "group-font-page-coverage-narrowed"
        if after < before
        else "group-font-page-coverage-tied"
    )
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": target_sha256,
        "source_group_extract_sha256": source_group_extract_sha256,
        "source_visible_mapping_sha256": source_visible_mapping_sha256,
        "source_font_catalog_sha256": source_font_catalog_sha256,
        "captured_utc": captured_utc,
        "group": {
            "selector": selector,
            "record_count": record_count,
        },
        "mapping": {
            key: int(mapping[key])
            for key in MAPPING_KEYS
        },
        "coverage_narrowing_only": True,
        "runtime_initial_page_confirmed": False,
        "local_payload_policy": (
            "symbols-pages-codepoints-characters-tokens-and-text-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": (
            "verify-unique-group-font-page-at-runtime"
            if after == 1
            else "trace-group-font-page-before-render"
        ),
    }
    validate_confirmed_group_unicode(safe)
    return safe


def validate_confirmed_group_unicode(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("confirmed group Unicode fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "group-font-page-coverage-unique",
            "group-font-page-coverage-narrowed",
            "group-font-page-coverage-tied",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "source_group_extract_sha256",
                "source_visible_mapping_sha256",
                "source_font_catalog_sha256",
            )
        )
    ):
        raise ValueError("confirmed group Unicode policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("confirmed group Unicode timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("confirmed group Unicode timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("confirmed group Unicode timestamp must include UTC")
    group = value["group"]
    if not isinstance(group, dict) or set(group) != GROUP_KEYS:
        raise ValueError("confirmed group Unicode group fields do not match")
    if (
        not _bounded_int(group["selector"], 0, 0xFFFF)
        or not _bounded_int(group["record_count"], 1, 0xFFFF)
    ):
        raise ValueError("confirmed group Unicode group is invalid")
    mapping = value["mapping"]
    if not isinstance(mapping, dict) or set(mapping) != MAPPING_KEYS:
        raise ValueError("confirmed group Unicode mapping fields do not match")
    before = mapping["candidate_page_count_before"]
    after = mapping["candidate_page_count_after"]
    if (
        not _bounded_int(before, 1, 244)
        or not _bounded_int(after, 1, before)
        or not _bounded_int(mapping["best_candidate_bank_count"], 1, after)
    ):
        raise ValueError("confirmed group Unicode candidate counts are invalid")
    for key in MAPPING_KEYS - {
        "candidate_page_count_before",
        "candidate_page_count_after",
        "best_candidate_bank_count",
    }:
        if not _bounded_int(mapping[key], 0, 0x1000000):
            raise ValueError(f"confirmed group Unicode {key} is invalid")
    if (
        mapping["unique_glyph_count"]
        + mapping["ambiguous_glyph_count"]
        + mapping["unmatched_glyph_count"]
        != mapping["visible_glyph_count"]
        or mapping["terminator_count"] != group["record_count"]
        or mapping["records_with_page_select"] > group["record_count"]
    ):
        raise ValueError("confirmed group Unicode totals are inconsistent")
    expected_status = (
        "group-font-page-coverage-unique"
        if after == 1
        else "group-font-page-coverage-narrowed"
        if after < before
        else "group-font-page-coverage-tied"
    )
    if (
        value["status"] != expected_status
        or value["coverage_narrowing_only"] is not True
        or value["runtime_initial_page_confirmed"] is not False
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != (
            "verify-unique-group-font-page-at-runtime"
            if after == 1
            else "trace-group-font-page-before-render"
        )
    ):
        raise ValueError("confirmed group Unicode result is inconsistent")
    if value["local_payload_policy"] != (
        "symbols-pages-codepoints-characters-tokens-and-text-local-only"
    ):
        raise ValueError("confirmed group Unicode local policy is invalid")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    group_path = root / GROUP_EXTRACT_PATH
    local_group_path = root / LOCAL_GROUP_PATH
    visible_mapping_path = root / VISIBLE_MAPPING_PATH
    local_visible_mapping_path = root / LOCAL_VISIBLE_MAPPING_PATH
    catalog_path = root / LOCAL_FONT_CATALOG_PATH
    prerequisites = (
        group_path,
        local_group_path,
        visible_mapping_path,
        local_visible_mapping_path,
        catalog_path,
    )
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Confirmed group Unicode mapping is not ready")
            return 0
        raise SystemExit("confirmed group Unicode mapping input is missing")
    group = _load_json_object(group_path)
    validate_confirmed_group_extract(group)
    visible = _load_json_object(visible_mapping_path)
    validate_visible_unicode_mapping(visible)
    local_group = _load_json_object(local_group_path)
    local_visible = _load_json_object(local_visible_mapping_path)
    catalog = _load_json_object(catalog_path)
    if (
        group["status"] != "confirmed-group-roundtrip-pass"
        or group["target_sha256"] != visible["target_sha256"]
        or local_group.get("target_sha256") != group["target_sha256"]
        or local_visible.get("target_sha256") != group["target_sha256"]
        or catalog.get("artifact_kind")
        != "local-v5-1-galmuri7-font-catalog"
        or catalog.get("status") != "verified-static-local-analysis"
    ):
        raise ValueError("confirmed group Unicode identities disagree")
    records = local_group.get("records")
    candidates = local_visible.get("mapping", {}).get(
        "initial_page_candidates"
    )
    entries = catalog.get("entries")
    if (
        not isinstance(records, list)
        or not isinstance(candidates, list)
        or not isinstance(entries, list)
    ):
        raise ValueError("confirmed group Unicode local data is missing")
    candidate_pages = sorted(
        int(item["page"])
        for item in candidates
        if isinstance(item, dict) and isinstance(item.get("page"), int)
    )
    safe_counts, local_analysis = analyze_confirmed_group_unicode(
        records=records,
        catalog_entries=entries,
        candidate_pages=candidate_pages,
    )
    group_info = group["group"]
    assert isinstance(group_info, dict)
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_confirmed_group_unicode(
        target_sha256=str(group["target_sha256"]),
        source_group_extract_sha256=sha256_file(group_path),
        source_visible_mapping_sha256=sha256_file(visible_mapping_path),
        source_font_catalog_sha256=sha256_file(catalog_path),
        selector=int(group_info["selector"]),
        record_count=int(group_info["declared_entry_count"]),
        mapping=safe_counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-confirmed-group-unicode",
        "schema_version": 1,
        "target_sha256": group["target_sha256"],
        "captured_utc": captured_utc,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-symbols-pages-codepoints-characters-tokens-or-text"
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
    print(f"SFKR confirmed group Unicode: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
