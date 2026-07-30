#!/usr/bin/env python3
"""Map the exact visible record to local Unicode candidates.

Raw symbols, codepoints, characters, and reconstructed text stay in ignored
local reports.  The publishable artifact contains only counts and identity
links needed to decide whether the full script extractor can reuse the map.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .v5_1_renderer_output_trace import (
        PUBLISH_RELATIVE_PATH as RENDERER_OUTPUT_TRACE_RELATIVE_PATH,
        validate_renderer_output_trace,
    )
    from .v5_1_visible_script_record import (
        PUBLISH_RELATIVE_PATH as VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH,
        validate_visible_script_roundtrip,
    )
except ImportError:  # direct script execution
    from v5_1_renderer_output_trace import (
        PUBLISH_RELATIVE_PATH as RENDERER_OUTPUT_TRACE_RELATIVE_PATH,
        validate_renderer_output_trace,
    )
    from v5_1_visible_script_record import (
        PUBLISH_RELATIVE_PATH as VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH,
        validate_visible_script_roundtrip,
    )


ARTIFACT_KIND = "sanitized-v5-1-visible-unicode-mapping"
SCHEMA_VERSION = 3
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_visible_unicode_mapping.json"
)
LOCAL_VISIBLE_RECORD_PATH = Path(
    "analysis/local/v5_1_visible_script_record.json"
)
LOCAL_FONT_CATALOG_PATH = Path(
    "analysis/local/v5_1_font_catalog.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_visible_unicode_mapping.json"
)
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "captured_utc",
    "runtime_entry",
    "mapping",
    "renderer_chain_confirmed",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
RUNTIME_ENTRY_KEYS = {
    "physical_start",
    "logical_start",
    "mapped_bank",
    "record_length_bytes",
}
MAPPING_KEYS = {
    "decoded_symbol_count",
    "initial_page",
    "initial_page_candidate_count",
    "implicit_initial_page_used",
    "page_select_count",
    "visible_glyph_count",
    "unique_glyph_count",
    "ambiguous_glyph_count",
    "unmatched_glyph_count",
    "control_symbol_count",
    "terminator_count",
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


def validate_visible_unicode_mapping(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("visible Unicode mapping fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "visible-glyph-map-resolved",
            "visible-glyph-map-candidate",
            "visible-glyph-map-incomplete",
        }
    ):
        raise ValueError("visible Unicode mapping policy is invalid")
    if not _is_sha256(value["target_sha256"]):
        raise ValueError("visible Unicode mapping target is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("visible Unicode mapping timestamp is invalid")
    try:
        parsed_time = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("visible Unicode mapping timestamp is invalid") from error
    if parsed_time.tzinfo is None:
        raise ValueError("visible Unicode mapping timestamp must include UTC")

    runtime = value["runtime_entry"]
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_ENTRY_KEYS:
        raise ValueError("visible Unicode runtime fields do not match")
    for key, minimum, maximum in (
        ("physical_start", 0, 0x17BFFF),
        ("logical_start", 0x4000, 0x7FFF),
        ("mapped_bank", 0, 0xFF),
        ("record_length_bytes", 1, 0xFF),
    ):
        if not _bounded_int(runtime[key], minimum, maximum):
            raise ValueError(f"visible Unicode {key} is invalid")

    mapping = value["mapping"]
    if not isinstance(mapping, dict) or set(mapping) != MAPPING_KEYS:
        raise ValueError("visible Unicode mapping counts do not match")
    for key in MAPPING_KEYS - {"implicit_initial_page_used"}:
        if not _bounded_int(mapping[key], 0, 0x1000):
            raise ValueError(f"visible Unicode {key} is invalid")
    if (
        not isinstance(mapping["implicit_initial_page_used"], bool)
        or mapping["implicit_initial_page_used"]
        is not (mapping["page_select_count"] == 0)
        or mapping["initial_page"] > 243
        or mapping["initial_page_candidate_count"] > 244
        or mapping["implicit_initial_page_used"]
        is not (mapping["initial_page_candidate_count"] > 0)
        or mapping["decoded_symbol_count"] < mapping["visible_glyph_count"]
        or mapping["visible_glyph_count"]
        != mapping["unique_glyph_count"]
        + mapping["ambiguous_glyph_count"]
        + mapping["unmatched_glyph_count"]
        or mapping["terminator_count"] != 1
    ):
        raise ValueError("visible Unicode mapping counts are inconsistent")
    complete = (
        mapping["visible_glyph_count"] > 0
        and mapping["ambiguous_glyph_count"] == 0
        and mapping["unmatched_glyph_count"] == 0
        and value["renderer_chain_confirmed"] is True
    )
    expected_status = (
        "visible-glyph-map-candidate"
        if complete
        and mapping["implicit_initial_page_used"]
        and mapping["initial_page_candidate_count"] == 1
        else "visible-glyph-map-resolved"
        if complete
        else "visible-glyph-map-incomplete"
    )
    if value["status"] != expected_status:
        raise ValueError("visible Unicode mapping status is inconsistent")
    if value["local_payload_policy"] != (
        "symbols-codepoints-characters-and-text-local-only"
    ):
        raise ValueError("visible Unicode local payload policy is invalid")
    if value["translation_build_eligible"] is not False:
        raise ValueError("visible Unicode mapping cannot enable release builds")
    expected_checkpoint = {
        "visible-glyph-map-resolved": "extract-full-script-record-set",
        "visible-glyph-map-candidate": "confirm-runtime-initial-font-page",
        "visible-glyph-map-incomplete": "classify-visible-symbol-stream",
    }[expected_status]
    if value["next_checkpoint"] != expected_checkpoint:
        raise ValueError("visible Unicode next checkpoint is inconsistent")


def _map_visible_symbols_with_page(
    symbols: list[int],
    catalog: dict[tuple[int, int], dict[str, object]],
    initial_page: int,
) -> tuple[dict[str, object], dict[str, object]]:
    page = initial_page
    initial_page = page
    explicit_page_selected = False
    page_select_count = 0
    control_symbol_count = 0
    terminator_count = 0
    tokens: list[dict[str, object]] = []
    unique = 0
    ambiguous = 0
    unmatched = 0
    index = 0
    while index < len(symbols):
        symbol = symbols[index]
        if symbol == 0xC9:
            terminator_count += 1
            control_symbol_count += 1
            tokens.append({"kind": "terminator", "symbol": symbol})
            index += 1
            continue
        if symbol == 0x5F:
            if index + 2 >= len(symbols):
                raise ValueError("truncated page-select control")
            high = symbols[index + 1]
            low = symbols[index + 2]
            if not 0x02 <= high <= 0x11 or not 0x02 <= low <= 0x11:
                raise ValueError("page-select operand is out of range")
            page = (high - 2) << 4 | (low - 2)
            explicit_page_selected = True
            page_select_count += 1
            control_symbol_count += 3
            tokens.append(
                {
                    "kind": "page-select",
                    "symbols": symbols[index : index + 3],
                    "page": page,
                }
            )
            index += 3
            continue
        if 0x02 <= symbol <= 0x20:
            entry = catalog.get((page, symbol))
            codepoints = [] if entry is None else entry.get("codepoints", [])
            characters = [] if entry is None else entry.get("characters", [])
            if not isinstance(codepoints, list) or not isinstance(characters, list):
                raise ValueError("font catalog candidate list is invalid")
            if len(codepoints) == 1:
                unique += 1
                status = "unique"
            elif codepoints:
                ambiguous += 1
                status = "ambiguous"
            else:
                unmatched += 1
                status = "unmatched"
            tokens.append(
                {
                    "kind": "glyph",
                    "page": page,
                    "symbol": symbol,
                    "status": status,
                    "codepoints": codepoints,
                    "characters": characters,
                }
            )
        else:
            control_symbol_count += 1
            tokens.append({"kind": "control", "symbol": symbol})
        index += 1

    visible = unique + ambiguous + unmatched
    safe = {
        "decoded_symbol_count": len(symbols),
        "initial_page": initial_page,
        "implicit_initial_page_used": not explicit_page_selected,
        "page_select_count": page_select_count,
        "visible_glyph_count": visible,
        "unique_glyph_count": unique,
        "ambiguous_glyph_count": ambiguous,
        "unmatched_glyph_count": unmatched,
        "control_symbol_count": control_symbol_count,
        "terminator_count": terminator_count,
    }
    local = {"tokens": tokens}
    return safe, local


def map_visible_symbols(
    symbols: list[int],
    catalog_entries: list[dict[str, object]],
) -> tuple[dict[str, object], dict[str, object]]:
    catalog: dict[tuple[int, int], dict[str, object]] = {}
    for entry in catalog_entries:
        if not isinstance(entry, dict):
            raise ValueError("font catalog entry is invalid")
        page = entry.get("page")
        symbol = entry.get("symbol")
        if not isinstance(page, int) or not isinstance(symbol, int):
            raise ValueError("font catalog coordinate is invalid")
        catalog[(page, symbol)] = entry

    if 0x5F in symbols:
        safe, local = _map_visible_symbols_with_page(symbols, catalog, 0)
        safe["initial_page_candidate_count"] = 0
        local["initial_page_candidates"] = []
        return safe, local

    trials: list[tuple[tuple[int, int, int], dict[str, object], dict[str, object]]] = []
    for initial_page in range(244):
        safe, local = _map_visible_symbols_with_page(
            symbols,
            catalog,
            initial_page,
        )
        score = (
            int(safe["unmatched_glyph_count"]),
            int(safe["ambiguous_glyph_count"]),
            -int(safe["unique_glyph_count"]),
        )
        trials.append((score, safe, local))
    best_score = min(item[0] for item in trials)
    best = [item for item in trials if item[0] == best_score]
    _, selected_safe, selected_local = min(
        best,
        key=lambda item: int(item[1]["initial_page"]),
    )
    selected_safe["initial_page_candidate_count"] = len(best)
    selected_local["initial_page_candidates"] = [
        {
            "page": int(item[1]["initial_page"]),
            "unique_glyph_count": int(item[1]["unique_glyph_count"]),
            "ambiguous_glyph_count": int(item[1]["ambiguous_glyph_count"]),
            "unmatched_glyph_count": int(item[1]["unmatched_glyph_count"]),
        }
        for item in best
    ]
    return selected_safe, selected_local


def _load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    visible_path = root / VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH
    renderer_path = root / RENDERER_OUTPUT_TRACE_RELATIVE_PATH
    local_visible_path = root / LOCAL_VISIBLE_RECORD_PATH
    catalog_path = root / LOCAL_FONT_CATALOG_PATH
    prerequisites = (
        visible_path,
        renderer_path,
        local_visible_path,
        catalog_path,
    )
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Visible Unicode mapping is not ready")
            return 0
        raise SystemExit("visible Unicode mapping input is missing")

    visible = _load_object(visible_path)
    validate_visible_script_roundtrip(visible)
    renderer = _load_object(renderer_path)
    validate_renderer_output_trace(renderer)
    if renderer["consumer_chain_confirmed"] is not True:
        if args.if_ready:
            print("Visible Unicode mapping waits for the renderer chain")
            return 0
        raise SystemExit("renderer chain is not confirmed")
    local_visible = _load_object(local_visible_path)
    catalog = _load_object(catalog_path)
    if (
        local_visible.get("baseline_target_sha256")
        != visible["baseline_target_sha256"]
        or renderer["target_sha256"] != visible["baseline_target_sha256"]
    ):
        raise ValueError("visible Unicode mapping identities disagree")
    raw_symbols = local_visible.get("symbols_hex")
    if not isinstance(raw_symbols, list) or not all(
        isinstance(item, str)
        and re.fullmatch(r"0x[0-9A-Fa-f]{2}", item) is not None
        for item in raw_symbols
    ):
        raise ValueError("local visible symbols are invalid")
    symbols = [int(item, 16) for item in raw_symbols]
    roundtrip = visible["roundtrip"]
    if (
        not isinstance(roundtrip, dict)
        or len(symbols) != int(roundtrip["decoded_symbol_count"])
    ):
        raise ValueError("visible symbol count disagrees with the roundtrip")
    if (
        catalog.get("artifact_kind")
        != "local-v5-1-galmuri7-font-catalog"
        or catalog.get("status") != "verified-static-local-analysis"
        or not isinstance(catalog.get("entries"), list)
    ):
        raise ValueError("local font catalog is invalid")

    safe_mapping, local_mapping = map_visible_symbols(
        symbols,
        catalog["entries"],
    )
    complete = (
        safe_mapping["visible_glyph_count"] > 0
        and safe_mapping["ambiguous_glyph_count"] == 0
        and safe_mapping["unmatched_glyph_count"] == 0
        and safe_mapping["terminator_count"] == 1
    )
    status = (
        "visible-glyph-map-candidate"
        if complete
        and safe_mapping["implicit_initial_page_used"]
        and safe_mapping["initial_page_candidate_count"] == 1
        else "visible-glyph-map-resolved"
        if complete
        else "visible-glyph-map-incomplete"
    )
    runtime = visible["runtime_entry"]
    assert isinstance(runtime, dict)
    captured_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    safe: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": visible["baseline_target_sha256"],
        "captured_utc": captured_utc,
        "runtime_entry": {
            key: runtime[key]
            for key in RUNTIME_ENTRY_KEYS
        },
        "mapping": safe_mapping,
        "renderer_chain_confirmed": True,
        "local_payload_policy": (
            "symbols-codepoints-characters-and-text-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": {
            "visible-glyph-map-resolved": "extract-full-script-record-set",
            "visible-glyph-map-candidate": "confirm-runtime-initial-font-page",
            "visible-glyph-map-incomplete": "classify-visible-symbol-stream",
        }[status],
    }
    validate_visible_unicode_mapping(safe)
    local = {
        "artifact_kind": "local-v5-1-visible-unicode-mapping",
        "schema_version": 1,
        "target_sha256": safe["target_sha256"],
        "captured_utc": captured_utc,
        "symbols_hex": raw_symbols,
        "mapping": local_mapping,
        "publication_policy": (
            "never-publish-symbols-codepoints-characters-or-text"
        ),
    }
    publish_path = root / PUBLISH_RELATIVE_PATH
    local_path = root / LOCAL_REPORT_PATH
    publish_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    publish_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR visible Unicode mapping: {publish_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
