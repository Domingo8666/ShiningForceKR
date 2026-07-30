#!/usr/bin/env python3
"""Resolve expanded-corpus glyphs by exact non-Hangul bitmap matches.

The earlier font catalogue deliberately covered Hangul syllables only.  This
stage compares the remaining patch tiles with every visible 8×8 glyph in the
verified Galmuri7 BDF.  Only unique, pixel-exact matches become overrides.
Coordinates, masks, codepoints, characters, and overrides stay phone-local.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import unicodedata

try:
    from .fetch_galmuri7_bdf import BDF_SHA256, BDF_SIZE, digest
    from .patch_io import sha256_file
    from .v5_1_engine import EXPECTED_PATCH_SHA256
    from .v5_1_font_catalog import parse_bdf_glyphs
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_target_group_expanded_glyphs import (
        LOCAL_REPORT_PATH as LOCAL_EXPANDED_GLYPHS_PATH,
        PUBLISH_RELATIVE_PATH as EXPANDED_GLYPHS_PATH,
        validate_target_group_expanded_glyphs,
    )
    from .v5_1_unmatched_glyph_fuzzy import DEFAULT_BDF, DEFAULT_PATCH
except ImportError:  # direct script execution
    from fetch_galmuri7_bdf import BDF_SHA256, BDF_SIZE, digest
    from patch_io import sha256_file
    from v5_1_engine import EXPECTED_PATCH_SHA256
    from v5_1_font_catalog import parse_bdf_glyphs
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_target_group_expanded_glyphs import (
        LOCAL_REPORT_PATH as LOCAL_EXPANDED_GLYPHS_PATH,
        PUBLISH_RELATIVE_PATH as EXPANDED_GLYPHS_PATH,
        validate_target_group_expanded_glyphs,
    )
    from v5_1_unmatched_glyph_fuzzy import DEFAULT_BDF, DEFAULT_PATCH


ARTIFACT_KIND = "sanitized-v5-1-target-group-non-hangul-glyphs"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_target_group_non_hangul_glyphs.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_target_group_non_hangul_glyphs.json"
)
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_expanded_glyphs_sha256",
    "source_font_reference_sha256",
    "captured_utc",
    "classification",
    "exact_match_policy",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
CLASSIFICATION_KEYS = {
    "occurrence_count",
    "distinct_glyph_count",
    "in_range_distinct_count",
    "outside_font_range_distinct_count",
    "unique_exact_distinct_count",
    "unique_exact_occurrence_count",
    "ambiguous_exact_distinct_count",
    "ambiguous_exact_occurrence_count",
    "unmatched_distinct_count",
    "unmatched_occurrence_count",
    "eligible_reference_glyph_count",
}


def _eligible_non_hangul(codepoint: int) -> bool:
    character = chr(codepoint)
    return not (0xAC00 <= codepoint <= 0xD7A3) and (
        unicodedata.category(character)[0] in {
            "L",
            "N",
            "P",
            "S",
            "Z",
        }
    )


def classify_exact_non_hangul(
    *,
    local_glyphs: list[dict[str, object]],
    reference_glyphs: dict[int, tuple[int, ...]],
) -> tuple[dict[str, int], dict[str, object]]:
    reverse: dict[tuple[int, ...], list[int]] = defaultdict(list)
    eligible_count = 0
    for codepoint, mask in reference_glyphs.items():
        if _eligible_non_hangul(codepoint):
            reverse[mask].append(codepoint)
            eligible_count += 1
    counts = {key: 0 for key in CLASSIFICATION_KEYS}
    counts["eligible_reference_glyph_count"] = eligible_count
    details: list[dict[str, object]] = []
    overrides: list[dict[str, object]] = []
    for glyph in local_glyphs:
        if not isinstance(glyph, dict):
            raise ValueError("non-Hangul glyph entry is invalid")
        occurrence_count = glyph.get("occurrence_count")
        page = glyph.get("page")
        symbol = glyph.get("symbol")
        if (
            not isinstance(occurrence_count, int)
            or isinstance(occurrence_count, bool)
            or occurrence_count < 1
            or not isinstance(page, int)
            or not isinstance(symbol, int)
        ):
            raise ValueError("non-Hangul glyph fields are invalid")
        counts["occurrence_count"] += occurrence_count
        counts["distinct_glyph_count"] += 1
        if glyph.get("status") == "outside-font-page-range":
            counts["outside_font_range_distinct_count"] += 1
            counts["unmatched_occurrence_count"] += occurrence_count
            details.append(
                {
                    "page": page,
                    "symbol": symbol,
                    "occurrence_count": occurrence_count,
                    "status": "outside-font-page-range",
                }
            )
            continue
        rows = glyph.get("mask_rows_hex")
        if (
            not isinstance(rows, list)
            or len(rows) != 8
            or any(
                not isinstance(row, str)
                or re.fullmatch(r"[0-9A-Fa-f]{2}", row) is None
                for row in rows
            )
        ):
            raise ValueError("non-Hangul glyph mask is invalid")
        counts["in_range_distinct_count"] += 1
        mask = tuple(int(row, 16) for row in rows)
        candidates = sorted(reverse.get(mask, []))
        if len(candidates) == 1:
            status = "unique-exact-non-hangul"
            counts["unique_exact_distinct_count"] += 1
            counts["unique_exact_occurrence_count"] += occurrence_count
            overrides.append(
                {
                    "page": page,
                    "symbol": symbol,
                    "codepoint": candidates[0],
                    "character": chr(candidates[0]),
                    "resolution_source": "exact-non-hangul-bdf",
                }
            )
        elif candidates:
            status = "ambiguous-exact-non-hangul"
            counts["ambiguous_exact_distinct_count"] += 1
            counts["ambiguous_exact_occurrence_count"] += occurrence_count
        else:
            status = "unmatched"
            counts["unmatched_distinct_count"] += 1
            counts["unmatched_occurrence_count"] += occurrence_count
        details.append(
            {
                "page": page,
                "symbol": symbol,
                "occurrence_count": occurrence_count,
                "mask_rows_hex": rows,
                "status": status,
                "candidate_codepoints": candidates,
                "candidate_characters": [
                    chr(codepoint)
                    for codepoint in candidates
                ],
            }
        )
    return counts, {
        "glyphs": details,
        "exact_non_hangul_overrides": overrides,
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


def build_target_group_non_hangul_glyphs(
    *,
    target_sha256: str,
    source_expanded_glyphs_sha256: str,
    source_font_reference_sha256: str,
    classification: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    exact = int(classification["unique_exact_distinct_count"])
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "exact-non-hangul-overrides-ready"
            if exact > 0
            else "non-hangul-glyphs-unresolved"
        ),
        "target_sha256": target_sha256,
        "source_expanded_glyphs_sha256": source_expanded_glyphs_sha256,
        "source_font_reference_sha256": source_font_reference_sha256,
        "captured_utc": captured_utc,
        "classification": {
            key: int(classification[key])
            for key in CLASSIFICATION_KEYS
        },
        "exact_match_policy": {
            "pixel_distance": 0,
            "unique_reference_required": True,
            "non_hangul_reference_only": True,
            "visible_unicode_category_required": True,
        },
        "local_payload_policy": (
            "glyph-coordinates-masks-codepoints-characters-and-overrides-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": "assemble-expanded-target-script-corpus",
    }
    validate_target_group_non_hangul_glyphs(value)
    return value


def validate_target_group_non_hangul_glyphs(
    value: dict[str, object],
) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("non-Hangul glyph fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "exact-non-hangul-overrides-ready",
            "non-hangul-glyphs-unresolved",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_expanded_glyphs_sha256"])
        or not _is_sha256(value["source_font_reference_sha256"])
    ):
        raise ValueError("non-Hangul glyph policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("non-Hangul glyph timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("non-Hangul glyph timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("non-Hangul glyph timestamp needs UTC")
    counts = value["classification"]
    if not isinstance(counts, dict) or set(counts) != CLASSIFICATION_KEYS:
        raise ValueError("non-Hangul glyph counts do not match")
    for key in CLASSIFICATION_KEYS:
        if not _bounded_int(counts[key], 0, 0x1000000):
            raise ValueError(f"non-Hangul glyph {key} is invalid")
    distinct = int(counts["distinct_glyph_count"])
    occurrences = int(counts["occurrence_count"])
    exact = int(counts["unique_exact_distinct_count"])
    expected_status = (
        "exact-non-hangul-overrides-ready"
        if exact > 0
        else "non-hangul-glyphs-unresolved"
    )
    if (
        counts["in_range_distinct_count"]
        + counts["outside_font_range_distinct_count"] != distinct
        or counts["unique_exact_distinct_count"]
        + counts["ambiguous_exact_distinct_count"]
        + counts["unmatched_distinct_count"]
        != counts["in_range_distinct_count"]
        or counts["unique_exact_occurrence_count"]
        + counts["ambiguous_exact_occurrence_count"]
        + counts["unmatched_occurrence_count"] != occurrences
        or value["status"] != expected_status
        or value["exact_match_policy"]
        != {
            "pixel_distance": 0,
            "unique_reference_required": True,
            "non_hangul_reference_only": True,
            "visible_unicode_category_required": True,
        }
        or value["local_payload_policy"]
        != "glyph-coordinates-masks-codepoints-characters-and-overrides-local-only"
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != "assemble-expanded-target-script-corpus"
    ):
        raise ValueError("non-Hangul glyph result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--patch", type=Path, default=DEFAULT_PATCH)
    parser.add_argument("--bdf", type=Path, default=DEFAULT_BDF)
    args = parser.parse_args()
    patch_path = args.patch if args.patch.is_absolute() else root / args.patch
    bdf_path = args.bdf if args.bdf.is_absolute() else root / args.bdf
    safe_glyphs_path = root / EXPANDED_GLYPHS_PATH
    local_glyphs_path = root / LOCAL_EXPANDED_GLYPHS_PATH
    if not all(
        path.is_file()
        for path in (
            patch_path,
            bdf_path,
            safe_glyphs_path,
            local_glyphs_path,
        )
    ):
        if args.if_ready:
            print("Exact non-Hangul glyph analysis is not ready")
            return 0
        raise SystemExit("exact non-Hangul glyph input is missing")
    patch = patch_path.read_bytes()
    bdf = bdf_path.read_bytes()
    if (
        sha256_file(patch_path) != EXPECTED_PATCH_SHA256
        or len(bdf) != BDF_SIZE
        or digest(bdf) != BDF_SHA256
    ):
        raise ValueError("exact non-Hangul glyph identity mismatch")
    safe_glyphs = _load_json_object(safe_glyphs_path)
    local_glyphs = _load_json_object(local_glyphs_path)
    validate_target_group_expanded_glyphs(safe_glyphs)
    if local_glyphs.get("target_sha256") != safe_glyphs["target_sha256"]:
        raise ValueError("exact non-Hangul glyph target disagrees")
    glyph_entries = local_glyphs.get("analysis", {}).get("glyphs")
    if not isinstance(glyph_entries, list):
        raise ValueError("exact non-Hangul local glyphs are missing")
    counts, analysis = classify_exact_non_hangul(
        local_glyphs=glyph_entries,
        reference_glyphs=parse_bdf_glyphs(bdf),
    )
    if (
        counts["occurrence_count"]
        != safe_glyphs["unmatched"]["occurrence_count"]
        or counts["distinct_glyph_count"]
        != safe_glyphs["unmatched"]["distinct_glyph_count"]
    ):
        raise ValueError("exact non-Hangul glyph population changed")
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_target_group_non_hangul_glyphs(
        target_sha256=str(safe_glyphs["target_sha256"]),
        source_expanded_glyphs_sha256=sha256_file(safe_glyphs_path),
        source_font_reference_sha256=BDF_SHA256,
        classification=counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-target-group-non-hangul-glyphs",
        "schema_version": 1,
        "target_sha256": safe_glyphs["target_sha256"],
        "captured_utc": captured_utc,
        "analysis": analysis,
        "publication_policy": (
            "never-publish-glyph-coordinates-masks-codepoints-characters-or-overrides"
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
    print(f"SFKR exact non-Hangul glyphs: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
