#!/usr/bin/env python3
"""Classify unresolved glyphs across the expanded target population.

Glyph coordinates, masks, Unicode candidates, characters, and overrides remain
in an ignored phone-local report.  Only distance buckets and counts are safe.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .fetch_galmuri7_bdf import BDF_SHA256, BDF_SIZE, digest
    from .patch_io import sha256_file
    from .v5_1_engine import EXPECTED_PATCH_SHA256
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_target_group_population_decode import (
        LOCAL_REPORT_PATH as LOCAL_DECODE_PATH,
        PUBLISH_RELATIVE_PATH as DECODE_PATH,
        validate_target_group_population_decode,
    )
    from .v5_1_unmatched_glyph_fuzzy import (
        DEFAULT_BDF,
        DEFAULT_PATCH,
        HIGH_CONFIDENCE_MAX_DISTANCE,
        HIGH_CONFIDENCE_MIN_MARGIN,
        UNMATCHED_KEYS,
        analyze_unmatched_glyphs,
    )
except ImportError:  # direct script execution
    from fetch_galmuri7_bdf import BDF_SHA256, BDF_SIZE, digest
    from patch_io import sha256_file
    from v5_1_engine import EXPECTED_PATCH_SHA256
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_target_group_population_decode import (
        LOCAL_REPORT_PATH as LOCAL_DECODE_PATH,
        PUBLISH_RELATIVE_PATH as DECODE_PATH,
        validate_target_group_population_decode,
    )
    from v5_1_unmatched_glyph_fuzzy import (
        DEFAULT_BDF,
        DEFAULT_PATCH,
        HIGH_CONFIDENCE_MAX_DISTANCE,
        HIGH_CONFIDENCE_MIN_MARGIN,
        UNMATCHED_KEYS,
        analyze_unmatched_glyphs,
    )


ARTIFACT_KIND = "sanitized-v5-1-target-group-expanded-glyphs"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_target_group_expanded_glyphs.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_target_group_expanded_glyphs.json"
)
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_population_decode_sha256",
    "source_font_reference_sha256",
    "captured_utc",
    "unmatched",
    "high_confidence_policy",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
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


def build_target_group_expanded_glyphs(
    *,
    target_sha256: str,
    source_population_decode_sha256: str,
    source_font_reference_sha256: str,
    unmatched: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    high = int(unmatched["high_confidence_distinct_count"])
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "expanded-glyph-high-confidence-overrides-ready"
            if high > 0
            else "expanded-glyphs-require-non-hangul-classification"
        ),
        "target_sha256": target_sha256,
        "source_population_decode_sha256":
            source_population_decode_sha256,
        "source_font_reference_sha256": source_font_reference_sha256,
        "captured_utc": captured_utc,
        "unmatched": {
            key: int(unmatched[key])
            for key in UNMATCHED_KEYS
        },
        "high_confidence_policy": {
            "maximum_pixel_distance": HIGH_CONFIDENCE_MAX_DISTANCE,
            "minimum_distance_margin": HIGH_CONFIDENCE_MIN_MARGIN,
            "unique_nearest_required": True,
            "quality_inference_only": True,
        },
        "local_payload_policy": (
            "glyph-coordinates-masks-codepoints-characters-and-overrides-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": "assemble-expanded-target-script-corpus",
    }
    validate_target_group_expanded_glyphs(value)
    return value


def validate_target_group_expanded_glyphs(
    value: dict[str, object],
) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("expanded glyph fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "expanded-glyph-high-confidence-overrides-ready",
            "expanded-glyphs-require-non-hangul-classification",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_population_decode_sha256"])
        or not _is_sha256(value["source_font_reference_sha256"])
    ):
        raise ValueError("expanded glyph policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("expanded glyph timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("expanded glyph timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("expanded glyph timestamp needs UTC")
    unmatched = value["unmatched"]
    if not isinstance(unmatched, dict) or set(unmatched) != UNMATCHED_KEYS:
        raise ValueError("expanded glyph counts do not match")
    for key in UNMATCHED_KEYS:
        if not _bounded_int(unmatched[key], 0, 0x1000000):
            raise ValueError(f"expanded glyph {key} is invalid")
    distinct = int(unmatched["distinct_glyph_count"])
    in_range = int(unmatched["in_range_distinct_count"])
    if (
        unmatched["unique_nearest_distinct_count"]
        + unmatched["tied_nearest_distinct_count"] != in_range
        or in_range + unmatched["out_of_range_distinct_count"] != distinct
        or unmatched["out_of_range_occurrence_count"]
        > unmatched["occurrence_count"]
        or sum(
            unmatched[key]
            for key in (
                "distance_zero_distinct_count",
                "distance_one_distinct_count",
                "distance_two_distinct_count",
                "distance_three_or_four_distinct_count",
                "distance_over_four_distinct_count",
            )
        ) != in_range
        or unmatched["high_confidence_distinct_count"] > in_range
        or unmatched["high_confidence_occurrence_count"]
        > unmatched["occurrence_count"]
    ):
        raise ValueError("expanded glyph aggregates are inconsistent")
    expected_policy = {
        "maximum_pixel_distance": HIGH_CONFIDENCE_MAX_DISTANCE,
        "minimum_distance_margin": HIGH_CONFIDENCE_MIN_MARGIN,
        "unique_nearest_required": True,
        "quality_inference_only": True,
    }
    expected_status = (
        "expanded-glyph-high-confidence-overrides-ready"
        if unmatched["high_confidence_distinct_count"] > 0
        else "expanded-glyphs-require-non-hangul-classification"
    )
    if (
        value["status"] != expected_status
        or value["high_confidence_policy"] != expected_policy
        or value["local_payload_policy"]
        != "glyph-coordinates-masks-codepoints-characters-and-overrides-local-only"
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != "assemble-expanded-target-script-corpus"
    ):
        raise ValueError("expanded glyph result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--patch", type=Path, default=DEFAULT_PATCH)
    parser.add_argument("--bdf", type=Path, default=DEFAULT_BDF)
    args = parser.parse_args()
    patch_path = args.patch if args.patch.is_absolute() else root / args.patch
    bdf_path = args.bdf if args.bdf.is_absolute() else root / args.bdf
    safe_decode_path = root / DECODE_PATH
    local_decode_path = root / LOCAL_DECODE_PATH
    prerequisites = (
        patch_path,
        bdf_path,
        safe_decode_path,
        local_decode_path,
    )
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Expanded target glyph analysis is not ready")
            return 0
        raise SystemExit("expanded target glyph input is missing")
    patch = patch_path.read_bytes()
    bdf = bdf_path.read_bytes()
    if (
        sha256_file(patch_path) != EXPECTED_PATCH_SHA256
        or len(bdf) != BDF_SIZE
        or digest(bdf) != BDF_SHA256
    ):
        raise ValueError("expanded target glyph identity mismatch")
    safe_decode = _load_json_object(safe_decode_path)
    local_decode = _load_json_object(local_decode_path)
    validate_target_group_population_decode(safe_decode)
    if local_decode.get("target_sha256") != safe_decode["target_sha256"]:
        raise ValueError("expanded glyph target identity disagrees")
    quality = local_decode.get("quality_analysis")
    records = quality.get("resolved_records") if isinstance(quality, dict) else None
    if not isinstance(records, list):
        raise ValueError("expanded glyph local records are missing")
    counts, local_analysis = analyze_unmatched_glyphs(
        patch=patch,
        bdf=bdf,
        records=records,
    )
    if (
        counts["occurrence_count"]
        != safe_decode["decode"]["selected_unmatched_glyph_count"]
    ):
        raise ValueError("expanded glyph occurrence count changed")
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_target_group_expanded_glyphs(
        target_sha256=str(safe_decode["target_sha256"]),
        source_population_decode_sha256=sha256_file(safe_decode_path),
        source_font_reference_sha256=BDF_SHA256,
        unmatched=counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-target-group-expanded-glyphs",
        "schema_version": 1,
        "target_sha256": safe_decode["target_sha256"],
        "captured_utc": captured_utc,
        "analysis": local_analysis,
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
    print(f"SFKR expanded target glyphs: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
