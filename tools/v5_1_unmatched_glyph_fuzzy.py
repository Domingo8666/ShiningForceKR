#!/usr/bin/env python3
"""Find conservative Galmuri7 near-matches for unresolved group glyphs.

Glyph coordinates, masks, Unicode candidates, characters, and overrides remain
in an ignored phone-local report.  Only distance buckets and aggregate counts
are publishable.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .fetch_galmuri7_bdf import BDF_SHA256, BDF_SIZE, digest
    from .patch_io import (
        PatchError,
        extract_bps_target_literals,
        sha256_file,
    )
    from .v5_1_engine import EXPECTED_PATCH_SHA256
    from .v5_1_font_catalog import parse_bdf_hangul, tile_ink_mask
    from .v5_1_group_text_candidate_resolution import (
        LOCAL_REPORT_PATH as LOCAL_TEXT_CANDIDATE_PATH,
        PUBLISH_RELATIVE_PATH as TEXT_CANDIDATE_PATH,
        validate_group_text_candidate_resolution,
    )
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_test_phrase import FONT_TILE_BYTES, font_tile_offset
except ImportError:  # direct script execution
    from fetch_galmuri7_bdf import BDF_SHA256, BDF_SIZE, digest
    from patch_io import PatchError, extract_bps_target_literals, sha256_file
    from v5_1_engine import EXPECTED_PATCH_SHA256
    from v5_1_font_catalog import parse_bdf_hangul, tile_ink_mask
    from v5_1_group_text_candidate_resolution import (
        LOCAL_REPORT_PATH as LOCAL_TEXT_CANDIDATE_PATH,
        PUBLISH_RELATIVE_PATH as TEXT_CANDIDATE_PATH,
        validate_group_text_candidate_resolution,
    )
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_test_phrase import FONT_TILE_BYTES, font_tile_offset


ARTIFACT_KIND = "sanitized-v5-1-unmatched-glyph-fuzzy"
SCHEMA_VERSION = 1
DEFAULT_PATCH = Path("patch/Final_Conflict_Japan_to_Korean_v5.1.bps")
DEFAULT_BDF = Path("analysis/local/Galmuri7.bdf")
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_unmatched_glyph_fuzzy.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_unmatched_glyph_fuzzy.json")
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_text_candidate_sha256",
    "source_font_reference_sha256",
    "captured_utc",
    "unmatched",
    "high_confidence_policy",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
UNMATCHED_KEYS = {
    "occurrence_count",
    "distinct_glyph_count",
    "unique_nearest_distinct_count",
    "tied_nearest_distinct_count",
    "distance_zero_distinct_count",
    "distance_one_distinct_count",
    "distance_two_distinct_count",
    "distance_three_or_four_distinct_count",
    "distance_over_four_distinct_count",
    "high_confidence_distinct_count",
    "high_confidence_occurrence_count",
}
HIGH_CONFIDENCE_MAX_DISTANCE = 2
HIGH_CONFIDENCE_MIN_MARGIN = 2


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


def mask_distance(
    left: tuple[int, ...],
    right: tuple[int, ...],
) -> int:
    if len(left) != 8 or len(right) != 8:
        raise ValueError("glyph masks must have eight rows")
    return sum((a ^ b).bit_count() for a, b in zip(left, right, strict=True))


def nearest_glyphs(
    mask: tuple[int, ...],
    glyphs: dict[int, tuple[int, ...]],
) -> dict[str, object]:
    if not glyphs:
        raise ValueError("reference glyph set is empty")
    ranked = sorted(
        (mask_distance(mask, candidate), codepoint)
        for codepoint, candidate in glyphs.items()
    )
    best_distance = ranked[0][0]
    best = [
        codepoint
        for distance, codepoint in ranked
        if distance == best_distance
    ]
    second_distance = next(
        (
            distance
            for distance, _ in ranked
            if distance > best_distance
        ),
        64,
    )
    margin = second_distance - best_distance
    high_confidence = (
        len(best) == 1
        and best_distance <= HIGH_CONFIDENCE_MAX_DISTANCE
        and margin >= HIGH_CONFIDENCE_MIN_MARGIN
    )
    return {
        "best_distance": best_distance,
        "second_distance": second_distance,
        "distance_margin": margin,
        "best_codepoints": best,
        "high_confidence": high_confidence,
    }


def analyze_unmatched_glyphs(
    *,
    patch: bytes,
    bdf: bytes,
    records: list[dict[str, object]],
) -> tuple[dict[str, int], dict[str, object]]:
    sparse = extract_bps_target_literals(patch)
    glyphs = parse_bdf_hangul(bdf)
    occurrences: dict[tuple[int, int], int] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("fuzzy glyph record is invalid")
        tokens = record.get("tokens")
        if not isinstance(tokens, list):
            raise ValueError("fuzzy glyph tokens are missing")
        for token in tokens:
            if (
                isinstance(token, dict)
                and token.get("kind") == "glyph"
                and token.get("status") == "unmatched"
            ):
                page = token.get("page")
                symbol = token.get("symbol")
                if not isinstance(page, int) or not isinstance(symbol, int):
                    raise ValueError("fuzzy glyph coordinate is invalid")
                key = (page, symbol)
                occurrences[key] = occurrences.get(key, 0) + 1
    local_glyphs: list[dict[str, object]] = []
    buckets = {
        "distance_zero_distinct_count": 0,
        "distance_one_distinct_count": 0,
        "distance_two_distinct_count": 0,
        "distance_three_or_four_distinct_count": 0,
        "distance_over_four_distinct_count": 0,
    }
    unique_nearest = 0
    tied_nearest = 0
    high_distinct = 0
    high_occurrences = 0
    overrides: list[dict[str, object]] = []
    for (page, symbol), occurrence_count in sorted(occurrences.items()):
        offset = font_tile_offset(page, symbol)
        end = offset + FONT_TILE_BYTES
        if any(value == 0 for value in sparse.known[offset:end]):
            raise PatchError("fuzzy glyph tile is not source-independent")
        mask = tile_ink_mask(sparse.data[offset:end])
        nearest = nearest_glyphs(mask, glyphs)
        best = nearest["best_codepoints"]
        assert isinstance(best, list)
        unique_nearest += int(len(best) == 1)
        tied_nearest += int(len(best) > 1)
        distance = int(nearest["best_distance"])
        if distance == 0:
            bucket = "distance_zero_distinct_count"
        elif distance == 1:
            bucket = "distance_one_distinct_count"
        elif distance == 2:
            bucket = "distance_two_distinct_count"
        elif distance <= 4:
            bucket = "distance_three_or_four_distinct_count"
        else:
            bucket = "distance_over_four_distinct_count"
        buckets[bucket] += 1
        if nearest["high_confidence"]:
            high_distinct += 1
            high_occurrences += occurrence_count
            overrides.append(
                {
                    "page": page,
                    "symbol": symbol,
                    "codepoint": best[0],
                    "character": chr(best[0]),
                    "distance": distance,
                    "distance_margin": nearest["distance_margin"],
                }
            )
        local_glyphs.append(
            {
                "page": page,
                "symbol": symbol,
                "occurrence_count": occurrence_count,
                "mask_rows_hex": [f"{row:02X}" for row in mask],
                **nearest,
                "best_characters": [chr(value) for value in best],
            }
        )
    safe_counts = {
        "occurrence_count": sum(occurrences.values()),
        "distinct_glyph_count": len(occurrences),
        "unique_nearest_distinct_count": unique_nearest,
        "tied_nearest_distinct_count": tied_nearest,
        **buckets,
        "high_confidence_distinct_count": high_distinct,
        "high_confidence_occurrence_count": high_occurrences,
    }
    local = {
        "glyphs": local_glyphs,
        "high_confidence_overrides": overrides,
    }
    return safe_counts, local


def build_unmatched_glyph_fuzzy(
    *,
    target_sha256: str,
    source_text_candidate_sha256: str,
    source_font_reference_sha256: str,
    unmatched: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    high = int(unmatched["high_confidence_distinct_count"])
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "unmatched-glyph-high-confidence-overrides-ready"
            if high > 0
            else "unmatched-glyphs-require-non-hangul-classification"
        ),
        "target_sha256": target_sha256,
        "source_text_candidate_sha256": source_text_candidate_sha256,
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
        "next_checkpoint": "assemble-provisional-target-script-corpus",
    }
    validate_unmatched_glyph_fuzzy(safe)
    return safe


def validate_unmatched_glyph_fuzzy(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("unmatched glyph fuzzy fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "unmatched-glyph-high-confidence-overrides-ready",
            "unmatched-glyphs-require-non-hangul-classification",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "source_text_candidate_sha256",
                "source_font_reference_sha256",
            )
        )
    ):
        raise ValueError("unmatched glyph fuzzy policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("unmatched glyph fuzzy timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("unmatched glyph fuzzy timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("unmatched glyph fuzzy timestamp must include UTC")
    unmatched = value["unmatched"]
    if not isinstance(unmatched, dict) or set(unmatched) != UNMATCHED_KEYS:
        raise ValueError("unmatched glyph fuzzy counts do not match")
    for key in UNMATCHED_KEYS:
        if not _bounded_int(unmatched[key], 0, 0x1000000):
            raise ValueError(f"unmatched glyph fuzzy {key} is invalid")
    distinct = int(unmatched["distinct_glyph_count"])
    if (
        unmatched["unique_nearest_distinct_count"]
        + unmatched["tied_nearest_distinct_count"] != distinct
        or sum(
            unmatched[key]
            for key in (
                "distance_zero_distinct_count",
                "distance_one_distinct_count",
                "distance_two_distinct_count",
                "distance_three_or_four_distinct_count",
                "distance_over_four_distinct_count",
            )
        ) != distinct
        or unmatched["high_confidence_distinct_count"] > distinct
        or unmatched["high_confidence_occurrence_count"]
        > unmatched["occurrence_count"]
    ):
        raise ValueError("unmatched glyph fuzzy aggregates are inconsistent")
    policy = value["high_confidence_policy"]
    if (
        not isinstance(policy, dict)
        or policy
        != {
            "maximum_pixel_distance": HIGH_CONFIDENCE_MAX_DISTANCE,
            "minimum_distance_margin": HIGH_CONFIDENCE_MIN_MARGIN,
            "unique_nearest_required": True,
            "quality_inference_only": True,
        }
    ):
        raise ValueError("unmatched glyph fuzzy confidence policy is invalid")
    expected_status = (
        "unmatched-glyph-high-confidence-overrides-ready"
        if unmatched["high_confidence_distinct_count"] > 0
        else "unmatched-glyphs-require-non-hangul-classification"
    )
    if (
        value["status"] != expected_status
        or value["local_payload_policy"]
        != "glyph-coordinates-masks-codepoints-characters-and-overrides-local-only"
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != "assemble-provisional-target-script-corpus"
    ):
        raise ValueError("unmatched glyph fuzzy result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--patch", type=Path, default=DEFAULT_PATCH)
    parser.add_argument("--bdf", type=Path, default=DEFAULT_BDF)
    args = parser.parse_args()
    patch_path = args.patch if args.patch.is_absolute() else root / args.patch
    bdf_path = args.bdf if args.bdf.is_absolute() else root / args.bdf
    safe_text_path = root / TEXT_CANDIDATE_PATH
    local_text_path = root / LOCAL_TEXT_CANDIDATE_PATH
    prerequisites = (
        patch_path,
        bdf_path,
        safe_text_path,
        local_text_path,
    )
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Unmatched glyph fuzzy analysis is not ready")
            return 0
        raise SystemExit("unmatched glyph fuzzy input is missing")
    patch = patch_path.read_bytes()
    bdf = bdf_path.read_bytes()
    if (
        sha256_file(patch_path) != EXPECTED_PATCH_SHA256
        or len(bdf) != BDF_SIZE
        or digest(bdf) != BDF_SHA256
    ):
        raise ValueError("unmatched glyph fuzzy input identity mismatch")
    safe_text = _load_json_object(safe_text_path)
    local_text = _load_json_object(local_text_path)
    validate_group_text_candidate_resolution(safe_text)
    if local_text.get("target_sha256") != safe_text["target_sha256"]:
        raise ValueError("unmatched glyph fuzzy target identities disagree")
    records = local_text.get("analysis", {}).get("resolved_records")
    if not isinstance(records, list):
        raise ValueError("unmatched glyph fuzzy local records are missing")
    counts, local_analysis = analyze_unmatched_glyphs(
        patch=patch,
        bdf=bdf,
        records=records,
    )
    if (
        counts["occurrence_count"]
        != safe_text["resolution"]["selected_unmatched_glyph_count"]
    ):
        raise ValueError("unmatched glyph occurrence count changed")
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_unmatched_glyph_fuzzy(
        target_sha256=str(safe_text["target_sha256"]),
        source_text_candidate_sha256=sha256_file(safe_text_path),
        source_font_reference_sha256=BDF_SHA256,
        unmatched=counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-unmatched-glyph-fuzzy",
        "schema_version": 1,
        "target_sha256": safe_text["target_sha256"],
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
    print(f"SFKR unmatched glyph fuzzy: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
