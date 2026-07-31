#!/usr/bin/env python3
"""Cross-reference runtime-context glyph demand with fuzzy font candidates.

Glyph coordinates, masks, codepoints, candidate characters, source text, and
speakers remain in ignored phone-local reports.  The safe receipt publishes
fixed aggregate counts only and never selects a character automatically.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

try:
    from .patch_io import sha256_file
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_runtime_context_glyph_demand import (
        LOCAL_REPORT_PATH as LOCAL_DEMAND_PATH,
        PUBLISH_RELATIVE_PATH as DEMAND_PATH,
        validate_runtime_context_glyph_demand,
    )
    from .v5_1_target_group_expanded_glyphs import (
        LOCAL_REPORT_PATH as LOCAL_EXPANDED_GLYPHS_PATH,
        PUBLISH_RELATIVE_PATH as EXPANDED_GLYPHS_PATH,
        validate_target_group_expanded_glyphs,
    )
    from .v5_1_unmatched_glyph_fuzzy import (
        HIGH_CONFIDENCE_MAX_DISTANCE,
        HIGH_CONFIDENCE_MIN_MARGIN,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_runtime_context_glyph_demand import (
        LOCAL_REPORT_PATH as LOCAL_DEMAND_PATH,
        PUBLISH_RELATIVE_PATH as DEMAND_PATH,
        validate_runtime_context_glyph_demand,
    )
    from v5_1_target_group_expanded_glyphs import (
        LOCAL_REPORT_PATH as LOCAL_EXPANDED_GLYPHS_PATH,
        PUBLISH_RELATIVE_PATH as EXPANDED_GLYPHS_PATH,
        validate_target_group_expanded_glyphs,
    )
    from v5_1_unmatched_glyph_fuzzy import (
        HIGH_CONFIDENCE_MAX_DISTANCE,
        HIGH_CONFIDENCE_MIN_MARGIN,
    )


ARTIFACT_KIND = "sanitized-v5-1-runtime-context-glyph-candidates"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_runtime_context_glyph_candidates.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_runtime_context_glyph_candidates.json"
)

DISTANCE_BUCKETS = {
    "zero": lambda value: value == 0,
    "one": lambda value: value == 1,
    "two": lambda value: value == 2,
    "three_or_four": lambda value: 3 <= value <= 4,
    "over_four": lambda value: value > 4,
}
COUNT_KEYS = {
    "demanded_occurrence_count",
    "demanded_distinct_glyph_count",
    "matched_fuzzy_occurrence_count",
    "matched_fuzzy_distinct_count",
    "missing_fuzzy_occurrence_count",
    "missing_fuzzy_distinct_count",
    "in_range_occurrence_count",
    "in_range_distinct_count",
    "out_of_range_occurrence_count",
    "out_of_range_distinct_count",
    "unique_nearest_occurrence_count",
    "unique_nearest_distinct_count",
    "tied_nearest_occurrence_count",
    "tied_nearest_distinct_count",
    "distance_zero_occurrence_count",
    "distance_zero_distinct_count",
    "distance_one_occurrence_count",
    "distance_one_distinct_count",
    "distance_two_occurrence_count",
    "distance_two_distinct_count",
    "distance_three_or_four_occurrence_count",
    "distance_three_or_four_distinct_count",
    "distance_over_four_occurrence_count",
    "distance_over_four_distinct_count",
    "margin_at_least_two_occurrence_count",
    "margin_at_least_two_distinct_count",
    "margin_under_two_occurrence_count",
    "margin_under_two_distinct_count",
    "high_confidence_occurrence_count",
    "high_confidence_distinct_count",
    "maximum_nearest_candidate_count",
}
SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "runtime_context_glyph_demand_sha256",
    "target_group_expanded_glyphs_sha256",
    "local_candidates_sha256",
    "captured_utc",
    "candidates",
    "high_confidence_policy",
    "automatic_character_selection_allowed",
    "human_character_review_required",
    "hancharacter_contract_mode",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _bounded_int(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _coordinate(value: object, *, label: str) -> tuple[int, int]:
    if not isinstance(value, dict):
        raise ValueError(f"runtime glyph candidate {label} is invalid")
    page = value.get("page")
    symbol = value.get("symbol")
    if not _bounded_int(page, 0, 0xFF) or not _bounded_int(
        symbol, 0, 0xFF
    ):
        raise ValueError(
            f"runtime glyph candidate {label} coordinate is invalid"
        )
    assert isinstance(page, int)
    assert isinstance(symbol, int)
    return page, symbol


def analyze_runtime_context_glyph_candidates(
    demand_analysis: dict[str, object],
    fuzzy_analysis: dict[str, object],
) -> tuple[dict[str, int], dict[str, object]]:
    rows = demand_analysis.get("rows")
    distinct = demand_analysis.get("distinct_glyphs")
    fuzzy_glyphs = fuzzy_analysis.get("glyphs")
    if not isinstance(rows, list) or not isinstance(distinct, list):
        raise ValueError("runtime glyph candidate demand analysis is missing")
    if not isinstance(fuzzy_glyphs, list):
        raise ValueError("runtime glyph candidate fuzzy analysis is missing")

    occurrences: dict[tuple[int, int], int] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(
            row.get("unresolved"), list
        ):
            raise ValueError("runtime glyph candidate demand row is invalid")
        for unresolved in row["unresolved"]:
            coordinate = _coordinate(unresolved, label="demand")
            occurrences[coordinate] = occurrences.get(coordinate, 0) + 1

    declared_coordinates = {
        _coordinate(glyph, label="distinct demand") for glyph in distinct
    }
    if declared_coordinates != set(occurrences):
        raise ValueError(
            "runtime glyph candidate demand coordinates disagree"
        )

    fuzzy_by_coordinate: dict[tuple[int, int], dict[str, object]] = {}
    for glyph in fuzzy_glyphs:
        coordinate = _coordinate(glyph, label="fuzzy")
        if coordinate in fuzzy_by_coordinate:
            raise ValueError(
                "runtime glyph candidate fuzzy coordinate is duplicated"
            )
        assert isinstance(glyph, dict)
        fuzzy_by_coordinate[coordinate] = glyph

    counts = {key: 0 for key in COUNT_KEYS}
    counts["demanded_occurrence_count"] = sum(occurrences.values())
    counts["demanded_distinct_glyph_count"] = len(occurrences)
    local_rows: list[dict[str, object]] = []

    for (page, symbol), occurrence_count in sorted(occurrences.items()):
        fuzzy = fuzzy_by_coordinate.get((page, symbol))
        if fuzzy is None:
            counts["missing_fuzzy_occurrence_count"] += occurrence_count
            counts["missing_fuzzy_distinct_count"] += 1
            local_rows.append(
                {
                    "page": page,
                    "symbol": symbol,
                    "occurrence_count": occurrence_count,
                    "status": "missing-from-expanded-fuzzy-analysis",
                }
            )
            continue

        counts["matched_fuzzy_occurrence_count"] += occurrence_count
        counts["matched_fuzzy_distinct_count"] += 1
        if fuzzy.get("status") == "outside-font-page-range":
            counts["out_of_range_occurrence_count"] += occurrence_count
            counts["out_of_range_distinct_count"] += 1
            local_rows.append(
                {
                    "page": page,
                    "symbol": symbol,
                    "occurrence_count": occurrence_count,
                    **fuzzy,
                }
            )
            continue

        best = fuzzy.get("best_codepoints")
        distance = fuzzy.get("best_distance")
        margin = fuzzy.get("distance_margin")
        high_confidence = fuzzy.get("high_confidence")
        if (
            not isinstance(best, list)
            or not best
            or any(
                not _bounded_int(codepoint, 0, 0x10FFFF)
                for codepoint in best
            )
            or not _bounded_int(distance, 0, 64)
            or not _bounded_int(margin, 0, 64)
            or not isinstance(high_confidence, bool)
        ):
            raise ValueError(
                "runtime glyph candidate fuzzy match is invalid"
            )
        assert isinstance(distance, int)
        assert isinstance(margin, int)
        counts["in_range_occurrence_count"] += occurrence_count
        counts["in_range_distinct_count"] += 1
        nearest_kind = "unique_nearest" if len(best) == 1 else "tied_nearest"
        counts[f"{nearest_kind}_occurrence_count"] += occurrence_count
        counts[f"{nearest_kind}_distinct_count"] += 1
        counts["maximum_nearest_candidate_count"] = max(
            counts["maximum_nearest_candidate_count"], len(best)
        )
        distance_bucket = next(
            name
            for name, predicate in DISTANCE_BUCKETS.items()
            if predicate(distance)
        )
        counts[
            f"distance_{distance_bucket}_occurrence_count"
        ] += occurrence_count
        counts[f"distance_{distance_bucket}_distinct_count"] += 1
        margin_bucket = (
            "margin_at_least_two" if margin >= 2 else "margin_under_two"
        )
        counts[f"{margin_bucket}_occurrence_count"] += occurrence_count
        counts[f"{margin_bucket}_distinct_count"] += 1
        if high_confidence:
            counts["high_confidence_occurrence_count"] += occurrence_count
            counts["high_confidence_distinct_count"] += 1
        local_rows.append(
            {
                "page": page,
                "symbol": symbol,
                "occurrence_count": occurrence_count,
                **fuzzy,
            }
        )

    return counts, {
        "glyphs": local_rows,
        "automatic_character_selection_allowed": False,
        "publication_policy": (
            "never-publish-glyph-coordinates-masks-codepoints-characters-"
            "source-text-speakers-selectors-ordinals-tokens-or-rows"
        ),
    }


def _next_checkpoint(counts: dict[str, int]) -> str:
    if (
        counts["missing_fuzzy_distinct_count"] > 0
        or counts["out_of_range_distinct_count"] > 0
    ):
        return "trace-runtime-context-font-source"
    if counts["high_confidence_distinct_count"] > 0:
        return "prepare-local-runtime-glyph-review"
    return "analyze-runtime-context-glyph-transform"


def build_runtime_context_glyph_candidates(
    *,
    target_sha256: str,
    runtime_context_glyph_demand_sha256: str,
    target_group_expanded_glyphs_sha256: str,
    local_candidates_sha256: str,
    candidates: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    complete = candidates["missing_fuzzy_distinct_count"] == 0
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "runtime-context-glyph-candidates-classified"
            if complete
            else "runtime-context-glyph-candidates-incomplete"
        ),
        "target_sha256": target_sha256,
        "runtime_context_glyph_demand_sha256":
            runtime_context_glyph_demand_sha256,
        "target_group_expanded_glyphs_sha256":
            target_group_expanded_glyphs_sha256,
        "local_candidates_sha256": local_candidates_sha256,
        "captured_utc": captured_utc,
        "candidates": candidates,
        "high_confidence_policy": {
            "maximum_pixel_distance": HIGH_CONFIDENCE_MAX_DISTANCE,
            "minimum_distance_margin": HIGH_CONFIDENCE_MIN_MARGIN,
            "unique_nearest_required": True,
            "quality_inference_only": True,
        },
        "automatic_character_selection_allowed": False,
        "human_character_review_required": True,
        "hancharacter_contract_mode": "translator_declared",
        "local_payload_policy": (
            "glyph-coordinates-masks-codepoints-characters-source-text-"
            "speakers-selectors-ordinals-tokens-and-rows-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": _next_checkpoint(candidates),
    }
    validate_runtime_context_glyph_candidates(value)
    return value


def validate_runtime_context_glyph_candidates(
    value: dict[str, object],
) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError("runtime glyph candidate fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "runtime-context-glyph-candidates-classified",
            "runtime-context-glyph-candidates-incomplete",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "runtime_context_glyph_demand_sha256",
                "target_group_expanded_glyphs_sha256",
                "local_candidates_sha256",
            )
        )
    ):
        raise ValueError("runtime glyph candidate identity is invalid")
    try:
        timestamp = datetime.fromisoformat(
            str(value["captured_utc"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError(
            "runtime glyph candidate timestamp is invalid"
        ) from error
    if timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
        raise ValueError("runtime glyph candidate timestamp needs UTC")
    counts = value["candidates"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("runtime glyph candidate counts do not match")
    for key, count in counts.items():
        if not _bounded_int(count, 0, 0x1000000):
            raise ValueError(f"runtime glyph candidate {key} is invalid")

    demanded_occurrences = counts["demanded_occurrence_count"]
    demanded_distinct = counts["demanded_distinct_glyph_count"]
    matched_occurrences = counts["matched_fuzzy_occurrence_count"]
    matched_distinct = counts["matched_fuzzy_distinct_count"]
    missing_distinct = counts["missing_fuzzy_distinct_count"]
    in_range_distinct = counts["in_range_distinct_count"]
    complete = missing_distinct == 0
    distance_distinct = sum(
        counts[f"distance_{bucket}_distinct_count"]
        for bucket in DISTANCE_BUCKETS
    )
    distance_occurrences = sum(
        counts[f"distance_{bucket}_occurrence_count"]
        for bucket in DISTANCE_BUCKETS
    )
    expected_status = (
        "runtime-context-glyph-candidates-classified"
        if complete
        else "runtime-context-glyph-candidates-incomplete"
    )
    if (
        matched_occurrences + counts["missing_fuzzy_occurrence_count"]
        != demanded_occurrences
        or matched_distinct + missing_distinct != demanded_distinct
        or counts["in_range_occurrence_count"]
        + counts["out_of_range_occurrence_count"]
        != matched_occurrences
        or in_range_distinct + counts["out_of_range_distinct_count"]
        != matched_distinct
        or counts["unique_nearest_occurrence_count"]
        + counts["tied_nearest_occurrence_count"]
        != counts["in_range_occurrence_count"]
        or counts["unique_nearest_distinct_count"]
        + counts["tied_nearest_distinct_count"]
        != in_range_distinct
        or distance_occurrences != counts["in_range_occurrence_count"]
        or distance_distinct != in_range_distinct
        or counts["margin_at_least_two_occurrence_count"]
        + counts["margin_under_two_occurrence_count"]
        != counts["in_range_occurrence_count"]
        or counts["margin_at_least_two_distinct_count"]
        + counts["margin_under_two_distinct_count"]
        != in_range_distinct
        or counts["high_confidence_occurrence_count"]
        > counts["in_range_occurrence_count"]
        or counts["high_confidence_distinct_count"] > in_range_distinct
        or value["status"] != expected_status
        or value["high_confidence_policy"]
        != {
            "maximum_pixel_distance": HIGH_CONFIDENCE_MAX_DISTANCE,
            "minimum_distance_margin": HIGH_CONFIDENCE_MIN_MARGIN,
            "unique_nearest_required": True,
            "quality_inference_only": True,
        }
        or value["automatic_character_selection_allowed"] is not False
        or value["human_character_review_required"] is not True
        or value["hancharacter_contract_mode"] != "translator_declared"
        or value["local_payload_policy"]
        != (
            "glyph-coordinates-masks-codepoints-characters-source-text-"
            "speakers-selectors-ordinals-tokens-and-rows-local-only"
        )
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"] != _next_checkpoint(counts)
    ):
        raise ValueError("runtime glyph candidate result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = {
        "demand": root / DEMAND_PATH,
        "local_demand": root / LOCAL_DEMAND_PATH,
        "expanded": root / EXPANDED_GLYPHS_PATH,
        "local_expanded": root / LOCAL_EXPANDED_GLYPHS_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print("Runtime context glyph candidates are not ready")
            return 0
        raise SystemExit("runtime glyph candidate input is missing")

    demand = _load_json_object(paths["demand"])
    local_demand = _load_json_object(paths["local_demand"])
    expanded = _load_json_object(paths["expanded"])
    local_expanded = _load_json_object(paths["local_expanded"])
    validate_runtime_context_glyph_demand(demand)
    validate_target_group_expanded_glyphs(expanded)
    if (
        demand["target_sha256"] != expanded["target_sha256"]
        or sha256_file(paths["local_demand"]) != demand["local_demand_sha256"]
        or local_demand.get("target_sha256") != demand["target_sha256"]
        or local_expanded.get("target_sha256") != demand["target_sha256"]
        or local_demand.get("artifact_kind")
        != "local-v5-1-runtime-context-glyph-demand"
        or local_expanded.get("artifact_kind")
        != "local-v5-1-target-group-expanded-glyphs"
    ):
        raise ValueError("runtime glyph candidate input identity disagrees")
    demand_analysis = local_demand.get("analysis")
    fuzzy_analysis = local_expanded.get("analysis")
    if not isinstance(demand_analysis, dict) or not isinstance(
        fuzzy_analysis, dict
    ):
        raise ValueError("runtime glyph candidate local inputs are missing")

    counts, local_analysis = analyze_runtime_context_glyph_candidates(
        demand_analysis, fuzzy_analysis
    )
    if (
        counts["demanded_occurrence_count"]
        != demand["demand"]["unresolved_glyph_occurrence_count"]
        or counts["demanded_distinct_glyph_count"]
        != demand["demand"]["distinct_unresolved_glyph_count"]
    ):
        raise ValueError(
            "runtime glyph candidate aggregates disagree with demand"
        )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    local = {
        "artifact_kind": "local-v5-1-runtime-context-glyph-candidates",
        "schema_version": SCHEMA_VERSION,
        "target_sha256": demand["target_sha256"],
        "runtime_context_glyph_demand_sha256": sha256_file(paths["demand"]),
        "target_group_expanded_glyphs_sha256":
            sha256_file(paths["expanded"]),
        "captured_utc": captured_utc,
        "candidates": counts,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-glyph-coordinates-masks-codepoints-characters-"
            "source-text-speakers-selectors-ordinals-tokens-or-rows"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_runtime_context_glyph_candidates(
        target_sha256=str(demand["target_sha256"]),
        runtime_context_glyph_demand_sha256=sha256_file(paths["demand"]),
        target_group_expanded_glyphs_sha256=sha256_file(paths["expanded"]),
        local_candidates_sha256=sha256_file(local_path),
        candidates=counts,
        captured_utc=captured_utc,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR runtime context glyph candidates: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
