#!/usr/bin/env python3
"""Measure unresolved glyph demand in the verified runtime context window.

All glyph coordinates, candidate characters, text, speakers, selectors,
ordinals, tokens, and rows stay in ignored phone-local reports.  The safe
receipt publishes fixed aggregate counts only and never chooses a character.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

try:
    from .patch_io import sha256_file
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_source_target_runtime_context import (
        LOCAL_REPORT_PATH as LOCAL_RUNTIME_CONTEXT_PATH,
        PUBLISH_RELATIVE_PATH as RUNTIME_CONTEXT_PATH,
        validate_source_target_runtime_context,
    )
    from .v5_1_source_target_runtime_sequence import (
        LOCAL_REPORT_PATH as LOCAL_RUNTIME_SEQUENCE_PATH,
        PUBLISH_RELATIVE_PATH as RUNTIME_SEQUENCE_PATH,
        validate_source_target_runtime_sequence,
    )
    from .v5_1_source_target_section_projection import (
        LOCAL_REPORT_PATH as LOCAL_PROJECTION_PATH,
        PUBLISH_RELATIVE_PATH as PROJECTION_PATH,
        validate_source_target_section_projection,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_source_target_runtime_context import (
        LOCAL_REPORT_PATH as LOCAL_RUNTIME_CONTEXT_PATH,
        PUBLISH_RELATIVE_PATH as RUNTIME_CONTEXT_PATH,
        validate_source_target_runtime_context,
    )
    from v5_1_source_target_runtime_sequence import (
        LOCAL_REPORT_PATH as LOCAL_RUNTIME_SEQUENCE_PATH,
        PUBLISH_RELATIVE_PATH as RUNTIME_SEQUENCE_PATH,
        validate_source_target_runtime_sequence,
    )
    from v5_1_source_target_section_projection import (
        LOCAL_REPORT_PATH as LOCAL_PROJECTION_PATH,
        PUBLISH_RELATIVE_PATH as PROJECTION_PATH,
        validate_source_target_section_projection,
    )


ARTIFACT_KIND = "sanitized-v5-1-runtime-context-glyph-demand"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_runtime_context_glyph_demand.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_runtime_context_glyph_demand.json"
)

COUNT_KEYS = {
    "runtime_context_entry_count",
    "human_translation_review_ready_entry_count",
    "glyph_blocked_entry_count",
    "unresolved_glyph_occurrence_count",
    "distinct_unresolved_glyph_count",
    "single_candidate_occurrence_count",
    "single_candidate_distinct_glyph_count",
    "ambiguous_candidate_occurrence_count",
    "ambiguous_candidate_distinct_glyph_count",
    "unmatched_occurrence_count",
    "unmatched_distinct_glyph_count",
    "maximum_candidate_count",
}

SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "runtime_context_sha256",
    "source_section_projection_sha256",
    "runtime_sequence_sha256",
    "local_demand_sha256",
    "captured_utc",
    "demand",
    "glyph_recovery_complete",
    "automatic_character_selection_allowed",
    "human_translation_review_required",
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


def analyze_runtime_context_glyph_demand(
    pairs: list[dict[str, object]],
) -> tuple[dict[str, int], dict[str, object]]:
    if not pairs:
        raise ValueError("runtime context glyph demand pairs are missing")
    rows: list[dict[str, object]] = []
    distinct: dict[tuple[int, int], set[str]] = {}
    occurrence_categories = {
        "single": 0,
        "ambiguous": 0,
        "unmatched": 0,
    }
    distinct_categories: dict[str, set[tuple[int, int]]] = {
        "single": set(),
        "ambiguous": set(),
        "unmatched": set(),
    }
    blocked_entries = 0
    review_ready_entries = 0
    unresolved_occurrences = 0
    maximum_candidates = 0

    for pair_index, pair in enumerate(pairs):
        if not isinstance(pair, dict):
            raise ValueError(
                "runtime context glyph demand pair is invalid"
            )
        target_record = pair.get("target_record")
        if not isinstance(target_record, dict):
            raise ValueError(
                "runtime context glyph demand target record is invalid"
            )
        tokens = target_record.get("tokens")
        if not isinstance(tokens, list):
            raise ValueError(
                "runtime context glyph demand tokens are missing"
            )
        unresolved: list[dict[str, object]] = []
        for token in tokens:
            if not isinstance(token, dict):
                raise ValueError(
                    "runtime context glyph demand token is invalid"
                )
            if token.get("kind") != "glyph":
                continue
            text = token.get("text")
            if isinstance(text, str) and len(text) == 1:
                continue
            page = token.get("page")
            symbol = token.get("symbol")
            if (
                not _bounded_int(page, 0, 0xFF)
                or not _bounded_int(symbol, 0, 0xFF)
            ):
                raise ValueError(
                    "runtime context glyph demand coordinate is invalid"
                )
            assert isinstance(page, int)
            assert isinstance(symbol, int)
            raw_candidates = token.get("characters")
            if raw_candidates is None:
                raw_candidates = []
            if (
                not isinstance(raw_candidates, list)
                or any(
                    not isinstance(candidate, str)
                    or len(candidate) != 1
                    for candidate in raw_candidates
                )
            ):
                raise ValueError(
                    "runtime context glyph demand candidates are invalid"
                )
            candidates = sorted(set(raw_candidates))
            candidate_count = len(candidates)
            maximum_candidates = max(maximum_candidates, candidate_count)
            if candidate_count == 0:
                category = "unmatched"
            elif candidate_count == 1:
                category = "single"
            else:
                category = "ambiguous"
            coordinate = (page, symbol)
            distinct.setdefault(coordinate, set()).update(candidates)
            occurrence_categories[category] += 1
            distinct_categories[category].add(coordinate)
            unresolved_occurrences += 1
            unresolved.append(
                {
                    "page": page,
                    "symbol": symbol,
                    "characters": candidates,
                    "candidate_count": candidate_count,
                    "category": category,
                    "token": token,
                }
            )
        if unresolved:
            blocked_entries += 1
        else:
            review_ready_entries += 1
        rows.append(
            {
                "pair_index": pair_index,
                "source_text": pair.get("source_text"),
                "speaker": pair.get("speaker"),
                "target_text": target_record.get("translation_text"),
                "quality_tier": target_record.get("quality_tier"),
                "unresolved": unresolved,
            }
        )

    counts = {
        "runtime_context_entry_count": len(pairs),
        "human_translation_review_ready_entry_count":
            review_ready_entries,
        "glyph_blocked_entry_count": blocked_entries,
        "unresolved_glyph_occurrence_count": unresolved_occurrences,
        "distinct_unresolved_glyph_count": len(distinct),
        "single_candidate_occurrence_count":
            occurrence_categories["single"],
        "single_candidate_distinct_glyph_count":
            len(distinct_categories["single"]),
        "ambiguous_candidate_occurrence_count":
            occurrence_categories["ambiguous"],
        "ambiguous_candidate_distinct_glyph_count":
            len(distinct_categories["ambiguous"]),
        "unmatched_occurrence_count":
            occurrence_categories["unmatched"],
        "unmatched_distinct_glyph_count":
            len(distinct_categories["unmatched"]),
        "maximum_candidate_count": maximum_candidates,
    }
    return counts, {
        "rows": rows,
        "distinct_glyphs": [
            {
                "page": page,
                "symbol": symbol,
                "characters": sorted(candidates),
            }
            for (page, symbol), candidates in sorted(distinct.items())
        ],
        "automatic_character_selection_allowed": False,
        "publication_policy": (
            "never-publish-glyph-coordinates-candidate-characters-text-"
            "speakers-selectors-ordinals-tokens-or-rows"
        ),
    }


def build_runtime_context_glyph_demand(
    *,
    target_sha256: str,
    runtime_context_sha256: str,
    source_section_projection_sha256: str,
    runtime_sequence_sha256: str,
    local_demand_sha256: str,
    demand: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    complete = demand["unresolved_glyph_occurrence_count"] == 0
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "runtime-context-glyph-demand-resolved"
            if complete
            else "runtime-context-glyph-demand-needs-recovery"
        ),
        "target_sha256": target_sha256,
        "runtime_context_sha256": runtime_context_sha256,
        "source_section_projection_sha256":
            source_section_projection_sha256,
        "runtime_sequence_sha256": runtime_sequence_sha256,
        "local_demand_sha256": local_demand_sha256,
        "captured_utc": captured_utc,
        "demand": demand,
        "glyph_recovery_complete": complete,
        "automatic_character_selection_allowed": False,
        "human_translation_review_required": True,
        "hancharacter_contract_mode": "translator_declared",
        "local_payload_policy": (
            "glyph-coordinates-candidate-characters-text-speakers-"
            "selectors-ordinals-tokens-and-rows-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": (
            "prepare-first-contextual-translation-review"
            if complete
            else "resolve-runtime-context-glyph-candidates"
        ),
    }
    validate_runtime_context_glyph_demand(value)
    return value


def validate_runtime_context_glyph_demand(
    value: dict[str, object],
) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError("runtime context glyph demand fields do not match")
    complete = value["glyph_recovery_complete"]
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "runtime-context-glyph-demand-resolved",
            "runtime-context-glyph-demand-needs-recovery",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["runtime_context_sha256"])
        or not _is_sha256(value["source_section_projection_sha256"])
        or not _is_sha256(value["runtime_sequence_sha256"])
        or not _is_sha256(value["local_demand_sha256"])
        or not isinstance(complete, bool)
    ):
        raise ValueError("runtime context glyph demand identity is invalid")
    try:
        timestamp = datetime.fromisoformat(
            str(value["captured_utc"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError(
            "runtime context glyph demand timestamp is invalid"
        ) from error
    if timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
        raise ValueError(
            "runtime context glyph demand timestamp needs UTC"
        )
    counts = value["demand"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError(
            "runtime context glyph demand counts do not match"
        )
    entry_count = counts.get("runtime_context_entry_count")
    if not _bounded_int(entry_count, 1, 1000):
        raise ValueError(
            "runtime context glyph demand entry count is invalid"
        )
    assert isinstance(entry_count, int)
    occurrence_limit = max(1, entry_count * 1000)
    for key, count in counts.items():
        if not _bounded_int(count, 0, occurrence_limit):
            raise ValueError(
                f"runtime context glyph demand {key} is invalid"
            )
    unresolved = int(counts["unresolved_glyph_occurrence_count"])
    expected_complete = unresolved == 0
    expected_status = (
        "runtime-context-glyph-demand-resolved"
        if expected_complete
        else "runtime-context-glyph-demand-needs-recovery"
    )
    if (
        counts["human_translation_review_ready_entry_count"]
        + counts["glyph_blocked_entry_count"]
        != entry_count
        or counts["single_candidate_occurrence_count"]
        + counts["ambiguous_candidate_occurrence_count"]
        + counts["unmatched_occurrence_count"]
        != unresolved
        or counts["distinct_unresolved_glyph_count"]
        < max(
            counts["single_candidate_distinct_glyph_count"],
            counts["ambiguous_candidate_distinct_glyph_count"],
            counts["unmatched_distinct_glyph_count"],
        )
        or complete is not expected_complete
        or value["status"] != expected_status
        or value["automatic_character_selection_allowed"] is not False
        or value["human_translation_review_required"] is not True
        or value["hancharacter_contract_mode"] != "translator_declared"
        or value["local_payload_policy"]
        != (
            "glyph-coordinates-candidate-characters-text-speakers-"
            "selectors-ordinals-tokens-and-rows-local-only"
        )
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != (
            "prepare-first-contextual-translation-review"
            if expected_complete
            else "resolve-runtime-context-glyph-candidates"
        )
    ):
        raise ValueError(
            "runtime context glyph demand result is inconsistent"
        )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = {
        "context": root / RUNTIME_CONTEXT_PATH,
        "local_context": root / LOCAL_RUNTIME_CONTEXT_PATH,
        "runtime": root / RUNTIME_SEQUENCE_PATH,
        "local_runtime": root / LOCAL_RUNTIME_SEQUENCE_PATH,
        "projection": root / PROJECTION_PATH,
        "local_projection": root / LOCAL_PROJECTION_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print("Runtime context glyph demand is not ready")
            return 0
        raise SystemExit("runtime context glyph demand input is missing")
    context = _load_json_object(paths["context"])
    local_context = _load_json_object(paths["local_context"])
    runtime = _load_json_object(paths["runtime"])
    local_runtime = _load_json_object(paths["local_runtime"])
    projection = _load_json_object(paths["projection"])
    local_projection = _load_json_object(paths["local_projection"])
    validate_source_target_runtime_context(context)
    validate_source_target_runtime_sequence(runtime)
    validate_source_target_section_projection(projection)
    if (
        context["runtime_context_window_pairing_complete"] is not True
        or context["target_sha256"] != projection["target_sha256"]
        or context["runtime_sequence_sha256"]
        != sha256_file(paths["runtime"])
        or context["source_section_projection_sha256"]
        != sha256_file(paths["projection"])
        or sha256_file(paths["local_context"])
        != context["local_context_sha256"]
        or sha256_file(paths["local_runtime"])
        != runtime["local_sequence_sha256"]
        or sha256_file(paths["local_projection"])
        != projection["local_projection_sha256"]
        or local_context.get("target_sha256") != context["target_sha256"]
        or local_runtime.get("baseline_target_sha256")
        != context["target_sha256"]
    ):
        raise ValueError(
            "runtime context glyph demand identity disagrees"
        )
    runtime_observations = local_runtime.get("observations")
    projection_payload = local_projection.get("projection")
    if (
        not isinstance(runtime_observations, list)
        or not isinstance(projection_payload, dict)
        or not isinstance(projection_payload.get("pairs"), list)
    ):
        raise ValueError(
            "runtime context glyph demand local inputs are missing"
        )
    projection_pairs = projection_payload["pairs"]
    selected_pairs: list[dict[str, object]] = []
    for observation in runtime_observations:
        if not isinstance(observation, dict):
            raise ValueError(
                "runtime context glyph demand observation is invalid"
            )
        matches = [
            pair
            for pair in projection_pairs
            if isinstance(pair, dict)
            and pair.get("target_selector") == observation.get("selector")
            and pair.get("target_ordinal") == observation.get("ordinal")
        ]
        if len(matches) != 1:
            raise ValueError(
                "runtime context glyph demand mapping is not unique"
            )
        selected_pairs.append(matches[0])
    counts, local_analysis = analyze_runtime_context_glyph_demand(
        selected_pairs
    )
    if (
        counts["runtime_context_entry_count"]
        != context["context"]["runtime_entry_count"]
        or counts["human_translation_review_ready_entry_count"]
        != context["context"]["translation_ready_context_entry_count"]
        + context["context"]["non_hangul_review_context_entry_count"]
        or counts["glyph_blocked_entry_count"]
        != context["context"]["glyph_recovery_context_entry_count"]
        + context["context"]["structure_review_context_entry_count"]
    ):
        raise ValueError(
            "runtime context glyph demand aggregates disagree with context"
        )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    local = {
        "artifact_kind": "local-v5-1-runtime-context-glyph-demand",
        "schema_version": SCHEMA_VERSION,
        "target_sha256": context["target_sha256"],
        "runtime_context_sha256": sha256_file(paths["context"]),
        "source_section_projection_sha256":
            sha256_file(paths["projection"]),
        "runtime_sequence_sha256": sha256_file(paths["runtime"]),
        "captured_utc": captured_utc,
        "demand": counts,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-glyph-coordinates-candidate-characters-text-"
            "speakers-selectors-ordinals-tokens-or-rows"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_runtime_context_glyph_demand(
        target_sha256=str(context["target_sha256"]),
        runtime_context_sha256=sha256_file(paths["context"]),
        source_section_projection_sha256=sha256_file(paths["projection"]),
        runtime_sequence_sha256=sha256_file(paths["runtime"]),
        local_demand_sha256=sha256_file(local_path),
        demand=counts,
        captured_utc=captured_utc,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR runtime context glyph demand: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
