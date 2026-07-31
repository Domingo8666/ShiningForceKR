#!/usr/bin/env python3
"""Preserve visually reviewed non-text runtime glyphs as raw glyph tokens.

The user-supplied review screenshot confirms that this fixed target/context
contains two blank cells, two one-pixel markers, and one visual symbol.  This
stage verifies that exact local mask distribution before recording a
preserve-original-glyph-token policy.  It never assigns Unicode characters.
Coordinates, masks, text, speakers, and candidate characters stay phone-local.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_runtime_context_glyph_candidates import (
        LOCAL_REPORT_PATH as LOCAL_CANDIDATES_PATH,
        PUBLISH_RELATIVE_PATH as CANDIDATES_PATH,
        validate_runtime_context_glyph_candidates,
    )
    from .v5_1_runtime_context_glyph_review import (
        LOCAL_REPORT_PATH as LOCAL_REVIEW_PATH,
        PUBLISH_RELATIVE_PATH as REVIEW_PATH,
        validate_runtime_context_glyph_review,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_runtime_context_glyph_candidates import (
        LOCAL_REPORT_PATH as LOCAL_CANDIDATES_PATH,
        PUBLISH_RELATIVE_PATH as CANDIDATES_PATH,
        validate_runtime_context_glyph_candidates,
    )
    from v5_1_runtime_context_glyph_review import (
        LOCAL_REPORT_PATH as LOCAL_REVIEW_PATH,
        PUBLISH_RELATIVE_PATH as REVIEW_PATH,
        validate_runtime_context_glyph_review,
    )


ARTIFACT_KIND = "sanitized-v5-1-runtime-context-glyph-preservation"
SCHEMA_VERSION = 1
EXPECTED_TARGET_SHA256 = (
    "5dc9d1aef40c8fea4e9374ddf12a7e6e"
    "ff4fb5d77fe66d5361d78059186adb39"
)
EXPECTED_REVIEW_COUNTS = {
    "glyph_card_count": 5,
    "glyph_occurrence_count": 5,
    "source_context_occurrence_count": 5,
    "ambiguous_exact_non_hangul_card_count": 3,
    "unmatched_non_hangul_card_count": 2,
    "maximum_exact_candidate_count": 13,
    "maximum_fuzzy_candidate_count": 1,
}
EXPECTED_SHAPE_COUNTS = {
    "blank_cell_distinct_count": 2,
    "one_pixel_marker_distinct_count": 2,
    "visual_symbol_distinct_count": 1,
}
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_runtime_context_glyph_preservation.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_runtime_context_glyph_preservation.json"
)

COUNT_KEYS = {
    "glyph_occurrence_count",
    "distinct_glyph_count",
    "blank_cell_occurrence_count",
    "blank_cell_distinct_count",
    "one_pixel_marker_occurrence_count",
    "one_pixel_marker_distinct_count",
    "visual_symbol_occurrence_count",
    "visual_symbol_distinct_count",
    "preserve_original_glyph_occurrence_count",
    "preserve_original_glyph_distinct_count",
    "unicode_character_assignment_count",
    "unclassified_occurrence_count",
    "unclassified_distinct_count",
    "maximum_ink_pixel_count",
}
SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "runtime_context_glyph_candidates_sha256",
    "runtime_context_glyph_review_sha256",
    "local_preservation_sha256",
    "captured_utc",
    "preservation",
    "review_evidence_kind",
    "reviewed_shape_contract",
    "human_visual_review_complete",
    "original_glyph_tokens_preserved",
    "automatic_character_selection_allowed",
    "hancharacter_contract_mode",
    "local_payload_policy",
    "runtime_context_glyph_recovery_complete",
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


def analyze_runtime_glyph_preservation(
    cards: list[dict[str, object]],
) -> tuple[dict[str, int], list[dict[str, object]]]:
    if not cards:
        raise ValueError("runtime glyph preservation cards are missing")
    counts = {key: 0 for key in COUNT_KEYS}
    records: list[dict[str, object]] = []
    seen: set[tuple[int, int]] = set()
    for card in cards:
        if not isinstance(card, dict):
            raise ValueError("runtime glyph preservation card is invalid")
        page = card.get("page")
        symbol = card.get("symbol")
        occurrence_count = card.get("occurrence_count")
        rows = card.get("mask_rows_hex")
        if (
            not _bounded_int(page, 0, 0xFF)
            or not _bounded_int(symbol, 0, 0xFF)
            or not _bounded_int(occurrence_count, 1, 1000)
            or not isinstance(rows, list)
            or len(rows) != 8
            or any(
                not isinstance(row, str)
                or re.fullmatch(r"[0-9A-Fa-f]{2}", row) is None
                for row in rows
            )
        ):
            raise ValueError(
                "runtime glyph preservation card fields are invalid"
            )
        assert isinstance(page, int)
        assert isinstance(symbol, int)
        assert isinstance(occurrence_count, int)
        coordinate = (page, symbol)
        if coordinate in seen:
            raise ValueError(
                "runtime glyph preservation coordinate is duplicated"
            )
        seen.add(coordinate)
        ink_pixel_count = sum(int(row, 16).bit_count() for row in rows)
        if ink_pixel_count == 0:
            category = "blank_cell"
        elif ink_pixel_count == 1:
            category = "one_pixel_marker"
        else:
            category = "visual_symbol"
        counts["glyph_occurrence_count"] += occurrence_count
        counts["distinct_glyph_count"] += 1
        counts[f"{category}_occurrence_count"] += occurrence_count
        counts[f"{category}_distinct_count"] += 1
        counts["preserve_original_glyph_occurrence_count"] += (
            occurrence_count
        )
        counts["preserve_original_glyph_distinct_count"] += 1
        counts["maximum_ink_pixel_count"] = max(
            counts["maximum_ink_pixel_count"], ink_pixel_count
        )
        records.append(
            {
                "page": page,
                "symbol": symbol,
                "occurrence_count": occurrence_count,
                "mask_rows_hex": rows,
                "ink_pixel_count": ink_pixel_count,
                "visual_category": category.replace("_", "-"),
                "preservation_action": "preserve-original-glyph-token",
                "unicode_character": None,
            }
        )
    return counts, records


def build_runtime_context_glyph_preservation(
    *,
    target_sha256: str,
    runtime_context_glyph_candidates_sha256: str,
    runtime_context_glyph_review_sha256: str,
    local_preservation_sha256: str,
    preservation: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    complete = (
        preservation["unclassified_occurrence_count"] == 0
        and preservation["glyph_occurrence_count"]
        == preservation["preserve_original_glyph_occurrence_count"]
    )
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "runtime-context-non-text-glyphs-preserved"
            if complete
            else "runtime-context-glyph-preservation-incomplete"
        ),
        "target_sha256": target_sha256,
        "runtime_context_glyph_candidates_sha256":
            runtime_context_glyph_candidates_sha256,
        "runtime_context_glyph_review_sha256":
            runtime_context_glyph_review_sha256,
        "local_preservation_sha256": local_preservation_sha256,
        "captured_utc": captured_utc,
        "preservation": preservation,
        "review_evidence_kind": "user-supplied-runtime-glyph-screenshot",
        "reviewed_shape_contract": {
            "blank_cell_distinct_count":
                EXPECTED_SHAPE_COUNTS["blank_cell_distinct_count"],
            "one_pixel_marker_distinct_count":
                EXPECTED_SHAPE_COUNTS["one_pixel_marker_distinct_count"],
            "visual_symbol_distinct_count":
                EXPECTED_SHAPE_COUNTS["visual_symbol_distinct_count"],
            "classification_rule":
                "zero-ink-blank-one-ink-marker-otherwise-symbol",
            "preservation_action": "preserve-original-glyph-token",
        },
        "human_visual_review_complete": complete,
        "original_glyph_tokens_preserved": complete,
        "automatic_character_selection_allowed": False,
        "hancharacter_contract_mode": "translator_declared",
        "local_payload_policy": (
            "glyph-coordinates-masks-text-speakers-codepoints-characters-"
            "and-preservation-records-local-only"
        ),
        "runtime_context_glyph_recovery_complete": complete,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "prepare-first-contextual-translation-review"
            if complete
            else "repeat-runtime-glyph-visual-review"
        ),
    }
    validate_runtime_context_glyph_preservation(value)
    return value


def validate_runtime_context_glyph_preservation(
    value: dict[str, object],
) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError("runtime glyph preservation fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "runtime-context-non-text-glyphs-preserved",
            "runtime-context-glyph-preservation-incomplete",
        }
        or value["target_sha256"] != EXPECTED_TARGET_SHA256
        or not all(
            _is_sha256(value[key])
            for key in (
                "runtime_context_glyph_candidates_sha256",
                "runtime_context_glyph_review_sha256",
                "local_preservation_sha256",
            )
        )
    ):
        raise ValueError("runtime glyph preservation identity is invalid")
    try:
        timestamp = datetime.fromisoformat(
            str(value["captured_utc"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError(
            "runtime glyph preservation timestamp is invalid"
        ) from error
    if timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
        raise ValueError("runtime glyph preservation timestamp needs UTC")
    counts = value["preservation"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("runtime glyph preservation counts do not match")
    for key, count in counts.items():
        if not _bounded_int(count, 0, 0x1000000):
            raise ValueError(f"runtime glyph preservation {key} is invalid")
    occurrences = counts["glyph_occurrence_count"]
    distinct = counts["distinct_glyph_count"]
    complete = (
        counts["unclassified_occurrence_count"] == 0
        and occurrences == counts["preserve_original_glyph_occurrence_count"]
        and distinct == counts["preserve_original_glyph_distinct_count"]
    )
    expected_status = (
        "runtime-context-non-text-glyphs-preserved"
        if complete
        else "runtime-context-glyph-preservation-incomplete"
    )
    if (
        sum(
            counts[f"{category}_occurrence_count"]
            for category in (
                "blank_cell",
                "one_pixel_marker",
                "visual_symbol",
            )
        )
        + counts["unclassified_occurrence_count"]
        != occurrences
        or sum(
            counts[f"{category}_distinct_count"]
            for category in (
                "blank_cell",
                "one_pixel_marker",
                "visual_symbol",
            )
        )
        + counts["unclassified_distinct_count"]
        != distinct
        or counts["unicode_character_assignment_count"] != 0
        or value["status"] != expected_status
        or value["review_evidence_kind"]
        != "user-supplied-runtime-glyph-screenshot"
        or value["reviewed_shape_contract"]
        != {
            "blank_cell_distinct_count":
                EXPECTED_SHAPE_COUNTS["blank_cell_distinct_count"],
            "one_pixel_marker_distinct_count":
                EXPECTED_SHAPE_COUNTS["one_pixel_marker_distinct_count"],
            "visual_symbol_distinct_count":
                EXPECTED_SHAPE_COUNTS["visual_symbol_distinct_count"],
            "classification_rule":
                "zero-ink-blank-one-ink-marker-otherwise-symbol",
            "preservation_action": "preserve-original-glyph-token",
        }
        or value["human_visual_review_complete"] is not complete
        or value["original_glyph_tokens_preserved"] is not complete
        or value["automatic_character_selection_allowed"] is not False
        or value["hancharacter_contract_mode"] != "translator_declared"
        or value["local_payload_policy"]
        != (
            "glyph-coordinates-masks-text-speakers-codepoints-characters-"
            "and-preservation-records-local-only"
        )
        or value["runtime_context_glyph_recovery_complete"] is not complete
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != (
            "prepare-first-contextual-translation-review"
            if complete
            else "repeat-runtime-glyph-visual-review"
        )
    ):
        raise ValueError("runtime glyph preservation result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = {
        "candidates": root / CANDIDATES_PATH,
        "local_candidates": root / LOCAL_CANDIDATES_PATH,
        "review": root / REVIEW_PATH,
        "local_review": root / LOCAL_REVIEW_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print("Runtime glyph preservation is not ready")
            return 0
        raise SystemExit("runtime glyph preservation input is missing")
    candidates = _load_json_object(paths["candidates"])
    local_candidates = _load_json_object(paths["local_candidates"])
    review = _load_json_object(paths["review"])
    local_review = _load_json_object(paths["local_review"])
    validate_runtime_context_glyph_candidates(candidates)
    validate_runtime_context_glyph_review(review)
    if (
        candidates["target_sha256"] != EXPECTED_TARGET_SHA256
        or review["target_sha256"] != EXPECTED_TARGET_SHA256
        or review["runtime_context_glyph_candidates_sha256"]
        != sha256_file(paths["candidates"])
        or candidates["local_candidates_sha256"]
        != sha256_file(paths["local_candidates"])
        or local_review.get("html_sha256")
        != review["local_review_packet_sha256"]
        or local_review.get("target_sha256") != EXPECTED_TARGET_SHA256
    ):
        raise ValueError("runtime glyph preservation identity disagrees")
    for key, expected in EXPECTED_REVIEW_COUNTS.items():
        if review["review"].get(key) != expected:
            raise ValueError(
                "runtime glyph preservation review evidence changed"
            )
    cards = local_review.get("cards")
    if not isinstance(cards, list):
        raise ValueError("runtime glyph preservation local cards are missing")
    counts, records = analyze_runtime_glyph_preservation(cards)
    if any(
        counts[key] != expected
        for key, expected in EXPECTED_SHAPE_COUNTS.items()
    ):
        raise ValueError(
            "runtime glyph preservation reviewed shapes changed"
        )
    if (
        counts["glyph_occurrence_count"]
        != review["review"]["glyph_occurrence_count"]
        or counts["distinct_glyph_count"]
        != review["review"]["glyph_card_count"]
    ):
        raise ValueError(
            "runtime glyph preservation aggregates disagree with review"
        )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    local = {
        "artifact_kind": "local-v5-1-runtime-context-glyph-preservation",
        "schema_version": SCHEMA_VERSION,
        "target_sha256": EXPECTED_TARGET_SHA256,
        "runtime_context_glyph_candidates_sha256":
            sha256_file(paths["candidates"]),
        "runtime_context_glyph_review_sha256": sha256_file(paths["review"]),
        "captured_utc": captured_utc,
        "preservation": counts,
        "records": records,
        "review_evidence_kind": "user-supplied-runtime-glyph-screenshot",
        "publication_policy": (
            "never-publish-glyph-coordinates-masks-text-speakers-"
            "codepoints-characters-or-preservation-records"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_runtime_context_glyph_preservation(
        target_sha256=EXPECTED_TARGET_SHA256,
        runtime_context_glyph_candidates_sha256=
            sha256_file(paths["candidates"]),
        runtime_context_glyph_review_sha256=sha256_file(paths["review"]),
        local_preservation_sha256=sha256_file(local_path),
        preservation=counts,
        captured_utc=captured_utc,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR runtime glyph preservation: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
