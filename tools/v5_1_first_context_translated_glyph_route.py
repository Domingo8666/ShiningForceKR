#!/usr/bin/env python3
"""Join confirmed translated VRAM tiles to their private font assignments.

The local report retains pages, symbols, rows, characters, and tile hashes.
The publishable receipt exposes counts and route conclusions only.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_first_context_translated_vram_diff import (
        LOCAL_REPORT_PATH as TRANSLATED_VRAM_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as TRANSLATED_VRAM_PATH,
        validate_first_context_translated_vram_diff,
    )
    from .v5_1_first_context_translation_encoding import (
        LOCAL_REPORT_PATH as TRANSLATION_ENCODING_LOCAL_PATH,
    )
    from .v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TRANSLATION_TEST_BUILD_PATH,
        validate_first_context_translation_test_build,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_first_context_translated_vram_diff import (
        LOCAL_REPORT_PATH as TRANSLATED_VRAM_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as TRANSLATED_VRAM_PATH,
        validate_first_context_translated_vram_diff,
    )
    from v5_1_first_context_translation_encoding import (
        LOCAL_REPORT_PATH as TRANSLATION_ENCODING_LOCAL_PATH,
    )
    from v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TRANSLATION_TEST_BUILD_PATH,
        validate_first_context_translation_test_build,
    )


ARTIFACT_KIND = "sanitized-v5-1-first-context-translated-glyph-route"
LOCAL_ARTIFACT_KIND = "local-v5-1-first-context-translated-glyph-route"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_translated_glyph_route.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_first_context_translated_glyph_route.json"
)
COUNT_KEYS = {
    "confirmed_vram_match_count",
    "assignment_candidate_count",
    "slot_aligned_candidate_count",
    "match_with_slot_alignment_count",
    "uniquely_aligned_match_count",
    "aligned_candidate_page_count",
    "aligned_candidate_row_count",
    "first_row_aligned_candidate_count",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "baseline_target_sha256",
    "test_target_sha256",
    "source_translated_vram_diff_sha256",
    "source_local_encoding_sha256",
    "local_route_sha256",
    "captured_utc",
    "analysis",
    "direct_glyph_slot_alignment_confirmed",
    "single_font_page_candidate_confirmed",
    "first_row_candidate_observed",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def analyze_translated_glyph_route(
    local_vram: dict[str, object],
    local_encoding: dict[str, object],
) -> tuple[dict[str, int], dict[str, object]]:
    analysis = local_vram.get("analysis")
    assignments = local_encoding.get("character_assignments")
    if not isinstance(analysis, dict) or not isinstance(assignments, list):
        raise ValueError("translated glyph route local inputs are incomplete")

    normalized_assignments = []
    for assignment in assignments:
        if not isinstance(assignment, dict):
            raise ValueError("translated glyph assignment is invalid")
        page = assignment.get("page")
        symbol = assignment.get("symbol")
        row = assignment.get("row_index")
        tile_hash = assignment.get("tile_sha256")
        if (
            not isinstance(page, int)
            or isinstance(page, bool)
            or not isinstance(symbol, int)
            or isinstance(symbol, bool)
            or not isinstance(row, int)
            or isinstance(row, bool)
            or not _is_sha256(tile_hash)
        ):
            raise ValueError("translated glyph assignment fields are invalid")
        normalized_assignments.append(assignment)

    matches = analysis.get("changed_custom_glyph_matches")
    pairing_method = "direct-vram-tile-hash-pairs"
    if not isinstance(matches, list) or not matches:
        legacy_tiles = analysis.get("changed_custom_glyph_match_tiles")
        legacy_hashes = analysis.get("changed_custom_glyph_hashes")
        if (
            not isinstance(legacy_tiles, list)
            or not legacy_tiles
            or not isinstance(legacy_hashes, list)
            or len(legacy_tiles) != len(legacy_hashes)
            or len(set(legacy_tiles)) != len(legacy_tiles)
            or len(set(legacy_hashes)) != len(legacy_hashes)
        ):
            raise ValueError("translated glyph route needs paired VRAM tile matches")
        legacy_hash_set = set(legacy_hashes)
        inferred_matches = []
        for tile_index in legacy_tiles:
            if (
                not isinstance(tile_index, int)
                or isinstance(tile_index, bool)
                or tile_index < 0
            ):
                raise ValueError("legacy translated VRAM tile index is invalid")
            inferred_matches.append(
                {
                    "tile_index": tile_index,
                    "candidate_tile_sha256s": sorted(legacy_hash_set),
                }
            )
        matches = inferred_matches
        pairing_method = "slot-constrained-legacy-candidates"

    local_matches = []
    all_candidates = []
    aligned_candidates = []
    aligned_pages = set()
    aligned_rows = set()
    aligned_match_count = 0
    uniquely_aligned_count = 0
    for match in matches:
        if not isinstance(match, dict):
            raise ValueError("translated VRAM glyph match is invalid")
        tile_index = match.get("tile_index")
        tile_hash = match.get("tile_sha256")
        candidate_hashes = match.get("candidate_tile_sha256s")
        if (
            not isinstance(tile_index, int)
            or isinstance(tile_index, bool)
            or tile_index < 0
        ):
            raise ValueError("translated VRAM glyph match fields are invalid")
        if _is_sha256(tile_hash):
            candidate_hash_set = {str(tile_hash)}
        elif (
            isinstance(candidate_hashes, list)
            and candidate_hashes
            and all(_is_sha256(item) for item in candidate_hashes)
        ):
            candidate_hash_set = {str(item) for item in candidate_hashes}
        else:
            raise ValueError("translated VRAM glyph match hashes are invalid")
        candidates = [
            assignment
            for assignment in normalized_assignments
            if assignment["tile_sha256"] in candidate_hash_set
        ]
        aligned = [
            assignment
            for assignment in candidates
            if int(assignment["symbol"]) == (tile_index & 0xFF)
        ]
        all_candidates.extend(candidates)
        aligned_candidates.extend(aligned)
        aligned_pages.update(int(item["page"]) for item in aligned)
        aligned_rows.update(int(item["row_index"]) for item in aligned)
        aligned_match_count += int(bool(aligned))
        uniquely_aligned_count += int(len(aligned) == 1)
        local_matches.append(
            {
                "tile_index": tile_index,
                "candidate_tile_sha256s": sorted(candidate_hash_set),
                "candidate_assignments": candidates,
                "slot_aligned_assignments": aligned,
            }
        )

    counts = {
        "confirmed_vram_match_count": len(matches),
        "assignment_candidate_count": len(all_candidates),
        "slot_aligned_candidate_count": len(aligned_candidates),
        "match_with_slot_alignment_count": aligned_match_count,
        "uniquely_aligned_match_count": uniquely_aligned_count,
        "aligned_candidate_page_count": len(aligned_pages),
        "aligned_candidate_row_count": len(aligned_rows),
        "first_row_aligned_candidate_count": sum(
            int(item["row_index"]) == 1 for item in aligned_candidates
        ),
    }
    local = {
        "matches": local_matches,
        "aligned_pages": sorted(aligned_pages),
        "aligned_rows": sorted(aligned_rows),
        "pairing_method": pairing_method,
    }
    return counts, local


def build_first_context_translated_glyph_route(
    *,
    baseline_target_sha256: str,
    test_target_sha256: str,
    source_translated_vram_diff_sha256: str,
    source_local_encoding_sha256: str,
    local_route_sha256: str,
    analysis: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    aligned = (
        analysis["confirmed_vram_match_count"] > 0
        and analysis["match_with_slot_alignment_count"]
        == analysis["confirmed_vram_match_count"]
    )
    single_page = aligned and analysis["aligned_candidate_page_count"] == 1
    first_row = analysis["first_row_aligned_candidate_count"] > 0
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "translated-glyph-slot-route-confirmed"
            if aligned
            else "translated-glyph-slot-route-unresolved"
        ),
        "baseline_target_sha256": baseline_target_sha256,
        "test_target_sha256": test_target_sha256,
        "source_translated_vram_diff_sha256": source_translated_vram_diff_sha256,
        "source_local_encoding_sha256": source_local_encoding_sha256,
        "local_route_sha256": local_route_sha256,
        "captured_utc": captured_utc,
        "analysis": analysis,
        "direct_glyph_slot_alignment_confirmed": aligned,
        "single_font_page_candidate_confirmed": single_page,
        "first_row_candidate_observed": first_row,
        "local_payload_policy": (
            "pages-symbols-rows-characters-tile-hashes-and-matches-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": (
            "capture-changed-glyph-vdp-source-page"
            if aligned
            else "repair-translated-glyph-slot-alignment"
        ),
    }
    validate_first_context_translated_glyph_route(value)
    return value


def validate_first_context_translated_glyph_route(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("translated glyph route fields do not match")
    if (
        value.get("artifact_kind") != ARTIFACT_KIND
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("status")
        not in {
            "translated-glyph-slot-route-confirmed",
            "translated-glyph-slot-route-unresolved",
        }
        or not all(
            _is_sha256(value.get(key))
            for key in (
                "baseline_target_sha256",
                "test_target_sha256",
                "source_translated_vram_diff_sha256",
                "source_local_encoding_sha256",
                "local_route_sha256",
            )
        )
    ):
        raise ValueError("translated glyph route identity is invalid")
    counts = value.get("analysis")
    if (
        not isinstance(counts, dict)
        or set(counts) != COUNT_KEYS
        or any(
            not isinstance(item, int) or isinstance(item, bool) or item < 0
            for item in counts.values()
        )
    ):
        raise ValueError("translated glyph route counts are invalid")
    aligned = (
        counts["confirmed_vram_match_count"] > 0
        and counts["match_with_slot_alignment_count"]
        == counts["confirmed_vram_match_count"]
    )
    single_page = aligned and counts["aligned_candidate_page_count"] == 1
    first_row = counts["first_row_aligned_candidate_count"] > 0
    if (
        value["direct_glyph_slot_alignment_confirmed"] is not aligned
        or value["single_font_page_candidate_confirmed"] is not single_page
        or value["first_row_candidate_observed"] is not first_row
        or value["translation_build_eligible"] is not False
        or value["status"]
        != (
            "translated-glyph-slot-route-confirmed"
            if aligned
            else "translated-glyph-slot-route-unresolved"
        )
        or value["next_checkpoint"]
        != (
            "capture-changed-glyph-vdp-source-page"
            if aligned
            else "repair-translated-glyph-slot-alignment"
        )
        or value["local_payload_policy"]
        != "pages-symbols-rows-characters-tile-hashes-and-matches-local-only"
    ):
        raise ValueError("translated glyph route conclusion is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = {
        "diff": root / TRANSLATED_VRAM_PATH,
        "local_diff": root / TRANSLATED_VRAM_LOCAL_PATH,
        "encoding": root / TRANSLATION_ENCODING_LOCAL_PATH,
        "build": root / TRANSLATION_TEST_BUILD_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print("First context translated glyph route is not ready")
            return 0
        raise SystemExit("translated glyph route input is missing")
    diff = _load_object(paths["diff"])
    build = _load_object(paths["build"])
    local_diff = _load_object(paths["local_diff"])
    local_encoding = _load_object(paths["encoding"])
    validate_first_context_translated_vram_diff(diff)
    validate_first_context_translation_test_build(build)
    if (
        diff["status"] != "translated-custom-glyph-vram-confirmed"
        or diff["baseline_target_sha256"] != build["baseline_target_sha256"]
        or diff["test_target_sha256"] != build["test_target_sha256"]
        or local_diff.get("test_target_sha256") != diff["test_target_sha256"]
        or local_encoding.get("target_sha256") != diff["baseline_target_sha256"]
    ):
        raise ValueError("translated glyph route identity disagrees")
    counts, local_analysis = analyze_translated_glyph_route(
        local_diff,
        local_encoding,
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    local = {
        "artifact_kind": LOCAL_ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "baseline_target_sha256": diff["baseline_target_sha256"],
        "test_target_sha256": diff["test_target_sha256"],
        "captured_utc": captured_utc,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-pages-symbols-rows-characters-tile-hashes-or-matches"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_first_context_translated_glyph_route(
        baseline_target_sha256=str(diff["baseline_target_sha256"]),
        test_target_sha256=str(diff["test_target_sha256"]),
        source_translated_vram_diff_sha256=sha256_file(paths["diff"]),
        source_local_encoding_sha256=sha256_file(paths["encoding"]),
        local_route_sha256=sha256_file(local_path),
        analysis=counts,
        captured_utc=captured_utc,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR first context translated glyph route: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
