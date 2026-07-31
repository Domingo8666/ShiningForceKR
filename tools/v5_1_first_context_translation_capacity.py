#!/usr/bin/env python3
"""Plan the approved first-context Hangul page and screen its cell budget.

Approved target strings, source strings, glyph assignments, codepoints, tile
masks, and patch coordinates stay in ignored phone-local files.  The tracked
receipt contains hashes and fixed aggregate counts only.  The generated IPS is
a test-only font-page component; it is not a translation or release patch.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

try:
    from .expected_writes import (
        ExpectedWrite,
        apply_expected_writes,
        expected_writes_to_ips,
    )
    from .patch_io import extract_bps_target_literals, sha256_bytes, sha256_file
    from .v5_1_engine import analyze_patch
    from .v5_1_first_context_translation_approval import (
        LOCAL_REPORT_PATH as LOCAL_APPROVAL_PATH,
        PUBLISH_RELATIVE_PATH as APPROVAL_PATH,
        approval_counts,
        validate_first_context_translation_approval,
        validate_local_first_context_translation_approval,
    )
    from .v5_1_first_context_translation_review import (
        LOCAL_REPORT_PATH as LOCAL_REVIEW_PATH,
        PUBLISH_RELATIVE_PATH as REVIEW_PATH,
        first_context_review_batch_sha256,
        validate_first_context_translation_review,
    )
    from .v5_1_font_catalog import (
        build_font_catalog,
        parse_bdf_hangul,
        tile_ink_mask,
    )
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_test_phrase import (
        FONT_GLYPH_FIRST_SYMBOL,
        FONT_GLYPH_LAST_SYMBOL,
        FONT_TILE_BYTES,
        font_tile_offset,
    )
except ImportError:  # pragma: no cover - direct script execution
    from expected_writes import (
        ExpectedWrite,
        apply_expected_writes,
        expected_writes_to_ips,
    )
    from patch_io import extract_bps_target_literals, sha256_bytes, sha256_file
    from v5_1_engine import analyze_patch
    from v5_1_first_context_translation_approval import (
        LOCAL_REPORT_PATH as LOCAL_APPROVAL_PATH,
        PUBLISH_RELATIVE_PATH as APPROVAL_PATH,
        approval_counts,
        validate_first_context_translation_approval,
        validate_local_first_context_translation_approval,
    )
    from v5_1_first_context_translation_review import (
        LOCAL_REPORT_PATH as LOCAL_REVIEW_PATH,
        PUBLISH_RELATIVE_PATH as REVIEW_PATH,
        first_context_review_batch_sha256,
        validate_first_context_translation_review,
    )
    from v5_1_font_catalog import (
        build_font_catalog,
        parse_bdf_hangul,
        tile_ink_mask,
    )
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_test_phrase import (
        FONT_GLYPH_FIRST_SYMBOL,
        FONT_GLYPH_LAST_SYMBOL,
        FONT_TILE_BYTES,
        font_tile_offset,
    )


ARTIFACT_KIND = "sanitized-v5-1-first-context-translation-capacity"
LOCAL_ARTIFACT_KIND = "local-v5-1-first-context-translation-capacity"
SCHEMA_VERSION = 1
CUSTOM_TEST_PAGE = 243
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_translation_capacity.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_first_context_translation_capacity.json"
)
LOCAL_FONT_CATALOG_PATH = Path("analysis/local/v5_1_font_catalog.json")
LOCAL_BDF_PATH = Path("analysis/local/Galmuri7.bdf")
PATCH_PATH = Path("patch/Final_Conflict_Japan_to_Korean_v5.1.bps")
LOCAL_FONT_OVERLAY_PATH = Path(
    "build/Final_Conflict_Korean_first_context_font_page.ips"
)
COUNT_KEYS = {
    "context_entry_count",
    "target_character_count",
    "hangul_syllable_count",
    "unique_hangul_syllable_count",
    "existing_font_exact_match_count",
    "existing_font_missing_count",
    "verified_bdf_supply_count",
    "planned_custom_page_glyph_count",
    "custom_page_capacity",
    "custom_page_unused_slot_count",
    "source_cell_budget_fit_entry_count",
    "target_unique_non_hangul_count",
    "source_observed_target_non_hangul_count",
    "missing_source_observed_non_hangul_count",
    "font_page_write_byte_count",
    "font_page_changed_byte_count",
}
SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "review_batch_sha256",
    "first_context_translation_approval_sha256",
    "local_capacity_sha256",
    "font_overlay_sha256",
    "captured_utc",
    "capacity",
    "human_translation_approval_confirmed",
    "verified_galmuri7_supply_confirmed",
    "test_font_page_plan_complete",
    "source_visible_cell_screening_complete",
    "runtime_layout_confirmed",
    "full_game_font_allocation_confirmed",
    "text_encoding_confirmed",
    "font_overlay_scope",
    "source_and_target_text_local_only",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return timestamp.utcoffset() == timezone.utc.utcoffset(timestamp)


def _is_hangul_syllable(character: str) -> bool:
    return "\uac00" <= character <= "\ud7a3"


def tile_bytes_from_ink_mask(mask: tuple[int, ...]) -> bytes:
    if len(mask) != 8 or any(not 0 <= row <= 0xFF for row in mask):
        raise ValueError("first context font glyph mask is invalid")
    output = bytearray()
    for row in mask:
        background = (~row) & 0xFF
        output.extend((0xFF, background, background, background))
    tile = bytes(output)
    if len(tile) != FONT_TILE_BYTES or tile_ink_mask(tile) != mask:
        raise ValueError("first context font tile roundtrip failed")
    return tile


def analyze_first_context_translation_capacity(
    *,
    source_rows: list[dict[str, object]],
    target_rows: list[dict[str, object]],
    font_catalog: dict[str, object],
    bdf_hangul: dict[int, tuple[int, ...]],
) -> tuple[dict[str, int], dict[str, object]]:
    if len(source_rows) != len(target_rows) or len(source_rows) < 4:
        raise ValueError("first context capacity row count does not match")
    entries = font_catalog.get("entries")
    if not isinstance(entries, list):
        raise ValueError("first context capacity font catalogue is missing")
    existing: set[str] = set()
    for entry in entries:
        if (
            isinstance(entry, dict)
            and entry.get("status") == "unique"
            and isinstance(entry.get("characters"), list)
            and len(entry["characters"]) == 1
            and isinstance(entry["characters"][0], str)
        ):
            existing.add(entry["characters"][0])

    sources: list[str] = []
    targets: list[str] = []
    for expected_index, (source_row, target_row) in enumerate(
        zip(source_rows, target_rows),
        start=1,
    ):
        if (
            not isinstance(source_row, dict)
            or not isinstance(target_row, dict)
            or source_row.get("review_index") != expected_index
            or target_row.get("review_index") != expected_index
            or not isinstance(source_row.get("source_text"), str)
            or not isinstance(target_row.get("target_text"), str)
        ):
            raise ValueError("first context capacity row is invalid")
        sources.append(source_row["source_text"])
        targets.append(target_row["target_text"])

    unique_hangul = list(
        dict.fromkeys(
            character
            for target in targets
            for character in target
            if _is_hangul_syllable(character)
        )
    )
    page_capacity = (
        FONT_GLYPH_LAST_SYMBOL - FONT_GLYPH_FIRST_SYMBOL + 1
    )
    if len(unique_hangul) > page_capacity:
        raise ValueError("first context Hangul demand exceeds one test page")
    missing_bdf = [
        character
        for character in unique_hangul
        if ord(character) not in bdf_hangul
    ]
    if missing_bdf:
        raise ValueError("first context Hangul glyph is missing from Galmuri7")
    assignments = []
    for index, character in enumerate(unique_hangul):
        mask = bdf_hangul[ord(character)]
        tile = tile_bytes_from_ink_mask(mask)
        assignments.append(
            {
                "character": character,
                "codepoint": f"U+{ord(character):04X}",
                "page": CUSTOM_TEST_PAGE,
                "symbol": FONT_GLYPH_FIRST_SYMBOL + index,
                "ink_mask": list(mask),
                "tile_sha256": sha256_bytes(tile),
            }
        )

    source_non_hangul = {
        character
        for source in sources
        for character in source
        if not _is_hangul_syllable(character)
    }
    target_non_hangul = {
        character
        for target in targets
        for character in target
        if not _is_hangul_syllable(character)
    }
    missing_non_hangul = target_non_hangul - source_non_hangul
    rows = []
    fit = 0
    for index, (source, target) in enumerate(zip(sources, targets), start=1):
        source_cells = len(source)
        target_cells = len(target)
        fits = target_cells <= source_cells
        fit += int(fits)
        rows.append(
            {
                "review_index": index,
                "source_text": source,
                "target_text": target,
                "source_visible_cell_count": source_cells,
                "target_visible_cell_count": target_cells,
                "target_within_source_cell_budget": fits,
            }
        )
    counts = {
        "context_entry_count": len(rows),
        "target_character_count": sum(len(target) for target in targets),
        "hangul_syllable_count": sum(
            _is_hangul_syllable(character)
            for target in targets
            for character in target
        ),
        "unique_hangul_syllable_count": len(unique_hangul),
        "existing_font_exact_match_count": sum(
            character in existing for character in unique_hangul
        ),
        "existing_font_missing_count": sum(
            character not in existing for character in unique_hangul
        ),
        "verified_bdf_supply_count": len(assignments),
        "planned_custom_page_glyph_count": len(assignments),
        "custom_page_capacity": page_capacity,
        "custom_page_unused_slot_count": page_capacity - len(assignments),
        "source_cell_budget_fit_entry_count": fit,
        "target_unique_non_hangul_count": len(target_non_hangul),
        "source_observed_target_non_hangul_count":
            len(target_non_hangul & source_non_hangul),
        "missing_source_observed_non_hangul_count": len(missing_non_hangul),
        "font_page_write_byte_count": len(assignments) * FONT_TILE_BYTES,
        "font_page_changed_byte_count": 0,
    }
    return counts, {
        "rows": rows,
        "assignments": assignments,
        "missing_source_observed_non_hangul": sorted(missing_non_hangul),
        "custom_test_page": CUSTOM_TEST_PAGE,
        "publication_policy": (
            "never-publish-source-target-text-characters-codepoints-glyph-"
            "assignments-masks-symbols-pages-or-patch-coordinates"
        ),
    }


def build_first_context_translation_capacity(
    *,
    target_sha256: str,
    review_batch_sha256: str,
    first_context_translation_approval_sha256: str,
    local_capacity_sha256: str,
    font_overlay_sha256: str,
    capacity: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    ready = (
        capacity["context_entry_count"] >= 4
        and capacity["verified_bdf_supply_count"]
        == capacity["unique_hangul_syllable_count"]
        and capacity["planned_custom_page_glyph_count"]
        <= capacity["custom_page_capacity"]
        and capacity["source_cell_budget_fit_entry_count"]
        == capacity["context_entry_count"]
        and capacity["missing_source_observed_non_hangul_count"] == 0
        and capacity["font_page_write_byte_count"] > 0
        and capacity["font_page_changed_byte_count"] > 0
    )
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "first-context-test-font-plan-ready"
            if ready
            else "first-context-translation-capacity-incomplete"
        ),
        "target_sha256": target_sha256,
        "review_batch_sha256": review_batch_sha256,
        "first_context_translation_approval_sha256":
            first_context_translation_approval_sha256,
        "local_capacity_sha256": local_capacity_sha256,
        "font_overlay_sha256": font_overlay_sha256,
        "captured_utc": captured_utc,
        "capacity": capacity,
        "human_translation_approval_confirmed": True,
        "verified_galmuri7_supply_confirmed": ready,
        "test_font_page_plan_complete": ready,
        "source_visible_cell_screening_complete": ready,
        "runtime_layout_confirmed": False,
        "full_game_font_allocation_confirmed": False,
        "text_encoding_confirmed": False,
        "font_overlay_scope": "first-context-technical-test-only",
        "source_and_target_text_local_only": True,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "encode-first-context-translation-test"
            if ready
            else "repair-first-context-translation-capacity"
        ),
    }
    validate_first_context_translation_capacity(value)
    return value


def validate_first_context_translation_capacity(
    value: dict[str, object],
) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError("first context translation capacity fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "first-context-test-font-plan-ready",
            "first-context-translation-capacity-incomplete",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "review_batch_sha256",
                "first_context_translation_approval_sha256",
                "local_capacity_sha256",
                "font_overlay_sha256",
            )
        )
        or not _is_utc_timestamp(value["captured_utc"])
    ):
        raise ValueError("first context translation capacity identity is invalid")
    counts = value["capacity"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("first context translation capacity counts do not match")
    if any(
        not isinstance(count, int)
        or isinstance(count, bool)
        or count < 0
        or count > 1000000
        for count in counts.values()
    ):
        raise ValueError("first context translation capacity count is invalid")
    ready = (
        counts["context_entry_count"] >= 4
        and counts["verified_bdf_supply_count"]
        == counts["unique_hangul_syllable_count"]
        and counts["planned_custom_page_glyph_count"]
        <= counts["custom_page_capacity"]
        and counts["source_cell_budget_fit_entry_count"]
        == counts["context_entry_count"]
        and counts["missing_source_observed_non_hangul_count"] == 0
        and counts["font_page_write_byte_count"] > 0
        and counts["font_page_changed_byte_count"] > 0
    )
    if (
        value["status"]
        != (
            "first-context-test-font-plan-ready"
            if ready
            else "first-context-translation-capacity-incomplete"
        )
        or value["human_translation_approval_confirmed"] is not True
        or value["verified_galmuri7_supply_confirmed"] is not ready
        or value["test_font_page_plan_complete"] is not ready
        or value["source_visible_cell_screening_complete"] is not ready
        or value["runtime_layout_confirmed"] is not False
        or value["full_game_font_allocation_confirmed"] is not False
        or value["text_encoding_confirmed"] is not False
        or value["font_overlay_scope"]
        != "first-context-technical-test-only"
        or value["source_and_target_text_local_only"] is not True
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != (
            "encode-first-context-translation-test"
            if ready
            else "repair-first-context-translation-capacity"
        )
    ):
        raise ValueError("first context translation capacity is inconsistent")


def _required_inputs(root: Path) -> dict[str, Path]:
    return {
        "approval": root / APPROVAL_PATH,
        "local_approval": root / LOCAL_APPROVAL_PATH,
        "review": root / REVIEW_PATH,
        "local_review": root / LOCAL_REVIEW_PATH,
        "font_catalog": root / LOCAL_FONT_CATALOG_PATH,
        "bdf": root / LOCAL_BDF_PATH,
        "patch": root / PATCH_PATH,
    }


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = _required_inputs(root)
    if not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print("First context translation capacity is not ready")
            return 0
        raise SystemExit("first context translation capacity input is missing")

    approval = _load_json_object(paths["approval"])
    local_approval = _load_json_object(paths["local_approval"])
    review = _load_json_object(paths["review"])
    local_review = _load_json_object(paths["local_review"])
    font_catalog = _load_json_object(paths["font_catalog"])
    validate_first_context_translation_approval(approval)
    validate_local_first_context_translation_approval(local_approval)
    validate_first_context_translation_review(review)
    source_rows = local_review.get("rows")
    target_rows = local_approval.get("rows")
    if not isinstance(source_rows, list) or not isinstance(target_rows, list):
        raise ValueError("first context translation capacity rows are missing")
    if (
        approval["target_sha256"] != review["target_sha256"]
        or local_approval["target_sha256"] != approval["target_sha256"]
        or local_approval["review_batch_sha256"]
        != approval["review_batch_sha256"]
        or first_context_review_batch_sha256(source_rows)
        != approval["review_batch_sha256"]
        or approval_counts(
            local_approval,
            context_entry_count=len(source_rows),
        )
        != approval["approval"]
        or sha256_file(paths["local_approval"])
        != approval["local_approval_sha256"]
    ):
        raise ValueError("first context translation capacity identity disagrees")

    patch = paths["patch"].read_bytes()
    bdf = paths["bdf"].read_bytes()
    analyze_patch(patch)
    rebuilt_catalog = build_font_catalog(patch, bdf)
    if rebuilt_catalog != font_catalog:
        raise ValueError("first context translation font catalogue disagrees")
    bdf_hangul = parse_bdf_hangul(bdf)
    counts, local_analysis = analyze_first_context_translation_capacity(
        source_rows=source_rows,
        target_rows=target_rows,
        font_catalog=font_catalog,
        bdf_hangul=bdf_hangul,
    )

    sparse = extract_bps_target_literals(patch)
    assignments = local_analysis["assignments"]
    assert isinstance(assignments, list)
    first_offset = font_tile_offset(CUSTOM_TEST_PAGE, FONT_GLYPH_FIRST_SYMBOL)
    after = b"".join(
        tile_bytes_from_ink_mask(tuple(assignment["ink_mask"]))
        for assignment in assignments
    )
    end = first_offset + len(after)
    if any(value == 0 for value in sparse.known[first_offset:end]):
        raise ValueError("first context font page contains source-dependent bytes")
    write = ExpectedWrite(
        writer="first-context-approved-font-page",
        purpose="first-context-technical-test-only",
        offset=first_offset,
        before=sparse.data[first_offset:end],
        after=after,
        allowed_start=first_offset,
        allowed_end_exclusive=end,
    )
    _, audit = apply_expected_writes(sparse.data, [write])
    counts["font_page_changed_byte_count"] = int(audit["changed_byte_count"])
    overlay = expected_writes_to_ips([write])
    overlay_path = root / LOCAL_FONT_OVERLAY_PATH
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    overlay_path.write_bytes(overlay)
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    local = {
        "artifact_kind": LOCAL_ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "target_sha256": approval["target_sha256"],
        "review_batch_sha256": approval["review_batch_sha256"],
        "captured_utc": captured_utc,
        "capacity": counts,
        "analysis": local_analysis,
        "font_overlay_sha256": sha256_bytes(overlay),
        "font_overlay_size": len(overlay),
        "font_write_audit": audit,
        "publication_policy": (
            "never-publish-source-target-text-characters-codepoints-glyph-"
            "assignments-masks-symbols-pages-or-patch-coordinates"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_first_context_translation_capacity(
        target_sha256=str(approval["target_sha256"]),
        review_batch_sha256=str(approval["review_batch_sha256"]),
        first_context_translation_approval_sha256=sha256_file(
            paths["approval"]
        ),
        local_capacity_sha256=sha256_file(local_path),
        font_overlay_sha256=sha256_bytes(overlay),
        capacity=counts,
        captured_utc=captured_utc,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR first context translation capacity: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
