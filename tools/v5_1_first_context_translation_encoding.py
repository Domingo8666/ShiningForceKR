#!/usr/bin/env python3
"""Encode the approved first-context translation without writing a ROM.

The stage assigns the approved visible characters to two test-only font pages,
re-inserts every visually reviewed non-text glyph token, and proves each of the
four resulting symbol streams roundtrips through the verified Korean Huffman
trees.  Text, symbols, page coordinates, encoded bytes, and glyph positions
remain in ignored phone-local files.
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
    from .patch_io import PatchError, extract_bps_target_literals, sha256_bytes
    from .sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        _symbol_codes,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from .v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
        analyze_patch,
    )
    from .v5_1_first_context_translation_approval import (
        LOCAL_REPORT_PATH as LOCAL_APPROVAL_PATH,
        PUBLISH_RELATIVE_PATH as APPROVAL_PATH,
        validate_first_context_translation_approval,
        validate_local_first_context_translation_approval,
    )
    from .v5_1_first_context_translation_capacity import (
        LOCAL_BDF_PATH,
        LOCAL_REPORT_PATH as LOCAL_CAPACITY_PATH,
        PATCH_PATH,
        PUBLISH_RELATIVE_PATH as CAPACITY_PATH,
        tile_bytes_from_ink_mask,
        validate_first_context_translation_capacity,
    )
    from .v5_1_first_context_translation_review import (
        LOCAL_REPORT_PATH as LOCAL_REVIEW_PATH,
    )
    from .v5_1_font_catalog import parse_bdf_glyphs
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_runtime_context_glyph_preservation import (
        LOCAL_REPORT_PATH as LOCAL_PRESERVATION_PATH,
        PUBLISH_RELATIVE_PATH as PRESERVATION_PATH,
        validate_runtime_context_glyph_preservation,
    )
    from .v5_1_source_target_runtime_context import (
        LOCAL_REPORT_PATH as LOCAL_CONTEXT_PATH,
    )
    from .v5_1_source_target_section_projection import (
        LOCAL_REPORT_PATH as LOCAL_PROJECTION_PATH,
    )
    from .v5_1_test_phrase import (
        FONT_GLYPH_FIRST_SYMBOL,
        FONT_GLYPH_LAST_SYMBOL,
        FONT_TILE_BYTES,
        font_tile_offset,
        page_select_symbols,
    )
except ImportError:  # pragma: no cover - direct script execution
    from expected_writes import (
        ExpectedWrite,
        apply_expected_writes,
        expected_writes_to_ips,
    )
    from patch_io import PatchError, extract_bps_target_literals, sha256_bytes
    from sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        _symbol_codes,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
        analyze_patch,
    )
    from v5_1_first_context_translation_approval import (
        LOCAL_REPORT_PATH as LOCAL_APPROVAL_PATH,
        PUBLISH_RELATIVE_PATH as APPROVAL_PATH,
        validate_first_context_translation_approval,
        validate_local_first_context_translation_approval,
    )
    from v5_1_first_context_translation_capacity import (
        LOCAL_BDF_PATH,
        LOCAL_REPORT_PATH as LOCAL_CAPACITY_PATH,
        PATCH_PATH,
        PUBLISH_RELATIVE_PATH as CAPACITY_PATH,
        tile_bytes_from_ink_mask,
        validate_first_context_translation_capacity,
    )
    from v5_1_first_context_translation_review import (
        LOCAL_REPORT_PATH as LOCAL_REVIEW_PATH,
    )
    from v5_1_font_catalog import parse_bdf_glyphs
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_runtime_context_glyph_preservation import (
        LOCAL_REPORT_PATH as LOCAL_PRESERVATION_PATH,
        PUBLISH_RELATIVE_PATH as PRESERVATION_PATH,
        validate_runtime_context_glyph_preservation,
    )
    from v5_1_source_target_runtime_context import (
        LOCAL_REPORT_PATH as LOCAL_CONTEXT_PATH,
    )
    from v5_1_source_target_section_projection import (
        LOCAL_REPORT_PATH as LOCAL_PROJECTION_PATH,
    )
    from v5_1_test_phrase import (
        FONT_GLYPH_FIRST_SYMBOL,
        FONT_GLYPH_LAST_SYMBOL,
        FONT_TILE_BYTES,
        font_tile_offset,
        page_select_symbols,
    )


ARTIFACT_KIND = "sanitized-v5-1-first-context-translation-encoding"
LOCAL_ARTIFACT_KIND = "local-v5-1-first-context-translation-encoding"
SCHEMA_VERSION = 1
ROW_FONT_PAGES = (240, 241, 242, 243)
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_translation_encoding.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_first_context_translation_encoding.json"
)
LOCAL_COMBINED_FONT_OVERLAY_PATH = Path(
    "build/Final_Conflict_Korean_first_context_font_pages.ips"
)
COUNT_KEYS = {
    "context_entry_count",
    "target_character_count",
    "unique_target_character_count",
    "custom_font_page_count",
    "custom_font_glyph_count",
    "preserved_non_text_glyph_occurrence_count",
    "planned_visible_symbol_count",
    "planned_page_select_count",
    "planned_terminator_count",
    "planned_total_symbol_count",
    "huffman_roundtrip_entry_count",
    "huffman_failure_entry_count",
    "encoded_bit_count",
    "encoded_byte_count",
    "maximum_encoded_entry_bit_count",
    "font_page_write_byte_count",
    "font_page_changed_byte_count",
    "internally_encodable_font_page_count",
    "initially_selectable_font_page_count",
    "glyph_transition_edge_count",
    "glyph_symbol_page_select_exit_count",
    "glyph_symbol_terminator_exit_count",
    "initial_page_token_failure_entry_count",
    "post_initial_page_token_failure_entry_count",
}
SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "review_batch_sha256",
    "first_context_translation_capacity_sha256",
    "runtime_context_glyph_preservation_sha256",
    "local_encoding_sha256",
    "combined_font_overlay_sha256",
    "captured_utc",
    "encoding",
    "human_translation_approval_confirmed",
    "reviewed_non_text_glyph_visuals_preserved",
    "original_non_text_glyph_coordinates_reused",
    "custom_test_font_pages_complete",
    "huffman_roundtrip_complete",
    "text_encoding_confirmed",
    "record_storage_capacity_confirmed",
    "runtime_layout_confirmed",
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


def measure_huffman_route_capacity(
    trees: dict[int, object],
) -> dict[str, int]:
    codes = {
        previous: set(_symbol_codes(tree.root))
        for previous, tree in trees.items()
    }
    page_select = 0x5F
    initial_can_select = page_select in codes.get(CANDIDATE_END_SYMBOL, set())
    internally_encodable = 0
    for page in range(244):
        _, high, low = page_select_symbols(page)
        if (
            high in codes.get(page_select, set())
            and low in codes.get(high, set())
        ):
            internally_encodable += 1
    glyph_symbols = range(
        FONT_GLYPH_FIRST_SYMBOL,
        FONT_GLYPH_LAST_SYMBOL + 1,
    )
    return {
        "internally_encodable_font_page_count": internally_encodable,
        "initially_selectable_font_page_count": (
            internally_encodable if initial_can_select else 0
        ),
        "glyph_transition_edge_count": sum(
            next_symbol in codes.get(previous, set())
            for previous in glyph_symbols
            for next_symbol in glyph_symbols
        ),
        "glyph_symbol_page_select_exit_count": sum(
            page_select in codes.get(symbol, set())
            for symbol in glyph_symbols
        ),
        "glyph_symbol_terminator_exit_count": sum(
            CANDIDATE_END_SYMBOL in codes.get(symbol, set())
            for symbol in glyph_symbols
        ),
    }


def first_missing_transition_index(
    trees: dict[int, object],
    symbols: list[int],
) -> int | None:
    previous = CANDIDATE_END_SYMBOL
    for index, symbol in enumerate(symbols):
        tree = trees.get(previous)
        if tree is None or symbol not in _symbol_codes(tree.root):
            return index
        previous = symbol
    return None


def build_character_assignments(
    *,
    target_rows: list[dict[str, object]],
    hangul_assignments: list[dict[str, object]],
    reference_glyphs: dict[int, tuple[int, ...]],
) -> tuple[dict[str, tuple[int, int]], list[dict[str, object]]]:
    coordinates: dict[str, tuple[int, int]] = {}
    local_assignments: list[dict[str, object]] = []
    for assignment in hangul_assignments:
        if (
            not isinstance(assignment, dict)
            or not isinstance(assignment.get("character"), str)
            or len(assignment["character"]) != 1
            or not isinstance(assignment.get("page"), int)
            or not isinstance(assignment.get("symbol"), int)
        ):
            raise ValueError("first context encoding Hangul assignment is invalid")
        character = assignment["character"]
        coordinate = (assignment["page"], assignment["symbol"])
        coordinates[character] = coordinate
        local_assignments.append(dict(assignment))

    non_hangul = list(
        dict.fromkeys(
            character
            for row in target_rows
            for character in str(row.get("target_text", ""))
            if not _is_hangul_syllable(character)
        )
    )
    capacity = FONT_GLYPH_LAST_SYMBOL - FONT_GLYPH_FIRST_SYMBOL + 1
    if len(non_hangul) > capacity:
        raise ValueError("first context non-Hangul demand exceeds one test page")
    for index, character in enumerate(non_hangul):
        mask = reference_glyphs.get(ord(character))
        if mask is None:
            raise ValueError(
                "first context non-Hangul glyph is missing from Galmuri7"
            )
        symbol = FONT_GLYPH_FIRST_SYMBOL + index
        coordinates[character] = (ROW_FONT_PAGES[0], symbol)
        tile = tile_bytes_from_ink_mask(mask)
        local_assignments.append(
            {
                "character": character,
                "codepoint": f"U+{ord(character):04X}",
                "page": ROW_FONT_PAGES[0],
                "symbol": symbol,
                "ink_mask": list(mask),
                "tile_sha256": sha256_bytes(tile),
            }
        )
    return coordinates, local_assignments


def locate_preserved_occurrences(
    *,
    context_rows: list[dict[str, object]],
    projection_pairs: list[dict[str, object]],
    preservation_records: list[dict[str, object]],
    target_rows: list[dict[str, object]],
) -> list[list[dict[str, int]]]:
    preserved_coordinates = {
        (record.get("page"), record.get("symbol"))
        for record in preservation_records
        if isinstance(record, dict)
        and record.get("preservation_action") == "preserve-original-glyph-token"
    }
    if len(preserved_coordinates) != len(preservation_records):
        raise ValueError("first context preserved glyph coordinates are invalid")
    pair_index = {}
    for pair in projection_pairs:
        if not isinstance(pair, dict):
            raise ValueError("first context projection pair is invalid")
        key = (pair.get("source_section_index"), pair.get("source_line_index"))
        if key in pair_index:
            raise ValueError("first context projection pair is duplicated")
        pair_index[key] = pair
    output: list[list[dict[str, int]]] = []
    occurrence_counts = {coordinate: 0 for coordinate in preserved_coordinates}
    for expected_index, (context_row, target_row) in enumerate(
        zip(context_rows, target_rows),
        start=1,
    ):
        if (
            not isinstance(context_row, dict)
            or context_row.get("mapping_status") != "unique"
            or target_row.get("review_index") != expected_index
            or not isinstance(target_row.get("target_text"), str)
        ):
            raise ValueError("first context encoding row is invalid")
        key = (
            context_row.get("source_section_index"),
            context_row.get("source_line_index"),
        )
        pair = pair_index.get(key)
        target_record = None if pair is None else pair.get("target_record")
        tokens = (
            None
            if not isinstance(target_record, dict)
            else target_record.get("tokens")
        )
        if not isinstance(tokens, list):
            raise ValueError("first context encoding source tokens are missing")
        ordinary_glyph_count = sum(
            isinstance(token, dict)
            and token.get("kind") == "glyph"
            and (token.get("page"), token.get("symbol"))
            not in preserved_coordinates
            for token in tokens
        )
        seen = 0
        row_occurrences: list[dict[str, int]] = []
        target_length = len(target_row["target_text"])
        for token in tokens:
            if not isinstance(token, dict):
                raise ValueError("first context encoding token is invalid")
            if token.get("kind") != "glyph":
                continue
            coordinate = (token.get("page"), token.get("symbol"))
            if coordinate in preserved_coordinates:
                position = round(
                    seen / max(1, ordinary_glyph_count) * target_length
                )
                row_occurrences.append(
                    {
                        "target_character_index": min(position, target_length),
                        "page": int(coordinate[0]),
                        "symbol": int(coordinate[1]),
                    }
                )
                occurrence_counts[coordinate] += 1
            else:
                seen += 1
        output.append(row_occurrences)
    declared = {
        (record["page"], record["symbol"]): record["occurrence_count"]
        for record in preservation_records
    }
    if occurrence_counts != declared:
        raise ValueError("first context preserved glyph occurrences disagree")
    return output


def build_row_visuals(
    *,
    target_rows: list[dict[str, object]],
    preserved_by_row: list[list[dict[str, int]]],
) -> list[list[str]]:
    if len(target_rows) != len(preserved_by_row):
        raise ValueError("first context visual row count does not match")
    output = []
    for target_row, preserved in zip(target_rows, preserved_by_row):
        target = target_row.get("target_text")
        if not isinstance(target, str):
            raise ValueError("first context visual target is invalid")
        insertions: dict[int, list[str]] = {}
        for occurrence in preserved:
            position = occurrence.get("target_character_index")
            page = occurrence.get("page")
            symbol = occurrence.get("symbol")
            if (
                not isinstance(position, int)
                or not 0 <= position <= len(target)
                or not isinstance(page, int)
                or not isinstance(symbol, int)
            ):
                raise ValueError("first context visual insertion is invalid")
            insertions.setdefault(position, []).append(
                f"preserved:{page:02X}:{symbol:02X}"
            )
        visuals = []
        for position in range(len(target) + 1):
            visuals.extend(insertions.get(position, []))
            if position < len(target):
                visuals.append(f"text:{target[position]}")
        output.append(visuals)
    return output


def solve_row_visual_symbols(
    *,
    trees: dict[int, object],
    page: int,
    visuals: list[str],
) -> dict[str, int]:
    if not visuals:
        raise ValueError("first context visual row is empty")
    unique_visuals = list(dict.fromkeys(visuals))
    capacity = FONT_GLYPH_LAST_SYMBOL - FONT_GLYPH_FIRST_SYMBOL + 1
    if len(unique_visuals) > capacity:
        raise ValueError("first context visual row exceeds one font page")
    codes = {
        previous: set(_symbol_codes(tree.root))
        for previous, tree in trees.items()
    }
    page_token = page_select_symbols(page)
    previous = CANDIDATE_END_SYMBOL
    for symbol in page_token:
        if symbol not in codes.get(previous, set()):
            raise ValueError("first context row font page is not encodable")
        previous = symbol
    start_previous = previous

    outgoing: dict[str, set[str]] = {
        visual: set() for visual in unique_visuals
    }
    incoming: dict[str, set[str]] = {
        visual: set() for visual in unique_visuals
    }
    self_edges = set()
    for left, right in zip(visuals, visuals[1:]):
        if left == right:
            self_edges.add(left)
        else:
            outgoing[left].add(right)
            incoming[right].add(left)
    starts = {visuals[0]}
    ends = {visuals[-1]}
    glyph_symbols = set(
        range(FONT_GLYPH_FIRST_SYMBOL, FONT_GLYPH_LAST_SYMBOL + 1)
    )
    domains: dict[str, set[int]] = {}
    for visual in unique_visuals:
        domain = set(glyph_symbols)
        if visual in starts:
            domain &= codes.get(start_previous, set())
        if visual in ends:
            domain = {
                symbol
                for symbol in domain
                if CANDIDATE_END_SYMBOL in codes.get(symbol, set())
            }
        if visual in self_edges:
            domain = {
                symbol
                for symbol in domain
                if symbol in codes.get(symbol, set())
            }
        if not domain:
            raise ValueError("first context visual has no Huffman symbol domain")
        domains[visual] = domain

    assignments: dict[str, int] = {}
    used: set[int] = set()

    def candidates(visual: str) -> list[int]:
        possible = domains[visual] - used
        for source in incoming[visual]:
            if source in assignments:
                possible &= codes.get(assignments[source], set())
        for target in outgoing[visual]:
            if target in assignments:
                possible = {
                    symbol
                    for symbol in possible
                    if assignments[target] in codes.get(symbol, set())
                }
        return sorted(possible)

    def forward_possible() -> bool:
        for visual in unique_visuals:
            if visual in assignments:
                continue
            if not candidates(visual):
                return False
        return True

    def search() -> bool:
        if len(assignments) == len(unique_visuals):
            return True
        remaining = [
            visual for visual in unique_visuals if visual not in assignments
        ]
        remaining.sort(
            key=lambda visual: (
                len(candidates(visual)),
                -(len(incoming[visual]) + len(outgoing[visual])),
                unique_visuals.index(visual),
            )
        )
        visual = remaining[0]
        for symbol in candidates(visual):
            assignments[visual] = symbol
            used.add(symbol)
            if forward_possible() and search():
                return True
            used.remove(symbol)
            del assignments[visual]
        return False

    if not search():
        raise ValueError("first context visual row has no Huffman assignment")
    return assignments


def build_single_page_symbol_rows(
    *,
    trees: dict[int, object],
    target_rows: list[dict[str, object]],
    preserved_by_row: list[list[dict[str, int]]],
    pages: tuple[int, ...] = ROW_FONT_PAGES,
) -> tuple[
    dict[str, int],
    list[dict[str, object]],
    list[dict[str, int]],
]:
    visual_rows = build_row_visuals(
        target_rows=target_rows,
        preserved_by_row=preserved_by_row,
    )
    if len(visual_rows) != len(pages):
        raise ValueError("first context row font page count does not match")
    rows = []
    assignments_by_row = []
    for expected_index, (target_row, visuals, page) in enumerate(
        zip(target_rows, visual_rows, pages),
        start=1,
    ):
        assignments = solve_row_visual_symbols(
            trees=trees,
            page=page,
            visuals=visuals,
        )
        symbols = page_select_symbols(page)
        symbols.extend(assignments[visual] for visual in visuals)
        symbols.append(CANDIDATE_END_SYMBOL)
        rows.append(
            {
                "review_index": expected_index,
                "target_text": target_row["target_text"],
                "visuals": visuals,
                "symbols": symbols,
                "page_select_count": 1,
                "visible_symbol_count": len(visuals),
                "preserved_non_text_glyph_count": sum(
                    visual.startswith("preserved:") for visual in visuals
                ),
            }
        )
        assignments_by_row.append(
            {
                visual: symbol for visual, symbol in assignments.items()
            }
        )
    visible_count = sum(len(visuals) for visuals in visual_rows)
    preserved_count = sum(
        visual.startswith("preserved:")
        for visuals in visual_rows
        for visual in visuals
    )
    return {
        "planned_visible_symbol_count": visible_count,
        "planned_page_select_count": len(rows),
        "preserved_non_text_glyph_occurrence_count": preserved_count,
        "planned_terminator_count": len(rows),
        "planned_total_symbol_count": sum(len(row["symbols"]) for row in rows),
    }, rows, assignments_by_row


def build_symbol_rows(
    *,
    target_rows: list[dict[str, object]],
    character_coordinates: dict[str, tuple[int, int]],
    preserved_by_row: list[list[dict[str, int]]],
) -> tuple[dict[str, int], list[dict[str, object]]]:
    if len(target_rows) != len(preserved_by_row):
        raise ValueError("first context symbol row count does not match")
    rows = []
    total_page_selects = 0
    total_visible = 0
    total_preserved = 0
    for expected_index, (target_row, preserved) in enumerate(
        zip(target_rows, preserved_by_row),
        start=1,
    ):
        if (
            target_row.get("review_index") != expected_index
            or not isinstance(target_row.get("target_text"), str)
        ):
            raise ValueError("first context target symbol row is invalid")
        target = target_row["target_text"]
        insertions: dict[int, list[tuple[int, int]]] = {}
        for occurrence in preserved:
            position = occurrence.get("target_character_index")
            page = occurrence.get("page")
            symbol = occurrence.get("symbol")
            if (
                not isinstance(position, int)
                or not 0 <= position <= len(target)
                or not isinstance(page, int)
                or not isinstance(symbol, int)
            ):
                raise ValueError("first context preserved insertion is invalid")
            insertions.setdefault(position, []).append((page, symbol))
        symbols: list[int] = []
        selected_page: int | None = None
        page_select_count = 0
        visible_count = 0

        def emit(page: int, symbol: int) -> None:
            nonlocal selected_page, page_select_count, visible_count
            if page != selected_page:
                symbols.extend(page_select_symbols(page))
                selected_page = page
                page_select_count += 1
            symbols.append(symbol)
            visible_count += 1

        for position in range(len(target) + 1):
            for page, symbol in insertions.get(position, []):
                emit(page, symbol)
                total_preserved += 1
            if position < len(target):
                coordinate = character_coordinates.get(target[position])
                if coordinate is None:
                    raise ValueError("first context target character is unmapped")
                emit(*coordinate)
        symbols.append(CANDIDATE_END_SYMBOL)
        total_page_selects += page_select_count
        total_visible += visible_count
        rows.append(
            {
                "review_index": expected_index,
                "target_text": target,
                "symbols": symbols,
                "page_select_count": page_select_count,
                "visible_symbol_count": visible_count,
                "preserved_non_text_glyph_count": len(preserved),
            }
        )
    return {
        "planned_visible_symbol_count": total_visible,
        "planned_page_select_count": total_page_selects,
        "preserved_non_text_glyph_occurrence_count": total_preserved,
        "planned_terminator_count": len(rows),
        "planned_total_symbol_count": sum(len(row["symbols"]) for row in rows),
    }, rows


def build_first_context_translation_encoding(
    *,
    target_sha256: str,
    review_batch_sha256: str,
    first_context_translation_capacity_sha256: str,
    runtime_context_glyph_preservation_sha256: str,
    local_encoding_sha256: str,
    combined_font_overlay_sha256: str,
    encoding: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    complete = (
        encoding["context_entry_count"] >= 4
        and encoding["huffman_roundtrip_entry_count"]
        == encoding["context_entry_count"]
        and encoding["huffman_failure_entry_count"] == 0
        and encoding["preserved_non_text_glyph_occurrence_count"] == 5
        and encoding["custom_font_page_count"] == len(ROW_FONT_PAGES)
        and encoding["font_page_changed_byte_count"] > 0
    )
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "first-context-translation-encoding-ready"
            if complete
            else "first-context-translation-encoding-incomplete"
        ),
        "target_sha256": target_sha256,
        "review_batch_sha256": review_batch_sha256,
        "first_context_translation_capacity_sha256":
            first_context_translation_capacity_sha256,
        "runtime_context_glyph_preservation_sha256":
            runtime_context_glyph_preservation_sha256,
        "local_encoding_sha256": local_encoding_sha256,
        "combined_font_overlay_sha256": combined_font_overlay_sha256,
        "captured_utc": captured_utc,
        "encoding": encoding,
        "human_translation_approval_confirmed": True,
        "reviewed_non_text_glyph_visuals_preserved": complete,
        "original_non_text_glyph_coordinates_reused": False,
        "custom_test_font_pages_complete": complete,
        "huffman_roundtrip_complete": complete,
        "text_encoding_confirmed": complete,
        "record_storage_capacity_confirmed": False,
        "runtime_layout_confirmed": False,
        "source_and_target_text_local_only": True,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "plan-first-context-record-reinsertion"
            if complete
            else "repair-first-context-translation-encoding"
        ),
    }
    validate_first_context_translation_encoding(value)
    return value


def validate_first_context_translation_encoding(
    value: dict[str, object],
) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError("first context translation encoding fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "first-context-translation-encoding-ready",
            "first-context-translation-encoding-incomplete",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "review_batch_sha256",
                "first_context_translation_capacity_sha256",
                "runtime_context_glyph_preservation_sha256",
                "local_encoding_sha256",
                "combined_font_overlay_sha256",
            )
        )
        or not _is_utc_timestamp(value["captured_utc"])
    ):
        raise ValueError("first context translation encoding identity is invalid")
    counts = value["encoding"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("first context translation encoding counts do not match")
    if any(
        not isinstance(count, int)
        or isinstance(count, bool)
        or count < 0
        or count > 10000000
        for count in counts.values()
    ):
        raise ValueError("first context translation encoding count is invalid")
    complete = (
        counts["context_entry_count"] >= 4
        and counts["huffman_roundtrip_entry_count"]
        == counts["context_entry_count"]
        and counts["huffman_failure_entry_count"] == 0
        and counts["preserved_non_text_glyph_occurrence_count"] == 5
        and counts["custom_font_page_count"] == len(ROW_FONT_PAGES)
        and counts["font_page_changed_byte_count"] > 0
    )
    if (
        value["status"]
        != (
            "first-context-translation-encoding-ready"
            if complete
            else "first-context-translation-encoding-incomplete"
        )
        or value["human_translation_approval_confirmed"] is not True
        or value["reviewed_non_text_glyph_visuals_preserved"] is not complete
        or value["original_non_text_glyph_coordinates_reused"] is not False
        or value["custom_test_font_pages_complete"] is not complete
        or value["huffman_roundtrip_complete"] is not complete
        or value["text_encoding_confirmed"] is not complete
        or value["record_storage_capacity_confirmed"] is not False
        or value["runtime_layout_confirmed"] is not False
        or value["source_and_target_text_local_only"] is not True
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != (
            "plan-first-context-record-reinsertion"
            if complete
            else "repair-first-context-translation-encoding"
        )
    ):
        raise ValueError("first context translation encoding is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = {
        "capacity": root / CAPACITY_PATH,
        "local_capacity": root / LOCAL_CAPACITY_PATH,
        "approval": root / APPROVAL_PATH,
        "local_approval": root / LOCAL_APPROVAL_PATH,
        "local_review": root / LOCAL_REVIEW_PATH,
        "preservation": root / PRESERVATION_PATH,
        "local_preservation": root / LOCAL_PRESERVATION_PATH,
        "local_context": root / LOCAL_CONTEXT_PATH,
        "local_projection": root / LOCAL_PROJECTION_PATH,
        "patch": root / PATCH_PATH,
        "bdf": root / LOCAL_BDF_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print("First context translation encoding is not ready")
            return 0
        raise SystemExit("first context translation encoding input is missing")
    capacity = _load_json_object(paths["capacity"])
    local_capacity = _load_json_object(paths["local_capacity"])
    approval = _load_json_object(paths["approval"])
    local_approval = _load_json_object(paths["local_approval"])
    local_review = _load_json_object(paths["local_review"])
    preservation = _load_json_object(paths["preservation"])
    local_preservation = _load_json_object(paths["local_preservation"])
    local_context = _load_json_object(paths["local_context"])
    local_projection = _load_json_object(paths["local_projection"])
    validate_first_context_translation_capacity(capacity)
    validate_first_context_translation_approval(approval)
    validate_local_first_context_translation_approval(local_approval)
    validate_runtime_context_glyph_preservation(preservation)
    if (
        capacity["target_sha256"] != approval["target_sha256"]
        or capacity["review_batch_sha256"] != approval["review_batch_sha256"]
        or local_capacity.get("target_sha256") != capacity["target_sha256"]
        or local_approval.get("review_batch_sha256")
        != capacity["review_batch_sha256"]
        or local_preservation.get("target_sha256")
        != capacity["target_sha256"]
        or local_context.get("target_sha256") != capacity["target_sha256"]
        or local_projection.get("target_sha256") != capacity["target_sha256"]
    ):
        raise ValueError("first context translation encoding identity disagrees")
    source_rows = local_review.get("rows")
    target_rows = local_approval.get("rows")
    context_rows = local_context.get("analysis", {}).get("rows")
    projection_pairs = local_projection.get("projection", {}).get("pairs")
    preservation_records = local_preservation.get("records")
    hangul_assignments = local_capacity.get("analysis", {}).get("assignments")
    if not all(
        isinstance(value, list)
        for value in (
            source_rows,
            target_rows,
            context_rows,
            projection_pairs,
            preservation_records,
            hangul_assignments,
        )
    ):
        raise ValueError("first context translation encoding rows are missing")
    assert isinstance(target_rows, list)
    assert isinstance(context_rows, list)
    assert isinstance(projection_pairs, list)
    assert isinstance(preservation_records, list)
    assert isinstance(hangul_assignments, list)

    patch = paths["patch"].read_bytes()
    bdf = paths["bdf"].read_bytes()
    analyze_patch(patch)
    sparse = extract_bps_target_literals(patch)
    reference_glyphs = parse_bdf_glyphs(bdf)
    _, character_assignments = build_character_assignments(
        target_rows=target_rows,
        hangul_assignments=hangul_assignments,
        reference_glyphs=reference_glyphs,
    )
    character_tiles = {
        f"text:{assignment['character']}": tile_bytes_from_ink_mask(
            tuple(assignment["ink_mask"])
        )
        for assignment in character_assignments
    }
    preserved_by_row = locate_preserved_occurrences(
        context_rows=context_rows,
        projection_pairs=projection_pairs,
        preservation_records=preservation_records,
        target_rows=target_rows,
    )
    trees = load_trees_at(
        sparse.data,
        sparse.known,
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )
    (
        symbol_counts,
        symbol_rows,
        assignments_by_row,
    ) = build_single_page_symbol_rows(
        trees=trees,
        target_rows=target_rows,
        preserved_by_row=preserved_by_row,
    )
    custom_pages = set(ROW_FONT_PAGES)
    writes = []
    all_assignments = []
    for row_index, (page, assignments) in enumerate(
        zip(ROW_FONT_PAGES, assignments_by_row),
        start=1,
    ):
        for visual, symbol in assignments.items():
            if visual.startswith("text:"):
                after = character_tiles.get(visual)
                if after is None:
                    raise ValueError(
                        "first context target character tile is missing"
                    )
                visual_kind = "approved-target-character"
            else:
                _, source_page_hex, source_symbol_hex = visual.split(":")
                source_page = int(source_page_hex, 16)
                source_symbol = int(source_symbol_hex, 16)
                source_start = font_tile_offset(source_page, source_symbol)
                source_end = source_start + FONT_TILE_BYTES
                if any(
                    value == 0
                    for value in sparse.known[source_start:source_end]
                ):
                    raise ValueError(
                        "first context preserved visual depends on source bytes"
                    )
                after = sparse.data[source_start:source_end]
                visual_kind = "reviewed-non-text-glyph-visual"
            start = font_tile_offset(page, symbol)
            end = start + len(after)
            if any(value == 0 for value in sparse.known[start:end]):
                raise ValueError(
                    "first context encoding font page has source-dependent bytes"
                )
            writes.append(
                ExpectedWrite(
                    writer=(
                        f"first-context-row-{row_index}-font-{symbol:02x}"
                    ),
                    purpose="first-context-technical-test-only",
                    offset=start,
                    before=sparse.data[start:end],
                    after=after,
                    allowed_start=start,
                    allowed_end_exclusive=end,
                )
            )
            all_assignments.append(
                {
                    "row_index": row_index,
                    "visual": visual,
                    "visual_kind": visual_kind,
                    "page": page,
                    "symbol": symbol,
                    "tile_sha256": sha256_bytes(after),
                }
            )
    _, font_audit = apply_expected_writes(sparse.data, writes)
    font_overlay = expected_writes_to_ips(writes)
    overlay_path = root / LOCAL_COMBINED_FONT_OVERLAY_PATH
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    overlay_path.write_bytes(font_overlay)

    roundtrips = 0
    failures = 0
    encoded_bits = 0
    encoded_bytes = 0
    maximum_bits = 0
    initial_page_failures = 0
    later_failures = 0
    for row in symbol_rows:
        symbols = row["symbols"]
        assert isinstance(symbols, list)
        try:
            encoded, bits = encode_symbols(trees, symbols)
            decoded, decoded_bits = decode_symbols(
                encoded,
                bytes((1,)) * len(encoded),
                trees,
                0,
                max_symbols=len(symbols),
                max_bytes=len(encoded),
            )
            if decoded != symbols or decoded_bits != bits:
                raise PatchError("first context Huffman roundtrip disagrees")
        except PatchError as error:
            failures += 1
            row["encoding_error"] = str(error)
            missing_index = first_missing_transition_index(trees, symbols)
            if missing_index is not None and missing_index < 3:
                initial_page_failures += 1
            else:
                later_failures += 1
            continue
        row["encoded_hex"] = encoded.hex().upper()
        row["encoded_bits"] = bits
        row["encoded_bytes"] = len(encoded)
        roundtrips += 1
        encoded_bits += bits
        encoded_bytes += len(encoded)
        maximum_bits = max(maximum_bits, bits)
    counts = {
        "context_entry_count": len(symbol_rows),
        "target_character_count": sum(
            len(str(row["target_text"])) for row in symbol_rows
        ),
        "unique_target_character_count": len(character_tiles),
        "custom_font_page_count": len(custom_pages),
        "custom_font_glyph_count": len(all_assignments),
        **symbol_counts,
        "huffman_roundtrip_entry_count": roundtrips,
        "huffman_failure_entry_count": failures,
        "encoded_bit_count": encoded_bits,
        "encoded_byte_count": encoded_bytes,
        "maximum_encoded_entry_bit_count": maximum_bits,
        "font_page_write_byte_count": sum(len(write.after) for write in writes),
        "font_page_changed_byte_count":
            int(font_audit["changed_byte_count"]),
        **measure_huffman_route_capacity(trees),
        "initial_page_token_failure_entry_count": initial_page_failures,
        "post_initial_page_token_failure_entry_count": later_failures,
    }
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    local = {
        "artifact_kind": LOCAL_ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "target_sha256": capacity["target_sha256"],
        "review_batch_sha256": capacity["review_batch_sha256"],
        "captured_utc": captured_utc,
        "encoding": counts,
        "character_assignments": all_assignments,
        "preserved_by_row": preserved_by_row,
        "rows": symbol_rows,
        "font_write_audit": font_audit,
        "combined_font_overlay_sha256": sha256_bytes(font_overlay),
        "publication_policy": (
            "never-publish-source-target-text-characters-codepoints-symbols-"
            "pages-glyph-positions-encoded-bytes-or-patch-coordinates"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_first_context_translation_encoding(
        target_sha256=str(capacity["target_sha256"]),
        review_batch_sha256=str(capacity["review_batch_sha256"]),
        first_context_translation_capacity_sha256=sha256_bytes(
            paths["capacity"].read_bytes()
        ),
        runtime_context_glyph_preservation_sha256=sha256_bytes(
            paths["preservation"].read_bytes()
        ),
        local_encoding_sha256=sha256_bytes(local_path.read_bytes()),
        combined_font_overlay_sha256=sha256_bytes(font_overlay),
        encoding=counts,
        captured_utc=captured_utc,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR first context translation encoding: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
