#!/usr/bin/env python3
"""Encode the approved first-context translation without writing a ROM.

The stage assigns each approved dialogue row to a test-only font page,
re-inserts every visually reviewed non-text glyph token, and proves each
resulting symbol stream roundtrips through the verified Korean Huffman
trees.  Text, symbols, page coordinates, encoded bytes, and glyph positions
remain in ignored phone-local files.
"""

from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime, timezone
from functools import lru_cache
from heapq import heappop, heappush
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
        decode_symbol_count,
        decode_symbols,
        encode_symbol_count,
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
    from .v5_1_visible_entry_proof import (
        PUBLISH_RELATIVE_PATH as VISIBLE_ENTRY_PROOF_PATH,
        validate_visible_entry_proof,
    )
    from .v5_1_test_phrase import (
        FONT_PAGE_COUNT,
        FONT_GLYPH_FIRST_SYMBOL,
        FONT_GLYPH_LAST_SYMBOL,
        FONT_TILE_BYTES,
        _code_lengths,
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
        decode_symbol_count,
        decode_symbols,
        encode_symbol_count,
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
    from v5_1_visible_entry_proof import (
        PUBLISH_RELATIVE_PATH as VISIBLE_ENTRY_PROOF_PATH,
        validate_visible_entry_proof,
    )
    from v5_1_test_phrase import (
        FONT_PAGE_COUNT,
        FONT_GLYPH_FIRST_SYMBOL,
        FONT_GLYPH_LAST_SYMBOL,
        FONT_TILE_BYTES,
        _code_lengths,
        font_tile_offset,
        page_select_symbols,
    )


ARTIFACT_KIND = "sanitized-v5-1-first-context-translation-encoding"
LOCAL_ARTIFACT_KIND = "local-v5-1-first-context-translation-encoding"
SCHEMA_VERSION = 1
# Preferred starting pages only.  Runtime visual review invalidated both exact
# byte-length padding and compact-prefix writes: the caller keeps decoding a
# fixed number of output symbols.  Selection therefore tests bounded routes;
# the selected route is later padded with renderer-inert controls to the
# original decoded symbol count and verified with the fixed-count codec.
PROVEN_ROW_FONT_PAGES = (240, 241, 242, 243)
ROW_FONT_PAGES = PROVEN_ROW_FONT_PAGES + (239,)
MAX_EXACT_FONT_PAGE_CANDIDATES = 8
MAX_EXACT_SINGLE_PAGE_STATES = 5_000
MAX_BOUNDED_SINGLE_PAGE_STATES = 5_000
TARGET_PATH = Path("build/Final_Conflict_Korean_v5.1.gg")
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_translation_encoding.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_first_context_translation_encoding.json"
)
LOCAL_COMBINED_FONT_OVERLAY_PATH = Path(
    "build/Final_Conflict_Korean_first_context_font_pages.ips"
)
FAILURE_PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_translation_encoding_failure.json"
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
    "fixed_count_padding_symbol_count",
    "exact_runtime_symbol_count_entry_count",
    "fixed_count_roundtrip_entry_count",
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
    "runtime_initial_context_entry_count",
    "runtime_initial_context_distinct_count",
    "exact_encoded_length_entry_count",
    "in_place_storage_fit_entry_count",
    "group_storage_capacity_bit_count",
    "group_storage_fit_entry_count",
    "page_select_padding_count",
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
FAILURE_FIELDS_V1 = {
    "artifact_kind",
    "schema_version",
    "status",
    "category",
    "failure_step",
    "failure_kind",
    "failure_row_index",
    "failure_detail",
    "required_visible_symbol_count",
    "maximum_routable_visible_symbol_count",
    "captured_utc",
    "source_and_target_text_local_only",
    "next_checkpoint",
}
FAILURE_FIELDS_V2 = FAILURE_FIELDS_V1 | {
    "target_encoded_bit_count",
    "bounded_candidate_bit_count",
    "bounded_candidate_relation",
}
FAILURE_FIELDS = FAILURE_FIELDS_V2 | {
    "approved_visible_symbol_count",
    "compact_visible_symbol_count",
    "runtime_symbol_count",
    "layout_control_symbol_count",
}
FAILURE_CATEGORIES = {
    "identity",
    "input",
    "row-capacity",
    "page-route",
    "row-route",
    "font-input",
    "font-destination",
    "font-overlay",
    "validation",
    "unexpected",
}
ACTIVE_FAILURE_CATEGORY = "unexpected"
ACTIVE_FAILURE_STEP = "input"
ACTIVE_FAILURE_ROW_INDEX = 0
ACTIVE_FAILURE_DETAIL = "none"
ACTIVE_LAYOUT_APPROVED_COUNT = 0
ACTIVE_LAYOUT_COMPACT_COUNT = 0
ACTIVE_LAYOUT_RUNTIME_COUNT = 0
ACTIVE_LAYOUT_CONTROL_COUNT = 0
FAILURE_STEPS = {
    "input",
    "locate-preserved-occurrences",
    "load-runtime-trees",
    "build-runtime-codec-constraints",
    "build-runtime-layout-rows",
    "build-character-assignments",
    "select-row-font-pages",
    "build-symbol-rows",
    "build-font-overlay",
    "encode-symbol-rows",
    "validate-safe-result",
}
FAILURE_KINDS = {
    "AssertionError",
    "IndexError",
    "KeyError",
    "PatchError",
    "RowRouteError",
    "RuntimeError",
    "TypeError",
    "ValueError",
}
FAILURE_DETAILS = {
    "none",
    "layout-runtime-compaction-shape",
    "layout-hangul-sequence-change",
    "layout-no-compatible-control-count",
    "solve-unconstrained-row",
    "solve-proven-exact-row",
    "solve-proven-bounded-row",
    "solve-proven-multi-page-row",
    "solve-extra-single-page-row",
    "solve-extra-multi-page-row",
    "validate-row-assignments",
}


class RowRouteError(ValueError):
    def __init__(
        self,
        required: int,
        maximum: int,
        target_bits: int = 0,
        candidate_bits: int = 0,
    ) -> None:
        super().__init__("first context row has no usable Huffman route")
        self.required = required
        self.maximum = maximum
        self.target_bits = target_bits
        self.candidate_bits = candidate_bits


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


def build_first_context_translation_encoding_failure(
    *,
    category: str,
    captured_utc: str,
    required_visible_symbol_count: int = 0,
    maximum_routable_visible_symbol_count: int = 0,
    target_encoded_bit_count: int = 0,
    bounded_candidate_bit_count: int = 0,
    failure_step: str = "input",
    failure_kind: str = "ValueError",
    failure_row_index: int = 0,
    failure_detail: str = "none",
    approved_visible_symbol_count: int = 0,
    compact_visible_symbol_count: int = 0,
    runtime_symbol_count: int = 0,
    layout_control_symbol_count: int = 0,
) -> dict[str, object]:
    value: dict[str, object] = {
        "artifact_kind":
            "sanitized-v5-1-first-context-translation-encoding-failure",
        "schema_version": 3,
        "status": "first-context-translation-encoding-failed",
        "category": category,
        "failure_step": failure_step,
        "failure_kind": failure_kind,
        "failure_row_index": failure_row_index,
        "failure_detail": failure_detail,
        "required_visible_symbol_count": required_visible_symbol_count,
        "maximum_routable_visible_symbol_count":
            maximum_routable_visible_symbol_count,
        "target_encoded_bit_count": target_encoded_bit_count,
        "bounded_candidate_bit_count": bounded_candidate_bit_count,
        "bounded_candidate_relation": (
            "none"
            if bounded_candidate_bit_count == 0
            else "shorter"
            if bounded_candidate_bit_count < target_encoded_bit_count
            else "equal"
            if bounded_candidate_bit_count == target_encoded_bit_count
            else "longer"
        ),
        "approved_visible_symbol_count": approved_visible_symbol_count,
        "compact_visible_symbol_count": compact_visible_symbol_count,
        "runtime_symbol_count": runtime_symbol_count,
        "layout_control_symbol_count": layout_control_symbol_count,
        "captured_utc": captured_utc,
        "source_and_target_text_local_only": True,
        "next_checkpoint": f"repair-first-context-{category}",
    }
    validate_first_context_translation_encoding_failure(value)
    return value


def validate_first_context_translation_encoding_failure(
    value: dict[str, object],
) -> None:
    fields = set(value)
    schema_version = value.get("schema_version")
    if not (
        (schema_version == 1 and fields == FAILURE_FIELDS_V1)
        or (schema_version == 2 and fields == FAILURE_FIELDS_V2)
        or (schema_version == 3 and fields == FAILURE_FIELDS)
    ):
        raise ValueError(
            "first context translation encoding failure fields do not match"
        )
    if (
        value["artifact_kind"]
        != "sanitized-v5-1-first-context-translation-encoding-failure"
        or schema_version not in {1, 2, 3}
        or value["status"] != "first-context-translation-encoding-failed"
        or value["category"] not in FAILURE_CATEGORIES
        or value["failure_step"] not in FAILURE_STEPS
        or value["failure_kind"] not in FAILURE_KINDS
        or not isinstance(value["failure_row_index"], int)
        or isinstance(value["failure_row_index"], bool)
        or not 0 <= value["failure_row_index"] <= 1000
        or value["failure_detail"] not in FAILURE_DETAILS
        or not isinstance(value["required_visible_symbol_count"], int)
        or isinstance(value["required_visible_symbol_count"], bool)
        or not isinstance(value["maximum_routable_visible_symbol_count"], int)
        or isinstance(value["maximum_routable_visible_symbol_count"], bool)
        or not 0
        <= value["maximum_routable_visible_symbol_count"]
        <= value["required_visible_symbol_count"]
        <= 1000
        or not _is_utc_timestamp(value["captured_utc"])
        or value["source_and_target_text_local_only"] is not True
        or value["next_checkpoint"]
        != f"repair-first-context-{value['category']}"
    ):
        raise ValueError(
            "first context translation encoding failure is inconsistent"
        )
    if schema_version in {2, 3}:
        target_bits = value["target_encoded_bit_count"]
        candidate_bits = value["bounded_candidate_bit_count"]
        relation = value["bounded_candidate_relation"]
        if (
            not isinstance(target_bits, int)
            or isinstance(target_bits, bool)
            or not 0 <= target_bits <= 0x7FFF
            or not isinstance(candidate_bits, int)
            or isinstance(candidate_bits, bool)
            or not 0 <= candidate_bits <= 0x7FFF
            or relation
            != (
                "none"
                if candidate_bits == 0
                else "shorter"
                if candidate_bits < target_bits
                else "equal"
                if candidate_bits == target_bits
                else "longer"
            )
        ):
            raise ValueError(
                "first context translation encoding failure bit diagnostics "
                "are inconsistent"
            )
    if schema_version == 3:
        approved_count = value["approved_visible_symbol_count"]
        compact_count = value["compact_visible_symbol_count"]
        runtime_count = value["runtime_symbol_count"]
        control_count = value["layout_control_symbol_count"]
        if (
            not all(
                isinstance(item, int) and not isinstance(item, bool)
                for item in (
                    approved_count,
                    compact_count,
                    runtime_count,
                    control_count,
                )
            )
            or not 0 <= compact_count <= approved_count <= 1000
            or not 0 <= runtime_count <= 1000
            or not -1000 <= control_count <= 1000
        ):
            raise ValueError(
                "first context translation encoding layout diagnostics "
                "are inconsistent"
            )


def classify_encoding_failure(error: BaseException) -> str:
    message = str(error).lower()
    if "identity" in message:
        return "identity"
    if "input is missing" in message or "rows are missing" in message:
        return "input"
    if "exceeds one font page" in message or "page count" in message:
        return "row-capacity"
    if "font page is not encodable" in message:
        return "page-route"
    if "no huffman assignment" in message:
        return "row-route"
    if (
        "target character tile is missing" in message
        or "preserved visual depends on source bytes" in message
    ):
        return "font-input"
    if "font page has source-dependent bytes" in message:
        return "font-destination"
    if "expected write" in message or "ips" in message:
        return "font-overlay"
    if (
        "fields do not match" in message
        or "counts do not match" in message
        or "inconsistent" in message
    ):
        return "validation"
    return "unexpected"


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


def build_runtime_layout_rows(
    *,
    target_rows: list[dict[str, object]],
    runtime_constraints: list[dict[str, int]],
    compact_review_indexes: tuple[int, ...] = (1,),
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Build renderer-only rows without changing the approved translation.

    The first technical-test row has a fixed 19-symbol runtime contract.  Its
    reviewed 12-character display leaves room for only two three-symbol page
    controls, and exhaustive single- and two-page routing proved that shape
    unreachable.  Removing ASCII layout spacing and a trailing exclamation
    preserves every Hangul syllable while opening a third renderer-inert page
    control.  The approved rows remain untouched and the deletion-only layout
    transform is returned as a local audit record.
    """

    global ACTIVE_FAILURE_ROW_INDEX, ACTIVE_FAILURE_DETAIL
    global ACTIVE_LAYOUT_APPROVED_COUNT, ACTIVE_LAYOUT_COMPACT_COUNT
    global ACTIVE_LAYOUT_RUNTIME_COUNT, ACTIVE_LAYOUT_CONTROL_COUNT
    if len(target_rows) != len(runtime_constraints):
        ACTIVE_FAILURE_DETAIL = "layout-row-count-mismatch"
        raise ValueError("first context runtime layout row count does not match")
    compact_indexes = set(compact_review_indexes)
    output: list[dict[str, object]] = []
    audit: list[dict[str, object]] = []
    for expected_index, (target_row, constraint) in enumerate(
        zip(target_rows, runtime_constraints),
        start=1,
    ):
        if not isinstance(target_row, dict):
            raise ValueError("first context runtime layout row is invalid")
        target_text = target_row.get("target_text")
        target_symbol_count = constraint.get("original_symbol_count")
        if (
            target_row.get("review_index") != expected_index
            or not isinstance(target_text, str)
            or not isinstance(target_symbol_count, int)
        ):
            raise ValueError("first context runtime layout fields are invalid")
        runtime_row = dict(target_row)
        if expected_index in compact_indexes:
            approved_hangul = "".join(
                character
                for character in target_text
                if _is_hangul_syllable(character)
            )
            ACTIVE_FAILURE_ROW_INDEX = expected_index
            ACTIVE_FAILURE_DETAIL = "layout-runtime-compaction-shape"
            variants = [
                (
                    "remove-ascii-spaces",
                    target_text.replace(" ", ""),
                ),
            ]
            if target_text.endswith("!"):
                variants.extend(
                    (
                        ("remove-trailing-exclamation", target_text[:-1]),
                        (
                            "remove-ascii-spaces-and-trailing-exclamation",
                            target_text.replace(" ", "")[:-1],
                        ),
                    )
                )
            diagnostic_text = min(
                (candidate_text for _, candidate_text in variants),
                key=len,
            )
            ACTIVE_LAYOUT_APPROVED_COUNT = len(target_text)
            ACTIVE_LAYOUT_COMPACT_COUNT = len(diagnostic_text)
            ACTIVE_LAYOUT_RUNTIME_COUNT = target_symbol_count
            ACTIVE_LAYOUT_CONTROL_COUNT = (
                target_symbol_count - len(diagnostic_text) - 1
            )
            eligible_variants = []
            for layout_action, candidate_text in dict.fromkeys(variants):
                candidate_hangul = "".join(
                    character
                    for character in candidate_text
                    if _is_hangul_syllable(character)
                )
                if approved_hangul != candidate_hangul:
                    ACTIVE_FAILURE_DETAIL = "layout-hangul-sequence-change"
                    continue
                control_symbols = target_symbol_count - len(candidate_text) - 1
                if control_symbols < 3 or control_symbols % 3:
                    continue
                page_token_count = control_symbols // 3
                eligible_variants.append(
                    (
                        abs(page_token_count - 3),
                        len(target_text) - len(candidate_text),
                        layout_action,
                        candidate_text,
                        control_symbols,
                        page_token_count,
                    )
                )
            if not eligible_variants:
                ACTIVE_FAILURE_DETAIL = "layout-no-compatible-control-count"
                raise ValueError(
                    "first context runtime layout compaction is not safe"
                )
            (
                _,
                _,
                layout_action,
                compact_text,
                control_symbols,
                page_token_count,
            ) = min(eligible_variants)
            ACTIVE_LAYOUT_COMPACT_COUNT = len(compact_text)
            ACTIVE_LAYOUT_CONTROL_COUNT = control_symbols
            runtime_row["target_text"] = compact_text
            audit.append(
                {
                    "review_index": expected_index,
                    "layout_action": layout_action,
                    "approved_character_count": len(target_text),
                    "runtime_character_count": len(compact_text),
                    "removed_ascii_space_count": (
                        target_text.count(" ") - compact_text.count(" ")
                    ),
                    "removed_trailing_exclamation_count": int(
                        target_text.endswith("!")
                        and not compact_text.endswith("!")
                    ),
                    "hangul_sequence_preserved": True,
                    "runtime_symbol_count": target_symbol_count,
                    "required_page_token_count": page_token_count,
                }
            )
        output.append(runtime_row)
    return output, audit


def _bits_equal(left: bytes, right: bytes, bit_count: int) -> bool:
    return all(
        ((left[index >> 3] >> (7 - (index & 7))) & 1)
        == ((right[index >> 3] >> (7 - (index & 7))) & 1)
        for index in range(bit_count)
    )


def build_runtime_codec_constraints(
    *,
    target: bytes,
    trees: dict[int, object],
    context_rows: list[dict[str, object]],
    projection_pairs: list[dict[str, object]],
    runtime_records: list[dict[str, int]] | None = None,
) -> list[dict[str, int]]:
    global ACTIVE_FAILURE_ROW_INDEX
    if runtime_records is not None and not (
        1 <= len(runtime_records) <= len(context_rows)
    ):
        raise ValueError("first context runtime record count disagrees")
    pair_index = {
        (pair.get("source_section_index"), pair.get("source_line_index")): pair
        for pair in projection_pairs
        if isinstance(pair, dict)
    }
    constraints = []
    known = bytes((1,)) * len(target)
    for row_index, context_row in enumerate(context_rows):
        ACTIVE_FAILURE_ROW_INDEX = row_index + 1
        if (
            not isinstance(context_row, dict)
            or context_row.get("mapping_status") != "unique"
        ):
            raise ValueError("first context runtime codec row is invalid")
        observation = context_row.get("observation")
        if not isinstance(observation, dict):
            raise ValueError("first context runtime observation is missing")
        initial_context = observation.get("initial_context")
        if runtime_records is None or row_index >= len(runtime_records):
            pair = pair_index.get(
                (
                    context_row.get("source_section_index"),
                    context_row.get("source_line_index"),
                )
            )
            target_record = None if pair is None else pair.get("target_record")
        else:
            target_record = runtime_records[row_index]
        if not isinstance(target_record, dict):
            raise ValueError("first context runtime target record is missing")
        if runtime_records is not None:
            initial_context = CANDIDATE_END_SYMBOL
        length_offset = target_record.get("length_offset")
        record_length = target_record.get("record_length_bytes")
        if (
            not isinstance(initial_context, int)
            or isinstance(initial_context, bool)
            or not 0 <= initial_context <= 0xFF
            or not isinstance(length_offset, int)
            or isinstance(length_offset, bool)
            or not isinstance(record_length, int)
            or isinstance(record_length, bool)
            or not 0 <= length_offset < len(target)
            or target[length_offset] != record_length
        ):
            raise ValueError("first context runtime codec fields are invalid")
        payload_start = length_offset + 1
        payload_end = payload_start + record_length
        if not (0 < record_length and payload_end <= len(target)):
            raise ValueError("first context runtime record bounds are invalid")
        symbols, encoded_bits = decode_symbols(
            target,
            known,
            trees,
            payload_start,
            initial_symbol=initial_context,
            end_symbol=CANDIDATE_END_SYMBOL,
            max_symbols=0x1000,
            max_bytes=record_length,
        )
        reencoded, reencoded_bits = encode_symbols(
            trees,
            symbols,
            initial_symbol=initial_context,
            end_symbol=CANDIDATE_END_SYMBOL,
            max_bits=record_length * 8,
        )
        payload = target[payload_start:payload_end]
        if (
            symbols.count(CANDIDATE_END_SYMBOL) != 1
            or encoded_bits != reencoded_bits
            or not _bits_equal(payload, reencoded, encoded_bits)
        ):
            raise ValueError("first context runtime codec roundtrip disagrees")
        constraints.append(
            {
                "initial_context": initial_context,
                "original_encoded_bits": encoded_bits,
                "original_record_length_bytes": record_length,
                "original_symbol_count": len(symbols),
            }
        )
    return constraints


def resolve_runtime_records_from_visible_anchor(
    *,
    target: bytes,
    runtime_entry: dict[str, object],
    row_count: int,
) -> list[dict[str, int]]:
    """Resolve consecutive dialogue records from the proven visible entry.

    Source/target projection is useful for translation context, but it is not
    authoritative for binary placement.  The runtime display proof carries the
    decoder-proven payload address, so in-place encoding must follow the actual
    length-prefixed records beginning there.
    """
    if not isinstance(row_count, int) or isinstance(row_count, bool) or row_count < 1:
        raise ValueError("first context runtime row count is invalid")
    physical_start = runtime_entry.get("physical_start")
    proven_length = runtime_entry.get("record_length_bytes")
    if (
        not isinstance(physical_start, int)
        or isinstance(physical_start, bool)
        or not isinstance(proven_length, int)
        or isinstance(proven_length, bool)
    ):
        raise ValueError("first context visible runtime entry is invalid")
    length_offset = physical_start - 1
    if not 0 <= length_offset < len(target):
        raise ValueError("first context visible runtime entry is out of bounds")
    if target[length_offset] != proven_length:
        raise ValueError("first context visible runtime length disagrees")

    records: list[dict[str, int]] = []
    for _ in range(row_count):
        if not 0 <= length_offset < len(target):
            raise ValueError("first context consecutive runtime record is missing")
        record_length = target[length_offset]
        payload_start = length_offset + 1
        payload_end = payload_start + record_length
        if record_length < 1 or payload_end > len(target):
            raise ValueError("first context consecutive runtime record is invalid")
        records.append(
            {
                "length_offset": length_offset,
                "record_length_bytes": record_length,
                # The exact visible-record roundtrip starts every independent
                # compressed string from the end-symbol Huffman context.  A
                # sampled post-decode register value is not an entry context.
                "initial_context": CANDIDATE_END_SYMBOL,
            }
        )
        length_offset = payload_end
    return records


def solve_row_visual_symbols(
    *,
    trees: dict[int, object],
    page: int,
    visuals: list[str],
) -> list[int]:
    if not visuals:
        raise ValueError("first context visual row is empty")
    capacity = FONT_GLYPH_LAST_SYMBOL - FONT_GLYPH_FIRST_SYMBOL + 1
    if len(visuals) > capacity:
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
    glyph_symbols = set(
        range(FONT_GLYPH_FIRST_SYMBOL, FONT_GLYPH_LAST_SYMBOL + 1)
    )
    assignments: list[int] = []
    used: set[int] = set()

    def search(previous_symbol: int) -> bool:
        if len(assignments) == len(visuals):
            return CANDIDATE_END_SYMBOL in codes.get(previous_symbol, set())
        candidates = sorted(
            (codes.get(previous_symbol, set()) & glyph_symbols) - used,
            key=lambda symbol: (
                CANDIDATE_END_SYMBOL not in codes.get(symbol, set()),
                -len(codes.get(symbol, set()) & glyph_symbols),
                symbol,
            ),
        )
        if len(assignments) == len(visuals) - 1:
            candidates = [
                symbol
                for symbol in candidates
                if CANDIDATE_END_SYMBOL in codes.get(symbol, set())
            ]
        for symbol in candidates:
            assignments.append(symbol)
            used.add(symbol)
            if search(symbol):
                return True
            used.remove(symbol)
            assignments.pop()
        return False

    if not search(start_previous):
        raise ValueError("first context visual row has no Huffman assignment")
    return assignments


def exact_length_row_symbols(
    *,
    trees: dict[int, object],
    initial_context: int,
    target_bits: int,
    page: int,
    assignments: list[int],
) -> tuple[list[int], int]:
    if (
        not 0 <= initial_context <= 0xFF
        or not 1 <= target_bits <= 0x7FFF
        or not assignments
    ):
        raise ValueError("first context exact-length row inputs are invalid")
    lengths = _code_lengths(trees)

    def transition(
        previous: int,
        symbols: tuple[int, ...],
    ) -> tuple[int, int] | None:
        bits = 0
        for symbol in symbols:
            code_length = lengths.get(previous, {}).get(symbol)
            if code_length is None:
                return None
            bits += code_length
            previous = symbol
        return bits, previous

    visible_suffix = tuple(
        page_select_symbols(page) + assignments + [CANDIDATE_END_SYMBOL]
    )
    page_tokens = []
    for candidate_page in range(FONT_PAGE_COUNT):
        token = tuple(page_select_symbols(candidate_page))
        page_tokens.append(token)

    start = (0, initial_context)
    queue = deque([start])
    paths: dict[tuple[int, int], tuple[int, ...]] = {start: ()}
    while queue:
        bits, previous = queue.popleft()
        suffix = transition(previous, visible_suffix)
        if suffix is not None and bits + suffix[0] == target_bits:
            prefix = paths[(bits, previous)]
            return list(prefix + visible_suffix), len(prefix) // 3

        unique_transitions: dict[tuple[int, int], tuple[int, ...]] = {}
        for token in page_tokens:
            encoded = transition(previous, token)
            if encoded is None or bits + encoded[0] >= target_bits:
                continue
            unique_transitions.setdefault((encoded[0], encoded[1]), token)
        for (added_bits, next_previous), token in sorted(
            unique_transitions.items()
        ):
            candidate = (bits + added_bits, next_previous)
            if candidate in paths:
                continue
            paths[candidate] = paths[(bits, previous)] + token
            queue.append(candidate)
    raise ValueError("first context row has no exact-length Huffman route")


def bounded_length_row_symbols(
    *,
    trees: dict[int, object],
    initial_context: int,
    maximum_bits: int,
    page: int,
    assignments: list[int],
) -> tuple[list[int], int]:
    if (
        not 0 <= initial_context <= 0xFF
        or not 1 <= maximum_bits <= 0x7FFF
        or not assignments
    ):
        raise ValueError("first context bounded-length row inputs are invalid")
    lengths = _code_lengths(trees)

    def transition(
        previous: int,
        symbols: tuple[int, ...],
    ) -> tuple[int, int] | None:
        bits = 0
        for symbol in symbols:
            code_length = lengths.get(previous, {}).get(symbol)
            if code_length is None:
                return None
            bits += code_length
            previous = symbol
        return bits, previous

    visible_suffix = tuple(
        page_select_symbols(page) + assignments + [CANDIDATE_END_SYMBOL]
    )
    page_tokens = [
        tuple(page_select_symbols(candidate_page))
        for candidate_page in range(FONT_PAGE_COUNT)
    ]
    start = (0, initial_context)
    queue = deque([start])
    paths: dict[tuple[int, int], tuple[int, ...]] = {start: ()}
    while queue:
        bits, previous = queue.popleft()
        suffix = transition(previous, visible_suffix)
        if suffix is not None and bits + suffix[0] <= maximum_bits:
            prefix = paths[(bits, previous)]
            return list(prefix + visible_suffix), len(prefix) // 3

        unique_transitions: dict[tuple[int, int], tuple[int, ...]] = {}
        for token in page_tokens:
            encoded = transition(previous, token)
            if encoded is None or bits + encoded[0] >= maximum_bits:
                continue
            unique_transitions.setdefault((encoded[0], encoded[1]), token)
        for (added_bits, next_previous), token in sorted(
            unique_transitions.items()
        ):
            candidate = (bits + added_bits, next_previous)
            if candidate in paths:
                continue
            paths[candidate] = paths[(bits, previous)] + token
            queue.append(candidate)
    raise ValueError("first context row exceeds its in-place Huffman capacity")


def pad_row_to_runtime_symbol_count(
    *,
    trees: dict[int, object],
    initial_context: int,
    maximum_bits: int,
    target_symbol_count: int,
    symbols: list[int],
) -> tuple[list[int], int, int]:
    """Pad one visible row to the caller's exact decoded output count.

    Runtime screenshots proved that the dialogue consumer does not stop after
    the first ``0xC9``.  A shorter replacement therefore lets preserved suffix
    bits decode as visible garbage.  Prefix the reviewed visible route with
    only renderer-inert page selections (and terminators only when necessary)
    until its final terminator lands at the runtime symbol count.  Prefix
    padding is important because a visible glyph need not have a direct edge
    to a page-selection token.  The returned stream is later encoded and
    decoded with the fixed-count codec, so no preserved suffix bit is consumed
    by the caller.
    """

    if (
        not 0 <= initial_context <= 0xFF
        or not 1 <= maximum_bits <= 0x7FFF
        or not 1 <= target_symbol_count <= 0x1000
        or not symbols
        or symbols[-1] != CANDIDATE_END_SYMBOL
        or CANDIDATE_END_SYMBOL in symbols[:-1]
    ):
        raise ValueError("first context fixed-count padding inputs are invalid")
    if len(symbols) > target_symbol_count:
        raise ValueError("first context visible route exceeds runtime symbol count")
    if len(symbols) == target_symbol_count:
        return list(symbols), 0, 0

    lengths = _code_lengths(trees)

    def transition(
        previous: int,
        sequence: tuple[int, ...],
    ) -> tuple[int, int] | None:
        bit_count = 0
        for symbol in sequence:
            code_length = lengths.get(previous, {}).get(symbol)
            if code_length is None:
                return None
            bit_count += code_length
            previous = symbol
        return bit_count, previous

    visible_route = tuple(symbols)
    padding_symbols = target_symbol_count - len(symbols)

    page_tokens = tuple(
        dict.fromkeys(
            tuple(page_select_symbols(page)) for page in range(FONT_PAGE_COUNT)
        )
    )
    page_by_token = {
        tuple(page_select_symbols(page)): page for page in range(FONT_PAGE_COUNT)
    }
    atoms: list[tuple[tuple[int, ...], int | None]] = []
    symbol_index = 0
    while symbol_index < len(visible_route):
        token = tuple(visible_route[symbol_index:symbol_index + 3])
        page = page_by_token.get(token)
        if page is not None:
            atoms.append((token, page))
            symbol_index += 3
        else:
            atoms.append(((visible_route[symbol_index],), None))
            symbol_index += 1

    # Jointly place controls only at atomic boundaries.  At a boundary before
    # another visible glyph, reselect only the current page so glyph meaning is
    # unchanged.  Before a mandatory page selection or the final terminator,
    # any page token is safe because no glyph can observe the temporary page.
    # Prefer page controls over extra terminators, then the lowest-bit route.
    # Paths are private/local only and never appear in the sanitized receipt.
    heap: list[
        tuple[int, int, tuple[int, ...], int, int, int, int, int]
    ] = [(0, 0, (), 0, 0, initial_context, -1, 0)]
    best: dict[tuple[int, int, int, int], tuple[int, int]] = {
        (0, 0, initial_context, -1): (0, 0)
    }
    while heap:
        (
            terminator_padding_count,
            bits,
            path,
            atom_index,
            used,
            previous,
            current_page,
            page_token_count,
        ) = heappop(heap)
        state = (atom_index, used, previous, current_page)
        if (terminator_padding_count, bits) != best.get(state):
            continue
        if atom_index == len(atoms):
            if used == padding_symbols:
                return list(path), padding_symbols, page_token_count
            continue

        mandatory, mandatory_page = atoms[atom_index]
        encoded_mandatory = transition(previous, mandatory)
        if encoded_mandatory is not None:
            mandatory_bits, mandatory_previous = encoded_mandatory
            next_bits = bits + mandatory_bits
            if next_bits <= maximum_bits:
                next_page = (
                    mandatory_page
                    if mandatory_page is not None
                    else current_page
                )
                next_state = (
                    atom_index + 1,
                    used,
                    mandatory_previous,
                    next_page,
                )
                rank = (terminator_padding_count, next_bits)
                if rank < best.get(
                    next_state,
                    (0x1001, maximum_bits + 1),
                ):
                    best[next_state] = rank
                    heappush(
                        heap,
                        (
                            terminator_padding_count,
                            next_bits,
                            path + mandatory,
                            atom_index + 1,
                            used,
                            mandatory_previous,
                            next_page,
                            page_token_count,
                        ),
                    )

        if used >= padding_symbols:
            continue
        final_terminator_next = (
            atom_index == len(atoms) - 1
            and mandatory == (CANDIDATE_END_SYMBOL,)
        )
        if mandatory_page is not None or final_terminator_next or current_page < 0:
            candidate_pages = page_tokens
        else:
            candidate_pages = (tuple(page_select_symbols(current_page)),)
        candidates = tuple(candidate_pages)
        if final_terminator_next:
            candidates += ((CANDIDATE_END_SYMBOL,),)
        unique: dict[tuple[int, int, int], tuple[int, ...]] = {}
        for token in candidates:
            next_used = used + len(token)
            if next_used > padding_symbols:
                continue
            encoded = transition(previous, token)
            if encoded is None:
                continue
            unique.setdefault((len(token), encoded[0], encoded[1]), token)
        for (token_length, added_bits, next_previous), token in sorted(
            unique.items()
        ):
            next_bits = bits + added_bits
            if next_bits >= maximum_bits:
                continue
            next_used = used + token_length
            next_page = page_by_token.get(token, current_page)
            next_state = (atom_index, next_used, next_previous, next_page)
            next_terminators = terminator_padding_count + int(
                token == (CANDIDATE_END_SYMBOL,)
            )
            rank = (next_terminators, next_bits)
            if rank >= best.get(next_state, (0x1001, maximum_bits + 1)):
                continue
            best[next_state] = rank
            heappush(
                heap,
                (
                    next_terminators,
                    next_bits,
                    path + token,
                    atom_index,
                    next_used,
                    next_previous,
                    next_page,
                    page_token_count + int(token_length == 3),
                ),
            )
    raise ValueError("first context row has no fixed-count invisible padding route")


def solve_bounded_length_row_visual_symbols(
    *,
    trees: dict[int, object],
    initial_context: int,
    maximum_bits: int,
    page: int,
    visuals: list[str],
) -> tuple[list[int], int, list[int]]:
    if (
        not 0 <= initial_context <= 0xFF
        or not 1 <= maximum_bits <= 0x7FFF
        or not visuals
    ):
        raise ValueError("first context bounded-length visual inputs are invalid")
    capacity = FONT_GLYPH_LAST_SYMBOL - FONT_GLYPH_FIRST_SYMBOL + 1
    if len(visuals) > capacity:
        raise ValueError("first context visual row exceeds one font page")

    try:
        assignments = solve_row_visual_symbols(
            trees=trees,
            page=page,
            visuals=visuals,
        )
        symbols, padding_count = bounded_length_row_symbols(
            trees=trees,
            initial_context=initial_context,
            maximum_bits=maximum_bits,
            page=page,
            assignments=assignments,
        )
        return symbols, padding_count, assignments
    except ValueError:
        pass

    lengths = _code_lengths(trees)

    def transition(
        previous: int,
        symbols: tuple[int, ...],
    ) -> tuple[int, int] | None:
        bits = 0
        for symbol in symbols:
            code_length = lengths.get(previous, {}).get(symbol)
            if code_length is None:
                return None
            bits += code_length
            previous = symbol
        return bits, previous

    page_token = tuple(page_select_symbols(page))
    prefix_tokens = [
        tuple(page_select_symbols(candidate_page))
        for candidate_page in range(FONT_PAGE_COUNT)
    ]
    glyph_symbols = tuple(
        range(FONT_GLYPH_FIRST_SYMBOL, FONT_GLYPH_LAST_SYMBOL + 1)
    )
    expanded_state_count = 0
    queue = deque([(0, initial_context)])
    prefix_paths: dict[tuple[int, int], tuple[int, ...]] = {
        (0, initial_context): ()
    }

    @lru_cache(maxsize=None)
    def shortest_page_reselection(
        previous: int,
    ) -> tuple[int, tuple[int, ...]] | None:
        """Return the cheapest control-only route that selects ``page``.

        A dialogue may legitimately select its current font page again between
        two visible glyphs.  Besides being visually inert, that resets the
        Huffman context to the selected page's low nibble.  Some source trees
        have no direct glyph-to-glyph edge even though this control route fits
        inside the original record.  Earlier searches only allowed those
        control tokens before the first visible glyph and therefore rejected
        otherwise encodable rows.
        """

        queue: list[tuple[int, tuple[int, ...], int]] = [(0, (), previous)]
        best = {previous: 0}
        best_target: tuple[int, tuple[int, ...]] | None = None
        while queue:
            bits, path, current = heappop(queue)
            if bits != best.get(current):
                continue
            if best_target is not None and bits >= best_target[0]:
                break
            for candidate_page, token in enumerate(prefix_tokens):
                encoded = transition(current, token)
                if encoded is None:
                    continue
                added_bits, next_previous = encoded
                total_bits = bits + added_bits
                if total_bits >= maximum_bits:
                    continue
                candidate_path = path + token
                if candidate_page == page:
                    candidate_target = (total_bits, candidate_path)
                    if best_target is None or candidate_target < best_target:
                        best_target = candidate_target
                    continue
                if total_bits >= best.get(next_previous, maximum_bits + 1):
                    continue
                best[next_previous] = total_bits
                heappush(
                    queue,
                    (total_bits, candidate_path, next_previous),
                )
        return best_target

    @lru_cache(maxsize=None)
    def search_visible(
        previous: int,
        used_mask: int,
        depth: int,
        bits: int,
    ) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
        nonlocal expanded_state_count
        expanded_state_count += 1
        if expanded_state_count > MAX_BOUNDED_SINGLE_PAGE_STATES:
            raise ValueError(
                "first context bounded-length search state limit exceeded"
            )
        if depth == len(visuals):
            end_length = lengths.get(previous, {}).get(CANDIDATE_END_SYMBOL)
            if end_length is not None and bits + end_length <= maximum_bits:
                return (CANDIDATE_END_SYMBOL,), ()
            return None
        routes = [(0, (), previous)]
        reselection = shortest_page_reselection(previous)
        if reselection is not None:
            reselection_bits, reselection_symbols = reselection
            routes.append((reselection_bits, reselection_symbols, page_token[-1]))
        for route_bits, route_symbols, route_previous in routes:
            candidates = sorted(
                (
                    symbol
                    for symbol in glyph_symbols
                    if not used_mask
                    & (1 << (symbol - FONT_GLYPH_FIRST_SYMBOL))
                    and symbol in lengths.get(route_previous, {})
                ),
                key=lambda symbol: (
                    CANDIDATE_END_SYMBOL not in lengths.get(symbol, {}),
                    -len(set(lengths.get(symbol, {})) & set(glyph_symbols)),
                    symbol,
                ),
            )
            for symbol in candidates:
                added_bits = lengths[route_previous][symbol]
                next_bits = bits + route_bits + added_bits
                if next_bits >= maximum_bits:
                    continue
                suffix = search_visible(
                    symbol,
                    used_mask | (1 << (symbol - FONT_GLYPH_FIRST_SYMBOL)),
                    depth + 1,
                    next_bits,
                )
                if suffix is not None:
                    suffix_symbols, suffix_assignments = suffix
                    return (
                        route_symbols + (symbol,) + suffix_symbols,
                        (symbol,) + suffix_assignments,
                    )
        return None

    def fast_reselected_visible(
        previous: int,
        bits: int,
    ) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
        """Build a bounded route with an inert page reset between glyphs.

        Once the same page is selected again, every following glyph starts
        from the page's low-nibble Huffman context.  That makes the visible
        assignments independent except for their tile slots, so a cheapest
        distinct-slot selection avoids the exponential used-mask search for
        the common roomy group-capacity case.
        """

        visible_count = len(visuals)
        last_candidates = sorted(
            (
                symbol
                for symbol in glyph_symbols
                if symbol in lengths.get(previous, {})
                and CANDIDATE_END_SYMBOL in lengths.get(symbol, {})
            ),
            key=lambda symbol: (
                lengths[previous][symbol]
                + lengths[symbol][CANDIDATE_END_SYMBOL],
                symbol,
            ),
        )
        for last_symbol in last_candidates:
            intermediate_candidates = []
            for symbol in glyph_symbols:
                if symbol == last_symbol or symbol not in lengths.get(previous, {}):
                    continue
                reselection = shortest_page_reselection(symbol)
                if reselection is None:
                    continue
                reselection_bits, reselection_symbols = reselection
                intermediate_candidates.append(
                    (
                        lengths[previous][symbol] + reselection_bits,
                        symbol,
                        reselection_symbols,
                    )
                )
            intermediate_candidates.sort()
            selected_intermediates = intermediate_candidates[
                : max(0, visible_count - 1)
            ]
            if len(selected_intermediates) != visible_count - 1:
                continue
            visible_bits = sum(
                candidate[0] for candidate in selected_intermediates
            )
            visible_bits += lengths[previous][last_symbol]
            visible_bits += lengths[last_symbol][CANDIDATE_END_SYMBOL]
            if bits + visible_bits > maximum_bits:
                continue
            symbols = []
            assignments = []
            for _, symbol, reselection_symbols in selected_intermediates:
                symbols.append(symbol)
                assignments.append(symbol)
                symbols.extend(reselection_symbols)
            symbols.extend((last_symbol, CANDIDATE_END_SYMBOL))
            assignments.append(last_symbol)
            return tuple(symbols), tuple(assignments)
        return None

    while queue:
        prefix_state = queue.popleft()
        prefix_bits, prefix_previous = prefix_state
        selected = transition(prefix_previous, page_token)
        if selected is not None and prefix_bits + selected[0] < maximum_bits:
            fast_suffix = fast_reselected_visible(
                selected[1],
                prefix_bits + selected[0],
            )
            if fast_suffix is not None:
                prefix = prefix_paths[prefix_state]
                visible_symbols, visible_assignments = fast_suffix
                symbols = list(prefix + page_token + visible_symbols)
                return (
                    symbols,
                    sum(symbol == page_token[0] for symbol in symbols) - 1,
                    list(visible_assignments),
                )
            visible_suffix = search_visible(
                selected[1],
                0,
                0,
                prefix_bits + selected[0],
            )
            if visible_suffix is not None:
                prefix = prefix_paths[prefix_state]
                visible_symbols, visible_assignments = visible_suffix
                symbols = list(prefix + page_token + visible_symbols)
                assignments = list(visible_assignments)
                return (
                    symbols,
                    sum(symbol == page_token[0] for symbol in symbols) - 1,
                    assignments,
                )

        for token in prefix_tokens:
            encoded = transition(prefix_previous, token)
            if encoded is None or prefix_bits + encoded[0] >= maximum_bits:
                continue
            candidate = (prefix_bits + encoded[0], encoded[1])
            if candidate in prefix_paths:
                continue
            prefix_paths[candidate] = prefix_paths[prefix_state] + token
            queue.append(candidate)
    raise ValueError("first context visual row exceeds its Huffman capacity")


def solve_bounded_length_row_multi_page_visual_symbols(
    *,
    trees: dict[int, object],
    initial_context: int,
    maximum_bits: int,
    pages: tuple[int, ...],
    visuals: list[str],
) -> tuple[list[int], int, list[int], list[int]]:
    """Search a bounded row while permitting visible glyph page changes.

    Every returned assignment includes the page that must contain its tile.
    Control-only bridge pages may be selected transiently, but only pages that
    actually render a visible glyph are returned for font writes.
    """

    if (
        not 0 <= initial_context <= 0xFF
        or not 1 <= maximum_bits <= 0x7FFF
        or not visuals
        or not pages
    ):
        raise ValueError("first context multi-page row inputs are invalid")
    candidate_pages = tuple(dict.fromkeys(pages))
    if any(not 0 <= page < FONT_PAGE_COUNT for page in candidate_pages):
        raise ValueError("first context multi-page row page is invalid")
    capacity = FONT_GLYPH_LAST_SYMBOL - FONT_GLYPH_FIRST_SYMBOL + 1
    if len(visuals) > capacity * len(candidate_pages):
        raise ValueError("first context visual row exceeds glyph search capacity")

    lengths = _code_lengths(trees)
    all_page_tokens = tuple(
        (page, tuple(page_select_symbols(page)))
        for page in range(FONT_PAGE_COUNT)
    )
    candidate_page_set = set(candidate_pages)
    glyph_symbols = tuple(
        range(FONT_GLYPH_FIRST_SYMBOL, FONT_GLYPH_LAST_SYMBOL + 1)
    )

    def transition(
        previous: int,
        symbols: tuple[int, ...],
    ) -> tuple[int, int] | None:
        bits = 0
        for symbol in symbols:
            code_length = lengths.get(previous, {}).get(symbol)
            if code_length is None:
                return None
            bits += code_length
            previous = symbol
        return bits, previous

    @lru_cache(maxsize=None)
    def page_routes(
        previous: int,
    ) -> tuple[tuple[int, tuple[int, ...], int, int], ...]:
        queue: list[tuple[int, tuple[int, ...], int]] = [(0, (), previous)]
        best_context = {previous: 0}
        best_target: dict[
            tuple[int, int], tuple[int, tuple[int, ...], int, int]
        ] = {}
        while queue:
            bits, path, current = heappop(queue)
            if bits != best_context.get(current):
                continue
            for candidate_page, token in all_page_tokens:
                encoded = transition(current, token)
                if encoded is None:
                    continue
                added_bits, next_previous = encoded
                total_bits = bits + added_bits
                if total_bits >= maximum_bits:
                    continue
                candidate_path = path + token
                if candidate_page in candidate_page_set:
                    target = (
                        total_bits,
                        candidate_path,
                        candidate_page,
                        next_previous,
                    )
                    target_key = (next_previous, candidate_page)
                    if target < best_target.get(
                        target_key,
                        (maximum_bits + 1, (), FONT_PAGE_COUNT, 0x100),
                    ):
                        best_target[target_key] = target
                if total_bits >= best_context.get(
                    next_previous, maximum_bits + 1
                ):
                    continue
                best_context[next_previous] = total_bits
                heappush(
                    queue,
                    (total_bits, candidate_path, next_previous),
                )
        retained: dict[int, list[tuple[int, tuple[int, ...], int, int]]] = {}
        for target in sorted(best_target.values()):
            targets = retained.setdefault(target[3], [])
            if len(targets) < len(visuals):
                targets.append(target)
        return tuple(
            sorted(target for targets in retained.values() for target in targets)
        )

    best_visible_bits: dict[
        tuple[int, int, frozenset[tuple[int, int]], int], int
    ] = {}

    @lru_cache(maxsize=None)
    def search_visible(
        previous: int,
        current_page: int,
        used_assignments: frozenset[tuple[int, int]],
        depth: int,
        bits: int,
    ) -> tuple[
        tuple[int, ...], tuple[int, ...], tuple[int, ...]
    ] | None:
        state = (previous, current_page, used_assignments, depth)
        if bits >= best_visible_bits.get(state, maximum_bits + 1):
            return None
        best_visible_bits[state] = bits
        if depth == len(visuals):
            end_length = lengths.get(previous, {}).get(CANDIDATE_END_SYMBOL)
            if end_length is not None and bits + end_length <= maximum_bits:
                return (CANDIDATE_END_SYMBOL,), (), ()
            return None
        routes: list[tuple[int, tuple[int, ...], int, int]] = []
        if current_page >= 0:
            routes.append((0, (), current_page, previous))
        routes.extend(page_routes(previous))
        for route_bits, route_symbols, route_page, route_previous in routes:
            candidates = sorted(
                (
                    symbol
                    for symbol in glyph_symbols
                    if (route_page, symbol) not in used_assignments
                    and symbol in lengths.get(route_previous, {})
                ),
                key=lambda symbol: (
                    CANDIDATE_END_SYMBOL not in lengths.get(symbol, {}),
                    -len(set(lengths.get(symbol, {})) & set(glyph_symbols)),
                    symbol,
                ),
            )
            for symbol in candidates:
                added_bits = lengths[route_previous][symbol]
                next_bits = bits + route_bits + added_bits
                if next_bits >= maximum_bits:
                    continue
                suffix = search_visible(
                    symbol,
                    route_page,
                    used_assignments | {(route_page, symbol)},
                    depth + 1,
                    next_bits,
                )
                if suffix is None:
                    continue
                suffix_symbols, suffix_assignments, suffix_pages = suffix
                return (
                    route_symbols + (symbol,) + suffix_symbols,
                    (symbol,) + suffix_assignments,
                    (route_page,) + suffix_pages,
                )
        return None

    result = search_visible(initial_context, -1, frozenset(), 0, 0)
    if result is None:
        raise ValueError("first context visual row exceeds multi-page capacity")
    symbols, assignments, assignment_pages = result
    page_control_symbol = page_select_symbols(candidate_pages[0])[0]
    return (
        list(symbols),
        sum(symbol == page_control_symbol for symbol in symbols) - 1,
        list(assignments),
        list(assignment_pages),
    )


def solve_exact_length_row_visual_symbols(
    *,
    trees: dict[int, object],
    initial_context: int,
    target_bits: int,
    page: int,
    visuals: list[str],
) -> tuple[list[int], int, list[int]]:
    if (
        not 0 <= initial_context <= 0xFF
        or not 1 <= target_bits <= 0x7FFF
        or not visuals
    ):
        raise ValueError("first context exact-length visual inputs are invalid")
    capacity = FONT_GLYPH_LAST_SYMBOL - FONT_GLYPH_FIRST_SYMBOL + 1
    if len(visuals) > capacity:
        raise ValueError("first context visual row exceeds one font page")

    # Keep the already proven fast path.  If its first valid glyph assignment
    # misses the original record length, jointly search the other assignments
    # and invisible page-select prefixes instead of rejecting the whole page.
    try:
        assignments = solve_row_visual_symbols(
            trees=trees,
            page=page,
            visuals=visuals,
        )
        symbols, padding_count = exact_length_row_symbols(
            trees=trees,
            initial_context=initial_context,
            target_bits=target_bits,
            page=page,
            assignments=assignments,
        )
        return symbols, padding_count, assignments
    except ValueError:
        pass

    lengths = _code_lengths(trees)

    def transition(
        previous: int,
        symbols: tuple[int, ...],
    ) -> tuple[int, int] | None:
        bits = 0
        for symbol in symbols:
            code_length = lengths.get(previous, {}).get(symbol)
            if code_length is None:
                return None
            bits += code_length
            previous = symbol
        return bits, previous

    page_token = tuple(page_select_symbols(page))
    prefix_tokens = [
        tuple(page_select_symbols(candidate_page))
        for candidate_page in range(FONT_PAGE_COUNT)
    ]
    glyph_symbols = tuple(
        range(FONT_GLYPH_FIRST_SYMBOL, FONT_GLYPH_LAST_SYMBOL + 1)
    )
    glyph_symbol_set = set(glyph_symbols)
    expanded_state_count = 0
    maximum_expanded_states = MAX_EXACT_SINGLE_PAGE_STATES

    queue = deque([(0, initial_context)])
    prefix_paths: dict[tuple[int, int], tuple[int, ...]] = {
        (0, initial_context): ()
    }

    @lru_cache(maxsize=None)
    def shortest_page_reselection(
        previous: int,
    ) -> tuple[int, tuple[int, ...]] | None:
        """Find a visually inert route back to the row's font page.

        The exact solver used to permit page-select padding only before the
        first glyph.  Runtime review showed that accepting a shorter route is
        unsafe, so also permit a page reset between visible glyphs while still
        requiring the original encoded bit length exactly.
        """

        heap: list[tuple[int, tuple[int, ...], int]] = [(0, (), previous)]
        best = {previous: 0}
        best_target: tuple[int, tuple[int, ...]] | None = None
        while heap:
            bits, path, current = heappop(heap)
            if bits != best.get(current):
                continue
            if best_target is not None and bits >= best_target[0]:
                break
            for candidate_page, token in enumerate(prefix_tokens):
                encoded = transition(current, token)
                if encoded is None:
                    continue
                added_bits, next_previous = encoded
                total_bits = bits + added_bits
                if total_bits >= target_bits:
                    continue
                candidate_path = path + token
                if candidate_page == page:
                    candidate = (total_bits, candidate_path)
                    if best_target is None or candidate < best_target:
                        best_target = candidate
                    continue
                if total_bits >= best.get(next_previous, target_bits + 1):
                    continue
                best[next_previous] = total_bits
                heappush(heap, (total_bits, candidate_path, next_previous))
        return best_target

    @lru_cache(maxsize=None)
    def exact_terminator_route(
        previous: int,
        remaining_bits: int,
    ) -> tuple[int, ...] | None:
        """Reach the terminator exactly through trailing invisible controls."""

        queue = deque([(0, previous)])
        paths: dict[tuple[int, int], tuple[int, ...]] = {
            (0, previous): ()
        }
        while queue:
            bits, current = queue.popleft()
            end_length = lengths.get(current, {}).get(CANDIDATE_END_SYMBOL)
            if end_length is not None and bits + end_length == remaining_bits:
                return paths[(bits, current)] + (CANDIDATE_END_SYMBOL,)
            unique_transitions: dict[
                tuple[int, int], tuple[int, ...]
            ] = {}
            for token in prefix_tokens:
                encoded = transition(current, token)
                if encoded is not None:
                    unique_transitions.setdefault(encoded, token)
            for (added_bits, next_previous), token in sorted(
                unique_transitions.items()
            ):
                total_bits = bits + added_bits
                if total_bits >= remaining_bits:
                    continue
                state = (total_bits, next_previous)
                if state in paths:
                    continue
                paths[state] = paths[(bits, current)] + token
                queue.append(state)
        return None

    @lru_cache(maxsize=None)
    def relaxed_can_finish(
        previous: int,
        depth: int,
        remaining_bits: int,
    ) -> bool:
        """Reject exact-length states that cannot finish even without slots.

        The full search must remember which visual owns each glyph slot, which
        is necessarily combinatorial.  This cheaper relaxation ignores those
        ownership and uniqueness constraints while preserving the real
        Huffman transitions, visible-glyph count, page reselection route, and
        exact terminator length.  A false result therefore proves that the
        corresponding full state is impossible and can be discarded safely.
        """

        if remaining_bits <= 0:
            return False
        if depth == len(visuals):
            return exact_terminator_route(previous, remaining_bits) is not None
        routes = [(0, previous)]
        reselection = shortest_page_reselection(previous)
        if reselection is not None:
            routes.append((reselection[0], page_token[-1]))
        for route_bits, route_previous in routes:
            for symbol in glyph_symbols:
                symbol_bits = lengths.get(route_previous, {}).get(symbol)
                if symbol_bits is None:
                    continue
                consumed = route_bits + symbol_bits
                if consumed >= remaining_bits:
                    continue
                if relaxed_can_finish(
                    symbol,
                    depth + 1,
                    remaining_bits - consumed,
                ):
                    return True
        return False

    @lru_cache(maxsize=None)
    def search_visible(
        previous: int,
        used_mask: int,
        depth: int,
        bits: int,
    ) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
        nonlocal expanded_state_count
        expanded_state_count += 1
        if expanded_state_count > maximum_expanded_states:
            raise ValueError(
                "first context exact-length search state limit exceeded"
            )
        if not relaxed_can_finish(previous, depth, target_bits - bits):
            return None
        if depth == len(visuals):
            terminator = exact_terminator_route(
                previous, target_bits - bits
            )
            return (terminator, ()) if terminator is not None else None
        routes = [(0, (), previous)]
        reselection = shortest_page_reselection(previous)
        if reselection is not None:
            reselection_bits, reselection_symbols = reselection
            routes.append(
                (reselection_bits, reselection_symbols, page_token[-1])
            )
        for route_bits, route_symbols, route_previous in routes:
            candidates = tuple(
                sorted(
                    (
                        symbol
                        for symbol in glyph_symbols
                        if not used_mask
                        & (1 << (symbol - FONT_GLYPH_FIRST_SYMBOL))
                        and symbol in lengths.get(route_previous, {})
                    ),
                    key=lambda symbol: (
                        CANDIDATE_END_SYMBOL
                        not in lengths.get(symbol, {}),
                        -len(
                            set(lengths.get(symbol, {}))
                            & glyph_symbol_set
                        ),
                        symbol,
                    ),
                )
            )
            for symbol in candidates:
                added_bits = lengths[route_previous][symbol]
                next_bits = bits + route_bits + added_bits
                if next_bits >= target_bits:
                    continue
                next_used_mask = used_mask | 1 << (
                    symbol - FONT_GLYPH_FIRST_SYMBOL
                )
                suffix = search_visible(
                    symbol,
                    next_used_mask,
                    depth + 1,
                    next_bits,
                )
                if suffix is None:
                    continue
                suffix_symbols, suffix_assignments = suffix
                return (
                    route_symbols + (symbol,) + suffix_symbols,
                    (symbol,) + suffix_assignments,
                )
        return None

    while queue:
        prefix_state = queue.popleft()
        prefix_bits, prefix_previous = prefix_state
        selected = transition(prefix_previous, page_token)
        if selected is not None and prefix_bits + selected[0] < target_bits:
            visible_suffix = search_visible(
                selected[1],
                0,
                0,
                prefix_bits + selected[0],
            )
            if visible_suffix is not None:
                prefix = prefix_paths[prefix_state]
                visible_symbols, visible_assignments = visible_suffix
                assignments = list(visible_assignments)
                return (
                    list(prefix + page_token + visible_symbols),
                    (
                        sum(
                            symbol == page_token[0]
                            for symbol in prefix + page_token + visible_symbols
                        )
                        - 1
                    ),
                    assignments,
                )

        for token in prefix_tokens:
            encoded = transition(prefix_previous, token)
            if encoded is None or prefix_bits + encoded[0] >= target_bits:
                continue
            candidate = (prefix_bits + encoded[0], encoded[1])
            if candidate in prefix_paths:
                continue
            prefix_paths[candidate] = prefix_paths[prefix_state] + token
            queue.append(candidate)
    raise ValueError("first context visual row has no exact-length Huffman route")


def exact_multi_page_state_limit(page_count: int) -> int:
    if not 1 <= page_count <= FONT_PAGE_COUNT:
        raise ValueError("first context exact page count is invalid")
    return 5_000


def solve_exact_length_row_multi_page_visual_symbols(
    *,
    trees: dict[int, object],
    initial_context: int,
    target_bits: int,
    pages: tuple[int, ...],
    visuals: list[str],
) -> tuple[list[int], int, list[int], list[int]]:
    """Search an exact-length row across a small set of render pages."""

    if (
        not 0 <= initial_context <= 0xFF
        or not 1 <= target_bits <= 0x7FFF
        or not visuals
        or not pages
    ):
        raise ValueError("first context exact multi-page inputs are invalid")
    candidate_pages = tuple(dict.fromkeys(pages))
    if any(not 0 <= page < FONT_PAGE_COUNT for page in candidate_pages):
        raise ValueError("first context exact multi-page page is invalid")
    capacity = FONT_GLYPH_LAST_SYMBOL - FONT_GLYPH_FIRST_SYMBOL + 1
    if len(visuals) > capacity * len(candidate_pages):
        raise ValueError("first context exact multi-page capacity is too small")

    lengths = _code_lengths(trees)
    all_page_tokens = tuple(
        (page, tuple(page_select_symbols(page)))
        for page in range(FONT_PAGE_COUNT)
    )
    candidate_page_set = set(candidate_pages)
    page_priority = {
        page: priority for priority, page in enumerate(candidate_pages)
    }
    glyph_symbols = tuple(
        range(FONT_GLYPH_FIRST_SYMBOL, FONT_GLYPH_LAST_SYMBOL + 1)
    )
    glyph_symbol_set = set(glyph_symbols)
    expanded_state_count = 0
    maximum_expanded_states = exact_multi_page_state_limit(
        len(candidate_pages)
    )

    def transition(
        previous: int,
        symbols: tuple[int, ...],
    ) -> tuple[int, int] | None:
        bits = 0
        for symbol in symbols:
            code_length = lengths.get(previous, {}).get(symbol)
            if code_length is None:
                return None
            bits += code_length
            previous = symbol
        return bits, previous

    @lru_cache(maxsize=None)
    def unique_bridge_transitions(
        previous: int,
    ) -> tuple[tuple[int, int, tuple[int, ...]], ...]:
        unique: dict[tuple[int, int], tuple[int, ...]] = {}
        for _, token in all_page_tokens:
            encoded = transition(previous, token)
            if encoded is not None:
                unique.setdefault(encoded, token)
        return tuple(
            (added_bits, next_previous, token)
            for (added_bits, next_previous), token in sorted(unique.items())
        )

    @lru_cache(maxsize=None)
    def exact_terminator_route(
        previous: int,
        remaining_bits: int,
    ) -> tuple[int, ...] | None:
        queue = deque([(0, previous)])
        paths: dict[tuple[int, int], tuple[int, ...]] = {
            (0, previous): ()
        }
        while queue:
            bits, current = queue.popleft()
            end_length = lengths.get(current, {}).get(CANDIDATE_END_SYMBOL)
            if end_length is not None and bits + end_length == remaining_bits:
                return paths[(bits, current)] + (CANDIDATE_END_SYMBOL,)
            for added_bits, next_previous, token in (
                unique_bridge_transitions(current)
            ):
                total_bits = bits + added_bits
                if total_bits >= remaining_bits:
                    continue
                state = (total_bits, next_previous)
                if state in paths:
                    continue
                paths[state] = paths[(bits, current)] + token
                queue.append(state)
        return None

    @lru_cache(maxsize=None)
    def page_routes(
        previous: int,
    ) -> tuple[tuple[int, tuple[int, ...], int, int], ...]:
        """Enumerate bit-distinct invisible routes to each render page.

        Exact-length rows cannot discard a longer page-select path merely
        because a shorter path reaches the same Huffman context.  The extra
        bits are invisible on screen and may be exactly what preserves the
        source record boundary.  Bridge transitions that have the same bit
        cost and next context remain equivalent and are collapsed.
        """

        heap: list[tuple[int, tuple[int, ...], int]] = [(0, (), previous)]
        seen_contexts = {(0, previous)}
        best_target: dict[
            tuple[int, int, int], tuple[int, tuple[int, ...], int, int]
        ] = {}
        while heap:
            bits, path, current = heappop(heap)
            for candidate_page in candidate_pages:
                token = tuple(page_select_symbols(candidate_page))
                encoded = transition(current, token)
                if encoded is None:
                    continue
                added_bits, next_previous = encoded
                total_bits = bits + added_bits
                if total_bits >= target_bits:
                    continue
                candidate_path = path + token
                if candidate_page in candidate_page_set:
                    target = (
                        total_bits,
                        candidate_path,
                        candidate_page,
                        next_previous,
                    )
                    key = (total_bits, candidate_page, next_previous)
                    current_target = best_target.get(key)
                    if current_target is None or target < current_target:
                        best_target[key] = target

            for added_bits, next_previous, token in (
                unique_bridge_transitions(current)
            ):
                total_bits = bits + added_bits
                if total_bits >= target_bits:
                    continue
                state = (total_bits, next_previous)
                if state in seen_contexts:
                    continue
                seen_contexts.add(state)
                heappush(heap, (total_bits, path + token, next_previous))
        return tuple(
            sorted(
                best_target.values(),
                key=lambda route: (
                    route[0],
                    page_priority[route[2]],
                    route[1],
                    route[3],
                ),
            )
        )

    def visible_routes(
        previous: int,
        current_page: int,
    ) -> tuple[tuple[int, tuple[int, ...], int, int], ...]:
        routes: list[tuple[int, tuple[int, ...], int, int]] = []
        if current_page >= 0:
            routes.append((0, (), current_page, previous))
        routes.extend(page_routes(previous))
        return tuple(routes)

    @lru_cache(maxsize=None)
    def relaxed_can_finish(
        previous: int,
        current_page: int,
        depth: int,
        remaining_bits: int,
    ) -> bool:
        if remaining_bits <= 0:
            return False
        if depth == len(visuals):
            return exact_terminator_route(previous, remaining_bits) is not None
        for route_bits, _, route_page, route_previous in visible_routes(
            previous, current_page
        ):
            for symbol in glyph_symbols:
                symbol_bits = lengths.get(route_previous, {}).get(symbol)
                if symbol_bits is None:
                    continue
                consumed = route_bits + symbol_bits
                if consumed >= remaining_bits:
                    continue
                if relaxed_can_finish(
                    symbol,
                    route_page,
                    depth + 1,
                    remaining_bits - consumed,
                ):
                    return True
        return False

    @lru_cache(maxsize=None)
    def search_visible(
        previous: int,
        current_page: int,
        used_mask: int,
        depth: int,
        bits: int,
    ) -> tuple[
        tuple[int, ...], tuple[int, ...], tuple[int, ...]
    ] | None:
        nonlocal expanded_state_count
        expanded_state_count += 1
        if expanded_state_count > maximum_expanded_states:
            raise ValueError(
                "first context exact multi-page search state limit exceeded"
            )
        if not relaxed_can_finish(
            previous,
            current_page,
            depth,
            target_bits - bits,
        ):
            return None
        if depth == len(visuals):
            terminator = exact_terminator_route(
                previous, target_bits - bits
            )
            return (
                (terminator, (), ()) if terminator is not None else None
            )
        for route_bits, route_symbols, route_page, route_previous in (
            visible_routes(previous, current_page)
        ):
            candidates = tuple(
                sorted(
                    (
                        symbol
                        for symbol in glyph_symbols
                        if not used_mask
                        & (
                            1
                            << (
                                page_priority[route_page] * capacity
                                + symbol
                                - FONT_GLYPH_FIRST_SYMBOL
                            )
                        )
                        and symbol in lengths.get(route_previous, {})
                    ),
                    key=lambda symbol: (
                        CANDIDATE_END_SYMBOL
                        not in lengths.get(symbol, {}),
                        -len(
                            set(lengths.get(symbol, {}))
                            & glyph_symbol_set
                        ),
                        symbol,
                    ),
                )
            )
            for symbol in candidates:
                added_bits = lengths[route_previous][symbol]
                next_bits = bits + route_bits + added_bits
                if next_bits >= target_bits:
                    continue
                slot_index = (
                    page_priority[route_page] * capacity
                    + symbol
                    - FONT_GLYPH_FIRST_SYMBOL
                )
                next_used_mask = used_mask | 1 << slot_index
                suffix = search_visible(
                    symbol,
                    route_page,
                    next_used_mask,
                    depth + 1,
                    next_bits,
                )
                if suffix is None:
                    continue
                suffix_symbols, suffix_assignments, suffix_pages = suffix
                return (
                    route_symbols + (symbol,) + suffix_symbols,
                    (symbol,) + suffix_assignments,
                    (route_page,) + suffix_pages,
                )
        return None

    prefix_queue = deque([(0, initial_context)])
    prefix_paths: dict[tuple[int, int], tuple[int, ...]] = {
        (0, initial_context): ()
    }
    while prefix_queue:
        prefix_state = prefix_queue.popleft()
        prefix_bits, prefix_previous = prefix_state
        for candidate_page in candidate_pages:
            page_token = tuple(page_select_symbols(candidate_page))
            selected = transition(prefix_previous, page_token)
            if selected is None or prefix_bits + selected[0] >= target_bits:
                continue
            suffix = search_visible(
                selected[1],
                candidate_page,
                0,
                0,
                prefix_bits + selected[0],
            )
            if suffix is None:
                continue
            suffix_symbols, assignments, assignment_pages = suffix
            symbols = prefix_paths[prefix_state] + page_token + suffix_symbols
            control_symbol = page_select_symbols(candidate_pages[0])[0]
            return (
                list(symbols),
                sum(symbol == control_symbol for symbol in symbols) - 1,
                list(assignments),
                list(assignment_pages),
            )

        unique_transitions: dict[tuple[int, int], tuple[int, ...]] = {}
        for _, token in all_page_tokens:
            encoded = transition(prefix_previous, token)
            if encoded is None or prefix_bits + encoded[0] >= target_bits:
                continue
            unique_transitions.setdefault((encoded[0], encoded[1]), token)
        for (added_bits, next_previous), token in sorted(
            unique_transitions.items()
        ):
            candidate = (prefix_bits + added_bits, next_previous)
            if candidate in prefix_paths:
                continue
            prefix_paths[candidate] = prefix_paths[prefix_state] + token
            prefix_queue.append(candidate)
    raise ValueError(
        "first context visual row has no exact multi-page Huffman route"
    )


def solve_fixed_count_row_visual_symbols(
    *,
    trees: dict[int, object],
    initial_context: int,
    maximum_bits: int,
    target_symbol_count: int,
    page: int,
    visuals: list[str],
) -> tuple[list[int], int, list[int]]:
    """Choose glyph slots with a bounded fixed-count beam search.

    A fixed-count caller needs the final terminator at an exact decoded-symbol
    index, but the extra renderer-inert page selections may be placed between
    visible glyphs.  Enumerating every placement and then repeating a full DFS
    for each one made the device stage exceed its 120-second guard.  Carry the
    number of inserted page tokens in the search state instead and retain only
    the cheapest deterministic frontier after every visible glyph.
    """

    if (
        not 0 <= initial_context <= 0xFF
        or not 1 <= maximum_bits <= 0x7FFF
        or not 0 <= page < FONT_PAGE_COUNT
        or not visuals
        or not 1 <= target_symbol_count <= 0x1000
    ):
        raise ValueError("first context fixed-count visual inputs are invalid")
    control_symbols = target_symbol_count - len(visuals) - 1
    if control_symbols < 3 or control_symbols % 3:
        raise ValueError("first context fixed count cannot preserve page controls")
    required_page_tokens = control_symbols // 3
    extra_page_tokens = required_page_tokens - 1
    lengths = _code_lengths(trees)
    glyph_symbols = tuple(
        range(FONT_GLYPH_FIRST_SYMBOL, FONT_GLYPH_LAST_SYMBOL + 1)
    )
    glyph_symbol_set = set(glyph_symbols)
    row_page_token = tuple(page_select_symbols(page))
    all_page_tokens = tuple(
        dict.fromkeys(
            tuple(page_select_symbols(candidate_page))
            for candidate_page in range(FONT_PAGE_COUNT)
        )
    )

    def transition(
        previous: int,
        sequence: tuple[int, ...],
    ) -> tuple[int, int] | None:
        bits = 0
        for symbol in sequence:
            code_length = lengths.get(previous, {}).get(symbol)
            if code_length is None:
                return None
            bits += code_length
            previous = symbol
        return bits, previous

    initial_by_state: dict[
        tuple[int, int],
        tuple[int, int, int, int, tuple[int, ...], tuple[int, ...]],
    ] = {}
    initial_routes = [(row_page_token, 0)]
    if extra_page_tokens:
        # A temporary page before the mandatory row page is invisible: the
        # mandatory selection restores the correct page before any glyph.
        initial_routes.extend(
            (token + row_page_token, 1) for token in all_page_tokens
        )
    for route, inserted in initial_routes:
        selected = transition(initial_context, route)
        if selected is None or selected[0] >= maximum_bits:
            continue
        candidate = (selected[0], selected[1], 0, inserted, route, ())
        state = (selected[1], inserted)
        incumbent = initial_by_state.get(state)
        if incumbent is None or candidate < incumbent:
            initial_by_state[state] = candidate
    if not initial_by_state:
        raise ValueError("first context fixed-count page is not selectable")

    candidate_order: dict[int, tuple[int, ...]] = {}
    for previous in range(0x100):
        candidate_order[previous] = tuple(
            sorted(
                (
                    symbol
                    for symbol in glyph_symbols
                    if symbol in lengths.get(previous, {})
                ),
                key=lambda symbol: (
                    CANDIDATE_END_SYMBOL not in lengths.get(symbol, {}),
                    -len(set(lengths.get(symbol, {})) & glyph_symbol_set),
                    lengths[previous][symbol],
                    symbol,
                ),
            )
        )

    safe_suffix_by_previous: dict[int, tuple[int, tuple[int, ...]]] = {}
    for previous in range(0x100):
        candidates = []
        for token in all_page_tokens:
            tail = token + (CANDIDATE_END_SYMBOL,)
            encoded = transition(previous, tail)
            if encoded is not None:
                candidates.append((encoded[0], tail))
        if candidates:
            safe_suffix_by_previous[previous] = min(candidates)

    direct_end_by_previous: dict[int, tuple[int, tuple[int, ...]]] = {}
    for previous in range(0x100):
        encoded = transition(previous, (CANDIDATE_END_SYMBOL,))
        if encoded is not None:
            direct_end_by_previous[previous] = (
                encoded[0],
                (CANDIDATE_END_SYMBOL,),
            )

    def internally_controlled_path(
        *,
        start_previous: int,
        start_bits: int,
        control_count: int,
    ) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
        """Solve visible glyphs and page controls in one endpoint-proof search."""

        unreachable = maximum_bits + 1

        def final_tail(
            previous: int,
            controls_left: int,
        ) -> tuple[int, tuple[int, ...]] | None:
            if controls_left == 0:
                return direct_end_by_previous.get(previous)
            if controls_left == 1:
                return safe_suffix_by_previous.get(previous)
            tail = row_page_token * controls_left + (CANDIDATE_END_SYMBOL,)
            encoded = transition(previous, tail)
            return None if encoded is None else (encoded[0], tail)

        @lru_cache(maxsize=None)
        def minimum_remaining_bits(
            previous: int,
            remaining: int,
            controls_left: int,
        ) -> int:
            if remaining == 0:
                tail = final_tail(previous, controls_left)
                return unreachable if tail is None else tail[0]
            best = unreachable
            for inserted_now in range(controls_left + 1):
                controls = row_page_token * inserted_now
                controlled = transition(previous, controls)
                if controlled is None:
                    continue
                control_bits, controlled_previous = controlled
                for symbol in candidate_order[controlled_previous]:
                    suffix = minimum_remaining_bits(
                        symbol,
                        remaining - 1,
                        controls_left - inserted_now,
                    )
                    if suffix >= unreachable:
                        continue
                    best = min(
                        best,
                        control_bits
                        + lengths[controlled_previous][symbol]
                        + suffix,
                    )
            return best

        if (
            start_bits
            + minimum_remaining_bits(
                start_previous,
                len(visuals),
                control_count,
            )
            > maximum_bits
        ):
            return None
        expanded = 0
        best_bits: dict[tuple[int, int, int, int], int] = {}

        def search(
            previous: int,
            used_mask: int,
            remaining: int,
            controls_left: int,
            bits: int,
        ) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
            nonlocal expanded
            expanded += 1
            if expanded > 300_000:
                return None
            state = (previous, used_mask, remaining, controls_left)
            if bits >= best_bits.get(state, maximum_bits + 1):
                return None
            best_bits[state] = bits
            if remaining == 0:
                tail = final_tail(previous, controls_left)
                if tail is None or bits + tail[0] > maximum_bits:
                    return None
                return tail[1], ()
            ranked = []
            for inserted_now in range(controls_left + 1):
                controls = row_page_token * inserted_now
                controlled = transition(previous, controls)
                if controlled is None:
                    continue
                control_bits, controlled_previous = controlled
                for symbol in candidate_order[controlled_previous]:
                    mask = 1 << (symbol - FONT_GLYPH_FIRST_SYMBOL)
                    if used_mask & mask:
                        continue
                    suffix_minimum = minimum_remaining_bits(
                        symbol,
                        remaining - 1,
                        controls_left - inserted_now,
                    )
                    if suffix_minimum >= unreachable:
                        continue
                    added_bits = (
                        control_bits + lengths[controlled_previous][symbol]
                    )
                    if bits + added_bits + suffix_minimum > maximum_bits:
                        continue
                    ranked.append(
                        (
                            added_bits + suffix_minimum,
                            inserted_now,
                            symbol,
                            mask,
                            controls,
                            added_bits,
                        )
                    )
            for (
                _,
                inserted_now,
                symbol,
                mask,
                controls,
                added_bits,
            ) in sorted(ranked):
                suffix = search(
                    symbol,
                    used_mask | mask,
                    remaining - 1,
                    controls_left - inserted_now,
                    bits + added_bits,
                )
                if suffix is not None:
                    suffix_symbols, suffix_assignments = suffix
                    return (
                        controls + (symbol,) + suffix_symbols,
                        (symbol,) + suffix_assignments,
                    )
            return None

        return search(
            start_previous,
            0,
            len(visuals),
            control_count,
            start_bits,
        )

    # Solve the normal renderer-safe form first: mandatory row page, visible
    # glyphs with any required same-page reselection, then a safe terminator.
    # Two or more extra controls make the exact used-mask search too expensive
    # for the phone's 120-second guard.  The bounded endpoint-ranked frontier
    # below covers that layout in roughly linear time.
    exact_initials = (
        [] if extra_page_tokens >= 2 else sorted(initial_by_state.values())
    )
    for initial in exact_initials:
        start_bits, start_previous, _, inserted, route, _ = initial
        if inserted:
            continue
        controlled = internally_controlled_path(
            start_previous=start_previous,
            start_bits=start_bits,
            control_count=extra_page_tokens,
        )
        if controlled is None:
            continue
        controlled_symbols, assignments = controlled
        symbols = route + controlled_symbols
        if len(symbols) == target_symbol_count:
            return list(symbols), extra_page_tokens, list(assignments)

    def endpoint_constrained_path(
        *,
        start_previous: int,
        start_bits: int,
        tail_by_previous: dict[int, tuple[int, tuple[int, ...]]],
    ) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
        """Find a distinct-glyph path that is proved to reach its safe tail."""

        unreachable = maximum_bits + 1

        @lru_cache(maxsize=None)
        def minimum_remaining_bits(previous: int, remaining: int) -> int:
            if remaining == 0:
                tail = tail_by_previous.get(previous)
                return unreachable if tail is None else tail[0]
            best = unreachable
            for symbol in candidate_order[previous]:
                suffix = minimum_remaining_bits(symbol, remaining - 1)
                if suffix >= unreachable:
                    continue
                best = min(best, lengths[previous][symbol] + suffix)
            return best

        if (
            start_bits
            + minimum_remaining_bits(start_previous, len(visuals))
            > maximum_bits
        ):
            return None
        expanded = 0
        best_bits: dict[tuple[int, int, int], int] = {}

        def search(
            previous: int,
            used_mask: int,
            remaining: int,
            bits: int,
        ) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
            nonlocal expanded
            expanded += 1
            if expanded > 100_000:
                return None
            state = (previous, used_mask, remaining)
            if bits >= best_bits.get(state, maximum_bits + 1):
                return None
            best_bits[state] = bits
            if remaining == 0:
                tail = tail_by_previous.get(previous)
                if tail is None or bits + tail[0] > maximum_bits:
                    return None
                return tail[1], ()
            ranked = []
            for symbol in candidate_order[previous]:
                mask = 1 << (symbol - FONT_GLYPH_FIRST_SYMBOL)
                if used_mask & mask:
                    continue
                suffix_minimum = minimum_remaining_bits(symbol, remaining - 1)
                if suffix_minimum >= unreachable:
                    continue
                added_bits = lengths[previous][symbol]
                if bits + added_bits + suffix_minimum > maximum_bits:
                    continue
                ranked.append((added_bits + suffix_minimum, symbol, mask))
            for _, symbol, mask in sorted(ranked):
                added_bits = lengths[previous][symbol]
                suffix = search(
                    symbol,
                    used_mask | mask,
                    remaining - 1,
                    bits + added_bits,
                )
                if suffix is not None:
                    suffix_symbols, suffix_assignments = suffix
                    return (
                        (symbol,) + suffix_symbols,
                        (symbol,) + suffix_assignments,
                    )
            return None

        return search(start_previous, 0, len(visuals), start_bits)

    # First solve the two fully renderer-safe edge cases with an endpoint-aware
    # search.  Unlike a beam, it never discards the only state capable of
    # reaching the required terminator route.
    for initial in exact_initials:
        start_bits, start_previous, _, inserted, route, _ = initial
        if inserted == extra_page_tokens:
            tails = direct_end_by_previous
        elif inserted + 1 == extra_page_tokens:
            tails = safe_suffix_by_previous
        else:
            continue
        endpoint = endpoint_constrained_path(
            start_previous=start_previous,
            start_bits=start_bits,
            tail_by_previous=tails,
        )
        if endpoint is None:
            continue
        endpoint_symbols, assignments = endpoint
        symbols = route + endpoint_symbols
        if len(symbols) == target_symbol_count:
            return list(symbols), extra_page_tokens, list(assignments)

    # (bits, previous, used-mask, inserted-controls, route, assignments)
    frontier: list[
        tuple[int, int, int, int, tuple[int, ...], tuple[int, ...]]
    ] = sorted(initial_by_state.values())
    # The device runner has a 120-second guard.  A 5,000-state frontier can
    # create tens of millions of Python tuples across eight candidate pages.
    # Runtime analysis found only a handful of glyphs with a page-select exit,
    # so the frontier rank below explicitly preserves those scarce states.
    beam_width = min(
        MAX_BOUNDED_SINGLE_PAGE_STATES,
        1024 if extra_page_tokens >= 2 else 128,
    )
    for _depth in range(len(visuals)):
        next_by_state: dict[
            tuple[int, int, int],
            tuple[int, int, int, int, tuple[int, ...], tuple[int, ...]],
        ] = {}
        for bits, previous, used_mask, inserted, route, assignments in frontier:
            maximum_insert = extra_page_tokens - inserted
            for control_count in range(maximum_insert + 1):
                controls = row_page_token * control_count
                controlled = transition(previous, controls)
                if controlled is None:
                    continue
                control_bits, controlled_previous = controlled
                controlled_bits = bits + control_bits
                if controlled_bits >= maximum_bits:
                    continue
                for symbol in candidate_order[controlled_previous]:
                    mask = 1 << (symbol - FONT_GLYPH_FIRST_SYMBOL)
                    if used_mask & mask:
                        continue
                    next_bits = (
                        controlled_bits
                        + lengths[controlled_previous][symbol]
                    )
                    if next_bits >= maximum_bits:
                        continue
                    next_inserted = inserted + control_count
                    state = (symbol, used_mask | mask, next_inserted)
                    candidate = (
                        next_bits,
                        symbol,
                        used_mask | mask,
                        next_inserted,
                        route + controls + (symbol,),
                        assignments + (symbol,),
                    )
                    incumbent = next_by_state.get(state)
                    if incumbent is None or candidate < incumbent:
                        next_by_state[state] = candidate
        if not next_by_state:
            break
        frontier = sorted(
            next_by_state.values(),
            key=lambda item: (
                (
                    extra_page_tokens > item[3]
                    and transition(item[1], row_page_token) is None
                    and item[1] not in safe_suffix_by_previous
                ),
                item[0],
                CANDIDATE_END_SYMBOL not in lengths.get(item[1], {}),
                -len(set(lengths.get(item[1], {})) & glyph_symbol_set),
                item[4],
            ),
        )[:beam_width]

    completed = []
    for bits, previous, _used_mask, inserted, route, assignments in frontier:
        remaining = extra_page_tokens - inserted
        if remaining == 0:
            tails = ((CANDIDATE_END_SYMBOL,),)
        elif remaining == 1:
            # A temporary page immediately before the terminator is also
            # invisible because no following glyph observes that page.
            suffix = safe_suffix_by_previous.get(previous)
            tails = () if suffix is None else (suffix[1],)
        else:
            tails = (
                row_page_token * remaining + (CANDIDATE_END_SYMBOL,),
            )
        for tail in tails:
            ended = transition(previous, tail)
            if ended is None or bits + ended[0] > maximum_bits:
                continue
            symbols = route + tail
            if len(symbols) == target_symbol_count:
                completed.append((bits + ended[0], symbols, assignments))
    if completed:
        _, symbols, assignments = min(completed)
        return list(symbols), extra_page_tokens, list(assignments)
    raise ValueError("first context row has no scheduled fixed-count route")


def solve_fixed_count_row_multi_page_visual_symbols(
    *,
    trees: dict[int, object],
    initial_context: int,
    maximum_bits: int,
    target_symbol_count: int,
    pages: tuple[int, ...],
    visuals: list[str],
) -> tuple[list[int], int, list[int], list[int]]:
    """Jointly choose multi-page glyph slots for one fixed-count row."""

    candidate_pages = tuple(dict.fromkeys(pages))
    required_page_tokens = target_symbol_count - len(visuals) - 1
    if required_page_tokens >= 0 and required_page_tokens % 3 == 0:
        required_page_tokens //= 3
    else:
        required_page_tokens = -1

    # Solve short fixed-count structures directly: one visible segment on each
    # page, with no invisible padding and no exact-bit sweep.  The compact
    # first row uses three page tokens; keeping each segment independent avoids
    # the exponential generic multi-page search on the phone.
    if (
        required_page_tokens in {2, 3}
        and len(candidate_pages) == required_page_tokens
    ):
        lengths = _code_lengths(trees)
        glyph_symbols = tuple(
            range(FONT_GLYPH_FIRST_SYMBOL, FONT_GLYPH_LAST_SYMBOL + 1)
        )

        def transition(
            previous: int,
            sequence: tuple[int, ...],
        ) -> tuple[int, int] | None:
            bits = 0
            for symbol in sequence:
                code_length = lengths.get(previous, {}).get(symbol)
                if code_length is None:
                    return None
                bits += code_length
                previous = symbol
            return bits, previous

        def segment_path(
            *,
            start_previous: int,
            glyph_count: int,
            bit_limit: int,
            tail_by_previous: dict[int, tuple[int, tuple[int, ...]]],
        ) -> tuple[tuple[int, ...], tuple[int, ...], int] | None:
            unreachable = bit_limit + 1

            @lru_cache(maxsize=None)
            def minimum_bits(previous: int, remaining: int) -> int:
                if remaining == 0:
                    tail = tail_by_previous.get(previous)
                    return unreachable if tail is None else tail[0]
                best = unreachable
                for symbol in glyph_symbols:
                    edge = lengths.get(previous, {}).get(symbol)
                    if edge is None:
                        continue
                    suffix = minimum_bits(symbol, remaining - 1)
                    if suffix < unreachable:
                        best = min(best, edge + suffix)
                return best

            if minimum_bits(start_previous, glyph_count) > bit_limit:
                return None
            expanded = 0
            best_seen: dict[tuple[int, int, int], int] = {}

            def search(
                previous: int,
                used_mask: int,
                remaining: int,
                bits: int,
            ) -> tuple[tuple[int, ...], tuple[int, ...], int] | None:
                nonlocal expanded
                expanded += 1
                if expanded > 500:
                    return None
                state = (previous, used_mask, remaining)
                if bits >= best_seen.get(state, bit_limit + 1):
                    return None
                best_seen[state] = bits
                if remaining == 0:
                    tail = tail_by_previous.get(previous)
                    if tail is None or bits + tail[0] > bit_limit:
                        return None
                    return tail[1], (), bits + tail[0]
                ranked = []
                for symbol in glyph_symbols:
                    edge = lengths.get(previous, {}).get(symbol)
                    if edge is None:
                        continue
                    mask = 1 << (symbol - FONT_GLYPH_FIRST_SYMBOL)
                    if used_mask & mask:
                        continue
                    suffix = minimum_bits(symbol, remaining - 1)
                    if suffix >= unreachable or bits + edge + suffix > bit_limit:
                        continue
                    ranked.append((edge + suffix, symbol, mask, edge))
                for _, symbol, mask, edge in sorted(ranked):
                    suffix = search(
                        symbol,
                        used_mask | mask,
                        remaining - 1,
                        bits + edge,
                    )
                    if suffix is not None:
                        suffix_symbols, suffix_assignments, total_bits = suffix
                        return (
                            (symbol,) + suffix_symbols,
                            (symbol,) + suffix_assignments,
                            total_bits,
                        )
                return None

            return search(start_previous, 0, glyph_count, 0)

        direct_end = {}
        for previous in range(0x100):
            encoded = transition(previous, (CANDIDATE_END_SYMBOL,))
            if encoded is not None:
                direct_end[previous] = (encoded[0], (CANDIDATE_END_SYMBOL,))

        if required_page_tokens == 3:
            page_orders = tuple(
                (first, second, third)
                for first in candidate_pages
                for second in candidate_pages
                for third in candidate_pages
                if len({first, second, third}) == 3
            )
            split_pairs = sorted(
                (
                    (first_split, second_split)
                    for first_split in range(1, len(visuals) - 1)
                    for second_split in range(
                        first_split + 1,
                        len(visuals),
                    )
                ),
                key=lambda pair: (
                    max(
                        pair[0],
                        pair[1] - pair[0],
                        len(visuals) - pair[1],
                    )
                    - min(
                        pair[0],
                        pair[1] - pair[0],
                        len(visuals) - pair[1],
                    ),
                    pair,
                ),
            )
            for first_page, second_page, third_page in page_orders:
                first_token = tuple(page_select_symbols(first_page))
                second_token = tuple(page_select_symbols(second_page))
                third_token = tuple(page_select_symbols(third_page))
                selected = transition(initial_context, first_token)
                if selected is None or selected[0] >= maximum_bits:
                    continue
                transition_to_second = {}
                transition_to_third = {}
                for previous in range(0x100):
                    encoded_second = transition(previous, second_token)
                    if encoded_second is not None:
                        transition_to_second[previous] = (
                            encoded_second[0],
                            second_token,
                        )
                    encoded_third = transition(previous, third_token)
                    if encoded_third is not None:
                        transition_to_third[previous] = (
                            encoded_third[0],
                            third_token,
                        )
                for first_split, second_split in split_pairs:
                    suffix = segment_path(
                        start_previous=third_token[-1],
                        glyph_count=len(visuals) - second_split,
                        bit_limit=maximum_bits - selected[0],
                        tail_by_previous=direct_end,
                    )
                    if suffix is None:
                        continue
                    suffix_symbols, suffix_assignments, suffix_bits = suffix
                    middle_limit = maximum_bits - selected[0] - suffix_bits
                    if middle_limit <= 0:
                        continue
                    middle = segment_path(
                        start_previous=second_token[-1],
                        glyph_count=second_split - first_split,
                        bit_limit=middle_limit,
                        tail_by_previous=transition_to_third,
                    )
                    if middle is None:
                        continue
                    middle_symbols, middle_assignments, middle_bits = middle
                    prefix_limit = middle_limit - middle_bits
                    if prefix_limit <= 0:
                        continue
                    prefix = segment_path(
                        start_previous=selected[1],
                        glyph_count=first_split,
                        bit_limit=prefix_limit,
                        tail_by_previous=transition_to_second,
                    )
                    if prefix is None:
                        continue
                    prefix_symbols, prefix_assignments, _ = prefix
                    symbols = (
                        first_token
                        + prefix_symbols
                        + middle_symbols
                        + suffix_symbols
                    )
                    if len(symbols) != target_symbol_count:
                        continue
                    assignments = (
                        prefix_assignments
                        + middle_assignments
                        + suffix_assignments
                    )
                    assignment_pages = (
                        (first_page,) * first_split
                        + (second_page,) * (second_split - first_split)
                        + (third_page,) * (len(visuals) - second_split)
                    )
                    return (
                        list(symbols),
                        0,
                        list(assignments),
                        list(assignment_pages),
                    )
            raise ValueError(
                "first context row has no three-page fixed-count route"
            )

        for first_page, second_page in (
            candidate_pages,
            tuple(reversed(candidate_pages)),
        ):
            first_token = tuple(page_select_symbols(first_page))
            second_token = tuple(page_select_symbols(second_page))
            selected = transition(initial_context, first_token)
            if selected is None or selected[0] >= maximum_bits:
                continue
            transition_to_second = {}
            for previous in range(0x100):
                encoded = transition(previous, second_token)
                if encoded is not None:
                    transition_to_second[previous] = (encoded[0], second_token)
            split_order = sorted(
                range(1, len(visuals)),
                key=lambda split: (abs(len(visuals) - 2 * split), split),
            )
            for split in split_order:
                suffix = segment_path(
                    start_previous=second_token[-1],
                    glyph_count=len(visuals) - split,
                    bit_limit=maximum_bits - selected[0],
                    tail_by_previous=direct_end,
                )
                if suffix is None:
                    continue
                suffix_symbols, suffix_assignments, suffix_bits = suffix
                prefix_limit = maximum_bits - selected[0] - suffix_bits
                if prefix_limit <= 0:
                    continue
                prefix = segment_path(
                    start_previous=selected[1],
                    glyph_count=split,
                    bit_limit=prefix_limit,
                    tail_by_previous=transition_to_second,
                )
                if prefix is None:
                    continue
                prefix_symbols, prefix_assignments, _ = prefix
                symbols = first_token + prefix_symbols + suffix_symbols
                if len(symbols) != target_symbol_count:
                    continue
                assignments = prefix_assignments + suffix_assignments
                assignment_pages = (
                    (first_page,) * split
                    + (second_page,) * (len(visuals) - split)
                )
                return (
                    list(symbols),
                    0,
                    list(assignments),
                    list(assignment_pages),
                )
        raise ValueError(
            "first context row has no two-page fixed-count route"
        )

    if required_page_tokens >= 3:
        raise ValueError(
            "first context row has no bounded multi-page fixed-count route"
        )

    symbols, padding_count, assignments, assignment_pages = (
        solve_bounded_length_row_multi_page_visual_symbols(
            trees=trees,
            initial_context=initial_context,
            maximum_bits=maximum_bits,
            pages=pages,
            visuals=visuals,
        )
    )
    try:
        padded, _, added_pages = pad_row_to_runtime_symbol_count(
            trees=trees,
            initial_context=initial_context,
            maximum_bits=maximum_bits,
            target_symbol_count=target_symbol_count,
            symbols=symbols,
        )
        return (
            padded,
            padding_count + added_pages,
            assignments,
            assignment_pages,
        )
    except ValueError:
        pass

    _, bounded_bits = encode_symbols(
        trees,
        symbols,
        initial_symbol=initial_context,
        end_symbol=CANDIDATE_END_SYMBOL,
        max_bits=maximum_bits,
    )
    first_exact_bits = max(1, bounded_bits - 16)
    for target_bits in range(first_exact_bits, maximum_bits + 1):
        try:
            (
                exact_symbols,
                exact_padding,
                exact_assignments,
                exact_pages,
            ) = solve_exact_length_row_multi_page_visual_symbols(
                trees=trees,
                initial_context=initial_context,
                target_bits=target_bits,
                pages=pages,
                visuals=visuals,
            )
        except ValueError:
            continue
        if len(exact_symbols) == target_symbol_count:
            return (
                exact_symbols,
                exact_padding,
                exact_assignments,
                exact_pages,
            )
    raise ValueError("first context row has no joint multi-page fixed-count route")


def diagnose_bounded_candidate_bit_count(
    *,
    trees: dict[int, object],
    initial_context: int,
    target_bits: int,
    pages: tuple[int, ...],
    visuals: list[str],
) -> int:
    """Return one safe aggregate route length without exposing its symbols.

    The exact solver can fail because every renderable route is shorter than,
    longer than, or merely bit-incongruent with the source record.  A bounded
    route length distinguishes those cases on the private runtime host while
    keeping text, symbols, page coordinates, and encoded bytes out of the
    published failure report.
    """

    if not pages:
        return 0
    limits = tuple(
        dict.fromkeys(
            (
                target_bits,
                min(0x7FFF, max(target_bits + 512, target_bits * 2)),
            )
        )
    )
    for maximum_bits in limits:
        for page in pages:
            try:
                symbols, _, _ = solve_bounded_length_row_visual_symbols(
                    trees=trees,
                    initial_context=initial_context,
                    maximum_bits=maximum_bits,
                    page=page,
                    visuals=visuals,
                )
                _, encoded_bits = encode_symbols(
                    trees,
                    symbols,
                    initial_symbol=initial_context,
                    end_symbol=CANDIDATE_END_SYMBOL,
                    max_bits=maximum_bits,
                )
            except (PatchError, ValueError):
                continue
            return encoded_bits
    return 0


def select_row_font_pages(
    *,
    trees: dict[int, object],
    target_rows: list[dict[str, object]],
    preserved_by_row: list[list[dict[str, int]]],
    runtime_constraints: list[dict[str, int]] | None = None,
) -> tuple[int | tuple[int, ...], ...]:
    visual_rows = build_row_visuals(
        target_rows=target_rows,
        preserved_by_row=preserved_by_row,
    )
    if runtime_constraints is not None and len(runtime_constraints) != len(
        visual_rows
    ):
        raise ValueError("first context runtime constraint count does not match")
    pages: list[int | tuple[int, ...]] = []
    used_pages: set[int] = set()
    constraints = runtime_constraints or [None] * len(visual_rows)
    fixed_lengths = _code_lengths(trees)
    fixed_glyph_symbols = tuple(
        range(FONT_GLYPH_FIRST_SYMBOL, FONT_GLYPH_LAST_SYMBOL + 1)
    )

    def fixed_transition(
        previous: int,
        sequence: tuple[int, ...],
    ) -> tuple[int, int] | None:
        bits = 0
        for symbol in sequence:
            edge = fixed_lengths.get(previous, {}).get(symbol)
            if edge is None:
                return None
            bits += edge
            previous = symbol
        return bits, previous

    @lru_cache(maxsize=None)
    def can_reach_terminator(previous: int, glyph_count: int) -> bool:
        if glyph_count == 0:
            return CANDIDATE_END_SYMBOL in fixed_lengths.get(previous, {})
        return any(
            can_reach_terminator(symbol, glyph_count - 1)
            for symbol in fixed_glyph_symbols
            if symbol in fixed_lengths.get(previous, {})
        )
    for row_index, (visuals, constraint) in enumerate(
        zip(visual_rows, constraints)
    ):
        preferred = (
            ROW_FONT_PAGES[row_index]
            if row_index < len(ROW_FONT_PAGES)
            else FONT_PAGE_COUNT - 1 - row_index
        )
        candidate_pages = tuple(
            dict.fromkeys(
                (preferred, 89, *range(FONT_PAGE_COUNT - 1, -1, -1))
            )
        )
        if constraint is not None and "original_symbol_count" in constraint:
            ranked_secondary = []
            for candidate_page in range(FONT_PAGE_COUNT):
                if candidate_page == preferred or candidate_page in used_pages:
                    continue
                token = tuple(page_select_symbols(candidate_page))
                incoming = sum(
                    fixed_transition(previous, token) is not None
                    for previous in fixed_glyph_symbols
                )
                suffix_depths = sum(
                    can_reach_terminator(token[-1], remaining)
                    for remaining in range(1, len(visuals))
                )
                if not incoming or not suffix_depths:
                    continue
                ranked_secondary.append(
                    (
                        -suffix_depths,
                        -incoming,
                        abs(candidate_page - preferred),
                        candidate_page,
                    )
                )
            candidate_pages = tuple(
                dict.fromkeys(
                    (
                        preferred,
                        *(item[-1] for item in sorted(ranked_secondary)),
                    )
                )
            )
        if constraint is not None:
            if "original_symbol_count" in constraint:
                candidate_pages = tuple(
                    page for page in candidate_pages if page not in used_pages
                )[:4]
            else:
                candidate_pages = candidate_pages[
                    :MAX_EXACT_FONT_PAGE_CANDIDATES
                ]
        failed_pages: list[int] = []
        for page in candidate_pages:
            if page in used_pages:
                continue
            try:
                if constraint is None:
                    solve_row_visual_symbols(
                        trees=trees,
                        page=page,
                        visuals=visuals,
                    )
                else:
                    if "original_symbol_count" in constraint:
                        fixed_control_symbols = (
                            int(constraint["original_symbol_count"])
                            - len(visuals)
                            - 1
                        )
                        fixed_page_token_count = (
                            fixed_control_symbols // 3
                            if fixed_control_symbols >= 0
                            and fixed_control_symbols % 3 == 0
                            else -1
                        )
                        if fixed_page_token_count == 3:
                            raise ValueError(
                                "compact row prefers direct three-page route"
                            )
                        solve_fixed_count_row_visual_symbols(
                            trees=trees,
                            initial_context=int(constraint["initial_context"]),
                            maximum_bits=(
                                int(constraint["original_record_length_bytes"])
                                * 8
                            ),
                            target_symbol_count=int(
                                constraint["original_symbol_count"]
                            ),
                            page=page,
                            visuals=visuals,
                        )
                    else:
                        solve_bounded_length_row_visual_symbols(
                            trees=trees,
                            initial_context=int(constraint["initial_context"]),
                            maximum_bits=(
                                int(constraint["original_record_length_bytes"])
                                * 8
                            ),
                            page=page,
                            visuals=visuals,
                        )
            except ValueError:
                if constraint is not None:
                    if "original_symbol_count" in constraint:
                        required_page_tokens = (
                            int(constraint["original_symbol_count"])
                            - len(visuals)
                            - 1
                        )
                        required_page_tokens = (
                            required_page_tokens // 3
                            if required_page_tokens >= 0
                            and required_page_tokens % 3 == 0
                            else -1
                        )
                        if required_page_tokens == 3:
                            candidate_groups = (
                                [(failed_pages[0], failed_pages[1], page)]
                                if len(failed_pages) >= 2
                                else []
                            )
                        else:
                            candidate_groups = (
                                [(failed_pages[0], page)]
                                if failed_pages
                                else []
                            )
                    else:
                        candidate_groups = [
                            (anchor, page) for anchor in failed_pages[:4]
                        ]
                        expanded_pool = tuple((*failed_pages, page))
                        if len(expanded_pool) in {4, 8}:
                            candidate_groups.append(expanded_pool)
                    for page_group in candidate_groups:
                        try:
                            if "original_symbol_count" in constraint:
                                solve_fixed_count_row_multi_page_visual_symbols(
                                    trees=trees,
                                    initial_context=int(
                                        constraint["initial_context"]
                                    ),
                                    maximum_bits=(
                                        int(
                                            constraint[
                                                "original_record_length_bytes"
                                            ]
                                        )
                                        * 8
                                    ),
                                    target_symbol_count=int(
                                        constraint["original_symbol_count"]
                                    ),
                                    pages=page_group,
                                    visuals=visuals,
                                )
                            else:
                                solve_bounded_length_row_multi_page_visual_symbols(
                                    trees=trees,
                                    initial_context=int(
                                        constraint["initial_context"]
                                    ),
                                    maximum_bits=(
                                        int(
                                            constraint[
                                                "original_record_length_bytes"
                                            ]
                                        )
                                        * 8
                                    ),
                                    pages=page_group,
                                    visuals=visuals,
                                )
                        except ValueError:
                            continue
                        pages.append(page_group)
                        used_pages.update(page_group)
                        break
                    else:
                        if len(failed_pages) < 8:
                            failed_pages.append(page)
                        continue
                    break
                continue
            pages.append(page)
            used_pages.add(page)
            break
        else:
            target_bits = (
                int(constraint["original_record_length_bytes"]) * 8
                if constraint is not None
                else 0
            )
            fixed_page_token_count = (
                (
                    int(constraint["original_symbol_count"])
                    - len(visuals)
                    - 1
                )
                // 3
                if constraint is not None
                and "original_symbol_count" in constraint
                and (
                    int(constraint["original_symbol_count"])
                    - len(visuals)
                    - 1
                )
                >= 0
                and (
                    int(constraint["original_symbol_count"])
                    - len(visuals)
                    - 1
                )
                % 3
                == 0
                else -1
            )
            candidate_bits = (
                diagnose_bounded_candidate_bit_count(
                    trees=trees,
                    initial_context=int(constraint["initial_context"]),
                    target_bits=target_bits,
                    pages=tuple(failed_pages),
                    visuals=visuals,
                )
                if constraint is not None and fixed_page_token_count < 3
                else 0
            )
            raise RowRouteError(
                len(visuals),
                0,
                target_bits=target_bits,
                candidate_bits=candidate_bits,
            )
    return tuple(pages)


def build_single_page_symbol_rows(
    *,
    trees: dict[int, object],
    target_rows: list[dict[str, object]],
    preserved_by_row: list[list[dict[str, int]]],
    runtime_constraints: list[dict[str, int]] | None = None,
    pages: tuple[int | tuple[int, ...], ...] = ROW_FONT_PAGES,
) -> tuple[
    dict[str, int],
    list[dict[str, object]],
    list[list[dict[str, object]]],
]:
    global ACTIVE_FAILURE_ROW_INDEX, ACTIVE_FAILURE_DETAIL
    visual_rows = build_row_visuals(
        target_rows=target_rows,
        preserved_by_row=preserved_by_row,
    )
    if len(visual_rows) != len(pages):
        raise ValueError("first context row font page count does not match")
    if runtime_constraints is not None and len(runtime_constraints) != len(
        visual_rows
    ):
        raise ValueError("first context runtime constraint count does not match")
    rows = []
    assignments_by_row = []
    constraints = runtime_constraints or [None] * len(visual_rows)
    for expected_index, (target_row, visuals, page_spec, constraint) in enumerate(
        zip(target_rows, visual_rows, pages, constraints),
        start=1,
    ):
        ACTIVE_FAILURE_ROW_INDEX = expected_index
        row_pages = (page_spec,) if isinstance(page_spec, int) else page_spec
        if (
            not row_pages
            or len(row_pages) != len(set(row_pages))
            or any(not 0 <= page < FONT_PAGE_COUNT for page in row_pages)
        ):
            raise ValueError("first context row font page group is invalid")
        if constraint is None:
            if len(row_pages) != 1:
                raise ValueError(
                    "unconstrained first context row requires one font page"
                )
            page = row_pages[0]
            ACTIVE_FAILURE_DETAIL = "solve-unconstrained-row"
            assignments = solve_row_visual_symbols(
                trees=trees,
                page=page,
                visuals=visuals,
            )
            symbols = page_select_symbols(page)
            symbols.extend(assignments)
            symbols.append(CANDIDATE_END_SYMBOL)
            padding_count = 0
            initial_context = CANDIDATE_END_SYMBOL
            target_bits = 0
            storage_capacity_bits = 0
            route_capacity_bits = 0
            assignment_pages = [page] * len(assignments)
        else:
            initial_context = int(constraint["initial_context"])
            target_bits = int(constraint["original_record_length_bytes"]) * 8
            storage_capacity_bits = (
                int(constraint["original_record_length_bytes"]) * 8
            )
            route_capacity_bits = target_bits
            ACTIVE_FAILURE_DETAIL = (
                "solve-proven-bounded-row"
                if expected_index <= len(PROVEN_ROW_FONT_PAGES)
                else "solve-extra-single-page-row"
            )
            if len(row_pages) == 1:
                page = row_pages[0]
                try:
                    if "original_symbol_count" in constraint:
                        (
                            symbols,
                            padding_count,
                            assignments,
                        ) = solve_fixed_count_row_visual_symbols(
                            trees=trees,
                            initial_context=initial_context,
                            maximum_bits=target_bits,
                            target_symbol_count=int(
                                constraint["original_symbol_count"]
                            ),
                            page=page,
                            visuals=visuals,
                        )
                    else:
                        (
                            symbols,
                            padding_count,
                            assignments,
                        ) = solve_bounded_length_row_visual_symbols(
                            trees=trees,
                            initial_context=initial_context,
                            maximum_bits=target_bits,
                            page=page,
                            visuals=visuals,
                        )
                except ValueError:
                    ACTIVE_FAILURE_DETAIL = (
                        "solve-proven-bounded-row"
                        if expected_index <= len(PROVEN_ROW_FONT_PAGES)
                        else "solve-extra-single-page-row"
                    )
                    candidate_bits = diagnose_bounded_candidate_bit_count(
                        trees=trees,
                        initial_context=initial_context,
                        target_bits=target_bits,
                        pages=(page,),
                        visuals=visuals,
                    )
                    raise RowRouteError(
                        required=len(visuals),
                        maximum=len(visuals) if candidate_bits else 0,
                        target_bits=target_bits,
                        candidate_bits=candidate_bits,
                    )
                assignment_pages = [page] * len(assignments)
            else:
                ACTIVE_FAILURE_DETAIL = "solve-bounded-multi-page-row"
                try:
                    if "original_symbol_count" in constraint:
                        (
                            symbols,
                            padding_count,
                            assignments,
                            assignment_pages,
                        ) = solve_fixed_count_row_multi_page_visual_symbols(
                            trees=trees,
                            initial_context=initial_context,
                            maximum_bits=target_bits,
                            target_symbol_count=int(
                                constraint["original_symbol_count"]
                            ),
                            pages=row_pages,
                            visuals=visuals,
                        )
                    else:
                        (
                            symbols,
                            padding_count,
                            assignments,
                            assignment_pages,
                        ) = solve_bounded_length_row_multi_page_visual_symbols(
                            trees=trees,
                            initial_context=initial_context,
                            maximum_bits=target_bits,
                            pages=row_pages,
                            visuals=visuals,
                        )
                except ValueError:
                    ACTIVE_FAILURE_DETAIL = (
                        "solve-proven-multi-page-row"
                        if expected_index <= len(PROVEN_ROW_FONT_PAGES)
                        else "solve-extra-multi-page-row"
                    )
                    candidate_bits = diagnose_bounded_candidate_bit_count(
                        trees=trees,
                        initial_context=initial_context,
                        target_bits=target_bits,
                        pages=tuple(row_pages),
                        visuals=visuals,
                    )
                    raise RowRouteError(
                        required=len(visuals),
                        maximum=len(visuals) if candidate_bits else 0,
                        target_bits=target_bits,
                        candidate_bits=candidate_bits,
                    )
            runtime_symbol_count = int(
                constraint.get("original_symbol_count", len(symbols))
            )
            visible_page_select_count = 0
            selected_page: int | None = None
            for assignment_page in assignment_pages:
                if assignment_page != selected_page:
                    visible_page_select_count += 1
                    selected_page = assignment_page
            fixed_count_padding_symbol_count = max(
                0,
                len(symbols)
                - len(visuals)
                - 1
                - visible_page_select_count * 3,
            )
        if constraint is None:
            runtime_symbol_count = len(symbols)
            fixed_count_padding_symbol_count = 0
        ACTIVE_FAILURE_DETAIL = "validate-row-assignments"
        if (
            len(assignments) != len(visuals)
            or len(assignment_pages) != len(visuals)
        ):
            raise ValueError("first context visual assignment count disagrees")
        rows.append(
            {
                "review_index": expected_index,
                "target_text": target_row["target_text"],
                "visuals": visuals,
                "symbols": symbols,
                "page_select_count": 1 + padding_count,
                "page_select_padding_count": padding_count,
                "initial_context": initial_context,
                "target_encoded_bits": target_bits,
                "storage_capacity_bits": storage_capacity_bits,
                "route_capacity_bits": route_capacity_bits,
                "visible_symbol_count": len(visuals),
                "runtime_symbol_count": runtime_symbol_count,
                "fixed_count_padding_symbol_count": (
                    fixed_count_padding_symbol_count
                ),
                "preserved_non_text_glyph_count": sum(
                    visual.startswith("preserved:") for visual in visuals
                ),
            }
        )
        assignments_by_row.append(
            [
                {"visual": visual, "page": assignment_page, "symbol": symbol}
                for visual, assignment_page, symbol in zip(
                    visuals, assignment_pages, assignments
                )
            ]
        )
    visible_count = sum(len(visuals) for visuals in visual_rows)
    preserved_count = sum(
        visual.startswith("preserved:")
        for visuals in visual_rows
        for visual in visuals
    )
    return {
        "planned_visible_symbol_count": visible_count,
        "planned_page_select_count": sum(
            int(row["page_select_count"]) for row in rows
        ),
        "preserved_non_text_glyph_occurrence_count": preserved_count,
        "planned_terminator_count": len(rows),
        "planned_total_symbol_count": sum(len(row["symbols"]) for row in rows),
        "fixed_count_padding_symbol_count": sum(
            int(row["fixed_count_padding_symbol_count"]) for row in rows
        ),
        "exact_runtime_symbol_count_entry_count": sum(
            len(row["symbols"]) == int(row["runtime_symbol_count"])
            for row in rows
        ),
        "page_select_padding_count": sum(
            int(row["page_select_padding_count"]) for row in rows
        ),
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
        and encoding["fixed_count_roundtrip_entry_count"]
        == encoding["context_entry_count"]
        and encoding["exact_runtime_symbol_count_entry_count"]
        == encoding["context_entry_count"]
        and encoding["preserved_non_text_glyph_occurrence_count"] > 0
        and encoding["custom_font_page_count"]
        >= encoding["context_entry_count"]
        and encoding["font_page_changed_byte_count"] > 0
        and encoding["runtime_initial_context_entry_count"]
        == encoding["context_entry_count"]
        and encoding["runtime_initial_context_distinct_count"] > 0
        and encoding["in_place_storage_fit_entry_count"]
        == encoding["context_entry_count"]
        and encoding["group_storage_fit_entry_count"]
        == encoding["context_entry_count"]
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
        and counts["fixed_count_roundtrip_entry_count"]
        == counts["context_entry_count"]
        and counts["exact_runtime_symbol_count_entry_count"]
        == counts["context_entry_count"]
        and counts["preserved_non_text_glyph_occurrence_count"] > 0
        and counts["custom_font_page_count"] >= counts["context_entry_count"]
        and counts["font_page_changed_byte_count"] > 0
        and counts["runtime_initial_context_entry_count"]
        == counts["context_entry_count"]
        and counts["runtime_initial_context_distinct_count"] > 0
        and counts["in_place_storage_fit_entry_count"]
        == counts["context_entry_count"]
        and counts["group_storage_fit_entry_count"]
        == counts["context_entry_count"]
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


def _main() -> int:
    global ACTIVE_FAILURE_CATEGORY, ACTIVE_FAILURE_STEP
    global ACTIVE_FAILURE_ROW_INDEX, ACTIVE_FAILURE_DETAIL
    global ACTIVE_LAYOUT_APPROVED_COUNT, ACTIVE_LAYOUT_COMPACT_COUNT
    global ACTIVE_LAYOUT_RUNTIME_COUNT, ACTIVE_LAYOUT_CONTROL_COUNT
    ACTIVE_FAILURE_CATEGORY = "input"
    ACTIVE_FAILURE_STEP = "input"
    ACTIVE_FAILURE_ROW_INDEX = 0
    ACTIVE_FAILURE_DETAIL = "none"
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
        "visible_entry_proof": root / VISIBLE_ENTRY_PROOF_PATH,
        "patch": root / PATCH_PATH,
        "bdf": root / LOCAL_BDF_PATH,
        "target": root / TARGET_PATH,
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
    visible_entry_proof = _load_json_object(paths["visible_entry_proof"])
    validate_first_context_translation_capacity(capacity)
    validate_first_context_translation_approval(approval)
    validate_local_first_context_translation_approval(local_approval)
    validate_runtime_context_glyph_preservation(preservation)
    validate_visible_entry_proof(visible_entry_proof)
    ACTIVE_FAILURE_CATEGORY = "identity"
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
        or visible_entry_proof.get("baseline_target_sha256")
        != capacity["target_sha256"]
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

    approved_target_rows = target_rows
    ACTIVE_FAILURE_CATEGORY = "font-input"
    patch = paths["patch"].read_bytes()
    bdf = paths["bdf"].read_bytes()
    target = paths["target"].read_bytes()
    if sha256_bytes(target) != capacity["target_sha256"]:
        raise ValueError("first context translation target identity disagrees")
    analyze_patch(patch)
    sparse = extract_bps_target_literals(patch)
    reference_glyphs = parse_bdf_glyphs(bdf)
    ACTIVE_FAILURE_CATEGORY = "input"
    ACTIVE_FAILURE_STEP = "locate-preserved-occurrences"
    preserved_by_row = locate_preserved_occurrences(
        context_rows=context_rows,
        projection_pairs=projection_pairs,
        preservation_records=preservation_records,
        target_rows=approved_target_rows,
    )
    # The reviewed source glyphs are evidence about the original script, not
    # target-language punctuation to append.  Runtime review showed them as
    # visible garbage after otherwise correct Korean.  The approved Korean
    # target already carries its own punctuation and digits, so retain the
    # source occurrences in the private audit while rendering target text only.
    rendered_preserved_by_row = [[] for _ in preserved_by_row]
    ACTIVE_FAILURE_STEP = "load-runtime-trees"
    trees = load_trees_at(
        sparse.data,
        sparse.known,
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )
    ACTIVE_FAILURE_STEP = "build-runtime-codec-constraints"
    runtime_records = resolve_runtime_records_from_visible_anchor(
        target=target,
        runtime_entry=visible_entry_proof["runtime_entry"],
        row_count=1,
    )
    runtime_constraints = build_runtime_codec_constraints(
        target=target,
        trees=trees,
        context_rows=context_rows,
        projection_pairs=projection_pairs,
        runtime_records=runtime_records,
    )
    ACTIVE_FAILURE_STEP = "build-runtime-layout-rows"
    target_rows, layout_compactions = build_runtime_layout_rows(
        target_rows=approved_target_rows,
        runtime_constraints=runtime_constraints,
    )
    ACTIVE_FAILURE_ROW_INDEX = 0
    ACTIVE_FAILURE_DETAIL = "none"
    ACTIVE_LAYOUT_APPROVED_COUNT = 0
    ACTIVE_LAYOUT_COMPACT_COUNT = 0
    ACTIVE_LAYOUT_RUNTIME_COUNT = 0
    ACTIVE_LAYOUT_CONTROL_COUNT = 0
    ACTIVE_FAILURE_STEP = "build-character-assignments"
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
    ACTIVE_FAILURE_CATEGORY = "row-route"
    ACTIVE_FAILURE_STEP = "select-row-font-pages"
    selected_row_font_pages = select_row_font_pages(
        trees=trees,
        target_rows=target_rows,
        preserved_by_row=rendered_preserved_by_row,
        runtime_constraints=runtime_constraints,
    )
    ACTIVE_FAILURE_STEP = "build-symbol-rows"
    (
        symbol_counts,
        symbol_rows,
        assignments_by_row,
    ) = build_single_page_symbol_rows(
        trees=trees,
        target_rows=target_rows,
        preserved_by_row=rendered_preserved_by_row,
        runtime_constraints=runtime_constraints,
        pages=selected_row_font_pages,
    )
    symbol_counts["preserved_non_text_glyph_occurrence_count"] = sum(
        len(row) for row in preserved_by_row
    )
    custom_pages = {
        int(assignment["page"])
        for assignments in assignments_by_row
        for assignment in assignments
    }
    ACTIVE_FAILURE_CATEGORY = "font-input"
    ACTIVE_FAILURE_STEP = "build-font-overlay"
    writes = []
    all_assignments = []
    for row_index, assignments in enumerate(assignments_by_row, start=1):
        for assignment in assignments:
            visual = assignment["visual"]
            page = assignment["page"]
            symbol = assignment["symbol"]
            assert isinstance(visual, str)
            assert isinstance(page, int)
            assert isinstance(symbol, int)
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
            before = sparse.data[start:end]
            if before != after:
                writes.append(
                    ExpectedWrite(
                        writer=(
                            f"first-context-row-{row_index}-font-"
                            f"{page:02x}-{symbol:02x}"
                        ),
                        purpose="first-context-technical-test-only",
                        offset=start,
                        before=before,
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
    ACTIVE_FAILURE_CATEGORY = "font-overlay"
    _, font_audit = apply_expected_writes(sparse.data, writes)
    font_overlay = expected_writes_to_ips(writes)
    overlay_path = root / LOCAL_COMBINED_FONT_OVERLAY_PATH
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    overlay_path.write_bytes(font_overlay)

    ACTIVE_FAILURE_CATEGORY = "row-route"
    ACTIVE_FAILURE_STEP = "encode-symbol-rows"
    roundtrips = 0
    failures = 0
    encoded_bits = 0
    encoded_bytes = 0
    maximum_bits = 0
    initial_page_failures = 0
    later_failures = 0
    exact_length_entries = 0
    exact_runtime_symbol_count_entries = 0
    fixed_count_roundtrips = 0
    in_place_storage_fits = 0
    runtime_initial_contexts: set[int] = set()
    for row in symbol_rows:
        symbols = row["symbols"]
        assert isinstance(symbols, list)
        initial_context = int(row["initial_context"])
        target_bits = int(row["target_encoded_bits"])
        storage_capacity_bits = int(row["storage_capacity_bits"])
        route_capacity_bits = int(row["route_capacity_bits"])
        runtime_symbol_count = int(row["runtime_symbol_count"])
        runtime_initial_contexts.add(initial_context)
        try:
            encoded, bits = encode_symbol_count(
                trees,
                symbols,
                initial_symbol=initial_context,
                max_bits=route_capacity_bits,
            )
            decoded, decoded_bits = decode_symbol_count(
                encoded,
                bytes((1,)) * len(encoded),
                trees,
                0,
                runtime_symbol_count,
                initial_symbol=initial_context,
                max_bytes=len(encoded),
            )
            if (
                decoded != symbols
                or decoded_bits != bits
                or bits > route_capacity_bits
                or len(symbols) != runtime_symbol_count
                or symbols[-1] != CANDIDATE_END_SYMBOL
            ):
                raise PatchError(
                    "first context fixed-count Huffman roundtrip disagrees"
                )
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
        fixed_count_roundtrips += 1
        exact_runtime_symbol_count_entries += int(
            len(symbols) == runtime_symbol_count
        )
        exact_length_entries += int(bits == target_bits)
        in_place_storage_fits += int(
            len(encoded) <= storage_capacity_bits // 8
        )
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
        "fixed_count_roundtrip_entry_count": fixed_count_roundtrips,
        "exact_runtime_symbol_count_entry_count": (
            exact_runtime_symbol_count_entries
        ),
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
        "runtime_initial_context_entry_count": len(symbol_rows),
        "runtime_initial_context_distinct_count": len(
            runtime_initial_contexts
        ),
        "exact_encoded_length_entry_count": exact_length_entries,
        "in_place_storage_fit_entry_count": in_place_storage_fits,
        "group_storage_capacity_bit_count": sum(
            int(row["storage_capacity_bits"]) for row in symbol_rows
        ),
        "group_storage_fit_entry_count": (
            len(symbol_rows)
            if encoded_bytes
            <= sum(int(row["storage_capacity_bits"]) for row in symbol_rows)
            // 8
            else 0
        ),
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
        "layout_compactions": layout_compactions,
        "preserved_by_row": preserved_by_row,
        "rendered_preserved_non_text_glyph_occurrence_count": 0,
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
    ACTIVE_FAILURE_CATEGORY = "validation"
    ACTIVE_FAILURE_STEP = "validate-safe-result"
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


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    failure_path = root / FAILURE_PUBLISH_RELATIVE_PATH
    try:
        result = _main()
    except (
        AssertionError,
        IndexError,
        KeyError,
        PatchError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as error:
        captured_utc = datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
        category = classify_encoding_failure(error)
        if category == "unexpected":
            category = ACTIVE_FAILURE_CATEGORY
        required_visible_symbol_count = 0
        maximum_routable_visible_symbol_count = 0
        target_encoded_bit_count = 0
        bounded_candidate_bit_count = 0
        if isinstance(error, RowRouteError):
            required_visible_symbol_count = error.required
            maximum_routable_visible_symbol_count = error.maximum
            target_encoded_bit_count = error.target_bits
            bounded_candidate_bit_count = error.candidate_bits
        failure = build_first_context_translation_encoding_failure(
            category=category,
            captured_utc=captured_utc,
            required_visible_symbol_count=required_visible_symbol_count,
            maximum_routable_visible_symbol_count=
                maximum_routable_visible_symbol_count,
            target_encoded_bit_count=target_encoded_bit_count,
            bounded_candidate_bit_count=bounded_candidate_bit_count,
            failure_step=ACTIVE_FAILURE_STEP,
            failure_kind=type(error).__name__,
            failure_row_index=ACTIVE_FAILURE_ROW_INDEX,
            failure_detail=ACTIVE_FAILURE_DETAIL,
            approved_visible_symbol_count=ACTIVE_LAYOUT_APPROVED_COUNT,
            compact_visible_symbol_count=ACTIVE_LAYOUT_COMPACT_COUNT,
            runtime_symbol_count=ACTIVE_LAYOUT_RUNTIME_COUNT,
            layout_control_symbol_count=ACTIVE_LAYOUT_CONTROL_COUNT,
        )
        failure_path.parent.mkdir(parents=True, exist_ok=True)
        failure_path.write_text(
            json.dumps(failure, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(
            "SFKR first context translation encoding failed safely: "
            f"{category}"
        )
        return 1
    if failure_path.is_file():
        failure_path.unlink()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
