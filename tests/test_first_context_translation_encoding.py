from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_first_context_translation_encoding import (  # noqa: E402
    ROW_FONT_PAGES,
    build_character_assignments,
    build_first_context_translation_encoding,
    build_first_context_translation_encoding_failure,
    build_runtime_codec_constraints,
    build_row_visuals,
    build_symbol_rows,
    exact_length_row_symbols,
    select_row_font_pages,
    solve_row_visual_symbols,
    validate_first_context_translation_encoding,
    validate_first_context_translation_encoding_failure,
)
from tools.sfgfc_huffman import HuffmanNode, ParsedTree  # noqa: E402


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
STAMP = "2026-07-31T10:00:00Z"


def tree(previous: int, left: int, right: int) -> ParsedTree:
    return ParsedTree(
        previous_symbol=previous,
        pointer=0,
        structure_offset=0,
        structure_bits=3,
        leaf_count=2,
        symbol_offset=0,
        root=HuffmanNode(
            left=HuffmanNode(symbol=left),
            right=HuffmanNode(symbol=right),
        ),
    )


class FirstContextTranslationEncodingTests(unittest.TestCase):
    def test_keeps_proven_four_row_pages_before_the_fifth_page(self) -> None:
        self.assertEqual(ROW_FONT_PAGES, (240, 241, 242, 243, 239))

    def test_searches_past_an_unusable_extra_row_page(self) -> None:
        targets = [{"target_text": "가"} for _ in range(5)]
        constraints = [
            {"initial_context": 0xC9, "original_encoded_bits": 8}
            for _ in range(5)
        ]

        def solve(*, trees, page, visuals):
            del trees
            if page == 239:
                raise ValueError("unusable route")
            return [0x02] * len(visuals)

        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_row_visual_symbols",
            side_effect=solve,
        ), patch(
            "tools.v5_1_first_context_translation_encoding."
            "exact_length_row_symbols",
            return_value=([0x02], 0),
        ):
            pages = select_row_font_pages(
                trees={},
                target_rows=targets,
                preserved_by_row=[[] for _ in targets],
                runtime_constraints=constraints,
            )

        self.assertEqual(pages, (240, 241, 242, 243, 238))

    def test_adds_invisible_page_select_padding_to_exact_bit_length(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x02, 0x11),
            0x11: tree(0x11, 0x02, 0x11),
            0x02: ParsedTree(
                previous_symbol=0x02,
                pointer=0,
                structure_offset=0,
                structure_bits=5,
                leaf_count=3,
                symbol_offset=0,
                root=HuffmanNode(
                    left=HuffmanNode(symbol=0x02),
                    right=HuffmanNode(
                        left=HuffmanNode(symbol=0x5F),
                        right=HuffmanNode(symbol=0x03),
                    ),
                ),
            ),
            0x03: tree(0x03, 0xC9, 0x03),
        }
        symbols, padding_count = exact_length_row_symbols(
            trees=trees,
            initial_context=0xC9,
            target_bits=10,
            page=240,
            assignments=[0x03],
        )
        self.assertEqual(padding_count, 1)
        self.assertEqual(symbols[:3], [0x5F, 0x02, 0x02])
        self.assertEqual(symbols[-1], 0xC9)

    def test_builds_two_page_symbols_and_preserves_insertions(self) -> None:
        targets = [
            {"review_index": 1, "target_text": "가!"},
            {"review_index": 2, "target_text": "나?"},
            {"review_index": 3, "target_text": "다 3"},
            {"review_index": 4, "target_text": "라!"},
        ]
        hangul = [
            {
                "character": character,
                "page": 243,
                "symbol": 2 + index,
                "ink_mask": [index + 1] * 8,
            }
            for index, character in enumerate("가나다라")
        ]
        references = {
            ord(character): tuple([index + 8] * 8)
            for index, character in enumerate(" !?3")
        }
        coordinates, assignments = build_character_assignments(
            target_rows=targets,
            hangul_assignments=hangul,
            reference_glyphs=references,
        )
        self.assertEqual(len({item["page"] for item in assignments}), 2)
        counts, rows = build_symbol_rows(
            target_rows=targets,
            character_coordinates=coordinates,
            preserved_by_row=[
                [{"target_character_index": 1, "page": 10, "symbol": 4}],
                [{"target_character_index": 0, "page": 11, "symbol": 5}],
                [{"target_character_index": 2, "page": 12, "symbol": 6}],
                [
                    {"target_character_index": 0, "page": 13, "symbol": 7},
                    {"target_character_index": 2, "page": 14, "symbol": 8},
                ],
            ],
        )
        self.assertEqual(
            counts["preserved_non_text_glyph_occurrence_count"], 5
        )
        self.assertEqual(counts["planned_terminator_count"], 4)
        self.assertTrue(all(row["symbols"][-1] == 0xC9 for row in rows))

    def test_assigns_one_encodable_font_page_to_a_visual_row(self) -> None:
        visuals = build_row_visuals(
            target_rows=[{"target_text": "가나"}],
            preserved_by_row=[[]],
        )
        self.assertEqual(visuals, [["text:가", "text:나"]])
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: tree(0x11, 0x02, 0x11),
            0x02: tree(0x02, 0x03, 0x04),
            0x03: tree(0x03, 0x04, 0xC9),
            0x04: tree(0x04, 0xC9, 0x03),
        }
        assignments = solve_row_visual_symbols(
            trees=trees,
            page=240,
            visuals=visuals[0],
        )
        self.assertEqual(assignments, [0x03, 0x04])

        symbols, padding_count = exact_length_row_symbols(
            trees=trees,
            initial_context=0xC9,
            target_bits=6,
            page=240,
            assignments=assignments,
        )
        self.assertEqual(symbols, [0x5F, 0x11, 0x02, 0x03, 0x04, 0xC9])
        self.assertEqual(padding_count, 0)

        constraints = build_runtime_codec_constraints(
            target=b"\x01\x00",
            trees=trees,
            context_rows=[
                {
                    "mapping_status": "unique",
                    "source_section_index": 1,
                    "source_line_index": 2,
                    "observation": {"initial_context": 0xC9},
                }
            ],
            projection_pairs=[
                {
                    "source_section_index": 1,
                    "source_line_index": 2,
                    "target_record": {
                        "length_offset": 0,
                        "record_length_bytes": 1,
                    },
                }
            ],
        )
        self.assertEqual(constraints[0]["original_encoded_bits"], 6)

    def test_builds_safe_ready_receipt_without_local_payload(self) -> None:
        counts = {
            "context_entry_count": 5,
            "target_character_count": 61,
            "unique_target_character_count": 40,
            "custom_font_page_count": 5,
            "custom_font_glyph_count": 67,
            "preserved_non_text_glyph_occurrence_count": 6,
            "planned_visible_symbol_count": 67,
            "planned_page_select_count": 10,
            "planned_terminator_count": 5,
            "planned_total_symbol_count": 102,
            "huffman_roundtrip_entry_count": 5,
            "huffman_failure_entry_count": 0,
            "encoded_bit_count": 300,
            "encoded_byte_count": 40,
            "maximum_encoded_entry_bit_count": 90,
            "font_page_write_byte_count": 320,
            "font_page_changed_byte_count": 200,
            "internally_encodable_font_page_count": 20,
            "initially_selectable_font_page_count": 20,
            "glyph_transition_edge_count": 200,
            "glyph_symbol_page_select_exit_count": 10,
            "glyph_symbol_terminator_exit_count": 8,
            "initial_page_token_failure_entry_count": 0,
            "post_initial_page_token_failure_entry_count": 0,
            "runtime_initial_context_entry_count": 5,
            "runtime_initial_context_distinct_count": 1,
            "exact_encoded_length_entry_count": 5,
            "page_select_padding_count": 8,
        }
        safe = build_first_context_translation_encoding(
            target_sha256=SHA_A,
            review_batch_sha256=SHA_B,
            first_context_translation_capacity_sha256=SHA_C,
            runtime_context_glyph_preservation_sha256=SHA_D,
            local_encoding_sha256=SHA_A,
            combined_font_overlay_sha256=SHA_B,
            encoding=counts,
            captured_utc=STAMP,
        )
        self.assertEqual(
            safe["status"], "first-context-translation-encoding-ready"
        )
        self.assertTrue(safe["text_encoding_confirmed"])
        self.assertTrue(safe["reviewed_non_text_glyph_visuals_preserved"])
        self.assertFalse(safe["original_non_text_glyph_coordinates_reused"])
        self.assertFalse(safe["translation_build_eligible"])
        unsafe = deepcopy(safe)
        unsafe["encoded_bytes"] = "private"
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_first_context_translation_encoding(unsafe)

    def test_builds_sanitized_failure_category(self) -> None:
        failure = build_first_context_translation_encoding_failure(
            category="row-route",
            captured_utc=STAMP,
        )
        self.assertEqual(failure["category"], "row-route")
        self.assertNotIn("error", failure)
        unsafe = deepcopy(failure)
        unsafe["category"] = "private-detail"
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            validate_first_context_translation_encoding_failure(unsafe)
