from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_first_context_translation_encoding import (  # noqa: E402
    MAX_EXACT_FONT_PAGE_CANDIDATES,
    RowRouteError,
    ROW_FONT_PAGES,
    bounded_length_row_symbols,
    build_character_assignments,
    build_first_context_translation_encoding,
    build_first_context_translation_encoding_failure,
    build_runtime_codec_constraints,
    build_row_visuals,
    build_single_page_symbol_rows,
    build_symbol_rows,
    diagnose_bounded_candidate_bit_count,
    exact_multi_page_state_limit,
    exact_length_row_symbols,
    select_row_font_pages,
    solve_bounded_length_row_visual_symbols,
    solve_bounded_length_row_multi_page_visual_symbols,
    solve_exact_length_row_multi_page_visual_symbols,
    solve_exact_length_row_visual_symbols,
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
        self.assertEqual(MAX_EXACT_FONT_PAGE_CANDIDATES, 8)

    def test_builds_a_proven_row_with_the_joint_exact_solver(self) -> None:
        target = [{"review_index": 1, "target_text": "가"}]
        constraints = [{
            "initial_context": 0xC9,
            "original_encoded_bits": 8,
            "original_record_length_bytes": 1,
        }]
        with (
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_row_visual_symbols",
                side_effect=AssertionError("must not pre-solve a proven row"),
            ),
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_exact_length_row_visual_symbols",
                return_value=([0x5F, 0x11, 0x02, 0x03, 0xC9], 0, [0x03]),
            ) as exact_solver,
        ):
            _, rows, assignments = build_single_page_symbol_rows(
                trees={},
                target_rows=target,
                preserved_by_row=[[]],
                runtime_constraints=constraints,
                pages=(240,),
            )

        exact_solver.assert_called_once()
        self.assertEqual(rows[0]["symbols"], [0x5F, 0x11, 0x02, 0x03, 0xC9])
        self.assertEqual(assignments[0], [
            {"visual": "text:가", "page": 240, "symbol": 0x03}
        ])

    def test_rejects_a_nonexact_runtime_row(self) -> None:
        target = [{"review_index": 1, "target_text": "가"}]
        constraints = [{
            "initial_context": 0xC9,
            "original_encoded_bits": 4,
            "original_record_length_bytes": 1,
        }]
        with (
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_exact_length_row_visual_symbols",
                side_effect=ValueError("exact route unavailable"),
            ),
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_bounded_length_row_visual_symbols",
                return_value=([0x5F, 0x11, 0x02, 0x03, 0xC9], 0, [0x03]),
            ) as bounded_solver,
        ):
            with self.assertRaisesRegex(ValueError, "exact route unavailable"):
                build_single_page_symbol_rows(
                    trees={},
                    target_rows=target,
                    preserved_by_row=[[]],
                    runtime_constraints=constraints,
                    pages=(240,),
                )

        bounded_solver.assert_not_called()

    def test_searches_past_an_unusable_extra_row_page(self) -> None:
        targets = [{"target_text": "가"} for _ in range(5)]
        constraints = [
            {
                "initial_context": 0xC9,
                "original_encoded_bits": 8,
                "original_record_length_bytes": 1,
            }
            for _ in range(5)
        ]

        def solve(*, trees, initial_context, target_bits, page, visuals):
            del trees, initial_context, target_bits
            if page == 239:
                raise ValueError("unusable route")
            return [0x02], 0, [0x02] * len(visuals)

        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_exact_length_row_visual_symbols",
            side_effect=solve,
        ):
            pages = select_row_font_pages(
                trees={},
                target_rows=targets,
                preserved_by_row=[[] for _ in targets],
                runtime_constraints=constraints,
            )

        self.assertEqual(pages, (240, 241, 242, 243, 89))

    def test_replaces_an_unusable_preferred_page_for_the_first_row(self) -> None:
        def solve(*, trees, initial_context, target_bits, page, visuals):
            del trees, initial_context, target_bits, visuals
            if page == 240:
                raise ValueError("preferred page is not exact")
            return [0x02], 0, [0x02]

        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_exact_length_row_visual_symbols",
            side_effect=solve,
        ):
            pages = select_row_font_pages(
                trees={},
                target_rows=[{"target_text": "가"}],
                preserved_by_row=[[]],
                runtime_constraints=[{
                    "initial_context": 0xC9,
                    "original_encoded_bits": 8,
                    "original_record_length_bytes": 1,
                }],
            )
        self.assertEqual(pages, (89,))

    def test_falls_back_to_an_exact_two_page_row(self) -> None:
        with (
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_exact_length_row_visual_symbols",
                side_effect=ValueError("single page is not exact"),
            ),
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_exact_length_row_multi_page_visual_symbols",
                return_value=(
                    [0x5F, 0x11, 0x02, 0x03, 0x5F, 0x11, 0x02, 0x04, 0xC9],
                    1,
                    [0x03, 0x04],
                    [240, 89],
                ),
            ) as multi_solver,
        ):
            pages = select_row_font_pages(
                trees={},
                target_rows=[{"target_text": "가나"}],
                preserved_by_row=[[]],
                runtime_constraints=[{
                    "initial_context": 0xC9,
                    "original_encoded_bits": 9,
                    "original_record_length_bytes": 2,
                }],
            )

        self.assertEqual(pages, ((240, 89),))
        multi_solver.assert_called_once()

    def test_expands_an_exact_row_to_four_font_pages(self) -> None:
        def solve_multi(*, trees, initial_context, target_bits, pages, visuals):
            del trees, initial_context, target_bits
            if len(pages) < 4:
                raise ValueError("two pages are not exact")
            return (
                [0x5F, 0x11, 0x02, 0x03, 0xC9],
                0,
                [0x03] * len(visuals),
                [pages[0]] * len(visuals),
            )

        with (
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_exact_length_row_visual_symbols",
                side_effect=ValueError("single page is not exact"),
            ),
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_exact_length_row_multi_page_visual_symbols",
                side_effect=solve_multi,
            ),
        ):
            pages = select_row_font_pages(
                trees={},
                target_rows=[{"target_text": "가"}],
                preserved_by_row=[[]],
                runtime_constraints=[{
                    "initial_context": 0xC9,
                    "original_encoded_bits": 9,
                    "original_record_length_bytes": 2,
                }],
            )

        self.assertEqual(pages, ((240, 89, 243, 242),))

    def test_reports_a_safe_bounded_bit_candidate_after_exact_failure(self) -> None:
        with (
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_exact_length_row_visual_symbols",
                side_effect=ValueError("single page is not exact"),
            ),
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_exact_length_row_multi_page_visual_symbols",
                side_effect=ValueError("page group is not exact"),
            ),
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "diagnose_bounded_candidate_bit_count",
                return_value=137,
            ) as diagnostic,
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "FONT_PAGE_COUNT",
                8,
            ),
            self.assertRaises(RowRouteError) as caught,
        ):
            select_row_font_pages(
                trees={},
                target_rows=[{"target_text": "가"}],
                preserved_by_row=[[]],
                runtime_constraints=[{
                    "initial_context": 0xC9,
                    "original_encoded_bits": 150,
                    "original_record_length_bytes": 19,
                }],
            )

        self.assertEqual(caught.exception.target_bits, 150)
        self.assertEqual(caught.exception.candidate_bits, 137)
        diagnostic.assert_called_once()

    def test_diagnoses_candidate_bits_with_fast_single_page_routes(self) -> None:
        def solve_bounded(*, page, **kwargs):
            del kwargs
            if page == 240:
                raise ValueError("first page has no route")
            return [0x5F, 0x11, 0x02, 0x03, 0xC9], 0, [0x03]

        with (
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_bounded_length_row_visual_symbols",
                side_effect=solve_bounded,
            ),
            patch(
                "tools.v5_1_first_context_translation_encoding.encode_symbols",
                return_value=(b"", 137),
            ),
        ):
            bits = diagnose_bounded_candidate_bit_count(
                trees={},
                initial_context=0xC9,
                target_bits=150,
                pages=(240, 89),
                visuals=["가"],
            )

        self.assertEqual(bits, 137)

    def test_bounds_large_exact_page_group_searches(self) -> None:
        self.assertEqual(exact_multi_page_state_limit(2), 5_000)
        self.assertEqual(exact_multi_page_state_limit(4), 5_000)
        self.assertEqual(exact_multi_page_state_limit(8), 5_000)

    def test_records_exact_multi_page_assignments(self) -> None:
        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_exact_length_row_multi_page_visual_symbols",
            return_value=(
                [0x5F, 0x11, 0x02, 0x03, 0x5F, 0x11, 0x02, 0x04, 0xC9],
                1,
                [0x03, 0x04],
                [240, 89],
            ),
        ):
            counts, rows, assignments = build_single_page_symbol_rows(
                trees={},
                target_rows=[{"review_index": 1, "target_text": "가나"}],
                preserved_by_row=[[]],
                runtime_constraints=[{
                    "initial_context": 0xC9,
                    "original_encoded_bits": 9,
                    "original_record_length_bytes": 2,
                }],
                pages=((240, 89),),
            )

        self.assertEqual(counts["planned_page_select_count"], 2)
        self.assertEqual(rows[0]["page_select_padding_count"], 1)
        self.assertEqual(assignments[0], [
            {"visual": "text:가", "page": 240, "symbol": 0x03},
            {"visual": "text:나", "page": 89, "symbol": 0x04},
        ])

    def test_records_the_selected_exact_render_page(self) -> None:
        targets = [
            {"review_index": index, "target_text": "가"}
            for index in range(1, 6)
        ]
        constraints = [
            {
                "initial_context": 0xC9,
                "original_encoded_bits": 8,
                "original_record_length_bytes": 1,
            }
            for _ in targets
        ]
        with (
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_row_visual_symbols",
                return_value=[0x03],
            ),
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "exact_length_row_symbols",
                return_value=([0x5F, 0x11, 0x02, 0x03, 0xC9], 0),
            ),
        ):
            _, _, assignments = build_single_page_symbol_rows(
                trees={},
                target_rows=targets,
                preserved_by_row=[[] for _ in targets],
                runtime_constraints=constraints,
                pages=ROW_FONT_PAGES,
            )
        self.assertEqual(assignments[-1], [
            {"visual": "text:가", "page": 239, "symbol": 0x03}
        ])

    def test_jointly_searches_a_bounded_visual_assignment(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: tree(0x11, 0x02, 0x11),
            0x02: tree(0x02, 0x03, 0x04),
            0x03: tree(0x03, 0x04, 0xC9),
            0x04: tree(0x04, 0xC9, 0x03),
        }
        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_row_visual_symbols",
            side_effect=ValueError("force joint search"),
        ):
            symbols, padding_count, assignments = (
                solve_bounded_length_row_visual_symbols(
                    trees=trees,
                    initial_context=0xC9,
                    maximum_bits=8,
                    page=240,
                    visuals=["text:가", "text:나"],
                )
            )
        self.assertEqual(padding_count, 0)
        self.assertEqual(assignments, [0x03, 0x04])
        self.assertEqual(symbols, [0x5F, 0x11, 0x02, 0x03, 0x04, 0xC9])

    def test_reselects_the_same_page_between_bounded_visible_glyphs(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: tree(0x11, 0x02, 0x11),
            0x02: tree(0x02, 0x03, 0x04),
            0x03: tree(0x03, 0x5F, 0x03),
            0x04: tree(0x04, 0xC9, 0x04),
        }
        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_row_visual_symbols",
            side_effect=ValueError("force joint search"),
        ):
            symbols, padding_count, assignments = (
                solve_bounded_length_row_visual_symbols(
                    trees=trees,
                    initial_context=0xC9,
                    maximum_bits=9,
                    page=240,
                    visuals=["text:가", "text:나"],
                )
            )
        self.assertEqual(padding_count, 1)
        self.assertEqual(assignments, [0x03, 0x04])
        self.assertEqual(
            symbols,
            [0x5F, 0x11, 0x02, 0x03, 0x5F, 0x11, 0x02, 0x04, 0xC9],
        )

    def test_reselects_the_same_page_at_the_exact_runtime_length(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: tree(0x11, 0x02, 0x11),
            0x02: tree(0x02, 0x03, 0x04),
            0x03: tree(0x03, 0x5F, 0x03),
            0x04: tree(0x04, 0xC9, 0x04),
        }
        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_row_visual_symbols",
            side_effect=ValueError("force joint exact search"),
        ):
            symbols, padding_count, assignments = (
                solve_exact_length_row_visual_symbols(
                    trees=trees,
                    initial_context=0xC9,
                    target_bits=9,
                    page=240,
                    visuals=["text:가", "text:나"],
                )
            )
        self.assertEqual(padding_count, 1)
        self.assertEqual(assignments, [0x03, 0x04])
        self.assertEqual(
            symbols,
            [0x5F, 0x11, 0x02, 0x03, 0x5F, 0x11, 0x02, 0x04, 0xC9],
        )

    def test_may_duplicate_a_repeated_visual_for_an_exact_route(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: tree(0x11, 0x02, 0x11),
            0x02: tree(0x02, 0x03, 0x04),
            0x03: tree(0x03, 0x5F, 0xC9),
            0x04: tree(0x04, 0xC9, 0x04),
        }
        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_row_visual_symbols",
            side_effect=ValueError("force repeated exact search"),
        ):
            symbols, _, assignments = solve_exact_length_row_visual_symbols(
                trees=trees,
                initial_context=0xC9,
                target_bits=9,
                page=240,
                visuals=["text:가", "text:가"],
            )
        self.assertEqual(assignments, [0x03, 0x04])
        self.assertEqual(
            symbols,
            [0x5F, 0x11, 0x02, 0x03, 0x5F, 0x11, 0x02, 0x04, 0xC9],
        )

    def test_switches_font_pages_between_bounded_visible_glyphs(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x10),
            0x10: tree(0x10, 0x11, 0x10),
            0x11: tree(0x11, 0x02, 0x04),
            0x02: tree(0x02, 0x03, 0x02),
            0x03: tree(0x03, 0x5F, 0x03),
            0x04: tree(0x04, 0xC9, 0x04),
        }
        (
            symbols,
            padding_count,
            assignments,
            assignment_pages,
        ) = solve_bounded_length_row_multi_page_visual_symbols(
            trees=trees,
            initial_context=0xC9,
            maximum_bits=9,
            pages=(240, 239),
            visuals=["text:가", "text:나"],
        )
        self.assertEqual(padding_count, 1)
        self.assertEqual(assignments, [0x03, 0x04])
        self.assertEqual(assignment_pages, [240, 239])
        self.assertEqual(
            symbols,
            [0x5F, 0x11, 0x02, 0x03, 0x5F, 0x10, 0x11, 0x04, 0xC9],
        )

    def test_uses_invisible_controls_at_the_exact_original_length(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x10),
            0x10: tree(0x10, 0x11, 0x10),
            0x11: tree(0x11, 0x02, 0x04),
            0x02: tree(0x02, 0x03, 0x02),
            0x03: tree(0x03, 0x5F, 0x03),
            0x04: tree(0x04, 0xC9, 0x04),
        }
        (
            symbols,
            padding_count,
            assignments,
            assignment_pages,
        ) = solve_exact_length_row_multi_page_visual_symbols(
            trees=trees,
            initial_context=0xC9,
            target_bits=9,
            pages=(240, 239),
            visuals=["text:가", "text:나"],
        )
        self.assertGreaterEqual(padding_count, 1)
        self.assertEqual(len(assignments), 2)
        self.assertEqual(len(assignment_pages), 2)
        self.assertTrue(set(assignment_pages) <= {240, 239})
        self.assertEqual(symbols[-1], 0xC9)

    def test_reuses_a_glyph_slot_on_a_different_font_page(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x10),
            0x10: tree(0x10, 0x11, 0x10),
            0x11: tree(0x11, 0x02, 0x03),
            0x02: tree(0x02, 0x03, 0x02),
            0x03: tree(0x03, 0x5F, 0xC9),
        }
        (
            _,
            padding_count,
            assignments,
            assignment_pages,
        ) = solve_bounded_length_row_multi_page_visual_symbols(
            trees=trees,
            initial_context=0xC9,
            maximum_bits=9,
            pages=(240, 239),
            visuals=["text:가", "text:나"],
        )
        self.assertEqual(padding_count, 1)
        self.assertEqual(assignments, [0x03, 0x03])
        self.assertEqual(len(set(assignment_pages)), 2)

    def test_jointly_searches_a_non_greedy_exact_length_assignment(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: tree(0x11, 0x02, 0x11),
            0x02: tree(0x02, 0x03, 0x04),
            0x03: tree(0x03, 0x04, 0xC9),
            0x04: tree(0x04, 0xC9, 0x03),
        }
        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_row_visual_symbols",
            side_effect=ValueError("force joint search"),
        ):
            symbols, padding_count, assignments = (
                solve_exact_length_row_visual_symbols(
                    trees=trees,
                    initial_context=0xC9,
                    target_bits=6,
                    page=240,
                    visuals=["text:가", "text:나"],
                )
            )
        self.assertEqual(padding_count, 0)
        self.assertEqual(assignments, [0x03, 0x04])
        self.assertEqual(symbols, [0x5F, 0x11, 0x02, 0x03, 0x04, 0xC9])

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

    def test_accepts_a_shorter_route_within_the_original_record(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: tree(0x11, 0x02, 0x11),
            0x02: tree(0x02, 0x03, 0x04),
            0x03: tree(0x03, 0xC9, 0x03),
        }
        symbols, padding_count = bounded_length_row_symbols(
            trees=trees,
            initial_context=0xC9,
            maximum_bits=8,
            page=240,
            assignments=[0x03],
        )
        self.assertEqual(padding_count, 0)
        self.assertEqual(symbols, [0x5F, 0x11, 0x02, 0x03, 0xC9])

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
            "in_place_storage_fit_entry_count": 5,
            "group_storage_capacity_bit_count": 400,
            "group_storage_fit_entry_count": 5,
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
        self.assertEqual(failure["failure_step"], "input")
        self.assertEqual(failure["failure_kind"], "ValueError")
        self.assertEqual(failure["failure_row_index"], 0)
        self.assertEqual(failure["failure_detail"], "none")
        self.assertEqual(failure["required_visible_symbol_count"], 0)
        self.assertEqual(failure["maximum_routable_visible_symbol_count"], 0)
        self.assertEqual(failure["target_encoded_bit_count"], 0)
        self.assertEqual(failure["bounded_candidate_bit_count"], 0)
        self.assertEqual(failure["bounded_candidate_relation"], "none")
        self.assertNotIn("error", failure)
        unsafe = deepcopy(failure)
        unsafe["category"] = "private-detail"
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            validate_first_context_translation_encoding_failure(unsafe)

        bounded = build_first_context_translation_encoding_failure(
            category="row-route",
            captured_utc=STAMP,
            target_encoded_bit_count=150,
            bounded_candidate_bit_count=137,
        )
        self.assertEqual(bounded["bounded_candidate_relation"], "shorter")
