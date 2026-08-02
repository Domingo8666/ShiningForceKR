from copy import deepcopy
import ast
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_first_context_translation_encoding import (  # noqa: E402
    MAX_BOUNDED_SINGLE_PAGE_STATES,
    MAX_EXACT_FONT_PAGE_CANDIDATES,
    MAX_EXACT_SINGLE_PAGE_STATES,
    RowRouteError,
    ROW_FONT_PAGES,
    bounded_length_row_symbols,
    build_character_assignments,
    build_first_context_translation_encoding,
    build_first_context_translation_encoding_failure,
    build_runtime_layout_rows,
    build_runtime_codec_constraints,
    build_row_visuals,
    build_single_page_symbol_rows,
    build_symbol_rows,
    diagnose_bounded_candidate_bit_count,
    direct_renderer_font_tile_offset,
    exact_multi_page_state_limit,
    exact_length_row_symbols,
    infer_direct_renderer_physical_symbol_map,
    pad_row_to_runtime_symbol_count,
    resolve_runtime_records_from_visible_anchor,
    select_row_font_pages,
    solve_bounded_length_row_visual_symbols,
    solve_bounded_length_row_multi_page_visual_symbols,
    solve_direct_renderer_proof_symbols,
    solve_fixed_count_row_visual_symbols,
    solve_fixed_count_row_multi_page_visual_symbols,
    solve_exact_length_row_multi_page_visual_symbols,
    solve_exact_length_row_blank_padded_visual_symbols,
    solve_byte_aligned_row_blank_padded_visual_symbols,
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
    def test_cli_wires_renderer_slot_shift_to_symbol_builder_only(self) -> None:
        source = (
            ROOT / "tools" / "v5_1_first_context_translation_encoding.py"
        ).read_text(encoding="utf-8")
        calls = [
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        by_name = {
            node.func.id: {keyword.arg for keyword in node.keywords}
            for node in calls
            if node.func.id in {
                "select_row_font_pages",
                "build_single_page_symbol_rows",
            }
        }
        self.assertNotIn(
            "direct_renderer_slot_shift",
            by_name["select_row_font_pages"],
        )
        self.assertIn(
            "direct_renderer_slot_shift",
            by_name["build_single_page_symbol_rows"],
        )

    def test_resolves_consecutive_runtime_records_from_visible_anchor(self) -> None:
        target = b"\x00\x03abc\x02de\x01f"
        records = resolve_runtime_records_from_visible_anchor(
            target=target,
            runtime_entry={"physical_start": 2, "record_length_bytes": 3},
            row_count=3,
        )
        self.assertEqual(
            records,
            [
                {
                    "length_offset": 1,
                    "record_length_bytes": 3,
                    "initial_context": 0xC9,
                },
                {
                    "length_offset": 5,
                    "record_length_bytes": 2,
                    "initial_context": 0xC9,
                },
                {
                    "length_offset": 8,
                    "record_length_bytes": 1,
                    "initial_context": 0xC9,
                },
            ],
        )

    def test_rejects_visible_anchor_with_wrong_record_length(self) -> None:
        with self.assertRaisesRegex(ValueError, "length disagrees"):
            resolve_runtime_records_from_visible_anchor(
                target=b"\x03abc",
                runtime_entry={"physical_start": 1, "record_length_bytes": 2},
                row_count=1,
            )

    def test_keeps_proven_four_row_pages_before_the_fifth_page(self) -> None:
        self.assertEqual(ROW_FONT_PAGES, (240, 241, 242, 243, 239))
        self.assertEqual(MAX_EXACT_FONT_PAGE_CANDIDATES, 8)
        self.assertEqual(MAX_EXACT_SINGLE_PAGE_STATES, 5_000)
        self.assertEqual(MAX_BOUNDED_SINGLE_PAGE_STATES, 5_000)

    def test_builds_direct_renderer_fixed_count_route(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x02, 0xFE),
            **{
                symbol: tree(symbol, symbol + 1, 0xFE)
                for symbol in range(0x02, 0x0A)
            },
            0x0A: tree(0x0A, 0xC9, 0xFE),
        }
        symbols, assignments = solve_direct_renderer_proof_symbols(
            trees=trees,
            initial_context=0xC9,
            maximum_bits=32,
            visuals=[f"text:{index}" for index in range(9)],
        )
        self.assertEqual(assignments, list(range(0x02, 0x0B)))
        self.assertEqual(symbols, [*assignments, 0xC9])
        self.assertEqual(
            direct_renderer_font_tile_offset(21, 0x05),
            direct_renderer_font_tile_offset(21, 0x02) + 3 * 32,
        )

    def test_exact_record_padding_uses_only_same_page_blank_glyphs(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xFE),
            0x5F: tree(0x5F, 0x11, 0xFE),
            0x11: tree(0x11, 0x02, 0xFE),
            0x02: tree(0x02, 0x03, 0xFE),
            0x03: tree(0x03, 0x04, 0xFE),
            0x04: tree(0x04, 0x04, 0xC9),
        }
        symbols, assignments, blank_count = (
            solve_exact_length_row_blank_padded_visual_symbols(
                trees=trees,
                initial_context=0xC9,
                target_bits=7,
                page=240,
                visuals=["text:가"],
                target_symbol_count=6,
            )
        )
        self.assertEqual(
            symbols,
            [0x5F, 0x11, 0x02, 0x03, 0x04, 0x04, 0xC9],
        )
        self.assertEqual(assignments, [0x03, 0x04, 0x04])
        self.assertEqual(blank_count, 2)

    def test_proven_prefix_ends_on_the_earliest_whole_byte(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xFE),
            0x5F: tree(0x5F, 0x11, 0xFE),
            0x11: tree(0x11, 0x02, 0xFE),
            0x02: tree(0x02, 0x03, 0xFE),
            0x03: tree(0x03, 0x04, 0xFE),
            0x04: tree(0x04, 0x04, 0xC9),
        }
        symbols, assignments, blank_count, encoded_bits = (
            solve_byte_aligned_row_blank_padded_visual_symbols(
                trees=trees,
                initial_context=0xC9,
                maximum_bits=16,
                page=240,
                visuals=["text:가"],
                target_symbol_count=6,
            )
        )
        self.assertEqual(
            symbols,
            [0x5F, 0x11, 0x02, 0x03, 0x04, 0x04, 0x04, 0xC9],
        )
        self.assertEqual(assignments, [0x03, 0x04, 0x04, 0x04])
        self.assertEqual(blank_count, 3)
        self.assertEqual(encoded_bits, 8)

    def test_direct_renderer_reuses_only_the_same_visual_symbol(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x02, 0xFE),
            0x02: tree(0x02, 0x03, 0xFE),
            0x03: tree(0x03, 0x03, 0xC9),
        }
        symbols, assignments = solve_direct_renderer_proof_symbols(
            trees=trees,
            initial_context=0xC9,
            maximum_bits=8,
            visuals=["text:가", "technical-blank", "technical-blank"],
        )
        self.assertEqual(symbols, [0x02, 0x03, 0x03, 0xC9])
        self.assertEqual(assignments, symbols[:-1])

    def test_direct_renderer_accepts_traced_page_marker_as_a_slot(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xFE),
            0x5F: tree(0x5F, 0x02, 0xFE),
            0x02: tree(0x02, 0xC9, 0xFE),
        }
        symbols, assignments = solve_direct_renderer_proof_symbols(
            trees=trees,
            initial_context=0xC9,
            maximum_bits=8,
            visuals=["text:두", "text:고"],
        )
        self.assertEqual(symbols, [0x5F, 0x02, 0xC9])
        self.assertEqual(assignments, symbols[:-1])
        self.assertGreater(
            direct_renderer_font_tile_offset(21, 0x5F),
            direct_renderer_font_tile_offset(21, 0x5E),
        )

    def test_direct_renderer_limits_decoded_symbols_to_shifted_font_slots(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0x02),
            0x5F: tree(0x5F, 0xC9, 0xFE),
            0x02: tree(0x02, 0xC9, 0xFE),
        }
        symbols, assignments = solve_direct_renderer_proof_symbols(
            trees=trees,
            initial_context=0xC9,
            maximum_bits=8,
            visuals=["text:두"],
            font_slot_shift=1,
        )
        self.assertEqual(symbols, [0x02, 0xC9])
        self.assertEqual(assignments, [0x02])
        self.assertLessEqual(assignments[0] + 1, 0x5F)

    def test_direct_renderer_rejects_known_physical_slot_collision(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x04, 0x05),
            0x04: tree(0x04, 0x03, 0x06),
            0x03: tree(0x03, 0xC9, 0xFE),
            0x06: tree(0x06, 0xC9, 0xFE),
        }
        symbols, assignments = solve_direct_renderer_proof_symbols(
            trees=trees,
            initial_context=0xC9,
            maximum_bits=8,
            visuals=["text:라", "text:!"],
            physical_symbol_by_decoded={0x04: 0x06, 0x03: 0x06},
        )
        self.assertEqual(symbols, [0x04, 0x06, 0xC9])
        self.assertEqual(assignments, [0x04, 0x06])

    def test_infers_nonconstant_direct_renderer_physical_slots(self) -> None:
        capture = {
            "schema_version": 8,
            "slot_alignment": {
                "sample_route_candidates": [
                    {
                        "encoded_symbol": 0x5F,
                        "rendered_tile": 98,
                        "font_tiles": [[19, 4], [20, 3]],
                    },
                    {
                        "encoded_symbol": 0x02,
                        "rendered_tile": 97,
                        "font_tiles": [[19, 3], [20, 5]],
                    },
                ],
            },
        }
        self.assertEqual(
            infer_direct_renderer_physical_symbol_map(capture),
            (19, 94, {0x5F: 4, 0x02: 3}),
        )

    def test_first_row_direct_renderer_omits_inline_page_token(self) -> None:
        direct_symbols = [*range(0x02, 0x0A), 0xC9]
        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_direct_renderer_proof_symbols",
            return_value=(direct_symbols, direct_symbols[:-1]),
        ):
            counts, rows, assignments = build_single_page_symbol_rows(
                trees={},
                target_rows=[{"review_index": 1, "target_text": "가"}],
                preserved_by_row=[[]],
                runtime_constraints=[{
                    "initial_context": 0xC9,
                    "original_record_length_bytes": 16,
                    "original_symbol_count": 9,
                }],
                pages=(240,),
                direct_renderer_first_row=True,
                direct_renderer_pages=(21, 22),
                direct_renderer_slot_shift=3,
            )
        self.assertEqual(rows[0]["symbols"], direct_symbols)
        self.assertEqual(rows[0]["runtime_symbol_count"], 9)
        self.assertEqual(rows[0]["page_select_count"], 0)
        self.assertEqual(rows[0]["terminator_count"], 1)
        self.assertTrue(rows[0]["direct_renderer_proof"])
        self.assertEqual(counts["planned_page_select_count"], 0)
        self.assertEqual(counts["planned_terminator_count"], 1)
        self.assertEqual(len(assignments[0]), 16)
        self.assertEqual(assignments[0][0]["visual"], "text:가")
        self.assertTrue(assignments[0][0]["direct_renderer_page"])
        self.assertEqual(
            {assignment["page"] for assignment in assignments[0]},
            {21, 22},
        )
        self.assertTrue(all(
            assignment["font_symbol"] == assignment["symbol"] + 3
            for assignment in assignments[0]
        ))
        self.assertTrue(all(
            assignment["visual"] == "technical-blank"
            for assignment in assignments[0][2:]
        ))

    def test_skips_disproven_page_route_for_direct_renderer_row(self) -> None:
        targets = [{"target_text": "가"}, {"target_text": "나"}]
        constraints = [
            {
                "initial_context": 0xC9,
                "original_encoded_bits": 8,
                "original_record_length_bytes": 1,
            }
            for _ in targets
        ]
        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_bounded_length_row_visual_symbols",
            return_value=([0x02, 0xC9], 0, [0x02]),
        ) as solver:
            pages = select_row_font_pages(
                trees={},
                target_rows=targets,
                preserved_by_row=[[], []],
                runtime_constraints=constraints,
                direct_renderer_first_row=True,
                direct_renderer_pages=(21, 22),
            )
        self.assertEqual(pages, (21, 241))
        solver.assert_called_once()

    def test_prefers_the_previously_visible_page_for_first_row(self) -> None:
        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_bounded_length_row_visual_symbols",
            return_value=([0x02, 0xC9], 0, [0x02]),
        ) as solver:
            pages = select_row_font_pages(
                trees={},
                target_rows=[{"target_text": "가"}],
                preserved_by_row=[[]],
                runtime_constraints=[{
                    "initial_context": 0xC9,
                    "original_record_length_bytes": 16,
                }],
                proven_first_row_page=89,
            )
        self.assertEqual(pages, (89,))
        self.assertEqual(solver.call_args.kwargs["page"], 89)

    def test_marks_proven_visible_page_route_on_first_row(self) -> None:
        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_byte_aligned_row_blank_padded_visual_symbols",
            return_value=([0x02, 0xC9], [0x02], 0, 8),
        ):
            _, rows, _ = build_single_page_symbol_rows(
                trees={},
                target_rows=[{"review_index": 1, "target_text": "가"}],
                preserved_by_row=[[]],
                runtime_constraints=[{
                    "initial_context": 0xC9,
                    "original_record_length_bytes": 16,
                    "original_symbol_count": 5,
                }],
                pages=(89,),
                proven_first_row_page=89,
            )
        self.assertTrue(rows[0]["proven_visible_page_route"])

    def test_proven_page_select_route_fills_fixed_slots_with_blank_tiles(self) -> None:
        symbols = [
            0x5F, 0x11, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07,
            0xC9,
        ]
        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_byte_aligned_row_blank_padded_visual_symbols",
            return_value=(symbols, [0x03, 0x04, 0x05, 0x06, 0x07], 2, 16),
        ):
            counts, rows, assignments = build_single_page_symbol_rows(
                trees={},
                target_rows=[{"review_index": 1, "target_text": "가"}],
                preserved_by_row=[[]],
                runtime_constraints=[{
                    "initial_context": 0xC9,
                    "original_record_length_bytes": 16,
                    "original_symbol_count": 7,
                }],
                pages=(89,),
                proven_first_row_page=89,
            )
        self.assertEqual(rows[0]["symbols"], symbols)
        self.assertEqual(rows[0]["page_select_count"], 1)
        self.assertEqual(rows[0]["runtime_symbol_count"], len(symbols))
        self.assertEqual(rows[0]["fixed_count_padding_symbol_count"], 4)
        self.assertEqual(counts["planned_page_select_count"], 1)
        self.assertEqual(
            [item["visual"] for item in assignments[0]],
            [
                "text:가",
                "technical-blank",
                "technical-blank",
                "technical-blank",
                "technical-blank",
            ],
        )
        self.assertEqual({item["page"] for item in assignments[0]}, {89})

    def test_proven_visible_page_can_use_implicit_renderer_blank_slots(self) -> None:
        direct_symbols = [*range(0x02, 0x0A), 0xC9]
        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_direct_renderer_proof_symbols",
            return_value=(direct_symbols, direct_symbols[:-1]),
        ):
            counts, rows, assignments = build_single_page_symbol_rows(
                trees={},
                target_rows=[{"review_index": 1, "target_text": "가"}],
                preserved_by_row=[[]],
                runtime_constraints=[{
                    "initial_context": 0xC9,
                    "original_record_length_bytes": 16,
                    "original_symbol_count": 9,
                }],
                pages=(89,),
                direct_renderer_first_row=True,
                direct_renderer_pages=(89,),
                proven_first_row_page=89,
            )
        self.assertTrue(rows[0]["proven_visible_page_route"])
        self.assertTrue(rows[0]["direct_renderer_proof"])
        self.assertEqual(rows[0]["page_select_count"], 0)
        self.assertEqual(counts["planned_page_select_count"], 0)
        self.assertEqual({item["page"] for item in assignments[0]}, {89})
        self.assertTrue(all(
            item["visual"] == "technical-blank"
            for item in assignments[0][1:]
        ))

    def test_accepts_direct_renderer_failure_diagnostics(self) -> None:
        failure = build_first_context_translation_encoding_failure(
            category="row-route",
            captured_utc=STAMP,
            failure_step="build-symbol-rows",
            failure_kind="MemoryError",
            failure_row_index=1,
            failure_detail="solve-direct-renderer-first-row",
        )
        validate_first_context_translation_encoding_failure(failure)

    def test_compacts_only_ascii_layout_and_preserves_hangul_sequence(self) -> None:
        approved = [{
            "review_index": 1,
            "target_text": "가나 다라, 마바사아!",
        }]
        runtime, audit = build_runtime_layout_rows(
            target_rows=approved,
            runtime_constraints=[{"original_symbol_count": 19}],
        )
        self.assertEqual(runtime[0]["target_text"], "가나다라,마바사아")
        self.assertEqual(approved[0]["target_text"], "가나 다라, 마바사아!")
        self.assertEqual(audit[0]["approved_character_count"], 12)
        self.assertEqual(audit[0]["runtime_character_count"], 9)
        self.assertEqual(audit[0]["required_page_token_count"], 3)
        self.assertTrue(audit[0]["hangul_sequence_preserved"])

    def test_rejects_layout_compaction_without_exact_fixed_count_shape(self) -> None:
        with self.assertRaisesRegex(ValueError, "compaction is not safe"):
            build_runtime_layout_rows(
                target_rows=[{
                    "review_index": 1,
                    "target_text": "가나 다라, 마바사아?",
                }],
                runtime_constraints=[{"original_symbol_count": 19}],
            )

    def test_builds_an_audited_short_clause_for_the_codec_proof(self) -> None:
        approved = [{
            "review_index": 1,
            "target_text": "두고 봐라, 미샤엘라!",
        }]
        runtime, audit = build_runtime_layout_rows(
            target_rows=approved,
            runtime_constraints=[{"original_symbol_count": 9}],
            technical_proof_prefixes=True,
        )
        self.assertEqual(runtime[0]["target_text"], "두고봐라!")
        self.assertEqual(approved[0]["target_text"], "두고 봐라, 미샤엘라!")
        self.assertEqual(
            audit[0]["layout_action"],
            "technical-codec-proof-short-clause",
        )
        self.assertTrue(audit[0]["technical_proof_only"])
        self.assertFalse(audit[0]["hangul_sequence_preserved"])
        self.assertEqual(audit[0]["required_page_token_count"], 1)

    def test_adapts_layout_compaction_to_runtime_symbol_count(self) -> None:
        runtime, audit = build_runtime_layout_rows(
            target_rows=[{
                "review_index": 1,
                "target_text": "가나 다라, 마바사아!",
            }],
            runtime_constraints=[{"original_symbol_count": 20}],
        )
        self.assertEqual(runtime[0]["target_text"], "가나다라,마바사아!")
        self.assertEqual(audit[0]["layout_action"], "remove-ascii-spaces")
        self.assertEqual(audit[0]["runtime_character_count"], 10)
        self.assertEqual(audit[0]["required_page_token_count"], 3)

    def test_compacts_a_later_row_when_font_control_has_no_room(self) -> None:
        runtime, audit = build_runtime_layout_rows(
            target_rows=[
                {"review_index": 1, "target_text": "가"},
                {"review_index": 2, "target_text": "마구스, 차례다!"},
            ],
            runtime_constraints=[
                {"original_symbol_count": 5},
                {"original_symbol_count": 10},
            ],
            compact_review_indexes=(),
        )
        self.assertEqual(runtime[0]["target_text"], "가")
        self.assertEqual(runtime[1]["target_text"], "마구스차례다")
        self.assertEqual(audit[0]["review_index"], 2)
        self.assertEqual(audit[0]["layout_action"], "remove-ascii-layout-characters")
        self.assertEqual(audit[0]["required_page_token_count"], 1)
        self.assertTrue(audit[0]["hangul_sequence_preserved"])

    def test_builds_a_proven_row_with_the_joint_bounded_solver(self) -> None:
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
                "solve_bounded_length_row_visual_symbols",
                return_value=([0x5F, 0x11, 0x02, 0x03, 0xC9], 0, [0x03]),
            ) as bounded_solver,
        ):
            _, rows, assignments = build_single_page_symbol_rows(
                trees={},
                target_rows=target,
                preserved_by_row=[[]],
                runtime_constraints=constraints,
                pages=(240,),
            )

        bounded_solver.assert_called_once()
        self.assertEqual(rows[0]["symbols"], [0x5F, 0x11, 0x02, 0x03, 0xC9])
        self.assertEqual(assignments[0], [
            {"visual": "text:가", "page": 240, "symbol": 0x03}
        ])

    def test_rejects_a_shorter_record_bounded_runtime_row(self) -> None:
        target = [{"review_index": 1, "target_text": "가"}]
        constraints = [{
            "initial_context": 0xC9,
            "original_encoded_bits": 4,
            "original_record_length_bytes": 1,
        }]
        with (
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_bounded_length_row_visual_symbols",
                side_effect=ValueError("exact route unavailable"),
            ),
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "diagnose_bounded_candidate_bit_count",
                return_value=6,
            ) as diagnostic,
        ):
            with self.assertRaises(RowRouteError) as caught:
                build_single_page_symbol_rows(
                    trees={},
                    target_rows=target,
                    preserved_by_row=[[]],
                    runtime_constraints=constraints,
                    pages=(240,),
                )

        diagnostic.assert_called_once_with(
            trees={},
            initial_context=0xC9,
            target_bits=8,
            pages=(240,),
            visuals=["text:가"],
        )
        self.assertEqual(caught.exception.target_bits, 8)
        self.assertEqual(caught.exception.candidate_bits, 6)

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

        def solve(*, trees, initial_context, maximum_bits, page, visuals):
            del trees, initial_context, maximum_bits
            if page == 239:
                raise ValueError("unusable route")
            return [0x02], 0, [0x02] * len(visuals)

        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_bounded_length_row_visual_symbols",
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
        def solve(*, trees, initial_context, maximum_bits, page, visuals):
            del trees, initial_context, maximum_bits, visuals
            if page == 240:
                raise ValueError("preferred page is not exact")
            return [0x02], 0, [0x02]

        with patch(
            "tools.v5_1_first_context_translation_encoding."
            "solve_bounded_length_row_visual_symbols",
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
                "solve_bounded_length_row_visual_symbols",
                side_effect=ValueError("single page is not exact"),
            ),
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_bounded_length_row_multi_page_visual_symbols",
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
        def solve_multi(*, trees, initial_context, maximum_bits, pages, visuals):
            del trees, initial_context, maximum_bits
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
                "solve_bounded_length_row_visual_symbols",
                side_effect=ValueError("single page is not exact"),
            ),
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_bounded_length_row_multi_page_visual_symbols",
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

    def test_searches_all_ranked_fixed_three_page_combinations(self) -> None:
        lengths = {
            previous: {symbol: 1 for symbol in range(0x100)}
            for previous in range(0x100)
        }

        def solve_multi(*, pages, **kwargs):
            del kwargs
            if set(pages) != {4, 5, 6}:
                raise ValueError("ranked group is not routable")
            return ([0xC9] * 20, 0, [0x02] * 10, [6] * 10)

        with (
            patch(
                "tools.v5_1_first_context_translation_encoding._code_lengths",
                return_value=lengths,
            ),
            patch(
                "tools.v5_1_first_context_translation_encoding.FONT_PAGE_COUNT",
                8,
            ),
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_fixed_count_row_visual_symbols",
                side_effect=ValueError("single page is not routable"),
            ),
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_fixed_count_row_multi_page_visual_symbols",
                side_effect=solve_multi,
            ),
        ):
            pages = select_row_font_pages(
                trees={},
                target_rows=[{"target_text": "가나다라마바사아자차"}],
                preserved_by_row=[[]],
                runtime_constraints=[{
                    "initial_context": 0xC9,
                    "original_encoded_bits": 192,
                    "original_record_length_bytes": 24,
                    "original_symbol_count": 20,
                }],
            )

        self.assertEqual(set(pages[0]), {4, 5, 6})

    def test_reports_a_safe_bounded_bit_candidate_after_exact_failure(self) -> None:
        with (
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "diagnose_bounded_candidate_bit_count",
                return_value=137,
            ) as diagnostic,
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_bounded_length_row_visual_symbols",
                side_effect=ValueError("record capacity unavailable"),
            ),
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_bounded_length_row_multi_page_visual_symbols",
                side_effect=ValueError("page group is unavailable"),
            ),
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

        self.assertEqual(caught.exception.target_bits, 152)
        self.assertEqual(caught.exception.candidate_bits, 137)
        diagnostic.assert_called_once()

    def test_selects_a_record_bounded_page_after_exact_failure(self) -> None:
        with (
            patch(
                "tools.v5_1_first_context_translation_encoding."
                "solve_bounded_length_row_visual_symbols",
                return_value=([0x5F, 0x11, 0x02, 0x03, 0xC9], 0, [0x03]),
            ) as bounded_solver,
        ):
            pages = select_row_font_pages(
                trees={},
                target_rows=[{"target_text": "가"}],
                preserved_by_row=[[]],
                runtime_constraints=[{
                    "initial_context": 0xC9,
                    "original_encoded_bits": 4,
                    "original_record_length_bytes": 2,
                }],
            )

        self.assertEqual(pages, (240,))
        self.assertEqual(bounded_solver.call_args.kwargs["maximum_bits"], 16)

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
            "solve_bounded_length_row_multi_page_visual_symbols",
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
                "bounded_length_row_symbols",
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

    def test_pads_a_visible_row_to_the_runtime_symbol_count(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: tree(0x11, 0x02, 0x11),
            0x02: tree(0x02, 0x03, 0x02),
            0x03: tree(0x03, 0xC9, 0x03),
        }
        symbols, padding_symbols, padding_pages = (
            pad_row_to_runtime_symbol_count(
                trees=trees,
                initial_context=0xC9,
                maximum_bits=8,
                target_symbol_count=6,
                symbols=[0x5F, 0x11, 0x02, 0x03, 0xC9],
            )
        )
        self.assertEqual(symbols, [0x5F, 0x11, 0x02, 0x03, 0xC9, 0xC9])
        self.assertEqual(padding_symbols, 1)
        self.assertEqual(padding_pages, 0)

    def test_places_fixed_count_page_padding_between_visible_glyphs(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: tree(0x11, 0x02, 0x11),
            0x02: tree(0x02, 0x03, 0x04),
            0x03: tree(0x03, 0x04, 0x5F),
            0x04: tree(0x04, 0xC9, 0x04),
        }
        symbols, padding_symbols, padding_pages = (
            pad_row_to_runtime_symbol_count(
                trees=trees,
                initial_context=0xC9,
                maximum_bits=9,
                target_symbol_count=9,
                symbols=[0x5F, 0x11, 0x02, 0x03, 0x04, 0xC9],
            )
        )
        self.assertEqual(
            symbols,
            [0x5F, 0x11, 0x02, 0x03, 0x5F, 0x11, 0x02, 0x04, 0xC9],
        )
        self.assertEqual(padding_symbols, 3)
        self.assertEqual(padding_pages, 1)

    def test_fixed_count_solver_retries_joint_glyph_assignments(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: tree(0x11, 0x02, 0x11),
            0x02: tree(0x02, 0x03, 0x04),
            0x03: tree(0x03, 0x04, 0x5F),
            0x04: tree(0x04, 0xC9, 0x04),
        }
        symbols, padding, assignments = solve_fixed_count_row_visual_symbols(
            trees=trees,
            initial_context=0xC9,
            maximum_bits=9,
            target_symbol_count=9,
            page=240,
            visuals=["text:가", "text:나"],
        )
        self.assertEqual(
            symbols,
            [0x5F, 0x11, 0x02, 0x03, 0x5F, 0x11, 0x02, 0x04, 0xC9],
        )
        self.assertEqual(padding, 1)
        self.assertEqual(assignments, [3, 4])

    def test_fixed_count_solver_uses_safe_temporary_suffix_page(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: tree(0x11, 0x02, 0x03),
            0x02: tree(0x02, 0x03, 0x02),
            0x03: tree(0x03, 0x04, 0xC9),
            0x04: tree(0x04, 0x5F, 0x04),
        }
        symbols, padding, assignments = solve_fixed_count_row_visual_symbols(
            trees=trees,
            initial_context=0xC9,
            maximum_bits=9,
            target_symbol_count=9,
            page=240,
            visuals=["text:가", "text:나"],
        )
        self.assertEqual(
            symbols,
            [0x5F, 0x11, 0x02, 0x03, 0x04, 0x5F, 0x11, 0x03, 0xC9],
        )
        self.assertEqual(padding, 1)
        self.assertEqual(assignments, [3, 4])

    def test_fixed_count_solver_bounds_three_page_token_layout(self) -> None:
        three_way = ParsedTree(
            previous_symbol=0x02,
            pointer=0,
            structure_offset=0,
            structure_bits=5,
            leaf_count=3,
            symbol_offset=0,
            root=HuffmanNode(
                left=HuffmanNode(symbol=0x03),
                right=HuffmanNode(
                    left=HuffmanNode(symbol=0x04),
                    right=HuffmanNode(symbol=0xC9),
                ),
            ),
        )
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: tree(0x11, 0x02, 0x11),
            0x02: three_way,
            0x03: tree(0x03, 0x5F, 0x03),
            0x04: tree(0x04, 0x5F, 0x04),
        }
        symbols, padding, assignments = solve_fixed_count_row_visual_symbols(
            trees=trees,
            initial_context=0xC9,
            maximum_bits=14,
            target_symbol_count=12,
            page=240,
            visuals=["text:가", "text:나"],
        )
        self.assertEqual(len(symbols), 12)
        self.assertEqual(symbols[-1], 0xC9)
        self.assertEqual(padding, 2)
        self.assertEqual(assignments, [3, 4])

    def test_fixed_count_solver_splits_visible_glyphs_across_two_pages(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: tree(0x11, 0x02, 0x03),
            0x02: tree(0x02, 0x04, 0x02),
            0x04: tree(0x04, 0x5F, 0x04),
            0x03: tree(0x03, 0x05, 0x03),
            0x05: tree(0x05, 0xC9, 0x05),
        }
        symbols, padding, assignments, pages = (
            solve_fixed_count_row_multi_page_visual_symbols(
                trees=trees,
                initial_context=0xC9,
                maximum_bits=9,
                target_symbol_count=9,
                pages=(240, 241),
                visuals=["text:가", "text:나"],
            )
        )
        self.assertEqual(
            symbols,
            [0x5F, 0x11, 0x02, 0x04, 0x5F, 0x11, 0x03, 0x05, 0xC9],
        )
        self.assertEqual(padding, 0)
        self.assertEqual(assignments, [4, 5])
        self.assertEqual(pages, [240, 241])

    def test_fixed_count_solver_splits_compact_row_across_three_pages(self) -> None:
        page_contexts = ParsedTree(
            previous_symbol=0x11,
            pointer=0,
            structure_offset=0,
            structure_bits=5,
            leaf_count=3,
            symbol_offset=0,
            root=HuffmanNode(
                left=HuffmanNode(symbol=0x02),
                right=HuffmanNode(
                    left=HuffmanNode(symbol=0x03),
                    right=HuffmanNode(symbol=0x04),
                ),
            ),
        )
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: page_contexts,
            0x02: tree(0x02, 0x05, 0x02),
            0x03: tree(0x03, 0x06, 0x03),
            0x04: tree(0x04, 0x07, 0x04),
            0x05: tree(0x05, 0x5F, 0x05),
            0x06: tree(0x06, 0x5F, 0x06),
            0x07: tree(0x07, 0xC9, 0x07),
        }
        symbols, padding, assignments, pages = (
            solve_fixed_count_row_multi_page_visual_symbols(
                trees=trees,
                initial_context=0xC9,
                maximum_bits=20,
                target_symbol_count=13,
                pages=(240, 241, 242),
                visuals=["text:가", "text:나", "text:다"],
            )
        )
        self.assertEqual(len(symbols), 13)
        self.assertEqual(symbols[-1], 0xC9)
        self.assertEqual(padding, 0)
        self.assertEqual(assignments, [5, 6, 7])
        self.assertEqual(pages, [240, 241, 242])

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
                    "observation": {
                        "selector": 7,
                        "ordinal": 2,
                        "initial_context": 0x11,
                    },
                }
            ],
            projection_pairs=[
                {
                    "source_section_index": 1,
                    "source_line_index": 2,
                    "target_selector": 7,
                    "target_ordinal": 2,
                    "target_record": {
                        "length_offset": 0,
                        "record_length_bytes": 1,
                    },
                }
            ],
        )
        self.assertEqual(constraints[0]["initial_context"], 0x11)
        self.assertEqual(
            constraints[0]["context_resolution_basis"],
            "captured-runtime-vector-context",
        )
        self.assertEqual(constraints[0]["original_encoded_bits"], 4)
        self.assertEqual(constraints[0]["original_symbol_count"], 4)

        anchored_constraints = build_runtime_codec_constraints(
            target=b"\x01\x00\x01\x00",
            trees=trees,
            context_rows=[
                {
                    "mapping_status": "unique",
                    "source_section_index": 1,
                    "source_line_index": 2,
                    "observation": {
                        "selector": 7,
                        "ordinal": 2,
                        "initial_context": 0xC9,
                    },
                },
                {
                    "mapping_status": "unique",
                    "source_section_index": 1,
                    "source_line_index": 3,
                    "observation": {
                        "selector": 7,
                        "ordinal": 3,
                        "initial_context": 0xC9,
                    },
                },
            ],
            projection_pairs=[
                {
                    "source_section_index": 1,
                    "source_line_index": 2,
                    "target_selector": 7,
                    "target_ordinal": 2,
                    "target_record": {
                        "length_offset": 0,
                        "record_length_bytes": 1,
                    },
                },
                {
                    "source_section_index": 1,
                    "source_line_index": 3,
                    "target_selector": 7,
                    "target_ordinal": 3,
                    "target_record": {
                        "length_offset": 2,
                        "record_length_bytes": 1,
                    },
                },
            ],
            runtime_records=[
                {
                    "length_offset": 0,
                    "record_length_bytes": 1,
                    "initial_context": 0xC9,
                }
            ],
        )
        self.assertEqual(anchored_constraints[0]["original_encoded_bits"], 6)
        self.assertEqual(anchored_constraints[0]["original_symbol_count"], 6)
        self.assertEqual(anchored_constraints[0]["initial_context"], 0xC9)
        self.assertEqual(anchored_constraints[1]["original_encoded_bits"], 6)
        self.assertEqual(anchored_constraints[1]["original_symbol_count"], 6)

        self.assertEqual(anchored_constraints[0]["length_offset"], 0)
        self.assertEqual(anchored_constraints[1]["length_offset"], 2)

    def test_uses_runtime_coordinates_when_source_rows_are_duplicated(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: tree(0x11, 0x02, 0x11),
            0x02: tree(0x02, 0x03, 0x04),
            0x03: tree(0x03, 0x04, 0xC9),
            0x04: tree(0x04, 0xC9, 0x03),
        }
        constraints = build_runtime_codec_constraints(
            target=b"\x01\x00\x00",
            trees=trees,
            context_rows=[{
                "mapping_status": "unique",
                "source_section_index": 1,
                "source_line_index": 2,
                "observation": {
                    "selector": 7,
                    "ordinal": 2,
                    "initial_context": 0xC9,
                },
            }],
            projection_pairs=[
                {
                    "source_section_index": 1,
                    "source_line_index": 2,
                    "target_selector": 7,
                    "target_ordinal": 2,
                    "target_record": {
                        "length_offset": 0,
                        "record_length_bytes": 1,
                    },
                },
                {
                    "source_section_index": 1,
                    "source_line_index": 2,
                    "target_selector": 8,
                    "target_ordinal": 2,
                    "target_record": {
                        "length_offset": 2,
                        "record_length_bytes": 0,
                    },
                },
            ],
        )
        self.assertEqual(constraints[0]["length_offset"], 0)
        self.assertEqual(
            constraints[0]["record_resolution_basis"],
            "captured-runtime-coordinate",
        )

    def test_falls_back_to_the_visible_anchor_record_chain(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0x5F, 0xC9),
            0x5F: tree(0x5F, 0x11, 0x5F),
            0x11: tree(0x11, 0x02, 0x11),
            0x02: tree(0x02, 0x03, 0x04),
            0x03: tree(0x03, 0x04, 0xC9),
            0x04: tree(0x04, 0xC9, 0x03),
        }
        constraints = build_runtime_codec_constraints(
            target=b"\x01\x00\x01\x00\x00",
            trees=trees,
            context_rows=[
                {
                    "mapping_status": "unique",
                    "observation": {
                        "selector": 7,
                        "ordinal": 2,
                        "initial_context": 0xC9,
                    },
                },
                {
                    "mapping_status": "unique",
                    "observation": {
                        "selector": 7,
                        "ordinal": 3,
                        "initial_context": 0xC9,
                    },
                },
            ],
            projection_pairs=[
                {
                    "target_selector": 7,
                    "target_ordinal": 2,
                    "target_record": {
                        "length_offset": 0,
                        "record_length_bytes": 1,
                    },
                },
                {
                    "target_selector": 7,
                    "target_ordinal": 3,
                    "target_record": {
                        "length_offset": 4,
                        "record_length_bytes": 0,
                    },
                },
            ],
            runtime_records=[
                {"length_offset": 0, "record_length_bytes": 1},
                {"length_offset": 2, "record_length_bytes": 1},
            ],
        )
        self.assertEqual(constraints[1]["length_offset"], 2)
        self.assertEqual(
            constraints[1]["record_resolution_basis"],
            "visible-anchor-consecutive-fallback",
        )

    def test_prefers_the_directly_captured_runtime_context(self) -> None:
        trees = {
            0xC9: tree(0xC9, 0xC9, 0xAA),
            0x11: tree(0x11, 0x03, 0xC9),
        }
        constraints = build_runtime_codec_constraints(
            target=b"\x01\x80\x01\x00",
            trees=trees,
            context_rows=[
                {
                    "mapping_status": "unique",
                    "observation": {
                        "selector": 7,
                        "ordinal": 2,
                        "initial_context": 0xC9,
                    },
                },
                {
                    "mapping_status": "unique",
                    "observation": {
                        "selector": 7,
                        "ordinal": 3,
                        "initial_context": 0x11,
                    },
                },
            ],
            projection_pairs=[
                {
                    "target_selector": 7,
                    "target_ordinal": 2,
                    "target_record": {
                        "length_offset": 2,
                        "record_length_bytes": 1,
                    },
                },
                {
                    "target_selector": 7,
                    "target_ordinal": 3,
                    "target_record": {
                        "length_offset": 0,
                        "record_length_bytes": 1,
                    },
                },
            ],
        )
        self.assertEqual(constraints[1]["initial_context"], 0x11)
        self.assertEqual(
            constraints[1]["context_resolution_basis"],
            "captured-runtime-vector-context",
        )

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
            "fixed_count_padding_symbol_count": 12,
            "exact_runtime_symbol_count_entry_count": 5,
            "fixed_count_roundtrip_entry_count": 5,
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
        bounded = deepcopy(counts)
        bounded["exact_encoded_length_entry_count"] = 1
        bounded_safe = build_first_context_translation_encoding(
            target_sha256=SHA_A,
            review_batch_sha256=SHA_B,
            first_context_translation_capacity_sha256=SHA_C,
            runtime_context_glyph_preservation_sha256=SHA_D,
            local_encoding_sha256=SHA_A,
            combined_font_overlay_sha256=SHA_B,
            encoding=bounded,
            captured_utc=STAMP,
        )
        self.assertEqual(
            bounded_safe["status"], "first-context-translation-encoding-ready"
        )
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
        self.assertEqual(failure["approved_visible_symbol_count"], 0)
        self.assertEqual(failure["compact_visible_symbol_count"], 0)
        self.assertEqual(failure["runtime_symbol_count"], 0)
        self.assertEqual(failure["layout_control_symbol_count"], 0)
        self.assertNotIn("error", failure)
        unsafe = deepcopy(failure)
        unsafe["category"] = "private-detail"
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            validate_first_context_translation_encoding_failure(unsafe)

        legacy = deepcopy(failure)
        legacy["schema_version"] = 2
        for field in (
            "approved_visible_symbol_count",
            "compact_visible_symbol_count",
            "runtime_symbol_count",
            "layout_control_symbol_count",
        ):
            legacy.pop(field)
        validate_first_context_translation_encoding_failure(legacy)

        bounded = build_first_context_translation_encoding_failure(
            category="row-route",
            captured_utc=STAMP,
            target_encoded_bit_count=150,
            bounded_candidate_bit_count=137,
        )
        self.assertEqual(bounded["bounded_candidate_relation"], "shorter")
