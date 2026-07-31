from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_first_context_translation_encoding import (  # noqa: E402
    build_character_assignments,
    build_first_context_translation_encoding,
    build_symbol_rows,
    validate_first_context_translation_encoding,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
STAMP = "2026-07-31T10:00:00Z"


class FirstContextTranslationEncodingTests(unittest.TestCase):
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

    def test_builds_safe_ready_receipt_without_local_payload(self) -> None:
        counts = {
            "context_entry_count": 4,
            "target_character_count": 20,
            "unique_target_character_count": 10,
            "custom_font_page_count": 2,
            "custom_font_glyph_count": 10,
            "preserved_non_text_glyph_occurrence_count": 5,
            "planned_visible_symbol_count": 25,
            "planned_page_select_count": 8,
            "planned_terminator_count": 4,
            "planned_total_symbol_count": 53,
            "huffman_roundtrip_entry_count": 4,
            "huffman_failure_entry_count": 0,
            "encoded_bit_count": 300,
            "encoded_byte_count": 40,
            "maximum_encoded_entry_bit_count": 90,
            "font_page_write_byte_count": 320,
            "font_page_changed_byte_count": 200,
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
        self.assertFalse(safe["translation_build_eligible"])
        unsafe = deepcopy(safe)
        unsafe["encoded_bytes"] = "private"
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_first_context_translation_encoding(unsafe)
