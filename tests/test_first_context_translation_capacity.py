from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_first_context_translation_capacity import (  # noqa: E402
    analyze_first_context_translation_capacity,
    build_first_context_translation_capacity,
    tile_bytes_from_ink_mask,
    validate_first_context_translation_capacity,
)
from tools.v5_1_font_catalog import tile_ink_mask  # noqa: E402


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
STAMP = "2026-07-31T09:00:00Z"


def _source(index: int, text: str) -> dict[str, object]:
    return {"review_index": index, "source_text": text}


def _target(index: int, text: str) -> dict[str, object]:
    return {"review_index": index, "target_text": text}


class FirstContextTranslationCapacityTests(unittest.TestCase):
    def test_galmuri_mask_roundtrips_to_game_tile(self) -> None:
        mask = (0x00, 0x44, 0xFC, 0x96, 0x64, 0x04, 0x40, 0x7C)
        self.assertEqual(tile_ink_mask(tile_bytes_from_ink_mask(mask)), mask)

    def test_plans_one_verified_page_without_publishing_text(self) -> None:
        source_rows = [
            _source(1, "source one!"),
            _source(2, "source two?"),
            _source(3, "source three, 3!"),
            _source(4, "source four!"),
        ]
        target_rows = [
            _target(1, "가!"),
            _target(2, "나?"),
            _target(3, "다, 3!"),
            _target(4, "라!"),
        ]
        masks = {
            ord(character): tuple([index] * 8)
            for index, character in enumerate("가나다라", start=1)
        }
        catalogue = {
            "entries": [
                {
                    "status": "unique",
                    "characters": ["가"],
                }
            ]
        }
        counts, local = analyze_first_context_translation_capacity(
            source_rows=source_rows,
            target_rows=target_rows,
            font_catalog=catalogue,
            bdf_hangul=masks,
        )
        counts["font_page_changed_byte_count"] = 20
        self.assertEqual(counts["unique_hangul_syllable_count"], 4)
        self.assertEqual(counts["existing_font_exact_match_count"], 1)
        self.assertEqual(counts["existing_font_missing_count"], 3)
        self.assertEqual(counts["verified_bdf_supply_count"], 4)
        self.assertEqual(counts["source_cell_budget_fit_entry_count"], 4)
        self.assertEqual(
            counts["missing_source_observed_non_hangul_count"], 0
        )
        self.assertEqual(len(local["assignments"]), 4)
        safe = build_first_context_translation_capacity(
            target_sha256=SHA_A,
            review_batch_sha256=SHA_B,
            first_context_translation_approval_sha256=SHA_C,
            local_capacity_sha256=SHA_D,
            font_overlay_sha256=SHA_A,
            capacity=counts,
            captured_utc=STAMP,
        )
        self.assertEqual(safe["status"], "first-context-test-font-plan-ready")
        self.assertFalse(safe["translation_build_eligible"])
        self.assertNotIn("assignments", safe)
        unsafe = deepcopy(safe)
        unsafe["target_text"] = "비공개"
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_first_context_translation_capacity(unsafe)

    def test_rejects_more_than_one_page_of_hangul(self) -> None:
        characters = [chr(0xAC00 + index) for index in range(32)]
        with self.assertRaisesRegex(ValueError, "exceeds one test page"):
            analyze_first_context_translation_capacity(
                source_rows=[
                    _source(1, "x" * 40),
                    _source(2, "x" * 40),
                    _source(3, "x" * 40),
                    _source(4, "x" * 40),
                ],
                target_rows=[
                    _target(1, "".join(characters[:8])),
                    _target(2, "".join(characters[8:16])),
                    _target(3, "".join(characters[16:24])),
                    _target(4, "".join(characters[24:])),
                ],
                font_catalog={"entries": []},
                bdf_hangul={
                    ord(character): tuple([1] * 8)
                    for character in characters
                },
            )
