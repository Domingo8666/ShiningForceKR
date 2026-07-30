from __future__ import annotations

from pathlib import Path
import unittest

from tools.patch_io import PatchError
from tools.v5_1_poc_expansion import (
    EXPANSION_PHRASE,
    build_expanded_phrase_plan,
)


ROOT = Path(__file__).resolve().parents[1]


def visible_proof() -> dict[str, object]:
    return {
        "artifact_kind": "sanitized-s25u-visible-entry-proof",
        "schema_version": 1,
        "status": "exact-visible-entry-confirmed",
        "purpose": "technical-poc-only",
        "baseline_target_sha256": (
            "5dc9d1aef40c8fea4e9374ddf12a7e6eff4fb5d77fe66d53"
            "61d78059186adb39"
        ),
        "test_target_sha256": (
            "fc063d908ab52b17af2f07a6c904a1cce71270ea28126a178"
            "0de3d7c28c03711"
        ),
        "phrase_codepoints": ["U+D55C", "U+B2E4"],
        "runtime_entry": {
            "kind": "runtime-length-prefixed-entry",
            "selection_basis": (
                "decoder-register-proven-length-prefixed-skip-loop"
            ),
            "physical_start": 133395,
            "logical_start": 18707,
            "mapped_bank": 8,
            "group_pointer_address": 17374,
            "length_prefix_logical_address": 18706,
            "record_length_bytes": 16,
            "skipped_record_count": 147,
            "symbol_count": 19,
            "encoded_bits": 100,
            "roundtrip_exact": True,
        },
        "display_proof": {
            "capture_png_sha256": "1" * 64,
            "new_technical_marker_matches": 1,
            "review_result": "phrase-visible-pass",
            "phrase_visible": True,
            "surrounding_text_readable": True,
            "portrait_intact": True,
            "dialogue_box_intact": True,
        },
        "translation_build_eligible": False,
        "next_checkpoint": "expand-poc-to-multiple-visible-glyphs",
    }


class PocExpansionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.patch = (
            ROOT / "patch" / "Final_Conflict_Japan_to_Korean_v5.1.bps"
        ).read_bytes()

    def test_builds_four_glyph_exact_length_plan(self) -> None:
        plan = build_expanded_phrase_plan(
            self.patch,
            100,
            visible_proof(),
        )
        self.assertEqual(plan["phrase"], EXPANSION_PHRASE)
        self.assertEqual(len(plan["font"]["glyphs"]), 4)
        self.assertEqual(plan["encoding"]["base_encoded_bits"], 44)
        self.assertEqual(plan["encoding"]["encoded_bits"], 100)
        self.assertTrue(plan["encoding"]["roundtrip_exact"])
        self.assertEqual(
            plan["next_checkpoint"],
            "cold-boot-and-confirm-expanded-poc-on-screen",
        )

    def test_rejects_a_different_runtime_bit_budget(self) -> None:
        with self.assertRaisesRegex(PatchError, "bit budget"):
            build_expanded_phrase_plan(
                self.patch,
                99,
                visible_proof(),
            )


if __name__ == "__main__":
    unittest.main()
