from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_group_script_corpus import (  # noqa: E402
    assemble_script_corpus,
    build_group_script_corpus,
    validate_group_script_corpus,
)


class GroupScriptCorpusTests(unittest.TestCase):
    def test_assembles_exact_text_and_explicit_unresolved_markers(self) -> None:
        counts, corpus = assemble_script_corpus(
            records=[
                {
                    "entry_id": "group-02/000",
                    "ordinal": 0,
                    "tokens": [
                        {
                            "kind": "glyph",
                            "page": 0,
                            "symbol": 2,
                            "status": "unique",
                            "characters": ["가"],
                        },
                        {"kind": "control", "symbol": 0xD0},
                        {
                            "kind": "glyph",
                            "page": 1,
                            "symbol": 3,
                            "status": "unmatched",
                            "characters": [],
                        },
                    ],
                },
                {
                    "entry_id": "group-02/001",
                    "ordinal": 1,
                    "tokens": [
                        {
                            "kind": "glyph",
                            "page": 2,
                            "symbol": 4,
                            "status": "unmatched",
                            "characters": [],
                        }
                    ],
                },
            ],
            fuzzy_overrides=[
                {
                    "page": 2,
                    "symbol": 4,
                    "character": "나",
                    "resolution_source": "exact-non-hangul-bdf",
                },
            ],
        )
        self.assertEqual(counts["record_count"], 2)
        self.assertEqual(counts["complete_unicode_record_count"], 1)
        self.assertEqual(counts["incomplete_unicode_record_count"], 1)
        self.assertEqual(counts["unicode_character_count"], 2)
        self.assertEqual(counts["control_token_count"], 1)
        self.assertEqual(counts["unresolved_glyph_occurrence_count"], 1)
        self.assertEqual(
            counts["high_confidence_override_occurrence_count"],
            1,
        )
        self.assertEqual(
            corpus[0]["translation_text"],
            "가⟦CTRL:D0⟧⟦GLYPH:01:03⟧",
        )
        self.assertEqual(corpus[1]["translation_text"], "나")
        self.assertEqual(
            corpus[1]["tokens"][0]["resolution_source"],
            "exact-non-hangul-bdf",
        )

    def test_builds_safe_counts_and_rejects_text_leakage(self) -> None:
        artifact = build_group_script_corpus(
            target_sha256="1" * 64,
            source_text_candidate_sha256="2" * 64,
            source_fuzzy_glyph_sha256="3" * 64,
            local_corpus_sha256="4" * 64,
            selector=2,
            candidate_record_count=2,
            corpus={
                "record_count": 2,
                "complete_unicode_record_count": 1,
                "incomplete_unicode_record_count": 1,
                "empty_text_record_count": 0,
                "unicode_character_count": 2,
                "control_token_count": 1,
                "unresolved_glyph_occurrence_count": 1,
                "high_confidence_override_occurrence_count": 1,
            },
            captured_utc="2026-07-30T18:00:00Z",
        )
        validate_group_script_corpus(artifact)
        self.assertEqual(
            artifact["status"],
            "provisional-target-corpus-with-unresolved-glyphs",
        )
        self.assertEqual(
            artifact["hancharacter_contract_mode"],
            "translator_declared",
        )
        for field, value in (
            ("translation_text", "가"),
            ("source_text", "待て"),
            ("symbols", [2, 0xD0]),
            ("speaker_id", "hero"),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_group_script_corpus(unsafe)


if __name__ == "__main__":
    unittest.main()
