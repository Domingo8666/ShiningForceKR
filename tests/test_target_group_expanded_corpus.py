from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_target_group_expanded_corpus import (  # noqa: E402
    attach_record_storage,
    build_target_group_expanded_corpus,
    validate_target_group_expanded_corpus,
)


class TargetGroupExpandedCorpusTests(unittest.TestCase):
    def test_attaches_private_record_storage_for_reinsertion(self) -> None:
        corpus = [{"entry_id": "population-record-0001"}]
        aliases = [{"selector": 2, "ordinal": 147}]
        attach_record_storage(
            corpus,
            [
                {
                    "entry_id": "population-record-0001",
                    "length_offset": 0x12345,
                    "record_length_bytes": 17,
                    "payload_sha256": "a" * 64,
                    "aliases": aliases,
                }
            ],
        )
        self.assertEqual(corpus[0]["length_offset"], 0x12345)
        self.assertEqual(corpus[0]["record_length_bytes"], 17)
        self.assertEqual(corpus[0]["payload_sha256"], "a" * 64)
        self.assertEqual(corpus[0]["aliases"], aliases)
        self.assertTrue(corpus[0]["population_superset"])

    def test_rejects_missing_private_record_storage(self) -> None:
        with self.assertRaisesRegex(ValueError, "storage is missing"):
            attach_record_storage(
                [{"entry_id": "population-record-0001"}],
                [
                    {
                        "entry_id": "population-record-0001",
                        "aliases": [],
                    }
                ],
            )

    def test_builds_safe_incomplete_corpus(self) -> None:
        artifact = build_target_group_expanded_corpus(
            target_sha256="1" * 64,
            source_population_decode_sha256="2" * 64,
            source_expanded_glyphs_sha256="3" * 64,
            source_non_hangul_glyphs_sha256="4" * 64,
            local_corpus_sha256="5" * 64,
            corpus={
                "record_count": 625,
                "complete_unicode_record_count": 300,
                "incomplete_unicode_record_count": 325,
                "empty_text_record_count": 0,
                "unicode_character_count": 2452,
                "control_token_count": 700,
                "unresolved_glyph_occurrence_count": 1104,
                "high_confidence_override_occurrence_count": 0,
                "exact_non_hangul_override_occurrence_count": 0,
            },
            captured_utc="2026-07-30T17:00:00Z",
        )
        validate_target_group_expanded_corpus(artifact)
        self.assertEqual(
            artifact["status"],
            "expanded-target-corpus-with-unresolved-glyphs",
        )
        self.assertFalse(artifact["translation_build_eligible"])
        self.assertEqual(
            artifact["hancharacter_contract_mode"],
            "translator_declared",
        )

    def test_rejects_local_text_and_aliases(self) -> None:
        artifact = build_target_group_expanded_corpus(
            target_sha256="1" * 64,
            source_population_decode_sha256="2" * 64,
            source_expanded_glyphs_sha256="3" * 64,
            source_non_hangul_glyphs_sha256="4" * 64,
            local_corpus_sha256="5" * 64,
            corpus={
                "record_count": 1,
                "complete_unicode_record_count": 1,
                "incomplete_unicode_record_count": 0,
                "empty_text_record_count": 0,
                "unicode_character_count": 4,
                "control_token_count": 1,
                "unresolved_glyph_occurrence_count": 0,
                "high_confidence_override_occurrence_count": 0,
                "exact_non_hangul_override_occurrence_count": 0,
            },
            captured_utc="2026-07-30T17:00:00Z",
        )
        for field, local_value in (
            ("text", "기다려라"),
            ("aliases", [{"selector": 2, "ordinal": 147}]),
            ("tokens", [{"kind": "glyph"}]),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = local_value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_target_group_expanded_corpus(unsafe)


if __name__ == "__main__":
    unittest.main()
