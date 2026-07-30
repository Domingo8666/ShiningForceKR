from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_target_group_record_quality import (  # noqa: E402
    build_target_group_record_quality,
    classify_expanded_records,
    is_hangul,
    validate_target_group_record_quality,
)


def glyph(text: str) -> dict[str, object]:
    return {"kind": "glyph", "text": text}


class TargetGroupRecordQualityTests(unittest.TestCase):
    def test_detects_modern_and_compatibility_hangul(self) -> None:
        self.assertTrue(is_hangul("한"))
        self.assertTrue(is_hangul("ㄱ"))
        self.assertFalse(is_hangul("A"))

    def test_tiers_records_without_dropping_population(self) -> None:
        records = [
            {
                "entry_id": "ready",
                "unicode_complete": True,
                "unresolved_glyph_count": 0,
                "tokens": [glyph("한"), glyph("글")],
                "aliases": [{"selector": 1, "ordinal": 2}],
            },
            {
                "entry_id": "recover",
                "unicode_complete": False,
                "unresolved_glyph_count": 1,
                "tokens": [glyph("한"), glyph("⟦GLYPH:01:02⟧")],
                "aliases": [
                    {"selector": 1, "ordinal": 3},
                    {"selector": 2, "ordinal": 4},
                ],
            },
            {
                "entry_id": "latin",
                "unicode_complete": True,
                "unresolved_glyph_count": 0,
                "tokens": [glyph("A")],
                "aliases": [],
            },
            {
                "entry_id": "structure",
                "unicode_complete": False,
                "unresolved_glyph_count": 1,
                "tokens": [
                    {"kind": "control", "text": "⟦CTRL:01⟧"},
                    glyph("⟦GLYPH:01:03⟧"),
                ],
                "aliases": [],
            },
        ]
        counts, classified = classify_expanded_records(deepcopy(records))
        self.assertEqual(counts["record_count"], 4)
        self.assertEqual(counts["translation_ready_record_count"], 1)
        self.assertEqual(counts["glyph_recovery_record_count"], 1)
        self.assertEqual(counts["non_hangul_review_record_count"], 1)
        self.assertEqual(counts["structure_review_record_count"], 1)
        self.assertEqual(counts["shared_alias_record_count"], 1)
        self.assertEqual(counts["unresolved_glyph_occurrence_count"], 2)
        self.assertEqual(
            {record["quality_tier"] for record in classified},
            {
                "translation-ready",
                "glyph-recovery",
                "non-hangul-review",
                "structure-review",
            },
        )

    def test_builds_safe_aggregate_only(self) -> None:
        quality = {
            "record_count": 4,
            "translation_ready_record_count": 1,
            "glyph_recovery_record_count": 1,
            "non_hangul_review_record_count": 1,
            "structure_review_record_count": 1,
            "records_with_hangul_count": 2,
            "records_with_unresolved_glyphs_count": 2,
            "shared_alias_record_count": 1,
            "resolved_glyph_occurrence_count": 4,
            "hangul_glyph_occurrence_count": 3,
            "unresolved_glyph_occurrence_count": 2,
            "control_token_count": 1,
        }
        artifact = build_target_group_record_quality(
            target_sha256="1" * 64,
            source_expanded_corpus_sha256="2" * 64,
            local_quality_sha256="3" * 64,
            quality=quality,
            captured_utc="2026-07-30T17:30:00Z",
        )
        validate_target_group_record_quality(artifact)
        self.assertEqual(artifact["status"], "expanded-record-quality-tiered")
        self.assertNotIn("records", artifact)
        self.assertFalse(artifact["translation_build_eligible"])


if __name__ == "__main__":
    unittest.main()
