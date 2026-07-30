from pathlib import Path
import hashlib
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_source_target_anchor import (  # noqa: E402
    build_source_target_anchor,
    normalize_source_line,
    resolve_sequence_anchor,
    validate_source_target_anchor,
)


class SourceTargetAnchorTests(unittest.TestCase):
    def test_normalizes_source_line_stably(self) -> None:
        self.assertEqual(
            normalize_source_line("  TEST   Line! "),
            "test line!",
        )

    def test_resolves_one_local_sequence_anchor(self) -> None:
        target_records = [
            {
                "entry_id": "before",
                "quality_tier": "translation-ready",
                "aliases": [{"selector": 2, "ordinal": 146}],
            },
            {
                "entry_id": "anchor",
                "quality_tier": "translation-ready",
                "aliases": [{"selector": 2, "ordinal": 147}],
            },
            {
                "entry_id": "after",
                "quality_tier": "glyph-recovery",
                "aliases": [{"selector": 2, "ordinal": 148}],
            },
        ]
        source_sections = [
            {
                "annotated_lines": [
                    {"speaker": "Max", "text": "Before"},
                    {"speaker": "Max", "text": "Anchor line"},
                    {"speaker": "Mishaela", "text": "After"},
                ]
            }
        ]
        anchor_digest = hashlib.sha256(b"anchor line").hexdigest()
        with patch(
            "tools.v5_1_source_target_anchor.SOURCE_LINE_SHA256",
            anchor_digest,
        ):
            counts, local = resolve_sequence_anchor(
                target_records=target_records,
                source_sections=source_sections,
            )
        self.assertEqual(counts["paired_anchor_count"], 1)
        self.assertEqual(counts["target_selector_text_record_count"], 3)
        self.assertEqual(counts["source_section_text_line_count"], 3)
        self.assertEqual(counts["translation_ready_target_window_count"], 2)
        self.assertTrue(local["single_anchor_only"])

    def test_builds_safe_anchor_without_text_or_indices(self) -> None:
        alignment = {
            "target_anchor_candidate_count": 1,
            "source_anchor_candidate_count": 1,
            "paired_anchor_count": 1,
            "target_selector_text_record_count": 120,
            "source_section_text_line_count": 80,
            "target_window_record_count": 25,
            "source_window_line_count": 25,
            "translation_ready_target_window_count": 20,
        }
        artifact = build_source_target_anchor(
            target_sha256="1" * 64,
            source_record_quality_sha256="2" * 64,
            source_script_reference_sha256="3" * 64,
            local_alignment_sha256="4" * 64,
            alignment=alignment,
            captured_utc="2026-07-30T18:30:00Z",
        )
        validate_source_target_anchor(artifact)
        self.assertEqual(
            artifact["status"],
            "source-target-sequence-anchor-resolved",
        )
        self.assertNotIn("text", artifact)
        self.assertNotIn("selector", artifact)
        self.assertFalse(artifact["translation_build_eligible"])


if __name__ == "__main__":
    unittest.main()
