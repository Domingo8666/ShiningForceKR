from copy import deepcopy
import hashlib
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_source_target_anchor import normalize_source_line  # noqa: E402
from tools.v5_1_source_target_section_projection import (  # noqa: E402
    build_source_target_section_projection,
    build_human_review_rows,
    project_anchored_section,
    render_human_review_text,
    validate_local_quality_identity,
    validate_source_target_section_projection,
)


class SourceTargetSectionProjectionTests(unittest.TestCase):
    def test_projects_complete_section_by_relative_anchor_offset(self) -> None:
        anchor_text = "synthetic anchor"
        anchor_hash = hashlib.sha256(
            normalize_source_line(anchor_text).encode("utf-8")
        ).hexdigest()
        target_records = []
        tiers = [
            "structure-review",
            "translation-ready",
            "glyph-recovery",
            "translation-ready",
            "non-hangul-review",
        ]
        for index, tier in enumerate(tiers):
            target_records.append(
                {
                    "entry_id": f"entry-{index}",
                    "aliases": [
                        {"selector": 7, "ordinal": 145 + index}
                    ],
                    "quality_tier": tier,
                }
            )
        source_sections = [
            {
                "annotated_lines": [
                    {"speaker": "speaker-a", "text": "before"},
                    {"speaker": "speaker-a", "text": anchor_text},
                    {"speaker": None, "text": "after"},
                ]
            }
        ]
        counts, local = project_anchored_section(
            target_records=target_records,
            source_sections=source_sections,
            confirmed_selector=7,
            confirmed_ordinal=147,
            source_line_sha256=anchor_hash,
        )
        self.assertEqual(counts["projected_pair_count"], 3)
        self.assertEqual(counts["translation_ready_pair_count"], 2)
        self.assertEqual(counts["speaker_labeled_pair_count"], 2)
        self.assertEqual(counts["narration_pair_count"], 1)
        self.assertEqual(
            [pair["target_ordinal"] for pair in local["pairs"]],
            [146, 147, 148],
        )

    def test_builds_candidate_only_safe_receipt(self) -> None:
        artifact = build_source_target_section_projection(
            target_sha256="1" * 64,
            source_record_quality_sha256="2" * 64,
            source_script_reference_sha256="3" * 64,
            source_target_anchor_sha256="4" * 64,
            local_projection_sha256="5" * 64,
            projection={
                "target_selector_record_count": 216,
                "duplicate_target_ordinal_count": 0,
                "source_section_line_count": 79,
                "anchor_pair_count": 1,
                "projected_pair_count": 79,
                "out_of_range_source_line_count": 0,
                "translation_ready_pair_count": 20,
                "glyph_recovery_pair_count": 50,
                "structure_review_pair_count": 9,
                "non_hangul_review_pair_count": 0,
                "speaker_labeled_pair_count": 75,
                "narration_pair_count": 4,
            },
            captured_utc="2026-07-30T22:00:00Z",
        )
        validate_source_target_section_projection(artifact)
        self.assertEqual(
            artifact["status"],
            "anchored-section-projection-ready",
        )
        self.assertTrue(artifact["human_review_required"])
        self.assertFalse(artifact["source_pairing_complete"])
        unsafe = deepcopy(artifact)
        unsafe["source_text"] = "must remain local"
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_source_target_section_projection(unsafe)

    def test_local_quality_identity_uses_the_jsonl_payload_hash(self) -> None:
        with TemporaryDirectory() as directory:
            jsonl_path = Path(directory) / "quality.jsonl"
            jsonl_path.write_text('{"quality_tier":"translation-ready"}\n', encoding="utf-8")
            digest = hashlib.sha256(jsonl_path.read_bytes()).hexdigest()
            validate_local_quality_identity(
                quality={"local_quality_sha256": digest},
                local_quality={"jsonl_sha256": digest},
                local_quality_jsonl_path=jsonl_path,
            )
            summary_path = Path(directory) / "quality.json"
            summary_path.write_text('{"jsonl_sha256":"different"}\n', encoding="utf-8")
            self.assertNotEqual(
                hashlib.sha256(summary_path.read_bytes()).hexdigest(),
                digest,
            )

    def test_local_quality_identity_rejects_a_changed_jsonl_payload(self) -> None:
        with TemporaryDirectory() as directory:
            jsonl_path = Path(directory) / "quality.jsonl"
            jsonl_path.write_text('{"quality_tier":"glyph-recovery"}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "local quality identity"):
                validate_local_quality_identity(
                    quality={"local_quality_sha256": "1" * 64},
                    local_quality={"jsonl_sha256": "1" * 64},
                    local_quality_jsonl_path=jsonl_path,
                )

    def test_builds_a_local_only_human_review_packet(self) -> None:
        rows = build_human_review_rows(
            [
                {
                    "pair_index": 0,
                    "target_selector": 2,
                    "target_ordinal": 147,
                    "source_text": "Synthetic source.",
                    "speaker": "speaker-a",
                    "target_record": {
                        "translation_text": "가상 문장",
                        "quality_tier": "translation-ready",
                    },
                },
                {
                    "pair_index": 1,
                    "target_selector": 2,
                    "target_ordinal": 148,
                    "source_text": "Synthetic narration.",
                    "speaker": None,
                    "target_record": {
                        "translation_text": "가상 나레이션",
                        "quality_tier": "glyph-recovery",
                    },
                },
            ]
        )
        text = render_human_review_text(
            packet_id="0123456789ab",
            rows=rows,
        )
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["pairing_decision"], "unreviewed")
        self.assertEqual(rows[0]["approved_korean_text"], "")
        self.assertIn("연결 판정: [ ] 승인  [ ] 거부  [ ] 보류", text)
        self.assertIn("화자: (나레이션)", text)
        self.assertIn("승인된 번역이 아닙니다", text)


if __name__ == "__main__":
    unittest.main()
