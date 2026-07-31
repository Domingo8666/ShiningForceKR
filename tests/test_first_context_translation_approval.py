from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_first_context_translation_approval import (  # noqa: E402
    approval_counts,
    build_first_context_translation_approval,
    build_local_first_context_translation_approval,
    migrate_legacy_local_approval,
    normalize_approved_targets,
    validate_first_context_translation_approval,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
STAMP = "2026-07-31T08:00:00Z"


class FirstContextTranslationApprovalTests(unittest.TestCase):
    def test_builds_local_only_human_approval_and_safe_counts(self) -> None:
        targets = normalize_approved_targets(
            ["대상 하나", "대상 둘", "대상 셋", "대상 넷"],
            expected_count=4,
        )
        local = build_local_first_context_translation_approval(
            target_sha256=SHA_A,
            review_batch_sha256=SHA_B,
            targets=targets,
            captured_utc=STAMP,
        )
        counts = approval_counts(local, context_entry_count=4)
        self.assertEqual(counts["approved_entry_count"], 4)
        self.assertGreater(counts["unique_hangul_syllable_count"], 0)
        safe = build_first_context_translation_approval(
            target_sha256=SHA_A,
            review_batch_sha256=SHA_B,
            local_approval_sha256=SHA_C,
            approval=counts,
            captured_utc=STAMP,
        )
        self.assertEqual(
            safe["status"], "first-context-translation-human-approved"
        )
        self.assertTrue(safe["human_approval_recorded"])
        self.assertFalse(safe["translation_build_eligible"])
        self.assertNotIn("rows", safe)
        self.assertNotIn("target_text", safe)

    def test_rejects_wrong_batch_size(self) -> None:
        with self.assertRaisesRegex(ValueError, "line count"):
            normalize_approved_targets(["대상 하나"], expected_count=4)

    def test_rejects_safe_text_leak(self) -> None:
        local = build_local_first_context_translation_approval(
            target_sha256=SHA_A,
            review_batch_sha256=SHA_B,
            targets=["가", "나", "다", "라"],
            captured_utc=STAMP,
        )
        safe = build_first_context_translation_approval(
            target_sha256=SHA_A,
            review_batch_sha256=SHA_B,
            local_approval_sha256=SHA_C,
            approval=approval_counts(local, context_entry_count=4),
            captured_utc=STAMP,
        )
        unsafe = deepcopy(safe)
        unsafe["target_text"] = "비공개"
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_first_context_translation_approval(unsafe)

    def test_migrates_timestamp_bound_legacy_local_approval(self) -> None:
        legacy = {
            "artifact_kind": "local-v5-1-first-context-translation-approval",
            "schema_version": 1,
            "target_sha256": SHA_A,
            "first_context_translation_review_sha256": SHA_B,
            "first_context_local_review_sha256": SHA_C,
            "captured_utc": STAMP,
            "approval_label": "A-recommended",
            "approval_authority": "human-user-explicit",
            "hancharacter_contract_mode": "translator_declared",
            "rows": [
                {"review_index": index, "target_text": target}
                for index, target in enumerate(
                    ["대상 하나", "대상 둘", "대상 셋", "대상 넷"],
                    start=1,
                )
            ],
            "publication_policy": (
                "never-publish-source-text-speakers-target-text-selectors-"
                "ordinals-indices-screens-translations-or-review-cards"
            ),
        }
        migrated = migrate_legacy_local_approval(
            legacy,
            target_sha256=SHA_A,
            review_batch_sha256=SHA_B,
        )
        self.assertEqual(migrated["schema_version"], 2)
        self.assertEqual(migrated["review_batch_sha256"], SHA_B)
        self.assertNotIn(
            "first_context_translation_review_sha256", migrated
        )
