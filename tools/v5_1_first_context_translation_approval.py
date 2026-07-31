#!/usr/bin/env python3
"""Record and validate the first human-approved translation batch.

The four target strings stay in an ignored phone-local JSON file.  The
publishable receipt contains only fixed aggregate counts and hashes.  This
stage records an explicit human decision; it does not claim that a
translator-declared rendering is an established published precedent.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unicodedata

try:
    from .patch_io import sha256_file
    from .v5_1_first_context_translation_review import (
        LOCAL_REPORT_PATH as LOCAL_REVIEW_PATH,
        PUBLISH_RELATIVE_PATH as REVIEW_PATH,
        first_context_review_batch_sha256,
        validate_first_context_translation_review,
    )
    from .v5_1_renderer_output_trace import _load_json_object
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_first_context_translation_review import (
        LOCAL_REPORT_PATH as LOCAL_REVIEW_PATH,
        PUBLISH_RELATIVE_PATH as REVIEW_PATH,
        first_context_review_batch_sha256,
        validate_first_context_translation_review,
    )
    from v5_1_renderer_output_trace import _load_json_object


ARTIFACT_KIND = "sanitized-v5-1-first-context-translation-approval"
LOCAL_ARTIFACT_KIND = "local-v5-1-first-context-translation-approval"
SCHEMA_VERSION = 2
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_translation_approval.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_first_context_translation_approval.json"
)
APPROVAL_LABEL = "A-recommended"
COUNT_KEYS = {
    "context_entry_count",
    "approved_entry_count",
    "nonempty_target_entry_count",
    "target_character_count",
    "hangul_syllable_count",
    "unique_hangul_syllable_count",
}
SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "review_batch_sha256",
    "local_approval_sha256",
    "captured_utc",
    "approval",
    "human_approval_recorded",
    "human_approval_scope",
    "approval_authority",
    "hancharacter_contract_mode",
    "hancharacter_claim_scope",
    "translation_generated_by_mechanical_stage",
    "source_and_target_text_local_only",
    "non_text_glyph_preservation_required",
    "translation_build_eligible",
    "next_checkpoint",
}
LOCAL_FIELDS = {
    "artifact_kind",
    "schema_version",
    "target_sha256",
    "review_batch_sha256",
    "captured_utc",
    "approval_label",
    "approval_authority",
    "hancharacter_contract_mode",
    "rows",
    "publication_policy",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return timestamp.utcoffset() == timezone.utc.utcoffset(timestamp)


def _is_hangul_syllable(character: str) -> bool:
    return "\uac00" <= character <= "\ud7a3"


def normalize_approved_targets(
    lines: list[str], *, expected_count: int
) -> list[str]:
    targets = [unicodedata.normalize("NFC", line.strip()) for line in lines]
    if len(targets) != expected_count:
        raise ValueError(
            "approved translation line count does not match the review batch"
        )
    for target in targets:
        if (
            not target
            or len(target) > 160
            or "\n" in target
            or "\r" in target
            or any(
                unicodedata.category(character) in {"Cc", "Cs"}
                for character in target
            )
        ):
            raise ValueError("approved translation target is invalid")
    if not any(
        _is_hangul_syllable(character)
        for target in targets
        for character in target
    ):
        raise ValueError("approved translation batch contains no Hangul syllables")
    return targets


def build_local_first_context_translation_approval(
    *,
    target_sha256: str,
    review_batch_sha256: str,
    targets: list[str],
    captured_utc: str,
) -> dict[str, object]:
    value: dict[str, object] = {
        "artifact_kind": LOCAL_ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "target_sha256": target_sha256,
        "review_batch_sha256": review_batch_sha256,
        "captured_utc": captured_utc,
        "approval_label": APPROVAL_LABEL,
        "approval_authority": "human-user-explicit",
        "hancharacter_contract_mode": "translator_declared",
        "rows": [
            {"review_index": index, "target_text": target}
            for index, target in enumerate(targets, start=1)
        ],
        "publication_policy": (
            "never-publish-source-text-speakers-target-text-selectors-ordinals-"
            "indices-screens-translations-or-review-cards"
        ),
    }
    validate_local_first_context_translation_approval(value)
    return value


def validate_local_first_context_translation_approval(
    value: dict[str, object],
) -> None:
    if set(value) != LOCAL_FIELDS:
        raise ValueError("local translation approval fields do not match")
    if (
        value["artifact_kind"] != LOCAL_ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "review_batch_sha256",
            )
        )
        or not _is_utc_timestamp(value["captured_utc"])
        or value["approval_label"] != APPROVAL_LABEL
        or value["approval_authority"] != "human-user-explicit"
        or value["hancharacter_contract_mode"] != "translator_declared"
        or value["publication_policy"]
        != (
            "never-publish-source-text-speakers-target-text-selectors-ordinals-"
            "indices-screens-translations-or-review-cards"
        )
    ):
        raise ValueError("local translation approval identity is invalid")
    rows = value["rows"]
    if not isinstance(rows, list) or not rows:
        raise ValueError("local translation approval rows are missing")
    targets: list[str] = []
    for expected_index, row in enumerate(rows, start=1):
        if (
            not isinstance(row, dict)
            or set(row) != {"review_index", "target_text"}
            or row["review_index"] != expected_index
            or not isinstance(row["target_text"], str)
        ):
            raise ValueError("local translation approval row is invalid")
        targets.append(row["target_text"])
    normalize_approved_targets(targets, expected_count=len(rows))


def approval_counts(
    local_approval: dict[str, object],
    *,
    context_entry_count: int,
) -> dict[str, int]:
    validate_local_first_context_translation_approval(local_approval)
    rows = local_approval["rows"]
    assert isinstance(rows, list)
    targets = [str(row["target_text"]) for row in rows]
    hangul = [
        character
        for target in targets
        for character in target
        if _is_hangul_syllable(character)
    ]
    return {
        "context_entry_count": context_entry_count,
        "approved_entry_count": len(rows),
        "nonempty_target_entry_count": sum(bool(target) for target in targets),
        "target_character_count": sum(len(target) for target in targets),
        "hangul_syllable_count": len(hangul),
        "unique_hangul_syllable_count": len(set(hangul)),
    }


def build_first_context_translation_approval(
    *,
    target_sha256: str,
    review_batch_sha256: str,
    local_approval_sha256: str,
    approval: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    ready = (
        approval["context_entry_count"] >= 4
        and approval["approved_entry_count"]
        == approval["context_entry_count"]
        and approval["nonempty_target_entry_count"]
        == approval["context_entry_count"]
        and approval["target_character_count"] > 0
        and approval["hangul_syllable_count"] > 0
        and approval["unique_hangul_syllable_count"] > 0
    )
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "first-context-translation-human-approved"
            if ready
            else "first-context-translation-approval-incomplete"
        ),
        "target_sha256": target_sha256,
        "review_batch_sha256": review_batch_sha256,
        "local_approval_sha256": local_approval_sha256,
        "captured_utc": captured_utc,
        "approval": approval,
        "human_approval_recorded": ready,
        "human_approval_scope": "first-context-four-entry-batch",
        "approval_authority": "human-user-explicit",
        "hancharacter_contract_mode": "translator_declared",
        "hancharacter_claim_scope": (
            "translator-declared-rendering-consistency-only"
        ),
        "translation_generated_by_mechanical_stage": False,
        "source_and_target_text_local_only": True,
        "non_text_glyph_preservation_required": True,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "validate-first-context-translation-capacity"
            if ready
            else "repair-first-context-translation-approval"
        ),
    }
    validate_first_context_translation_approval(value)
    return value


def validate_first_context_translation_approval(
    value: dict[str, object],
) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError("translation approval fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "first-context-translation-human-approved",
            "first-context-translation-approval-incomplete",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "review_batch_sha256",
                "local_approval_sha256",
            )
        )
        or not _is_utc_timestamp(value["captured_utc"])
    ):
        raise ValueError("translation approval identity is invalid")
    counts = value["approval"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("translation approval counts do not match")
    if any(
        not isinstance(count, int)
        or isinstance(count, bool)
        or count < 0
        or count > 1000000
        for count in counts.values()
    ):
        raise ValueError("translation approval count is invalid")
    ready = (
        counts["context_entry_count"] >= 4
        and counts["approved_entry_count"] == counts["context_entry_count"]
        and counts["nonempty_target_entry_count"]
        == counts["context_entry_count"]
        and counts["target_character_count"] > 0
        and counts["hangul_syllable_count"] > 0
        and counts["unique_hangul_syllable_count"] > 0
    )
    if (
        value["status"]
        != (
            "first-context-translation-human-approved"
            if ready
            else "first-context-translation-approval-incomplete"
        )
        or value["human_approval_recorded"] is not ready
        or value["human_approval_scope"] != "first-context-four-entry-batch"
        or value["approval_authority"] != "human-user-explicit"
        or value["hancharacter_contract_mode"] != "translator_declared"
        or value["hancharacter_claim_scope"]
        != "translator-declared-rendering-consistency-only"
        or value["translation_generated_by_mechanical_stage"] is not False
        or value["source_and_target_text_local_only"] is not True
        or value["non_text_glyph_preservation_required"] is not True
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != (
            "validate-first-context-translation-capacity"
            if ready
            else "repair-first-context-translation-approval"
        )
    ):
        raise ValueError("translation approval result is inconsistent")


def migrate_legacy_local_approval(
    value: dict[str, object],
    *,
    target_sha256: str,
    review_batch_sha256: str,
) -> dict[str, object]:
    legacy_fields = {
        "artifact_kind",
        "schema_version",
        "target_sha256",
        "first_context_translation_review_sha256",
        "first_context_local_review_sha256",
        "captured_utc",
        "approval_label",
        "approval_authority",
        "hancharacter_contract_mode",
        "rows",
        "publication_policy",
    }
    if set(value) != legacy_fields or value.get("schema_version") != 1:
        return value
    if (
        value.get("artifact_kind") != LOCAL_ARTIFACT_KIND
        or value.get("target_sha256") != target_sha256
        or value.get("approval_label") != APPROVAL_LABEL
        or value.get("approval_authority") != "human-user-explicit"
        or value.get("hancharacter_contract_mode") != "translator_declared"
        or not _is_utc_timestamp(value.get("captured_utc"))
        or value.get("publication_policy")
        != (
            "never-publish-source-text-speakers-target-text-selectors-ordinals-"
            "indices-screens-translations-or-review-cards"
        )
        or not isinstance(value.get("rows"), list)
    ):
        raise ValueError("legacy local translation approval is invalid")
    rows = value["rows"]
    assert isinstance(rows, list)
    targets = []
    for expected_index, row in enumerate(rows, start=1):
        if (
            not isinstance(row, dict)
            or set(row) != {"review_index", "target_text"}
            or row.get("review_index") != expected_index
            or not isinstance(row.get("target_text"), str)
        ):
            raise ValueError("legacy local translation approval row is invalid")
        targets.append(row["target_text"])
    targets = normalize_approved_targets(
        targets,
        expected_count=len(rows),
    )
    return build_local_first_context_translation_approval(
        target_sha256=target_sha256,
        review_batch_sha256=review_batch_sha256,
        targets=targets,
        captured_utc=str(value["captured_utc"]),
    )


def _load_review_inputs(root: Path) -> tuple[dict[str, object], Path]:
    safe_path = root / REVIEW_PATH
    local_path = root / LOCAL_REVIEW_PATH
    if not safe_path.is_file() or not local_path.is_file():
        raise ValueError("first context translation review input is missing")
    safe = _load_json_object(safe_path)
    local = _load_json_object(local_path)
    validate_first_context_translation_review(safe)
    if (
        local.get("target_sha256") != safe["target_sha256"]
        or local.get("review") != safe["review"]
        or local.get("html_sha256") != safe["local_review_packet_sha256"]
        or local.get("review_batch_sha256") != safe["review_batch_sha256"]
        or not isinstance(local.get("rows"), list)
        or len(local["rows"]) != safe["review"]["context_entry_count"]
        or first_context_review_batch_sha256(local["rows"])
        != safe["review_batch_sha256"]
    ):
        raise ValueError("first context translation review identity disagrees")
    return safe, local_path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record-approved-stdin", action="store_true")
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    try:
        review, local_review_path = _load_review_inputs(root)
    except ValueError as error:
        if args.if_ready and "input is missing" in str(error):
            print("First context translation approval is not ready")
            return 0
        raise
    local_path = root / LOCAL_REPORT_PATH
    if args.record_approved_stdin:
        lines = sys.stdin.read().splitlines()
        targets = normalize_approved_targets(
            lines,
            expected_count=int(review["review"]["context_entry_count"]),
        )
        captured_utc = datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
        local = build_local_first_context_translation_approval(
            target_sha256=str(review["target_sha256"]),
            review_batch_sha256=str(review["review_batch_sha256"]),
            targets=targets,
            captured_utc=captured_utc,
        )
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text(
            json.dumps(local, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    if not local_path.is_file():
        if args.if_ready:
            print("First context translation approval is not ready")
            return 0
        raise SystemExit(
            "local first context translation approval input is missing"
        )
    local = migrate_legacy_local_approval(
        _load_json_object(local_path),
        target_sha256=str(review["target_sha256"]),
        review_batch_sha256=str(review["review_batch_sha256"]),
    )
    if local.get("schema_version") == SCHEMA_VERSION:
        local_path.write_text(
            json.dumps(local, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    validate_local_first_context_translation_approval(local)
    if (
        local["target_sha256"] != review["target_sha256"]
        or local["review_batch_sha256"] != review["review_batch_sha256"]
    ):
        raise ValueError("first context translation approval identity disagrees")
    counts = approval_counts(
        local,
        context_entry_count=int(review["review"]["context_entry_count"]),
    )
    safe = build_first_context_translation_approval(
        target_sha256=str(review["target_sha256"]),
        review_batch_sha256=str(review["review_batch_sha256"]),
        local_approval_sha256=sha256_file(local_path),
        approval=counts,
        captured_utc=str(local["captured_utc"]),
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR first context translation approval: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
