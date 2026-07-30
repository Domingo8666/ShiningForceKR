#!/usr/bin/env python3
"""Tier the expanded target corpus without publishing dialogue text.

The expanded population is intentionally a superset.  This stage keeps every
record, but separates Hangul-complete translation candidates from records that
need glyph recovery or structural review.  Text, tokens, aliases, selectors,
and per-record decisions remain in ignored phone-local reports.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_target_group_expanded_corpus import (
        LOCAL_REPORT_PATH as LOCAL_CORPUS_PATH,
        PUBLISH_RELATIVE_PATH as CORPUS_PATH,
        validate_target_group_expanded_corpus,
    )
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_target_group_expanded_corpus import (
        LOCAL_REPORT_PATH as LOCAL_CORPUS_PATH,
        PUBLISH_RELATIVE_PATH as CORPUS_PATH,
        validate_target_group_expanded_corpus,
    )


ARTIFACT_KIND = "sanitized-v5-1-target-group-record-quality"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_target_group_record_quality.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_target_group_record_quality.json"
)
LOCAL_JSONL_PATH = Path(
    "reports/local/v5_1_target_group_record_quality.jsonl"
)
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_expanded_corpus_sha256",
    "local_quality_sha256",
    "captured_utc",
    "quality",
    "population_superset_retained",
    "quality_inference_only",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
QUALITY_KEYS = {
    "record_count",
    "translation_ready_record_count",
    "glyph_recovery_record_count",
    "non_hangul_review_record_count",
    "structure_review_record_count",
    "records_with_hangul_count",
    "records_with_unresolved_glyphs_count",
    "shared_alias_record_count",
    "resolved_glyph_occurrence_count",
    "hangul_glyph_occurrence_count",
    "unresolved_glyph_occurrence_count",
    "control_token_count",
}
TIERS = {
    "translation-ready",
    "glyph-recovery",
    "non-hangul-review",
    "structure-review",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _bounded_int(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def is_hangul(character: str) -> bool:
    if len(character) != 1:
        return False
    codepoint = ord(character)
    return (
        0x1100 <= codepoint <= 0x11FF
        or 0x3130 <= codepoint <= 0x318F
        or 0xA960 <= codepoint <= 0xA97F
        or 0xAC00 <= codepoint <= 0xD7A3
        or 0xD7B0 <= codepoint <= 0xD7FF
    )


def classify_expanded_records(
    records: list[dict[str, object]],
) -> tuple[dict[str, int], list[dict[str, object]]]:
    if not records:
        raise ValueError("record quality corpus is missing")
    counts = {key: 0 for key in QUALITY_KEYS}
    output: list[dict[str, object]] = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("record quality entry is invalid")
        tokens = record.get("tokens")
        aliases = record.get("aliases")
        if not isinstance(tokens, list) or not isinstance(aliases, list):
            raise ValueError("record quality local fields are missing")
        resolved = 0
        hangul = 0
        unresolved = 0
        controls = 0
        for token in tokens:
            if not isinstance(token, dict):
                raise ValueError("record quality token is invalid")
            kind = token.get("kind")
            if kind == "control":
                controls += 1
                continue
            if kind in {"page-select", "terminator"}:
                continue
            if kind != "glyph":
                raise ValueError("record quality token kind is invalid")
            text = token.get("text")
            if isinstance(text, str) and len(text) == 1:
                resolved += 1
                hangul += int(is_hangul(text))
            else:
                unresolved += 1
        declared_unresolved = record.get("unresolved_glyph_count")
        unicode_complete = record.get("unicode_complete")
        if (
            not isinstance(declared_unresolved, int)
            or isinstance(declared_unresolved, bool)
            or declared_unresolved != unresolved
            or unicode_complete is not (unresolved == 0)
        ):
            raise ValueError("record quality completeness disagrees")
        if unicode_complete and hangul > 0:
            tier = "translation-ready"
        elif hangul > 0:
            tier = "glyph-recovery"
        elif resolved > 0:
            tier = "non-hangul-review"
        else:
            tier = "structure-review"
        counts["record_count"] += 1
        counts[f"{tier.replace('-', '_')}_record_count"] += 1
        counts["records_with_hangul_count"] += int(hangul > 0)
        counts["records_with_unresolved_glyphs_count"] += int(unresolved > 0)
        counts["shared_alias_record_count"] += int(len(aliases) > 1)
        counts["resolved_glyph_occurrence_count"] += resolved
        counts["hangul_glyph_occurrence_count"] += hangul
        counts["unresolved_glyph_occurrence_count"] += unresolved
        counts["control_token_count"] += controls
        output.append(
            {
                **record,
                "quality_tier": tier,
                "quality_metrics": {
                    "resolved_glyph_count": resolved,
                    "hangul_glyph_count": hangul,
                    "unresolved_glyph_count": unresolved,
                    "control_token_count": controls,
                    "alias_count": len(aliases),
                },
            }
        )
    return counts, output


def build_target_group_record_quality(
    *,
    target_sha256: str,
    source_expanded_corpus_sha256: str,
    local_quality_sha256: str,
    quality: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    ready = int(quality["translation_ready_record_count"])
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "expanded-record-quality-tiered"
            if ready > 0
            else "expanded-record-quality-needs-review"
        ),
        "target_sha256": target_sha256,
        "source_expanded_corpus_sha256": source_expanded_corpus_sha256,
        "local_quality_sha256": local_quality_sha256,
        "captured_utc": captured_utc,
        "quality": {
            key: int(quality[key])
            for key in QUALITY_KEYS
        },
        "population_superset_retained": True,
        "quality_inference_only": True,
        "local_payload_policy": (
            "text-tokens-aliases-selectors-ordinals-and-per-record-tiers-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": (
            "pair-translation-ready-records-with-source-script"
            if ready > 0
            else "review-expanded-record-structure"
        ),
    }
    validate_target_group_record_quality(value)
    return value


def validate_target_group_record_quality(
    value: dict[str, object],
) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("record quality fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "expanded-record-quality-tiered",
            "expanded-record-quality-needs-review",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_expanded_corpus_sha256"])
        or not _is_sha256(value["local_quality_sha256"])
    ):
        raise ValueError("record quality policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("record quality timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("record quality timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("record quality timestamp needs UTC")
    quality = value["quality"]
    if not isinstance(quality, dict) or set(quality) != QUALITY_KEYS:
        raise ValueError("record quality counts do not match")
    for key in QUALITY_KEYS:
        if not _bounded_int(quality[key], 0, 0x1000000):
            raise ValueError(f"record quality {key} is invalid")
    record_count = int(quality["record_count"])
    tier_total = sum(
        int(quality[key])
        for key in (
            "translation_ready_record_count",
            "glyph_recovery_record_count",
            "non_hangul_review_record_count",
            "structure_review_record_count",
        )
    )
    ready = int(quality["translation_ready_record_count"])
    expected_status = (
        "expanded-record-quality-tiered"
        if ready > 0
        else "expanded-record-quality-needs-review"
    )
    expected_checkpoint = (
        "pair-translation-ready-records-with-source-script"
        if ready > 0
        else "review-expanded-record-structure"
    )
    if (
        record_count < 1
        or tier_total != record_count
        or quality["records_with_hangul_count"] > record_count
        or quality["records_with_unresolved_glyphs_count"] > record_count
        or quality["shared_alias_record_count"] > record_count
        or value["status"] != expected_status
        or value["next_checkpoint"] != expected_checkpoint
        or value["population_superset_retained"] is not True
        or value["quality_inference_only"] is not True
        or value["local_payload_policy"]
        != "text-tokens-aliases-selectors-ordinals-and-per-record-tiers-local-only"
        or value["translation_build_eligible"] is not False
    ):
        raise ValueError("record quality result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    safe_corpus_path = root / CORPUS_PATH
    local_corpus_path = root / LOCAL_CORPUS_PATH
    if not safe_corpus_path.is_file() or not local_corpus_path.is_file():
        if args.if_ready:
            print("Expanded target record quality is not ready")
            return 0
        raise SystemExit("expanded target record quality input is missing")
    safe_corpus = _load_json_object(safe_corpus_path)
    local_corpus = _load_json_object(local_corpus_path)
    validate_target_group_expanded_corpus(safe_corpus)
    if local_corpus.get("target_sha256") != safe_corpus["target_sha256"]:
        raise ValueError("record quality target identity disagrees")
    records = local_corpus.get("records")
    if not isinstance(records, list):
        raise ValueError("record quality local records are missing")
    counts, classified = classify_expanded_records(records)
    if (
        counts["record_count"] != safe_corpus["corpus"]["record_count"]
        or counts["unresolved_glyph_occurrence_count"]
        != safe_corpus["corpus"]["unresolved_glyph_occurrence_count"]
        or counts["control_token_count"]
        != safe_corpus["corpus"]["control_token_count"]
    ):
        raise ValueError("record quality aggregates disagree with corpus")
    local_jsonl_path = root / LOCAL_JSONL_PATH
    local_jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    local_jsonl_path.write_text(
        "".join(
            json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
            for record in classified
        ),
        encoding="utf-8",
    )
    local_quality_sha256 = hashlib.sha256(
        local_jsonl_path.read_bytes()
    ).hexdigest()
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_target_group_record_quality(
        target_sha256=str(safe_corpus["target_sha256"]),
        source_expanded_corpus_sha256=sha256_file(safe_corpus_path),
        local_quality_sha256=local_quality_sha256,
        quality=counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-target-group-record-quality",
        "schema_version": 1,
        "target_sha256": safe_corpus["target_sha256"],
        "captured_utc": captured_utc,
        "records": classified,
        "jsonl_path": str(local_jsonl_path),
        "jsonl_sha256": local_quality_sha256,
        "publication_policy": (
            "never-publish-text-tokens-aliases-selectors-ordinals-or-record-tiers"
        ),
    }
    safe_path = root / PUBLISH_RELATIVE_PATH
    local_path = root / LOCAL_REPORT_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR target group record quality: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
