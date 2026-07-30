#!/usr/bin/env python3
"""Assemble the quality-selected target population into a local text corpus.

Text, symbols, glyph coordinates, controls, selectors, ordinals, aliases, and
per-record metadata stay in ignored phone-local JSON/JSONL files.  The safe
receipt publishes aggregate completeness only.
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
    from .v5_1_group_script_corpus import assemble_script_corpus
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_target_group_population_decode import (
        LOCAL_REPORT_PATH as LOCAL_DECODE_PATH,
        PUBLISH_RELATIVE_PATH as DECODE_PATH,
        validate_target_group_population_decode,
    )
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from v5_1_group_script_corpus import assemble_script_corpus
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_target_group_population_decode import (
        LOCAL_REPORT_PATH as LOCAL_DECODE_PATH,
        PUBLISH_RELATIVE_PATH as DECODE_PATH,
        validate_target_group_population_decode,
    )


ARTIFACT_KIND = "sanitized-v5-1-target-group-expanded-corpus"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_target_group_expanded_corpus.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_target_group_expanded_corpus.json"
)
LOCAL_JSONL_PATH = Path(
    "reports/local/v5_1_target_group_expanded_corpus.jsonl"
)
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_population_decode_sha256",
    "local_corpus_sha256",
    "captured_utc",
    "corpus",
    "population_superset",
    "quality_inference_only",
    "hancharacter_contract_mode",
    "source_pairing_complete",
    "speaker_assignment_complete",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
CORPUS_KEYS = {
    "record_count",
    "complete_unicode_record_count",
    "incomplete_unicode_record_count",
    "empty_text_record_count",
    "unicode_character_count",
    "control_token_count",
    "unresolved_glyph_occurrence_count",
    "high_confidence_override_occurrence_count",
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


def build_target_group_expanded_corpus(
    *,
    target_sha256: str,
    source_population_decode_sha256: str,
    local_corpus_sha256: str,
    corpus: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    complete = int(corpus["incomplete_unicode_record_count"]) == 0
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "expanded-target-corpus-unicode-complete"
            if complete
            else "expanded-target-corpus-with-unresolved-glyphs"
        ),
        "target_sha256": target_sha256,
        "source_population_decode_sha256":
            source_population_decode_sha256,
        "local_corpus_sha256": local_corpus_sha256,
        "captured_utc": captured_utc,
        "corpus": {
            key: int(corpus[key])
            for key in CORPUS_KEYS
        },
        "population_superset": True,
        "quality_inference_only": True,
        "hancharacter_contract_mode": "translator_declared",
        "source_pairing_complete": False,
        "speaker_assignment_complete": False,
        "local_payload_policy": (
            "text-symbols-glyphs-controls-selectors-ordinals-aliases-source-and-speakers-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": (
            "pair-expanded-corpus-with-source-script-and-speakers"
            if complete
            else "classify-expanded-corpus-unresolved-glyphs"
        ),
    }
    validate_target_group_expanded_corpus(value)
    return value


def validate_target_group_expanded_corpus(
    value: dict[str, object],
) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("expanded target corpus fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "expanded-target-corpus-unicode-complete",
            "expanded-target-corpus-with-unresolved-glyphs",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_population_decode_sha256"])
        or not _is_sha256(value["local_corpus_sha256"])
    ):
        raise ValueError("expanded target corpus policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("expanded target corpus timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(
            "expanded target corpus timestamp is invalid"
        ) from error
    if parsed.tzinfo is None:
        raise ValueError("expanded target corpus timestamp needs UTC")
    corpus = value["corpus"]
    if not isinstance(corpus, dict) or set(corpus) != CORPUS_KEYS:
        raise ValueError("expanded target corpus counts do not match")
    for key in CORPUS_KEYS:
        if not _bounded_int(corpus[key], 0, 0x1000000):
            raise ValueError(f"expanded target corpus {key} is invalid")
    record_count = int(corpus["record_count"])
    if (
        record_count < 1
        or corpus["complete_unicode_record_count"]
        + corpus["incomplete_unicode_record_count"]
        != record_count
        or corpus["empty_text_record_count"] > record_count
    ):
        raise ValueError("expanded target corpus aggregates disagree")
    complete = int(corpus["incomplete_unicode_record_count"]) == 0
    expected_status = (
        "expanded-target-corpus-unicode-complete"
        if complete
        else "expanded-target-corpus-with-unresolved-glyphs"
    )
    expected_checkpoint = (
        "pair-expanded-corpus-with-source-script-and-speakers"
        if complete
        else "classify-expanded-corpus-unresolved-glyphs"
    )
    if (
        value["status"] != expected_status
        or value["next_checkpoint"] != expected_checkpoint
        or value["population_superset"] is not True
        or value["quality_inference_only"] is not True
        or value["hancharacter_contract_mode"] != "translator_declared"
        or value["source_pairing_complete"] is not False
        or value["speaker_assignment_complete"] is not False
        or value["local_payload_policy"]
        != "text-symbols-glyphs-controls-selectors-ordinals-aliases-source-and-speakers-local-only"
        or value["translation_build_eligible"] is not False
    ):
        raise ValueError("expanded target corpus result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    safe_decode_path = root / DECODE_PATH
    local_decode_path = root / LOCAL_DECODE_PATH
    if not safe_decode_path.is_file() or not local_decode_path.is_file():
        if args.if_ready:
            print("Expanded target group corpus is not ready")
            return 0
        raise SystemExit("expanded target corpus input is missing")
    safe_decode = _load_json_object(safe_decode_path)
    local_decode = _load_json_object(local_decode_path)
    validate_target_group_population_decode(safe_decode)
    if local_decode.get("target_sha256") != safe_decode["target_sha256"]:
        raise ValueError("expanded target corpus identity disagrees")
    quality = local_decode.get("quality_analysis")
    source_records = local_decode.get("records")
    if not isinstance(quality, dict) or not isinstance(source_records, list):
        raise ValueError("expanded target corpus local inputs are missing")
    resolved = quality.get("resolved_records")
    if not isinstance(resolved, list) or not resolved:
        if args.if_ready:
            print("Expanded target group corpus has no resolved records")
            return 0
        raise ValueError("expanded target corpus records are missing")
    aliases_by_id = {
        str(record.get("entry_id")): record.get("aliases", [])
        for record in source_records
        if isinstance(record, dict)
    }
    counts, corpus = assemble_script_corpus(
        records=resolved,
        fuzzy_overrides=[],
    )
    for record in corpus:
        record["aliases"] = aliases_by_id.get(
            str(record.get("entry_id")),
            [],
        )
        record["population_superset"] = True
    if counts["record_count"] != safe_decode["decode"][
        "unique_best_text_record_count"
    ]:
        raise ValueError("expanded target corpus record count disagrees")
    local_jsonl_path = root / LOCAL_JSONL_PATH
    local_jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    jsonl = "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        for record in corpus
    )
    local_jsonl_path.write_text(jsonl, encoding="utf-8")
    local_corpus_sha256 = hashlib.sha256(
        local_jsonl_path.read_bytes()
    ).hexdigest()
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_target_group_expanded_corpus(
        target_sha256=str(safe_decode["target_sha256"]),
        source_population_decode_sha256=sha256_file(safe_decode_path),
        local_corpus_sha256=local_corpus_sha256,
        corpus=counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-target-group-expanded-corpus",
        "schema_version": 1,
        "target_sha256": safe_decode["target_sha256"],
        "captured_utc": captured_utc,
        "records": corpus,
        "jsonl_path": str(local_jsonl_path),
        "jsonl_sha256": local_corpus_sha256,
        "publication_policy": (
            "never-publish-text-symbols-glyphs-controls-selectors-ordinals-aliases-source-or-speakers"
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
    print(f"SFKR expanded target group corpus: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
