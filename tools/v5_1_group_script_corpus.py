#!/usr/bin/env python3
"""Assemble a provisional target-script corpus from resolved group records.

Text, symbols, glyph coordinates, control values, and per-record metadata stay
in ignored phone-local JSON/JSONL files.  The safe receipt publishes only
aggregate completeness and provenance.
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
    from .v5_1_group_text_candidate_resolution import (
        LOCAL_REPORT_PATH as LOCAL_TEXT_CANDIDATE_PATH,
        PUBLISH_RELATIVE_PATH as TEXT_CANDIDATE_PATH,
        validate_group_text_candidate_resolution,
    )
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_unmatched_glyph_fuzzy import (
        LOCAL_REPORT_PATH as LOCAL_FUZZY_PATH,
        PUBLISH_RELATIVE_PATH as FUZZY_PATH,
        validate_unmatched_glyph_fuzzy,
    )
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from v5_1_group_text_candidate_resolution import (
        LOCAL_REPORT_PATH as LOCAL_TEXT_CANDIDATE_PATH,
        PUBLISH_RELATIVE_PATH as TEXT_CANDIDATE_PATH,
        validate_group_text_candidate_resolution,
    )
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_unmatched_glyph_fuzzy import (
        LOCAL_REPORT_PATH as LOCAL_FUZZY_PATH,
        PUBLISH_RELATIVE_PATH as FUZZY_PATH,
        validate_unmatched_glyph_fuzzy,
    )


ARTIFACT_KIND = "sanitized-v5-1-group-script-corpus"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_group_script_corpus.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_group_script_corpus.json")
LOCAL_JSONL_PATH = Path("reports/local/v5_1_group_script_corpus.jsonl")
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_text_candidate_sha256",
    "source_fuzzy_glyph_sha256",
    "local_corpus_sha256",
    "captured_utc",
    "group",
    "corpus",
    "hancharacter_contract_mode",
    "source_pairing_complete",
    "speaker_assignment_complete",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
GROUP_KEYS = {
    "selector",
    "candidate_record_count",
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


def assemble_script_corpus(
    *,
    records: list[dict[str, object]],
    fuzzy_overrides: list[dict[str, object]],
) -> tuple[dict[str, int], list[dict[str, object]]]:
    if not records:
        raise ValueError("script corpus records are missing")
    override_index: dict[tuple[int, int], dict[str, object]] = {}
    for override in fuzzy_overrides:
        if not isinstance(override, dict):
            raise ValueError("script corpus fuzzy override is invalid")
        page = override.get("page")
        symbol = override.get("symbol")
        character = override.get("character")
        if (
            not isinstance(page, int)
            or not isinstance(symbol, int)
            or not isinstance(character, str)
            or len(character) != 1
        ):
            raise ValueError("script corpus fuzzy override fields are invalid")
        override_index[(page, symbol)] = override

    complete_count = 0
    empty_count = 0
    unicode_characters = 0
    control_tokens = 0
    unresolved_occurrences = 0
    override_occurrences = 0
    corpus: list[dict[str, object]] = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("script corpus record is invalid")
        tokens = record.get("tokens")
        if not isinstance(tokens, list):
            raise ValueError("script corpus tokens are missing")
        text_parts: list[str] = []
        local_tokens: list[dict[str, object]] = []
        record_unresolved = 0
        record_overrides = 0
        for token in tokens:
            if not isinstance(token, dict):
                raise ValueError("script corpus token is invalid")
            kind = token.get("kind")
            if kind == "page-select" or kind == "terminator":
                local_tokens.append(token)
                continue
            if kind == "control":
                symbol = token.get("symbol")
                if not isinstance(symbol, int):
                    raise ValueError("script corpus control is invalid")
                marker = f"⟦CTRL:{symbol:02X}⟧"
                text_parts.append(marker)
                control_tokens += 1
                local_tokens.append({**token, "text": marker})
                continue
            if kind != "glyph":
                raise ValueError("script corpus token kind is invalid")
            page = token.get("page")
            symbol = token.get("symbol")
            status = token.get("status")
            if not isinstance(page, int) or not isinstance(symbol, int):
                raise ValueError("script corpus glyph coordinate is invalid")
            characters = token.get("characters")
            character: str | None = None
            source = status
            if (
                status == "unique"
                and isinstance(characters, list)
                and len(characters) == 1
                and isinstance(characters[0], str)
                and len(characters[0]) == 1
            ):
                character = characters[0]
            else:
                override = override_index.get((page, symbol))
                if override is not None:
                    character = str(override["character"])
                    source = "fuzzy-high-confidence"
                    override_occurrences += 1
                    record_overrides += 1
            if character is None:
                marker = f"⟦GLYPH:{page:02X}:{symbol:02X}⟧"
                text_parts.append(marker)
                unresolved_occurrences += 1
                record_unresolved += 1
                local_tokens.append({**token, "text": marker})
            else:
                text_parts.append(character)
                unicode_characters += 1
                local_tokens.append(
                    {
                        **token,
                        "text": character,
                        "resolution_source": source,
                    }
                )
        text = "".join(text_parts)
        empty_count += int(not text)
        complete = record_unresolved == 0
        complete_count += int(complete)
        corpus.append(
            {
                "entry_id": record.get("entry_id"),
                "ordinal": record.get("ordinal"),
                "speaker_id": None,
                "source_text": None,
                "translation_text": text,
                "unicode_complete": complete,
                "unresolved_glyph_count": record_unresolved,
                "fuzzy_override_count": record_overrides,
                "quality_inferred_stream": True,
                "tokens": local_tokens,
            }
        )
    counts = {
        "record_count": len(corpus),
        "complete_unicode_record_count": complete_count,
        "incomplete_unicode_record_count": len(corpus) - complete_count,
        "empty_text_record_count": empty_count,
        "unicode_character_count": unicode_characters,
        "control_token_count": control_tokens,
        "unresolved_glyph_occurrence_count": unresolved_occurrences,
        "high_confidence_override_occurrence_count": override_occurrences,
    }
    return counts, corpus


def build_group_script_corpus(
    *,
    target_sha256: str,
    source_text_candidate_sha256: str,
    source_fuzzy_glyph_sha256: str,
    local_corpus_sha256: str,
    selector: int,
    candidate_record_count: int,
    corpus: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    complete = int(corpus["incomplete_unicode_record_count"]) == 0
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "provisional-target-corpus-unicode-complete"
            if complete
            else "provisional-target-corpus-with-unresolved-glyphs"
        ),
        "target_sha256": target_sha256,
        "source_text_candidate_sha256": source_text_candidate_sha256,
        "source_fuzzy_glyph_sha256": source_fuzzy_glyph_sha256,
        "local_corpus_sha256": local_corpus_sha256,
        "captured_utc": captured_utc,
        "group": {
            "selector": selector,
            "candidate_record_count": candidate_record_count,
        },
        "corpus": {
            key: int(corpus[key])
            for key in CORPUS_KEYS
        },
        "hancharacter_contract_mode": "translator_declared",
        "source_pairing_complete": False,
        "speaker_assignment_complete": False,
        "local_payload_policy": (
            "symbols-glyphs-controls-source-target-text-and-speakers-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": "extract-source-script-pairs-and-speaker-ids",
    }
    validate_group_script_corpus(safe)
    return safe


def validate_group_script_corpus(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("group script corpus fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "provisional-target-corpus-unicode-complete",
            "provisional-target-corpus-with-unresolved-glyphs",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "source_text_candidate_sha256",
                "source_fuzzy_glyph_sha256",
                "local_corpus_sha256",
            )
        )
    ):
        raise ValueError("group script corpus policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("group script corpus timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("group script corpus timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("group script corpus timestamp must include UTC")
    group = value["group"]
    if not isinstance(group, dict) or set(group) != GROUP_KEYS:
        raise ValueError("group script corpus group fields do not match")
    if (
        not _bounded_int(group["selector"], 0, 0xFFFF)
        or not _bounded_int(group["candidate_record_count"], 1, 0xFF)
    ):
        raise ValueError("group script corpus group is invalid")
    corpus = value["corpus"]
    if not isinstance(corpus, dict) or set(corpus) != CORPUS_KEYS:
        raise ValueError("group script corpus counts do not match")
    for key in CORPUS_KEYS:
        if not _bounded_int(corpus[key], 0, 0x1000000):
            raise ValueError(f"group script corpus {key} is invalid")
    record_count = int(corpus["record_count"])
    if (
        record_count != group["candidate_record_count"]
        or corpus["complete_unicode_record_count"]
        + corpus["incomplete_unicode_record_count"] != record_count
        or corpus["empty_text_record_count"] > record_count
    ):
        raise ValueError("group script corpus aggregates are inconsistent")
    expected_status = (
        "provisional-target-corpus-unicode-complete"
        if corpus["incomplete_unicode_record_count"] == 0
        else "provisional-target-corpus-with-unresolved-glyphs"
    )
    if (
        value["status"] != expected_status
        or value["hancharacter_contract_mode"] != "translator_declared"
        or value["source_pairing_complete"] is not False
        or value["speaker_assignment_complete"] is not False
        or value["local_payload_policy"]
        != "symbols-glyphs-controls-source-target-text-and-speakers-local-only"
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != "extract-source-script-pairs-and-speaker-ids"
    ):
        raise ValueError("group script corpus result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    safe_text_path = root / TEXT_CANDIDATE_PATH
    local_text_path = root / LOCAL_TEXT_CANDIDATE_PATH
    fuzzy_path = root / FUZZY_PATH
    local_fuzzy_path = root / LOCAL_FUZZY_PATH
    prerequisites = (
        safe_text_path,
        local_text_path,
        fuzzy_path,
        local_fuzzy_path,
    )
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Group script corpus is not ready")
            return 0
        raise SystemExit("group script corpus input is missing")
    safe_text = _load_json_object(safe_text_path)
    local_text = _load_json_object(local_text_path)
    fuzzy = _load_json_object(fuzzy_path)
    local_fuzzy = _load_json_object(local_fuzzy_path)
    validate_group_text_candidate_resolution(safe_text)
    validate_unmatched_glyph_fuzzy(fuzzy)
    if (
        fuzzy["target_sha256"] != safe_text["target_sha256"]
        or fuzzy["source_text_candidate_sha256"]
        != sha256_file(safe_text_path)
        or local_text.get("target_sha256") != safe_text["target_sha256"]
        or local_fuzzy.get("target_sha256") != safe_text["target_sha256"]
    ):
        raise ValueError("group script corpus identities disagree")
    records = local_text.get("analysis", {}).get("resolved_records")
    overrides = local_fuzzy.get("analysis", {}).get(
        "high_confidence_overrides"
    )
    if not isinstance(records, list) or not isinstance(overrides, list):
        raise ValueError("group script corpus local data is missing")
    counts, corpus_records = assemble_script_corpus(
        records=records,
        fuzzy_overrides=overrides,
    )
    if (
        counts["record_count"]
        != safe_text["resolution"]["unique_best_record_count"]
        or counts["unresolved_glyph_occurrence_count"]
        != fuzzy["unmatched"]["occurrence_count"]
        - fuzzy["unmatched"]["high_confidence_occurrence_count"]
    ):
        raise ValueError("group script corpus counts changed")
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    jsonl_bytes = (
        "\n".join(
            json.dumps(record, ensure_ascii=False, sort_keys=True)
            for record in corpus_records
        )
        + "\n"
    ).encode("utf-8")
    local_corpus_sha256 = hashlib.sha256(jsonl_bytes).hexdigest()
    group = safe_text["group"]
    assert isinstance(group, dict)
    safe = build_group_script_corpus(
        target_sha256=str(safe_text["target_sha256"]),
        source_text_candidate_sha256=sha256_file(safe_text_path),
        source_fuzzy_glyph_sha256=sha256_file(fuzzy_path),
        local_corpus_sha256=local_corpus_sha256,
        selector=int(group["selector"]),
        candidate_record_count=len(corpus_records),
        corpus=counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-group-script-corpus",
        "schema_version": 1,
        "target_sha256": safe_text["target_sha256"],
        "captured_utc": captured_utc,
        "records": corpus_records,
        "jsonl_sha256": local_corpus_sha256,
        "publication_policy": (
            "never-publish-symbols-glyphs-controls-source-target-text-or-speakers"
        ),
    }
    safe_path = root / PUBLISH_RELATIVE_PATH
    local_path = root / LOCAL_REPORT_PATH
    jsonl_path = root / LOCAL_JSONL_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    jsonl_path.write_bytes(jsonl_bytes)
    print(f"SFKR group script corpus: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
