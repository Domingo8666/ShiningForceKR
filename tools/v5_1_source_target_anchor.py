#!/usr/bin/env python3
"""Bind the confirmed visible target record to one local source-script line.

Only the already-confirmed selector/ordinal and a SHA-256 source-line fingerprint
are used as anchors.  Source text, target text, aliases, indices, and sequence
windows remain in ignored phone-local reports.
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
    from .v5_1_source_script_reference import (
        LOCAL_REPORT_PATH as LOCAL_SOURCE_PATH,
        PUBLISH_RELATIVE_PATH as SOURCE_PATH,
        validate_source_script_reference,
    )
    from .v5_1_target_group_record_quality import (
        LOCAL_REPORT_PATH as LOCAL_QUALITY_PATH,
        PUBLISH_RELATIVE_PATH as QUALITY_PATH,
        validate_target_group_record_quality,
    )
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_source_script_reference import (
        LOCAL_REPORT_PATH as LOCAL_SOURCE_PATH,
        PUBLISH_RELATIVE_PATH as SOURCE_PATH,
        validate_source_script_reference,
    )
    from v5_1_target_group_record_quality import (
        LOCAL_REPORT_PATH as LOCAL_QUALITY_PATH,
        PUBLISH_RELATIVE_PATH as QUALITY_PATH,
        validate_target_group_record_quality,
    )


ARTIFACT_KIND = "sanitized-v5-1-source-target-anchor"
SCHEMA_VERSION = 1
CONFIRMED_SELECTOR = 2
CONFIRMED_ORDINAL = 147
SOURCE_LINE_SHA256 = (
    "93ac717a5eb94468c8558023800780a31fbfdcc974bf7104d34b93b34ac0e46b"
)
WINDOW_RADIUS = 12
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_source_target_anchor.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_source_target_anchor.json"
)
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_record_quality_sha256",
    "source_script_reference_sha256",
    "local_alignment_sha256",
    "captured_utc",
    "alignment",
    "single_anchor_only",
    "local_payload_policy",
    "source_pairing_complete",
    "speaker_assignment_complete",
    "translation_build_eligible",
    "next_checkpoint",
}
ALIGNMENT_KEYS = {
    "target_anchor_candidate_count",
    "source_anchor_candidate_count",
    "paired_anchor_count",
    "target_selector_text_record_count",
    "source_section_text_line_count",
    "target_window_record_count",
    "source_window_line_count",
    "translation_ready_target_window_count",
}


def normalize_source_line(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().casefold()


def resolve_sequence_anchor(
    *,
    target_records: list[dict[str, object]],
    source_sections: list[dict[str, object]],
) -> tuple[dict[str, int], dict[str, object]]:
    target_matches: list[dict[str, object]] = []
    selector_records: list[tuple[int, dict[str, object]]] = []
    for record in target_records:
        if not isinstance(record, dict):
            raise ValueError("source-target target record is invalid")
        aliases = record.get("aliases")
        if not isinstance(aliases, list):
            raise ValueError("source-target aliases are missing")
        selector_ordinals = [
            int(alias["ordinal"])
            for alias in aliases
            if isinstance(alias, dict)
            and alias.get("selector") == CONFIRMED_SELECTOR
            and isinstance(alias.get("ordinal"), int)
        ]
        for ordinal in selector_ordinals:
            selector_records.append((ordinal, record))
            if ordinal == CONFIRMED_ORDINAL:
                target_matches.append(record)
    selector_records.sort(key=lambda item: item[0])

    source_matches: list[tuple[int, int, dict[str, object]]] = []
    for section_index, section in enumerate(source_sections):
        if not isinstance(section, dict):
            raise ValueError("source-target source section is invalid")
        lines = section.get("annotated_lines")
        if not isinstance(lines, list):
            raise ValueError("source-target annotations are missing")
        for line_index, line in enumerate(lines):
            if not isinstance(line, dict) or not isinstance(line.get("text"), str):
                raise ValueError("source-target source line is invalid")
            digest = hashlib.sha256(
                normalize_source_line(str(line["text"])).encode("utf-8")
            ).hexdigest()
            if digest == SOURCE_LINE_SHA256:
                source_matches.append((section_index, line_index, line))

    if len(target_matches) != 1 or len(source_matches) != 1:
        raise ValueError("source-target sequence anchor is not unique")
    target_anchor = target_matches[0]
    target_anchor_index = next(
        index
        for index, (_, record) in enumerate(selector_records)
        if record is target_anchor
    )
    target_start = max(0, target_anchor_index - WINDOW_RADIUS)
    target_end = min(
        len(selector_records),
        target_anchor_index + WINDOW_RADIUS + 1,
    )
    target_window = [
        {"selector_ordinal": ordinal, "record": record}
        for ordinal, record in selector_records[target_start:target_end]
    ]
    source_section_index, source_line_index, source_anchor = source_matches[0]
    source_section = source_sections[source_section_index]
    source_lines = source_section["annotated_lines"]
    assert isinstance(source_lines, list)
    source_start = max(0, source_line_index - WINDOW_RADIUS)
    source_end = min(len(source_lines), source_line_index + WINDOW_RADIUS + 1)
    source_window = source_lines[source_start:source_end]
    ready_window = sum(
        int(item["record"].get("quality_tier") == "translation-ready")
        for item in target_window
    )
    counts = {
        "target_anchor_candidate_count": len(target_matches),
        "source_anchor_candidate_count": len(source_matches),
        "paired_anchor_count": 1,
        "target_selector_text_record_count": len(selector_records),
        "source_section_text_line_count": len(source_lines),
        "target_window_record_count": len(target_window),
        "source_window_line_count": len(source_window),
        "translation_ready_target_window_count": ready_window,
    }
    local = {
        "confirmed_selector": CONFIRMED_SELECTOR,
        "confirmed_ordinal": CONFIRMED_ORDINAL,
        "source_line_sha256": SOURCE_LINE_SHA256,
        "target_anchor": target_anchor,
        "source_anchor": source_anchor,
        "source_section_index": source_section_index,
        "source_line_index": source_line_index,
        "target_window": target_window,
        "source_window": source_window,
        "single_anchor_only": True,
    }
    return counts, local


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


def build_source_target_anchor(
    *,
    target_sha256: str,
    source_record_quality_sha256: str,
    source_script_reference_sha256: str,
    local_alignment_sha256: str,
    alignment: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    resolved = (
        alignment["target_anchor_candidate_count"] == 1
        and alignment["source_anchor_candidate_count"] == 1
        and alignment["paired_anchor_count"] == 1
    )
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "source-target-sequence-anchor-resolved"
            if resolved
            else "source-target-sequence-anchor-unresolved"
        ),
        "target_sha256": target_sha256,
        "source_record_quality_sha256": source_record_quality_sha256,
        "source_script_reference_sha256": source_script_reference_sha256,
        "local_alignment_sha256": local_alignment_sha256,
        "captured_utc": captured_utc,
        "alignment": {
            key: int(alignment[key])
            for key in ALIGNMENT_KEYS
        },
        "single_anchor_only": True,
        "local_payload_policy": (
            "source-target-text-speakers-aliases-selectors-ordinals-indices-and-windows-local-only"
        ),
        "source_pairing_complete": False,
        "speaker_assignment_complete": False,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "align-records-within-anchored-sequence-window"
            if resolved
            else "capture-additional-source-target-anchor"
        ),
    }
    validate_source_target_anchor(value)
    return value


def validate_source_target_anchor(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("source-target anchor fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "source-target-sequence-anchor-resolved",
            "source-target-sequence-anchor-unresolved",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "source_record_quality_sha256",
                "source_script_reference_sha256",
                "local_alignment_sha256",
            )
        )
    ):
        raise ValueError("source-target anchor policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("source-target anchor timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("source-target anchor timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("source-target anchor timestamp needs UTC")
    alignment = value["alignment"]
    if not isinstance(alignment, dict) or set(alignment) != ALIGNMENT_KEYS:
        raise ValueError("source-target anchor counts do not match")
    for key in ALIGNMENT_KEYS:
        if not _bounded_int(alignment[key], 0, 0x1000000):
            raise ValueError(f"source-target anchor {key} is invalid")
    resolved = (
        alignment["target_anchor_candidate_count"] == 1
        and alignment["source_anchor_candidate_count"] == 1
        and alignment["paired_anchor_count"] == 1
    )
    expected_status = (
        "source-target-sequence-anchor-resolved"
        if resolved
        else "source-target-sequence-anchor-unresolved"
    )
    expected_checkpoint = (
        "align-records-within-anchored-sequence-window"
        if resolved
        else "capture-additional-source-target-anchor"
    )
    if (
        alignment["paired_anchor_count"]
        > min(
            alignment["target_anchor_candidate_count"],
            alignment["source_anchor_candidate_count"],
        )
        or alignment["translation_ready_target_window_count"]
        > alignment["target_window_record_count"]
        or value["status"] != expected_status
        or value["next_checkpoint"] != expected_checkpoint
        or value["single_anchor_only"] is not True
        or value["local_payload_policy"]
        != "source-target-text-speakers-aliases-selectors-ordinals-indices-and-windows-local-only"
        or value["source_pairing_complete"] is not False
        or value["speaker_assignment_complete"] is not False
        or value["translation_build_eligible"] is not False
    ):
        raise ValueError("source-target anchor result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = (
        root / QUALITY_PATH,
        root / LOCAL_QUALITY_PATH,
        root / SOURCE_PATH,
        root / LOCAL_SOURCE_PATH,
    )
    if not all(path.is_file() for path in paths):
        if args.if_ready:
            print("Source-target sequence anchor is not ready")
            return 0
        raise SystemExit("source-target sequence anchor input is missing")
    safe_quality = _load_json_object(paths[0])
    local_quality = _load_json_object(paths[1])
    safe_source = _load_json_object(paths[2])
    local_source = _load_json_object(paths[3])
    validate_target_group_record_quality(safe_quality)
    validate_source_script_reference(safe_source)
    if (
        local_quality.get("target_sha256") != safe_quality["target_sha256"]
        or safe_source["source_host"] != "www.shiningforcecentral.com"
    ):
        raise ValueError("source-target sequence anchor identity disagrees")
    target_records = local_quality.get("records")
    source_sections = local_source.get("sections")
    if not isinstance(target_records, list) or not isinstance(
        source_sections, list
    ):
        raise ValueError("source-target sequence anchor local inputs are missing")
    alignment, local_alignment = resolve_sequence_anchor(
        target_records=target_records,
        source_sections=source_sections,
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    local = {
        "artifact_kind": "local-v5-1-source-target-anchor",
        "schema_version": 1,
        "target_sha256": safe_quality["target_sha256"],
        "captured_utc": captured_utc,
        "alignment": local_alignment,
        "publication_policy": (
            "never-publish-source-target-text-speakers-aliases-selectors-ordinals-indices-or-windows"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    local_alignment_sha256 = hashlib.sha256(local_path.read_bytes()).hexdigest()
    safe = build_source_target_anchor(
        target_sha256=str(safe_quality["target_sha256"]),
        source_record_quality_sha256=sha256_file(paths[0]),
        source_script_reference_sha256=sha256_file(paths[2]),
        local_alignment_sha256=local_alignment_sha256,
        alignment=alignment,
        captured_utc=captured_utc,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR source-target sequence anchor: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
