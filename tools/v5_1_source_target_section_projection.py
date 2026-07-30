#!/usr/bin/env python3
"""Project one source-script section onto target records around a unique anchor.

The projection is a review candidate, not an approved translation pairing.
Source and target text, speakers, aliases, ordinals, section indices, and every
candidate pair stay in ignored phone-local files.  The safe receipt publishes
only aggregate counts and dependency hashes.
"""

from __future__ import annotations

import argparse
from collections import Counter
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
    from .v5_1_source_target_anchor import (
        CONFIRMED_ORDINAL,
        CONFIRMED_SELECTOR,
        LOCAL_REPORT_PATH as LOCAL_ANCHOR_PATH,
        PUBLISH_RELATIVE_PATH as ANCHOR_PATH,
        SOURCE_LINE_SHA256,
        normalize_source_line,
        validate_source_target_anchor,
    )
    from .v5_1_target_group_record_quality import (
        LOCAL_REPORT_PATH as LOCAL_QUALITY_PATH,
        PUBLISH_RELATIVE_PATH as QUALITY_PATH,
        TIERS,
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
    from v5_1_source_target_anchor import (
        CONFIRMED_ORDINAL,
        CONFIRMED_SELECTOR,
        LOCAL_REPORT_PATH as LOCAL_ANCHOR_PATH,
        PUBLISH_RELATIVE_PATH as ANCHOR_PATH,
        SOURCE_LINE_SHA256,
        normalize_source_line,
        validate_source_target_anchor,
    )
    from v5_1_target_group_record_quality import (
        LOCAL_REPORT_PATH as LOCAL_QUALITY_PATH,
        PUBLISH_RELATIVE_PATH as QUALITY_PATH,
        TIERS,
        validate_target_group_record_quality,
    )


ARTIFACT_KIND = "sanitized-v5-1-source-target-section-projection"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_source_target_section_projection.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_source_target_section_projection.json"
)
LOCAL_JSONL_PATH = Path(
    "reports/local/v5_1_source_target_section_projection.jsonl"
)
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_record_quality_sha256",
    "source_script_reference_sha256",
    "source_target_anchor_sha256",
    "local_projection_sha256",
    "captured_utc",
    "projection",
    "single_anchor_projection_only",
    "candidate_pairing_only",
    "human_review_required",
    "hancharacter_contract_mode",
    "local_payload_policy",
    "source_pairing_complete",
    "speaker_assignment_complete",
    "translation_build_eligible",
    "next_checkpoint",
}
PROJECTION_KEYS = {
    "target_selector_record_count",
    "duplicate_target_ordinal_count",
    "source_section_line_count",
    "anchor_pair_count",
    "projected_pair_count",
    "out_of_range_source_line_count",
    "translation_ready_pair_count",
    "glyph_recovery_pair_count",
    "structure_review_pair_count",
    "non_hangul_review_pair_count",
    "speaker_labeled_pair_count",
    "narration_pair_count",
}


def _source_digest(text: str) -> str:
    return hashlib.sha256(
        normalize_source_line(text).encode("utf-8")
    ).hexdigest()


def project_anchored_section(
    *,
    target_records: list[dict[str, object]],
    source_sections: list[dict[str, object]],
    confirmed_selector: int = CONFIRMED_SELECTOR,
    confirmed_ordinal: int = CONFIRMED_ORDINAL,
    source_line_sha256: str = SOURCE_LINE_SHA256,
) -> tuple[dict[str, int], dict[str, object]]:
    selector_records: list[tuple[int, dict[str, object]]] = []
    for record in target_records:
        if not isinstance(record, dict):
            raise ValueError("section projection target record is invalid")
        aliases = record.get("aliases")
        if not isinstance(aliases, list):
            raise ValueError("section projection target aliases are missing")
        for alias in aliases:
            if (
                isinstance(alias, dict)
                and alias.get("selector") == confirmed_selector
                and isinstance(alias.get("ordinal"), int)
            ):
                selector_records.append((int(alias["ordinal"]), record))
    selector_records.sort(key=lambda item: item[0])
    ordinal_counts = Counter(ordinal for ordinal, _ in selector_records)
    duplicate_ordinals = sum(
        count - 1
        for count in ordinal_counts.values()
        if count > 1
    )
    target_anchor_indices = [
        index
        for index, (ordinal, _) in enumerate(selector_records)
        if ordinal == confirmed_ordinal
    ]

    source_matches: list[tuple[int, int, dict[str, object]]] = []
    for section_index, section in enumerate(source_sections):
        if not isinstance(section, dict):
            raise ValueError("section projection source section is invalid")
        lines = section.get("annotated_lines")
        if not isinstance(lines, list):
            raise ValueError("section projection source annotations are missing")
        for line_index, line in enumerate(lines):
            if not isinstance(line, dict) or not isinstance(
                line.get("text"), str
            ):
                raise ValueError("section projection source line is invalid")
            if _source_digest(str(line["text"])) == source_line_sha256:
                source_matches.append((section_index, line_index, line))
    if len(target_anchor_indices) != 1 or len(source_matches) != 1:
        raise ValueError("section projection anchor is not unique")

    target_anchor_index = target_anchor_indices[0]
    source_section_index, source_anchor_index, _ = source_matches[0]
    source_section = source_sections[source_section_index]
    source_lines = source_section["annotated_lines"]
    assert isinstance(source_lines, list)
    tier_counts = {tier: 0 for tier in TIERS}
    pairs: list[dict[str, object]] = []
    out_of_range = 0
    speaker_labeled = 0
    narration = 0
    for source_line_index, source_line in enumerate(source_lines):
        assert isinstance(source_line, dict)
        relative_offset = source_line_index - source_anchor_index
        target_index = target_anchor_index + relative_offset
        if not 0 <= target_index < len(selector_records):
            out_of_range += 1
            continue
        target_ordinal, target_record = selector_records[target_index]
        tier = target_record.get("quality_tier")
        if tier not in TIERS:
            raise ValueError("section projection target quality tier is invalid")
        tier_counts[str(tier)] += 1
        speaker = source_line.get("speaker")
        if speaker is None:
            narration += 1
        elif isinstance(speaker, str) and speaker:
            speaker_labeled += 1
        else:
            raise ValueError("section projection source speaker is invalid")
        pairs.append(
            {
                "pair_index": len(pairs),
                "relative_offset": relative_offset,
                "target_selector": confirmed_selector,
                "target_ordinal": target_ordinal,
                "target_record": target_record,
                "source_section_index": source_section_index,
                "source_line_index": source_line_index,
                "source_text": source_line["text"],
                "speaker": speaker,
                "pairing_basis": "single-anchor-relative-offset",
                "review_status": "unreviewed",
            }
        )
    counts = {
        "target_selector_record_count": len(selector_records),
        "duplicate_target_ordinal_count": duplicate_ordinals,
        "source_section_line_count": len(source_lines),
        "anchor_pair_count": 1,
        "projected_pair_count": len(pairs),
        "out_of_range_source_line_count": out_of_range,
        "translation_ready_pair_count": tier_counts["translation-ready"],
        "glyph_recovery_pair_count": tier_counts["glyph-recovery"],
        "structure_review_pair_count": tier_counts["structure-review"],
        "non_hangul_review_pair_count": tier_counts["non-hangul-review"],
        "speaker_labeled_pair_count": speaker_labeled,
        "narration_pair_count": narration,
    }
    return counts, {
        "confirmed_selector": confirmed_selector,
        "confirmed_ordinal": confirmed_ordinal,
        "source_line_sha256": source_line_sha256,
        "target_anchor_index": target_anchor_index,
        "source_section_index": source_section_index,
        "source_anchor_line_index": source_anchor_index,
        "pairs": pairs,
        "candidate_pairing_only": True,
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


def build_source_target_section_projection(
    *,
    target_sha256: str,
    source_record_quality_sha256: str,
    source_script_reference_sha256: str,
    source_target_anchor_sha256: str,
    local_projection_sha256: str,
    projection: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    ready = (
        projection["anchor_pair_count"] == 1
        and projection["duplicate_target_ordinal_count"] == 0
        and projection["out_of_range_source_line_count"] == 0
        and projection["projected_pair_count"]
        == projection["source_section_line_count"]
    )
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "anchored-section-projection-ready"
            if ready
            else "anchored-section-projection-incomplete"
        ),
        "target_sha256": target_sha256,
        "source_record_quality_sha256": source_record_quality_sha256,
        "source_script_reference_sha256": source_script_reference_sha256,
        "source_target_anchor_sha256": source_target_anchor_sha256,
        "local_projection_sha256": local_projection_sha256,
        "captured_utc": captured_utc,
        "projection": {
            key: int(projection[key])
            for key in PROJECTION_KEYS
        },
        "single_anchor_projection_only": True,
        "candidate_pairing_only": True,
        "human_review_required": True,
        "hancharacter_contract_mode": "translator_declared",
        "local_payload_policy": (
            "source-target-text-speakers-aliases-selectors-ordinals-indices-and-pairs-local-only"
        ),
        "source_pairing_complete": False,
        "speaker_assignment_complete": False,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "human-review-anchored-section-projection"
            if ready
            else "capture-additional-source-target-anchor"
        ),
    }
    validate_source_target_section_projection(value)
    return value


def validate_source_target_section_projection(
    value: dict[str, object],
) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("section projection fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "anchored-section-projection-ready",
            "anchored-section-projection-incomplete",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "source_record_quality_sha256",
                "source_script_reference_sha256",
                "source_target_anchor_sha256",
                "local_projection_sha256",
            )
        )
    ):
        raise ValueError("section projection policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("section projection timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("section projection timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("section projection timestamp needs UTC")
    projection = value["projection"]
    if (
        not isinstance(projection, dict)
        or set(projection) != PROJECTION_KEYS
    ):
        raise ValueError("section projection counts do not match")
    for key in PROJECTION_KEYS:
        if not _bounded_int(projection[key], 0, 0x1000000):
            raise ValueError(f"section projection {key} is invalid")
    projected = int(projection["projected_pair_count"])
    ready = (
        projection["anchor_pair_count"] == 1
        and projection["duplicate_target_ordinal_count"] == 0
        and projection["out_of_range_source_line_count"] == 0
        and projected == projection["source_section_line_count"]
    )
    if (
        projection["anchor_pair_count"] > projected
        or projected
        + projection["out_of_range_source_line_count"]
        != projection["source_section_line_count"]
        or sum(
            projection[key]
            for key in (
                "translation_ready_pair_count",
                "glyph_recovery_pair_count",
                "structure_review_pair_count",
                "non_hangul_review_pair_count",
            )
        )
        != projected
        or projection["speaker_labeled_pair_count"]
        + projection["narration_pair_count"] != projected
        or value["status"]
        != (
            "anchored-section-projection-ready"
            if ready
            else "anchored-section-projection-incomplete"
        )
        or value["single_anchor_projection_only"] is not True
        or value["candidate_pairing_only"] is not True
        or value["human_review_required"] is not True
        or value["hancharacter_contract_mode"] != "translator_declared"
        or value["local_payload_policy"]
        != "source-target-text-speakers-aliases-selectors-ordinals-indices-and-pairs-local-only"
        or value["source_pairing_complete"] is not False
        or value["speaker_assignment_complete"] is not False
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != (
            "human-review-anchored-section-projection"
            if ready
            else "capture-additional-source-target-anchor"
        )
    ):
        raise ValueError("section projection result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = {
        "quality": root / QUALITY_PATH,
        "local_quality": root / LOCAL_QUALITY_PATH,
        "source": root / SOURCE_PATH,
        "local_source": root / LOCAL_SOURCE_PATH,
        "anchor": root / ANCHOR_PATH,
        "local_anchor": root / LOCAL_ANCHOR_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print("Source-target section projection is not ready")
            return 0
        raise SystemExit("source-target section projection input is missing")
    quality = _load_json_object(paths["quality"])
    local_quality = _load_json_object(paths["local_quality"])
    source = _load_json_object(paths["source"])
    local_source = _load_json_object(paths["local_source"])
    anchor = _load_json_object(paths["anchor"])
    local_anchor = _load_json_object(paths["local_anchor"])
    validate_target_group_record_quality(quality)
    validate_source_script_reference(source)
    validate_source_target_anchor(anchor)
    if (
        anchor["status"] != "source-target-sequence-anchor-resolved"
        or anchor["target_sha256"] != quality["target_sha256"]
        or anchor["source_record_quality_sha256"]
        != sha256_file(paths["quality"])
        or anchor["source_script_reference_sha256"]
        != sha256_file(paths["source"])
        or anchor["local_alignment_sha256"]
        != sha256_file(paths["local_anchor"])
        or quality["local_quality_sha256"]
        != sha256_file(paths["local_quality"])
        or source["local_reference_sha256"]
        != sha256_file(paths["local_source"])
        or local_quality.get("target_sha256") != quality["target_sha256"]
        or local_anchor.get("target_sha256") != quality["target_sha256"]
    ):
        raise ValueError("section projection identity disagrees")
    target_records = local_quality.get("records")
    source_sections = local_source.get("sections")
    if not isinstance(target_records, list) or not isinstance(
        source_sections, list
    ):
        raise ValueError("section projection local inputs are missing")
    counts, projection = project_anchored_section(
        target_records=target_records,
        source_sections=source_sections,
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    local_jsonl_path = root / LOCAL_JSONL_PATH
    local_jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    local_jsonl_path.write_text(
        "".join(
            json.dumps(pair, ensure_ascii=False, sort_keys=True) + "\n"
            for pair in projection["pairs"]
        ),
        encoding="utf-8",
    )
    local = {
        "artifact_kind": "local-v5-1-source-target-section-projection",
        "schema_version": 1,
        "target_sha256": quality["target_sha256"],
        "captured_utc": captured_utc,
        "projection": projection,
        "jsonl_path": str(local_jsonl_path),
        "jsonl_sha256": sha256_file(local_jsonl_path),
        "publication_policy": (
            "never-publish-source-target-text-speakers-aliases-selectors-ordinals-indices-or-pairs"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_source_target_section_projection(
        target_sha256=str(quality["target_sha256"]),
        source_record_quality_sha256=sha256_file(paths["quality"]),
        source_script_reference_sha256=sha256_file(paths["source"]),
        source_target_anchor_sha256=sha256_file(paths["anchor"]),
        local_projection_sha256=sha256_file(local_path),
        projection=counts,
        captured_utc=captured_utc,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR source-target section projection: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
