#!/usr/bin/env python3
"""Map a verified runtime entry sequence into the local source context.

Source text, target text, speakers, selectors, ordinals, source indices, screen
paths, and every row stay in ignored phone-local reports.  The publishable
receipt contains counts only and can make a small context window ready for
human translation review without approving the full 79-line projection.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

try:
    from .patch_io import sha256_file
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_source_target_runtime_sequence import (
        LOCAL_REPORT_PATH as LOCAL_RUNTIME_SEQUENCE_PATH,
        PUBLISH_RELATIVE_PATH as RUNTIME_SEQUENCE_PATH,
        validate_source_target_runtime_sequence,
    )
    from .v5_1_source_target_section_projection import (
        LOCAL_REPORT_PATH as LOCAL_PROJECTION_PATH,
        PUBLISH_RELATIVE_PATH as PROJECTION_PATH,
        validate_source_target_section_projection,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_source_target_runtime_sequence import (
        LOCAL_REPORT_PATH as LOCAL_RUNTIME_SEQUENCE_PATH,
        PUBLISH_RELATIVE_PATH as RUNTIME_SEQUENCE_PATH,
        validate_source_target_runtime_sequence,
    )
    from v5_1_source_target_section_projection import (
        LOCAL_REPORT_PATH as LOCAL_PROJECTION_PATH,
        PUBLISH_RELATIVE_PATH as PROJECTION_PATH,
        validate_source_target_section_projection,
    )


ARTIFACT_KIND = "sanitized-v5-1-source-target-runtime-context"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_source_target_runtime_context.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_source_target_runtime_context.json"
)
LOCAL_REVIEW_DIR = Path("reports/HUMAN_REVIEW")
LOCAL_REVIEW_LATEST_PATH = (
    LOCAL_REVIEW_DIR / "FIRST_KOREAN_CONTEXT_REVIEW_LATEST.txt"
)

COUNT_KEYS = {
    "runtime_entry_count",
    "uniquely_mapped_runtime_entry_count",
    "unmapped_runtime_entry_count",
    "multiply_mapped_runtime_entry_count",
    "mapped_source_section_count",
    "consecutive_source_line_step_count",
    "nonconsecutive_source_line_step_count",
    "speaker_labeled_context_entry_count",
    "narration_context_entry_count",
    "distinct_speaker_count",
    "translation_ready_context_entry_count",
    "glyph_recovery_context_entry_count",
    "structure_review_context_entry_count",
    "non_hangul_review_context_entry_count",
    "local_screen_reference_count",
}

SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_section_projection_sha256",
    "runtime_sequence_sha256",
    "local_context_sha256",
    "captured_utc",
    "context",
    "runtime_context_window_pairing_complete",
    "candidate_pairing_only",
    "human_review_required",
    "hancharacter_contract_mode",
    "local_payload_policy",
    "source_pairing_complete",
    "speaker_assignment_complete",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _bounded_int(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def map_runtime_context(
    *,
    observations: list[dict[str, object]],
    pairs: list[dict[str, object]],
) -> tuple[dict[str, int], dict[str, object]]:
    if not observations:
        raise ValueError("runtime context observations are missing")
    if not pairs:
        raise ValueError("runtime context projection pairs are missing")

    pair_index: dict[tuple[int, int], list[dict[str, object]]] = {}
    for pair in pairs:
        if not isinstance(pair, dict):
            raise ValueError("runtime context projection pair is invalid")
        selector = pair.get("target_selector")
        ordinal = pair.get("target_ordinal")
        if (
            not _bounded_int(selector, 0, 0xFFFF)
            or not _bounded_int(ordinal, 0, 0xFF)
        ):
            raise ValueError(
                "runtime context projection coordinates are invalid"
            )
        assert isinstance(selector, int)
        assert isinstance(ordinal, int)
        pair_index.setdefault((selector, ordinal), []).append(pair)

    rows: list[dict[str, object]] = []
    unmapped = 0
    multiply_mapped = 0
    unique_mapped = 0
    sections: set[int] = set()
    speakers: set[str] = set()
    speaker_labeled = 0
    narration = 0
    local_screen_references = 0
    tier_counts = {
        "translation-ready": 0,
        "glyph-recovery": 0,
        "structure-review": 0,
        "non-hangul-review": 0,
    }

    for runtime_index, observation in enumerate(observations):
        if not isinstance(observation, dict):
            raise ValueError("runtime context observation is invalid")
        selector = observation.get("selector")
        ordinal = observation.get("ordinal")
        png_sha256 = observation.get("png_sha256")
        if (
            not _bounded_int(selector, 0, 0xFFFF)
            or not _bounded_int(ordinal, 0, 0xFF)
            or not _is_sha256(png_sha256)
        ):
            raise ValueError(
                "runtime context observation fields are invalid"
            )
        assert isinstance(selector, int)
        assert isinstance(ordinal, int)
        matches = pair_index.get((selector, ordinal), [])
        if not matches:
            unmapped += 1
            rows.append(
                {
                    "runtime_index": runtime_index,
                    "observation": observation,
                    "mapping_status": "unmapped",
                }
            )
            continue
        if len(matches) != 1:
            multiply_mapped += 1
            rows.append(
                {
                    "runtime_index": runtime_index,
                    "observation": observation,
                    "mapping_status": "multiply-mapped",
                    "candidate_count": len(matches),
                }
            )
            continue

        pair = matches[0]
        source_section = pair.get("source_section_index")
        source_line = pair.get("source_line_index")
        source_text = pair.get("source_text")
        speaker = pair.get("speaker")
        target_record = pair.get("target_record")
        if (
            not _bounded_int(source_section, 0, 100000)
            or not _bounded_int(source_line, 0, 100000)
            or not isinstance(source_text, str)
            or not isinstance(target_record, dict)
        ):
            raise ValueError(
                "runtime context mapped pair fields are invalid"
            )
        if speaker is None:
            narration += 1
        elif isinstance(speaker, str) and speaker:
            speaker_labeled += 1
            speakers.add(speaker)
        else:
            raise ValueError("runtime context speaker is invalid")
        tier = target_record.get("quality_tier")
        if tier not in tier_counts:
            raise ValueError("runtime context quality tier is invalid")
        target_text = target_record.get("translation_text")
        if not isinstance(target_text, str):
            raise ValueError("runtime context target text is invalid")
        sections.add(int(source_section))
        tier_counts[str(tier)] += 1
        unique_mapped += 1
        local_screen_references += 1
        rows.append(
            {
                "runtime_index": runtime_index,
                "observation": observation,
                "mapping_status": "unique",
                "source_section_index": source_section,
                "source_line_index": source_line,
                "source_text": source_text,
                "speaker": speaker,
                "target_text": target_text,
                "quality_tier": tier,
                "pairing_basis": pair.get("pairing_basis"),
            }
        )

    consecutive = 0
    nonconsecutive = 0
    unique_rows = [
        row for row in rows if row["mapping_status"] == "unique"
    ]
    for previous, current in zip(unique_rows, unique_rows[1:]):
        same_section = (
            current["source_section_index"]
            == previous["source_section_index"]
        )
        line_step = (
            int(current["source_line_index"])
            - int(previous["source_line_index"])
        )
        if same_section and line_step == 1:
            consecutive += 1
        else:
            nonconsecutive += 1

    counts = {
        "runtime_entry_count": len(observations),
        "uniquely_mapped_runtime_entry_count": unique_mapped,
        "unmapped_runtime_entry_count": unmapped,
        "multiply_mapped_runtime_entry_count": multiply_mapped,
        "mapped_source_section_count": len(sections),
        "consecutive_source_line_step_count": consecutive,
        "nonconsecutive_source_line_step_count": nonconsecutive,
        "speaker_labeled_context_entry_count": speaker_labeled,
        "narration_context_entry_count": narration,
        "distinct_speaker_count": len(speakers),
        "translation_ready_context_entry_count":
            tier_counts["translation-ready"],
        "glyph_recovery_context_entry_count":
            tier_counts["glyph-recovery"],
        "structure_review_context_entry_count":
            tier_counts["structure-review"],
        "non_hangul_review_context_entry_count":
            tier_counts["non-hangul-review"],
        "local_screen_reference_count": local_screen_references,
    }
    ready = (
        len(observations) >= 4
        and unique_mapped == len(observations)
        and unmapped == 0
        and multiply_mapped == 0
        and len(sections) == 1
        and consecutive == len(observations) - 1
        and nonconsecutive == 0
        and all(
            row.get("pairing_basis") == "single-anchor-relative-offset"
            for row in unique_rows
        )
    )
    return counts, {
        "rows": rows,
        "runtime_context_window_pairing_complete": ready,
        "publication_policy": (
            "never-publish-source-target-text-speakers-selectors-ordinals-"
            "indices-screens-or-rows"
        ),
    }


def render_local_context_review(
    *,
    packet_id: str,
    rows: list[dict[str, object]],
) -> str:
    lines = [
        "Shining Force KR 첫 실제 플레이 문맥 묶음",
        f"문맥 묶음 ID: {packet_id}",
        "",
        "이 파일은 실제 플레이 순서와 원문 후보를 기술적으로 대조한 결과입니다.",
        "현재는 자동 분석 중이므로 사용자가 [x]를 표시하거나 수정할 필요가 없습니다.",
        "한글 문장 선택이 필요한 단계가 되면 더 쉬운 별도 안내를 제공합니다.",
        "",
    ]
    for display_index, row in enumerate(rows, start=1):
        if row.get("mapping_status") != "unique":
            continue
        lines.extend(
            [
                f"[{display_index}]",
                f"화자: {row['speaker'] if row['speaker'] is not None else '(나레이션)'}",
                f"원문 후보: {row['source_text']}",
                f"현재 대상문: {row['target_text']}",
                f"기술 상태: {row['quality_tier']}",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def build_source_target_runtime_context(
    *,
    target_sha256: str,
    source_section_projection_sha256: str,
    runtime_sequence_sha256: str,
    local_context_sha256: str,
    context: dict[str, int],
    runtime_context_window_pairing_complete: bool,
    captured_utc: str,
) -> dict[str, object]:
    status = (
        "runtime-context-window-ready-for-human-translation-review"
        if runtime_context_window_pairing_complete
        else "runtime-context-window-needs-more-evidence"
    )
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": target_sha256,
        "source_section_projection_sha256":
            source_section_projection_sha256,
        "runtime_sequence_sha256": runtime_sequence_sha256,
        "local_context_sha256": local_context_sha256,
        "captured_utc": captured_utc,
        "context": context,
        "runtime_context_window_pairing_complete":
            runtime_context_window_pairing_complete,
        "candidate_pairing_only": True,
        "human_review_required": True,
        "hancharacter_contract_mode": "translator_declared",
        "local_payload_policy": (
            "source-target-text-speakers-selectors-ordinals-indices-"
            "screens-and-rows-local-only"
        ),
        "source_pairing_complete": False,
        "speaker_assignment_complete": False,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "prepare-first-contextual-translation-review"
            if runtime_context_window_pairing_complete
            else "capture-additional-runtime-sequence"
        ),
    }
    validate_source_target_runtime_context(value)
    return value


def validate_source_target_runtime_context(
    value: dict[str, object],
) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError("runtime context fields do not match")
    ready = value["runtime_context_window_pairing_complete"]
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "runtime-context-window-ready-for-human-translation-review",
            "runtime-context-window-needs-more-evidence",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_section_projection_sha256"])
        or not _is_sha256(value["runtime_sequence_sha256"])
        or not _is_sha256(value["local_context_sha256"])
        or not isinstance(ready, bool)
    ):
        raise ValueError("runtime context identity is invalid")
    try:
        timestamp = datetime.fromisoformat(
            str(value["captured_utc"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError("runtime context timestamp is invalid") from error
    if timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
        raise ValueError("runtime context timestamp needs UTC")

    counts = value["context"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("runtime context counts do not match")
    runtime_count = counts.get("runtime_entry_count")
    if not _bounded_int(runtime_count, 1, 1000):
        raise ValueError("runtime context entry count is invalid")
    assert isinstance(runtime_count, int)
    for key, count in counts.items():
        if not _bounded_int(count, 0, runtime_count):
            raise ValueError(f"runtime context {key} is invalid")
    unique_count = int(counts["uniquely_mapped_runtime_entry_count"])
    expected_ready = (
        runtime_count >= 4
        and unique_count == runtime_count
        and counts["unmapped_runtime_entry_count"] == 0
        and counts["multiply_mapped_runtime_entry_count"] == 0
        and counts["mapped_source_section_count"] == 1
        and counts["consecutive_source_line_step_count"]
        == runtime_count - 1
        and counts["nonconsecutive_source_line_step_count"] == 0
    )
    if (
        unique_count
        + counts["unmapped_runtime_entry_count"]
        + counts["multiply_mapped_runtime_entry_count"]
        != runtime_count
        or counts["speaker_labeled_context_entry_count"]
        + counts["narration_context_entry_count"]
        != unique_count
        or counts["translation_ready_context_entry_count"]
        + counts["glyph_recovery_context_entry_count"]
        + counts["structure_review_context_entry_count"]
        + counts["non_hangul_review_context_entry_count"]
        != unique_count
        or counts["local_screen_reference_count"] != unique_count
        or ready is not expected_ready
    ):
        raise ValueError("runtime context aggregates are inconsistent")
    expected_status = (
        "runtime-context-window-ready-for-human-translation-review"
        if ready
        else "runtime-context-window-needs-more-evidence"
    )
    expected_checkpoint = (
        "prepare-first-contextual-translation-review"
        if ready
        else "capture-additional-runtime-sequence"
    )
    if (
        value["status"] != expected_status
        or value["candidate_pairing_only"] is not True
        or value["human_review_required"] is not True
        or value["hancharacter_contract_mode"] != "translator_declared"
        or value["local_payload_policy"]
        != (
            "source-target-text-speakers-selectors-ordinals-indices-"
            "screens-and-rows-local-only"
        )
        or value["source_pairing_complete"] is not False
        or value["speaker_assignment_complete"] is not False
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"] != expected_checkpoint
    ):
        raise ValueError("runtime context policy is invalid")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = {
        "projection": root / PROJECTION_PATH,
        "local_projection": root / LOCAL_PROJECTION_PATH,
        "runtime": root / RUNTIME_SEQUENCE_PATH,
        "local_runtime": root / LOCAL_RUNTIME_SEQUENCE_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print("Source-target runtime context is not ready")
            return 0
        raise SystemExit("source-target runtime context input is missing")

    projection = _load_json_object(paths["projection"])
    local_projection = _load_json_object(paths["local_projection"])
    runtime = _load_json_object(paths["runtime"])
    local_runtime = _load_json_object(paths["local_runtime"])
    validate_source_target_section_projection(projection)
    validate_source_target_runtime_sequence(runtime)
    if (
        runtime["status"] != "runtime-sequence-corroboration-ready"
        or runtime["baseline_target_sha256"] != projection["target_sha256"]
        or local_projection.get("target_sha256")
        != projection["target_sha256"]
        or sha256_file(paths["local_projection"])
        != projection["local_projection_sha256"]
        or local_runtime.get("baseline_target_sha256")
        != runtime["baseline_target_sha256"]
        or sha256_file(paths["local_runtime"])
        != runtime["local_sequence_sha256"]
    ):
        raise ValueError("runtime context input identity disagrees")
    local_projection_payload = local_projection.get("projection")
    if not isinstance(local_projection_payload, dict):
        raise ValueError("runtime context local projection is missing")
    pairs = local_projection_payload.get("pairs")
    observations = local_runtime.get("observations")
    if not isinstance(pairs, list) or not isinstance(observations, list):
        raise ValueError("runtime context local inputs are missing")
    counts, local_context = map_runtime_context(
        observations=observations,
        pairs=pairs,
    )
    rows = local_context["rows"]
    assert isinstance(rows, list)
    review_bytes = json.dumps(
        rows,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    packet_id = hashlib.sha256(review_bytes).hexdigest()[:12]
    review_dir = root / LOCAL_REVIEW_DIR
    review_dir.mkdir(parents=True, exist_ok=True)
    review_path = review_dir / f"FIRST_KOREAN_CONTEXT_REVIEW_{packet_id}.txt"
    review_path.write_text(
        render_local_context_review(
            packet_id=packet_id,
            rows=rows,
        ),
        encoding="utf-8",
    )
    latest_path = root / LOCAL_REVIEW_LATEST_PATH
    latest_path.write_text(
        "\n".join(
            [
                "Shining Force KR 첫 실제 플레이 문맥 묶음",
                f"문맥 묶음 ID: {packet_id}",
                f"열 파일: {review_path.name}",
                "",
                "현재는 자동 분석 중이므로 사용자가 수정할 필요가 없습니다.",
                "한글 문장 선택이 필요할 때 별도의 쉬운 안내를 제공합니다.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    local = {
        "artifact_kind": "local-v5-1-source-target-runtime-context",
        "schema_version": SCHEMA_VERSION,
        "target_sha256": projection["target_sha256"],
        "source_section_projection_sha256":
            sha256_file(paths["projection"]),
        "runtime_sequence_sha256": sha256_file(paths["runtime"]),
        "captured_utc": captured_utc,
        "context": counts,
        "analysis": local_context,
        "review_packet_id": packet_id,
        "review_path": str(review_path),
        "review_sha256": sha256_file(review_path),
        "review_latest_path": str(latest_path),
        "publication_policy": (
            "never-publish-source-target-text-speakers-selectors-ordinals-"
            "indices-screens-or-rows"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_source_target_runtime_context(
        target_sha256=str(projection["target_sha256"]),
        source_section_projection_sha256=sha256_file(paths["projection"]),
        runtime_sequence_sha256=sha256_file(paths["runtime"]),
        local_context_sha256=sha256_file(local_path),
        context=counts,
        runtime_context_window_pairing_complete=bool(
            local_context["runtime_context_window_pairing_complete"]
        ),
        captured_utc=captured_utc,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR source-target runtime context: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
