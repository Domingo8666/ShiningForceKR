#!/usr/bin/env python3
"""Build a mobile review page for the first verified translation context.

Source text, speakers, target text, selectors, ordinals, indices, screens, and
review cards remain in ignored phone-local files.  The safe receipt publishes
fixed aggregate counts and dependency hashes only.  No translation is created
or approved by this mechanical stage.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from html import escape
import json
from pathlib import Path

try:
    from .patch_io import sha256_file
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_runtime_context_glyph_preservation import (
        LOCAL_REPORT_PATH as LOCAL_PRESERVATION_PATH,
        PUBLISH_RELATIVE_PATH as PRESERVATION_PATH,
        validate_runtime_context_glyph_preservation,
    )
    from .v5_1_source_target_runtime_context import (
        LOCAL_REPORT_PATH as LOCAL_CONTEXT_PATH,
        PUBLISH_RELATIVE_PATH as CONTEXT_PATH,
        validate_source_target_runtime_context,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_runtime_context_glyph_preservation import (
        LOCAL_REPORT_PATH as LOCAL_PRESERVATION_PATH,
        PUBLISH_RELATIVE_PATH as PRESERVATION_PATH,
        validate_runtime_context_glyph_preservation,
    )
    from v5_1_source_target_runtime_context import (
        LOCAL_REPORT_PATH as LOCAL_CONTEXT_PATH,
        PUBLISH_RELATIVE_PATH as CONTEXT_PATH,
        validate_source_target_runtime_context,
    )


ARTIFACT_KIND = "sanitized-v5-1-first-context-translation-review"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_translation_review.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_first_context_translation_review.json"
)
LOCAL_REVIEW_DIR = Path("reports/HUMAN_REVIEW")
LOCAL_REVIEW_HTML_PATH = (
    LOCAL_REVIEW_DIR / "FIRST_CONTEXT_TRANSLATION_REVIEW_LATEST.html"
)
LOCAL_REVIEW_POINTER_PATH = (
    LOCAL_REVIEW_DIR / "FIRST_CONTEXT_TRANSLATION_REVIEW_LATEST.txt"
)

COUNT_KEYS = {
    "context_entry_count",
    "uniquely_mapped_entry_count",
    "speaker_labeled_entry_count",
    "narration_entry_count",
    "distinct_speaker_count",
    "consecutive_source_line_step_count",
    "preserved_non_text_glyph_occurrence_count",
    "translation_draft_entry_count",
    "human_translation_required_entry_count",
}
SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_target_runtime_context_sha256",
    "runtime_context_glyph_preservation_sha256",
    "local_review_packet_sha256",
    "captured_utc",
    "review",
    "context_pairing_complete",
    "non_text_glyph_preservation_complete",
    "translation_generated_by_mechanical_stage",
    "human_translation_review_required",
    "hancharacter_contract_mode",
    "local_payload_policy",
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


def build_first_context_review_rows(
    context_rows: list[dict[str, object]],
) -> tuple[dict[str, int], list[dict[str, object]]]:
    if not context_rows:
        raise ValueError("first context translation review rows are missing")
    rows: list[dict[str, object]] = []
    speakers: set[str] = set()
    speaker_labeled = 0
    narration = 0
    unique = 0
    previous_section: int | None = None
    previous_line: int | None = None
    consecutive = 0
    for row in context_rows:
        if not isinstance(row, dict):
            raise ValueError(
                "first context translation review row is invalid"
            )
        if row.get("mapping_status") != "unique":
            raise ValueError(
                "first context translation review mapping is not unique"
            )
        source_text = row.get("source_text")
        speaker = row.get("speaker")
        section = row.get("source_section_index")
        line = row.get("source_line_index")
        if (
            not isinstance(source_text, str)
            or not source_text
            or not _bounded_int(section, 0, 100000)
            or not _bounded_int(line, 0, 100000)
        ):
            raise ValueError(
                "first context translation review source fields are invalid"
            )
        assert isinstance(section, int)
        assert isinstance(line, int)
        if speaker is None:
            narration += 1
        elif isinstance(speaker, str) and speaker:
            speaker_labeled += 1
            speakers.add(speaker)
        else:
            raise ValueError(
                "first context translation review speaker is invalid"
            )
        if previous_section is not None:
            if section == previous_section and line == previous_line + 1:
                consecutive += 1
            else:
                raise ValueError(
                    "first context translation review lines are not consecutive"
                )
        previous_section = section
        previous_line = line
        unique += 1
        rows.append(
            {
                "review_index": len(rows) + 1,
                "source_text": source_text,
                "speaker": speaker,
                "translation_draft": None,
                "human_translation_required": True,
            }
        )
    counts = {
        "context_entry_count": len(context_rows),
        "uniquely_mapped_entry_count": unique,
        "speaker_labeled_entry_count": speaker_labeled,
        "narration_entry_count": narration,
        "distinct_speaker_count": len(speakers),
        "consecutive_source_line_step_count": consecutive,
        "preserved_non_text_glyph_occurrence_count": 0,
        "translation_draft_entry_count": 0,
        "human_translation_required_entry_count": len(rows),
    }
    return counts, rows


def render_first_context_translation_review_html(
    *, rows: list[dict[str, object]], captured_utc: str
) -> str:
    cards = []
    for row in rows:
        index = int(row["review_index"])
        speaker = row["speaker"]
        cards.append(
            "\n".join(
                [
                    '<section class="card">',
                    f"<h2>대사 {index} / {len(rows)}</h2>",
                    (
                        '<p class="speaker">화자: '
                        f'{escape(str(speaker) if speaker else "나레이션")}</p>'
                    ),
                    (
                        '<p class="source">'
                        f'{escape(str(row["source_text"]))}</p>'
                    ),
                    '<p class="pending">한국어 초안: ChatGPT 검토 대기</p>',
                    "</section>",
                ]
            )
        )
    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Shining Force KR 첫 대사 검토</title>
<style>
body {{ margin: 0; padding: 16px; background: #111; color: #f5f5f5;
       font-family: sans-serif; line-height: 1.55; }}
.notice {{ background: #173b2b; border: 2px solid #43d17d; padding: 15px;
           border-radius: 12px; margin-bottom: 18px; }}
.card {{ min-height: 62vh; box-sizing: border-box; background: #202020;
         border: 2px solid #666; border-radius: 14px; padding: 18px;
         margin-bottom: 22px; break-inside: avoid; }}
.card h2 {{ color: #ffe36e; font-size: 1.6rem; }}
.speaker {{ font-size: 1.45rem; color: #8ee6ff; }}
.source {{ font-size: 2.15rem; line-height: 1.65; font-weight: 700;
           word-break: keep-all; }}
.pending {{ margin-top: 24px; padding-top: 14px; border-top: 1px solid #666;
            font-size: 1.2rem; color: #bbb; }}
.muted {{ color: #aaa; }}
</style>
</head>
<body>
<div class="notice">
<h1>첫 실제 플레이 대사 4줄</h1>
<p><b>번역하거나 파일을 수정하지 마세요.</b></p>
<p>스크롤 캡처가 아닌 일반 스크린샷으로 대사 카드가 크게 보이게
찍어 ChatGPT에 보내주세요. ChatGPT가 한국어 초안과 근거를 제시합니다.</p>
<p>비문자 글리프 5개는 원본 토큰으로 이미 안전하게 보존됐습니다.</p>
<p class="muted">생성 시각: {escape(captured_utc)}</p>
</div>
{"".join(cards)}
</body>
</html>
"""


def build_first_context_translation_review(
    *,
    target_sha256: str,
    source_target_runtime_context_sha256: str,
    runtime_context_glyph_preservation_sha256: str,
    local_review_packet_sha256: str,
    review: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    ready = (
        review["context_entry_count"] >= 4
        and review["uniquely_mapped_entry_count"]
        == review["context_entry_count"]
        and review["consecutive_source_line_step_count"]
        == review["context_entry_count"] - 1
        and review["human_translation_required_entry_count"]
        == review["context_entry_count"]
        and review["translation_draft_entry_count"] == 0
    )
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "first-context-translation-review-ready"
            if ready
            else "first-context-translation-review-incomplete"
        ),
        "target_sha256": target_sha256,
        "source_target_runtime_context_sha256":
            source_target_runtime_context_sha256,
        "runtime_context_glyph_preservation_sha256":
            runtime_context_glyph_preservation_sha256,
        "local_review_packet_sha256": local_review_packet_sha256,
        "captured_utc": captured_utc,
        "review": review,
        "context_pairing_complete": ready,
        "non_text_glyph_preservation_complete": True,
        "translation_generated_by_mechanical_stage": False,
        "human_translation_review_required": True,
        "hancharacter_contract_mode": "translator_declared",
        "local_payload_policy": (
            "source-text-speakers-target-text-selectors-ordinals-indices-"
            "screens-translations-and-review-cards-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": (
            "human-share-first-context-translation-review"
            if ready
            else "repair-first-context-translation-review"
        ),
    }
    validate_first_context_translation_review(value)
    return value


def validate_first_context_translation_review(
    value: dict[str, object],
) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError(
            "first context translation review fields do not match"
        )
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "first-context-translation-review-ready",
            "first-context-translation-review-incomplete",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "source_target_runtime_context_sha256",
                "runtime_context_glyph_preservation_sha256",
                "local_review_packet_sha256",
            )
        )
    ):
        raise ValueError(
            "first context translation review identity is invalid"
        )
    try:
        timestamp = datetime.fromisoformat(
            str(value["captured_utc"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError(
            "first context translation review timestamp is invalid"
        ) from error
    if timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
        raise ValueError(
            "first context translation review timestamp needs UTC"
        )
    counts = value["review"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError(
            "first context translation review counts do not match"
        )
    for key, count in counts.items():
        if not _bounded_int(count, 0, 1000000):
            raise ValueError(
                f"first context translation review {key} is invalid"
            )
    entries = counts["context_entry_count"]
    ready = (
        entries >= 4
        and counts["uniquely_mapped_entry_count"] == entries
        and counts["speaker_labeled_entry_count"]
        + counts["narration_entry_count"] == entries
        and counts["consecutive_source_line_step_count"] == entries - 1
        and counts["human_translation_required_entry_count"] == entries
        and counts["translation_draft_entry_count"] == 0
    )
    expected_status = (
        "first-context-translation-review-ready"
        if ready
        else "first-context-translation-review-incomplete"
    )
    if (
        value["status"] != expected_status
        or value["context_pairing_complete"] is not ready
        or value["non_text_glyph_preservation_complete"] is not True
        or value["translation_generated_by_mechanical_stage"] is not False
        or value["human_translation_review_required"] is not True
        or value["hancharacter_contract_mode"] != "translator_declared"
        or value["local_payload_policy"]
        != (
            "source-text-speakers-target-text-selectors-ordinals-indices-"
            "screens-translations-and-review-cards-local-only"
        )
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != (
            "human-share-first-context-translation-review"
            if ready
            else "repair-first-context-translation-review"
        )
    ):
        raise ValueError(
            "first context translation review result is inconsistent"
        )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = {
        "context": root / CONTEXT_PATH,
        "local_context": root / LOCAL_CONTEXT_PATH,
        "preservation": root / PRESERVATION_PATH,
        "local_preservation": root / LOCAL_PRESERVATION_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print("First context translation review is not ready")
            return 0
        raise SystemExit("first context translation review input is missing")
    context = _load_json_object(paths["context"])
    local_context = _load_json_object(paths["local_context"])
    preservation = _load_json_object(paths["preservation"])
    local_preservation = _load_json_object(paths["local_preservation"])
    validate_source_target_runtime_context(context)
    validate_runtime_context_glyph_preservation(preservation)
    if (
        context["target_sha256"] != preservation["target_sha256"]
        or context["local_context_sha256"]
        != sha256_file(paths["local_context"])
        or preservation["local_preservation_sha256"]
        != sha256_file(paths["local_preservation"])
        or preservation["runtime_context_glyph_recovery_complete"] is not True
        or local_context.get("target_sha256") != context["target_sha256"]
        or local_preservation.get("target_sha256")
        != context["target_sha256"]
    ):
        raise ValueError(
            "first context translation review identity disagrees"
        )
    analysis = local_context.get("analysis")
    if not isinstance(analysis, dict) or not isinstance(
        analysis.get("rows"), list
    ):
        raise ValueError(
            "first context translation review local rows are missing"
        )
    counts, rows = build_first_context_review_rows(analysis["rows"])
    counts["preserved_non_text_glyph_occurrence_count"] = int(
        preservation["preservation"][
            "preserve_original_glyph_occurrence_count"
        ]
    )
    if (
        counts["context_entry_count"]
        != context["context"]["runtime_entry_count"]
        or counts["uniquely_mapped_entry_count"]
        != context["context"]["uniquely_mapped_runtime_entry_count"]
        or counts["speaker_labeled_entry_count"]
        != context["context"]["speaker_labeled_context_entry_count"]
        or counts["narration_entry_count"]
        != context["context"]["narration_context_entry_count"]
        or counts["distinct_speaker_count"]
        != context["context"]["distinct_speaker_count"]
    ):
        raise ValueError(
            "first context translation review aggregates disagree"
        )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    html = render_first_context_translation_review_html(
        rows=rows, captured_utc=captured_utc
    )
    review_dir = root / LOCAL_REVIEW_DIR
    review_dir.mkdir(parents=True, exist_ok=True)
    html_path = root / LOCAL_REVIEW_HTML_PATH
    html_path.write_text(html, encoding="utf-8")
    pointer_path = root / LOCAL_REVIEW_POINTER_PATH
    pointer_path.write_text(
        "\n".join(
            [
                "Shining Force KR 첫 실제 플레이 대사 4줄",
                "",
                "1. FIRST_CONTEXT_TRANSLATION_REVIEW_LATEST.html을 엽니다.",
                "2. 스크롤 캡처가 아닌 일반 스크린샷으로 대사 카드를 찍습니다.",
                "3. 카드 4개가 읽히도록 사진을 ChatGPT에 보냅니다.",
                "",
                "직접 번역하거나 파일을 수정하지 마세요.",
                "ChatGPT가 초안과 근거를 먼저 제시합니다.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    packet_sha256 = hashlib.sha256(html.encode("utf-8")).hexdigest()
    local = {
        "artifact_kind": "local-v5-1-first-context-translation-review",
        "schema_version": SCHEMA_VERSION,
        "target_sha256": context["target_sha256"],
        "source_target_runtime_context_sha256": sha256_file(paths["context"]),
        "runtime_context_glyph_preservation_sha256":
            sha256_file(paths["preservation"]),
        "captured_utc": captured_utc,
        "review": counts,
        "rows": rows,
        "html_sha256": packet_sha256,
        "publication_policy": (
            "never-publish-source-text-speakers-target-text-selectors-"
            "ordinals-indices-screens-translations-or-review-cards"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_first_context_translation_review(
        target_sha256=str(context["target_sha256"]),
        source_target_runtime_context_sha256=sha256_file(paths["context"]),
        runtime_context_glyph_preservation_sha256=
            sha256_file(paths["preservation"]),
        local_review_packet_sha256=packet_sha256,
        review=counts,
        captured_utc=captured_utc,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR first context translation review: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
