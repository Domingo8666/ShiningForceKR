#!/usr/bin/env python3
"""Build a phone-local visual review packet for runtime-context glyphs.

Source text, speakers, decoded target text, glyph coordinates, masks,
codepoints, and candidate characters remain in ignored phone-local files.
The committed receipt contains fixed aggregate counts and dependency hashes.
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
    from .v5_1_runtime_context_glyph_candidates import (
        LOCAL_REPORT_PATH as LOCAL_CANDIDATES_PATH,
        PUBLISH_RELATIVE_PATH as CANDIDATES_PATH,
        validate_runtime_context_glyph_candidates,
    )
    from .v5_1_runtime_context_glyph_demand import (
        LOCAL_REPORT_PATH as LOCAL_DEMAND_PATH,
        PUBLISH_RELATIVE_PATH as DEMAND_PATH,
        validate_runtime_context_glyph_demand,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_runtime_context_glyph_candidates import (
        LOCAL_REPORT_PATH as LOCAL_CANDIDATES_PATH,
        PUBLISH_RELATIVE_PATH as CANDIDATES_PATH,
        validate_runtime_context_glyph_candidates,
    )
    from v5_1_runtime_context_glyph_demand import (
        LOCAL_REPORT_PATH as LOCAL_DEMAND_PATH,
        PUBLISH_RELATIVE_PATH as DEMAND_PATH,
        validate_runtime_context_glyph_demand,
    )


ARTIFACT_KIND = "sanitized-v5-1-runtime-context-glyph-review"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_runtime_context_glyph_review.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_runtime_context_glyph_review.json"
)
LOCAL_REVIEW_DIR = Path("reports/HUMAN_REVIEW")
LOCAL_REVIEW_HTML_PATH = (
    LOCAL_REVIEW_DIR / "RUNTIME_GLYPH_REVIEW_LATEST.html"
)
LOCAL_REVIEW_POINTER_PATH = (
    LOCAL_REVIEW_DIR / "RUNTIME_GLYPH_REVIEW_LATEST.txt"
)

COUNT_KEYS = {
    "glyph_card_count",
    "glyph_occurrence_count",
    "source_context_occurrence_count",
    "unique_exact_non_hangul_card_count",
    "equivalent_exact_non_hangul_card_count",
    "ambiguous_exact_non_hangul_card_count",
    "unmatched_non_hangul_card_count",
    "out_of_range_non_hangul_card_count",
    "missing_non_hangul_card_count",
    "maximum_exact_candidate_count",
    "maximum_fuzzy_candidate_count",
}
SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "runtime_context_glyph_demand_sha256",
    "runtime_context_glyph_candidates_sha256",
    "local_review_packet_sha256",
    "captured_utc",
    "review",
    "automatic_character_selection_allowed",
    "human_character_review_required",
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


def _coordinate(value: object, *, label: str) -> tuple[int, int]:
    if not isinstance(value, dict):
        raise ValueError(f"runtime glyph review {label} is invalid")
    page = value.get("page")
    symbol = value.get("symbol")
    if not _bounded_int(page, 0, 0xFF) or not _bounded_int(
        symbol, 0, 0xFF
    ):
        raise ValueError(f"runtime glyph review {label} coordinate is invalid")
    assert isinstance(page, int)
    assert isinstance(symbol, int)
    return page, symbol


def build_runtime_glyph_review_rows(
    demand_analysis: dict[str, object],
    candidate_analysis: dict[str, object],
) -> tuple[dict[str, int], list[dict[str, object]]]:
    demand_rows = demand_analysis.get("rows")
    candidate_rows = candidate_analysis.get("glyphs")
    if not isinstance(demand_rows, list):
        raise ValueError("runtime glyph review demand rows are missing")
    if not isinstance(candidate_rows, list):
        raise ValueError("runtime glyph review candidate rows are missing")

    contexts: dict[tuple[int, int], list[dict[str, object]]] = {}
    for demand_row in demand_rows:
        if not isinstance(demand_row, dict) or not isinstance(
            demand_row.get("unresolved"), list
        ):
            raise ValueError("runtime glyph review demand row is invalid")
        for unresolved in demand_row["unresolved"]:
            coordinate = _coordinate(unresolved, label="demand")
            contexts.setdefault(coordinate, []).append(
                {
                    "source_text": demand_row.get("source_text"),
                    "speaker": demand_row.get("speaker"),
                    "target_text": demand_row.get("target_text"),
                    "quality_tier": demand_row.get("quality_tier"),
                }
            )

    cards: list[dict[str, object]] = []
    seen: set[tuple[int, int]] = set()
    counts = {key: 0 for key in COUNT_KEYS}
    counts["glyph_occurrence_count"] = sum(
        len(values) for values in contexts.values()
    )
    for candidate in candidate_rows:
        coordinate = _coordinate(candidate, label="candidate")
        if coordinate in seen:
            raise ValueError(
                "runtime glyph review candidate coordinate is duplicated"
            )
        seen.add(coordinate)
        coordinate_contexts = contexts.get(coordinate)
        if not coordinate_contexts:
            raise ValueError(
                "runtime glyph review candidate has no source context"
            )
        fuzzy = candidate.get("fuzzy")
        non_hangul = candidate.get("non_hangul")
        if fuzzy is not None and not isinstance(fuzzy, dict):
            raise ValueError("runtime glyph review fuzzy match is invalid")
        if non_hangul is not None and not isinstance(non_hangul, dict):
            raise ValueError(
                "runtime glyph review non-Hangul match is invalid"
            )
        non_hangul_status = (
            "missing" if non_hangul is None else non_hangul.get("status")
        )
        status_key = {
            "unique-exact-non-hangul":
                "unique_exact_non_hangul_card_count",
            "equivalent-exact-non-hangul":
                "equivalent_exact_non_hangul_card_count",
            "ambiguous-exact-non-hangul":
                "ambiguous_exact_non_hangul_card_count",
            "unmatched": "unmatched_non_hangul_card_count",
            "outside-font-page-range":
                "out_of_range_non_hangul_card_count",
            "missing": "missing_non_hangul_card_count",
        }.get(str(non_hangul_status))
        if status_key is None:
            raise ValueError(
                "runtime glyph review non-Hangul status is invalid"
            )
        counts[status_key] += 1
        exact_candidates = (
            []
            if non_hangul is None
            else non_hangul.get("candidate_characters", [])
        )
        fuzzy_candidates = (
            [] if fuzzy is None else fuzzy.get("best_characters", [])
        )
        if (
            not isinstance(exact_candidates, list)
            or not isinstance(fuzzy_candidates, list)
            or any(
                not isinstance(character, str) or len(character) != 1
                for character in [*exact_candidates, *fuzzy_candidates]
            )
        ):
            raise ValueError(
                "runtime glyph review candidate characters are invalid"
            )
        counts["maximum_exact_candidate_count"] = max(
            counts["maximum_exact_candidate_count"], len(exact_candidates)
        )
        counts["maximum_fuzzy_candidate_count"] = max(
            counts["maximum_fuzzy_candidate_count"], len(fuzzy_candidates)
        )
        counts["source_context_occurrence_count"] += len(
            coordinate_contexts
        )
        cards.append(
            {
                "page": coordinate[0],
                "symbol": coordinate[1],
                "occurrence_count": len(coordinate_contexts),
                "contexts": coordinate_contexts,
                "mask_rows_hex": (
                    [] if fuzzy is None else fuzzy.get("mask_rows_hex", [])
                ),
                "non_hangul_status": non_hangul_status,
                "exact_candidate_characters": exact_candidates,
                "exact_candidate_codepoints": (
                    []
                    if non_hangul is None
                    else non_hangul.get("candidate_codepoints", [])
                ),
                "fuzzy_candidate_characters": fuzzy_candidates,
                "fuzzy_candidate_codepoints": (
                    [] if fuzzy is None else fuzzy.get("best_codepoints", [])
                ),
                "fuzzy_best_distance": (
                    None if fuzzy is None else fuzzy.get("best_distance")
                ),
                "fuzzy_distance_margin": (
                    None if fuzzy is None else fuzzy.get("distance_margin")
                ),
            }
        )
    if seen != set(contexts):
        raise ValueError(
            "runtime glyph review demand and candidates disagree"
        )
    counts["glyph_card_count"] = len(cards)
    return counts, cards


def _render_mask(rows: object) -> str:
    if (
        not isinstance(rows, list)
        or len(rows) != 8
        or any(not isinstance(row, str) or len(row) != 2 for row in rows)
    ):
        return "<p class=\"muted\">마스크 없음</p>"
    cells: list[str] = []
    for row in rows:
        value = int(row, 16)
        for bit in range(7, -1, -1):
            css_class = "on" if value & (1 << bit) else "off"
            cells.append(f'<span class="{css_class}"></span>')
    return '<div class="mask">' + "".join(cells) + "</div>"


def render_runtime_glyph_review_html(
    *,
    cards: list[dict[str, object]],
    captured_utc: str,
) -> str:
    rendered_cards: list[str] = []
    for index, card in enumerate(cards, start=1):
        contexts = card["contexts"]
        assert isinstance(contexts, list)
        context_html = "".join(
            (
                '<div class="context">'
                f'<p><b>원문 문맥:</b> {escape(str(context.get("source_text") or ""))}</p>'
                f'<p><b>화자:</b> {escape(str(context.get("speaker") or "없음"))}</p>'
                f'<p><b>현재 대상:</b> {escape(str(context.get("target_text") or ""))}</p>'
                "</div>"
            )
            for context in contexts
            if isinstance(context, dict)
        )
        exact = " ".join(
            escape(character)
            for character in card["exact_candidate_characters"]
        ) or "없음"
        fuzzy = " ".join(
            escape(character)
            for character in card["fuzzy_candidate_characters"]
        ) or "없음"
        rendered_cards.append(
            "\n".join(
                [
                    '<section class="card">',
                    f"<h2>글자 {index} / {len(cards)}</h2>",
                    '<div class="row">',
                    _render_mask(card["mask_rows_hex"]),
                    '<div class="details">',
                    (
                        "<p><b>픽셀 완전일치 비한글 후보:</b> "
                        f'<span class="candidates">{exact}</span></p>'
                    ),
                    (
                        "<p><b>가까운 한글 후보(확정 아님):</b> "
                        f'<span class="candidates">{fuzzy}</span></p>'
                    ),
                    (
                        "<p><b>한글 후보 거리/여유:</b> "
                        f'{escape(str(card["fuzzy_best_distance"]))} / '
                        f'{escape(str(card["fuzzy_distance_margin"]))}</p>'
                    ),
                    "</div>",
                    "</div>",
                    context_html,
                    "</section>",
                ]
            )
        )
    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Shining Force KR 글자 검토</title>
<style>
body {{ margin: 0; padding: 18px; background: #111; color: #f4f4f4;
       font-family: sans-serif; line-height: 1.55; }}
.notice {{ background: #173b2b; border: 2px solid #43d17d; padding: 14px;
           border-radius: 12px; margin-bottom: 18px; }}
.card {{ background: #202020; border: 1px solid #555; border-radius: 12px;
         padding: 14px; margin: 0 0 18px; break-inside: avoid; }}
.row {{ display: flex; gap: 18px; align-items: flex-start; flex-wrap: wrap; }}
.mask {{ display: grid; grid-template-columns: repeat(8, 20px);
         grid-template-rows: repeat(8, 20px); background: #fff;
         border: 4px solid #ddd; image-rendering: pixelated; }}
.mask span {{ width: 20px; height: 20px; }}
.mask .on {{ background: #000; }} .mask .off {{ background: #fff; }}
.details {{ min-width: 240px; flex: 1; }}
.candidates {{ font-size: 2rem; letter-spacing: .35rem; color: #ffe36e; }}
.context {{ border-top: 1px solid #555; margin-top: 12px; padding-top: 8px; }}
.muted {{ color: #aaa; }}
</style>
</head>
<body>
<div class="notice">
<h1>Shining Force KR 글자 검토표</h1>
<p><b>사용자가 후보를 고르거나 파일을 수정할 필요는 없습니다.</b></p>
<p>이 페이지의 글자 카드가 모두 보이도록 스크린샷을 찍어
ChatGPT에 보내주세요. 그러면 문맥과 모양을 함께 판단합니다.</p>
<p class="muted">생성 시각: {escape(captured_utc)}</p>
</div>
{"".join(rendered_cards)}
</body>
</html>
"""


def build_runtime_context_glyph_review(
    *,
    target_sha256: str,
    runtime_context_glyph_demand_sha256: str,
    runtime_context_glyph_candidates_sha256: str,
    local_review_packet_sha256: str,
    review: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": "runtime-context-glyph-review-packet-ready",
        "target_sha256": target_sha256,
        "runtime_context_glyph_demand_sha256":
            runtime_context_glyph_demand_sha256,
        "runtime_context_glyph_candidates_sha256":
            runtime_context_glyph_candidates_sha256,
        "local_review_packet_sha256": local_review_packet_sha256,
        "captured_utc": captured_utc,
        "review": review,
        "automatic_character_selection_allowed": False,
        "human_character_review_required": True,
        "hancharacter_contract_mode": "translator_declared",
        "local_payload_policy": (
            "source-text-speakers-target-text-glyph-coordinates-masks-"
            "codepoints-characters-and-review-cards-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": "human-share-local-runtime-glyph-review",
    }
    validate_runtime_context_glyph_review(value)
    return value


def validate_runtime_context_glyph_review(
    value: dict[str, object],
) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError("runtime glyph review fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"] != "runtime-context-glyph-review-packet-ready"
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "runtime_context_glyph_demand_sha256",
                "runtime_context_glyph_candidates_sha256",
                "local_review_packet_sha256",
            )
        )
    ):
        raise ValueError("runtime glyph review identity is invalid")
    try:
        timestamp = datetime.fromisoformat(
            str(value["captured_utc"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError("runtime glyph review timestamp is invalid") from error
    if timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
        raise ValueError("runtime glyph review timestamp needs UTC")
    counts = value["review"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("runtime glyph review counts do not match")
    for key, count in counts.items():
        if not _bounded_int(count, 0, 0x1000000):
            raise ValueError(f"runtime glyph review {key} is invalid")
    cards = counts["glyph_card_count"]
    if (
        sum(
            counts[key]
            for key in (
                "unique_exact_non_hangul_card_count",
                "equivalent_exact_non_hangul_card_count",
                "ambiguous_exact_non_hangul_card_count",
                "unmatched_non_hangul_card_count",
                "out_of_range_non_hangul_card_count",
                "missing_non_hangul_card_count",
            )
        )
        != cards
        or counts["source_context_occurrence_count"]
        != counts["glyph_occurrence_count"]
        or value["automatic_character_selection_allowed"] is not False
        or value["human_character_review_required"] is not True
        or value["hancharacter_contract_mode"] != "translator_declared"
        or value["local_payload_policy"]
        != (
            "source-text-speakers-target-text-glyph-coordinates-masks-"
            "codepoints-characters-and-review-cards-local-only"
        )
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != "human-share-local-runtime-glyph-review"
    ):
        raise ValueError("runtime glyph review result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = {
        "demand": root / DEMAND_PATH,
        "local_demand": root / LOCAL_DEMAND_PATH,
        "candidates": root / CANDIDATES_PATH,
        "local_candidates": root / LOCAL_CANDIDATES_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print("Runtime context glyph review is not ready")
            return 0
        raise SystemExit("runtime glyph review input is missing")

    demand = _load_json_object(paths["demand"])
    local_demand = _load_json_object(paths["local_demand"])
    candidates = _load_json_object(paths["candidates"])
    local_candidates = _load_json_object(paths["local_candidates"])
    validate_runtime_context_glyph_demand(demand)
    validate_runtime_context_glyph_candidates(candidates)
    if (
        candidates["target_sha256"] != demand["target_sha256"]
        or candidates["runtime_context_glyph_demand_sha256"]
        != sha256_file(paths["demand"])
        or demand["local_demand_sha256"]
        != sha256_file(paths["local_demand"])
        or candidates["local_candidates_sha256"]
        != sha256_file(paths["local_candidates"])
        or local_demand.get("target_sha256") != demand["target_sha256"]
        or local_candidates.get("target_sha256") != demand["target_sha256"]
    ):
        raise ValueError("runtime glyph review input identity disagrees")
    demand_analysis = local_demand.get("analysis")
    candidate_analysis = local_candidates.get("analysis")
    if not isinstance(demand_analysis, dict) or not isinstance(
        candidate_analysis, dict
    ):
        raise ValueError("runtime glyph review local inputs are missing")
    counts, cards = build_runtime_glyph_review_rows(
        demand_analysis, candidate_analysis
    )
    if (
        counts["glyph_card_count"]
        != candidates["candidates"]["demanded_distinct_glyph_count"]
        or counts["glyph_occurrence_count"]
        != candidates["candidates"]["demanded_occurrence_count"]
    ):
        raise ValueError(
            "runtime glyph review aggregates disagree with candidates"
        )

    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    review_dir = root / LOCAL_REVIEW_DIR
    review_dir.mkdir(parents=True, exist_ok=True)
    html_path = root / LOCAL_REVIEW_HTML_PATH
    html = render_runtime_glyph_review_html(
        cards=cards, captured_utc=captured_utc
    )
    html_path.write_text(html, encoding="utf-8")
    pointer_path = root / LOCAL_REVIEW_POINTER_PATH
    pointer_path.write_text(
        "\n".join(
            [
                "Shining Force KR 글자 검토표",
                "",
                "1. 같은 폴더의 RUNTIME_GLYPH_REVIEW_LATEST.html 파일을 엽니다.",
                "2. 글자 카드가 모두 보이게 스크린샷을 찍습니다.",
                "3. 스크린샷을 ChatGPT에 보냅니다.",
                "",
                "후보를 고르거나 파일을 수정하지 마세요.",
                "ChatGPT가 원문 문맥과 글자 모양을 함께 판단합니다.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    packet_sha256 = hashlib.sha256(html.encode("utf-8")).hexdigest()
    local = {
        "artifact_kind": "local-v5-1-runtime-context-glyph-review",
        "schema_version": SCHEMA_VERSION,
        "target_sha256": demand["target_sha256"],
        "runtime_context_glyph_demand_sha256": sha256_file(paths["demand"]),
        "runtime_context_glyph_candidates_sha256":
            sha256_file(paths["candidates"]),
        "captured_utc": captured_utc,
        "review": counts,
        "cards": cards,
        "html_sha256": packet_sha256,
        "publication_policy": (
            "never-publish-source-text-speakers-target-text-glyph-"
            "coordinates-masks-codepoints-characters-or-review-cards"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_runtime_context_glyph_review(
        target_sha256=str(demand["target_sha256"]),
        runtime_context_glyph_demand_sha256=sha256_file(paths["demand"]),
        runtime_context_glyph_candidates_sha256=
            sha256_file(paths["candidates"]),
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
    print(f"SFKR runtime glyph review: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
