#!/usr/bin/env python3
"""Cold-boot and capture the four translated first-context dialogue screens."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import html
import json
from pathlib import Path

try:
    from .patch_io import sha256_file
    from .v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TEST_BUILD_PATH,
        validate_first_context_translation_test_build,
    )
    from .v5_1_source_target_runtime_sequence import (
        COUNT_KEYS,
        PUBLISH_RELATIVE_PATH as SOURCE_SEQUENCE_PATH,
        capture_runtime_sequence,
        summarize_runtime_sequence,
        validate_source_target_runtime_sequence,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TEST_BUILD_PATH,
        validate_first_context_translation_test_build,
    )
    from v5_1_source_target_runtime_sequence import (
        COUNT_KEYS,
        PUBLISH_RELATIVE_PATH as SOURCE_SEQUENCE_PATH,
        capture_runtime_sequence,
        summarize_runtime_sequence,
        validate_source_target_runtime_sequence,
    )


ARTIFACT_KIND = (
    "sanitized-v5-1-first-context-translation-runtime-capture"
)
SCHEMA_VERSION = 1
TEST_ROM_PATH = Path(
    "build/Final_Conflict_Korean_first_context_translation_test.gg"
)
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/"
    "v5_1_latest_first_context_translation_runtime_capture.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_first_context_translation_runtime_capture.json"
)
LOCAL_EVIDENCE_DIR = Path(
    "evidence/local/v5_1_first_context_translation_runtime_capture"
)
LOCAL_REVIEW_PATH = Path(
    "reports/HUMAN_REVIEW_FIRST_CONTEXT_TRANSLATION.html"
)
EXPECTED_TRANSLATIONS = (
    "두고 봐라, 미샤엘라!",
    "호호호!",
    "그래, 아직도 떠날 생각이 없느냐?",
    "스파크 레벨 3을 써 주마!",
)
SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "baseline_target_sha256",
    "test_target_sha256",
    "first_context_translation_test_build_sha256",
    "source_runtime_sequence_sha256",
    "local_capture_sha256",
    "captured_utc",
    "runtime_sequence",
    "cold_boot",
    "test_media_identity_confirmed",
    "target_entry_sequence_confirmed",
    "human_visual_review_required",
    "runtime_layout_confirmed",
    "source_and_target_text_local_only",
    "translation_build_eligible",
    "next_checkpoint",
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


def build_first_context_translation_runtime_capture(
    *,
    baseline_target_sha256: str,
    test_target_sha256: str,
    first_context_translation_test_build_sha256: str,
    source_runtime_sequence_sha256: str,
    local_capture_sha256: str,
    runtime_sequence: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    sequence_confirmed = (
        runtime_sequence["captured_entry_count"] >= 4
        and runtime_sequence["post_anchor_entry_count"] >= 3
        and runtime_sequence["same_selector_post_anchor_entry_count"] >= 3
        and runtime_sequence["different_selector_post_anchor_entry_count"] == 0
        and runtime_sequence["consecutive_same_selector_step_count"] >= 3
        and runtime_sequence["nonconsecutive_same_selector_step_count"] == 0
        and runtime_sequence["distinct_screen_hash_count"] >= 4
    )
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "first-context-translation-runtime-capture-ready"
            if sequence_confirmed
            else "first-context-translation-runtime-capture-incomplete"
        ),
        "baseline_target_sha256": baseline_target_sha256,
        "test_target_sha256": test_target_sha256,
        "first_context_translation_test_build_sha256":
            first_context_translation_test_build_sha256,
        "source_runtime_sequence_sha256": source_runtime_sequence_sha256,
        "local_capture_sha256": local_capture_sha256,
        "captured_utc": captured_utc,
        "runtime_sequence": runtime_sequence,
        "cold_boot": True,
        "test_media_identity_confirmed": True,
        "target_entry_sequence_confirmed": sequence_confirmed,
        "human_visual_review_required": True,
        "runtime_layout_confirmed": False,
        "source_and_target_text_local_only": True,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "human-review-first-context-translation-runtime-screens"
            if sequence_confirmed
            else "retry-first-context-translation-runtime-capture"
        ),
    }
    validate_first_context_translation_runtime_capture(value)
    return value


def validate_first_context_translation_runtime_capture(
    value: dict[str, object],
) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError(
            "first context translation runtime capture fields do not match"
        )
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "first-context-translation-runtime-capture-ready",
            "first-context-translation-runtime-capture-incomplete",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "baseline_target_sha256",
                "test_target_sha256",
                "first_context_translation_test_build_sha256",
                "source_runtime_sequence_sha256",
                "local_capture_sha256",
            )
        )
        or value["baseline_target_sha256"] == value["test_target_sha256"]
        or not _is_utc_timestamp(value["captured_utc"])
    ):
        raise ValueError(
            "first context translation runtime capture identity is invalid"
        )
    counts = value["runtime_sequence"]
    if (
        not isinstance(counts, dict)
        or set(counts) != COUNT_KEYS
        or any(
            not isinstance(count, int)
            or isinstance(count, bool)
            or not 0 <= count <= 1000000
            for count in counts.values()
        )
    ):
        raise ValueError(
            "first context translation runtime capture counts do not match"
        )
    sequence_confirmed = (
        counts["captured_entry_count"] >= 4
        and counts["post_anchor_entry_count"] >= 3
        and counts["same_selector_post_anchor_entry_count"] >= 3
        and counts["different_selector_post_anchor_entry_count"] == 0
        and counts["consecutive_same_selector_step_count"] >= 3
        and counts["nonconsecutive_same_selector_step_count"] == 0
        and counts["distinct_screen_hash_count"] >= 4
    )
    if (
        value["status"]
        != (
            "first-context-translation-runtime-capture-ready"
            if sequence_confirmed
            else "first-context-translation-runtime-capture-incomplete"
        )
        or value["cold_boot"] is not True
        or value["test_media_identity_confirmed"] is not True
        or value["target_entry_sequence_confirmed"]
        is not sequence_confirmed
        or value["human_visual_review_required"] is not True
        or value["runtime_layout_confirmed"] is not False
        or value["source_and_target_text_local_only"] is not True
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != (
            "human-review-first-context-translation-runtime-screens"
            if sequence_confirmed
            else "retry-first-context-translation-runtime-capture"
        )
    ):
        raise ValueError(
            "first context translation runtime capture is inconsistent"
        )


def _write_review(
    *,
    root: Path,
    screenshots: list[dict[str, object]],
) -> None:
    cards = []
    for index, (translation, screenshot) in enumerate(
        zip(EXPECTED_TRANSLATIONS, screenshots),
        start=1,
    ):
        path = Path(str(screenshot["file"])).resolve()
        relative = path.relative_to(root.resolve()).as_posix()
        cards.append(
            "<article><h2>대사 "
            f"{index}/4</h2><p class=\"expected\">"
            f"{html.escape(translation)}</p>"
            f"<img src=\"../{html.escape(relative)}\" "
            f"alt=\"한글 대사 {index} 실행 화면\"></article>"
        )
    document = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Shining Force KR 첫 한글 대사 실행 검토</title>
<style>
body{margin:0;background:#111;color:#eee;font-family:sans-serif}
main{max-width:760px;margin:auto;padding:20px}
header,article{background:#1d1d1d;border:1px solid #555;border-radius:16px;
margin:0 0 18px;padding:20px}
h1{font-size:1.7rem}.expected{font-size:1.35rem;color:#7de7ff}
img{width:100%;height:auto;image-rendering:pixelated;border-radius:8px}
</style></head><body><main>
<header><h1>첫 한글 대사 4줄 실행 검토</h1>
<p>실제 테스트 ROM을 콜드부팅해 자동 캡처했습니다.</p>
<p>글자 깨짐, 잘림, 겹침, 잘못된 줄바꿈이 없는지 확인합니다.</p>
</header>
""" + "\n".join(cards) + """
</main></body></html>
"""
    review_path = root / LOCAL_REVIEW_PATH
    review_path.parent.mkdir(parents=True, exist_ok=True)
    review_path.write_text(document, encoding="utf-8")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = {
        "rom": root / TEST_ROM_PATH,
        "build": root / TEST_BUILD_PATH,
        "source_sequence": root / SOURCE_SEQUENCE_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print(
                "First context translation runtime capture is not ready"
            )
            return 0
        raise SystemExit(
            "first context translation runtime capture input is missing"
        )
    build = json.loads(paths["build"].read_text(encoding="utf-8"))
    source_sequence = json.loads(
        paths["source_sequence"].read_text(encoding="utf-8")
    )
    if not isinstance(build, dict) or not isinstance(source_sequence, dict):
        raise ValueError(
            "first context translation runtime capture inputs are invalid"
        )
    validate_first_context_translation_test_build(build)
    validate_source_target_runtime_sequence(source_sequence)
    if (
        build["status"] != "first-context-translation-static-build-ready"
        or source_sequence["status"]
        != "runtime-sequence-corroboration-ready"
        or sha256_file(paths["rom"]) != build["test_target_sha256"]
        or source_sequence["baseline_target_sha256"]
        != build["baseline_target_sha256"]
    ):
        raise ValueError(
            "first context translation runtime capture identity disagrees"
        )
    safe_path = root / PUBLISH_RELATIVE_PATH
    local_path = root / LOCAL_REPORT_PATH
    if safe_path.is_file() and local_path.is_file():
        try:
            existing = json.loads(safe_path.read_text(encoding="utf-8"))
            existing_local = json.loads(
                local_path.read_text(encoding="utf-8")
            )
            if (
                existing["test_target_sha256"]
                == build["test_target_sha256"]
                and existing["baseline_target_sha256"]
                == build["baseline_target_sha256"]
                and existing["local_capture_sha256"]
                == sha256_file(local_path)
            ):
                existing_counts = existing_local.get("runtime_sequence")
                existing_capture = existing_local.get("capture")
                if (
                    not isinstance(existing_counts, dict)
                    or not isinstance(existing_capture, dict)
                    or set(existing_counts) != COUNT_KEYS
                ):
                    raise ValueError(
                        "reusable first context runtime capture is invalid"
                    )
                refreshed = (
                    build_first_context_translation_runtime_capture(
                        baseline_target_sha256=str(
                            build["baseline_target_sha256"]
                        ),
                        test_target_sha256=str(
                            build["test_target_sha256"]
                        ),
                        first_context_translation_test_build_sha256=
                            sha256_file(paths["build"]),
                        source_runtime_sequence_sha256=sha256_file(
                            paths["source_sequence"]
                        ),
                        local_capture_sha256=sha256_file(local_path),
                        runtime_sequence=existing_counts,
                        captured_utc=str(existing["captured_utc"]),
                    )
                )
                screens = existing_capture.get("screens")
                if isinstance(screens, list):
                    _write_review(root=root, screenshots=screens)
                safe_path.write_text(
                    json.dumps(
                        refreshed,
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                print(
                    "SFKR first context translation runtime capture: "
                    "refreshed matching local capture"
                )
                return 0
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    evidence_dir = (
        root
        / LOCAL_EVIDENCE_DIR
        / str(build["test_target_sha256"])[:16]
    )
    evidence_dir.mkdir(parents=True, exist_ok=True)
    observations, advance_attempt_count, local_capture = (
        capture_runtime_sequence(
            rom_path=paths["rom"],
            rom_size=paths["rom"].stat().st_size,
            evidence_dir=evidence_dir,
        )
    )
    counts, status, first_consecutive = summarize_runtime_sequence(
        observations,
        advance_attempt_count=advance_attempt_count,
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    local = {
        "artifact_kind":
            "local-v5-1-first-context-translation-runtime-capture",
        "schema_version": SCHEMA_VERSION,
        "baseline_target_sha256": build["baseline_target_sha256"],
        "test_target_sha256": build["test_target_sha256"],
        "captured_utc": captured_utc,
        "runtime_sequence": counts,
        "source_sequence_status": status,
        "first_post_anchor_step_consecutive": first_consecutive,
        "observations": observations,
        "capture": local_capture,
        "review_path": str(root / LOCAL_REVIEW_PATH),
        "expected_translations": list(EXPECTED_TRANSLATIONS),
        "publication_policy": (
            "never-publish-screens-selectors-ordinals-registers-hit-order-"
            "or-source-and-target-text"
        ),
    }
    screens = local_capture.get("screens")
    if not isinstance(screens, list):
        raise RuntimeError(
            "first context translation runtime screenshots are missing"
        )
    _write_review(root=root, screenshots=screens)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_first_context_translation_runtime_capture(
        baseline_target_sha256=str(build["baseline_target_sha256"]),
        test_target_sha256=str(build["test_target_sha256"]),
        first_context_translation_test_build_sha256=sha256_file(
            paths["build"]
        ),
        source_runtime_sequence_sha256=sha256_file(
            paths["source_sequence"]
        ),
        local_capture_sha256=sha256_file(local_path),
        runtime_sequence=counts,
        captured_utc=captured_utc,
    )
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR first context translation runtime capture: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
