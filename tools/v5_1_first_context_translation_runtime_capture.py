#!/usr/bin/env python3
"""Cold-boot and capture every approved first-context dialogue screen."""

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
    from .v5_1_first_context_translation_approval import (
        LOCAL_REPORT_PATH as LOCAL_APPROVAL_PATH,
        validate_local_first_context_translation_approval,
    )
    from .v5_1_source_target_runtime_sequence import (
        COUNT_KEYS,
        PUBLISH_RELATIVE_PATH as SOURCE_SEQUENCE_PATH,
        capture_runtime_sequence,
        summarize_runtime_sequence,
        validate_source_target_runtime_sequence,
    )
    from .v5_1_source_target_anchor import (
        CONFIRMED_ORDINAL,
        CONFIRMED_SELECTOR,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TEST_BUILD_PATH,
        validate_first_context_translation_test_build,
    )
    from v5_1_first_context_translation_approval import (
        LOCAL_REPORT_PATH as LOCAL_APPROVAL_PATH,
        validate_local_first_context_translation_approval,
    )
    from v5_1_source_target_runtime_sequence import (
        COUNT_KEYS,
        PUBLISH_RELATIVE_PATH as SOURCE_SEQUENCE_PATH,
        capture_runtime_sequence,
        summarize_runtime_sequence,
        validate_source_target_runtime_sequence,
    )
    from v5_1_source_target_anchor import (
        CONFIRMED_ORDINAL,
        CONFIRMED_SELECTOR,
    )

try:
    from .run_s25u_runtime_probe import (
        _runtime_failure_kind,
        _write_runtime_failure_receipt,
    )
    from .v5_1_runtime_stage_failure import (
        build_first_context_runtime_capture_failure,
    )
except ImportError:  # pragma: no cover - direct script execution
    from run_s25u_runtime_probe import (
        _runtime_failure_kind,
        _write_runtime_failure_receipt,
    )
    from v5_1_runtime_stage_failure import (
        build_first_context_runtime_capture_failure,
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
FAILURE_PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/"
    "v5_1_latest_first_context_translation_runtime_capture_failure.json"
)
ACTIVE_CAPTURE_FAILURE_STAGE = "first-context-runtime-capture-input"
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
    "expected_entry_count",
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
    expected_entry_count: int,
    runtime_sequence: dict[str, int],
    captured_utc: str,
) -> dict[str, object]:
    sequence_confirmed = (
        expected_entry_count >= 4
        and runtime_sequence["captured_entry_count"] == expected_entry_count
        and runtime_sequence["post_anchor_entry_count"]
        == expected_entry_count - 1
        and runtime_sequence["same_selector_post_anchor_entry_count"]
        == expected_entry_count - 1
        and runtime_sequence["different_selector_post_anchor_entry_count"] == 0
        and runtime_sequence["consecutive_same_selector_step_count"]
        == expected_entry_count - 1
        and runtime_sequence["nonconsecutive_same_selector_step_count"] == 0
        and runtime_sequence["distinct_screen_hash_count"]
        >= expected_entry_count
        and runtime_sequence["runtime_initial_context_observation_count"]
        == expected_entry_count
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
        "expected_entry_count": expected_entry_count,
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
        or not isinstance(value["expected_entry_count"], int)
        or isinstance(value["expected_entry_count"], bool)
        or not 4 <= value["expected_entry_count"] <= 100
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
    expected_entry_count = value["expected_entry_count"]
    sequence_confirmed = (
        counts["captured_entry_count"] == expected_entry_count
        and counts["post_anchor_entry_count"] == expected_entry_count - 1
        and counts["same_selector_post_anchor_entry_count"]
        == expected_entry_count - 1
        and counts["different_selector_post_anchor_entry_count"] == 0
        and counts["consecutive_same_selector_step_count"]
        == expected_entry_count - 1
        and counts["nonconsecutive_same_selector_step_count"] == 0
        and counts["distinct_screen_hash_count"] >= expected_entry_count
        and counts["runtime_initial_context_observation_count"]
        == expected_entry_count
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
    translations: list[str],
    screenshots: list[dict[str, object]],
) -> None:
    if len(translations) != len(screenshots) or len(translations) < 4:
        raise ValueError("first context review screen count disagrees")
    if any(not translation for translation in translations):
        raise ValueError("first context review translation is empty")
    total = len(translations)
    cards = []
    for index, (translation, screenshot) in enumerate(
        zip(translations, screenshots),
        start=1,
    ):
        path = Path(str(screenshot["file"])).resolve()
        relative = path.relative_to(root.resolve()).as_posix()
        cards.append(
            "<article><h2>대사 "
            f"{index}/{total}</h2><p class=\"expected\">"
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
<header><h1>첫 한글 대사 실행 검토</h1>
<p>실제 테스트 ROM을 콜드부팅해 자동 캡처했습니다.</p>
<p>글자 깨짐, 잘림, 겹침, 잘못된 줄바꿈이 없는지 확인합니다.</p>
</header>
""" + "\n".join(cards) + """
</main></body></html>
"""
    review_path = root / LOCAL_REVIEW_PATH
    review_path.parent.mkdir(parents=True, exist_ok=True)
    review_path.write_text(document, encoding="utf-8")


def select_target_runtime_sequence(
    *,
    observations: list[dict[str, object]],
    screenshots: list[dict[str, object]],
    expected_entry_count: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    if (
        len(observations) != len(screenshots)
        or not 1 <= expected_entry_count <= 100
    ):
        raise ValueError("first context captured screen sequence is invalid")
    selected_observations = []
    selected_screens = []
    for observation, screenshot in zip(observations, screenshots):
        if observation.get("selector") != CONFIRMED_SELECTOR:
            continue
        selected_observations.append(observation)
        selected_screens.append(screenshot)
        if len(selected_observations) == expected_entry_count:
            break
    return selected_observations, selected_screens


def _main() -> int:
    global ACTIVE_CAPTURE_FAILURE_STAGE
    ACTIVE_CAPTURE_FAILURE_STAGE = "first-context-runtime-capture-input"
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = {
        "rom": root / TEST_ROM_PATH,
        "build": root / TEST_BUILD_PATH,
        "source_sequence": root / SOURCE_SEQUENCE_PATH,
        "local_approval": root / LOCAL_APPROVAL_PATH,
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
    ACTIVE_CAPTURE_FAILURE_STAGE = (
        "first-context-runtime-capture-build-validation"
    )
    build = json.loads(paths["build"].read_text(encoding="utf-8"))
    if not isinstance(build, dict):
        raise ValueError(
            "first context translation runtime build input is invalid"
        )
    validate_first_context_translation_test_build(build)
    ACTIVE_CAPTURE_FAILURE_STAGE = (
        "first-context-runtime-capture-source-sequence-validation"
    )
    source_sequence = json.loads(
        paths["source_sequence"].read_text(encoding="utf-8")
    )
    if not isinstance(source_sequence, dict):
        raise ValueError(
            "first context translation runtime sequence input is invalid"
        )
    validate_source_target_runtime_sequence(source_sequence)
    ACTIVE_CAPTURE_FAILURE_STAGE = (
        "first-context-runtime-capture-approval-validation"
    )
    local_approval = json.loads(
        paths["local_approval"].read_text(encoding="utf-8")
    )
    if not isinstance(local_approval, dict):
        raise ValueError(
            "first context translation runtime approval input is invalid"
        )
    validate_local_first_context_translation_approval(local_approval)
    approval_rows = local_approval.get("rows")
    expected_entry_count = int(build["verification"]["context_entry_count"])
    if not isinstance(approval_rows, list):
        raise ValueError("first context runtime approval rows are missing")
    translations = [str(row.get("target_text", "")) for row in approval_rows]
    ACTIVE_CAPTURE_FAILURE_STAGE = "first-context-runtime-capture-identity"
    if (
        build["status"] != "first-context-translation-static-build-ready"
        or source_sequence["status"]
        != "runtime-sequence-corroboration-ready"
        or sha256_file(paths["rom"]) != build["test_target_sha256"]
        or source_sequence["baseline_target_sha256"]
        != build["baseline_target_sha256"]
        or local_approval["target_sha256"] != build["baseline_target_sha256"]
        or len(translations) != expected_entry_count
    ):
        raise ValueError(
            "first context translation runtime capture identity disagrees"
        )
    ACTIVE_CAPTURE_FAILURE_STAGE = "first-context-runtime-capture-validation"
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
                        expected_entry_count=expected_entry_count,
                        runtime_sequence=existing_counts,
                        captured_utc=str(existing["captured_utc"]),
                    )
                )
                screens = existing_capture.get("screens")
                if isinstance(screens, list):
                    _write_review(
                        root=root,
                        translations=translations,
                        screenshots=screens,
                    )
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
                (root / FAILURE_PUBLISH_RELATIVE_PATH).unlink(missing_ok=True)
                return 0
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    ACTIVE_CAPTURE_FAILURE_STAGE = "first-context-runtime-capture-sequence"
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
    raw_screens = local_capture.get("screens")
    if not isinstance(raw_screens, list):
        raise RuntimeError(
            "first context translation runtime screenshots are missing"
        )
    selected_observations, selected_screens = select_target_runtime_sequence(
        observations=observations,
        screenshots=raw_screens,
        expected_entry_count=expected_entry_count,
    )
    ACTIVE_CAPTURE_FAILURE_STAGE = (
        "first-context-runtime-capture-summary-validation"
    )
    counts, status, first_consecutive = summarize_runtime_sequence(
        selected_observations,
        advance_attempt_count=advance_attempt_count,
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    ACTIVE_CAPTURE_FAILURE_STAGE = (
        "first-context-runtime-capture-output-validation"
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
        "expected_translations": translations,
        "publication_policy": (
            "never-publish-screens-selectors-ordinals-registers-hit-order-"
            "or-source-and-target-text"
        ),
    }
    screens = local_capture.get("screens")
    ACTIVE_CAPTURE_FAILURE_STAGE = (
        "first-context-runtime-capture-screen-validation"
    )
    if not isinstance(screens, list):
        raise RuntimeError(
            "first context translation runtime screenshots are missing"
        )
    ACTIVE_CAPTURE_FAILURE_STAGE = "first-context-runtime-capture-review-write"
    _write_review(
        root=root,
        translations=translations,
        screenshots=selected_screens,
    )
    ACTIVE_CAPTURE_FAILURE_STAGE = "first-context-runtime-capture-local-write"
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    ACTIVE_CAPTURE_FAILURE_STAGE = "first-context-runtime-capture-safe-build"
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
        expected_entry_count=expected_entry_count,
        runtime_sequence=counts,
        captured_utc=captured_utc,
    )
    ACTIVE_CAPTURE_FAILURE_STAGE = "first-context-runtime-capture-safe-write"
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (root / FAILURE_PUBLISH_RELATIVE_PATH).unlink(missing_ok=True)
    print(f"SFKR first context translation runtime capture: {safe_path}")
    return 0


def main() -> int:
    try:
        return _main()
    except Exception as error:
        root = Path(__file__).resolve().parents[1]
        captured_utc = datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
        runtime_failure: dict[str, object] = {
            "schema_version": 1,
            "failure_stage": ACTIVE_CAPTURE_FAILURE_STAGE,
            "failure_kind": _runtime_failure_kind(error),
            "mcp_method": None,
        }
        _write_runtime_failure_receipt(root, runtime_failure)
        safe_failure = build_first_context_runtime_capture_failure(
            pipeline_stage=ACTIVE_CAPTURE_FAILURE_STAGE,
            runtime_failure=runtime_failure,
            captured_utc=captured_utc,
        )
        failure_path = root / FAILURE_PUBLISH_RELATIVE_PATH
        failure_path.parent.mkdir(parents=True, exist_ok=True)
        failure_path.write_text(
            json.dumps(safe_failure, ensure_ascii=True, indent=2) + "\n",
            encoding="utf-8",
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
