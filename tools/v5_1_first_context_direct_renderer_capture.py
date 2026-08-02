#!/usr/bin/env python3
"""Capture the first dialogue after rebuilding it on the observed font page."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import argparse

try:
    from .patch_io import sha256_file
    from .v5_1_first_context_translated_vram_diff import _capture_anchor_vram
    from .v5_1_first_context_translation_encoding import (
        LOCAL_REPORT_PATH as LOCAL_ENCODING_PATH,
    )
    from .v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TEST_BUILD_PATH,
        validate_first_context_translation_test_build,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_first_context_translated_vram_diff import _capture_anchor_vram
    from v5_1_first_context_translation_encoding import (
        LOCAL_REPORT_PATH as LOCAL_ENCODING_PATH,
    )
    from v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TEST_BUILD_PATH,
        validate_first_context_translation_test_build,
    )


ARTIFACT_KIND = "sanitized-v5-1-first-context-direct-renderer-capture"
SCHEMA_VERSION = 2
TEST_ROM_PATH = Path(
    "build/Final_Conflict_Korean_first_context_translation_test.gg"
)
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_direct_renderer_capture.json"
)
PUBLISH_IMAGE_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_direct_renderer_capture.png"
)
LOCAL_EVIDENCE_PATH = Path(
    "evidence/local/v5_1_first_context_direct_renderer_capture.png"
)
FAILURE_STAGE_PATH = Path(
    "reports/local/v5_1_first_context_direct_renderer_capture_failure_stage.txt"
)
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "baseline_target_sha256",
    "test_target_sha256",
    "first_context_translation_test_build_sha256",
    "local_encoding_sha256",
    "capture_png_sha256",
    "captured_utc",
    "runtime_entry",
    "renderer_route",
    "direct_renderer_first_row_confirmed",
    "cold_boot",
    "human_visual_review_required",
    "translation_build_eligible",
    "next_checkpoint",
}
RUNTIME_ENTRY_KEYS = {"selector", "ordinal"}


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_first_context_direct_renderer_capture(
    value: dict[str, object],
) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("direct renderer capture fields do not match")
    runtime_entry = value.get("runtime_entry")
    if (
        value.get("artifact_kind") != ARTIFACT_KIND
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("status") != "direct-renderer-first-screen-captured"
        or value.get("renderer_route")
        not in {"direct-observed-page", "proven-visible-page"}
        or not all(
            _is_sha256(value.get(key))
            for key in (
                "baseline_target_sha256",
                "test_target_sha256",
                "first_context_translation_test_build_sha256",
                "local_encoding_sha256",
                "capture_png_sha256",
            )
        )
        or not isinstance(runtime_entry, dict)
        or set(runtime_entry) != RUNTIME_ENTRY_KEYS
        or any(
            not isinstance(item, int) or isinstance(item, bool) or item < 0
            for item in runtime_entry.values()
        )
        or value.get("direct_renderer_first_row_confirmed") is not True
        or value.get("cold_boot") is not True
        or value.get("human_visual_review_required") is not True
        or value.get("translation_build_eligible") is not False
        or value.get("next_checkpoint")
        != "human-verify-first-direct-renderer-dialogue-screen"
    ):
        raise ValueError("direct renderer capture is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proven-visible-page", action="store_true")
    args = parser.parse_args()
    paths = {
        "rom": root / TEST_ROM_PATH,
        "build": root / TEST_BUILD_PATH,
        "encoding": root / LOCAL_ENCODING_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        raise SystemExit("direct renderer capture input is missing")
    build = json.loads(paths["build"].read_text(encoding="utf-8"))
    encoding = json.loads(paths["encoding"].read_text(encoding="utf-8"))
    if not isinstance(build, dict) or not isinstance(encoding, dict):
        raise ValueError("direct renderer capture input is invalid")
    validate_first_context_translation_test_build(build)
    rows = encoding.get("rows")
    if (
        sha256_file(paths["rom"]) != build["test_target_sha256"]
        or encoding.get("target_sha256") != build["baseline_target_sha256"]
        or not isinstance(rows, list)
        or not rows
        or not isinstance(rows[0], dict)
        or (
            rows[0].get("proven_visible_page_route") is not True
            if args.proven_visible_page
            else rows[0].get("direct_renderer_proof") is not True
        )
    ):
        raise ValueError("direct renderer capture identity disagrees")

    local_image = root / LOCAL_EVIDENCE_PATH
    failure_path = root / FAILURE_STAGE_PATH
    capture = _capture_anchor_vram(
        rom_path=paths["rom"],
        evidence_path=local_image,
        failure_stage_path=failure_path,
        phase_prefix="first-context-direct-renderer",
    )
    capture.pop("vram")
    publish_image = root / PUBLISH_IMAGE_RELATIVE_PATH
    publish_image.parent.mkdir(parents=True, exist_ok=True)
    publish_image.write_bytes(local_image.read_bytes())
    if not publish_image.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("direct renderer capture image is not PNG")
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": "direct-renderer-first-screen-captured",
        "baseline_target_sha256": build["baseline_target_sha256"],
        "test_target_sha256": build["test_target_sha256"],
        "first_context_translation_test_build_sha256": sha256_file(
            paths["build"]
        ),
        "local_encoding_sha256": sha256_file(paths["encoding"]),
        "capture_png_sha256": sha256_file(publish_image),
        "captured_utc": datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        "runtime_entry": {
            "selector": int(capture["selector"]),
            "ordinal": int(capture["ordinal"]),
        },
        "renderer_route": (
            "proven-visible-page"
            if args.proven_visible_page
            else "direct-observed-page"
        ),
        "direct_renderer_first_row_confirmed": True,
        "cold_boot": True,
        "human_visual_review_required": True,
        "translation_build_eligible": False,
        "next_checkpoint": "human-verify-first-direct-renderer-dialogue-screen",
    }
    validate_first_context_direct_renderer_capture(safe)
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    failure_path.unlink(missing_ok=True)
    print(f"SFKR direct renderer first screen: {publish_image}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
