#!/usr/bin/env python3
"""Build a sanitized pixel comparison for paired S25U display captures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


ARTIFACT_KIND = "sanitized-s25u-test-display-comparison"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_display_comparison.json"
)
RESULTS = {
    "no-visible-pixel-change",
    "visible-pixel-change-human-review-required",
    "comparison-unavailable",
}
FRAME_KEYS = {
    "frame_after_hit",
    "width",
    "height",
    "total_pixels",
    "changed_pixels",
    "difference_bounds",
    "baseline_png_sha256",
    "test_png_sha256",
    "baseline_pixel_sha256",
    "test_pixel_sha256",
}
BOUNDS_KEYS = {
    "left",
    "top",
    "right_exclusive",
    "bottom_exclusive",
}
STREAM_KEYS = {"physical_start", "logical_start", "mapped_bank"}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "baseline_target_sha256",
    "test_target_sha256",
    "compared_stream",
    "frame_comparisons",
    "post_advance_comparison",
    "result",
    "automatic_rejected_physical_starts",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _validate_stream(value: object) -> None:
    if not isinstance(value, dict) or set(value) != STREAM_KEYS:
        raise ValueError("compared stream fields do not match")
    for key, maximum in (
        ("physical_start", 0x17BFFF),
        ("logical_start", 0xFFFF),
        ("mapped_bank", 0xFF),
    ):
        item = value[key]
        if (
            not isinstance(item, int)
            or isinstance(item, bool)
            or not 0 <= item <= maximum
        ):
            raise ValueError(f"compared stream {key} is invalid")


def _validate_comparison(value: object, label: str, *, post_advance: bool) -> None:
    required = FRAME_KEYS - {"frame_after_hit"} if post_advance else FRAME_KEYS
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError(f"{label} fields do not match")
    if not post_advance:
        frame = value["frame_after_hit"]
        if not isinstance(frame, int) or isinstance(frame, bool) or frame <= 0:
            raise ValueError(f"{label} frame is invalid")
    width = value["width"]
    height = value["height"]
    total = value["total_pixels"]
    changed = value["changed_pixels"]
    if (
        not isinstance(width, int)
        or isinstance(width, bool)
        or not 1 <= width <= 1024
        or not isinstance(height, int)
        or isinstance(height, bool)
        or not 1 <= height <= 1024
        or total != width * height
        or not isinstance(changed, int)
        or isinstance(changed, bool)
        or not 0 <= changed <= total
    ):
        raise ValueError(f"{label} pixel counts are invalid")
    for key in (
        "baseline_png_sha256",
        "test_png_sha256",
        "baseline_pixel_sha256",
        "test_pixel_sha256",
    ):
        if not _is_sha256(value[key]):
            raise ValueError(f"{label} {key} is invalid")
    bounds = value["difference_bounds"]
    if changed == 0:
        if bounds is not None:
            raise ValueError(f"{label} unchanged pixels cannot have bounds")
        if value["baseline_pixel_sha256"] != value["test_pixel_sha256"]:
            raise ValueError(f"{label} unchanged pixel hashes disagree")
    else:
        if not isinstance(bounds, dict) or set(bounds) != BOUNDS_KEYS:
            raise ValueError(f"{label} changed pixels require bounds")
        left = bounds["left"]
        top = bounds["top"]
        right = bounds["right_exclusive"]
        bottom = bounds["bottom_exclusive"]
        if (
            not all(isinstance(item, int) and not isinstance(item, bool) for item in bounds.values())
            or not 0 <= left < right <= width
            or not 0 <= top < bottom <= height
            or value["baseline_pixel_sha256"] == value["test_pixel_sha256"]
        ):
            raise ValueError(f"{label} difference bounds are invalid")


def validate_display_comparison(comparison: dict[str, object]) -> None:
    if set(comparison) != TOP_LEVEL_KEYS:
        raise ValueError("display comparison top-level fields do not match")
    if comparison["artifact_kind"] != ARTIFACT_KIND:
        raise ValueError("unexpected display comparison artifact kind")
    if comparison["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unexpected display comparison schema")
    for key in ("baseline_target_sha256", "test_target_sha256"):
        if not _is_sha256(comparison[key]):
            raise ValueError(f"{key} must be a lowercase SHA-256")
    if comparison["baseline_target_sha256"] == comparison["test_target_sha256"]:
        raise ValueError("baseline and test target identities must differ")
    _validate_stream(comparison["compared_stream"])
    frames = comparison["frame_comparisons"]
    if not isinstance(frames, list) or len(frames) > 16:
        raise ValueError("frame comparisons must contain at most 16 items")
    previous_frame = 0
    for index, item in enumerate(frames):
        _validate_comparison(item, f"frame_comparisons[{index}]", post_advance=False)
        assert isinstance(item, dict)
        frame = int(item["frame_after_hit"])
        if frame <= previous_frame:
            raise ValueError("comparison frames must be strictly increasing")
        previous_frame = frame
    post_advance = comparison["post_advance_comparison"]
    if post_advance is not None:
        _validate_comparison(post_advance, "post_advance_comparison", post_advance=True)
    result = comparison["result"]
    if result not in RESULTS:
        raise ValueError("unexpected display comparison result")
    rejected = comparison["automatic_rejected_physical_starts"]
    if (
        not isinstance(rejected, list)
        or len(rejected) > 64
        or any(
            not isinstance(item, int)
            or isinstance(item, bool)
            or not 0 <= item <= 0x17BFFF
            for item in rejected
        )
        or rejected != sorted(set(rejected))
    ):
        raise ValueError("automatic rejected stream coordinates are invalid")
    changed = any(
        isinstance(item, dict) and int(item["changed_pixels"]) > 0
        for item in frames
    ) or (
        isinstance(post_advance, dict)
        and int(post_advance["changed_pixels"]) > 0
    )
    complete = bool(frames) and post_advance is not None
    stream = comparison["compared_stream"]
    assert isinstance(stream, dict)
    current_rejected = int(stream["physical_start"]) in rejected
    if result == "no-visible-pixel-change":
        if not complete or changed or not current_rejected:
            raise ValueError("automatic no-change rejection evidence is incomplete")
    elif result == "visible-pixel-change-human-review-required":
        if not complete or not changed or current_rejected:
            raise ValueError("visible-change comparison evidence is inconsistent")
    elif frames or post_advance is not None or current_rejected:
        raise ValueError("unavailable comparison cannot reject the current stream")
    if comparison["translation_build_eligible"] is not False:
        raise ValueError("display comparison cannot enable translation builds")
    expected_checkpoint = {
        "no-visible-pixel-change": "try-next-runtime-observed-stream",
        "visible-pixel-change-human-review-required": (
            "human-review-visible-pixel-change"
        ),
        "comparison-unavailable": "human-review-unpaired-capture",
    }[str(result)]
    if comparison["next_checkpoint"] != expected_checkpoint:
        raise ValueError("display comparison next checkpoint is inconsistent")


def build_display_comparison(
    *,
    build_report: dict[str, object],
    frame_comparisons: list[dict[str, object]],
    post_advance_comparison: dict[str, object] | None,
    prior_rejected_physical_starts: set[int] | None = None,
) -> dict[str, object]:
    runtime_entry = build_report.get("runtime_entry")
    if not isinstance(runtime_entry, dict):
        raise ValueError("test build report has no runtime entry")
    stream = {
        "physical_start": int(runtime_entry["target_file_offset"]),
        "logical_start": int(runtime_entry["pointer_address"]),
        "mapped_bank": int(runtime_entry["pointer_bank"]),
    }
    complete = bool(frame_comparisons) and post_advance_comparison is not None
    changed = any(int(item["changed_pixels"]) > 0 for item in frame_comparisons)
    if post_advance_comparison is not None:
        changed = changed or int(post_advance_comparison["changed_pixels"]) > 0
    rejected = set(prior_rejected_physical_starts or set())
    if complete and not changed:
        result = "no-visible-pixel-change"
        rejected.add(stream["physical_start"])
    elif complete:
        result = "visible-pixel-change-human-review-required"
    else:
        result = "comparison-unavailable"
    comparison = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "baseline_target_sha256": build_report["baseline_target_sha256"],
        "test_target_sha256": build_report["test_target_sha256"],
        "compared_stream": stream,
        "frame_comparisons": frame_comparisons,
        "post_advance_comparison": post_advance_comparison,
        "result": result,
        "automatic_rejected_physical_starts": sorted(rejected),
        "translation_build_eligible": False,
        "next_checkpoint": {
            "no-visible-pixel-change": "try-next-runtime-observed-stream",
            "visible-pixel-change-human-review-required": (
                "human-review-visible-pixel-change"
            ),
            "comparison-unavailable": "human-review-unpaired-capture",
        }[result],
    }
    validate_display_comparison(comparison)
    return comparison


def prior_automatic_rejections(root: Path, baseline_sha256: str) -> set[int]:
    path = root.resolve() / PUBLISH_RELATIVE_PATH
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            return set()
        validate_display_comparison(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return set()
    if value["baseline_target_sha256"] != baseline_sha256:
        return set()
    rejected = value["automatic_rejected_physical_starts"]
    assert isinstance(rejected, list)
    return {int(item) for item in rejected}


def write_display_comparison(
    root: Path,
    comparison: dict[str, object],
) -> Path:
    validate_display_comparison(comparison)
    path = root.resolve() / PUBLISH_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(comparison, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--result-only",
        action="store_true",
        help="print the validated current comparison result",
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    path = root / PUBLISH_RELATIVE_PATH
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("display comparison must be a JSON object")
    validate_display_comparison(value)
    if args.result_only:
        build_report_path = root / "reports/local/v5_1_test_patch_build.json"
        build_report = json.loads(build_report_path.read_text(encoding="utf-8"))
        if (
            not isinstance(build_report, dict)
            or value["baseline_target_sha256"]
            != build_report.get("baseline_target_sha256")
            or value["test_target_sha256"]
            != build_report.get("test_target_sha256")
        ):
            raise ValueError(
                "display comparison does not match the current test build"
            )
        print(value["result"])
    else:
        print(
            "SFKR display comparison: "
            f"{value['result']} "
            f"({len(value['automatic_rejected_physical_starts'])} "
            "automatic rejection(s))"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
