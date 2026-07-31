#!/usr/bin/env python3
"""Write a sanitized receipt for a failed S25U runtime pipeline substage."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

try:
    from .run_s25u_runtime_probe import (
        LOCAL_FAILURE_REPORT,
        RUNTIME_FAILURE_STAGES,
        _write_runtime_failure_receipt,
        validate_runtime_failure_receipt,
    )
except ImportError:  # direct script execution
    from run_s25u_runtime_probe import (
        LOCAL_FAILURE_REPORT,
        RUNTIME_FAILURE_STAGES,
        _write_runtime_failure_receipt,
        validate_runtime_failure_receipt,
    )


RUNTIME_CAPTURE_FAILURE_PATH = Path(
    "analysis/device/"
    "v5_1_latest_first_context_translation_runtime_capture_failure.json"
)


def _is_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return False
    return True


def _is_first_context_runtime_capture_stage(stage: str) -> bool:
    return stage.startswith("first-context-") and "runtime-capture" in stage


def build_first_context_runtime_capture_failure(
    *,
    pipeline_stage: str,
    runtime_failure: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    validate_runtime_failure_receipt(runtime_failure)
    if (
        pipeline_stage not in RUNTIME_FAILURE_STAGES
        or not _is_first_context_runtime_capture_stage(pipeline_stage)
        or not _is_utc_timestamp(captured_utc)
    ):
        raise ValueError("runtime capture failure inputs are invalid")
    value: dict[str, object] = {
        "artifact_kind": (
            "sanitized-v5-1-first-context-translation-runtime-capture-failure"
        ),
        "schema_version": 1,
        "status": "first-context-translation-runtime-capture-failed",
        "pipeline_stage": pipeline_stage,
        "failure_stage": runtime_failure["failure_stage"],
        "failure_kind": runtime_failure["failure_kind"],
        "mcp_method": runtime_failure["mcp_method"],
        "captured_utc": captured_utc,
        "source_and_target_text_local_only": True,
        "next_checkpoint": "repair-first-context-translation-runtime-capture",
    }
    validate_first_context_runtime_capture_failure(value)
    return value


def validate_first_context_runtime_capture_failure(
    value: dict[str, object],
) -> None:
    if set(value) != {
        "artifact_kind",
        "schema_version",
        "status",
        "pipeline_stage",
        "failure_stage",
        "failure_kind",
        "mcp_method",
        "captured_utc",
        "source_and_target_text_local_only",
        "next_checkpoint",
    }:
        raise ValueError("runtime capture failure fields do not match")
    runtime_failure = {
        "schema_version": 1,
        "failure_stage": value["failure_stage"],
        "failure_kind": value["failure_kind"],
        "mcp_method": value["mcp_method"],
    }
    validate_runtime_failure_receipt(runtime_failure)
    if (
        value["artifact_kind"]
        != "sanitized-v5-1-first-context-translation-runtime-capture-failure"
        or value["schema_version"] != 1
        or value["status"]
        != "first-context-translation-runtime-capture-failed"
        or value["pipeline_stage"] not in RUNTIME_FAILURE_STAGES
        or not isinstance(value["pipeline_stage"], str)
        or not _is_first_context_runtime_capture_stage(
            value["pipeline_stage"]
        )
        or not _is_utc_timestamp(value["captured_utc"])
        or value["source_and_target_text_local_only"] is not True
        or value["next_checkpoint"]
        != "repair-first-context-translation-runtime-capture"
    ):
        raise ValueError("runtime capture failure is inconsistent")


def _publish_first_context_runtime_capture_failure(
    *,
    root: Path,
    pipeline_stage: str,
    runtime_failure: dict[str, object],
) -> Path:
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    value = build_first_context_runtime_capture_failure(
        pipeline_stage=pipeline_stage,
        runtime_failure=runtime_failure,
        captured_utc=captured_utc,
    )
    path = root / RUNTIME_CAPTURE_FAILURE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def build_stage_failure_receipt(stage: str) -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema_version": 1,
        "failure_stage": stage,
        "failure_kind": "runtime-error",
        "mcp_method": None,
    }
    validate_runtime_failure_receipt(receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=sorted(RUNTIME_FAILURE_STAGES), required=True)
    parser.add_argument("--if-missing", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    path = root / LOCAL_FAILURE_REPORT
    if args.if_missing and path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(existing, dict):
                raise ValueError("runtime failure receipt must be an object")
            validate_runtime_failure_receipt(existing)
            if _is_first_context_runtime_capture_stage(args.stage):
                _publish_first_context_runtime_capture_failure(
                    root=root,
                    pipeline_stage=args.stage,
                    runtime_failure=existing,
                )
            print(f"SFKR runtime failure receipt kept: {existing['failure_stage']}")
            return 0
        except (OSError, ValueError, json.JSONDecodeError):
            pass

    receipt = build_stage_failure_receipt(args.stage)
    written = _write_runtime_failure_receipt(root, receipt)
    if _is_first_context_runtime_capture_stage(args.stage):
        _publish_first_context_runtime_capture_failure(
            root=root,
            pipeline_stage=args.stage,
            runtime_failure=receipt,
        )
    print(f"SFKR runtime failure receipt: {receipt['failure_stage']} ({written})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
