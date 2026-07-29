#!/usr/bin/env python3
"""Write a sanitized receipt for a failed S25U runtime pipeline substage."""

from __future__ import annotations

import argparse
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
            print(f"SFKR runtime failure receipt kept: {existing['failure_stage']}")
            return 0
        except (OSError, ValueError, json.JSONDecodeError):
            pass

    receipt = build_stage_failure_receipt(args.stage)
    written = _write_runtime_failure_receipt(root, receipt)
    print(f"SFKR runtime failure receipt: {receipt['failure_stage']} ({written})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
