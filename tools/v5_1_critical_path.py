#!/usr/bin/env python3
"""Select one evidence-backed runtime task instead of replaying the whole pipeline."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_active_ram_register_trace import (
        LOCAL_REPORT_PATH as REGISTER_TRACE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as REGISTER_TRACE_PATH,
        validate_active_ram_register_trace,
    )
    from .v5_1_active_register_rom_source import (
        PUBLISH_RELATIVE_PATH as ROM_SOURCE_PATH,
        validate_active_register_rom_source,
    )
    from .v5_1_active_rom_source_role import (
        PUBLISH_RELATIVE_PATH as ROM_SOURCE_ROLE_PATH,
        validate_active_rom_source_role,
    )
    from .v5_1_renderer_output_trace import DEFAULT_ROM
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_active_ram_register_trace import (
        LOCAL_REPORT_PATH as REGISTER_TRACE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as REGISTER_TRACE_PATH,
        validate_active_ram_register_trace,
    )
    from v5_1_active_register_rom_source import (
        PUBLISH_RELATIVE_PATH as ROM_SOURCE_PATH,
        validate_active_register_rom_source,
    )
    from v5_1_active_rom_source_role import (
        PUBLISH_RELATIVE_PATH as ROM_SOURCE_ROLE_PATH,
        validate_active_rom_source_role,
    )
    from v5_1_renderer_output_trace import DEFAULT_ROM


ARTIFACT_KIND = "sanitized-s25u-critical-path"
SCHEMA_VERSION = 2
PUBLISH_RELATIVE_PATH = Path("analysis/device/v5_1_latest_critical_path.json")
FOCUSED_STAGE = "active-register-rom-source"
SOURCE_ROLE_STAGE = "active-rom-source-role"
FALLBACK_STAGE = "continue"
STAGE_POLICIES = {
    FOCUSED_STAGE: {
        "confirmed_boundary": "active-vram-to-register-rom-window-read",
        "blocked_boundary": "logical-rom-window-read-to-physical-rom-source",
        "selection_reason": "current-register-trace-ready-current-rom-source-missing",
        "next_checkpoint": "map-active-register-rom-source",
    },
    SOURCE_ROLE_STAGE: {
        "confirmed_boundary": "active-vram-to-physical-rom-source",
        "blocked_boundary": "physical-rom-source-to-source-role",
        "selection_reason": "current-rom-source-ready-current-role-missing",
        "next_checkpoint": "classify-active-rom-source-role",
    },
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_register_trace_sha256",
    "selected_stage",
    "confirmed_boundary",
    "blocked_boundary",
    "selection_reason",
    "generated_utc",
    "baseline_script_bytes_unchanged",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"critical path input is not an object: {path}")
    return value


def _trace_ready(root: Path, target_sha256: str) -> tuple[bool, str | None]:
    safe_path = root / REGISTER_TRACE_PATH
    local_path = root / REGISTER_TRACE_LOCAL_PATH
    if not safe_path.is_file() or not local_path.is_file():
        return False, None
    try:
        safe = _load_object(safe_path)
        local = _load_object(local_path)
        validate_active_ram_register_trace(safe)
    except (OSError, ValueError, json.JSONDecodeError):
        return False, None
    selected = local.get("analysis", {}).get("selected")
    if not isinstance(selected, dict):
        return False, None
    reads = selected.get("read_addresses")
    ready = (
        safe.get("target_sha256") == target_sha256
        and safe.get("writer_instance_confirmed") is True
        and safe.get("register_definition_confirmed") is True
        and safe.get("definition_source_class") == "rom-window"
        and isinstance(reads, list)
        and len(reads) == 1
    )
    return ready, sha256_file(safe_path) if ready else None


def _rom_source_current(
    root: Path,
    *,
    target_sha256: str,
    trace_sha256: str,
) -> bool:
    path = root / ROM_SOURCE_PATH
    if not path.is_file():
        return False
    try:
        value = _load_object(path)
        validate_active_register_rom_source(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        value.get("target_sha256") == target_sha256
        and value.get("source_register_trace_sha256") == trace_sha256
        and value.get("rom_source_confirmed") is True
    )


def _source_role_current(
    root: Path,
    *,
    target_sha256: str,
    source_sha256: str,
) -> bool:
    path = root / ROM_SOURCE_ROLE_PATH
    if not path.is_file():
        return False
    try:
        value = _load_object(path)
        validate_active_rom_source_role(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        value.get("target_sha256") == target_sha256
        and value.get("source_active_register_rom_source_sha256") == source_sha256
    )


def _build_selection(
    *,
    target_sha256: str,
    trace_sha256: str,
    stage: str,
) -> dict[str, object]:
    policy = STAGE_POLICIES[stage]
    generated_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": "one-unresolved-boundary-selected",
        "target_sha256": target_sha256,
        "source_register_trace_sha256": trace_sha256,
        "selected_stage": stage,
        "confirmed_boundary": policy["confirmed_boundary"],
        "blocked_boundary": policy["blocked_boundary"],
        "selection_reason": policy["selection_reason"],
        "generated_utc": generated_utc,
        "baseline_script_bytes_unchanged": True,
        "translation_build_eligible": False,
        "next_checkpoint": policy["next_checkpoint"],
    }
    validate_critical_path(value)
    return value


def select_critical_path(root: Path, rom_path: Path) -> dict[str, object] | None:
    """Return a focused stage only when all of its prerequisites are current."""

    if not rom_path.is_file():
        return None
    target_sha256 = sha256_file(rom_path)
    trace_ready, trace_sha256 = _trace_ready(root, target_sha256)
    if not trace_ready or trace_sha256 is None:
        return None
    source_current = _rom_source_current(
        root,
        target_sha256=target_sha256,
        trace_sha256=trace_sha256,
    )
    if not source_current:
        return _build_selection(
            target_sha256=target_sha256,
            trace_sha256=trace_sha256,
            stage=FOCUSED_STAGE,
        )
    source_sha256 = sha256_file(root / ROM_SOURCE_PATH)
    if not _source_role_current(
        root,
        target_sha256=target_sha256,
        source_sha256=source_sha256,
    ):
        return _build_selection(
            target_sha256=target_sha256,
            trace_sha256=trace_sha256,
            stage=SOURCE_ROLE_STAGE,
        )
    return None


def validate_critical_path(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("critical path fields do not match")
    stage = value.get("selected_stage")
    policy = STAGE_POLICIES.get(str(stage))
    if (
        value.get("artifact_kind") != ARTIFACT_KIND
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("status") != "one-unresolved-boundary-selected"
        or not _is_sha256(value.get("target_sha256"))
        or not _is_sha256(value.get("source_register_trace_sha256"))
        or policy is None
        or value.get("confirmed_boundary") != policy["confirmed_boundary"]
        or value.get("blocked_boundary") != policy["blocked_boundary"]
        or value.get("selection_reason") != policy["selection_reason"]
        or value.get("baseline_script_bytes_unchanged") is not True
        or value.get("translation_build_eligible") is not False
        or value.get("next_checkpoint") != policy["next_checkpoint"]
    ):
        raise ValueError("critical path policy is invalid")
    try:
        generated = datetime.fromisoformat(str(value["generated_utc"]).replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("critical path timestamp is invalid") from error
    if generated.tzinfo is None:
        raise ValueError("critical path timestamp lacks timezone")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--print-next-stage", action="store_true")
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    selected = select_critical_path(root, rom_path)
    stage = FALLBACK_STAGE
    if selected is not None:
        output = root / PUBLISH_RELATIVE_PATH
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(selected, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        stage = str(selected["selected_stage"])
    elif not args.if_ready and not rom_path.is_file():
        raise SystemExit("critical path target ROM is missing")
    if args.print_next_stage:
        print(stage)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
