#!/usr/bin/env python3
"""Publish a path-free diagnosis when the S25U runtime stage exits early."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess

try:
    from .patch_io import sha256_file
    from .run_s25u_runtime_probe import (
        McpStdioClient,
        REQUIRED_TOOLS,
        _default_command,
    )
    from .v5_1_consumer import verify_target_identity
    from .v5_1_safe_observation import _git, _normalized_remote
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from run_s25u_runtime_probe import (
        McpStdioClient,
        REQUIRED_TOOLS,
        _default_command,
    )
    from v5_1_consumer import verify_target_identity
    from v5_1_safe_observation import _git, _normalized_remote

ARTIFACT_KIND = "sanitized-runtime-stage-diagnostic"
SCHEMA_VERSION = 2
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_runtime_diagnostic.json"
)
EXPECTED_REMOTE = "github.com/Domingo8666/ShiningForceKR"
DEFAULT_GIT_NAME = "Domingo8666"
DEFAULT_GIT_EMAIL = "145947995+Domingo8666@users.noreply.github.com"
ALLOWED_TRIGGERS = {"setup", "probe", "manual"}
CHECK_KEYS = {
    "proot_available",
    "ubuntu_available",
    "gearsystem_binary_available",
    "dynamic_dependencies_ready",
    "mcp_initialize_ready",
    "required_tools_ready",
    "local_target_present",
    "trace_plan_present",
    "target_identity_ready",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "trigger",
    "exit_code",
    "attempt_utc",
    "checks",
    "failed_stage",
    "runtime_observation_present",
    "next_checkpoint",
}


def validate_runtime_diagnostic(diagnostic: dict[str, object]) -> None:
    if set(diagnostic) != TOP_LEVEL_KEYS:
        raise ValueError("runtime diagnostic top-level fields do not match")
    if diagnostic["artifact_kind"] != ARTIFACT_KIND:
        raise ValueError("unexpected diagnostic artifact kind")
    if diagnostic["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unexpected diagnostic schema version")
    if diagnostic["status"] not in {
        "runtime-stage-ready",
        "runtime-stage-not-ready",
    }:
        raise ValueError("unexpected runtime diagnostic status")
    if diagnostic["trigger"] not in ALLOWED_TRIGGERS:
        raise ValueError("unexpected runtime diagnostic trigger")
    attempt_utc = diagnostic["attempt_utc"]
    if (
        not isinstance(attempt_utc, str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
            r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            attempt_utc,
        )
        is None
    ):
        raise ValueError("attempt_utc must be a sanitized UTC timestamp")
    exit_code = diagnostic["exit_code"]
    if (
        not isinstance(exit_code, int)
        or isinstance(exit_code, bool)
        or not 0 <= exit_code <= 255
    ):
        raise ValueError("exit_code must be between 0 and 255")
    checks = diagnostic["checks"]
    if not isinstance(checks, dict) or set(checks) != CHECK_KEYS:
        raise ValueError("diagnostic checks do not match the safe schema")
    if any(not isinstance(value, bool) for value in checks.values()):
        raise ValueError("diagnostic check values must be boolean")
    failed_stage = diagnostic["failed_stage"]
    if failed_stage is not None and (
        not isinstance(failed_stage, str)
        or re.fullmatch(r"[a-z0-9-]{1,40}", failed_stage) is None
    ):
        raise ValueError("failed_stage must be a short safe token or null")
    if not isinstance(diagnostic["runtime_observation_present"], bool):
        raise ValueError("runtime_observation_present must be boolean")
    next_checkpoint = diagnostic["next_checkpoint"]
    if (
        not isinstance(next_checkpoint, str)
        or re.fullmatch(r"[a-z0-9-]{1,80}", next_checkpoint) is None
    ):
        raise ValueError("next_checkpoint must be a short safe token")
    checks_ready = all(checks.values())
    ready = checks_ready and exit_code == 0
    if ready != (diagnostic["status"] == "runtime-stage-ready"):
        raise ValueError("diagnostic status, checks, and exit code disagree")
    expected_failed = None
    if not checks_ready:
        expected_failed = next(key for key, value in checks.items() if not value)
        expected_failed = expected_failed.replace("_", "-")
    elif exit_code != 0:
        expected_failed = "runtime-command"
    if failed_stage != expected_failed:
        raise ValueError("failed_stage does not identify the first failed check")


def _run_check(command: list[str], timeout: int = 30) -> bool:
    try:
        return (
            subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            ).returncode
            == 0
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


def collect_runtime_diagnostic(
    root: Path, trigger: str, exit_code: int
) -> dict[str, object]:
    if trigger not in ALLOWED_TRIGGERS:
        raise ValueError("unsupported diagnostic trigger")
    proot_available = shutil.which("proot-distro") is not None
    ubuntu_available = proot_available and _run_check(
        ["proot-distro", "login", "ubuntu", "--", "true"]
    )
    binary_available = ubuntu_available and _run_check(
        [
            "proot-distro",
            "login",
            "ubuntu",
            "--",
            "test",
            "-x",
            "/opt/sfkr-gearsystem/gearsystem",
        ]
    )
    dependencies_ready = binary_available and _run_check(
        [
            "proot-distro",
            "login",
            "ubuntu",
            "--",
            "bash",
            "-lc",
            (
                "ldd /opt/sfkr-gearsystem/gearsystem "
                ">/tmp/sfkr-gearsystem-ldd.txt && "
                "! grep -q 'not found' /tmp/sfkr-gearsystem-ldd.txt"
            ),
        ]
    )
    mcp_ready = False
    tools_ready = False
    if dependencies_ready:
        client: McpStdioClient | None = None
        try:
            client = McpStdioClient(_default_command())
            tools = client.initialize()
            mcp_ready = True
            tools_ready = REQUIRED_TOOLS <= tools
        except (OSError, RuntimeError, ValueError):
            pass
        finally:
            if client is not None:
                client.close()
    rom_path = root / "build/Final_Conflict_Korean_v5.1.gg"
    plan_path = root / "reports/v5_1_emucap_trace_plan.json"
    local_target_present = rom_path.is_file()
    trace_plan_present = plan_path.is_file()
    target_identity_ready = False
    if local_target_present and trace_plan_present:
        try:
            rom = rom_path.read_bytes()
            verify_target_identity(rom)
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            target_identity_ready = (
                isinstance(plan, dict)
                and plan.get("source_analysis_sha256") == sha256_file(rom_path)
            )
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    checks = {
        "proot_available": proot_available,
        "ubuntu_available": ubuntu_available,
        "gearsystem_binary_available": binary_available,
        "dynamic_dependencies_ready": dependencies_ready,
        "mcp_initialize_ready": mcp_ready,
        "required_tools_ready": tools_ready,
        "local_target_present": local_target_present,
        "trace_plan_present": trace_plan_present,
        "target_identity_ready": target_identity_ready,
    }
    checks_ready = all(checks.values())
    ready = checks_ready and exit_code == 0
    failed_stage = None
    if not checks_ready:
        failed_stage = next(key for key, value in checks.items() if not value)
        failed_stage = failed_stage.replace("_", "-")
    elif exit_code != 0:
        failed_stage = "runtime-command"
    diagnostic: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": "runtime-stage-ready" if ready else "runtime-stage-not-ready",
        "trigger": trigger,
        "exit_code": exit_code,
        "attempt_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checks": checks,
        "failed_stage": failed_stage,
        "runtime_observation_present": (
            root
            / "analysis/device/v5_1_latest_runtime_observation.json"
        ).is_file(),
        "next_checkpoint": (
            "rerun-runtime-probe"
            if ready
            else (
                "repair-runtime-command"
                if checks_ready
                else "repair-first-failed-runtime-stage"
            )
        ),
    }
    validate_runtime_diagnostic(diagnostic)
    return diagnostic


def write_runtime_diagnostic(
    root: Path, diagnostic: dict[str, object]
) -> Path:
    validate_runtime_diagnostic(diagnostic)
    path = root.resolve() / PUBLISH_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(diagnostic, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def publish_runtime_diagnostic(root: Path, path: Path) -> dict[str, object]:
    root = root.resolve()
    expected = root / PUBLISH_RELATIVE_PATH
    if path.resolve() != expected:
        raise ValueError(f"runtime diagnostic path must be {expected}")
    diagnostic = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(diagnostic, dict):
        raise ValueError("runtime diagnostic must be a JSON object")
    validate_runtime_diagnostic(diagnostic)
    top = Path(_git(root, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    if top != root:
        raise ValueError("repository root mismatch")
    if _git(root, "branch", "--show-current").stdout.strip() != "main":
        raise ValueError("runtime diagnostic may only be published from main")
    remote = _normalized_remote(_git(root, "remote", "get-url", "origin").stdout)
    if EXPECTED_REMOTE not in remote:
        raise ValueError("origin is not the canonical repository")

    relative = str(PUBLISH_RELATIVE_PATH).replace("\\", "/")
    porcelain = _git(root, "status", "--porcelain").stdout.splitlines()
    unrelated = [
        line
        for line in porcelain
        if line[3:].replace("\\", "/") != relative
    ]
    if unrelated:
        raise ValueError("refusing to publish with unrelated working tree changes")
    changed = any(
        line[3:].replace("\\", "/") == relative for line in porcelain
    )
    if changed:
        if not _git(root, "config", "user.name").stdout.strip():
            _git(root, "config", "user.name", DEFAULT_GIT_NAME)
        if not _git(root, "config", "user.email").stdout.strip():
            _git(root, "config", "user.email", DEFAULT_GIT_EMAIL)
        _git(root, "add", "--", relative)
        _git(
            root,
            "commit",
            "-m",
            "Record sanitized S25U runtime diagnostic",
            "--",
            relative,
        )
    _git(root, "push", "origin", "HEAD:main")
    return {
        "changed": changed,
        "commit": _git(root, "rev-parse", "HEAD").stdout.strip(),
        "path": relative,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trigger", choices=sorted(ALLOWED_TRIGGERS), required=True)
    parser.add_argument("--exit-code", type=int, default=1)
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    diagnostic = collect_runtime_diagnostic(root, args.trigger, args.exit_code)
    path = write_runtime_diagnostic(root, diagnostic)
    print(
        "SFKR runtime diagnostic: "
        f"{diagnostic['status']} failed={diagnostic['failed_stage']}"
    )
    if args.publish:
        result = publish_runtime_diagnostic(root, path)
        print(f"Published runtime diagnostic: {result['path']} @ {result['commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
