#!/usr/bin/env python3
"""Validate and atomically publish all sanitized S25U runtime artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from .v5_1_runtime_diagnostic import validate_runtime_diagnostic
    from .v5_1_runtime_hit_resolver import validate_consumer_resolution
    from .v5_1_runtime_observation import validate_runtime_observation
    from .v5_1_safe_observation import _git, _normalized_remote
except ImportError:  # direct script execution
    from v5_1_runtime_diagnostic import validate_runtime_diagnostic
    from v5_1_runtime_hit_resolver import validate_consumer_resolution
    from v5_1_runtime_observation import validate_runtime_observation
    from v5_1_safe_observation import _git, _normalized_remote

EXPECTED_REMOTE = "github.com/Domingo8666/ShiningForceKR"
DEFAULT_GIT_NAME = "Domingo8666"
DEFAULT_GIT_EMAIL = "145947995+Domingo8666@users.noreply.github.com"

SAFE_ARTIFACTS = {
    Path("analysis/device/v5_1_latest_runtime_observation.json"):
        validate_runtime_observation,
    Path("analysis/device/v5_1_latest_runtime_diagnostic.json"):
        validate_runtime_diagnostic,
    Path("analysis/device/v5_1_latest_consumer_resolution.json"):
        validate_consumer_resolution,
}


def _load_validated_artifacts(root: Path) -> dict[Path, dict[str, object]]:
    artifacts: dict[Path, dict[str, object]] = {}
    for relative, validator in SAFE_ARTIFACTS.items():
        path = root / relative
        if not path.is_file():
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError(f"{relative} must contain a JSON object")
            validator(value)
        except (OSError, ValueError, json.JSONDecodeError):
            # A stale or malformed local artifact must never block publication
            # of newly validated safe artifacts, and is never staged itself.
            continue
        artifacts[relative] = value
    if not artifacts:
        raise ValueError("no sanitized runtime artifacts are available")

    observation = artifacts.get(
        Path("analysis/device/v5_1_latest_runtime_observation.json")
    )
    resolution = artifacts.get(
        Path("analysis/device/v5_1_latest_consumer_resolution.json")
    )
    if (
        observation is not None
        and resolution is not None
        and observation["target_sha256"] != resolution["target_sha256"]
    ):
        raise ValueError("runtime observation and resolution identities disagree")
    return artifacts


def _porcelain_path(line: str) -> str:
    if len(line) < 4:
        raise ValueError("unexpected git status entry")
    path = line[3:]
    if " -> " in path:
        path = path.split(" -> ", 1)[1]
    return path.replace("\\", "/")


def publish_runtime_bundle(root: Path) -> dict[str, object]:
    root = root.resolve()
    artifacts = _load_validated_artifacts(root)
    top = Path(
        _git(root, "rev-parse", "--show-toplevel").stdout.strip()
    ).resolve()
    if top != root:
        raise ValueError("repository root mismatch")
    if _git(root, "branch", "--show-current").stdout.strip() != "main":
        raise ValueError("runtime artifacts may only be published from main")
    remote = _normalized_remote(
        _git(root, "remote", "get-url", "origin").stdout
    )
    if EXPECTED_REMOTE not in remote:
        raise ValueError("origin is not the canonical repository")

    allowed = {
        str(relative).replace("\\", "/") for relative in SAFE_ARTIFACTS
    }
    porcelain = _git(root, "status", "--porcelain").stdout.splitlines()
    changed_paths = {_porcelain_path(line) for line in porcelain}

    selected = sorted(
        str(relative).replace("\\", "/")
        for relative in artifacts
        if str(relative).replace("\\", "/") in changed_paths
    )
    if selected:
        if not _git(root, "config", "user.name").stdout.strip():
            _git(root, "config", "user.name", DEFAULT_GIT_NAME)
        if not _git(root, "config", "user.email").stdout.strip():
            _git(root, "config", "user.email", DEFAULT_GIT_EMAIL)
        _git(root, "add", "--", *selected)
        _git(
            root,
            "commit",
            "-m",
            "Record sanitized S25U runtime bundle",
            "--",
            *selected,
        )
    _git(root, "push", "origin", "HEAD:main")
    return {
        "changed": bool(selected),
        "commit": _git(root, "rev-parse", "HEAD").stdout.strip(),
        "ignored_paths": sorted(changed_paths - allowed),
        "paths": sorted(
            str(relative).replace("\\", "/") for relative in artifacts
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    artifacts = _load_validated_artifacts(root)
    print(f"SFKR sanitized runtime bundle: {len(artifacts)} artifact(s)")
    if args.publish:
        result = publish_runtime_bundle(root)
        print(
            "Published sanitized runtime bundle: "
            f"{len(result['paths'])} artifact(s) @ {result['commit']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
