#!/usr/bin/env python3
"""Validate and atomically publish all sanitized S25U runtime artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from .v5_1_decoder_register_trace import (
        validate_decoder_register_trace,
    )
    from .v5_1_decoder_stream_resolution import (
        validate_decoder_stream_resolution,
    )
    from .v5_1_test_display_capture import validate_display_capture
    from .v5_1_test_display_comparison import validate_display_comparison
    from .v5_1_test_display_review import validate_display_review
    from .v5_1_visible_entry_proof import (
        PUBLISH_RELATIVE_PATH as VISIBLE_ENTRY_PROOF_RELATIVE_PATH,
        validate_visible_entry_proof,
    )
    from .v5_1_poc_expansion_proof import (
        PUBLISH_RELATIVE_PATH as POC_EXPANSION_PROOF_RELATIVE_PATH,
        validate_poc_expansion_proof,
    )
    from .v5_1_visible_script_record import (
        PUBLISH_RELATIVE_PATH as VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH,
        validate_visible_script_roundtrip,
    )
    from .v5_1_progress_preview import (
        PUBLISH_IMAGE_RELATIVE_PATH,
        PUBLISH_RECEIPT_RELATIVE_PATH,
        load_validated_progress_image,
        validate_progress_preview,
    )
    from .v5_1_runtime_diagnostic import validate_runtime_diagnostic
    from .v5_1_runtime_hit_resolver import validate_consumer_resolution
    from .v5_1_runtime_observation import validate_runtime_observation
    from .v5_1_renderer_observation import validate_renderer_observation
    from .v5_1_renderer_output_trace import (
        PUBLISH_RELATIVE_PATH as RENDERER_OUTPUT_TRACE_RELATIVE_PATH,
        validate_renderer_output_trace,
    )
    from .v5_1_route_capture import validate_route_capture
    from .v5_1_safe_observation import _git, _normalized_remote
except ImportError:  # direct script execution
    from v5_1_decoder_register_trace import validate_decoder_register_trace
    from v5_1_decoder_stream_resolution import (
        validate_decoder_stream_resolution,
    )
    from v5_1_test_display_capture import validate_display_capture
    from v5_1_test_display_comparison import validate_display_comparison
    from v5_1_test_display_review import validate_display_review
    from v5_1_visible_entry_proof import (
        PUBLISH_RELATIVE_PATH as VISIBLE_ENTRY_PROOF_RELATIVE_PATH,
        validate_visible_entry_proof,
    )
    from v5_1_poc_expansion_proof import (
        PUBLISH_RELATIVE_PATH as POC_EXPANSION_PROOF_RELATIVE_PATH,
        validate_poc_expansion_proof,
    )
    from v5_1_visible_script_record import (
        PUBLISH_RELATIVE_PATH as VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH,
        validate_visible_script_roundtrip,
    )
    from v5_1_progress_preview import (
        PUBLISH_IMAGE_RELATIVE_PATH,
        PUBLISH_RECEIPT_RELATIVE_PATH,
        load_validated_progress_image,
        validate_progress_preview,
    )
    from v5_1_runtime_diagnostic import validate_runtime_diagnostic
    from v5_1_runtime_hit_resolver import validate_consumer_resolution
    from v5_1_runtime_observation import validate_runtime_observation
    from v5_1_renderer_observation import validate_renderer_observation
    from v5_1_renderer_output_trace import (
        PUBLISH_RELATIVE_PATH as RENDERER_OUTPUT_TRACE_RELATIVE_PATH,
        validate_renderer_output_trace,
    )
    from v5_1_route_capture import validate_route_capture
    from v5_1_safe_observation import _git, _normalized_remote

EXPECTED_REMOTE = "github.com/Domingo8666/ShiningForceKR"
DEFAULT_GIT_NAME = "Domingo8666"
DEFAULT_GIT_EMAIL = "145947995+Domingo8666@users.noreply.github.com"

SAFE_ARTIFACTS = {
    Path("analysis/device/v5_1_latest_decoder_register_trace.json"):
        validate_decoder_register_trace,
    Path("analysis/device/v5_1_latest_decoder_stream_resolution.json"):
        validate_decoder_stream_resolution,
    Path("analysis/device/v5_1_latest_runtime_observation.json"):
        validate_runtime_observation,
    Path("analysis/device/v5_1_latest_renderer_observation.json"):
        validate_renderer_observation,
    Path("analysis/device/v5_1_latest_route_capture.json"):
        validate_route_capture,
    Path("analysis/device/v5_1_latest_runtime_diagnostic.json"):
        validate_runtime_diagnostic,
    Path("analysis/device/v5_1_latest_consumer_resolution.json"):
        validate_consumer_resolution,
    Path("analysis/device/v5_1_latest_display_capture.json"):
        validate_display_capture,
    Path("analysis/device/v5_1_latest_display_comparison.json"):
        validate_display_comparison,
    Path("analysis/device/v5_1_latest_display_review.json"):
        validate_display_review,
    VISIBLE_ENTRY_PROOF_RELATIVE_PATH: validate_visible_entry_proof,
    POC_EXPANSION_PROOF_RELATIVE_PATH: validate_poc_expansion_proof,
    VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH:
        validate_visible_script_roundtrip,
    RENDERER_OUTPUT_TRACE_RELATIVE_PATH:
        validate_renderer_output_trace,
    PUBLISH_RECEIPT_RELATIVE_PATH: validate_progress_preview,
}
SAFE_BINARY_ARTIFACTS = {
    PUBLISH_IMAGE_RELATIVE_PATH: PUBLISH_RECEIPT_RELATIVE_PATH,
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
    renderer = artifacts.get(
        Path("analysis/device/v5_1_latest_renderer_observation.json")
    )
    if (
        renderer is not None
        and observation is not None
        and renderer["target_sha256"] != observation["target_sha256"]
    ):
        raise ValueError("runtime and renderer observation identities disagree")
    route_capture = artifacts.get(
        Path("analysis/device/v5_1_latest_route_capture.json")
    )
    if (
        route_capture is not None
        and renderer is not None
        and route_capture["target_sha256"] != renderer["target_sha256"]
    ):
        raise ValueError("route and renderer observation identities disagree")
    display_capture = artifacts.get(
        Path("analysis/device/v5_1_latest_display_capture.json")
    )
    if (
        display_capture is not None
        and resolution is not None
        and display_capture["baseline_target_sha256"]
        != resolution["target_sha256"]
    ):
        raise ValueError("display capture and resolution identities disagree")
    display_review = artifacts.get(
        Path("analysis/device/v5_1_latest_display_review.json")
    )
    display_comparison = artifacts.get(
        Path("analysis/device/v5_1_latest_display_comparison.json")
    )
    if (
        display_comparison is not None
        and resolution is not None
        and display_comparison["baseline_target_sha256"]
        != resolution["target_sha256"]
    ):
        raise ValueError("display comparison and resolution identities disagree")
    if (
        display_comparison is not None
        and display_capture is not None
        and display_comparison["test_target_sha256"]
        == display_capture["test_target_sha256"]
        and display_comparison["baseline_target_sha256"]
        != display_capture["baseline_target_sha256"]
    ):
        raise ValueError("display capture and comparison identities disagree")
    if (
        display_review is not None
        and display_capture is not None
        and display_review["test_target_sha256"]
        == display_capture["test_target_sha256"]
    ):
        if (
            display_review["baseline_target_sha256"]
            != display_capture["baseline_target_sha256"]
        ):
            raise ValueError("display capture and review identities disagree")
        expected_hashes: list[str] = []
        for item in display_capture["captures"]:
            digest = str(item["png_sha256"])
            if digest not in expected_hashes:
                expected_hashes.append(digest)
        post_advance = display_capture["post_advance_capture"]
        if (
            post_advance is not None
            and post_advance["png_sha256"] not in expected_hashes
        ):
            expected_hashes.append(post_advance["png_sha256"])
        if display_review["capture_png_sha256s"] != expected_hashes:
            raise ValueError("display capture and review PNG identities disagree")
    progress_preview = artifacts.get(PUBLISH_RECEIPT_RELATIVE_PATH)
    if progress_preview is not None:
        if (
            display_capture is None
            or display_capture["status"]
            != "capture-ready-human-review-required"
            or progress_preview["baseline_target_sha256"]
            != display_capture["baseline_target_sha256"]
            or progress_preview["test_target_sha256"]
            != display_capture["test_target_sha256"]
            or progress_preview["capture_png_sha256"]
            not in {
                item["png_sha256"]
                for item in display_capture["captures"]
            } | (
                {
                    display_capture["post_advance_capture"]["png_sha256"]
                }
                if display_capture["post_advance_capture"] is not None
                else set()
            )
        ):
            artifacts.pop(PUBLISH_RECEIPT_RELATIVE_PATH)
    visible_entry_proof = artifacts.get(VISIBLE_ENTRY_PROOF_RELATIVE_PATH)
    if visible_entry_proof is not None:
        if (
            display_capture is None
            or display_comparison is None
            or display_review is None
            or visible_entry_proof["baseline_target_sha256"]
            != display_capture["baseline_target_sha256"]
            or visible_entry_proof["test_target_sha256"]
            != display_capture["test_target_sha256"]
            or visible_entry_proof["baseline_target_sha256"]
            != display_comparison["baseline_target_sha256"]
            or visible_entry_proof["test_target_sha256"]
            != display_comparison["test_target_sha256"]
            or visible_entry_proof["baseline_target_sha256"]
            != display_review["baseline_target_sha256"]
            or visible_entry_proof["test_target_sha256"]
            != display_review["test_target_sha256"]
            or visible_entry_proof["runtime_entry"]["physical_start"]
            != display_review["reviewed_stream"]["physical_start"]
            or visible_entry_proof["runtime_entry"]["logical_start"]
            != display_review["reviewed_stream"]["logical_start"]
            or visible_entry_proof["runtime_entry"]["mapped_bank"]
            != display_review["reviewed_stream"]["mapped_bank"]
        ):
            artifacts.pop(VISIBLE_ENTRY_PROOF_RELATIVE_PATH)
    poc_expansion_proof = artifacts.get(POC_EXPANSION_PROOF_RELATIVE_PATH)
    if poc_expansion_proof is not None:
        if (
            display_capture is None
            or display_comparison is None
            or display_review is None
            or progress_preview is None
            or poc_expansion_proof["baseline_target_sha256"]
            != display_capture["baseline_target_sha256"]
            or poc_expansion_proof["test_target_sha256"]
            != display_capture["test_target_sha256"]
            or poc_expansion_proof["test_target_sha256"]
            != display_comparison["test_target_sha256"]
            or poc_expansion_proof["test_target_sha256"]
            != display_review["test_target_sha256"]
            or poc_expansion_proof["display_proof"]["capture_png_sha256"]
            != progress_preview["capture_png_sha256"]
        ):
            artifacts.pop(POC_EXPANSION_PROOF_RELATIVE_PATH)
    visible_script_roundtrip = artifacts.get(
        VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH
    )
    if visible_script_roundtrip is not None:
        if (
            poc_expansion_proof is None
            or visible_script_roundtrip["baseline_target_sha256"]
            != poc_expansion_proof["baseline_target_sha256"]
            or visible_script_roundtrip["source_expansion_test_sha256"]
            != poc_expansion_proof["test_target_sha256"]
            or visible_script_roundtrip["runtime_entry"]["physical_start"]
            != poc_expansion_proof["runtime_entry"]["physical_start"]
            or visible_script_roundtrip["runtime_entry"]["logical_start"]
            != poc_expansion_proof["runtime_entry"]["logical_start"]
        ):
            artifacts.pop(VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH)
    visible_script_roundtrip = artifacts.get(
        VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH
    )
    renderer_output_trace = artifacts.get(
        RENDERER_OUTPUT_TRACE_RELATIVE_PATH
    )
    if renderer_output_trace is not None:
        if (
            visible_script_roundtrip is None
            or renderer_output_trace["target_sha256"]
            != visible_script_roundtrip["baseline_target_sha256"]
            or renderer_output_trace["runtime_entry"]["physical_start"]
            != visible_script_roundtrip["runtime_entry"]["physical_start"]
            or renderer_output_trace["runtime_entry"]["logical_start"]
            != visible_script_roundtrip["runtime_entry"]["logical_start"]
            or renderer_output_trace["runtime_entry"]["mapped_bank"]
            != visible_script_roundtrip["runtime_entry"]["mapped_bank"]
        ):
            artifacts.pop(RENDERER_OUTPUT_TRACE_RELATIVE_PATH)
    return artifacts


def _load_validated_binary_artifacts(
    root: Path,
    artifacts: dict[Path, dict[str, object]],
) -> set[Path]:
    binaries: set[Path] = set()
    for relative, receipt_relative in SAFE_BINARY_ARTIFACTS.items():
        receipt = artifacts.get(receipt_relative)
        if receipt is None:
            continue
        try:
            load_validated_progress_image(root, receipt)
        except (OSError, ValueError):
            continue
        binaries.add(relative)
    return binaries


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
    binaries = _load_validated_binary_artifacts(root, artifacts)
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
    } | {
        str(relative).replace("\\", "/") for relative in SAFE_BINARY_ARTIFACTS
    }
    porcelain = _git(root, "status", "--porcelain").stdout.splitlines()
    changed_paths = {_porcelain_path(line) for line in porcelain}

    selected = sorted(
        str(relative).replace("\\", "/")
        for relative in set(artifacts) | binaries
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
            str(relative).replace("\\", "/")
            for relative in set(artifacts) | binaries
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    artifacts = _load_validated_artifacts(root)
    binaries = _load_validated_binary_artifacts(root, artifacts)
    print(
        "SFKR sanitized runtime bundle: "
        f"{len(artifacts) + len(binaries)} artifact(s)"
    )
    if args.publish:
        result = publish_runtime_bundle(root)
        print(
            "Published sanitized runtime bundle: "
            f"{len(result['paths'])} artifact(s) @ {result['commit']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
