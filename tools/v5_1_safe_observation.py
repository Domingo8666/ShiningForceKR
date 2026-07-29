#!/usr/bin/env python3
"""Create and optionally publish a ROM-free S25U trace observation."""

from __future__ import annotations

import json
import math
from pathlib import Path
import re
import subprocess

ARTIFACT_KIND = "sanitized-runtime-trace-observation"
SCHEMA_VERSION = 2
MAX_SHARED_HYPOTHESES = 5
MAX_ALIGNMENT_ALTERNATIVES = 6
PUBLISH_RELATIVE_PATH = Path("analysis/device/v5_1_latest_observation.json")
EXPECTED_REMOTE = "github.com/Domingo8666/ShiningForceKR"
DEFAULT_GIT_NAME = "Domingo8666"
DEFAULT_GIT_EMAIL = "145947995+Domingo8666@users.noreply.github.com"

TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "trace_plan_schema_version",
    "target_sha256",
    "status",
    "ranked_hypotheses",
    "selected_rank",
    "selected_alignment_cluster",
    "selected_watch",
    "consumer_evidence_confirmed",
    "translation_build_eligible",
    "next_checkpoint",
}
CANDIDATE_KEYS = {
    "rank",
    "file_offset",
    "end_exclusive",
    "family",
    "format",
    "entries",
    "scanner_score",
    "combined_candidate_score",
    "unique_ratio",
    "monotonic_ratio",
    "original_512k_target_ratio",
    "decode_probe",
    "reference_shape_count",
    "pointer_load_shape_count",
    "control_flow_shape_count",
    "absolute_memory_shape_count",
    "bank_coupled_pointer_load_count",
    "mapper_coupled_pointer_load_count",
    "generic_slot_base_discounted",
    "logical_mappings",
}
MAPPING_KEYS = {
    "slot",
    "bank",
    "logical_start",
    "logical_end",
    "mapping_note",
    "extent_truncated_at_bank_end",
}
DECODE_KEYS = {
    "attempted",
    "bounded_terminations",
    "termination_ratio",
    "median_symbols",
}
ALIGNMENT_KEYS = {
    "file_offset",
    "end_exclusive",
    "format",
    "entries",
    "combined_candidate_score",
}
WATCH_KEYS = {
    "file_start",
    "end_exclusive",
    "logical_mappings",
}


def _shared_mapping(mapping: dict[str, object]) -> dict[str, object]:
    return {key: mapping[key] for key in MAPPING_KEYS}


def _shared_candidate(rank: int, item: dict[str, object]) -> dict[str, object]:
    output = {key: item[key] for key in CANDIDATE_KEYS if key != "rank"}
    output["rank"] = rank
    mappings = item["logical_mappings"]
    if not isinstance(mappings, list):
        raise ValueError("logical_mappings must be a list")
    output["logical_mappings"] = [_shared_mapping(mapping) for mapping in mappings]
    decode_probe = item["decode_probe"]
    if decode_probe is not None:
        if not isinstance(decode_probe, dict):
            raise ValueError("decode_probe must be an object or null")
        output["decode_probe"] = {key: decode_probe[key] for key in DECODE_KEYS}
    return output


def _shared_alignment(item: dict[str, object]) -> dict[str, object]:
    return {key: item[key] for key in ALIGNMENT_KEYS}


def _shared_watch(watch: dict[str, object] | None) -> dict[str, object] | None:
    if watch is None:
        return None
    mappings = watch["logical_mappings"]
    if not isinstance(mappings, list):
        raise ValueError("selected watch mappings must be a list")
    return {
        "file_start": watch["file_start"],
        "end_exclusive": watch["end_exclusive"],
        "logical_mappings": [_shared_mapping(mapping) for mapping in mappings],
    }


def build_safe_observation(trace_plan: dict[str, object]) -> dict[str, object]:
    """Whitelist safe coordinates and metrics from a full local trace plan."""

    ranked = trace_plan["ranked_consumer_hypotheses"]
    if not isinstance(ranked, list):
        raise ValueError("ranked_consumer_hypotheses must be a list")
    alignment_cluster = trace_plan["selected_alignment_cluster"]
    if not isinstance(alignment_cluster, list):
        raise ValueError("selected_alignment_cluster must be a list")
    observation = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "trace_plan_schema_version": trace_plan["schema_version"],
        "target_sha256": trace_plan["source_analysis_sha256"],
        "status": trace_plan["status"],
        "ranked_hypotheses": [
            _shared_candidate(rank, item)
            for rank, item in enumerate(ranked[:MAX_SHARED_HYPOTHESES], 1)
        ],
        "selected_rank": 1 if trace_plan["selected_hypothesis"] is not None else None,
        "selected_alignment_cluster": [
            _shared_alignment(item) for item in alignment_cluster
        ],
        "selected_watch": _shared_watch(trace_plan["selected_watch"]),
        "consumer_evidence_confirmed": bool(
            trace_plan["consumer_evidence_confirmed"]
        ),
        "translation_build_eligible": False,
        "next_checkpoint": "runtime-read-hit-with-matching-mapper-state",
    }
    validate_safe_observation(observation)
    return observation


def _require_int(value: object, label: str, minimum: int = 0) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")


def _require_number(value: object, label: str) -> None:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
    ):
        raise ValueError(f"{label} must be a finite number")


def _require_optional_number(value: object, label: str) -> None:
    if value is not None:
        _require_number(value, label)


def _require_short_token(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 80
        or "/" in value
        or "\\" in value
    ):
        raise ValueError(f"{label} must be a short path-free token")


def validate_safe_observation(observation: dict[str, object]) -> None:
    """Reject extra fields so raw bytes, text, and local paths cannot leak."""

    if set(observation) != TOP_LEVEL_KEYS:
        raise ValueError("safe observation top-level fields do not match the schema")
    if observation["artifact_kind"] != ARTIFACT_KIND:
        raise ValueError("unexpected artifact kind")
    if observation["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unexpected safe observation schema version")
    _require_int(observation["trace_plan_schema_version"], "trace plan schema", 1)
    target_sha256 = observation["target_sha256"]
    if not isinstance(target_sha256, str) or re.fullmatch(
        r"[0-9a-f]{64}", target_sha256
    ) is None:
        raise ValueError("target_sha256 must be a lowercase SHA-256")
    _require_short_token(observation["status"], "status")
    _require_short_token(observation["next_checkpoint"], "next_checkpoint")
    for key in ("consumer_evidence_confirmed", "translation_build_eligible"):
        if not isinstance(observation[key], bool):
            raise ValueError(f"{key} must be a boolean")
    if observation["consumer_evidence_confirmed"]:
        raise ValueError("the static observation cannot confirm a runtime consumer")
    if observation["translation_build_eligible"]:
        raise ValueError("the static observation cannot enable translation builds")

    ranked = observation["ranked_hypotheses"]
    if not isinstance(ranked, list) or len(ranked) > MAX_SHARED_HYPOTHESES:
        raise ValueError("ranked_hypotheses exceeds the safe sharing limit")
    for expected_rank, candidate in enumerate(ranked, 1):
        if not isinstance(candidate, dict) or set(candidate) != CANDIDATE_KEYS:
            raise ValueError("candidate fields do not match the safe schema")
        _require_int(candidate["rank"], "candidate rank", 1)
        if candidate["rank"] != expected_rank:
            raise ValueError("candidate ranks must be contiguous")
        for key in (
            "file_offset",
            "end_exclusive",
            "entries",
            "reference_shape_count",
            "pointer_load_shape_count",
            "control_flow_shape_count",
            "absolute_memory_shape_count",
            "bank_coupled_pointer_load_count",
            "mapper_coupled_pointer_load_count",
        ):
            _require_int(candidate[key], key)
        for key in ("scanner_score", "combined_candidate_score"):
            _require_number(candidate[key], key)
        for key in (
            "unique_ratio",
            "monotonic_ratio",
            "original_512k_target_ratio",
        ):
            _require_optional_number(candidate[key], key)
        for key in ("family", "format"):
            _require_short_token(candidate[key], key)
        if not isinstance(candidate["generic_slot_base_discounted"], bool):
            raise ValueError("generic_slot_base_discounted must be a boolean")
        mappings = candidate["logical_mappings"]
        if not isinstance(mappings, list) or len(mappings) > 3:
            raise ValueError("logical_mappings must contain at most three slots")
        for mapping in mappings:
            if not isinstance(mapping, dict) or set(mapping) != MAPPING_KEYS:
                raise ValueError("mapping fields do not match the safe schema")
            for key in ("slot", "bank", "logical_start", "logical_end"):
                _require_int(mapping[key], key)
            _require_short_token(mapping["mapping_note"], "mapping_note")
            if not isinstance(mapping["extent_truncated_at_bank_end"], bool):
                raise ValueError("extent_truncated_at_bank_end must be a boolean")
        decode_probe = candidate["decode_probe"]
        if decode_probe is not None:
            if not isinstance(decode_probe, dict) or set(decode_probe) != DECODE_KEYS:
                raise ValueError("decode_probe fields do not match the safe schema")
            for key in ("attempted", "bounded_terminations"):
                _require_int(decode_probe[key], key)
            _require_number(decode_probe["termination_ratio"], "termination_ratio")
            _require_optional_number(decode_probe["median_symbols"], "median_symbols")

    selected_rank = observation["selected_rank"]
    if selected_rank is not None:
        _require_int(selected_rank, "selected_rank", 1)
        if selected_rank > len(ranked):
            raise ValueError("selected_rank is outside ranked_hypotheses")

    alignment_cluster = observation["selected_alignment_cluster"]
    if (
        not isinstance(alignment_cluster, list)
        or len(alignment_cluster) > MAX_ALIGNMENT_ALTERNATIVES
    ):
        raise ValueError("selected_alignment_cluster exceeds the safe limit")
    for item in alignment_cluster:
        if not isinstance(item, dict) or set(item) != ALIGNMENT_KEYS:
            raise ValueError("alignment fields do not match the safe schema")
        for key in ("file_offset", "end_exclusive", "entries"):
            _require_int(item[key], key)
        _require_short_token(item["format"], "alignment format")
        _require_number(item["combined_candidate_score"], "alignment score")

    selected_watch = observation["selected_watch"]
    if selected_watch is not None:
        if not isinstance(selected_watch, dict) or set(selected_watch) != WATCH_KEYS:
            raise ValueError("selected_watch fields do not match the safe schema")
        _require_int(selected_watch["file_start"], "watch file_start")
        _require_int(selected_watch["end_exclusive"], "watch end_exclusive")
        mappings = selected_watch["logical_mappings"]
        if not isinstance(mappings, list) or len(mappings) > 3:
            raise ValueError("selected watch mappings must contain at most three slots")
        for mapping in mappings:
            if not isinstance(mapping, dict) or set(mapping) != MAPPING_KEYS:
                raise ValueError("selected watch mapping fields do not match the schema")
            for key in ("slot", "bank", "logical_start", "logical_end"):
                _require_int(mapping[key], key)
            _require_short_token(mapping["mapping_note"], "watch mapping_note")
            if not isinstance(mapping["extent_truncated_at_bank_end"], bool):
                raise ValueError("watch extent flag must be a boolean")


def write_safe_observation(
    root: Path, observation: dict[str, object]
) -> Path:
    validate_safe_observation(observation)
    path = root.resolve() / PUBLISH_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(observation, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def compact_summary(observation: dict[str, object]) -> str:
    validate_safe_observation(observation)
    ranked = observation["ranked_hypotheses"]
    assert isinstance(ranked, list)
    if not ranked:
        return (
            f"SFKR safe observation v{observation['schema_version']}: "
            "no ranked hypothesis"
        )
    selected = ranked[0]
    watch = observation["selected_watch"]
    assert isinstance(watch, dict)
    alignments = observation["selected_alignment_cluster"]
    assert isinstance(alignments, list)
    return (
        f"SFKR safe observation v{observation['schema_version']}: "
        f"trace-v{observation['trace_plan_schema_version']} "
        f"selected=0x{selected['file_offset']:06X} "
        f"entries={selected['entries']} "
        f"mapper-links={selected['mapper_coupled_pointer_load_count']} "
        f"score={selected['combined_candidate_score']:.2f} "
        f"alignments={len(alignments)} "
        f"watch=0x{watch['file_start']:06X}..0x{watch['end_exclusive'] - 1:06X}"
    )


def _git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=check,
        capture_output=True,
        text=True,
    )


def _normalized_remote(url: str) -> str:
    value = url.strip().removesuffix(".git").removesuffix("/")
    if value.startswith("https://"):
        return value.removeprefix("https://")
    if value.startswith("git@github.com:"):
        return "github.com/" + value.removeprefix("git@github.com:")
    return value


def publish_safe_observation(root: Path, path: Path) -> dict[str, object]:
    """Commit and push only the fixed, validated safe observation path."""

    root = root.resolve()
    path = path.resolve()
    expected_path = root / PUBLISH_RELATIVE_PATH
    if path != expected_path:
        raise RuntimeError(f"refusing to publish unexpected path: {path}")
    observation = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(observation, dict):
        raise RuntimeError("safe observation root must be an object")
    validate_safe_observation(observation)

    git_root = Path(_git(root, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    if git_root != root:
        raise RuntimeError("pipeline root is not the Git repository root")
    branch = _git(root, "branch", "--show-current").stdout.strip()
    if branch != "main":
        raise RuntimeError("safe observation publishing requires branch main")
    remote = _normalized_remote(_git(root, "remote", "get-url", "origin").stdout)
    if remote != EXPECTED_REMOTE:
        raise RuntimeError(f"refusing to publish to unexpected remote: {remote}")

    _git(root, "fetch", "origin", "main")
    behind = int(_git(root, "rev-list", "--count", "HEAD..origin/main").stdout)
    if behind:
        raise RuntimeError("repository is behind origin/main; pull and rerun the pipeline")
    if _git(root, "diff", "--cached", "--quiet", check=False).returncode != 0:
        raise RuntimeError("refusing to publish while unrelated staged changes exist")

    relative = PUBLISH_RELATIVE_PATH.as_posix()
    changed = bool(
        _git(
            root,
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            relative,
        ).stdout.strip()
    )
    if changed:
        if not _git(root, "config", "user.name", check=False).stdout.strip():
            _git(root, "config", "user.name", DEFAULT_GIT_NAME)
        if not _git(root, "config", "user.email", check=False).stdout.strip():
            _git(root, "config", "user.email", DEFAULT_GIT_EMAIL)
        _git(root, "add", "--", relative)
        _git(
            root,
            "commit",
            "-m",
            "Record sanitized S25U trace observation",
            "--",
            relative,
        )

    _git(root, "push", "origin", "HEAD:main")
    return {
        "changed": changed,
        "commit": _git(root, "rev-parse", "HEAD").stdout.strip(),
        "path": relative,
    }
