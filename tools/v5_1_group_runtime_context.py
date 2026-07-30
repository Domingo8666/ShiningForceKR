#!/usr/bin/env python3
"""Bind confirmed group records to the runtime-observed initial context.

The context value and decoded symbols remain in an ignored phone-local report.
The safe artifact publishes only provenance, aggregate coverage, and evidence
booleans.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_confirmed_group_extract import (
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        validate_confirmed_group_extract,
    )
    from .v5_1_engine import KO_TREE_BANK, KO_VECTOR_OFFSET
    from .v5_1_group_context_resolution import (
        LOCAL_REPORT_PATH as LOCAL_CONTEXT_PATH,
        PUBLISH_RELATIVE_PATH as CONTEXT_RESOLUTION_PATH,
        validate_group_context_resolution,
    )
    from .v5_1_renderer_observation import validate_renderer_observation
    from .v5_1_renderer_output_trace import _load_json_object
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from v5_1_confirmed_group_extract import (
        PUBLISH_RELATIVE_PATH as GROUP_EXTRACT_PATH,
        validate_confirmed_group_extract,
    )
    from v5_1_engine import KO_TREE_BANK, KO_VECTOR_OFFSET
    from v5_1_group_context_resolution import (
        LOCAL_REPORT_PATH as LOCAL_CONTEXT_PATH,
        PUBLISH_RELATIVE_PATH as CONTEXT_RESOLUTION_PATH,
        validate_group_context_resolution,
    )
    from v5_1_renderer_observation import validate_renderer_observation
    from v5_1_renderer_output_trace import _load_json_object


ARTIFACT_KIND = "sanitized-v5-1-group-runtime-context"
SCHEMA_VERSION = 1
RENDERER_OBSERVATION_PATH = Path(
    "analysis/device/v5_1_latest_renderer_observation.json"
)
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_group_runtime_context.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_group_runtime_context.json")
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_group_extract_sha256",
    "source_context_resolution_sha256",
    "source_renderer_observation_sha256",
    "captured_utc",
    "group",
    "runtime_evidence",
    "coverage",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
GROUP_KEYS = {
    "selector",
    "declared_record_count",
    "selected_entry_ordinal",
}
RUNTIME_EVIDENCE_KEYS = {
    "first_vector_access_resolved",
    "runtime_context_is_available_tree",
    "runtime_context_matches_unique_best",
    "selected_record_compatible",
}
COVERAGE_KEYS = {
    "runtime_context_exact_entry_count",
    "runtime_context_unresolved_entry_count",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _bounded_int(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def resolve_runtime_context(
    *,
    renderer_observation: dict[str, object],
    context_resolution: dict[str, object],
    local_context: dict[str, object],
    selected_entry_ordinal: int,
) -> tuple[dict[str, object], dict[str, object]]:
    validate_renderer_observation(renderer_observation)
    validate_group_context_resolution(context_resolution)
    reads = renderer_observation["decoder_reads"]
    assert isinstance(reads, list)
    vector_read = next(
        (
            item
            for item in reads
            if isinstance(item, dict)
            and item.get("classification") == "korean-huffman-vector"
        ),
        None,
    )
    if vector_read is None:
        raise ValueError("runtime group context vector access is missing")
    physical = vector_read.get("physical_file_offset")
    mapped_bank = vector_read.get("mapped_bank")
    if (
        not isinstance(physical, int)
        or physical < KO_VECTOR_OFFSET
        or (physical - KO_VECTOR_OFFSET) % 2
        or not 0 <= (physical - KO_VECTOR_OFFSET) // 2 <= 0xFF
        or mapped_bank != KO_TREE_BANK
    ):
        raise ValueError("runtime group context vector access is invalid")
    runtime_context = (physical - KO_VECTOR_OFFSET) // 2
    runtime_hex = f"0x{runtime_context:02X}"

    analysis = local_context.get("analysis")
    if not isinstance(analysis, dict):
        raise ValueError("runtime group local context analysis is missing")
    coverage = analysis.get("coverage_by_context")
    records = analysis.get("records")
    best_contexts = analysis.get("best_contexts_hex")
    candidate_contexts = analysis.get("candidate_contexts_hex")
    if (
        not isinstance(coverage, list)
        or not isinstance(records, list)
        or not isinstance(best_contexts, list)
        or not isinstance(candidate_contexts, list)
    ):
        raise ValueError("runtime group local context fields are missing")
    coverage_entry = next(
        (
            item
            for item in coverage
            if isinstance(item, dict)
            and item.get("initial_context_hex") == runtime_hex
        ),
        None,
    )
    if coverage_entry is None:
        raise ValueError("runtime context is not present in local coverage")

    resolved_records: list[dict[str, object]] = []
    selected_compatible = False
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("runtime context record is invalid")
        matches = record.get("candidate_decodes")
        if not isinstance(matches, list):
            raise ValueError("runtime context candidate list is invalid")
        match = next(
            (
                item
                for item in matches
                if isinstance(item, dict)
                and item.get("initial_context_hex") == runtime_hex
            ),
            None,
        )
        if match is None:
            continue
        resolved = {
            "entry_id": record.get("entry_id"),
            "ordinal": record.get("ordinal"),
            "symbols_hex": match.get("symbols_hex"),
            "encoded_bits": match.get("encoded_bits"),
            "roundtrip_exact": True,
            "terminator_exact": True,
            "classification": "runtime-context-roundtrip",
        }
        resolved_records.append(resolved)
        if record.get("ordinal") == selected_entry_ordinal:
            selected_compatible = True

    declared_count = int(
        context_resolution["group"]["record_count"]
    )
    exact_count = int(coverage_entry.get("exact_entry_count", -1))
    if (
        exact_count != len(resolved_records)
        or exact_count > declared_count
    ):
        raise ValueError("runtime context coverage is inconsistent")
    safe_counts = {
        "first_vector_access_resolved": True,
        "runtime_context_is_available_tree": (
            runtime_hex in candidate_contexts
        ),
        "runtime_context_matches_unique_best": (
            len(best_contexts) == 1 and best_contexts[0] == runtime_hex
        ),
        "selected_record_compatible": selected_compatible,
        "runtime_context_exact_entry_count": exact_count,
        "runtime_context_unresolved_entry_count": (
            declared_count - exact_count
        ),
    }
    local = {
        "runtime_initial_context_hex": runtime_hex,
        "first_vector_access": vector_read,
        "resolved_records": resolved_records,
    }
    return safe_counts, local


def build_group_runtime_context(
    *,
    target_sha256: str,
    source_group_extract_sha256: str,
    source_context_resolution_sha256: str,
    source_renderer_observation_sha256: str,
    selector: int,
    declared_record_count: int,
    selected_entry_ordinal: int,
    counts: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    resolved = int(counts["runtime_context_exact_entry_count"])
    unresolved = int(counts["runtime_context_unresolved_entry_count"])
    complete = unresolved == 0
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": (
            "runtime-group-context-full-coverage"
            if complete
            else "runtime-group-context-partial-coverage"
        ),
        "target_sha256": target_sha256,
        "source_group_extract_sha256": source_group_extract_sha256,
        "source_context_resolution_sha256": (
            source_context_resolution_sha256
        ),
        "source_renderer_observation_sha256": (
            source_renderer_observation_sha256
        ),
        "captured_utc": captured_utc,
        "group": {
            "selector": selector,
            "declared_record_count": declared_record_count,
            "selected_entry_ordinal": selected_entry_ordinal,
        },
        "runtime_evidence": {
            key: bool(counts[key])
            for key in RUNTIME_EVIDENCE_KEYS
        },
        "coverage": {
            "runtime_context_exact_entry_count": resolved,
            "runtime_context_unresolved_entry_count": unresolved,
        },
        "local_payload_policy": (
            "context-vector-access-symbols-and-text-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": (
            "map-runtime-context-records-to-unicode"
            if resolved > 0
            else "trace-group-context-again"
        ),
    }
    validate_group_runtime_context(safe)
    return safe


def validate_group_runtime_context(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("group runtime context fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "runtime-group-context-full-coverage",
            "runtime-group-context-partial-coverage",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "source_group_extract_sha256",
                "source_context_resolution_sha256",
                "source_renderer_observation_sha256",
            )
        )
    ):
        raise ValueError("group runtime context policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("group runtime context timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("group runtime context timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("group runtime context timestamp must include UTC")

    group = value["group"]
    if not isinstance(group, dict) or set(group) != GROUP_KEYS:
        raise ValueError("group runtime context group fields do not match")
    if (
        not _bounded_int(group["selector"], 0, 0xFFFF)
        or not _bounded_int(group["declared_record_count"], 1, 0xFF)
        or not _bounded_int(
            group["selected_entry_ordinal"],
            0,
            group["declared_record_count"] - 1,
        )
    ):
        raise ValueError("group runtime context group is invalid")
    evidence = value["runtime_evidence"]
    if (
        not isinstance(evidence, dict)
        or set(evidence) != RUNTIME_EVIDENCE_KEYS
        or any(not isinstance(evidence[key], bool) for key in evidence)
        or evidence["first_vector_access_resolved"] is not True
        or evidence["runtime_context_is_available_tree"] is not True
        or evidence["selected_record_compatible"] is not True
    ):
        raise ValueError("group runtime context evidence is incomplete")
    coverage = value["coverage"]
    if not isinstance(coverage, dict) or set(coverage) != COVERAGE_KEYS:
        raise ValueError("group runtime context coverage fields do not match")
    declared = int(group["declared_record_count"])
    resolved = coverage["runtime_context_exact_entry_count"]
    unresolved = coverage["runtime_context_unresolved_entry_count"]
    if (
        not _bounded_int(resolved, 1, declared)
        or not _bounded_int(unresolved, 0, declared)
        or resolved + unresolved != declared
    ):
        raise ValueError("group runtime context coverage is inconsistent")
    expected_status = (
        "runtime-group-context-full-coverage"
        if unresolved == 0
        else "runtime-group-context-partial-coverage"
    )
    if (
        value["status"] != expected_status
        or value["next_checkpoint"]
        != "map-runtime-context-records-to-unicode"
        or value["local_payload_policy"]
        != "context-vector-access-symbols-and-text-local-only"
        or value["translation_build_eligible"] is not False
    ):
        raise ValueError("group runtime context result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    group_path = root / GROUP_EXTRACT_PATH
    context_path = root / CONTEXT_RESOLUTION_PATH
    local_context_path = root / LOCAL_CONTEXT_PATH
    renderer_path = root / RENDERER_OBSERVATION_PATH
    prerequisites = (
        group_path,
        context_path,
        local_context_path,
        renderer_path,
    )
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Group runtime context is not ready")
            return 0
        raise SystemExit("group runtime context input is missing")

    group = _load_json_object(group_path)
    context = _load_json_object(context_path)
    local_context = _load_json_object(local_context_path)
    renderer = _load_json_object(renderer_path)
    validate_confirmed_group_extract(group)
    validate_group_context_resolution(context)
    validate_renderer_observation(renderer)
    if (
        group["target_sha256"] != context["target_sha256"]
        or group["target_sha256"] != renderer["target_sha256"]
        or context["source_group_extract_sha256"]
        != sha256_file(group_path)
        or local_context.get("target_sha256")
        != group["target_sha256"]
        or local_context.get("source_group_extract_sha256")
        != sha256_file(group_path)
    ):
        raise ValueError("group runtime context identities disagree")
    group_info = group["group"]
    assert isinstance(group_info, dict)
    counts, local_analysis = resolve_runtime_context(
        renderer_observation=renderer,
        context_resolution=context,
        local_context=local_context,
        selected_entry_ordinal=int(group_info["selected_entry_ordinal"]),
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_group_runtime_context(
        target_sha256=str(group["target_sha256"]),
        source_group_extract_sha256=sha256_file(group_path),
        source_context_resolution_sha256=sha256_file(context_path),
        source_renderer_observation_sha256=sha256_file(renderer_path),
        selector=int(group_info["selector"]),
        declared_record_count=int(group_info["declared_entry_count"]),
        selected_entry_ordinal=int(group_info["selected_entry_ordinal"]),
        counts=counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-group-runtime-context",
        "schema_version": 1,
        "target_sha256": group["target_sha256"],
        "captured_utc": captured_utc,
        "source_group_extract_sha256": sha256_file(group_path),
        "source_context_resolution_sha256": sha256_file(context_path),
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-context-vector-access-symbols-or-text"
        ),
    }
    safe_path = root / PUBLISH_RELATIVE_PATH
    local_path = root / LOCAL_REPORT_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR group runtime context: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
