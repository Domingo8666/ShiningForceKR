#!/usr/bin/env python3
"""Classify whether the active ROM read path can explain translated glyphs."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_active_register_rom_source import (
        PUBLISH_RELATIVE_PATH as ROM_SOURCE_PATH,
        validate_active_register_rom_source,
    )
    from .v5_1_active_rom_lookup_index_producer import (
        PUBLISH_RELATIVE_PATH as LOOKUP_PATH,
        validate_active_rom_lookup_index_producer,
    )
    from .v5_1_active_rom_read_block import (
        PUBLISH_RELATIVE_PATH as READ_BLOCK_PATH,
        validate_active_rom_read_block,
    )
    from .v5_1_active_rom_source_role import (
        PUBLISH_RELATIVE_PATH as SOURCE_ROLE_PATH,
        validate_active_rom_source_role,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_active_register_rom_source import (
        PUBLISH_RELATIVE_PATH as ROM_SOURCE_PATH,
        validate_active_register_rom_source,
    )
    from v5_1_active_rom_lookup_index_producer import (
        PUBLISH_RELATIVE_PATH as LOOKUP_PATH,
        validate_active_rom_lookup_index_producer,
    )
    from v5_1_active_rom_read_block import (
        PUBLISH_RELATIVE_PATH as READ_BLOCK_PATH,
        validate_active_rom_read_block,
    )
    from v5_1_active_rom_source_role import (
        PUBLISH_RELATIVE_PATH as SOURCE_ROLE_PATH,
        validate_active_rom_source_role,
    )


ARTIFACT_KIND = "sanitized-s25u-active-rom-path-scope"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_active_rom_path_scope.json"
)
PATH_SCOPES = {
    "repeated-interleaved-renderer-asset-candidate",
    "translation-path-unresolved",
}
COUNT_KEYS = {
    "read_occurrence_count",
    "unique_logical_read_count",
    "physical_projection_byte_span",
    "repeated_read_occurrence_count",
    "target_transfer_byte_count",
    "target_transfer_tile_count",
    "matching_predecessor_count",
    "script_projection_match_count",
    "source_executed_match_count",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_active_register_rom_source_sha256",
    "source_active_rom_source_role_sha256",
    "source_active_rom_read_block_sha256",
    "source_active_rom_lookup_index_producer_sha256",
    "captured_utc",
    "analysis",
    "path_scope",
    "current_path_relevant_to_translation_fix",
    "translated_glyph_path_confirmed",
    "baseline_script_bytes_unchanged",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"active ROM path scope input is not an object: {path}")
    return value


def analyze_active_rom_path_scope(
    *,
    rom_source: dict[str, object],
    source_role: dict[str, object],
    read_block: dict[str, object],
    lookup: dict[str, object],
) -> tuple[dict[str, int], str]:
    role_counts = source_role["analysis"]
    read_counts = read_block["analysis"]
    lookup_counts = lookup["analysis"]
    assert isinstance(role_counts, dict)
    assert isinstance(read_counts, dict)
    assert isinstance(lookup_counts, dict)

    script_matches = sum(
        int(role_counts[key])
        for key in (
            "source_script_payload_match_count",
            "source_script_length_match_count",
        )
    ) + sum(
        int(read_counts[key])
        for key in (
            "script_record_projection_match_count",
            "script_payload_projection_match_count",
            "script_length_projection_match_count",
        )
    )
    counts = {
        "read_occurrence_count": int(read_counts["read_occurrence_count"]),
        "unique_logical_read_count": int(read_counts["unique_logical_read_count"]),
        "physical_projection_byte_span": int(
            read_counts["physical_projection_byte_span"]
        ),
        "repeated_read_occurrence_count": int(
            read_counts["repeated_read_occurrence_count"]
        ),
        "target_transfer_byte_count": int(
            role_counts["target_transfer_byte_count"]
        ),
        "target_transfer_tile_count": int(
            role_counts["target_transfer_tile_count"]
        ),
        "matching_predecessor_count": int(
            lookup_counts["matched_predecessor_definition_count"]
        ),
        "script_projection_match_count": script_matches,
        "source_executed_match_count": int(
            role_counts["source_executed_match_count"]
        ),
    }
    tiles = counts["target_transfer_tile_count"]
    unique_reads = counts["unique_logical_read_count"]
    repeated_asset = (
        rom_source.get("source_region") == "original-rom"
        and source_role.get("source_role") == "unclassified-data"
        and read_block.get("access_pattern") in {
            "fixed-stride-lookup-candidate",
            "scattered-lookup-candidate",
        }
        and lookup.get("producer_class") == "incremental-cursor-candidate"
        and unique_reads == 8
        and 8 <= counts["physical_projection_byte_span"] <= 32
        and tiles >= 2
        and counts["target_transfer_byte_count"] == tiles * 32
        and counts["read_occurrence_count"] >= (tiles - 1) * unique_reads
        and counts["repeated_read_occurrence_count"] > unique_reads
        and counts["matching_predecessor_count"]
        == counts["read_occurrence_count"]
        and counts["script_projection_match_count"] == 0
        and counts["source_executed_match_count"] == 0
    )
    return counts, (
        "repeated-interleaved-renderer-asset-candidate"
        if repeated_asset
        else "translation-path-unresolved"
    )


def build_active_rom_path_scope(
    *,
    target_sha256: str,
    source_active_register_rom_source_sha256: str,
    source_active_rom_source_role_sha256: str,
    source_active_rom_read_block_sha256: str,
    source_active_rom_lookup_index_producer_sha256: str,
    analysis: dict[str, int],
    path_scope: str,
    captured_utc: str,
) -> dict[str, object]:
    relevant = path_scope != "repeated-interleaved-renderer-asset-candidate"
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": "active-rom-path-scope-bounded",
        "target_sha256": target_sha256,
        "source_active_register_rom_source_sha256":
            source_active_register_rom_source_sha256,
        "source_active_rom_source_role_sha256":
            source_active_rom_source_role_sha256,
        "source_active_rom_read_block_sha256":
            source_active_rom_read_block_sha256,
        "source_active_rom_lookup_index_producer_sha256":
            source_active_rom_lookup_index_producer_sha256,
        "captured_utc": captured_utc,
        "analysis": {key: int(analysis[key]) for key in COUNT_KEYS},
        "path_scope": path_scope,
        "current_path_relevant_to_translation_fix": relevant,
        "translated_glyph_path_confirmed": False,
        "baseline_script_bytes_unchanged": True,
        "local_payload_policy": "aggregate-counts-and-classification-only",
        "translation_build_eligible": False,
        "next_checkpoint": (
            "capture-translated-test-rom-vram-difference"
            if not relevant
            else "resolve-active-rom-path-scope"
        ),
    }
    validate_active_rom_path_scope(value)
    return value


def validate_active_rom_path_scope(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("active ROM path scope fields do not match")
    counts = value.get("analysis")
    scope = value.get("path_scope")
    relevant = scope != "repeated-interleaved-renderer-asset-candidate"
    if (
        value.get("artifact_kind") != ARTIFACT_KIND
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("status") != "active-rom-path-scope-bounded"
        or scope not in PATH_SCOPES
        or not isinstance(counts, dict)
        or set(counts) != COUNT_KEYS
        or any(
            not isinstance(counts[key], int)
            or isinstance(counts[key], bool)
            or counts[key] < 0
            for key in COUNT_KEYS
        )
        or not all(
            _is_sha256(value.get(key))
            for key in (
                "target_sha256",
                "source_active_register_rom_source_sha256",
                "source_active_rom_source_role_sha256",
                "source_active_rom_read_block_sha256",
                "source_active_rom_lookup_index_producer_sha256",
            )
        )
        or value.get("current_path_relevant_to_translation_fix") is not relevant
        or value.get("translated_glyph_path_confirmed") is not False
        or value.get("baseline_script_bytes_unchanged") is not True
        or value.get("local_payload_policy")
        != "aggregate-counts-and-classification-only"
        or value.get("translation_build_eligible") is not False
        or value.get("next_checkpoint")
        != (
            "capture-translated-test-rom-vram-difference"
            if not relevant
            else "resolve-active-rom-path-scope"
        )
    ):
        raise ValueError("active ROM path scope policy is invalid")
    try:
        captured = datetime.fromisoformat(
            str(value["captured_utc"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError("active ROM path scope timestamp is invalid") from error
    if captured.tzinfo is None:
        raise ValueError("active ROM path scope timestamp lacks timezone")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = {
        "rom_source": root / ROM_SOURCE_PATH,
        "source_role": root / SOURCE_ROLE_PATH,
        "read_block": root / READ_BLOCK_PATH,
        "lookup": root / LOOKUP_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print("Active ROM path scope is not ready")
            return 0
        raise SystemExit("active ROM path scope input is missing")
    rom_source = _load_object(paths["rom_source"])
    source_role = _load_object(paths["source_role"])
    read_block = _load_object(paths["read_block"])
    lookup = _load_object(paths["lookup"])
    validate_active_register_rom_source(rom_source)
    validate_active_rom_source_role(source_role)
    validate_active_rom_read_block(read_block)
    validate_active_rom_lookup_index_producer(lookup)
    target_sha256 = str(rom_source["target_sha256"])
    if any(value.get("target_sha256") != target_sha256 for value in (
        source_role, read_block, lookup
    )):
        raise ValueError("active ROM path scope identities disagree")
    counts, scope = analyze_active_rom_path_scope(
        rom_source=rom_source,
        source_role=source_role,
        read_block=read_block,
        lookup=lookup,
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    safe = build_active_rom_path_scope(
        target_sha256=target_sha256,
        source_active_register_rom_source_sha256=sha256_file(paths["rom_source"]),
        source_active_rom_source_role_sha256=sha256_file(paths["source_role"]),
        source_active_rom_read_block_sha256=sha256_file(paths["read_block"]),
        source_active_rom_lookup_index_producer_sha256=sha256_file(paths["lookup"]),
        analysis=counts,
        path_scope=scope,
        captured_utc=captured_utc,
    )
    output = root / PUBLISH_RELATIVE_PATH
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR active ROM path scope: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
