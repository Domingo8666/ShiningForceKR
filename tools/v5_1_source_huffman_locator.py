#!/usr/bin/env python3
"""Locate the clean Japanese ROM's Huffman vector structurally.

Candidate offsets, bank bases, pointers, trees, and source bytes stay in an
ignored phone-local report.  The safe receipt exposes only aggregate counts.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .analyze_v5_1 import EXPECTED_SOURCE_SHA256, EXPECTED_SOURCE_SIZE
    from .patch_io import PatchError, sha256_bytes, sha256_file
    from .sfgfc_huffman import VECTOR_ENTRIES, load_trees_at
    from .v5_1_group_source_delta import (
        PUBLISH_RELATIVE_PATH as SOURCE_DELTA_PATH,
        validate_group_source_delta,
    )
    from .v5_1_renderer_output_trace import _load_json_object
except ImportError:  # direct script execution
    from analyze_v5_1 import EXPECTED_SOURCE_SHA256, EXPECTED_SOURCE_SIZE
    from patch_io import PatchError, sha256_bytes, sha256_file
    from sfgfc_huffman import VECTOR_ENTRIES, load_trees_at
    from v5_1_group_source_delta import (
        PUBLISH_RELATIVE_PATH as SOURCE_DELTA_PATH,
        validate_group_source_delta,
    )
    from v5_1_renderer_output_trace import _load_json_object


ARTIFACT_KIND = "sanitized-v5-1-source-huffman-locator"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_source_huffman_locator.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_source_huffman_locator.json")
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "source_sha256",
    "target_sha256",
    "source_group_delta_sha256",
    "captured_utc",
    "scan",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
SCAN_KEYS = {
    "structural_window_count",
    "parseable_vector_count",
    "unique_vector_selected",
    "selected_populated_context_count",
    "selected_empty_context_count",
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


def find_structural_vector_windows(
    data: bytes,
    *,
    entries: int = VECTOR_ENTRIES,
    minimum_populated: int = 16,
) -> list[int]:
    if entries <= 0 or minimum_populated <= 0 or minimum_populated > entries:
        raise ValueError("source Huffman locator scan bounds are invalid")
    candidates: list[int] = []
    for parity in (0, 1):
        words = [
            int.from_bytes(data[offset : offset + 2], "little")
            for offset in range(parity, len(data) - 1, 2)
        ]
        if len(words) < entries:
            continue
        invalid = [
            int(value != 0xFFFF and not 0x4000 <= value <= 0x7FFF)
            for value in words
        ]
        invalid_count = sum(invalid[:entries])
        for index in range(len(words) - entries + 1):
            if index:
                invalid_count += (
                    invalid[index + entries - 1] - invalid[index - 1]
                )
            if invalid_count:
                continue
            window = words[index : index + entries]
            populated = [value for value in window if value != 0xFFFF]
            if (
                len(populated) < minimum_populated
                or len(set(populated)) != len(populated)
                or any(
                    left >= right
                    for left, right in zip(populated, populated[1:])
                )
            ):
                continue
            candidates.append(parity + index * 2)
    return candidates


def locate_source_huffman_vectors(
    source: bytes,
) -> tuple[dict[str, object], dict[str, object]]:
    structural_offsets = find_structural_vector_windows(source)
    known = bytes([1]) * len(source)
    parseable: list[dict[str, object]] = []
    failures: list[dict[str, object]] = []
    for vector_offset in structural_offsets:
        bank_base = vector_offset & ~0x3FFF
        try:
            trees = load_trees_at(
                source,
                known,
                vector_offset,
                bank_base,
                VECTOR_ENTRIES,
            )
        except (PatchError, ValueError, IndexError, RecursionError) as error:
            failures.append(
                {
                    "vector_offset": vector_offset,
                    "bank_base": bank_base,
                    "error": type(error).__name__,
                }
            )
            continue
        if not trees:
            continue
        leaf_counts = [tree.leaf_count for tree in trees.values()]
        parseable.append(
            {
                "vector_offset": vector_offset,
                "bank_base": bank_base,
                "populated_context_count": len(trees),
                "empty_context_count": VECTOR_ENTRIES - len(trees),
                "minimum_leaf_count": min(leaf_counts),
                "maximum_leaf_count": max(leaf_counts),
            }
        )
    selected = parseable[0] if len(parseable) == 1 else None
    counts = {
        "structural_window_count": len(structural_offsets),
        "parseable_vector_count": len(parseable),
        "unique_vector_selected": selected is not None,
        "selected_populated_context_count": (
            int(selected["populated_context_count"]) if selected else 0
        ),
        "selected_empty_context_count": (
            int(selected["empty_context_count"]) if selected else 0
        ),
    }
    local = {
        "structural_offsets": structural_offsets,
        "parseable_vectors": parseable,
        "parse_failures": failures,
        "selected_vector": selected,
    }
    return counts, local


def build_source_huffman_locator(
    *,
    source_sha256: str,
    target_sha256: str,
    source_group_delta_sha256: str,
    scan: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    selected = scan["unique_vector_selected"] is True
    parseable_count = int(scan["parseable_vector_count"])
    status = (
        "source-huffman-vector-uniquely-located"
        if selected
        else "source-huffman-vector-candidates-ambiguous"
        if parseable_count > 1
        else "source-huffman-vector-not-found"
    )
    next_checkpoint = (
        "decode-clean-source-group"
        if selected
        else "rank-source-vectors-by-group-roundtrip"
        if parseable_count > 1
        else "expand-source-vector-structure-scan"
    )
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "source_sha256": source_sha256,
        "target_sha256": target_sha256,
        "source_group_delta_sha256": source_group_delta_sha256,
        "captured_utc": captured_utc,
        "scan": {
            key: scan[key]
            for key in SCAN_KEYS
        },
        "local_payload_policy": (
            "source-bytes-vector-offsets-pointers-trees-and-symbols-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": next_checkpoint,
    }
    validate_source_huffman_locator(safe)
    return safe


def validate_source_huffman_locator(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("source Huffman locator fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "source-huffman-vector-uniquely-located",
            "source-huffman-vector-candidates-ambiguous",
            "source-huffman-vector-not-found",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "source_sha256",
                "target_sha256",
                "source_group_delta_sha256",
            )
        )
    ):
        raise ValueError("source Huffman locator policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("source Huffman locator timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("source Huffman locator timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("source Huffman locator timestamp must include UTC")
    scan = value["scan"]
    if not isinstance(scan, dict) or set(scan) != SCAN_KEYS:
        raise ValueError("source Huffman locator scan fields do not match")
    for key in SCAN_KEYS - {"unique_vector_selected"}:
        maximum = 0x100 if "context" in key else 0x100000
        if not _bounded_int(scan[key], 0, maximum):
            raise ValueError(f"source Huffman locator {key} is invalid")
    if not isinstance(scan["unique_vector_selected"], bool):
        raise ValueError("source Huffman locator selection is invalid")
    parseable_count = int(scan["parseable_vector_count"])
    selected = scan["unique_vector_selected"] is True
    if (
        scan["structural_window_count"] < parseable_count
        or selected != (parseable_count == 1)
        or (
            selected
            and scan["selected_populated_context_count"]
            + scan["selected_empty_context_count"] != VECTOR_ENTRIES
        )
        or (
            not selected
            and (
                scan["selected_populated_context_count"] != 0
                or scan["selected_empty_context_count"] != 0
            )
        )
    ):
        raise ValueError("source Huffman locator aggregates are inconsistent")
    expected_status = (
        "source-huffman-vector-uniquely-located"
        if selected
        else "source-huffman-vector-candidates-ambiguous"
        if parseable_count > 1
        else "source-huffman-vector-not-found"
    )
    expected_checkpoint = (
        "decode-clean-source-group"
        if selected
        else "rank-source-vectors-by-group-roundtrip"
        if parseable_count > 1
        else "expand-source-vector-structure-scan"
    )
    if (
        value["status"] != expected_status
        or value["next_checkpoint"] != expected_checkpoint
        or value["local_payload_policy"]
        != "source-bytes-vector-offsets-pointers-trees-and-symbols-local-only"
        or value["translation_build_eligible"] is not False
    ):
        raise ValueError("source Huffman locator result is inconsistent")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-rom", type=Path, required=True)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    source_path = (
        args.source_rom
        if args.source_rom.is_absolute()
        else root / args.source_rom
    )
    delta_path = root / SOURCE_DELTA_PATH
    prerequisites = (source_path, delta_path)
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Source Huffman locator is not ready")
            return 0
        raise SystemExit("source Huffman locator input is missing")
    source = source_path.read_bytes()
    if (
        len(source) != EXPECTED_SOURCE_SIZE
        or sha256_bytes(source) != EXPECTED_SOURCE_SHA256
    ):
        raise ValueError("source Huffman locator clean ROM identity mismatch")
    delta = _load_json_object(delta_path)
    validate_group_source_delta(delta)
    if delta["source_sha256"] != EXPECTED_SOURCE_SHA256:
        raise ValueError("source Huffman locator identity disagrees")
    counts, local_analysis = locate_source_huffman_vectors(source)
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    safe = build_source_huffman_locator(
        source_sha256=EXPECTED_SOURCE_SHA256,
        target_sha256=str(delta["target_sha256"]),
        source_group_delta_sha256=sha256_file(delta_path),
        scan=counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-v5-1-source-huffman-locator",
        "schema_version": 1,
        "source_sha256": EXPECTED_SOURCE_SHA256,
        "target_sha256": delta["target_sha256"],
        "captured_utc": captured_utc,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-source-bytes-vector-offsets-pointers-trees-or-symbols"
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
    print(f"SFKR source Huffman locator: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
