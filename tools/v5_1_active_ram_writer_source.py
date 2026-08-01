#!/usr/bin/env python3
"""Classify the input feeding the observed active-dialogue RAM writer.

Detailed writer opcodes, registers, and addresses remain in reports/local.
Only counts and a coarse memory class are published for device sync.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_active_ram_producer import (
        LOCAL_REPORT_PATH as PRODUCER_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as PRODUCER_PATH,
        _load_json_object,
        validate_active_ram_producer,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_active_ram_producer import (
        LOCAL_REPORT_PATH as PRODUCER_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as PRODUCER_PATH,
        _load_json_object,
        validate_active_ram_producer,
    )


ARTIFACT_KIND = "sanitized-s25u-active-ram-writer-source"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_active_ram_writer_source.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_active_ram_writer_source.json")
COUNT_KEYS = {
    "candidate_event_count",
    "classified_event_count",
    "memory_source_event_count",
    "system_ram_source_event_count",
    "rom_window_source_event_count",
    "register_source_event_count",
    "unresolved_source_event_count",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_active_ram_producer_sha256",
    "captured_utc",
    "analysis",
    "writer_sentinel_confirmed",
    "writer_source_class",
    "baseline_script_bytes_unchanged",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _writer_source(writer: dict[str, object]) -> dict[str, object]:
    """Recover the source of a supported post-instruction RAM write."""

    raw = writer.get("opcodes_hex")
    registers = writer.get("registers")
    if not isinstance(raw, str) or not isinstance(registers, dict):
        return {"kind": "unresolved"}
    try:
        opcodes = bytes.fromhex(raw)
        hl = int(registers["hl"]) & 0xFFFF
    except (ValueError, TypeError, KeyError):
        return {"kind": "unresolved"}
    if opcodes[:2] in {bytes.fromhex("ED A0"), bytes.fromhex("ED B0")}:
        return {
            "kind": "memory",
            "logical_address": (hl - 1) & 0xFFFF,
            "direction": "increment",
        }
    if opcodes[:2] in {bytes.fromhex("ED A8"), bytes.fromhex("ED B8")}:
        return {
            "kind": "memory",
            "logical_address": (hl + 1) & 0xFFFF,
            "direction": "decrement",
        }
    if writer.get("operand_kind") in {
        "accumulator-store",
        "register-store",
        "stack-store",
        "read-modify-write",
    }:
        return {"kind": "register"}
    return {"kind": "unresolved"}


def _memory_class(address: int) -> str:
    if 0xC000 <= address <= 0xFFFF:
        return "system-ram"
    if 0 <= address <= 0xBFFF:
        return "rom-window"
    return "unresolved"


def analyze_writer_sources(
    local_producer: dict[str, object],
) -> tuple[dict[str, int], dict[str, object]]:
    events = local_producer.get("events")
    local_analysis = local_producer.get("analysis")
    if not isinstance(events, list) or not isinstance(local_analysis, dict):
        raise ValueError("active RAM writer local producer payload is invalid")
    latest = local_analysis.get("latest_writer_event")
    if not isinstance(latest, dict):
        raise ValueError("active RAM writer event index is missing")
    event_indices = sorted({int(value) for value in latest.values()})
    candidates: list[dict[str, object]] = []
    class_counts = {
        "memory": 0,
        "system-ram": 0,
        "rom-window": 0,
        "register": 0,
        "unresolved": 0,
    }
    for event_index in event_indices:
        if not 0 <= event_index < len(events):
            raise ValueError("active RAM writer event index is out of range")
        event = events[event_index]
        if not isinstance(event, dict) or not isinstance(event.get("writer"), dict):
            raise ValueError("active RAM writer candidate is invalid")
        writer = event["writer"]
        assert isinstance(writer, dict)
        source = _writer_source(writer)
        kind = str(source["kind"])
        if kind == "memory":
            class_counts["memory"] += 1
            memory_class = _memory_class(int(source["logical_address"]))
            source["memory_class"] = memory_class
            class_counts[memory_class] += 1
        else:
            class_counts[kind] += 1
        candidates.append(
            {"event_index": event_index, "writer": writer, "source": source}
        )
    classified = (
        class_counts["memory"] + class_counts["register"]
    )
    counts = {
        "candidate_event_count": len(candidates),
        "classified_event_count": classified,
        "memory_source_event_count": class_counts["memory"],
        "system_ram_source_event_count": class_counts["system-ram"],
        "rom_window_source_event_count": class_counts["rom-window"],
        "register_source_event_count": class_counts["register"],
        "unresolved_source_event_count": class_counts["unresolved"],
    }
    return counts, {"candidates": candidates}


def _source_class(analysis: dict[str, int]) -> str:
    candidates = int(analysis["candidate_event_count"])
    classes = [
        name
        for name, key in (
            ("system-ram", "system_ram_source_event_count"),
            ("rom-window", "rom_window_source_event_count"),
            ("register", "register_source_event_count"),
        )
        if int(analysis[key]) == candidates and candidates > 0
    ]
    return classes[0] if len(classes) == 1 else "unresolved"


def build_active_ram_writer_source(
    *,
    target_sha256: str,
    source_active_ram_producer_sha256: str,
    analysis: dict[str, int],
    writer_sentinel_confirmed: bool,
    captured_utc: str,
) -> dict[str, object]:
    source_class = _source_class(analysis)
    classified = writer_sentinel_confirmed and source_class != "unresolved"
    status = (
        "active-ram-writer-source-classified"
        if classified
        else "active-ram-writer-source-unresolved"
    )
    next_checkpoint = {
        "system-ram": "trace-active-ram-writer-input",
        "rom-window": "map-active-ram-writer-rom-input",
        "register": "trace-active-ram-writer-register-input",
        "unresolved": "extend-active-ram-writer-source-decoder",
    }[source_class]
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": target_sha256,
        "source_active_ram_producer_sha256": source_active_ram_producer_sha256,
        "captured_utc": captured_utc,
        "analysis": {key: int(analysis[key]) for key in COUNT_KEYS},
        "writer_sentinel_confirmed": writer_sentinel_confirmed,
        "writer_source_class": source_class,
        "baseline_script_bytes_unchanged": True,
        "local_payload_policy": (
            "writer-opcodes-registers-pcs-and-source-addresses-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": next_checkpoint,
    }
    validate_active_ram_writer_source(value)
    return value


def validate_active_ram_writer_source(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("active RAM writer source fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"] not in {
            "active-ram-writer-source-classified",
            "active-ram-writer-source-unresolved",
        }
        or value["writer_source_class"] not in {
            "system-ram",
            "rom-window",
            "register",
            "unresolved",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_active_ram_producer_sha256"])
    ):
        raise ValueError("active RAM writer source policy is invalid")
    counts = value["analysis"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("active RAM writer source counts do not match")
    if any(
        not isinstance(counts[key], int)
        or isinstance(counts[key], bool)
        or counts[key] < 0
        for key in COUNT_KEYS
    ):
        raise ValueError("active RAM writer source count is invalid")
    candidates = int(counts["candidate_event_count"])
    classified_count = int(counts["classified_event_count"])
    memory = int(counts["memory_source_event_count"])
    system_ram = int(counts["system_ram_source_event_count"])
    rom = int(counts["rom_window_source_event_count"])
    register = int(counts["register_source_event_count"])
    unresolved = int(counts["unresolved_source_event_count"])
    if (
        classified_count != memory + register
        or memory != system_ram + rom
        or candidates != classified_count + unresolved
    ):
        raise ValueError("active RAM writer source counts are inconsistent")
    source_class = _source_class({key: int(counts[key]) for key in COUNT_KEYS})
    confirmed = value["writer_sentinel_confirmed"] is True
    classified = confirmed and source_class != "unresolved"
    expected_status = (
        "active-ram-writer-source-classified"
        if classified
        else "active-ram-writer-source-unresolved"
    )
    expected_next = {
        "system-ram": "trace-active-ram-writer-input",
        "rom-window": "map-active-ram-writer-rom-input",
        "register": "trace-active-ram-writer-register-input",
        "unresolved": "extend-active-ram-writer-source-decoder",
    }[source_class]
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("active RAM writer source timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("active RAM writer source timestamp is invalid") from error
    if (
        parsed.tzinfo is None
        or value["status"] != expected_status
        or value["writer_source_class"] != source_class
        or value["baseline_script_bytes_unchanged"] is not True
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"] != expected_next
        or value["local_payload_policy"]
        != "writer-opcodes-registers-pcs-and-source-addresses-local-only"
    ):
        raise ValueError("active RAM writer source result is inconsistent")


def _is_current(path: Path, *, target_sha256: str, source_sha256: str) -> bool:
    if not path.is_file():
        return False
    try:
        value = _load_json_object(path)
        validate_active_ram_writer_source(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        value["target_sha256"] == target_sha256
        and value["source_active_ram_producer_sha256"] == source_sha256
    )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    producer_path = root / PRODUCER_PATH
    producer_local_path = root / PRODUCER_LOCAL_PATH
    publish_path = root / PUBLISH_RELATIVE_PATH
    local_path = root / LOCAL_REPORT_PATH
    if not producer_path.is_file() or not producer_local_path.is_file():
        if args.if_ready:
            print("Active RAM writer source classification is not ready")
            return 0
        raise SystemExit("active RAM writer source input is missing")
    producer = _load_json_object(producer_path)
    producer_local = _load_json_object(producer_local_path)
    validate_active_ram_producer(producer)
    target_sha256 = str(producer["target_sha256"])
    producer_sha256 = sha256_file(producer_path)
    if _is_current(
        publish_path,
        target_sha256=target_sha256,
        source_sha256=producer_sha256,
    ):
        print("Active RAM writer source classification is already current")
        return 0
    if (
        producer["target_values_verified"] is not True
        or int(producer["analysis"]["parsed_target_write_event_count"]) <= 0
    ):
        if args.if_ready:
            print("Active RAM writer source classification is not ready")
            return 0
        raise ValueError("active RAM writer sentinel is not confirmed")
    if (
        producer_local.get("artifact_kind") != "local-s25u-active-ram-producer"
        or producer_local.get("target_sha256") != target_sha256
        or producer_local.get("source_active_vram_route_sha256")
        != producer["source_active_vram_route_sha256"]
    ):
        raise ValueError("active RAM writer local producer identity disagrees")
    counts, local_analysis = analyze_writer_sources(producer_local)
    captured_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    safe = build_active_ram_writer_source(
        target_sha256=target_sha256,
        source_active_ram_producer_sha256=producer_sha256,
        analysis=counts,
        writer_sentinel_confirmed=True,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-s25u-active-ram-writer-source",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "source_active_ram_producer_sha256": producer_sha256,
        "captured_utc": captured_utc,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-writer-opcodes-registers-pcs-or-source-addresses"
        ),
    }
    publish_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    publish_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR active RAM writer source: {publish_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
