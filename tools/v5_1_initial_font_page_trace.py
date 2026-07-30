#!/usr/bin/env python3
"""Narrow implicit font-page candidates at the first confirmed VDP upload."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .run_s25u_runtime_probe import (
        McpStdioClient,
        _capture_state,
        _default_command,
        _runtime_failure_receipt,
        _write_runtime_failure_receipt,
    )
    from .v5_1_renderer_output_trace import (
        DECODER_REGISTER_TRACE_PATH,
        DEFAULT_ROM,
        LOCAL_REPORT_PATH as LOCAL_RENDERER_TRACE_PATH,
        PUBLISH_RELATIVE_PATH as RENDERER_TRACE_PATH,
        REQUIRED_TOOLS,
        _load_json_object,
        _reach_exact_payload,
        _remove_breakpoint,
        _set_execute_breakpoint,
        validate_renderer_output_trace,
    )
    from .v5_1_test_display_capture import (
        _continue_until_breakpoint,
        _set_unlimited_fast_forward,
    )
    from .v5_1_test_phrase import (
        FONT_DATA_FIRST_BANK,
        FONT_PAGES_PER_BANK,
    )
    from .v5_1_visible_unicode_mapping import (
        LOCAL_REPORT_PATH as LOCAL_MAPPING_PATH,
        PUBLISH_RELATIVE_PATH as MAPPING_PATH,
        validate_visible_unicode_mapping,
    )
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from run_s25u_runtime_probe import (
        McpStdioClient,
        _capture_state,
        _default_command,
        _runtime_failure_receipt,
        _write_runtime_failure_receipt,
    )
    from v5_1_renderer_output_trace import (
        DECODER_REGISTER_TRACE_PATH,
        DEFAULT_ROM,
        LOCAL_REPORT_PATH as LOCAL_RENDERER_TRACE_PATH,
        PUBLISH_RELATIVE_PATH as RENDERER_TRACE_PATH,
        REQUIRED_TOOLS,
        _load_json_object,
        _reach_exact_payload,
        _remove_breakpoint,
        _set_execute_breakpoint,
        validate_renderer_output_trace,
    )
    from v5_1_test_display_capture import (
        _continue_until_breakpoint,
        _set_unlimited_fast_forward,
    )
    from v5_1_test_phrase import (
        FONT_DATA_FIRST_BANK,
        FONT_PAGES_PER_BANK,
    )
    from v5_1_visible_unicode_mapping import (
        LOCAL_REPORT_PATH as LOCAL_MAPPING_PATH,
        PUBLISH_RELATIVE_PATH as MAPPING_PATH,
        validate_visible_unicode_mapping,
    )


ARTIFACT_KIND = "sanitized-s25u-initial-font-page-trace"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_initial_font_page_trace.json"
)
LOCAL_REPORT_RELATIVE_PATH = Path(
    "reports/local/v5_1_initial_font_page_trace.json"
)
TRACE_TIMEOUT_SECONDS = 15.0
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_mapping_sha256",
    "captured_utc",
    "runtime_entry",
    "candidate_page_count_before",
    "candidate_page_count_after",
    "runtime_initial_page_confirmed",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
RUNTIME_ENTRY_KEYS = {
    "physical_start",
    "logical_start",
    "mapped_bank",
    "record_length_bytes",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def resolve_pages_from_font_bank(
    candidate_pages: list[int],
    mapped_font_bank: int,
) -> list[int]:
    if (
        not candidate_pages
        or candidate_pages != sorted(set(candidate_pages))
        or any(not 0 <= page < 244 for page in candidate_pages)
    ):
        raise ValueError("initial font-page candidates are invalid")
    if not 0 <= mapped_font_bank <= 0xFF:
        raise ValueError("mapped font bank is invalid")
    return [
        page
        for page in candidate_pages
        if FONT_DATA_FIRST_BANK + page // FONT_PAGES_PER_BANK
        == mapped_font_bank
    ]


def runtime_entry_matches(
    candidate: object,
    expected: object,
) -> bool:
    if not isinstance(candidate, dict) or not isinstance(expected, dict):
        return False
    return all(
        candidate.get(key) == expected.get(key)
        for key in RUNTIME_ENTRY_KEYS
    )


def build_initial_font_page_trace(
    *,
    target_sha256: str,
    source_mapping_sha256: str,
    runtime_entry: dict[str, object],
    candidate_pages: list[int],
    mapped_font_bank: int,
    captured_utc: str,
) -> dict[str, object]:
    remaining = resolve_pages_from_font_bank(
        candidate_pages,
        mapped_font_bank,
    )
    confirmed = len(remaining) == 1
    status = (
        "initial-font-page-confirmed"
        if confirmed
        else "initial-font-page-candidates-remain"
        if remaining
        else "font-bank-outside-candidates"
    )
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": target_sha256,
        "source_mapping_sha256": source_mapping_sha256,
        "captured_utc": captured_utc,
        "runtime_entry": {
            key: runtime_entry[key]
            for key in RUNTIME_ENTRY_KEYS
        },
        "candidate_page_count_before": len(candidate_pages),
        "candidate_page_count_after": len(remaining),
        "runtime_initial_page_confirmed": confirmed,
        "local_payload_policy": (
            "page-candidates-output-addresses-and-registers-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": (
            "extract-full-script-record-set"
            if confirmed
            else "trace-font-transfer-source"
        ),
    }
    validate_initial_font_page_trace(safe)
    return safe


def validate_initial_font_page_trace(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("initial font-page trace fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "initial-font-page-confirmed",
            "initial-font-page-candidates-remain",
            "font-bank-outside-candidates",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_mapping_sha256"])
    ):
        raise ValueError("initial font-page trace policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("initial font-page timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("initial font-page timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("initial font-page timestamp must include UTC")
    runtime = value["runtime_entry"]
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_ENTRY_KEYS:
        raise ValueError("initial font-page runtime fields do not match")
    for key, minimum, maximum in (
        ("physical_start", 0, 0x17BFFF),
        ("logical_start", 0x4000, 0x7FFF),
        ("mapped_bank", 0, 0xFF),
        ("record_length_bytes", 1, 0xFF),
    ):
        item = runtime[key]
        if (
            not isinstance(item, int)
            or isinstance(item, bool)
            or not minimum <= item <= maximum
        ):
            raise ValueError(f"initial font-page {key} is invalid")
    before = value["candidate_page_count_before"]
    after = value["candidate_page_count_after"]
    if (
        not isinstance(before, int)
        or isinstance(before, bool)
        or not 1 <= before <= 244
        or not isinstance(after, int)
        or isinstance(after, bool)
        or not 0 <= after <= before
    ):
        raise ValueError("initial font-page counts are invalid")
    confirmed = after == 1
    expected_status = (
        "initial-font-page-confirmed"
        if confirmed
        else "initial-font-page-candidates-remain"
        if after
        else "font-bank-outside-candidates"
    )
    if (
        value["status"] != expected_status
        or value["runtime_initial_page_confirmed"] is not confirmed
        or value["next_checkpoint"]
        != (
            "extract-full-script-record-set"
            if confirmed
            else "trace-font-transfer-source"
        )
    ):
        raise ValueError("initial font-page result is inconsistent")
    if value["local_payload_policy"] != (
        "page-candidates-output-addresses-and-registers-local-only"
    ):
        raise ValueError("initial font-page local policy is invalid")
    if value["translation_build_eligible"] is not False:
        raise ValueError("initial font-page trace cannot enable release builds")


def _output_anchor(local_renderer: dict[str, object]) -> tuple[int, int]:
    analysis = local_renderer.get("trace_analysis")
    if not isinstance(analysis, dict):
        raise ValueError("local renderer trace analysis is missing")
    outputs = analysis.get("vdp_outputs")
    if not isinstance(outputs, list):
        raise ValueError("local renderer VDP outputs are missing")
    for item in outputs:
        if (
            isinstance(item, dict)
            and item.get("port") == 0xBE
            and isinstance(item.get("pc"), int)
            and isinstance(item.get("bank"), int)
        ):
            return int(item["pc"]), int(item["bank"])
    raise ValueError("local renderer trace has no VDP data output")


def reuse_initial_font_page_trace(
    *,
    existing_safe: object,
    existing_local: object,
    target_sha256: str,
    source_mapping_sha256: str,
    runtime_entry: dict[str, object],
    candidate_pages: list[int],
) -> dict[str, object] | None:
    if not isinstance(existing_safe, dict) or not isinstance(existing_local, dict):
        return None
    try:
        validate_initial_font_page_trace(existing_safe)
    except ValueError:
        return None
    if (
        existing_safe["target_sha256"] != target_sha256
        or not runtime_entry_matches(
            existing_safe["runtime_entry"], runtime_entry
        )
        or existing_local.get("target_sha256") != target_sha256
        or existing_local.get("candidate_pages_before") != candidate_pages
    ):
        return None
    hit_state = existing_local.get("hit_state")
    if not isinstance(hit_state, dict):
        return None
    mapped_font_bank = hit_state.get("slot2_bank")
    if (
        not isinstance(mapped_font_bank, int)
        or isinstance(mapped_font_bank, bool)
        or not 0 <= mapped_font_bank <= 0xFF
    ):
        return None
    rebuilt = build_initial_font_page_trace(
        target_sha256=target_sha256,
        source_mapping_sha256=source_mapping_sha256,
        runtime_entry=runtime_entry,
        candidate_pages=candidate_pages,
        mapped_font_bank=mapped_font_bank,
        captured_utc=str(existing_safe["captured_utc"]),
    )
    for key in (
        "status",
        "candidate_page_count_before",
        "candidate_page_count_after",
        "runtime_initial_page_confirmed",
    ):
        if rebuilt[key] != existing_safe[key]:
            return None
    return rebuilt


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    mapping_path = root / MAPPING_PATH
    local_mapping_path = root / LOCAL_MAPPING_PATH
    local_renderer_path = root / LOCAL_RENDERER_TRACE_PATH
    renderer_trace_path = root / RENDERER_TRACE_PATH
    register_trace_path = root / DECODER_REGISTER_TRACE_PATH
    publish_path = root / PUBLISH_RELATIVE_PATH
    local_initial_path = root / LOCAL_REPORT_RELATIVE_PATH
    prerequisites = (
        rom_path,
        mapping_path,
        local_mapping_path,
        local_renderer_path,
        renderer_trace_path,
        register_trace_path,
    )
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Initial font-page trace is not ready")
            return 0
        raise SystemExit("initial font-page trace input is missing")
    mapping = _load_json_object(mapping_path)
    validate_visible_unicode_mapping(mapping)
    mapping_counts = mapping["mapping"]
    assert isinstance(mapping_counts, dict)
    if (
        mapping["next_checkpoint"] != "confirm-runtime-initial-font-page"
        or mapping_counts["initial_page_candidate_count"] <= 1
    ):
        if args.if_ready:
            print("Initial font-page runtime trace is not required")
            return 0
        raise SystemExit("initial font-page runtime trace is not required")
    target_sha256 = sha256_file(rom_path)
    if mapping["target_sha256"] != target_sha256:
        raise ValueError("initial font-page target identity disagrees")
    renderer_trace = _load_json_object(renderer_trace_path)
    validate_renderer_output_trace(renderer_trace)
    if (
        renderer_trace["target_sha256"] != target_sha256
        or not runtime_entry_matches(
            renderer_trace["runtime_entry"],
            mapping["runtime_entry"],
        )
        or renderer_trace["consumer_chain_confirmed"] is not True
    ):
        raise ValueError("initial font-page renderer identity disagrees")
    local_mapping = _load_json_object(local_mapping_path)
    candidates = local_mapping.get("mapping", {}).get(
        "initial_page_candidates"
    )
    if not isinstance(candidates, list):
        raise ValueError("local initial font-page candidates are missing")
    candidate_pages = sorted(
        int(item["page"])
        for item in candidates
        if isinstance(item, dict) and isinstance(item.get("page"), int)
    )
    if len(candidate_pages) != mapping_counts["initial_page_candidate_count"]:
        raise ValueError("local and safe initial page counts disagree")
    runtime = mapping["runtime_entry"]
    assert isinstance(runtime, dict)
    if publish_path.is_file() and local_initial_path.is_file():
        try:
            existing_safe = _load_json_object(publish_path)
            existing_local = _load_json_object(local_initial_path)
        except (OSError, ValueError, json.JSONDecodeError):
            reused = None
        else:
            reused = reuse_initial_font_page_trace(
                existing_safe=existing_safe,
                existing_local=existing_local,
                target_sha256=target_sha256,
                source_mapping_sha256=sha256_file(mapping_path),
                runtime_entry=runtime,
                candidate_pages=candidate_pages,
            )
        if reused is not None:
            publish_path.write_text(
                json.dumps(reused, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            print("Initial font-page trace reused without emulator replay")
            return 0
    local_renderer = _load_json_object(local_renderer_path)
    output_pc, output_bank = _output_anchor(local_renderer)
    register_trace = _load_json_object(register_trace_path)
    selector_de = int(register_trace["selector_de"])
    states = register_trace.get("states")
    if not isinstance(states, list) or not states or not isinstance(states[0], dict):
        raise ValueError("decoder register trace has no entry state")
    entry_ordinal = int(states[0]["bc"]) >> 8
    client = McpStdioClient(_default_command())
    breakpoint_armed = False
    fast_forward = False
    runtime_stage = "initial-font-page-mcp-initialize"
    route_progress = {"stage": runtime_stage}
    selected_state: dict[str, object] | None = None
    ready_state: dict[str, object] | None = None
    hit_state: dict[str, object] | None = None
    hit_evidence: dict[str, object] | None = None
    try:
        tools = client.initialize()
        missing = sorted(REQUIRED_TOOLS - tools)
        if missing:
            raise RuntimeError(f"Gearsystem MCP tools missing: {missing}")
        runtime_stage = "initial-font-page-load-media"
        client.call("load_media", {"file_path": str(rom_path)})
        media = client.call("get_media_info")
        if (
            media.get("ready") is not True
            or media.get("is_game_gear") is not True
            or int(media.get("rom_size", 0)) != rom_path.stat().st_size
        ):
            raise RuntimeError("Gearsystem did not load the expected Game Gear ROM")
        client.call("debug_reset")
        client.call("debug_pause")
        client.call("set_trace_log", {"enabled": False})
        runtime_stage = "initial-font-page-route-selection"
        selected_state, ready_state = _reach_exact_payload(
            client,
            selector_de=selector_de,
            entry_ordinal=entry_ordinal,
            logical_start=int(runtime["logical_start"]),
            mapped_bank=int(runtime["mapped_bank"]),
            progress=route_progress,
        )
        runtime_stage = "initial-font-page-output-watch"
        _set_execute_breakpoint(client, output_pc)
        breakpoint_armed = True
        _set_unlimited_fast_forward(client, True)
        fast_forward = True
        status = _continue_until_breakpoint(client, TRACE_TIMEOUT_SECONDS)
        if status.get("at_breakpoint") is not True:
            raise RuntimeError("first confirmed VDP data output was not reached")
        _set_unlimited_fast_forward(client, False)
        fast_forward = False
        hit_state, hit_evidence = _capture_state(client)
        if (
            int(hit_state["pc_after"]) != output_pc
            or int(hit_state["executing_bank"]) != output_bank
        ):
            raise RuntimeError("VDP output breakpoint identity disagrees")
    except Exception as error:
        if runtime_stage == "initial-font-page-route-selection":
            runtime_stage = route_progress["stage"]
        receipt = _runtime_failure_receipt(runtime_stage, error, client)
        _write_runtime_failure_receipt(root, receipt)
        raise
    finally:
        if fast_forward:
            try:
                _set_unlimited_fast_forward(client, False)
            except Exception:
                pass
        if breakpoint_armed:
            try:
                _remove_breakpoint(client, output_pc)
            except Exception:
                pass
        client.close()

    assert hit_state is not None
    mapped_font_bank = int(hit_state["slot2_bank"])
    captured_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    safe = build_initial_font_page_trace(
        target_sha256=target_sha256,
        source_mapping_sha256=sha256_file(mapping_path),
        runtime_entry=runtime,
        candidate_pages=candidate_pages,
        mapped_font_bank=mapped_font_bank,
        captured_utc=captured_utc,
    )
    remaining = resolve_pages_from_font_bank(candidate_pages, mapped_font_bank)
    local = {
        "artifact_kind": "local-s25u-initial-font-page-trace",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "captured_utc": captured_utc,
        "candidate_pages_before": candidate_pages,
        "candidate_pages_after": remaining,
        "output_anchor": {"pc": output_pc, "bank": output_bank},
        "selected_state": selected_state,
        "ready_state": ready_state,
        "hit_state": hit_state,
        "hit_evidence": hit_evidence,
        "publication_policy": (
            "never-publish-page-candidates-output-addresses-or-registers"
        ),
    }
    local_path = root / LOCAL_REPORT_RELATIVE_PATH
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
    print(f"SFKR initial font-page trace: {publish_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
