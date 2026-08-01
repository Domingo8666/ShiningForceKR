#!/usr/bin/env python3
"""Cold-boot baseline and translated ROMs and compare the same dialogue VRAM.

This stage deliberately avoids another speculative ROM patch.  It reaches the
confirmed first dialogue entry in two independent emulator processes, advances
both by the same bounded frame count, and compares VRAM.  Published output is a
fixed-schema receipt containing identities and counts only; screenshots, VRAM
bytes, glyph identities, registers, and addresses remain phone-local.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_bytes, sha256_file
    from .run_s25u_runtime_probe import (
        McpStdioClient,
        _capture_state,
        _default_command,
        _step_frames_and_wait,
        _step_instruction_and_wait,
    )
    from .v5_1_active_vram_route import (
        TILE_BYTES,
        _read_memory_area,
        _select_vram_area,
    )
    from .v5_1_first_context_record_reinsertion import TARGET_PATH
    from .v5_1_first_context_translation_encoding import (
        LOCAL_REPORT_PATH as LOCAL_ENCODING_PATH,
    )
    from .v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TEST_BUILD_PATH,
        TEST_ROM_PATH,
        validate_first_context_translation_test_build,
    )
    from .v5_1_source_target_runtime_sequence import (
        POST_DECODE_CAPTURE_FRAMES,
        REQUIRED_TOOLS,
        _capture_runtime_initial_context,
        _entry_coordinates,
    )
    from .v5_1_source_target_anchor import (
        CONFIRMED_ORDINAL,
        CONFIRMED_SELECTOR,
    )
    from .v5_1_test_display_capture import (
        ATTRACT_CAPTURE_SCHEDULE,
        ATTRACT_CAPTURE_TIMEOUT_SECONDS,
        DECODER_ENTRY_LOGICAL,
        MAX_REJECTED_TARGET_HITS,
        _continue_until_breakpoint,
        _parse_screenshot,
        _write_bytes_atomic,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_bytes, sha256_file
    from run_s25u_runtime_probe import (
        McpStdioClient,
        _capture_state,
        _default_command,
        _step_frames_and_wait,
        _step_instruction_and_wait,
    )
    from v5_1_active_vram_route import (
        TILE_BYTES,
        _read_memory_area,
        _select_vram_area,
    )
    from v5_1_first_context_record_reinsertion import TARGET_PATH
    from v5_1_first_context_translation_encoding import (
        LOCAL_REPORT_PATH as LOCAL_ENCODING_PATH,
    )
    from v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TEST_BUILD_PATH,
        TEST_ROM_PATH,
        validate_first_context_translation_test_build,
    )
    from v5_1_source_target_runtime_sequence import (
        POST_DECODE_CAPTURE_FRAMES,
        REQUIRED_TOOLS,
        _capture_runtime_initial_context,
        _entry_coordinates,
    )
    from v5_1_source_target_anchor import (
        CONFIRMED_ORDINAL,
        CONFIRMED_SELECTOR,
    )
    from v5_1_test_display_capture import (
        ATTRACT_CAPTURE_SCHEDULE,
        ATTRACT_CAPTURE_TIMEOUT_SECONDS,
        DECODER_ENTRY_LOGICAL,
        MAX_REJECTED_TARGET_HITS,
        _continue_until_breakpoint,
        _parse_screenshot,
        _write_bytes_atomic,
    )


ARTIFACT_KIND = "sanitized-v5-1-first-context-translated-vram-diff"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_translated_vram_diff.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_first_context_translated_vram_diff.json"
)
LOCAL_EVIDENCE_DIR = Path(
    "evidence/local/v5_1_first_context_translated_vram_diff"
)
COUNT_KEYS = {
    "vram_area_size",
    "changed_byte_count",
    "changed_tile_count",
    "custom_glyph_hash_count",
    "test_custom_glyph_tile_match_count",
    "changed_custom_glyph_tile_match_count",
    "unique_changed_custom_glyph_match_count",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "baseline_target_sha256",
    "test_target_sha256",
    "first_context_translation_test_build_sha256",
    "local_encoding_sha256",
    "local_capture_sha256",
    "captured_utc",
    "analysis",
    "same_runtime_entry_confirmed",
    "same_initial_context_confirmed",
    "cold_boot_each",
    "translation_vram_difference_observed",
    "custom_glyph_vram_observed",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _is_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def analyze_translated_vram_diff(
    *,
    baseline: bytes,
    translated: bytes,
    custom_glyph_hashes: set[str],
) -> tuple[dict[str, int], dict[str, object]]:
    if len(baseline) != len(translated) or len(baseline) % TILE_BYTES:
        raise ValueError("baseline and translated VRAM sizes disagree")
    if any(not _is_sha256(value) for value in custom_glyph_hashes):
        raise ValueError("custom glyph hash is invalid")

    changed_offsets = [
        offset
        for offset, (before, after) in enumerate(zip(baseline, translated))
        if before != after
    ]
    changed_tiles = sorted({offset // TILE_BYTES for offset in changed_offsets})
    translated_tiles = [
        translated[offset : offset + TILE_BYTES]
        for offset in range(0, len(translated), TILE_BYTES)
    ]
    translated_hashes = [sha256_bytes(tile) for tile in translated_tiles]
    all_matches = [
        index
        for index, tile_hash in enumerate(translated_hashes)
        if tile_hash in custom_glyph_hashes
    ]
    changed_matches = [
        index
        for index in changed_tiles
        if translated_hashes[index] in custom_glyph_hashes
    ]
    matched_hashes = {translated_hashes[index] for index in changed_matches}
    safe_counts = {
        "vram_area_size": len(translated),
        "changed_byte_count": len(changed_offsets),
        "changed_tile_count": len(changed_tiles),
        "custom_glyph_hash_count": len(custom_glyph_hashes),
        "test_custom_glyph_tile_match_count": len(all_matches),
        "changed_custom_glyph_tile_match_count": len(changed_matches),
        "unique_changed_custom_glyph_match_count": len(matched_hashes),
    }
    local = {
        "changed_offsets": changed_offsets,
        "changed_tiles": changed_tiles,
        "test_custom_glyph_match_tiles": all_matches,
        "changed_custom_glyph_match_tiles": changed_matches,
        "changed_custom_glyph_hashes": sorted(matched_hashes),
    }
    return safe_counts, local


def build_first_context_translated_vram_diff(
    *,
    baseline_target_sha256: str,
    test_target_sha256: str,
    first_context_translation_test_build_sha256: str,
    local_encoding_sha256: str,
    local_capture_sha256: str,
    analysis: dict[str, int],
    same_runtime_entry_confirmed: bool,
    same_initial_context_confirmed: bool,
    captured_utc: str,
) -> dict[str, object]:
    changed = analysis["changed_byte_count"] > 0
    glyphs = analysis["changed_custom_glyph_tile_match_count"] > 0
    if glyphs:
        status = "translated-custom-glyph-vram-confirmed"
        next_checkpoint = "trace-first-changed-translated-vram-tile-source"
    elif changed:
        status = "translated-vram-difference-observed"
        next_checkpoint = "repair-font-tile-lookup-before-dialogue-rebuild"
    else:
        status = "translated-vram-difference-not-observed"
        next_checkpoint = "repair-renderer-consumer-before-dialogue-rebuild"
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "baseline_target_sha256": baseline_target_sha256,
        "test_target_sha256": test_target_sha256,
        "first_context_translation_test_build_sha256":
            first_context_translation_test_build_sha256,
        "local_encoding_sha256": local_encoding_sha256,
        "local_capture_sha256": local_capture_sha256,
        "captured_utc": captured_utc,
        "analysis": dict(analysis),
        "same_runtime_entry_confirmed": same_runtime_entry_confirmed,
        "same_initial_context_confirmed": same_initial_context_confirmed,
        "cold_boot_each": True,
        "translation_vram_difference_observed": changed,
        "custom_glyph_vram_observed": glyphs,
        "local_payload_policy": (
            "never-publish-vram-bytes-addresses-glyph-identities-screens-or-registers"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": next_checkpoint,
    }
    validate_first_context_translated_vram_diff(value)
    return value


def validate_first_context_translated_vram_diff(
    value: dict[str, object],
) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("translated VRAM diff fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"] not in {
            "translated-custom-glyph-vram-confirmed",
            "translated-vram-difference-observed",
            "translated-vram-difference-not-observed",
        }
        or any(
            not _is_sha256(value[key])
            for key in {
                "baseline_target_sha256",
                "test_target_sha256",
                "first_context_translation_test_build_sha256",
                "local_encoding_sha256",
                "local_capture_sha256",
            }
        )
        or not _is_utc_timestamp(value["captured_utc"])
    ):
        raise ValueError("translated VRAM diff policy is invalid")
    counts = value["analysis"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("translated VRAM diff counts do not match")
    if any(
        not isinstance(counts[key], int)
        or isinstance(counts[key], bool)
        or counts[key] < 0
        for key in COUNT_KEYS
    ):
        raise ValueError("translated VRAM diff count is invalid")
    if (
        counts["changed_byte_count"] > counts["vram_area_size"]
        or counts["changed_tile_count"]
        > counts["vram_area_size"] // TILE_BYTES
        or counts["changed_custom_glyph_tile_match_count"]
        > counts["changed_tile_count"]
        or counts["unique_changed_custom_glyph_match_count"]
        > counts["changed_custom_glyph_tile_match_count"]
        or counts["test_custom_glyph_tile_match_count"]
        > counts["vram_area_size"] // TILE_BYTES
    ):
        raise ValueError("translated VRAM diff counts are inconsistent")
    expected_changed = counts["changed_byte_count"] > 0
    expected_glyphs = counts["changed_custom_glyph_tile_match_count"] > 0
    expected_status = (
        "translated-custom-glyph-vram-confirmed"
        if expected_glyphs
        else "translated-vram-difference-observed"
        if expected_changed
        else "translated-vram-difference-not-observed"
    )
    expected_checkpoint = (
        "trace-first-changed-translated-vram-tile-source"
        if expected_glyphs
        else "repair-font-tile-lookup-before-dialogue-rebuild"
        if expected_changed
        else "repair-renderer-consumer-before-dialogue-rebuild"
    )
    if (
        value["status"] != expected_status
        or value["translation_vram_difference_observed"] is not expected_changed
        or value["custom_glyph_vram_observed"] is not expected_glyphs
        or value["same_runtime_entry_confirmed"] is not True
        or value["same_initial_context_confirmed"] is not True
        or value["cold_boot_each"] is not True
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"] != expected_checkpoint
    ):
        raise ValueError("translated VRAM diff result is inconsistent")


def _custom_glyph_hashes(local_encoding: dict[str, object]) -> set[str]:
    assignments = local_encoding.get("character_assignments")
    if not isinstance(assignments, list):
        raise ValueError("local encoding character assignments are missing")
    result = {
        str(item["tile_sha256"])
        for item in assignments
        if isinstance(item, dict)
        and item.get("visual_kind") == "approved-target-character"
        and _is_sha256(item.get("tile_sha256"))
    }
    if not result:
        raise ValueError("local encoding has no approved target glyph hashes")
    return result


def _capture_anchor_vram(
    *,
    rom_path: Path,
    evidence_path: Path,
) -> dict[str, object]:
    client = McpStdioClient(_default_command())
    breakpoint_armed = False
    entry_address = f"{DECODER_ENTRY_LOGICAL:04X}"

    def arm() -> None:
        nonlocal breakpoint_armed
        client.call(
            "set_breakpoint_range",
            {
                "start_address": entry_address,
                "end_address": entry_address,
                "memory_area": "rom_ram",
                "execute": True,
                "read": False,
                "write": False,
            },
        )
        breakpoint_armed = True

    def disarm() -> None:
        nonlocal breakpoint_armed
        client.call(
            "remove_breakpoint",
            {
                "address": entry_address,
                "end_address": entry_address,
                "memory_area": "rom_ram",
            },
        )
        breakpoint_armed = False

    try:
        tools = client.initialize()
        missing = sorted(REQUIRED_TOOLS - tools)
        if missing:
            raise RuntimeError(f"Gearsystem MCP tools missing: {missing}")
        client.call("load_media", {"file_path": str(rom_path)})
        media = client.call("get_media_info")
        if (
            media.get("ready") is not True
            or media.get("is_game_gear") is not True
            or int(media.get("rom_size", 0)) != rom_path.stat().st_size
        ):
            raise RuntimeError("Gearsystem did not load the exact comparison ROM")
        client.call("debug_reset")
        client.call("debug_pause")
        if any(button is not None for _, button in ATTRACT_CAPTURE_SCHEDULE):
            raise RuntimeError("translated VRAM comparison schedule must be passive")
        arm()
        selected_state: dict[str, object] | None = None
        timeout = max(ATTRACT_CAPTURE_TIMEOUT_SECONDS, 240.0)
        for _ in range(MAX_REJECTED_TARGET_HITS):
            status = _continue_until_breakpoint(client, timeout)
            if status.get("at_breakpoint") is not True:
                break
            state, _ = _capture_state(client)
            selector, ordinal = _entry_coordinates(state)
            disarm()
            if selector == CONFIRMED_SELECTOR and ordinal == CONFIRMED_ORDINAL:
                selected_state = state
                break
            _step_instruction_and_wait(client)
            arm()
        if selected_state is None:
            raise RuntimeError("confirmed dialogue anchor was not reached")
        initial_context, _ = _capture_runtime_initial_context(
            client,
            rom_size=rom_path.stat().st_size,
        )
        _step_frames_and_wait(client, POST_DECODE_CAPTURE_FRAMES)
        memory_areas = client.call("list_memory_areas")
        area = _select_vram_area(memory_areas)
        vram = _read_memory_area(
            client,
            area_id=int(area["id"]),
            size=int(area["size"]),
        )
        png, screen_metadata = _parse_screenshot(client.call("get_screenshot"))
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        _write_bytes_atomic(evidence_path, png)
        return {
            "selector": CONFIRMED_SELECTOR,
            "ordinal": CONFIRMED_ORDINAL,
            "initial_context": initial_context,
            "vram": vram,
            "vram_area": {
                "id": int(area["id"]),
                "name": str(area["name"]),
                "size": int(area["size"]),
            },
            "screenshot": {"file": str(evidence_path), **screen_metadata},
        }
    finally:
        if breakpoint_armed:
            try:
                disarm()
            except RuntimeError:
                pass
        client.close()


def _main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    paths = {
        "baseline": root / TARGET_PATH,
        "test": root / TEST_ROM_PATH,
        "build": root / TEST_BUILD_PATH,
        "encoding": root / LOCAL_ENCODING_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        if args.if_ready:
            print("First context translated VRAM diff is not ready")
            return 0
        raise SystemExit("translated VRAM diff input is missing")

    build = json.loads(paths["build"].read_text(encoding="utf-8"))
    if not isinstance(build, dict):
        raise ValueError("translated VRAM diff build input is invalid")
    validate_first_context_translation_test_build(build)
    local_encoding = json.loads(paths["encoding"].read_text(encoding="utf-8"))
    if not isinstance(local_encoding, dict):
        raise ValueError("translated VRAM diff encoding input is invalid")
    if (
        build["status"] != "first-context-translation-static-build-ready"
        or sha256_file(paths["baseline"]) != build["baseline_target_sha256"]
        or sha256_file(paths["test"]) != build["test_target_sha256"]
        or local_encoding.get("target_sha256") != build["baseline_target_sha256"]
    ):
        raise ValueError("translated VRAM diff identity disagrees")

    glyph_hashes = _custom_glyph_hashes(local_encoding)
    evidence_dir = root / LOCAL_EVIDENCE_DIR / str(build["test_target_sha256"])[:16]
    baseline_capture = _capture_anchor_vram(
        rom_path=paths["baseline"],
        evidence_path=evidence_dir / "baseline.png",
    )
    translated_capture = _capture_anchor_vram(
        rom_path=paths["test"],
        evidence_path=evidence_dir / "translated.png",
    )
    baseline_vram = baseline_capture.pop("vram")
    translated_vram = translated_capture.pop("vram")
    assert isinstance(baseline_vram, bytes)
    assert isinstance(translated_vram, bytes)
    counts, local_analysis = analyze_translated_vram_diff(
        baseline=baseline_vram,
        translated=translated_vram,
        custom_glyph_hashes=glyph_hashes,
    )
    same_runtime = (
        baseline_capture["selector"] == translated_capture["selector"]
        and baseline_capture["ordinal"] == translated_capture["ordinal"]
    )
    same_context = (
        baseline_capture["initial_context"]
        == translated_capture["initial_context"]
    )
    if not same_runtime or not same_context:
        raise RuntimeError("translated VRAM captures did not reach the same context")

    captured_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    local = {
        "artifact_kind": "local-v5-1-first-context-translated-vram-diff",
        "schema_version": SCHEMA_VERSION,
        "baseline_target_sha256": build["baseline_target_sha256"],
        "test_target_sha256": build["test_target_sha256"],
        "captured_utc": captured_utc,
        "baseline_capture": baseline_capture,
        "translated_capture": translated_capture,
        "analysis": local_analysis,
        "baseline_vram_sha256": sha256_bytes(baseline_vram),
        "translated_vram_sha256": sha256_bytes(translated_vram),
        "publication_policy": (
            "never-publish-vram-bytes-addresses-glyph-identities-screens-or-registers"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_first_context_translated_vram_diff(
        baseline_target_sha256=str(build["baseline_target_sha256"]),
        test_target_sha256=str(build["test_target_sha256"]),
        first_context_translation_test_build_sha256=sha256_file(paths["build"]),
        local_encoding_sha256=sha256_file(paths["encoding"]),
        local_capture_sha256=sha256_file(local_path),
        analysis=counts,
        same_runtime_entry_confirmed=same_runtime,
        same_initial_context_confirmed=same_context,
        captured_utc=captured_utc,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR first context translated VRAM diff: {safe_path}")
    return 0


def main() -> int:
    return _main()


if __name__ == "__main__":
    raise SystemExit(main())
