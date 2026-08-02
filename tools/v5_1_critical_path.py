#!/usr/bin/env python3
"""Select one evidence-backed runtime task instead of replaying the whole pipeline."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_active_ram_register_trace import (
        LOCAL_REPORT_PATH as REGISTER_TRACE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as REGISTER_TRACE_PATH,
        validate_active_ram_register_trace,
    )
    from .v5_1_active_register_rom_source import (
        PUBLISH_RELATIVE_PATH as ROM_SOURCE_PATH,
        validate_active_register_rom_source,
    )
    from .v5_1_active_rom_source_role import (
        PUBLISH_RELATIVE_PATH as ROM_SOURCE_ROLE_PATH,
        validate_active_rom_source_role,
    )
    from .v5_1_active_rom_read_block import (
        PUBLISH_RELATIVE_PATH as ROM_READ_BLOCK_PATH,
        validate_active_rom_read_block,
    )
    from .v5_1_active_rom_lookup_index_producer import (
        PUBLISH_RELATIVE_PATH as ROM_LOOKUP_INDEX_PATH,
        validate_active_rom_lookup_index_producer,
    )
    from .v5_1_active_rom_path_scope import (
        PUBLISH_RELATIVE_PATH as ROM_PATH_SCOPE_PATH,
        validate_active_rom_path_scope,
    )
    from .v5_1_first_context_translated_vram_diff import (
        PUBLISH_RELATIVE_PATH as TRANSLATED_VRAM_DIFF_PATH,
        validate_first_context_translated_vram_diff,
    )
    from .v5_1_first_context_translated_glyph_route import (
        PUBLISH_RELATIVE_PATH as TRANSLATED_GLYPH_ROUTE_PATH,
        validate_first_context_translated_glyph_route,
    )
    from .v5_1_first_context_direct_renderer_capture import (
        PUBLISH_RELATIVE_PATH as DIRECT_RENDERER_CAPTURE_PATH,
        PUBLISH_IMAGE_RELATIVE_PATH as DIRECT_RENDERER_CAPTURE_IMAGE_PATH,
        RUNTIME_STAGE_REQUEST_PATH,
        validate_first_context_direct_renderer_capture,
    )
    from .v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TRANSLATION_TEST_BUILD_PATH,
        validate_first_context_translation_test_build,
    )
    from .v5_1_active_rom_cursor_reset import (
        PUBLISH_RELATIVE_PATH as ROM_CURSOR_RESET_PATH,
        validate_active_rom_cursor_reset,
    )
    from .v5_1_renderer_output_trace import DEFAULT_ROM
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_active_ram_register_trace import (
        LOCAL_REPORT_PATH as REGISTER_TRACE_LOCAL_PATH,
        PUBLISH_RELATIVE_PATH as REGISTER_TRACE_PATH,
        validate_active_ram_register_trace,
    )
    from v5_1_active_register_rom_source import (
        PUBLISH_RELATIVE_PATH as ROM_SOURCE_PATH,
        validate_active_register_rom_source,
    )
    from v5_1_active_rom_source_role import (
        PUBLISH_RELATIVE_PATH as ROM_SOURCE_ROLE_PATH,
        validate_active_rom_source_role,
    )
    from v5_1_active_rom_read_block import (
        PUBLISH_RELATIVE_PATH as ROM_READ_BLOCK_PATH,
        validate_active_rom_read_block,
    )
    from v5_1_active_rom_lookup_index_producer import (
        PUBLISH_RELATIVE_PATH as ROM_LOOKUP_INDEX_PATH,
        validate_active_rom_lookup_index_producer,
    )
    from v5_1_active_rom_path_scope import (
        PUBLISH_RELATIVE_PATH as ROM_PATH_SCOPE_PATH,
        validate_active_rom_path_scope,
    )
    from v5_1_first_context_translated_vram_diff import (
        PUBLISH_RELATIVE_PATH as TRANSLATED_VRAM_DIFF_PATH,
        validate_first_context_translated_vram_diff,
    )
    from v5_1_first_context_translated_glyph_route import (
        PUBLISH_RELATIVE_PATH as TRANSLATED_GLYPH_ROUTE_PATH,
        validate_first_context_translated_glyph_route,
    )
    from v5_1_first_context_direct_renderer_capture import (
        PUBLISH_RELATIVE_PATH as DIRECT_RENDERER_CAPTURE_PATH,
        PUBLISH_IMAGE_RELATIVE_PATH as DIRECT_RENDERER_CAPTURE_IMAGE_PATH,
        RUNTIME_STAGE_REQUEST_PATH,
        validate_first_context_direct_renderer_capture,
    )
    from v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TRANSLATION_TEST_BUILD_PATH,
        validate_first_context_translation_test_build,
    )
    from v5_1_active_rom_cursor_reset import (
        PUBLISH_RELATIVE_PATH as ROM_CURSOR_RESET_PATH,
        validate_active_rom_cursor_reset,
    )
    from v5_1_renderer_output_trace import DEFAULT_ROM


ARTIFACT_KIND = "sanitized-s25u-critical-path"
SCHEMA_VERSION = 5
PUBLISH_RELATIVE_PATH = Path("analysis/device/v5_1_latest_critical_path.json")
FOCUSED_STAGE = "active-register-rom-source"
SOURCE_ROLE_STAGE = "active-rom-source-role"
READ_BLOCK_STAGE = "active-rom-read-block"
LOOKUP_INDEX_STAGE = "active-rom-lookup-index-producer"
PATH_SCOPE_STAGE = "active-rom-path-scope"
TRANSLATED_VRAM_DIFF_STAGE = "first-context-translated-vram-diff"
TRANSLATED_GLYPH_ROUTE_STAGE = "first-context-translated-glyph-route"
DIRECT_RENDERER_CAPTURE_STAGE = "first-context-direct-renderer-capture"
CURSOR_RESET_STAGE = "active-rom-cursor-reset"
FALLBACK_STAGE = "continue"
STAGE_POLICIES = {
    FOCUSED_STAGE: {
        "confirmed_boundary": "active-vram-to-register-rom-window-read",
        "blocked_boundary": "logical-rom-window-read-to-physical-rom-source",
        "selection_reason": "current-register-trace-ready-current-rom-source-missing",
        "next_checkpoint": "map-active-register-rom-source",
    },
    SOURCE_ROLE_STAGE: {
        "confirmed_boundary": "active-vram-to-physical-rom-source",
        "blocked_boundary": "physical-rom-source-to-source-role",
        "selection_reason": "current-rom-source-ready-current-role-missing",
        "next_checkpoint": "classify-active-rom-source-role",
    },
    READ_BLOCK_STAGE: {
        "confirmed_boundary": "active-vram-to-unclassified-rom-read-set",
        "blocked_boundary": "unclassified-rom-read-set-to-access-pattern",
        "selection_reason": (
            "current-unclassified-rom-source-ready-current-read-block-missing"
        ),
        "next_checkpoint": "capture-active-rom-read-block",
    },
    LOOKUP_INDEX_STAGE: {
        "confirmed_boundary": "active-vram-to-scattered-rom-lookup-candidate",
        "blocked_boundary": "lookup-candidate-to-address-index-producer",
        "selection_reason": (
            "current-rom-lookup-candidate-ready-current-index-producer-missing"
        ),
        "next_checkpoint": "trace-active-rom-lookup-index-producer",
    },
    PATH_SCOPE_STAGE: {
        "confirmed_boundary": "active-vram-to-incremental-rom-source-path",
        "blocked_boundary": "incremental-rom-source-path-to-translation-relevance",
        "selection_reason": (
            "current-incremental-source-ready-current-path-scope-missing"
        ),
        "next_checkpoint": "classify-active-rom-path-scope",
    },
    TRANSLATED_VRAM_DIFF_STAGE: {
        "confirmed_boundary": "approved-translation-to-static-test-rom",
        "blocked_boundary": "static-test-rom-to-translated-glyph-vram",
        "selection_reason": (
            "current-rom-path-is-nontext-capture-baseline-test-vram-difference"
        ),
        "next_checkpoint": "capture-translated-test-rom-vram-difference",
    },
    TRANSLATED_GLYPH_ROUTE_STAGE: {
        "confirmed_boundary": "translated-custom-glyph-vram",
        "blocked_boundary": "translated-vram-tile-to-font-assignment-route",
        "selection_reason": (
            "current-translated-vram-ready-current-glyph-slot-route-missing"
        ),
        "next_checkpoint": "join-translated-vram-tiles-to-private-font-assignments",
    },
    DIRECT_RENDERER_CAPTURE_STAGE: {
        "confirmed_boundary": "translated-custom-glyph-observed-font-page",
        "blocked_boundary": "observed-font-page-to-correct-first-dialogue-screen",
        "selection_reason": (
            "single-observed-font-page-ready-direct-renderer-screen-missing"
        ),
        "next_checkpoint": "rebuild-first-dialogue-without-inline-page-select",
    },
    CURSOR_RESET_STAGE: {
        "confirmed_boundary": "active-vram-to-incremental-rom-cursor",
        "blocked_boundary": "incremental-rom-cursor-to-reset-and-stride",
        "selection_reason": (
            "current-incremental-cursor-ready-current-reset-analysis-missing"
        ),
        "next_checkpoint": "capture-cursor-reset-and-stride",
    },
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_register_trace_sha256",
    "selected_stage",
    "confirmed_boundary",
    "blocked_boundary",
    "selection_reason",
    "generated_utc",
    "baseline_script_bytes_unchanged",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"critical path input is not an object: {path}")
    return value


def _trace_ready(root: Path, target_sha256: str) -> tuple[bool, str | None]:
    safe_path = root / REGISTER_TRACE_PATH
    local_path = root / REGISTER_TRACE_LOCAL_PATH
    if not safe_path.is_file() or not local_path.is_file():
        return False, None
    try:
        safe = _load_object(safe_path)
        local = _load_object(local_path)
        validate_active_ram_register_trace(safe)
    except (OSError, ValueError, json.JSONDecodeError):
        return False, None
    selected = local.get("analysis", {}).get("selected")
    if not isinstance(selected, dict):
        return False, None
    reads = selected.get("read_addresses")
    ready = (
        safe.get("target_sha256") == target_sha256
        and safe.get("writer_instance_confirmed") is True
        and safe.get("register_definition_confirmed") is True
        and safe.get("definition_source_class") == "rom-window"
        and isinstance(reads, list)
        and len(reads) == 1
    )
    return ready, sha256_file(safe_path) if ready else None


def _rom_source_current(
    root: Path,
    *,
    target_sha256: str,
    trace_sha256: str,
) -> bool:
    path = root / ROM_SOURCE_PATH
    if not path.is_file():
        return False
    try:
        value = _load_object(path)
        validate_active_register_rom_source(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        value.get("target_sha256") == target_sha256
        and value.get("source_register_trace_sha256") == trace_sha256
        and value.get("rom_source_confirmed") is True
    )


def _source_role_current(
    root: Path,
    *,
    target_sha256: str,
    source_sha256: str,
) -> bool:
    path = root / ROM_SOURCE_ROLE_PATH
    if not path.is_file():
        return False
    try:
        value = _load_object(path)
        validate_active_rom_source_role(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        value.get("target_sha256") == target_sha256
        and value.get("source_active_register_rom_source_sha256") == source_sha256
    )


def _read_block_current(
    root: Path,
    *,
    target_sha256: str,
    role_sha256: str,
    source_sha256: str,
) -> bool:
    path = root / ROM_READ_BLOCK_PATH
    if not path.is_file():
        return False
    try:
        value = _load_object(path)
        validate_active_rom_read_block(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        value.get("target_sha256") == target_sha256
        and value.get("source_active_rom_source_role_sha256") == role_sha256
        and value.get("source_active_register_rom_source_sha256") == source_sha256
    )


def _lookup_index_current(
    root: Path,
    *,
    target_sha256: str,
    read_block_sha256: str,
    role_sha256: str,
    trace_sha256: str,
) -> bool:
    path = root / ROM_LOOKUP_INDEX_PATH
    if not path.is_file():
        return False
    try:
        value = _load_object(path)
        validate_active_rom_lookup_index_producer(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        value.get("target_sha256") == target_sha256
        and value.get("source_active_rom_read_block_sha256") == read_block_sha256
        and value.get("source_active_rom_source_role_sha256") == role_sha256
        and value.get("source_register_trace_sha256") == trace_sha256
    )


def _cursor_reset_current(
    root: Path,
    *,
    target_sha256: str,
    lookup_sha256: str,
    read_block_sha256: str,
    trace_sha256: str,
) -> bool:
    path = root / ROM_CURSOR_RESET_PATH
    if not path.is_file():
        return False
    try:
        value = _load_object(path)
        validate_active_rom_cursor_reset(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        value.get("target_sha256") == target_sha256
        and value.get("source_active_rom_lookup_index_producer_sha256")
        == lookup_sha256
        and value.get("source_active_rom_read_block_sha256")
        == read_block_sha256
        and value.get("source_register_trace_sha256") == trace_sha256
    )


def _path_scope_current(
    root: Path,
    *,
    target_sha256: str,
    source_sha256: str,
    role_sha256: str,
    read_block_sha256: str,
    lookup_sha256: str,
) -> dict[str, object] | None:
    path = root / ROM_PATH_SCOPE_PATH
    if not path.is_file():
        return None
    try:
        value = _load_object(path)
        validate_active_rom_path_scope(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if (
        value.get("target_sha256") != target_sha256
        or value.get("source_active_register_rom_source_sha256")
        != source_sha256
        or value.get("source_active_rom_source_role_sha256") != role_sha256
        or value.get("source_active_rom_read_block_sha256")
        != read_block_sha256
        or value.get("source_active_rom_lookup_index_producer_sha256")
        != lookup_sha256
    ):
        return None
    return value


def _translated_vram_diff_current(
    root: Path,
    *,
    target_sha256: str,
) -> bool:
    path = root / TRANSLATED_VRAM_DIFF_PATH
    build_path = root / TRANSLATION_TEST_BUILD_PATH
    if not path.is_file() or not build_path.is_file():
        return False
    try:
        value = _load_object(path)
        build = _load_object(build_path)
        validate_first_context_translated_vram_diff(value)
        validate_first_context_translation_test_build(build)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        value.get("baseline_target_sha256") == target_sha256
        and build.get("baseline_target_sha256") == target_sha256
        and value.get("test_target_sha256") == build.get("test_target_sha256")
    )


def _translated_glyph_route_current(
    root: Path,
    *,
    target_sha256: str,
) -> bool:
    path = root / TRANSLATED_GLYPH_ROUTE_PATH
    diff_path = root / TRANSLATED_VRAM_DIFF_PATH
    if not path.is_file() or not diff_path.is_file():
        return False
    try:
        value = _load_object(path)
        diff = _load_object(diff_path)
        validate_first_context_translated_glyph_route(value)
        validate_first_context_translated_vram_diff(diff)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        value.get("schema_version") == 3
        and value.get("baseline_target_sha256") == target_sha256
        and value.get("baseline_target_sha256")
        == diff.get("baseline_target_sha256")
        and value.get("test_target_sha256") == diff.get("test_target_sha256")
        and value.get("source_translated_vram_diff_sha256")
        == sha256_file(diff_path)
    )


def _direct_renderer_capture_current(
    root: Path,
    *,
    target_sha256: str,
) -> bool:
    path = root / DIRECT_RENDERER_CAPTURE_PATH
    image_path = root / DIRECT_RENDERER_CAPTURE_IMAGE_PATH
    build_path = root / TRANSLATION_TEST_BUILD_PATH
    request_path = root / RUNTIME_STAGE_REQUEST_PATH
    if (
        not path.is_file()
        or not image_path.is_file()
        or not build_path.is_file()
        or not request_path.is_file()
    ):
        return False
    try:
        value = _load_object(path)
        build = _load_object(build_path)
        request = _load_object(request_path)
        validate_first_context_direct_renderer_capture(value)
        validate_first_context_translation_test_build(build)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        set(request) == {"request_id", "stage"}
        and request.get("stage") == "first-context-direct-renderer-capture"
        and isinstance(request.get("request_id"), str)
        and re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", request["request_id"])
        is not None
        and value.get("schema_version") == 3
        and value.get("runtime_stage_request_id") == request["request_id"]
        and value.get("renderer_route") == "proven-visible-page"
        and value.get("baseline_target_sha256") == target_sha256
        and build.get("baseline_target_sha256") == target_sha256
        and value.get("test_target_sha256") == build.get("test_target_sha256")
        and value.get("first_context_translation_test_build_sha256")
        == sha256_file(build_path)
        and value.get("capture_png_sha256") == sha256_file(image_path)
    )


def _build_selection(
    *,
    target_sha256: str,
    trace_sha256: str,
    stage: str,
) -> dict[str, object]:
    policy = STAGE_POLICIES[stage]
    generated_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": "one-unresolved-boundary-selected",
        "target_sha256": target_sha256,
        "source_register_trace_sha256": trace_sha256,
        "selected_stage": stage,
        "confirmed_boundary": policy["confirmed_boundary"],
        "blocked_boundary": policy["blocked_boundary"],
        "selection_reason": policy["selection_reason"],
        "generated_utc": generated_utc,
        "baseline_script_bytes_unchanged": True,
        "translation_build_eligible": False,
        "next_checkpoint": policy["next_checkpoint"],
    }
    validate_critical_path(value)
    return value


def select_critical_path(root: Path, rom_path: Path) -> dict[str, object] | None:
    """Return a focused stage only when all of its prerequisites are current."""

    if not rom_path.is_file():
        return None
    target_sha256 = sha256_file(rom_path)
    trace_ready, trace_sha256 = _trace_ready(root, target_sha256)
    if not trace_ready or trace_sha256 is None:
        return None
    source_current = _rom_source_current(
        root,
        target_sha256=target_sha256,
        trace_sha256=trace_sha256,
    )
    if not source_current:
        return _build_selection(
            target_sha256=target_sha256,
            trace_sha256=trace_sha256,
            stage=FOCUSED_STAGE,
        )
    source_sha256 = sha256_file(root / ROM_SOURCE_PATH)
    if not _source_role_current(
        root,
        target_sha256=target_sha256,
        source_sha256=source_sha256,
    ):
        return _build_selection(
            target_sha256=target_sha256,
            trace_sha256=trace_sha256,
            stage=SOURCE_ROLE_STAGE,
        )
    role_path = root / ROM_SOURCE_ROLE_PATH
    role = _load_object(role_path)
    validate_active_rom_source_role(role)
    if role.get("source_role") == "unclassified-data":
        role_sha256 = sha256_file(role_path)
        if not _read_block_current(
            root,
            target_sha256=target_sha256,
            role_sha256=role_sha256,
            source_sha256=source_sha256,
        ):
            return _build_selection(
                target_sha256=target_sha256,
                trace_sha256=trace_sha256,
                stage=READ_BLOCK_STAGE,
            )
        read_block_path = root / ROM_READ_BLOCK_PATH
        read_block = _load_object(read_block_path)
        validate_active_rom_read_block(read_block)
        if read_block.get("access_pattern") in {
            "fixed-stride-lookup-candidate", "scattered-lookup-candidate"
        }:
            read_block_sha256 = sha256_file(read_block_path)
            if not _lookup_index_current(
                root,
                target_sha256=target_sha256,
                read_block_sha256=read_block_sha256,
                role_sha256=role_sha256,
                trace_sha256=trace_sha256,
            ):
                return _build_selection(
                    target_sha256=target_sha256,
                    trace_sha256=trace_sha256,
                    stage=LOOKUP_INDEX_STAGE,
                )
            lookup_path = root / ROM_LOOKUP_INDEX_PATH
            lookup = _load_object(lookup_path)
            validate_active_rom_lookup_index_producer(lookup)
            if lookup.get("producer_class") == "incremental-cursor-candidate":
                lookup_sha256 = sha256_file(lookup_path)
                path_scope = _path_scope_current(
                    root,
                    target_sha256=target_sha256,
                    source_sha256=source_sha256,
                    role_sha256=role_sha256,
                    read_block_sha256=read_block_sha256,
                    lookup_sha256=lookup_sha256,
                )
                if path_scope is None:
                    return _build_selection(
                        target_sha256=target_sha256,
                        trace_sha256=trace_sha256,
                        stage=PATH_SCOPE_STAGE,
                    )
                if path_scope.get("current_path_relevant_to_translation_fix") is False:
                    if not _translated_vram_diff_current(
                        root,
                        target_sha256=target_sha256,
                    ):
                        return _build_selection(
                            target_sha256=target_sha256,
                            trace_sha256=trace_sha256,
                            stage=TRANSLATED_VRAM_DIFF_STAGE,
                        )
                    if not _translated_glyph_route_current(
                        root,
                        target_sha256=target_sha256,
                    ):
                        return _build_selection(
                            target_sha256=target_sha256,
                            trace_sha256=trace_sha256,
                            stage=TRANSLATED_GLYPH_ROUTE_STAGE,
                        )
                    glyph_route_path = root / TRANSLATED_GLYPH_ROUTE_PATH
                    glyph_route = _load_object(glyph_route_path)
                    validate_first_context_translated_glyph_route(glyph_route)
                    if (
                        (
                            glyph_route.get("single_font_page_candidate_confirmed")
                            is True
                            or glyph_route.get(
                                "best_observed_page_candidate_confirmed"
                            )
                            is True
                        )
                        and not _direct_renderer_capture_current(
                            root,
                            target_sha256=target_sha256,
                        )
                    ):
                        return _build_selection(
                            target_sha256=target_sha256,
                            trace_sha256=trace_sha256,
                            stage=DIRECT_RENDERER_CAPTURE_STAGE,
                        )
                    return None
                if not _cursor_reset_current(
                    root,
                    target_sha256=target_sha256,
                    lookup_sha256=lookup_sha256,
                    read_block_sha256=read_block_sha256,
                    trace_sha256=trace_sha256,
                ):
                    return _build_selection(
                        target_sha256=target_sha256,
                        trace_sha256=trace_sha256,
                        stage=CURSOR_RESET_STAGE,
                    )
    return None


def validate_critical_path(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("critical path fields do not match")
    stage = value.get("selected_stage")
    policy = STAGE_POLICIES.get(str(stage))
    if (
        value.get("artifact_kind") != ARTIFACT_KIND
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("status") != "one-unresolved-boundary-selected"
        or not _is_sha256(value.get("target_sha256"))
        or not _is_sha256(value.get("source_register_trace_sha256"))
        or policy is None
        or value.get("confirmed_boundary") != policy["confirmed_boundary"]
        or value.get("blocked_boundary") != policy["blocked_boundary"]
        or value.get("selection_reason") != policy["selection_reason"]
        or value.get("baseline_script_bytes_unchanged") is not True
        or value.get("translation_build_eligible") is not False
        or value.get("next_checkpoint") != policy["next_checkpoint"]
    ):
        raise ValueError("critical path policy is invalid")
    try:
        generated = datetime.fromisoformat(str(value["generated_utc"]).replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("critical path timestamp is invalid") from error
    if generated.tzinfo is None:
        raise ValueError("critical path timestamp lacks timezone")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--print-next-stage", action="store_true")
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    selected = select_critical_path(root, rom_path)
    stage = FALLBACK_STAGE
    if selected is not None:
        output = root / PUBLISH_RELATIVE_PATH
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(selected, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        stage = str(selected["selected_stage"])
    elif not args.if_ready and not rom_path.is_file():
        raise SystemExit("critical path target ROM is missing")
    if args.print_next_stage:
        print(stage)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
