#!/usr/bin/env python3
"""Capture the first dialogue after rebuilding it on the observed font page."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import argparse

try:
    from .patch_io import sha256_file
    from .v5_1_png_pixels import decode_png_rgba
    from .v5_1_first_context_translated_vram_diff import _capture_anchor_vram
    from .v5_1_first_context_translation_encoding import (
        FONT_PAGE_COUNT,
        LOCAL_REPORT_PATH as LOCAL_ENCODING_PATH,
        direct_renderer_font_tile_offset,
    )
    from .v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TEST_BUILD_PATH,
        validate_first_context_translation_test_build,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_png_pixels import decode_png_rgba
    from v5_1_first_context_translated_vram_diff import _capture_anchor_vram
    from v5_1_first_context_translation_encoding import (
        FONT_PAGE_COUNT,
        LOCAL_REPORT_PATH as LOCAL_ENCODING_PATH,
        direct_renderer_font_tile_offset,
    )
    from v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TEST_BUILD_PATH,
        validate_first_context_translation_test_build,
    )


ARTIFACT_KIND = "sanitized-v5-1-first-context-direct-renderer-capture"
SCHEMA_VERSION = 6
NAME_TABLE_BASE = 0x3800
NAME_TABLE_WIDTH = 32
# Gearsystem returns the cropped 160x144 Game Gear viewport.  Its upper-left
# pixel corresponds to tile (6, 3) in the 256x224 VDP name table.  The first
# dialogue glyph is at viewport tile (1, 12), not name-table tile (1, 12).
GAME_GEAR_VIEWPORT_TILE_COLUMN = 6
GAME_GEAR_VIEWPORT_TILE_ROW = 3
FIRST_DIALOGUE_VIEWPORT_TEXT_COLUMN = 1
FIRST_DIALOGUE_VIEWPORT_TEXT_ROW = 12
FIRST_DIALOGUE_TEXT_COLUMN = (
    GAME_GEAR_VIEWPORT_TILE_COLUMN + FIRST_DIALOGUE_VIEWPORT_TEXT_COLUMN
)
FIRST_DIALOGUE_TEXT_ROW = (
    GAME_GEAR_VIEWPORT_TILE_ROW + FIRST_DIALOGUE_VIEWPORT_TEXT_ROW
)
VRAM_TILE_BYTES = 32
RUNTIME_STAGE_REQUEST_PATH = Path(
    "analysis/control/s25u_runtime_stage_request.json"
)
TEST_ROM_PATH = Path(
    "build/Final_Conflict_Korean_first_context_translation_test.gg"
)
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_direct_renderer_capture.json"
)
PUBLISH_IMAGE_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_direct_renderer_capture.png"
)
LOCAL_EVIDENCE_PATH = Path(
    "evidence/local/v5_1_first_context_direct_renderer_capture.png"
)
LOCAL_SLOT_ALIGNMENT_PATH = Path(
    "reports/local/v5_1_first_context_direct_renderer_slot_alignment.json"
)
FAILURE_STAGE_PATH = Path(
    "reports/local/v5_1_first_context_direct_renderer_capture_failure_stage.txt"
)
TOP_LEVEL_KEYS_V2 = {
    "artifact_kind",
    "schema_version",
    "status",
    "baseline_target_sha256",
    "test_target_sha256",
    "first_context_translation_test_build_sha256",
    "local_encoding_sha256",
    "capture_png_sha256",
    "captured_utc",
    "runtime_entry",
    "renderer_route",
    "direct_renderer_first_row_confirmed",
    "cold_boot",
    "human_visual_review_required",
    "translation_build_eligible",
    "next_checkpoint",
}
TOP_LEVEL_KEYS = TOP_LEVEL_KEYS_V2 | {"runtime_stage_request_id"}
TOP_LEVEL_KEYS_V4 = TOP_LEVEL_KEYS | {"slot_alignment"}
RUNTIME_ENTRY_KEYS = {"selector", "ordinal"}
SLOT_ALIGNMENT_KEYS_V4 = {
    "sample_count",
    "unique_desired_vram_match_count",
    "constant_loader_base",
    "constant_write_slot_shift",
    "mapping_confirmed",
}
SLOT_ALIGNMENT_KEYS_V5 = SLOT_ALIGNMENT_KEYS_V4 | {
    "rendered_assignment_match_count",
    "observed_assignment_page",
}
SLOT_ALIGNMENT_KEYS = SLOT_ALIGNMENT_KEYS_V5 | {
    "route_evidence_count",
    "common_route_candidate_count",
    "sample_route_candidates",
}


def _screenshot_dialogue_tile_candidates(
    vram: bytes,
    screenshot_png: bytes,
    visible_count: int,
) -> list[list[int]]:
    """Match each visible 8x8 screenshot cell to its resident VRAM tile."""

    image = decode_png_rgba(screenshot_png)
    left = FIRST_DIALOGUE_VIEWPORT_TEXT_COLUMN * 8
    top = FIRST_DIALOGUE_VIEWPORT_TEXT_ROW * 8
    if (
        image.width != 160
        or image.height != 144
        or left + visible_count * 8 > image.width
        or top + 8 > image.height
    ):
        raise ValueError("direct renderer screenshot viewport is invalid")
    def normalize(values: list[object]) -> tuple[int, ...]:
        labels: dict[object, int] = {}
        result = []
        for value in values:
            if value not in labels:
                labels[value] = len(labels)
            result.append(labels[value])
        return tuple(result)

    def tile_pixels(tile: bytes) -> list[int]:
        result = []
        for row in range(8):
            planes = tile[row * 4:row * 4 + 4]
            for column in range(8):
                bit = 7 - column
                result.append(sum(((plane >> bit) & 1) << index for index, plane in enumerate(planes)))
        return result

    tiles_by_pattern: dict[tuple[int, ...], set[int]] = {}
    for tile_index in range(len(vram) // VRAM_TILE_BYTES):
        start = tile_index * VRAM_TILE_BYTES
        pixels = tile_pixels(vram[start:start + VRAM_TILE_BYTES])
        rows = [pixels[row * 8:row * 8 + 8] for row in range(8)]
        variants = (
            rows,
            [list(reversed(row)) for row in rows],
            list(reversed(rows)),
            [list(reversed(row)) for row in reversed(rows)],
        )
        for variant in variants:
            pattern = normalize([value for row in variant for value in row])
            tiles_by_pattern.setdefault(pattern, set()).add(tile_index)
    result = []
    for glyph_index in range(visible_count):
        glyph_left = left + glyph_index * 8
        screenshot_pixels = []
        for row in range(8):
            for column in range(8):
                pixel = (top + row) * image.width + glyph_left + column
                offset = pixel * 4
                screenshot_pixels.append(image.rgba[offset:offset + 4])
        pattern = normalize(screenshot_pixels)
        result.append(sorted(tiles_by_pattern.get(pattern, set())))
    return result


def analyze_direct_renderer_slot_alignment(
    vram: bytes,
    encoding: dict[str, object],
    rom: bytes | None = None,
    screenshot_png: bytes | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    """Join rendered name-table slots to the intended first-row glyph tiles."""

    rows = encoding.get("rows")
    assignments = encoding.get("character_assignments")
    if (
        len(vram) < 0x4000
        or not isinstance(rows, list)
        or not rows
        or not isinstance(rows[0], dict)
        or rows[0].get("direct_renderer_proof") is not True
        or not isinstance(assignments, list)
    ):
        raise ValueError("direct renderer slot alignment input is invalid")
    visible_count = rows[0].get("visible_symbol_count")
    if not isinstance(visible_count, int) or not 1 <= visible_count <= 18:
        raise ValueError("direct renderer visible glyph count is invalid")
    first_row = [
        assignment
        for assignment in assignments
        if isinstance(assignment, dict)
        and assignment.get("row_index") == 1
        and assignment.get("visual_kind") == "approved-target-character"
    ]
    if len(first_row) != visible_count:
        raise ValueError("direct renderer first-row assignments are incomplete")
    screenshot_tile_candidates = (
        _screenshot_dialogue_tile_candidates(vram, screenshot_png, visible_count)
        if isinstance(screenshot_png, bytes)
        else [[] for _ in range(visible_count)]
    )

    hashes: dict[str, list[int]] = {}
    for tile_index in range(len(vram) // VRAM_TILE_BYTES):
        start = tile_index * VRAM_TILE_BYTES
        digest = sha256(vram[start:start + VRAM_TILE_BYTES]).hexdigest()
        hashes.setdefault(digest, []).append(tile_index)

    assignments_by_hash: dict[str, list[dict[str, int]]] = {}
    for assignment in assignments:
        if not isinstance(assignment, dict):
            continue
        tile_sha256 = assignment.get("tile_sha256")
        page = assignment.get("page")
        encoded_symbol = assignment.get("symbol")
        physical_symbol = assignment.get("font_symbol", encoded_symbol)
        if (
            not isinstance(tile_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", tile_sha256) is None
            or not isinstance(page, int)
            or isinstance(page, bool)
            or not isinstance(physical_symbol, int)
            or isinstance(physical_symbol, bool)
        ):
            continue
        assignments_by_hash.setdefault(tile_sha256, []).append(
            {
                "page": page,
                "physical_symbol": physical_symbol,
                "row_index": int(assignment.get("row_index", 0)),
            }
        )

    # (font page, VRAM loader base, physical write slot - decoded symbol)
    common_routes: set[tuple[int, int, int]] | None = None
    route_evidence_count = 0
    unique_matches = 0
    rendered_assignment_matches = 0
    samples = []
    for index, assignment in enumerate(first_row):
        symbol = assignment.get("symbol")
        tile_sha256 = assignment.get("tile_sha256")
        if (
            not isinstance(symbol, int)
            or isinstance(symbol, bool)
            or not isinstance(tile_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", tile_sha256) is None
        ):
            raise ValueError("direct renderer assignment identity is invalid")
        name_offset = NAME_TABLE_BASE + 2 * (
            FIRST_DIALOGUE_TEXT_ROW * NAME_TABLE_WIDTH
            + FIRST_DIALOGUE_TEXT_COLUMN
            + index
        )
        name_word = int.from_bytes(vram[name_offset:name_offset + 2], "little")
        rendered_tile = name_word & 0x01FF
        desired_tiles = hashes.get(tile_sha256, [])
        unique_matches += int(len(desired_tiles) == 1)
        screen_tiles = screenshot_tile_candidates[index]
        route_tiles = screen_tiles or [rendered_tile]
        rendered_assignments = []
        routes: set[tuple[int, int, int]] = set()
        rom_route_candidates: list[tuple[int, int, int]] = []
        route_tile_digests = []
        for route_tile in route_tiles:
            route_start = route_tile * VRAM_TILE_BYTES
            route_digest = sha256(
                vram[route_start:route_start + VRAM_TILE_BYTES]
            ).hexdigest()
            route_tile_digests.append(route_digest)
            tile_assignments = assignments_by_hash.get(route_digest, [])
            rendered_assignments.extend(tile_assignments)
            routes.update(
                (
                    candidate["page"],
                    route_tile - candidate["physical_symbol"],
                    candidate["physical_symbol"] - symbol,
                )
                for candidate in tile_assignments
            )
        # A garbled screen can legitimately contain glyphs that are not part of
        # the translated assignment set.  Compare the rendered tile against the
        # same decoded symbol on every complete ROM font page.  A page/base pair
        # that survives several different symbols identifies the page actually
        # loaded by the renderer without exposing ROM bytes or glyph identities.
        if isinstance(rom, bytes):
            for route_tile, route_digest in zip(route_tiles, route_tile_digests):
                for page in range(FONT_PAGE_COUNT):
                    font_offset = direct_renderer_font_tile_offset(page, symbol)
                    font_end = font_offset + VRAM_TILE_BYTES
                    if font_end > len(rom):
                        continue
                    if sha256(rom[font_offset:font_end]).hexdigest() == route_digest:
                        rom_route_candidates.append((page, route_tile - symbol, 0))
            routes.update(rom_route_candidates)
        if routes:
            rendered_assignment_matches += 1
        else:
            page = assignment.get("page")
            physical_symbol = assignment.get("font_symbol", symbol)
            if (
                isinstance(page, int)
                and not isinstance(page, bool)
                and isinstance(physical_symbol, int)
                and not isinstance(physical_symbol, bool)
            ):
                routes = {
                    (
                        page,
                        tile - physical_symbol,
                        physical_symbol - symbol + rendered_tile - tile,
                    )
                    for tile in desired_tiles
                }
        rendered_start = rendered_tile * VRAM_TILE_BYTES
        rendered_digest = sha256(
            vram[rendered_start:rendered_start + VRAM_TILE_BYTES]
        ).hexdigest()
        # Punctuation and repeated blank tiles are not always unique in VRAM.
        # Do not let an unmatched sample erase a route established by several
        # independent Hangul glyphs; intersect only samples that actually
        # produce a page/base/shift candidate.
        if routes:
            route_evidence_count += 1
            common_routes = (
                routes if common_routes is None else common_routes & routes
            )
        samples.append(
            {
                "index": index,
                "encoded_symbol": symbol,
                "rendered_tile": rendered_tile,
                "rendered_tile_sha256": rendered_digest,
                "screenshot_tile_candidates": screen_tiles,
                "desired_tiles": desired_tiles,
                "rendered_assignments": rendered_assignments,
                "rom_route_candidates": [
                    list(route) for route in sorted(rom_route_candidates)
                ],
                "route_candidates": [list(route) for route in sorted(routes)],
            }
        )
    routes = common_routes or set()
    minimum_route_evidence = min(3, visible_count)
    confirmed = (
        route_evidence_count >= minimum_route_evidence and len(routes) == 1
    )
    page, loader_base, write_slot_shift = (
        next(iter(routes)) if confirmed else (None, None, None)
    )
    safe = {
        "sample_count": visible_count,
        "unique_desired_vram_match_count": unique_matches,
        "rendered_assignment_match_count": rendered_assignment_matches,
        "observed_assignment_page": page,
        # A partial constant is not actionable and the safe schema deliberately
        # rejects it.  Publish both values only when the same base/shift pair
        # explains every sampled glyph; otherwise keep the safe receipt
        # explicitly unresolved and retain candidates in the local report.
        "constant_loader_base": loader_base,
        "constant_write_slot_shift": write_slot_shift,
        "mapping_confirmed": confirmed,
        "route_evidence_count": route_evidence_count,
        "common_route_candidate_count": len(routes),
        "sample_route_candidates": [
            {
                "index": int(sample["index"]),
                "routes": sample["route_candidates"],
            }
            for sample in samples
        ],
    }
    local = {
        "name_table_base": NAME_TABLE_BASE,
        "text_column": FIRST_DIALOGUE_TEXT_COLUMN,
        "text_row": FIRST_DIALOGUE_TEXT_ROW,
        "samples": samples,
        "route_evidence_count": route_evidence_count,
        "minimum_route_evidence": minimum_route_evidence,
    }
    return safe, local


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_first_context_direct_renderer_capture(
    value: dict[str, object],
) -> None:
    schema_version = value.get("schema_version")
    if not (
        (schema_version == 2 and set(value) == TOP_LEVEL_KEYS_V2)
        or (schema_version == 3 and set(value) == TOP_LEVEL_KEYS)
        or (
            schema_version in {4, 5, SCHEMA_VERSION}
            and set(value) == TOP_LEVEL_KEYS_V4
        )
    ):
        raise ValueError("direct renderer capture fields do not match")
    runtime_entry = value.get("runtime_entry")
    if (
        value.get("artifact_kind") != ARTIFACT_KIND
        or schema_version not in {2, 3, 4, 5, SCHEMA_VERSION}
        or value.get("status") != "direct-renderer-first-screen-captured"
        or value.get("renderer_route")
        not in {"direct-observed-page", "proven-visible-page"}
        or not all(
            _is_sha256(value.get(key))
            for key in (
                "baseline_target_sha256",
                "test_target_sha256",
                "first_context_translation_test_build_sha256",
                "local_encoding_sha256",
                "capture_png_sha256",
            )
        )
        or not isinstance(runtime_entry, dict)
        or set(runtime_entry) != RUNTIME_ENTRY_KEYS
        or any(
            not isinstance(item, int) or isinstance(item, bool) or item < 0
            for item in runtime_entry.values()
        )
        or value.get("direct_renderer_first_row_confirmed") is not True
        or value.get("cold_boot") is not True
        or value.get("human_visual_review_required") is not True
        or value.get("translation_build_eligible") is not False
    ):
        raise ValueError("direct renderer capture is inconsistent")
    if schema_version in {3, SCHEMA_VERSION} and (
        not isinstance(value.get("runtime_stage_request_id"), str)
        or re.fullmatch(
            r"[a-z0-9][a-z0-9._-]{0,63}",
            value["runtime_stage_request_id"],
        )
        is None
    ):
        raise ValueError("direct renderer capture request identity is invalid")
    if schema_version < 4:
        if (
            value.get("next_checkpoint")
            != "human-verify-first-direct-renderer-dialogue-screen"
        ):
            raise ValueError("direct renderer capture checkpoint is invalid")
        return
    alignment = value.get("slot_alignment")
    expected_alignment_keys = (
        SLOT_ALIGNMENT_KEYS_V4
        if schema_version == 4
        else SLOT_ALIGNMENT_KEYS_V5
        if schema_version == 5
        else SLOT_ALIGNMENT_KEYS
    )
    if not isinstance(alignment, dict) or set(alignment) != expected_alignment_keys:
        raise ValueError("direct renderer slot alignment fields do not match")
    confirmed = alignment.get("mapping_confirmed")
    if (
        not isinstance(alignment.get("sample_count"), int)
        or not 1 <= alignment["sample_count"] <= 18
        or not isinstance(alignment.get("unique_desired_vram_match_count"), int)
        or not 0 <= alignment["unique_desired_vram_match_count"] <= alignment["sample_count"]
        or not isinstance(confirmed, bool)
        or (
            schema_version == SCHEMA_VERSION
            and (
                not isinstance(alignment.get("rendered_assignment_match_count"), int)
                or not 0
                <= alignment["rendered_assignment_match_count"]
                <= alignment["sample_count"]
                or not isinstance(alignment.get("route_evidence_count"), int)
                or not 0
                <= alignment["route_evidence_count"]
                <= alignment["sample_count"]
                or not isinstance(
                    alignment.get("common_route_candidate_count"), int
                )
                or not 0 <= alignment["common_route_candidate_count"] <= 512
                or not isinstance(alignment.get("sample_route_candidates"), list)
                or len(alignment["sample_route_candidates"])
                != alignment["sample_count"]
            )
        )
        or (
            confirmed
            and (
                not isinstance(alignment.get("constant_loader_base"), int)
                or not isinstance(alignment.get("constant_write_slot_shift"), int)
                or (
                    schema_version == SCHEMA_VERSION
                    and not isinstance(alignment.get("observed_assignment_page"), int)
                )
            )
        )
        or (
            not confirmed
            and (
                alignment.get("constant_loader_base") is not None
                or alignment.get("constant_write_slot_shift") is not None
                or (
                    schema_version == SCHEMA_VERSION
                    and alignment.get("observed_assignment_page") is not None
                )
            )
        )
        or value.get("next_checkpoint")
        != (
            "rebuild-first-dialogue-with-observed-slot-shift"
            if confirmed
            else "trace-direct-renderer-slot-alignment"
        )
    ):
        raise ValueError("direct renderer slot alignment is inconsistent")
    if schema_version == SCHEMA_VERSION:
        for expected_index, sample in enumerate(
            alignment["sample_route_candidates"]
        ):
            routes = sample.get("routes") if isinstance(sample, dict) else None
            if (
                not isinstance(sample, dict)
                or set(sample) != {"index", "routes"}
                or sample.get("index") != expected_index
                or not isinstance(routes, list)
                or len(routes) > 512
                or any(
                    not isinstance(route, list)
                    or len(route) != 3
                    or any(
                        not isinstance(item, int) or isinstance(item, bool)
                        for item in route
                    )
                    for route in routes
                )
            ):
                raise ValueError("direct renderer slot route candidates are invalid")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proven-visible-page", action="store_true")
    args = parser.parse_args()
    paths = {
        "rom": root / TEST_ROM_PATH,
        "build": root / TEST_BUILD_PATH,
        "encoding": root / LOCAL_ENCODING_PATH,
        "request": root / RUNTIME_STAGE_REQUEST_PATH,
    }
    if not all(path.is_file() for path in paths.values()):
        raise SystemExit("direct renderer capture input is missing")
    build = json.loads(paths["build"].read_text(encoding="utf-8"))
    encoding = json.loads(paths["encoding"].read_text(encoding="utf-8"))
    request = json.loads(paths["request"].read_text(encoding="utf-8"))
    if (
        not isinstance(build, dict)
        or not isinstance(encoding, dict)
        or not isinstance(request, dict)
        or set(request) != {"request_id", "stage"}
        or request.get("stage") != "first-context-direct-renderer-capture"
        or not isinstance(request.get("request_id"), str)
        or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", request["request_id"])
        is None
    ):
        raise ValueError("direct renderer capture input is invalid")
    validate_first_context_translation_test_build(build)
    rows = encoding.get("rows")
    if (
        sha256_file(paths["rom"]) != build["test_target_sha256"]
        or encoding.get("target_sha256") != build["baseline_target_sha256"]
        or not isinstance(rows, list)
        or not rows
        or not isinstance(rows[0], dict)
        or (
            rows[0].get("proven_visible_page_route") is not True
            if args.proven_visible_page
            else rows[0].get("direct_renderer_proof") is not True
        )
    ):
        raise ValueError("direct renderer capture identity disagrees")

    local_image = root / LOCAL_EVIDENCE_PATH
    failure_path = root / FAILURE_STAGE_PATH
    capture = _capture_anchor_vram(
        rom_path=paths["rom"],
        evidence_path=local_image,
        failure_stage_path=failure_path,
        phase_prefix="first-context-direct-renderer",
    )
    vram = capture.pop("vram")
    if not isinstance(vram, bytes):
        raise ValueError("direct renderer VRAM capture is invalid")
    slot_alignment, local_slot_alignment = (
        analyze_direct_renderer_slot_alignment(
            vram,
            encoding,
            paths["rom"].read_bytes(),
            local_image.read_bytes(),
        )
    )
    local_slot_path = root / LOCAL_SLOT_ALIGNMENT_PATH
    local_slot_path.parent.mkdir(parents=True, exist_ok=True)
    local_slot_path.write_text(
        json.dumps(local_slot_alignment, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    publish_image = root / PUBLISH_IMAGE_RELATIVE_PATH
    publish_image.parent.mkdir(parents=True, exist_ok=True)
    publish_image.write_bytes(local_image.read_bytes())
    if not publish_image.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("direct renderer capture image is not PNG")
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": "direct-renderer-first-screen-captured",
        "baseline_target_sha256": build["baseline_target_sha256"],
        "test_target_sha256": build["test_target_sha256"],
        "first_context_translation_test_build_sha256": sha256_file(
            paths["build"]
        ),
        "local_encoding_sha256": sha256_file(paths["encoding"]),
        "capture_png_sha256": sha256_file(publish_image),
        "captured_utc": datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        "runtime_entry": {
            "selector": int(capture["selector"]),
            "ordinal": int(capture["ordinal"]),
        },
        "renderer_route": (
            "proven-visible-page"
            if args.proven_visible_page
            else "direct-observed-page"
        ),
        "runtime_stage_request_id": request["request_id"],
        "direct_renderer_first_row_confirmed": True,
        "slot_alignment": slot_alignment,
        "cold_boot": True,
        "human_visual_review_required": True,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "rebuild-first-dialogue-with-observed-slot-shift"
            if slot_alignment["mapping_confirmed"] is True
            else "trace-direct-renderer-slot-alignment"
        ),
    }
    validate_first_context_direct_renderer_capture(safe)
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    failure_path.unlink(missing_ok=True)
    print(f"SFKR direct renderer first screen: {publish_image}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
