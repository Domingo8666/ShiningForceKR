from __future__ import annotations

import copy
from hashlib import sha256
import unittest

from tools.v5_1_first_context_direct_renderer_capture import (
    FIRST_DIALOGUE_TEXT_COLUMN,
    FIRST_DIALOGUE_TEXT_ROW,
    FIRST_DIALOGUE_VIEWPORT_TEXT_COLUMN,
    FIRST_DIALOGUE_VIEWPORT_TEXT_ROW,
    GAME_GEAR_VIEWPORT_TILE_COLUMN,
    GAME_GEAR_VIEWPORT_TILE_ROW,
    NAME_TABLE_BASE,
    NAME_TABLE_WIDTH,
    analyze_direct_renderer_slot_alignment,
    validate_first_context_direct_renderer_capture,
    validate_first_context_direct_renderer_screenshot,
)
from tools.v5_1_first_context_translation_encoding import (
    direct_renderer_font_tile_offset,
)
from tools.v5_1_first_context_translation_capacity import (
    tile_bytes_from_ink_mask,
)
from tools.v5_1_png_pixels import (
    DEFAULT_TEXT_INK_RGBA,
    PixelImage,
)
from unittest.mock import patch


class FirstContextDirectRendererCaptureTests(unittest.TestCase):
    def test_accepts_split_screenshot_receipt(self) -> None:
        value = {
            "artifact_kind": (
                "sanitized-v5-1-first-context-direct-renderer-screenshot"
            ),
            "schema_version": 1,
            "status": "direct-renderer-screenshot-captured",
            "baseline_target_sha256": "a" * 64,
            "test_target_sha256": "b" * 64,
            "first_context_translation_test_build_sha256": "c" * 64,
            "local_encoding_sha256": "d" * 64,
            "capture_png_sha256": "e" * 64,
            "captured_utc": "2026-08-03T00:00:00Z",
            "runtime_entry": {"selector": 2, "ordinal": 147},
            "renderer_route": "direct-observed-page",
            "runtime_stage_request_id": "direct-slot-58-screenshot",
            "cold_boot": True,
            "human_visual_review_required": True,
            "next_checkpoint": "capture-direct-renderer-vram-in-fresh-session",
        }
        validate_first_context_direct_renderer_screenshot(value)
        invalid = copy.deepcopy(value)
        invalid["runtime_stage_request_id"] = "direct-slot-58-vram"
        with self.assertRaises(ValueError):
            validate_first_context_direct_renderer_screenshot(invalid)

    def test_dialogue_coordinates_include_game_gear_viewport_crop(self) -> None:
        self.assertEqual(GAME_GEAR_VIEWPORT_TILE_COLUMN, 6)
        self.assertEqual(GAME_GEAR_VIEWPORT_TILE_ROW, 3)
        self.assertEqual(FIRST_DIALOGUE_VIEWPORT_TEXT_COLUMN, 1)
        self.assertEqual(FIRST_DIALOGUE_VIEWPORT_TEXT_ROW, 12)
        self.assertEqual(FIRST_DIALOGUE_TEXT_COLUMN, 7)
        self.assertEqual(FIRST_DIALOGUE_TEXT_ROW, 15)

    def test_resolves_constant_direct_renderer_write_slot_shift(self) -> None:
        vram = bytearray(0x4000)
        tiles = [bytes([1]) * 32, bytes([2]) * 32]
        desired_indexes = [0x110, 0x111]
        rendered_indexes = [0x118, 0x119]
        for tile, tile_index in zip(tiles, desired_indexes):
            start = tile_index * 32
            vram[start:start + 32] = tile
        for index, tile_index in enumerate(rendered_indexes):
            offset = NAME_TABLE_BASE + 2 * (
                FIRST_DIALOGUE_TEXT_ROW * NAME_TABLE_WIDTH
                + FIRST_DIALOGUE_TEXT_COLUMN
                + index
            )
            vram[offset:offset + 2] = tile_index.to_bytes(2, "little")
        encoding = {
            "rows": [
                {
                    "direct_renderer_proof": True,
                    "visible_symbol_count": 2,
                }
            ],
            "character_assignments": [
                {
                    "row_index": 1,
                    "visual_kind": "approved-target-character",
                    "page": 21,
                    "symbol": symbol,
                    "tile_sha256": sha256(tile).hexdigest(),
                }
                for symbol, tile in zip((0x10, 0x11), tiles)
            ],
        }
        safe, local = analyze_direct_renderer_slot_alignment(
            bytes(vram), encoding
        )
        self.assertEqual(safe["sample_count"], 2)
        self.assertEqual(safe["unique_desired_vram_match_count"], 2)
        self.assertEqual(safe["constant_loader_base"], 0x100)
        self.assertEqual(safe["constant_write_slot_shift"], 8)
        self.assertEqual(safe["observed_assignment_page"], 21)
        self.assertTrue(safe["mapping_confirmed"])
        self.assertEqual(len(local["samples"]), 2)

    def test_resolves_loaded_rom_page_when_rendered_glyphs_are_unassigned(self) -> None:
        vram = bytearray(0x4000)
        symbols = (0x10, 0x11, 0x12)
        physical_symbols = tuple(symbol + 3 for symbol in symbols)
        page = 7
        loader_base = 0x100
        tiles = [bytes([0x31 + index]) * 32 for index in range(len(symbols))]
        rom_size = direct_renderer_font_tile_offset(page, physical_symbols[-1]) + 32
        rom = bytearray(rom_size)
        for index, (symbol, physical_symbol, tile) in enumerate(
            zip(symbols, physical_symbols, tiles)
        ):
            rendered_tile = loader_base + physical_symbol
            vram_start = rendered_tile * 32
            vram[vram_start:vram_start + 32] = tile
            font_start = direct_renderer_font_tile_offset(page, physical_symbol)
            rom[font_start:font_start + 32] = tile
            name_offset = NAME_TABLE_BASE + 2 * (
                FIRST_DIALOGUE_TEXT_ROW * NAME_TABLE_WIDTH
                + FIRST_DIALOGUE_TEXT_COLUMN
                + index
            )
            vram[name_offset:name_offset + 2] = rendered_tile.to_bytes(2, "little")
        encoding = {
            "rows": [{"direct_renderer_proof": True, "visible_symbol_count": 3}],
            "character_assignments": [
                {
                    "row_index": 1,
                    "visual_kind": "approved-target-character",
                    "page": 21,
                    "symbol": symbol,
                    "tile_sha256": "f" * 64,
                }
                for symbol in symbols
            ],
        }
        safe, local = analyze_direct_renderer_slot_alignment(
            bytes(vram), encoding, bytes(rom)
        )
        self.assertTrue(safe["mapping_confirmed"])
        self.assertEqual(safe["observed_assignment_page"], page)
        self.assertEqual(safe["constant_loader_base"], loader_base)
        self.assertEqual(safe["constant_write_slot_shift"], 3)
        self.assertEqual(
            [sample["font_tiles"] for sample in safe["sample_route_candidates"]],
            [[[page, physical_symbol]] for physical_symbol in physical_symbols],
        )
        self.assertTrue(all(sample["rom_route_candidates"] for sample in local["samples"]))

    def test_resolves_rom_page_from_cropped_screenshot_tiles(self) -> None:
        vram = bytearray(0x4000)
        symbols = (0x10, 0x11, 0x12)
        masks = (
            (0x18, 0x24, 0x42, 0x7E, 0x42, 0x42, 0x42, 0x00),
            (0x7C, 0x42, 0x42, 0x7C, 0x42, 0x42, 0x7C, 0x00),
            (0x3C, 0x42, 0x40, 0x40, 0x40, 0x42, 0x3C, 0x00),
        )
        page = 7
        loader_base = 0x100
        rom_size = direct_renderer_font_tile_offset(page, symbols[-1]) + 32
        rom = bytearray(rom_size)
        rgba = bytearray(bytes((0x00, 0x00, 0xAA, 0xFF)) * (160 * 144))
        for index, (symbol, mask) in enumerate(zip(symbols, masks)):
            tile = tile_bytes_from_ink_mask(mask)
            rendered_tile = loader_base + symbol
            vram_start = rendered_tile * 32
            vram[vram_start:vram_start + 32] = tile
            font_start = direct_renderer_font_tile_offset(page, symbol)
            rom[font_start:font_start + 32] = tile
            left = (FIRST_DIALOGUE_VIEWPORT_TEXT_COLUMN + index) * 8
            top = FIRST_DIALOGUE_VIEWPORT_TEXT_ROW * 8
            for row, bits in enumerate(mask):
                for column in range(8):
                    if bits & (1 << (7 - column)):
                        pixel = (top + row) * 160 + left + column
                        rgba[pixel * 4:pixel * 4 + 4] = DEFAULT_TEXT_INK_RGBA
        encoding = {
            "rows": [{"direct_renderer_proof": True, "visible_symbol_count": 3}],
            "character_assignments": [
                {
                    "row_index": 1,
                    "visual_kind": "approved-target-character",
                    "page": 21,
                    "symbol": symbol,
                    "tile_sha256": "f" * 64,
                }
                for symbol in symbols
            ],
        }
        with patch(
            "tools.v5_1_first_context_direct_renderer_capture.decode_png_rgba",
            return_value=PixelImage(width=160, height=144, rgba=bytes(rgba)),
        ):
            safe, local = analyze_direct_renderer_slot_alignment(
                bytes(vram), encoding, bytes(rom), b"screen"
            )
        self.assertTrue(safe["mapping_confirmed"])
        self.assertEqual(safe["observed_assignment_page"], page)
        self.assertEqual(safe["constant_loader_base"], loader_base)
        self.assertEqual(safe["constant_write_slot_shift"], 0)
        self.assertTrue(all(sample["screenshot_tile_candidates"] for sample in local["samples"]))
        self.assertEqual(
            [sample["screen_tiles"] for sample in safe["sample_route_candidates"]],
            [[loader_base + symbol] for symbol in symbols],
        )

    def test_keeps_partial_slot_alignment_out_of_safe_receipt(self) -> None:
        vram = bytearray(0x4000)
        tiles = [bytes([3]) * 32, bytes([4]) * 32]
        desired_indexes = [0x110, 0x120]
        rendered_indexes = [0x118, 0x128]
        for tile, tile_index in zip(tiles, desired_indexes):
            start = tile_index * 32
            vram[start:start + 32] = tile
        for index, tile_index in enumerate(rendered_indexes):
            offset = NAME_TABLE_BASE + 2 * (
                FIRST_DIALOGUE_TEXT_ROW * NAME_TABLE_WIDTH
                + FIRST_DIALOGUE_TEXT_COLUMN
                + index
            )
            vram[offset:offset + 2] = tile_index.to_bytes(2, "little")
        encoding = {
            "rows": [
                {
                    "direct_renderer_proof": True,
                    "visible_symbol_count": 2,
                }
            ],
            "character_assignments": [
                {
                    "row_index": 1,
                    "visual_kind": "approved-target-character",
                    "page": 21,
                    "symbol": symbol,
                    "tile_sha256": sha256(tile).hexdigest(),
                }
                for symbol, tile in zip((0x10, 0x11), tiles)
            ],
        }

        safe, local = analyze_direct_renderer_slot_alignment(bytes(vram), encoding)

        self.assertFalse(safe["mapping_confirmed"])
        self.assertIsNone(safe["constant_loader_base"])
        self.assertIsNone(safe["constant_write_slot_shift"])
        self.assertIsNone(safe["observed_assignment_page"])
        self.assertEqual(len(local["samples"]), 2)

    def test_maps_rendered_tiles_back_to_another_assignment_page(self) -> None:
        vram = bytearray(0x4000)
        intended_tiles = [bytes([5]) * 32, bytes([6]) * 32]
        rendered_tiles = [bytes([7]) * 32, bytes([8]) * 32]
        rendered_indexes = [0x113, 0x114]
        for tile, tile_index in zip(rendered_tiles, rendered_indexes):
            start = tile_index * 32
            vram[start:start + 32] = tile
        for index, tile_index in enumerate(rendered_indexes):
            offset = NAME_TABLE_BASE + 2 * (
                FIRST_DIALOGUE_TEXT_ROW * NAME_TABLE_WIDTH
                + FIRST_DIALOGUE_TEXT_COLUMN
                + index
            )
            vram[offset:offset + 2] = tile_index.to_bytes(2, "little")
        encoding = {
            "rows": [
                {
                    "direct_renderer_proof": True,
                    "visible_symbol_count": 2,
                }
            ],
            "character_assignments": [
                {
                    "row_index": 1,
                    "visual_kind": "approved-target-character",
                    "page": 21,
                    "symbol": symbol,
                    "tile_sha256": sha256(tile).hexdigest(),
                }
                for symbol, tile in zip((0x10, 0x11), intended_tiles)
            ] + [
                {
                    "row_index": 3,
                    "visual_kind": "approved-target-character",
                    "page": 44,
                    "symbol": symbol,
                    "tile_sha256": sha256(tile).hexdigest(),
                }
                for symbol, tile in zip((0x13, 0x14), rendered_tiles)
            ],
        }

        safe, _ = analyze_direct_renderer_slot_alignment(bytes(vram), encoding)

        self.assertTrue(safe["mapping_confirmed"])
        self.assertEqual(safe["rendered_assignment_match_count"], 2)
        self.assertEqual(safe["observed_assignment_page"], 44)
        self.assertEqual(safe["constant_loader_base"], 0x100)
        self.assertEqual(safe["constant_write_slot_shift"], 3)

    def test_confirms_three_consistent_glyphs_when_two_are_unmatched(self) -> None:
        vram = bytearray(0x4000)
        intended_tiles = [bytes([10 + index]) * 32 for index in range(5)]
        rendered_tiles = [bytes([20 + index]) * 32 for index in range(3)]
        rendered_indexes = [0x113, 0x114, 0x115, 0x180, 0x181]
        for tile, tile_index in zip(rendered_tiles, rendered_indexes):
            start = tile_index * 32
            vram[start:start + 32] = tile
        for index, tile_index in enumerate(rendered_indexes):
            offset = NAME_TABLE_BASE + 2 * (
                FIRST_DIALOGUE_TEXT_ROW * NAME_TABLE_WIDTH
                + FIRST_DIALOGUE_TEXT_COLUMN
                + index
            )
            vram[offset:offset + 2] = tile_index.to_bytes(2, "little")
        encoding = {
            "rows": [
                {
                    "direct_renderer_proof": True,
                    "visible_symbol_count": 5,
                }
            ],
            "character_assignments": [
                {
                    "row_index": 1,
                    "visual_kind": "approved-target-character",
                    "page": 21,
                    "symbol": 0x10 + index,
                    "tile_sha256": sha256(tile).hexdigest(),
                }
                for index, tile in enumerate(intended_tiles)
            ] + [
                {
                    "row_index": 3,
                    "visual_kind": "approved-target-character",
                    "page": 44,
                    "symbol": 0x13 + index,
                    "tile_sha256": sha256(tile).hexdigest(),
                }
                for index, tile in enumerate(rendered_tiles)
            ],
        }

        safe, local = analyze_direct_renderer_slot_alignment(bytes(vram), encoding)

        self.assertTrue(safe["mapping_confirmed"])
        self.assertEqual(safe["rendered_assignment_match_count"], 3)
        self.assertEqual(safe["observed_assignment_page"], 44)
        self.assertEqual(safe["constant_write_slot_shift"], 3)
        self.assertEqual(local["route_evidence_count"], 3)
        self.assertEqual(local["minimum_route_evidence"], 3)

    def test_accepts_rendered_assignment_capture_receipt(self) -> None:
        value = {
            "artifact_kind": "sanitized-v5-1-first-context-direct-renderer-capture",
            "schema_version": 8,
            "status": "direct-renderer-first-screen-captured",
            "baseline_target_sha256": "a" * 64,
            "test_target_sha256": "b" * 64,
            "first_context_translation_test_build_sha256": "c" * 64,
            "local_encoding_sha256": "d" * 64,
            "capture_png_sha256": "e" * 64,
            "captured_utc": "2026-08-02T00:00:00Z",
            "runtime_entry": {"selector": 2, "ordinal": 147},
            "renderer_route": "direct-observed-page",
            "runtime_stage_request_id": "direct-slot-map-20260802-02",
            "direct_renderer_first_row_confirmed": True,
            "slot_alignment": {
                "sample_count": 5,
                "unique_desired_vram_match_count": 0,
                "rendered_assignment_match_count": 5,
                "observed_assignment_page": 44,
                "constant_loader_base": 256,
                "constant_write_slot_shift": 3,
                "mapping_confirmed": True,
                "route_evidence_count": 5,
                "common_route_candidate_count": 1,
                "sample_route_candidates": [
                    {
                        "index": index,
                        "encoded_symbol": 0x10 + index,
                        "rendered_tile": 0x113 + index,
                        "screen_tiles": [0x113 + index],
                        "font_tile_match_count": 1,
                        "font_tiles": [[44, 0x13 + index]],
                        "rom_match_count": 1,
                        "rom_offsets": [0x1000 + index * 32],
                        "routes": [[44, 256, 3]],
                    }
                    for index in range(5)
                ],
            },
            "cold_boot": True,
            "human_visual_review_required": True,
            "translation_build_eligible": False,
            "next_checkpoint": "rebuild-first-dialogue-with-observed-slot-shift",
        }
        validate_first_context_direct_renderer_capture(value)
        numeric_legacy = copy.deepcopy(value)
        numeric_legacy["schema_version"] = 7
        for sample in numeric_legacy["slot_alignment"]["sample_route_candidates"]:
            for key in (
                "font_tile_match_count",
                "font_tiles",
                "rom_match_count",
                "rom_offsets",
            ):
                del sample[key]
        validate_first_context_direct_renderer_capture(numeric_legacy)
        legacy = copy.deepcopy(value)
        legacy["schema_version"] = 6
        legacy["slot_alignment"]["sample_route_candidates"] = [
            {"index": index, "routes": [[44, 256, 3]]}
            for index in range(5)
        ]
        validate_first_context_direct_renderer_capture(legacy)

    def test_accepts_slot_aligned_capture_receipt(self) -> None:
        value = {
            "artifact_kind": "sanitized-v5-1-first-context-direct-renderer-capture",
            "schema_version": 4,
            "status": "direct-renderer-first-screen-captured",
            "baseline_target_sha256": "a" * 64,
            "test_target_sha256": "b" * 64,
            "first_context_translation_test_build_sha256": "c" * 64,
            "local_encoding_sha256": "d" * 64,
            "capture_png_sha256": "e" * 64,
            "captured_utc": "2026-08-02T00:00:00Z",
            "runtime_entry": {"selector": 2, "ordinal": 147},
            "renderer_route": "direct-observed-page",
            "runtime_stage_request_id": "direct-slot-map-20260802-01",
            "direct_renderer_first_row_confirmed": True,
            "slot_alignment": {
                "sample_count": 5,
                "unique_desired_vram_match_count": 5,
                "constant_loader_base": 256,
                "constant_write_slot_shift": 8,
                "mapping_confirmed": True,
            },
            "cold_boot": True,
            "human_visual_review_required": True,
            "translation_build_eligible": False,
            "next_checkpoint": "rebuild-first-dialogue-with-observed-slot-shift",
        }
        validate_first_context_direct_renderer_capture(value)

    def test_accepts_safe_capture_receipt(self) -> None:
        value = {
            "artifact_kind": "sanitized-v5-1-first-context-direct-renderer-capture",
            "schema_version": 3,
            "status": "direct-renderer-first-screen-captured",
            "baseline_target_sha256": "a" * 64,
            "test_target_sha256": "b" * 64,
            "first_context_translation_test_build_sha256": "c" * 64,
            "local_encoding_sha256": "d" * 64,
            "capture_png_sha256": "e" * 64,
            "captured_utc": "2026-08-02T00:00:00Z",
            "runtime_entry": {"selector": 2, "ordinal": 147},
            "renderer_route": "proven-visible-page",
            "runtime_stage_request_id": "proven-page-select-blank-slots-20260802-02",
            "direct_renderer_first_row_confirmed": True,
            "cold_boot": True,
            "human_visual_review_required": True,
            "translation_build_eligible": False,
            "next_checkpoint": "human-verify-first-direct-renderer-dialogue-screen",
        }
        validate_first_context_direct_renderer_capture(value)
        invalid = copy.deepcopy(value)
        invalid["direct_renderer_first_row_confirmed"] = False
        with self.assertRaises(ValueError):
            validate_first_context_direct_renderer_capture(invalid)

    def test_accepts_legacy_safe_capture_receipt_for_bundle_publication(self) -> None:
        value = {
            "artifact_kind": "sanitized-v5-1-first-context-direct-renderer-capture",
            "schema_version": 2,
            "status": "direct-renderer-first-screen-captured",
            "baseline_target_sha256": "a" * 64,
            "test_target_sha256": "b" * 64,
            "first_context_translation_test_build_sha256": "c" * 64,
            "local_encoding_sha256": "d" * 64,
            "capture_png_sha256": "e" * 64,
            "captured_utc": "2026-08-02T00:00:00Z",
            "runtime_entry": {"selector": 2, "ordinal": 147},
            "renderer_route": "proven-visible-page",
            "direct_renderer_first_row_confirmed": True,
            "cold_boot": True,
            "human_visual_review_required": True,
            "translation_build_eligible": False,
            "next_checkpoint": "human-verify-first-direct-renderer-dialogue-screen",
        }
        validate_first_context_direct_renderer_capture(value)

    def test_rejects_invalid_runtime_stage_request_identity(self) -> None:
        value = {
            "artifact_kind": "sanitized-v5-1-first-context-direct-renderer-capture",
            "schema_version": 3,
            "status": "direct-renderer-first-screen-captured",
            "baseline_target_sha256": "a" * 64,
            "test_target_sha256": "b" * 64,
            "first_context_translation_test_build_sha256": "c" * 64,
            "local_encoding_sha256": "d" * 64,
            "capture_png_sha256": "e" * 64,
            "captured_utc": "2026-08-02T00:00:00Z",
            "runtime_entry": {"selector": 2, "ordinal": 147},
            "renderer_route": "proven-visible-page",
            "runtime_stage_request_id": "INVALID REQUEST",
            "direct_renderer_first_row_confirmed": True,
            "cold_boot": True,
            "human_visual_review_required": True,
            "translation_build_eligible": False,
            "next_checkpoint": "human-verify-first-direct-renderer-dialogue-screen",
        }
        with self.assertRaises(ValueError):
            validate_first_context_direct_renderer_capture(value)


if __name__ == "__main__":
    unittest.main()
