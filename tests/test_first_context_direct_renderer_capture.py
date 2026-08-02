from __future__ import annotations

import copy
from hashlib import sha256
import unittest

from tools.v5_1_first_context_direct_renderer_capture import (
    FIRST_DIALOGUE_TEXT_COLUMN,
    FIRST_DIALOGUE_TEXT_ROW,
    NAME_TABLE_BASE,
    NAME_TABLE_WIDTH,
    analyze_direct_renderer_slot_alignment,
    validate_first_context_direct_renderer_capture,
)


class FirstContextDirectRendererCaptureTests(unittest.TestCase):
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
        self.assertTrue(safe["mapping_confirmed"])
        self.assertEqual(len(local["samples"]), 2)

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
        self.assertEqual(len(local["samples"]), 2)

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
