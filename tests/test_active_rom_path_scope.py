from __future__ import annotations

import unittest

from tools.v5_1_active_rom_path_scope import (
    analyze_active_rom_path_scope,
    build_active_rom_path_scope,
    validate_active_rom_path_scope,
)


class ActiveRomPathScopeTests(unittest.TestCase):
    def _inputs(self) -> tuple[dict[str, object], ...]:
        rom_source = {"source_region": "original-rom"}
        source_role = {
            "source_role": "unclassified-data",
            "analysis": {
                "source_script_payload_match_count": 0,
                "source_script_length_match_count": 0,
                "source_executed_match_count": 0,
                "target_transfer_byte_count": 192,
                "target_transfer_tile_count": 6,
            },
        }
        read_block = {
            "access_pattern": "scattered-lookup-candidate",
            "analysis": {
                "read_occurrence_count": 46,
                "unique_logical_read_count": 8,
                "physical_projection_byte_span": 23,
                "repeated_read_occurrence_count": 38,
                "script_record_projection_match_count": 0,
                "script_payload_projection_match_count": 0,
                "script_length_projection_match_count": 0,
            },
        }
        lookup = {
            "producer_class": "incremental-cursor-candidate",
            "analysis": {"matched_predecessor_definition_count": 46},
        }
        return rom_source, source_role, read_block, lookup

    def test_classifies_repeated_interleaved_renderer_asset(self) -> None:
        counts, scope = analyze_active_rom_path_scope(
            rom_source=self._inputs()[0],
            source_role=self._inputs()[1],
            read_block=self._inputs()[2],
            lookup=self._inputs()[3],
        )
        self.assertEqual(
            scope, "repeated-interleaved-renderer-asset-candidate"
        )
        value = build_active_rom_path_scope(
            target_sha256="a" * 64,
            source_active_register_rom_source_sha256="b" * 64,
            source_active_rom_source_role_sha256="c" * 64,
            source_active_rom_read_block_sha256="d" * 64,
            source_active_rom_lookup_index_producer_sha256="e" * 64,
            analysis=counts,
            path_scope=scope,
            captured_utc="2026-08-02T00:00:00Z",
        )
        validate_active_rom_path_scope(value)
        self.assertFalse(value["current_path_relevant_to_translation_fix"])
        self.assertEqual(
            value["next_checkpoint"],
            "capture-translated-test-rom-vram-difference",
        )

    def test_does_not_hide_script_projection(self) -> None:
        rom_source, source_role, read_block, lookup = self._inputs()
        read_block["analysis"]["script_payload_projection_match_count"] = 1
        _, scope = analyze_active_rom_path_scope(
            rom_source=rom_source,
            source_role=source_role,
            read_block=read_block,
            lookup=lookup,
        )
        self.assertEqual(scope, "translation-path-unresolved")


if __name__ == "__main__":
    unittest.main()
