from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.patch_io import sha256_file
from tools.v5_1_active_ram_register_trace import (
    LOCAL_REPORT_PATH as REGISTER_TRACE_LOCAL_PATH,
    PUBLISH_RELATIVE_PATH as REGISTER_TRACE_PATH,
    build_active_ram_register_trace,
)
from tools.v5_1_active_register_rom_source import (
    PUBLISH_RELATIVE_PATH as ROM_SOURCE_PATH,
    build_active_register_rom_source,
)
from tools.v5_1_active_rom_source_role import (
    PUBLISH_RELATIVE_PATH as ROM_SOURCE_ROLE_PATH,
    build_active_rom_source_role,
)
from tools.v5_1_active_rom_read_block import (
    PUBLISH_RELATIVE_PATH as ROM_READ_BLOCK_PATH,
    build_active_rom_read_block,
)
from tools.v5_1_active_rom_lookup_index_producer import (
    PUBLISH_RELATIVE_PATH as ROM_LOOKUP_INDEX_PATH,
    build_active_rom_lookup_index_producer,
)
from tools.v5_1_active_rom_path_scope import (
    PUBLISH_RELATIVE_PATH as ROM_PATH_SCOPE_PATH,
    build_active_rom_path_scope,
)
from tools.v5_1_active_rom_cursor_reset import (
    PUBLISH_RELATIVE_PATH as ROM_CURSOR_RESET_PATH,
    build_active_rom_cursor_reset,
)
from tools.v5_1_critical_path import (
    CURSOR_RESET_STAGE,
    DIRECT_RENDERER_CAPTURE_STAGE,
    FOCUSED_STAGE,
    LOOKUP_INDEX_STAGE,
    PATH_SCOPE_STAGE,
    READ_BLOCK_STAGE,
    SOURCE_ROLE_STAGE,
    TRANSLATED_VRAM_DIFF_STAGE,
    TRANSLATED_GLYPH_ROUTE_STAGE,
    _direct_renderer_consumer_trace_needed,
    select_critical_path,
    validate_critical_path,
)


class CriticalPathTests(unittest.TestCase):
    def _write_json(self, path: Path, value: dict[str, object]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")

    def _ready_root(self, root: Path) -> tuple[Path, str]:
        rom_path = root / "build/Final_Conflict_Korean_v5.1.gg"
        rom_path.parent.mkdir(parents=True, exist_ok=True)
        rom_path.write_bytes(bytes(range(256)) * 64)
        target_sha256 = sha256_file(rom_path)
        safe = build_active_ram_register_trace(
            target_sha256=target_sha256,
            source_active_ram_writer_sha256="a" * 64,
            analysis={
                "trace_line_count": 12,
                "parsed_trace_line_count": 12,
                "source_definition_candidate_count": 1,
                "memory_definition_candidate_count": 1,
                "immediate_definition_candidate_count": 0,
                "register_definition_candidate_count": 0,
                "arithmetic_definition_candidate_count": 0,
                "unique_definition_pc_count": 1,
            },
            writer_instance_confirmed=True,
            definition_source_class="rom-window",
            captured_utc="2026-08-02T00:00:00Z",
        )
        self._write_json(root / REGISTER_TRACE_PATH, safe)
        self._write_json(
            root / REGISTER_TRACE_LOCAL_PATH,
            {
                "analysis": {
                    "selected": {
                        "bank": 1,
                        "pc": 0x4567,
                        "opcodes_hex": "7e",
                        "read_addresses": [0x8123],
                    }
                }
            },
        )
        return rom_path, target_sha256

    def test_selects_only_the_first_unresolved_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rom_path, _ = self._ready_root(root)
            selected = select_critical_path(root, rom_path)
            self.assertIsNotNone(selected)
            assert selected is not None
            validate_critical_path(selected)
            self.assertEqual(selected["selected_stage"], FOCUSED_STAGE)
            self.assertFalse(selected["translation_build_eligible"])

    def _write_current_mapping(
        self, root: Path, target_sha256: str
    ) -> dict[str, object]:
        trace_sha256 = sha256_file(root / REGISTER_TRACE_PATH)
        mapped = build_active_register_rom_source(
            target_sha256=target_sha256,
            source_register_trace_sha256=trace_sha256,
            analysis={
                "read_break_hit_count": 1,
                "matching_read_hit_count": 1,
                "logical_read_address_count": 1,
                "physical_source_count": 1,
                "rom_value_match_count": 1,
            },
            source_slot_name="slot2",
            mapped_bank=1,
            physical_source_offset=0x4123,
            captured_utc="2026-08-02T00:00:00Z",
        )
        self._write_json(root / ROM_SOURCE_PATH, mapped)
        return mapped

    def test_selects_role_classification_when_mapping_is_current(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rom_path, target_sha256 = self._ready_root(root)
            self._write_current_mapping(root, target_sha256)
            selected = select_critical_path(root, rom_path)
            self.assertIsNotNone(selected)
            assert selected is not None
            self.assertEqual(selected["selected_stage"], SOURCE_ROLE_STAGE)

    def test_skips_focus_when_role_is_already_current(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rom_path, target_sha256 = self._ready_root(root)
            self._write_current_mapping(root, target_sha256)
            role = build_active_rom_source_role(
                target_sha256=target_sha256,
                source_active_register_rom_source_sha256=sha256_file(
                    root / ROM_SOURCE_PATH
                ),
                source_register_trace_sha256=sha256_file(
                    root / REGISTER_TRACE_PATH
                ),
                source_target_population_sha256="d" * 64,
                analysis={
                    "matching_definition_event_count": 32,
                    "matching_read_event_count": 32,
                    "unique_logical_read_count": 32,
                    "contiguous_logical_span_bytes": 32,
                    "forward_sequential_transition_count": 31,
                    "source_script_payload_match_count": 0,
                    "source_script_length_match_count": 0,
                    "source_executed_match_count": 0,
                    "target_transfer_byte_count": 192,
                    "target_transfer_tile_count": 6,
                },
                source_role_name="renderer-source-candidate",
                captured_utc="2026-08-02T00:00:00Z",
            )
            self._write_json(root / ROM_SOURCE_ROLE_PATH, role)
            self.assertIsNone(select_critical_path(root, rom_path))

    def test_bounds_unclassified_reads_once_then_skips_current_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rom_path, target_sha256 = self._ready_root(root)
            self._write_current_mapping(root, target_sha256)
            source_sha256 = sha256_file(root / ROM_SOURCE_PATH)
            role = build_active_rom_source_role(
                target_sha256=target_sha256,
                source_active_register_rom_source_sha256=source_sha256,
                source_register_trace_sha256=sha256_file(
                    root / REGISTER_TRACE_PATH
                ),
                source_target_population_sha256="d" * 64,
                analysis={
                    "matching_definition_event_count": 46,
                    "matching_read_event_count": 46,
                    "unique_logical_read_count": 8,
                    "contiguous_logical_span_bytes": 0,
                    "forward_sequential_transition_count": 0,
                    "source_script_payload_match_count": 0,
                    "source_script_length_match_count": 0,
                    "source_executed_match_count": 0,
                    "target_transfer_byte_count": 192,
                    "target_transfer_tile_count": 6,
                },
                source_role_name="unclassified-data",
                captured_utc="2026-08-02T00:00:00Z",
            )
            self._write_json(root / ROM_SOURCE_ROLE_PATH, role)
            selected = select_critical_path(root, rom_path)
            self.assertIsNotNone(selected)
            assert selected is not None
            self.assertEqual(selected["selected_stage"], READ_BLOCK_STAGE)

            role_sha256 = sha256_file(root / ROM_SOURCE_ROLE_PATH)
            read_block = build_active_rom_read_block(
                target_sha256=target_sha256,
                source_active_rom_source_role_sha256=role_sha256,
                source_active_register_rom_source_sha256=source_sha256,
                source_target_population_sha256="d" * 64,
                analysis={
                    "read_occurrence_count": 46,
                    "unique_logical_read_count": 8,
                    "unique_physical_projection_count": 8,
                    "physical_projection_byte_span": 64,
                    "contiguous_run_count": 8,
                    "maximum_contiguous_run_bytes": 1,
                    "singleton_run_count": 8,
                    "repeated_read_occurrence_count": 38,
                    "forward_sequential_transition_count": 0,
                    "backward_sequential_transition_count": 0,
                    "same_address_transition_count": 8,
                    "fixed_stride_bytes": 0,
                    "script_record_projection_match_count": 0,
                    "script_payload_projection_match_count": 0,
                    "script_length_projection_match_count": 0,
                },
                access_pattern="scattered-lookup-candidate",
                captured_utc="2026-08-02T00:00:00Z",
            )
            self._write_json(root / ROM_READ_BLOCK_PATH, read_block)
            selected = select_critical_path(root, rom_path)
            self.assertIsNotNone(selected)
            assert selected is not None
            self.assertEqual(selected["selected_stage"], LOOKUP_INDEX_STAGE)

            lookup = build_active_rom_lookup_index_producer(
                target_sha256=target_sha256,
                source_active_rom_read_block_sha256=sha256_file(
                    root / ROM_READ_BLOCK_PATH
                ),
                source_active_rom_source_role_sha256=role_sha256,
                source_register_trace_sha256=sha256_file(
                    root / REGISTER_TRACE_PATH
                ),
                analysis={
                    "target_event_count": 46,
                    "target_unique_logical_read_count": 8,
                    "address_register_candidate_count": 1,
                    "matched_predecessor_definition_count": 46,
                    "unique_predecessor_instruction_count": 1,
                    "maximum_backtrack_instruction_count": 2,
                    "literal_pointer_definition_count": 0,
                    "arithmetic_pointer_definition_count": 0,
                    "incremental_pointer_definition_count": 46,
                    "memory_pointer_definition_count": 0,
                    "stack_pointer_definition_count": 0,
                    "split_pointer_definition_count": 0,
                    "unknown_pointer_definition_count": 0,
                },
                address_operand_kind="bc-indirect",
                producer_class="incremental-cursor-candidate",
                captured_utc="2026-08-02T00:00:00Z",
            )
            self._write_json(root / ROM_LOOKUP_INDEX_PATH, lookup)
            selected = select_critical_path(root, rom_path)
            self.assertIsNotNone(selected)
            assert selected is not None
            self.assertEqual(selected["selected_stage"], PATH_SCOPE_STAGE)

            path_scope = build_active_rom_path_scope(
                target_sha256=target_sha256,
                source_active_register_rom_source_sha256=source_sha256,
                source_active_rom_source_role_sha256=role_sha256,
                source_active_rom_read_block_sha256=sha256_file(
                    root / ROM_READ_BLOCK_PATH
                ),
                source_active_rom_lookup_index_producer_sha256=sha256_file(
                    root / ROM_LOOKUP_INDEX_PATH
                ),
                analysis={
                    "read_occurrence_count": 46,
                    "unique_logical_read_count": 8,
                    "physical_projection_byte_span": 64,
                    "repeated_read_occurrence_count": 38,
                    "target_transfer_byte_count": 192,
                    "target_transfer_tile_count": 6,
                    "matching_predecessor_count": 46,
                    "script_projection_match_count": 0,
                    "source_executed_match_count": 0,
                },
                path_scope="translation-path-unresolved",
                captured_utc="2026-08-02T00:00:00Z",
            )
            self._write_json(root / ROM_PATH_SCOPE_PATH, path_scope)
            selected = select_critical_path(root, rom_path)
            self.assertIsNotNone(selected)
            assert selected is not None
            self.assertEqual(selected["selected_stage"], CURSOR_RESET_STAGE)

            cursor = build_active_rom_cursor_reset(
                target_sha256=target_sha256,
                source_active_rom_lookup_index_producer_sha256=sha256_file(
                    root / ROM_LOOKUP_INDEX_PATH
                ),
                source_active_rom_read_block_sha256=sha256_file(
                    root / ROM_READ_BLOCK_PATH
                ),
                source_register_trace_sha256=sha256_file(
                    root / REGISTER_TRACE_PATH
                ),
                analysis={
                    "target_event_count": 46,
                    "target_unique_logical_read_count": 8,
                    "cursor_register_candidate_count": 1,
                    "incremental_producer_event_count": 46,
                    "positive_stride_event_count": 46,
                    "negative_stride_event_count": 0,
                    "unique_stride_count": 1,
                    "reset_definition_match_count": 46,
                    "unique_reset_instruction_count": 1,
                    "literal_reset_count": 46,
                    "memory_reset_count": 0,
                    "stack_reset_count": 0,
                    "split_reset_count": 0,
                    "arithmetic_reset_count": 0,
                    "unknown_reset_count": 0,
                    "reset_to_target_projection_match_count": 46,
                    "maximum_reset_backtrack_instruction_count": 8,
                },
                reset_class="literal-reset-fixed-stride-candidate",
                captured_utc="2026-08-02T00:00:00Z",
            )
            self._write_json(root / ROM_CURSOR_RESET_PATH, cursor)
            self.assertIsNone(select_critical_path(root, rom_path))

            nontext_scope = build_active_rom_path_scope(
                target_sha256=target_sha256,
                source_active_register_rom_source_sha256=source_sha256,
                source_active_rom_source_role_sha256=role_sha256,
                source_active_rom_read_block_sha256=sha256_file(
                    root / ROM_READ_BLOCK_PATH
                ),
                source_active_rom_lookup_index_producer_sha256=sha256_file(
                    root / ROM_LOOKUP_INDEX_PATH
                ),
                analysis={
                    "read_occurrence_count": 46,
                    "unique_logical_read_count": 8,
                    "physical_projection_byte_span": 64,
                    "repeated_read_occurrence_count": 38,
                    "target_transfer_byte_count": 192,
                    "target_transfer_tile_count": 6,
                    "matching_predecessor_count": 46,
                    "script_projection_match_count": 0,
                    "source_executed_match_count": 0,
                },
                path_scope="repeated-interleaved-renderer-asset-candidate",
                captured_utc="2026-08-02T00:00:00Z",
            )
            self._write_json(root / ROM_PATH_SCOPE_PATH, nontext_scope)
            selected = select_critical_path(root, rom_path)
            self.assertIsNotNone(selected)
            assert selected is not None
            self.assertEqual(
                selected["selected_stage"], TRANSLATED_VRAM_DIFF_STAGE
            )

    def test_does_not_focus_without_current_prerequisites(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rom_path = root / "build/Final_Conflict_Korean_v5.1.gg"
            rom_path.parent.mkdir(parents=True)
            rom_path.write_bytes(b"rom")
            self.assertIsNone(select_critical_path(root, rom_path))

    def test_prioritizes_current_direct_build_with_stale_consumer_trace(
        self,
    ) -> None:
        repository = Path(__file__).resolve().parents[1]
        relative_paths = (
            Path("analysis/device/v5_1_latest_first_context_direct_renderer_capture.json"),
            Path("analysis/device/v5_1_latest_first_context_direct_renderer_capture.png"),
            Path("analysis/device/v5_1_latest_first_context_translation_test_build.json"),
            Path("analysis/device/v5_1_latest_first_context_consumer_trace.json"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative_path in relative_paths:
                target = root / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((repository / relative_path).read_bytes())
            build = json.loads(
                (root / relative_paths[2]).read_text(encoding="utf-8")
            )
            capture_path = root / relative_paths[0]
            capture = json.loads(capture_path.read_text(encoding="utf-8"))
            capture["test_target_sha256"] = build["test_target_sha256"]
            capture["first_context_translation_test_build_sha256"] = (
                sha256_file(root / relative_paths[2])
            )
            capture["renderer_route"] = "direct-observed-page"
            self._write_json(capture_path, capture)
            consumer_path = root / relative_paths[3]
            consumer = json.loads(consumer_path.read_text(encoding="utf-8"))
            consumer["test_target_sha256"] = "0" * 64
            self._write_json(consumer_path, consumer)
            self.assertTrue(
                _direct_renderer_consumer_trace_needed(
                    root,
                    target_sha256=build["baseline_target_sha256"],
                )
            )
            self.assertEqual(
                DIRECT_RENDERER_CAPTURE_STAGE,
                "first-context-direct-renderer-capture",
            )


if __name__ == "__main__":
    unittest.main()
