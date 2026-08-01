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
from tools.v5_1_critical_path import (
    FOCUSED_STAGE,
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

    def test_skips_focus_when_mapping_is_already_current(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rom_path, target_sha256 = self._ready_root(root)
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
            self.assertIsNone(select_critical_path(root, rom_path))

    def test_does_not_focus_without_current_prerequisites(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rom_path = root / "build/Final_Conflict_Korean_v5.1.gg"
            rom_path.parent.mkdir(parents=True)
            rom_path.write_bytes(b"rom")
            self.assertIsNone(select_critical_path(root, rom_path))


if __name__ == "__main__":
    unittest.main()
