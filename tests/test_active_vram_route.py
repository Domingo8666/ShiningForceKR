from copy import deepcopy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_active_vram_route import (  # noqa: E402
    _contiguous_ranges,
    _parse_memory_bytes,
    _select_vram_area,
    analyze_active_vram_route,
    build_active_vram_route,
    replay_vdp_destinations,
    validate_active_vram_route,
)


def _runtime_entry() -> dict[str, int]:
    return {
        "physical_start": 0x20913,
        "logical_start": 0x4913,
        "mapped_bank": 8,
        "record_length_bytes": 16,
        "selector_de": 2,
        "entry_ordinal": 147,
    }


class ActiveVramRouteTests(unittest.TestCase):
    def test_parses_memory_and_selects_exact_vram_area(self) -> None:
        self.assertEqual(_parse_memory_bytes("00 7F FF", 3), b"\x00\x7f\xff")
        selected = _select_vram_area(
            {
                "areas": [
                    {"id": 1, "name": "RAM", "size": 0x2000},
                    {"id": 2, "name": "VRAM", "size": 0x4000},
                ]
            }
        )
        self.assertEqual(selected["id"], 2)

    def test_replays_vram_write_address_and_auto_increment(self) -> None:
        destinations, counts = replay_vdp_destinations(
            [
                {"trace_index": 0, "port": 0xBF, "value": 2},
                {"trace_index": 1, "port": 0xBF, "value": 0x8F},
                {"trace_index": 2, "port": 0xBF, "value": 0},
                {"trace_index": 3, "port": 0xBF, "value": 0x40},
                {"trace_index": 4, "port": 0xBE, "value": 0xAA},
                {"trace_index": 5, "port": 0xBE, "value": 0xBB},
            ]
        )
        self.assertEqual(
            [item["address"] for item in destinations],
            [0, 2],
        )
        self.assertEqual(counts["resolved_vram_data_write_count"], 2)
        self.assertEqual(counts["unresolved_vram_data_write_count"], 0)

    def test_counts_unresolved_data_without_a_write_command(self) -> None:
        destinations, counts = replay_vdp_destinations(
            [{"trace_index": 0, "port": 0xBE, "value": 1}]
        )
        self.assertEqual(destinations, [])
        self.assertEqual(counts["unresolved_vram_data_write_count"], 1)

    def test_analyzes_only_measured_vram_changes(self) -> None:
        before = bytes(0x4000)
        changed = bytearray(before)
        changed[0] = 0x11
        changed[1] = 0x22
        after = bytes(changed)
        outputs = [
            {"trace_index": 0, "port": 0xBF, "value": 0},
            {"trace_index": 1, "port": 0xBF, "value": 0x40},
            {"trace_index": 2, "port": 0xBE, "value": 0x11},
            {"trace_index": 3, "port": 0xBE, "value": 0x22},
        ]
        analysis, local = analyze_active_vram_route(
            before=before,
            after=after,
            outputs=outputs,
            rom=b"prefix" + after[:32] + b"suffix",
        )
        self.assertEqual(analysis["changed_byte_count"], 2)
        self.assertEqual(analysis["written_changed_byte_count"], 2)
        self.assertEqual(analysis["changed_tile_count"], 1)
        self.assertEqual(analysis["direct_rom_match_tile_count"], 1)
        self.assertEqual(
            local["changed_ranges"],
            [{"start": 0, "end_exclusive": 2}],
        )

    def test_builds_confirmed_non_promoting_artifact(self) -> None:
        analysis = {
            "vram_area_size": 0x4000,
            "trace_entry_count": 10,
            "vdp_control_write_count": 2,
            "vdp_data_write_count": 2,
            "resolved_vram_data_write_count": 2,
            "unresolved_vram_data_write_count": 0,
            "unique_vram_destination_count": 2,
            "changed_byte_count": 2,
            "changed_tile_count": 1,
            "written_changed_byte_count": 2,
            "direct_rom_match_tile_count": 1,
            "unique_direct_rom_source_count": 1,
        }
        value = build_active_vram_route(
            target_sha256="1" * 64,
            source_renderer_trace_sha256="2" * 64,
            runtime_entry=_runtime_entry(),
            analysis=analysis,
            captured_utc="2026-08-01T00:00:00Z",
        )
        validate_active_vram_route(value)
        self.assertEqual(value["status"], "active-vram-route-confirmed")
        self.assertEqual(value["next_checkpoint"], "map-active-vram-tiles-to-rom")
        self.assertFalse(value["translation_build_eligible"])

    def test_rejects_publishing_runtime_payload(self) -> None:
        analysis = {
            "vram_area_size": 0x4000,
            "trace_entry_count": 0,
            "vdp_control_write_count": 0,
            "vdp_data_write_count": 0,
            "resolved_vram_data_write_count": 0,
            "unresolved_vram_data_write_count": 0,
            "unique_vram_destination_count": 0,
            "changed_byte_count": 0,
            "changed_tile_count": 0,
            "written_changed_byte_count": 0,
            "direct_rom_match_tile_count": 0,
            "unique_direct_rom_source_count": 0,
        }
        value = build_active_vram_route(
            target_sha256="1" * 64,
            source_renderer_trace_sha256="2" * 64,
            runtime_entry=_runtime_entry(),
            analysis=analysis,
            captured_utc="2026-08-01T00:00:00Z",
        )
        unsafe = deepcopy(value)
        unsafe["vram_bytes"] = [1, 2, 3]
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_active_vram_route(unsafe)

    def test_builds_contiguous_ranges(self) -> None:
        self.assertEqual(
            _contiguous_ranges([1, 2, 4]),
            [
                {"start": 1, "end_exclusive": 3},
                {"start": 4, "end_exclusive": 5},
            ],
        )


if __name__ == "__main__":
    unittest.main()
