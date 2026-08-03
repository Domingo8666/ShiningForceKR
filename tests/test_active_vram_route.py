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
    _read_memory_area,
    _ram_offset,
    _select_ram_area,
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
    def test_can_read_vram_in_four_bounded_mcp_responses(self) -> None:
        class Client:
            calls: list[tuple[str, dict[str, object]]] = []

            def call(
                self,
                name: str,
                arguments: dict[str, object],
            ) -> dict[str, object]:
                self.calls.append((name, arguments))
                size = int(arguments["size"])
                return {"data": " ".join("00" for _ in range(size))}

        client = Client()
        self.assertEqual(
            _read_memory_area(
                client,
                area_id=2,
                size=0x4000,
                chunk_size=0x1000,
            ),
            bytes(0x4000),
        )
        self.assertEqual(len(client.calls), 4)
        self.assertTrue(
            all(call[1]["size"] == 0x1000 for call in client.calls)
        )

    def test_parses_memory_and_selects_exact_vram_area(self) -> None:
        self.assertEqual(_parse_memory_bytes("00 7F FF", 3), b"\x00\x7f\xff")
        selected = _select_vram_area(
            {
                "areas": [
                    {"id": 1, "name": "RAM", "size": 0x2004},
                    {"id": 2, "name": "VRAM", "size": 0x4000},
                ]
            }
        )
        self.assertEqual(selected["id"], 2)
        ram = _select_ram_area(
            {
                "areas": [
                    {"id": 1, "name": "RAM", "size": 0x2004},
                    {"id": 2, "name": "VRAM", "size": 0x4000},
                ]
            }
        )
        self.assertEqual(ram["id"], 1)
        self.assertEqual(_ram_offset(0xC100, 0x2000), 0x100)
        self.assertEqual(_ram_offset(0xE100, 0x2000), 0x100)

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
            ram_before=bytes(0x2000),
            ram_after=bytes(0x2000),
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
            "ram_backed_vdp_data_write_count": 0,
            "stable_ram_source_write_count": 0,
            "ram_source_matches_resident_vram_count": 0,
            "ram_reported_address_match_count": 0,
            "ram_previous_step_match_count": 0,
            "ram_next_step_match_count": 0,
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
            "ram_backed_vdp_data_write_count": 0,
            "stable_ram_source_write_count": 0,
            "ram_source_matches_resident_vram_count": 0,
            "ram_reported_address_match_count": 0,
            "ram_previous_step_match_count": 0,
            "ram_next_step_match_count": 0,
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

    def test_confirms_idempotent_ram_to_vram_transfer(self) -> None:
        vram = bytearray(0x4000)
        vram[0:2] = b"\x11\x22"
        ram = bytearray(0x2000)
        ram[0x100:0x102] = b"\x11\x22"
        analysis, _ = analyze_active_vram_route(
            before=bytes(vram),
            after=bytes(vram),
            ram_before=bytes(ram),
            ram_after=bytes(ram),
            outputs=[
                {"trace_index": 0, "port": 0xBF, "value": 0},
                {"trace_index": 1, "port": 0xBF, "value": 0x40},
                {
                    "trace_index": 2,
                    "port": 0xBE,
                    "source_address": 0xC100,
                    "source_step": 1,
                },
                {
                    "trace_index": 3,
                    "port": 0xBE,
                    "source_address": 0xC101,
                    "source_step": 1,
                },
            ],
            rom=bytes(0x8000),
        )
        value = build_active_vram_route(
            target_sha256="1" * 64,
            source_renderer_trace_sha256="2" * 64,
            runtime_entry=_runtime_entry(),
            analysis=analysis,
            captured_utc="2026-08-01T00:00:00Z",
        )
        self.assertTrue(value["active_vram_route_confirmed"])
        self.assertTrue(value["ram_source_route_confirmed"])
        self.assertEqual(
            value["ram_source_address_semantics"],
            "reported-address",
        )
        self.assertEqual(
            value["next_checkpoint"],
            "trace-active-ram-buffer-producer",
        )

    def test_resolves_post_increment_trace_registers(self) -> None:
        vram = bytearray(0x4000)
        vram[0:2] = b"\x11\x22"
        ram = bytearray(0x2000)
        ram[0x100:0x103] = b"\x11\x22\x33"
        analysis, _ = analyze_active_vram_route(
            before=bytes(vram),
            after=bytes(vram),
            ram_before=bytes(ram),
            ram_after=bytes(ram),
            outputs=[
                {"trace_index": 0, "port": 0xBF, "value": 0},
                {"trace_index": 1, "port": 0xBF, "value": 0x40},
                {
                    "trace_index": 2,
                    "port": 0xBE,
                    "source_address": 0xC101,
                    "source_step": 1,
                },
                {
                    "trace_index": 3,
                    "port": 0xBE,
                    "source_address": 0xC102,
                    "source_step": 1,
                },
            ],
            rom=bytes(0x8000),
        )
        value = build_active_vram_route(
            target_sha256="1" * 64,
            source_renderer_trace_sha256="2" * 64,
            runtime_entry=_runtime_entry(),
            analysis=analysis,
            captured_utc="2026-08-01T00:00:00Z",
        )
        self.assertEqual(analysis["ram_previous_step_match_count"], 2)
        self.assertEqual(analysis["ram_reported_address_match_count"], 0)
        self.assertTrue(value["ram_source_route_confirmed"])
        self.assertEqual(
            value["ram_source_address_semantics"],
            "previous-transfer-step",
        )

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
