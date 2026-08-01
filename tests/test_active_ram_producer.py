from __future__ import annotations

import copy
import unittest

from tools.v5_1_active_ram_producer import (
    _capture_producer_state,
    analyze_capture,
    build_active_ram_producer,
    contiguous_address_ranges,
    extract_target_values,
    previous_target_write,
    validate_active_ram_producer,
    write_addresses,
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


def _active_route() -> dict[str, object]:
    counts = {
        "vram_area_size": 0x4000,
        "trace_entry_count": 100,
        "vdp_control_write_count": 2,
        "vdp_data_write_count": 2,
        "resolved_vram_data_write_count": 2,
        "unresolved_vram_data_write_count": 0,
        "unique_vram_destination_count": 2,
        "changed_byte_count": 0,
        "changed_tile_count": 0,
        "written_changed_byte_count": 0,
        "direct_rom_match_tile_count": 0,
        "unique_direct_rom_source_count": 0,
        "ram_backed_vdp_data_write_count": 2,
        "stable_ram_source_write_count": 2,
        "ram_source_matches_resident_vram_count": 2,
        "ram_reported_address_match_count": 1,
        "ram_previous_step_match_count": 2,
        "ram_next_step_match_count": 0,
    }
    return {
        "artifact_kind": "sanitized-s25u-active-vram-route",
        "schema_version": 4,
        "status": "active-vram-route-confirmed",
        "target_sha256": "a" * 64,
        "source_renderer_trace_sha256": "b" * 64,
        "captured_utc": "2026-08-01T00:00:00Z",
        "runtime_entry": _runtime_entry(),
        "analysis": counts,
        "active_vram_route_confirmed": True,
        "ram_source_route_confirmed": True,
        "ram_source_address_semantics": "previous-transfer-step",
        "baseline_script_bytes_unchanged": True,
        "local_payload_policy": (
            "ram-vram-addresses-bytes-output-values-and-rom-offsets-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": "trace-active-ram-buffer-producer",
    }


class ActiveRamProducerTests(unittest.TestCase):
    def test_lightweight_capture_does_not_request_a_call_stack(self) -> None:
        class Client:
            def __init__(self) -> None:
                self.calls: list[str] = []

            def call(
                self,
                name: str,
                arguments: dict[str, object] | None = None,
            ) -> dict[str, object]:
                self.calls.append(name)
                if name == "debug_get_status":
                    return {"pc": "3411", "at_breakpoint": True}
                if name == "get_z80_status":
                    return {
                        "physical_PC": "3411",
                        "bank": "00",
                        "AF": "0000",
                        "BC": "9300",
                        "DE": "0002",
                        "HL": "4913",
                        "IX": "0000",
                        "IY": "0000",
                        "SP": "DFF0",
                    }
                if name == "read_memory":
                    return {"data": "00 00 08 09"}
                raise AssertionError(name)

        client = Client()
        state, evidence = _capture_producer_state(
            client,
            ram_area_id=1,
            ram_area_size=0x2004,
        )
        self.assertEqual(state["pc_after"], 0x3411)
        self.assertEqual(state["slot1_bank"], 8)
        self.assertIn("z80", evidence)
        self.assertNotIn("get_call_stack", client.calls)
        self.assertNotIn("get_trace_log", client.calls)

    def test_extracts_the_confirmed_previous_step_sources(self) -> None:
        local = {
            "artifact_kind": "local-s25u-active-vram-route",
            "target_sha256": "a" * 64,
            "analysis": {
                "selected_source_step_adjustment": -1,
                "ram_source_transfers": [
                    {
                        "candidate_adjustments": {
                            "-1": {
                                "logical_address": 0xC100,
                                "source_after": 0x12,
                                "source_stable": True,
                                "source_matches_resident_vram": True,
                            }
                        }
                    },
                    {
                        "candidate_adjustments": {
                            "-1": {
                                "logical_address": 0xC101,
                                "source_after": 0x34,
                                "source_stable": True,
                                "source_matches_resident_vram": True,
                            }
                        }
                    },
                ],
            },
        }
        values, transfer_count = extract_target_values(_active_route(), local)
        self.assertEqual(values, {0xC100: 0x12, 0xC101: 0x34})
        self.assertEqual(transfer_count, 2)

    def test_merges_only_adjacent_logical_addresses(self) -> None:
        self.assertEqual(
            contiguous_address_ranges([0xC103, 0xC100, 0xC101, 0xC200]),
            [(0xC100, 0xC101), (0xC103, 0xC103), (0xC200, 0xC200)],
        )

    def test_decodes_post_instruction_z80_write_addresses(self) -> None:
        registers = {
            "bc": 0xC100,
            "de": 0xC121,
            "hl": 0xC140,
            "sp": 0xD000,
            "ix": 0xC180,
            "iy": 0xC1A0,
        }
        self.assertEqual(write_addresses(bytes.fromhex("02"), registers), [0xC100])
        self.assertEqual(write_addresses(bytes.fromhex("12"), registers), [0xC121])
        self.assertEqual(
            write_addresses(bytes.fromhex("22 00 C2"), registers),
            [0xC200, 0xC201],
        )
        self.assertEqual(write_addresses(bytes.fromhex("70"), registers), [0xC140])
        self.assertEqual(
            write_addresses(bytes.fromhex("DD 70 02"), registers),
            [0xC182],
        )
        self.assertEqual(
            write_addresses(bytes.fromhex("ED B0"), registers),
            [0xC120],
        )
        self.assertEqual(
            write_addresses(bytes.fromhex("ED B8"), registers),
            [0xC122],
        )

    def test_decodes_completed_writer_from_rom_without_a_trace_buffer(self) -> None:
        rom = bytearray(0x200)
        rom[0x100:0x102] = bytes.fromhex("ED B0")
        state = {
            "physical_pc_after": 0x102,
            "pc_after": 0x4102,
            "executing_bank": 0,
            "registers": {
                "af": 0,
                "bc": 0,
                "de": 0xC121,
                "hl": 0,
                "ix": 0,
                "iy": 0,
                "sp": 0xD000,
            },
        }
        writer = previous_target_write(bytes(rom), state, {0xC120})
        self.assertIsNotNone(writer)
        assert writer is not None
        self.assertEqual(writer["physical_pc"], 0x100)
        self.assertEqual(writer["pc"], 0x4100)
        self.assertEqual(writer["operand_kind"], "block-copy")
        self.assertEqual(writer["addresses"], [0xC120])

    def test_confirms_only_full_nonzero_writer_coverage(self) -> None:
        final_ram = bytearray(0x2000)
        final_ram[0x100] = 0x12
        final_ram[0x101] = 0x34
        events = [
            {
                "writer": {"bank": 8, "pc": 0x6123, "operand_kind": "block-copy"},
                "addresses": [0xC100],
            },
            {
                "writer": {"bank": 8, "pc": 0x6123, "operand_kind": "block-copy"},
                "addresses": [0xC101],
            },
        ]
        counts, _ = analyze_capture(
            target_values={0xC100: 0x12, 0xC101: 0x34},
            target_transfer_count=2,
            final_ram=bytes(final_ram),
            write_ranges=[(0xC100, 0xC101)],
            write_watch_hit_count=2,
            events=events,
            latest_writer_event={0xC100: 0, 0xC101: 1},
        )
        artifact = build_active_ram_producer(
            target_sha256="a" * 64,
            source_active_vram_route_sha256="b" * 64,
            runtime_entry=_runtime_entry(),
            analysis=counts,
            captured_utc="2026-08-01T00:00:00Z",
        )
        validate_active_ram_producer(artifact)
        self.assertEqual(artifact["status"], "active-ram-producer-confirmed")
        self.assertTrue(artifact["producer_route_confirmed"])
        self.assertEqual(
            artifact["next_checkpoint"], "trace-active-ram-producer-inputs"
        )

        partial_counts = copy.deepcopy(counts)
        partial_counts["producer_covered_address_count"] = 1
        partial_counts["producer_covered_nonzero_address_count"] = 1
        partial_counts["dominant_writer_address_count"] = 1
        partial = build_active_ram_producer(
            target_sha256="a" * 64,
            source_active_vram_route_sha256="b" * 64,
            runtime_entry=_runtime_entry(),
            analysis=partial_counts,
            captured_utc="2026-08-01T00:00:00Z",
        )
        self.assertEqual(partial["status"], "active-ram-producer-partial")
        self.assertFalse(partial["producer_route_confirmed"])


if __name__ == "__main__":
    unittest.main()
