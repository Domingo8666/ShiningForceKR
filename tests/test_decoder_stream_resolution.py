from __future__ import annotations

from pathlib import Path
import unittest

from tools.v5_1_decoder_stream_resolution import (
    build_decoder_stream_resolution,
    validate_decoder_stream_resolution,
)


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patch" / "Final_Conflict_Japan_to_Korean_v5.1.bps"


def observation(start: int, next_start: int) -> dict[str, object]:
    reads = []
    for physical, logical in ((start, 0x43DE), (next_start, 0x43E8)):
        reads.append(
            {
                "slot": 1,
                "logical_access": logical,
                "physical_file_offset": physical,
                "mapped_bank": 8,
                "instruction_bank": 0,
                "instruction_pc": 0x3406,
                "pc_after": 0x3407,
                "physical_pc_after": 0x3407,
                "operand_kind": "hl-indirect",
                "classification": "source-region",
            }
        )
    reads.extend(
        [
            {
                "slot": 2,
                "logical_access": 0x810E,
                "physical_file_offset": 0x8010E,
                "mapped_bank": 0x20,
                "instruction_bank": 0,
                "instruction_pc": 0x343D,
                "pc_after": 0x343E,
                "physical_pc_after": 0x343E,
                "operand_kind": "hl-indirect",
                "classification": "korean-huffman-vector",
            },
            {
                "slot": 2,
                "logical_access": 0x8418,
                "physical_file_offset": 0x80418,
                "mapped_bank": 0x20,
                "instruction_bank": 0,
                "instruction_pc": 0x346B,
                "pc_after": 0x346C,
                "physical_pc_after": 0x346C,
                "operand_kind": "hl-indirect",
                "classification": "korean-huffman-tree",
            },
        ]
    )
    return {
        "artifact_kind": "sanitized-text-engine-observation",
        "schema_version": 5,
        "target_sha256": "a" * 64,
        "status": "text-decoder-observed",
        "probe": {
            "emulator": "Gearsystem",
            "emulator_version": "3.9.14",
            "system": "gamegear",
            "frame_sync": "debug-status-paused",
            "route": "cold-boot-attract-button-matrix",
            "anchor_kind": "text-decoder-entry",
            "frame_budget": 18_600,
            "mappings_attempted": [
                {
                    "probe_file_offset": 0x33FA,
                    "slot": 0,
                    "expected_bank": 0,
                    "logical_address": 0x33FA,
                }
            ],
        },
        "hit": {
            "probe_file_offset": 0x33FA,
            "slot": 0,
            "expected_bank": 0,
            "logical_address": 0x33FA,
            "pc_after": 0x33FA,
            "physical_pc_after": 0x33FA,
            "executing_bank": 0,
            "mapper_control": 0,
            "slot0_bank": 0,
            "slot1_bank": 8,
            "slot2_bank": 6,
            "registers": {
                "af": 0,
                "bc": 0,
                "de": 0,
                "hl": 0,
                "ix": 0,
                "iy": 0,
                "sp": 0,
            },
            "trace_entries": 0,
            "call_stack_depth": 1,
        },
        "decoder_reads": reads,
        "renderer_hook_reached": False,
        "text_decoder_reached": True,
        "translation_build_eligible": False,
        "next_checkpoint": "resolve-decoder-rom-reads",
    }


class DecoderStreamResolutionTests(unittest.TestCase):
    def test_runtime_stream_roundtrips_without_source_rom(self) -> None:
        patch = PATCH.read_bytes()
        start = 0x203DE
        next_start = 0x203E8
        resolution = build_decoder_stream_resolution(
            patch,
            observation(start, next_start),
        )
        validate_decoder_stream_resolution(resolution)
        self.assertTrue(resolution["consumer_evidence_confirmed"])
        self.assertEqual(resolution["selected_stream_index"], 0)
        self.assertEqual(resolution["streams"][0]["physical_start"], start)
        self.assertTrue(resolution["streams"][0]["roundtrip_exact"])

    def test_validator_rejects_promoted_translation_gate(self) -> None:
        resolution = build_decoder_stream_resolution(
            PATCH.read_bytes(),
            observation(0x203DE, 0x203E8),
        )
        resolution["translation_build_eligible"] = True
        with self.assertRaises(ValueError):
            validate_decoder_stream_resolution(resolution)


if __name__ == "__main__":
    unittest.main()
