from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_font_transfer_source import (  # noqa: E402
    analyze_font_transfer_trace,
    build_font_transfer_source,
    validate_font_transfer_source,
)


def _line(
    bank: int,
    pc: int,
    *,
    a: int = 0,
    bc: int = 0,
    de: int = 0,
    hl: int = 0,
    opcodes: str,
) -> str:
    return (
        f"{bank:02X}:{pc:04X} A:{a:02X} BC:{bc:04X} "
        f"DE:{de:04X} HL:{hl:04X} SP:DFF0  {opcodes}"
    )


def _runtime_entry() -> dict[str, object]:
    return {
        "physical_start": 0x20913,
        "logical_start": 0x4913,
        "mapped_bank": 8,
        "record_length_bytes": 16,
    }


class FontTransferSourceTests(unittest.TestCase):
    def test_tracks_font_read_through_ram_to_vdp(self) -> None:
        lines = [
            _line(8, 0x5000, a=0x22, opcodes="32 FF FF"),
            _line(8, 0x5003, a=0x41, hl=0x8123, opcodes="7E"),
            _line(8, 0x5004, a=0x41, de=0xC100, opcodes="12"),
            _line(0x21, 0x7000, a=0x41, opcodes="D3 BE"),
        ]
        safe, local = analyze_font_transfer_trace(
            lines=lines,
            candidate_pages=[0, 1, 4],
            initial_slot1_bank=1,
            initial_slot2_bank=0x10,
        )
        self.assertEqual(safe["candidate_page_count_after"], 2)
        self.assertEqual(safe["observed_candidate_bank_count"], 1)
        self.assertEqual(safe["mapper_write_count"], 1)
        self.assertEqual(safe["candidate_font_read_count"], 1)
        self.assertEqual(safe["ram_buffer_link_count"], 1)
        self.assertEqual(local["candidate_pages_after"], [0, 1])

    def test_block_transfer_origin_reaches_outi(self) -> None:
        lines = [
            _line(8, 0x5000, a=0x23, opcodes="32 FF FF"),
            _line(
                8,
                0x5003,
                bc=1,
                de=0xC101,
                hl=0x8101,
                opcodes="ED A0",
            ),
            _line(
                0x21,
                0x7000,
                bc=0x00BE,
                hl=0xC101,
                opcodes="ED A3",
            ),
        ]
        safe, _ = analyze_font_transfer_trace(
            lines=lines,
            candidate_pages=[4, 8],
            initial_slot1_bank=1,
            initial_slot2_bank=0x10,
        )
        self.assertEqual(safe["candidate_page_count_after"], 1)
        self.assertEqual(safe["ram_buffer_link_count"], 1)

    def test_builds_confirmed_sanitized_artifact(self) -> None:
        artifact = build_font_transfer_source(
            target_sha256="1" * 64,
            source_mapping_sha256="2" * 64,
            source_renderer_trace_sha256="3" * 64,
            source_initial_trace_sha256="4" * 64,
            runtime_entry=_runtime_entry(),
            analysis={
                "candidate_page_count_before": 9,
                "candidate_page_count_after": 1,
                "candidate_bank_count_before": 9,
                "observed_candidate_bank_count": 1,
                "mapper_write_count": 4,
                "candidate_font_read_count": 12,
                "ram_buffer_link_count": 8,
            },
            captured_utc="2026-07-30T13:00:00Z",
        )
        validate_font_transfer_source(artifact)
        self.assertEqual(
            artifact["status"], "font-transfer-source-confirmed"
        )
        self.assertTrue(artifact["font_transfer_source_confirmed"])

    def test_rejects_exact_pages_or_addresses_in_safe_artifact(self) -> None:
        artifact = build_font_transfer_source(
            target_sha256="1" * 64,
            source_mapping_sha256="2" * 64,
            source_renderer_trace_sha256="3" * 64,
            source_initial_trace_sha256="4" * 64,
            runtime_entry=_runtime_entry(),
            analysis={
                "candidate_page_count_before": 9,
                "candidate_page_count_after": 9,
                "candidate_bank_count_before": 9,
                "observed_candidate_bank_count": 0,
                "mapper_write_count": 0,
                "candidate_font_read_count": 0,
                "ram_buffer_link_count": 0,
            },
            captured_utc="2026-07-30T13:00:00Z",
        )
        for field, unsafe_value in (
            ("candidate_pages", [7]),
            ("font_banks", [0x22]),
            ("read_addresses", [0x8123]),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = unsafe_value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_font_transfer_source(unsafe)


if __name__ == "__main__":
    unittest.main()
