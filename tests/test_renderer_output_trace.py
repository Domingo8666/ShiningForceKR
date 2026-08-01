from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_renderer_output_trace import (  # noqa: E402
    _classify_vdp_output,
    _outer_return_address,
    _read_trace_window,
    analyze_trace_lines,
    build_renderer_output_trace,
    validate_renderer_output_trace,
)


class _TracePageClient:
    def __init__(self, lines: list[str]) -> None:
        self.lines = lines
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call(
        self,
        name: str,
        arguments: dict[str, object],
    ) -> dict[str, object]:
        self.calls.append((name, arguments))
        start = int(arguments["start"])
        count = int(arguments["count"])
        page = self.lines[start : start + count]
        return {
            "total_entries": len(self.lines),
            "start": start,
            "count": len(page),
            "lines": page,
        }


def _visible_roundtrip() -> dict[str, object]:
    return {
        "artifact_kind": "sanitized-v5-1-visible-script-roundtrip",
        "schema_version": 1,
        "status": "exact-visible-record-roundtrip-pass",
        "baseline_target_sha256": "1" * 64,
        "source_expansion_test_sha256": "2" * 64,
        "runtime_entry": {
            "physical_start": 0x20913,
            "logical_start": 0x4913,
            "mapped_bank": 8,
            "record_length_bytes": 16,
        },
        "roundtrip": {
            "source_independent_bytes": True,
            "decoded_symbol_count": 19,
            "terminator_count": 1,
            "encoded_bits": 100,
            "storage_capacity_bits": 128,
            "trailing_storage_bits": 28,
            "reencoded_bits": 100,
            "bit_exact": True,
        },
        "local_payload_policy": "symbols-and-text-local-only",
        "translation_build_eligible": False,
        "next_checkpoint": "map-visible-record-glyphs-to-unicode",
    }


def _trace_summary(*, data_writes: int = 1) -> dict[str, int]:
    return {
        "trace_entries_observed": 5,
        "parsed_instruction_count": 4,
        "vdp_data_write_count": data_writes,
        "vdp_control_write_count": 1,
        "vdp_event_line_count": 0,
        "unique_output_pattern_count": 2 if data_writes else 1,
        "candidate_entry_hit_count": 1,
        "unique_candidate_entry_count": 1,
        "primary_renderer_entry_hit_count": 1,
        "primary_renderer_data_write_count": data_writes,
        "primary_renderer_control_write_count": 1,
        "decoder_to_renderer_data_write_count": data_writes,
        "post_renderer_data_write_count": data_writes,
    }


class RendererOutputTraceTests(unittest.TestCase):
    def test_classifies_immediate_vdp_data_output(self) -> None:
        event = _classify_vdp_output(
            {
                "opcodes": bytes((0xD3, 0xBE)),
                "registers": {
                    "a": 0x42,
                    "bc": 0,
                    "de": 0,
                    "hl": 0,
                    "sp": 0,
                },
            }
        )
        self.assertEqual(event, {"port": 0xBE, "value": 0x42})

    def test_classifies_register_vdp_control_output(self) -> None:
        event = _classify_vdp_output(
            {
                "opcodes": bytes((0xED, 0x59)),
                "registers": {
                    "a": 0,
                    "bc": 0x12BF,
                    "de": 0x3456,
                    "hl": 0,
                    "sp": 0,
                },
            }
        )
        self.assertEqual(event, {"port": 0xBF, "value": 0x56})

    def test_ignores_non_vdp_output(self) -> None:
        self.assertIsNone(
            _classify_vdp_output(
                {
                    "opcodes": bytes((0xD3, 0x7F)),
                    "registers": {"a": 1, "bc": 0, "de": 0, "hl": 0},
                }
            )
        )

    def test_classifies_repeating_block_vdp_data_output(self) -> None:
        event = _classify_vdp_output(
            {
                "opcodes": bytes((0xED, 0xB3)),
                "registers": {
                    "a": 0,
                    "bc": 0x20BE,
                    "de": 0,
                    "hl": 0xC100,
                    "sp": 0,
                },
            }
        )
        self.assertEqual(event, {"port": 0xBE})

    def test_analyzes_trace_without_publishing_values(self) -> None:
        summary, local = analyze_trace_lines(
            [
                (
                    "00:3411 A:42 BC:0000 DE:0000 HL:0000 SP:D000  "
                    "D3 BE"
                ),
                (
                    "00:3413 A:00 BC:12BF DE:3456 HL:0000 SP:D000  "
                    "ED 59"
                ),
            ]
        )
        self.assertEqual(summary["vdp_data_write_count"], 1)
        self.assertEqual(summary["vdp_control_write_count"], 1)
        self.assertEqual(summary["candidate_entry_hit_count"], 1)
        self.assertNotIn("vdp_outputs", summary)
        self.assertEqual(local["vdp_outputs"][0]["value"], 0x42)

    def test_prefers_exact_io_events_without_double_counting(self) -> None:
        summary, local = analyze_trace_lines(
            [
                (
                    "00:3411 A:42 BC:0000 DE:0000 HL:0000 SP:D000  "
                    "D3 BE"
                ),
                "  [IO]   OUT     Port:$BE  Value:$42",
                "  [IO]   OUT     Port:$BF  Value:$80",
            ]
        )
        self.assertEqual(summary["vdp_data_write_count"], 1)
        self.assertEqual(summary["vdp_control_write_count"], 1)
        self.assertEqual(summary["vdp_event_line_count"], 2)
        self.assertEqual(len(local["vdp_io_events"]), 2)

    def test_attributes_primary_korean_renderer_outputs(self) -> None:
        summary, _ = analyze_trace_lines(
            [
                (
                    "21:7000 A:42 BC:0000 DE:0000 HL:0000 SP:D000  "
                    "D3 BE"
                ),
                (
                    "21:7A20 A:00 BC:12BF DE:3456 HL:0000 SP:D000  "
                    "ED 59"
                ),
            ]
        )
        self.assertEqual(summary["primary_renderer_entry_hit_count"], 1)
        self.assertEqual(summary["primary_renderer_data_write_count"], 1)
        self.assertEqual(summary["primary_renderer_control_write_count"], 1)

    def test_counts_data_after_primary_renderer_control(self) -> None:
        summary, _ = analyze_trace_lines(
            [
                (
                    "21:7000 A:00 BC:0000 DE:0000 HL:0000 SP:D000  "
                    "C3 00 7A"
                ),
                (
                    "21:706A A:38 BC:0000 DE:0000 HL:0000 SP:D000  "
                    "D3 BF"
                ),
                (
                    "00:1234 A:42 BC:0000 DE:0000 HL:0000 SP:D000  "
                    "D3 BE"
                ),
            ]
        )
        self.assertEqual(summary["primary_renderer_entry_hit_count"], 1)
        self.assertEqual(summary["primary_renderer_control_write_count"], 1)
        self.assertEqual(summary["decoder_to_renderer_data_write_count"], 0)
        self.assertEqual(summary["post_renderer_data_write_count"], 1)

    def test_counts_decoder_data_before_primary_renderer_control(self) -> None:
        summary, _ = analyze_trace_lines(
            [
                (
                    "00:3411 A:42 BC:0000 DE:0000 HL:0000 SP:D000  "
                    "D3 BE"
                ),
                (
                    "21:7000 A:00 BC:0000 DE:0000 HL:0000 SP:D000  "
                    "C3 00 7A"
                ),
                (
                    "21:706A A:38 BC:0000 DE:0000 HL:0000 SP:D000  "
                    "D3 BF"
                ),
            ]
        )
        self.assertEqual(summary["candidate_entry_hit_count"], 1)
        self.assertEqual(summary["decoder_to_renderer_data_write_count"], 1)
        self.assertEqual(summary["post_renderer_data_write_count"], 0)

    def test_requires_primary_control_after_the_renderer_entry(self) -> None:
        summary, _ = analyze_trace_lines(
            [
                (
                    "21:706A A:38 BC:0000 DE:0000 HL:0000 SP:D000  "
                    "D3 BF"
                ),
                (
                    "21:7000 A:00 BC:0000 DE:0000 HL:0000 SP:D000  "
                    "C3 00 7A"
                ),
                (
                    "00:1234 A:42 BC:0000 DE:0000 HL:0000 SP:D000  "
                    "D3 BE"
                ),
            ]
        )
        self.assertEqual(summary["post_renderer_data_write_count"], 0)

    def test_selects_outermost_call_return(self) -> None:
        self.assertEqual(
            _outer_return_address(
                {
                    "stack": [
                        {"return": "$402A"},
                        {"return": "$1234"},
                    ]
                },
                current_pc=0x340C,
            ),
            0x1234,
        )

    def test_reads_trace_in_api_sized_pages(self) -> None:
        client = _TracePageClient([f"line-{index}" for index in range(2205)])
        lines, pages = _read_trace_window(client, start=100, end=2205)
        self.assertEqual(len(lines), 2105)
        self.assertEqual([page["count"] for page in pages], [1000, 1000, 105])
        self.assertEqual(
            [int(arguments["count"]) for _, arguments in client.calls],
            [1000, 1000, 105],
        )

    def test_validates_captured_safe_artifact(self) -> None:
        artifact = build_renderer_output_trace(
            target_sha256="1" * 64,
            visible_roundtrip=_visible_roundtrip(),
            selector_de=2,
            entry_ordinal=147,
            trace_summary=_trace_summary(),
            captured_utc="2026-07-30T06:00:00Z",
            bounded_frame_windows=2,
        )
        validate_renderer_output_trace(artifact)
        self.assertTrue(artifact["consumer_chain_confirmed"])
        self.assertEqual(
            artifact["renderer_window"]["bounded_frame_windows"],
            2,
        )
        self.assertNotIn("symbols", artifact)
        self.assertNotIn("opcodes", artifact)

    def test_builds_non_promoting_no_output_artifact(self) -> None:
        artifact = build_renderer_output_trace(
            target_sha256="1" * 64,
            visible_roundtrip=_visible_roundtrip(),
            selector_de=2,
            entry_ordinal=147,
            trace_summary=_trace_summary(data_writes=0),
            captured_utc="2026-07-30T06:00:00Z",
        )
        self.assertEqual(
            artifact["status"],
            "renderer-output-events-not-observed",
        )
        self.assertFalse(artifact["consumer_chain_confirmed"])
        self.assertFalse(artifact["translation_build_eligible"])

    def test_does_not_promote_unrelated_frame_output(self) -> None:
        summary = _trace_summary()
        summary["primary_renderer_entry_hit_count"] = 0
        summary["primary_renderer_data_write_count"] = 0
        summary["decoder_to_renderer_data_write_count"] = 0
        summary["post_renderer_data_write_count"] = 0
        artifact = build_renderer_output_trace(
            target_sha256="1" * 64,
            visible_roundtrip=_visible_roundtrip(),
            selector_de=2,
            entry_ordinal=147,
            trace_summary=summary,
            captured_utc="2026-07-30T06:00:00Z",
        )
        self.assertEqual(
            artifact["status"],
            "renderer-output-events-not-observed",
        )
        self.assertFalse(artifact["consumer_chain_confirmed"])

    def test_rejects_raw_or_extra_fields(self) -> None:
        artifact = build_renderer_output_trace(
            target_sha256="1" * 64,
            visible_roundtrip=_visible_roundtrip(),
            selector_de=2,
            entry_ordinal=147,
            trace_summary=_trace_summary(),
            captured_utc="2026-07-30T06:00:00Z",
        )
        unsafe = deepcopy(artifact)
        unsafe["raw_trace_lines"] = ["secret"]
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_renderer_output_trace(unsafe)

    def test_rejects_inconsistent_consumer_gate(self) -> None:
        artifact = build_renderer_output_trace(
            target_sha256="1" * 64,
            visible_roundtrip=_visible_roundtrip(),
            selector_de=2,
            entry_ordinal=147,
            trace_summary=_trace_summary(),
            captured_utc="2026-07-30T06:00:00Z",
        )
        artifact["consumer_chain_confirmed"] = False
        with self.assertRaisesRegex(ValueError, "consumer gate"):
            validate_renderer_output_trace(artifact)


if __name__ == "__main__":
    unittest.main()
