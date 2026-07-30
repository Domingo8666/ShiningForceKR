from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.patch_io import sha256_file
from tools.v5_1_decoder_register_trace import (
    ARTIFACT_KIND,
    PUBLISH_RELATIVE_PATH,
    decoder_register_trace_needed,
    validate_decoder_register_trace,
)


def valid_trace(target_sha256: str = "1" * 64) -> dict[str, object]:
    states = [
        {
            "pc": 0x33FA,
            "af": 0x1200,
            "bc": 0x9300,
            "de": 2,
            "hl": 0x4000,
            "sp": 0xDFF0,
            "slot0_bank": 0,
            "slot1_bank": 8,
            "slot2_bank": 0x20,
        },
        {
            "pc": 0x33FD,
            "af": 0x1200,
            "bc": 0x9300,
            "de": 2,
            "hl": 0x3FE8,
            "sp": 0xDFF0,
            "slot0_bank": 0,
            "slot1_bank": 8,
            "slot2_bank": 0x20,
        },
    ]
    return {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": 1,
        "target_sha256": target_sha256,
        "status": "decoder-register-trace-captured",
        "captured_utc": "2026-07-30T05:00:00Z",
        "decoder_entry": 0x33FA,
        "selector_de": 2,
        "step_count": 1,
        "states": states,
        "translation_build_eligible": False,
        "next_checkpoint": "resolve-decoder-bc-register-role",
    }


class DecoderRegisterTraceTests(unittest.TestCase):
    def test_trace_schema_contains_no_rom_bytes_or_paths(self) -> None:
        trace = valid_trace()
        validate_decoder_register_trace(trace)
        serialized = json.dumps(trace)
        self.assertNotIn("rom", serialized.lower())
        self.assertNotIn("\\", serialized)

    def test_trace_requires_exact_state_fields(self) -> None:
        trace = valid_trace()
        trace["states"][0]["opcode"] = 0x21
        with self.assertRaisesRegex(ValueError, "state fields"):
            validate_decoder_register_trace(trace)

    def test_failed_fixed_count_range_requests_one_trace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "build/Final_Conflict_Korean_v5.1.gg"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"target")
            diagnostic = {
                "runtime_failure": {
                    "failure_stage": "test-patch-fixed-count-read-range"
                }
            }
            diagnostic_path = (
                root
                / "analysis/device/v5_1_latest_runtime_diagnostic.json"
            )
            diagnostic_path.parent.mkdir(parents=True)
            diagnostic_path.write_text(
                json.dumps(diagnostic),
                encoding="utf-8",
            )
            self.assertTrue(decoder_register_trace_needed(root))

            trace_path = root / PUBLISH_RELATIVE_PATH
            trace_path.write_text(
                json.dumps(valid_trace(sha256_file(target))),
                encoding="utf-8",
            )
            self.assertFalse(decoder_register_trace_needed(root))

    def test_failed_trace_operation_requests_a_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "build/Final_Conflict_Korean_v5.1.gg"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"target")
            diagnostic_path = (
                root
                / "analysis/device/v5_1_latest_runtime_diagnostic.json"
            )
            diagnostic_path.parent.mkdir(parents=True)
            diagnostic_path.write_text(
                json.dumps(
                    {
                        "runtime_failure": {
                            "failure_stage": "decoder-register-trace"
                        }
                    }
                ),
                encoding="utf-8",
            )
            self.assertTrue(decoder_register_trace_needed(root))


if __name__ == "__main__":
    unittest.main()
