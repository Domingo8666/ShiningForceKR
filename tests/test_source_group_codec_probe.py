from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.patch_io import PatchError  # noqa: E402
from tools.v5_1_source_group_codec_probe import (  # noqa: E402
    build_source_group_codec_probe,
    probe_source_group_codec,
    validate_source_group_codec_probe,
)


class SourceGroupCodecProbeTests(unittest.TestCase):
    def test_preserves_vector_failure_as_a_safe_result(self) -> None:
        records = [
            {
                "ordinal": 0,
                "payload_start": 1,
                "record_length_bytes": 1,
                "payload": b"\x00",
            }
        ]
        with patch(
            "tools.v5_1_source_group_codec_probe.load_trees_at",
            side_effect=PatchError("invalid vector"),
        ):
            counts, local = probe_source_group_codec(
                source=b"\x00" * 0x30000,
                records=records,
            )
        self.assertFalse(counts["vector_parse_succeeded"])
        self.assertEqual(counts["attempted_record_count"], 1)
        self.assertEqual(counts["records_without_roundtrip_count"], 1)
        self.assertEqual(local["vector_error"], "PatchError")

    def test_builds_safe_counts_and_rejects_symbol_leakage(self) -> None:
        artifact = build_source_group_codec_probe(
            source_sha256="1" * 64,
            target_sha256="2" * 64,
            source_group_extract_sha256="3" * 64,
            source_group_delta_sha256="4" * 64,
            selector=2,
            record_count=3,
            codec_probe={
                "vector_parse_succeeded": True,
                "populated_context_count": 2,
                "zero_length_record_count": 0,
                "attempted_record_count": 3,
                "candidate_context_roundtrip_count": 5,
                "candidate_symbol_stream_count": 4,
                "canonical_context_roundtrip_record_count": 2,
                "records_with_any_roundtrip_count": 2,
                "records_with_unique_stream_count": 1,
                "records_with_multiple_streams_count": 1,
                "records_without_roundtrip_count": 1,
            },
            captured_utc="2026-07-30T18:30:00Z",
        )
        validate_source_group_codec_probe(artifact)
        self.assertEqual(
            artifact["status"],
            "source-group-codec-candidates-partial",
        )
        for field, value in (
            ("initial_contexts", [0xC9]),
            ("symbols_hex", ["0x01", "0xC9"]),
            ("source_text", "待て"),
            ("codepoints", ["U+5F85"]),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_source_group_codec_probe(unsafe)


if __name__ == "__main__":
    unittest.main()
