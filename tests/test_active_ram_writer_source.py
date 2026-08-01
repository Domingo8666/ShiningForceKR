from __future__ import annotations

import copy
import unittest

from tools.v5_1_active_ram_writer_source import (
    _writer_source,
    analyze_writer_sources,
    build_active_ram_writer_source,
    validate_active_ram_writer_source,
)


class ActiveRamWriterSourceTests(unittest.TestCase):
    def test_recovers_post_increment_and_decrement_block_copy_sources(self) -> None:
        self.assertEqual(
            _writer_source(
                {
                    "opcodes_hex": "edb0",
                    "operand_kind": "block-copy",
                    "registers": {"hl": 0xC121},
                }
            ),
            {
                "kind": "memory",
                "logical_address": 0xC120,
                "direction": "increment",
            },
        )
        self.assertEqual(
            _writer_source(
                {
                    "opcodes_hex": "edb8",
                    "operand_kind": "block-copy",
                    "registers": {"hl": 0x8122},
                }
            )["logical_address"],
            0x8123,
        )

    def test_classifies_supported_non_block_writers(self) -> None:
        self.assertEqual(
            _writer_source(
                {
                    "opcodes_hex": "77",
                    "operand_kind": "hl-indirect",
                    "registers": {"hl": 0xC120},
                }
            ),
            {"kind": "register", "register": "a"},
        )
        self.assertEqual(
            _writer_source(
                {
                    "opcodes_hex": "34",
                    "operand_kind": "hl-indirect",
                    "registers": {"hl": 0xC120},
                }
            ),
            {"kind": "memory", "logical_address": 0xC120, "direction": "same"},
        )
        self.assertEqual(
            _writer_source(
                {
                    "opcodes_hex": "edb2",
                    "operand_kind": "block-input",
                    "registers": {"hl": 0xC120},
                }
            ),
            {"kind": "io"},
        )
        self.assertEqual(
            _writer_source(
                {
                    "opcodes_hex": "3634",
                    "operand_kind": "hl-indirect",
                    "registers": {"hl": 0xC120},
                }
            ),
            {"kind": "immediate", "value": 0x34},
        )

    def test_classifies_a_local_system_ram_source_without_publishing_addresses(self) -> None:
        local = {
            "events": [
                {
                    "writer": {
                        "opcodes_hex": "eda0",
                        "operand_kind": "block-copy",
                        "registers": {"hl": 0xC121},
                    }
                }
            ],
            "analysis": {"latest_writer_event": {"0xC200": 0}},
        }
        counts, details = analyze_writer_sources(local)
        self.assertEqual(counts["system_ram_source_event_count"], 1)
        self.assertEqual(
            details["candidates"][0]["source"]["logical_address"], 0xC120
        )
        safe = build_active_ram_writer_source(
            target_sha256="a" * 64,
            source_active_ram_producer_sha256="b" * 64,
            analysis=counts,
            writer_sentinel_confirmed=True,
            captured_utc="2026-08-01T00:00:00Z",
        )
        validate_active_ram_writer_source(safe)
        self.assertEqual(safe["writer_source_class"], "system-ram")
        self.assertEqual(safe["next_checkpoint"], "trace-active-ram-writer-input")
        self.assertNotIn("logical_address", str(safe))

        invalid = copy.deepcopy(safe)
        invalid["analysis"]["system_ram_source_event_count"] = 0
        with self.assertRaises(ValueError):
            validate_active_ram_writer_source(invalid)


if __name__ == "__main__":
    unittest.main()
