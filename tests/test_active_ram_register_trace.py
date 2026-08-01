from __future__ import annotations

import unittest

from tools.v5_1_active_ram_register_trace import (
    _defined_registers,
    _definition_source_class,
    analyze_register_trace,
    build_active_ram_register_trace,
    validate_active_ram_register_trace,
)


class ActiveRamRegisterTraceTests(unittest.TestCase):
    def test_detects_common_z80_register_definitions(self) -> None:
        self.assertEqual(_defined_registers(bytes.fromhex("3E 12")), {"a"})
        self.assertEqual(_defined_registers(bytes.fromhex("7E")), {"a"})
        self.assertEqual(_defined_registers(bytes.fromhex("21 00 C0")), {"hl", "h", "l"})
        self.assertEqual(_defined_registers(bytes.fromhex("77")), set())

    def test_selects_the_last_memory_definition_before_the_writer(self) -> None:
        lines = [
            "00:1000 A:00 BC:0000 DE:0000 HL:C100 SP:DFF0  3E 12",
            "00:1002 A:12 BC:0000 DE:0000 HL:C100 SP:DFF0  7E",
            "00:1003 A:34 BC:0000 DE:0000 HL:C100 SP:DFF0  23",
        ]
        counts, local = analyze_register_trace(lines, "a")
        self.assertEqual(counts["source_definition_candidate_count"], 2)
        self.assertEqual(local["selected"]["definition_kind"], "memory")
        self.assertEqual(_definition_source_class(local), "system-ram")
        safe = build_active_ram_register_trace(
            target_sha256="a" * 64,
            source_active_ram_writer_sha256="b" * 64,
            analysis=counts,
            writer_instance_confirmed=True,
            definition_source_class="system-ram",
            captured_utc="2026-08-01T00:00:00Z",
        )
        validate_active_ram_register_trace(safe)
        self.assertTrue(safe["register_definition_confirmed"])
        self.assertEqual(safe["next_checkpoint"], "trace-active-register-ram-source")


if __name__ == "__main__":
    unittest.main()
