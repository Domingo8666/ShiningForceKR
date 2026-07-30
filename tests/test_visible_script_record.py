from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from tools.v5_1_visible_script_record import (
    extract_visible_script_record,
    validate_visible_script_roundtrip,
)


ROOT = Path(__file__).resolve().parents[1]


class VisibleScriptRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.patch = (
            ROOT / "patch" / "Final_Conflict_Japan_to_Korean_v5.1.bps"
        ).read_bytes()
        cls.proof = json.loads(
            (
                ROOT
                / "analysis"
                / "device"
                / "v5_1_latest_poc_expansion_proof.json"
            ).read_text(encoding="utf-8")
        )

    def test_extracts_and_roundtrips_without_publishing_symbols(self) -> None:
        local, safe = extract_visible_script_record(
            self.patch,
            self.proof,
        )
        validate_visible_script_roundtrip(safe)
        self.assertEqual(local["encoded_bits"], 100)
        self.assertEqual(len(local["symbols_hex"]), 19)
        self.assertNotIn("symbols_hex", safe)
        self.assertEqual(safe["roundtrip"]["trailing_storage_bits"], 28)
        self.assertTrue(safe["roundtrip"]["bit_exact"])

    def test_validator_rejects_a_false_roundtrip(self) -> None:
        _, safe = extract_visible_script_record(
            self.patch,
            self.proof,
        )
        safe = copy.deepcopy(safe)
        safe["roundtrip"]["bit_exact"] = False
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            validate_visible_script_roundtrip(safe)


if __name__ == "__main__":
    unittest.main()
