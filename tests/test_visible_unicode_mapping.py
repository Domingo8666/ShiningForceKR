from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_visible_unicode_mapping import (  # noqa: E402
    map_visible_symbols,
    validate_visible_unicode_mapping,
)


def _catalog() -> list[dict[str, object]]:
    return [
        {
            "page": 6,
            "symbol": 0x11,
            "status": "unique",
            "codepoints": ["U+D55C"],
            "characters": ["한"],
        },
        {
            "page": 6,
            "symbol": 0x04,
            "status": "unique",
            "codepoints": ["U+B2E4"],
            "characters": ["다"],
        },
    ]


def _artifact() -> dict[str, object]:
    return {
        "artifact_kind": "sanitized-v5-1-visible-unicode-mapping",
        "schema_version": 3,
        "status": "visible-glyph-map-resolved",
        "target_sha256": "1" * 64,
        "captured_utc": "2026-07-30T11:00:00Z",
        "runtime_entry": {
            "physical_start": 0x20913,
            "logical_start": 0x4913,
            "mapped_bank": 8,
            "record_length_bytes": 16,
        },
        "mapping": {
            "decoded_symbol_count": 6,
            "initial_page": 0,
            "initial_page_candidate_count": 0,
            "implicit_initial_page_used": False,
            "page_select_count": 1,
            "visible_glyph_count": 2,
            "unique_glyph_count": 2,
            "ambiguous_glyph_count": 0,
            "unmatched_glyph_count": 0,
            "control_symbol_count": 4,
            "terminator_count": 1,
        },
        "renderer_chain_confirmed": True,
        "local_payload_policy": (
            "symbols-codepoints-characters-and-text-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": "extract-full-script-record-set",
    }


class VisibleUnicodeMappingTests(unittest.TestCase):
    def test_maps_verified_page_glyphs(self) -> None:
        safe, local = map_visible_symbols(
            [0x5F, 0x02, 0x08, 0x11, 0x04, 0xC9],
            _catalog(),
        )
        self.assertEqual(safe["page_select_count"], 1)
        self.assertEqual(safe["initial_page"], 0)
        self.assertEqual(safe["initial_page_candidate_count"], 0)
        self.assertFalse(safe["implicit_initial_page_used"])
        self.assertEqual(safe["visible_glyph_count"], 2)
        self.assertEqual(safe["unique_glyph_count"], 2)
        self.assertEqual(
            [
                token["characters"][0]
                for token in local["tokens"]
                if token["kind"] == "glyph"
            ],
            ["한", "다"],
        )

    def test_uses_page_zero_as_an_unconfirmed_initial_candidate(self) -> None:
        catalog = [
            {
                "page": 0,
                "symbol": 0x02,
                "status": "unique",
                "codepoints": ["U+AC00"],
                "characters": ["가"],
            },
            {
                "page": 0,
                "symbol": 0x03,
                "status": "unique",
                "codepoints": ["U+AC01"],
                "characters": ["각"],
            },
        ]
        safe, local = map_visible_symbols([0x02, 0x03, 0xC9], catalog)
        self.assertEqual(safe["visible_glyph_count"], 2)
        self.assertEqual(safe["initial_page"], 0)
        self.assertEqual(safe["initial_page_candidate_count"], 1)
        self.assertTrue(safe["implicit_initial_page_used"])
        self.assertEqual(local["tokens"][0]["characters"], ["가"])

    def test_reports_tied_implicit_initial_page_candidates(self) -> None:
        catalog = [
            {
                "page": page,
                "symbol": 0x02,
                "status": "unique",
                "codepoints": [f"U+{0xAC00 + page:04X}"],
                "characters": [chr(0xAC00 + page)],
            }
            for page in (0, 1)
        ]
        safe, local = map_visible_symbols([0x02, 0xC9], catalog)
        self.assertEqual(safe["initial_page"], 0)
        self.assertEqual(safe["initial_page_candidate_count"], 2)
        self.assertEqual(
            [item["page"] for item in local["initial_page_candidates"]],
            [0, 1],
        )

    def test_counts_unmatched_glyph_without_guessing(self) -> None:
        safe, _ = map_visible_symbols(
            [0x5F, 0x02, 0x08, 0x03, 0xC9],
            _catalog(),
        )
        self.assertEqual(safe["unmatched_glyph_count"], 1)
        self.assertEqual(safe["unique_glyph_count"], 0)

    def test_rejects_truncated_page_select(self) -> None:
        with self.assertRaisesRegex(ValueError, "truncated"):
            map_visible_symbols([0x5F, 0x02], _catalog())

    def test_validates_safe_artifact(self) -> None:
        validate_visible_unicode_mapping(_artifact())

    def test_rejects_raw_text_field(self) -> None:
        unsafe = deepcopy(_artifact())
        unsafe["text"] = "한다"
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_visible_unicode_mapping(unsafe)

    def test_rejects_inconsistent_resolved_status(self) -> None:
        value = _artifact()
        value["mapping"]["unmatched_glyph_count"] = 1
        value["mapping"]["visible_glyph_count"] = 3
        with self.assertRaisesRegex(ValueError, "status"):
            validate_visible_unicode_mapping(value)

    def test_validates_tied_implicit_pages_as_incomplete(self) -> None:
        value = _artifact()
        value["status"] = "visible-glyph-map-incomplete"
        value["mapping"]["initial_page"] = 21
        value["mapping"]["initial_page_candidate_count"] = 9
        value["mapping"]["implicit_initial_page_used"] = True
        value["mapping"]["page_select_count"] = 0
        value["next_checkpoint"] = "confirm-runtime-initial-font-page"
        validate_visible_unicode_mapping(value)


if __name__ == "__main__":
    unittest.main()
