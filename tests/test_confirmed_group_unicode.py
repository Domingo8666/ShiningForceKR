from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_confirmed_group_unicode import (  # noqa: E402
    analyze_confirmed_group_unicode,
    build_confirmed_group_unicode,
    validate_confirmed_group_unicode,
)


def _records() -> list[dict[str, object]]:
    return [
        {
            "entry_id": "group-02/000",
            "symbols_hex": ["0x02", "0xC9"],
        },
        {
            "entry_id": "group-02/001",
            "symbols_hex": ["0x03", "0xC9"],
        },
    ]


def _catalog() -> list[dict[str, object]]:
    return [
        {
            "page": 0,
            "symbol": 0x02,
            "codepoints": [0xAC00],
            "characters": ["가"],
        },
        {
            "page": 0,
            "symbol": 0x03,
            "codepoints": [0xB098],
            "characters": ["나"],
        },
        {
            "page": 4,
            "symbol": 0x02,
            "codepoints": [0xB2E4],
            "characters": ["다"],
        },
    ]


class ConfirmedGroupUnicodeTests(unittest.TestCase):
    def test_full_group_coverage_narrows_the_page_candidates(self) -> None:
        safe, local = analyze_confirmed_group_unicode(
            records=_records(),
            catalog_entries=_catalog(),
            candidate_pages=[0, 4],
        )
        self.assertEqual(safe["candidate_page_count_after"], 1)
        self.assertEqual(safe["unmatched_glyph_count"], 0)
        self.assertEqual(local["candidate_pages_after"], [0])

    def test_marks_unique_coverage_as_runtime_unconfirmed(self) -> None:
        artifact = build_confirmed_group_unicode(
            target_sha256="1" * 64,
            source_group_extract_sha256="2" * 64,
            source_visible_mapping_sha256="3" * 64,
            source_font_catalog_sha256="4" * 64,
            selector=2,
            record_count=2,
            mapping={
                "candidate_page_count_before": 2,
                "candidate_page_count_after": 1,
                "best_candidate_bank_count": 1,
                "visible_glyph_count": 2,
                "unique_glyph_count": 2,
                "ambiguous_glyph_count": 0,
                "unmatched_glyph_count": 0,
                "control_symbol_count": 2,
                "terminator_count": 2,
                "page_select_count": 0,
                "records_with_page_select": 0,
            },
            captured_utc="2026-07-30T14:00:00Z",
        )
        validate_confirmed_group_unicode(artifact)
        self.assertEqual(
            artifact["status"],
            "group-font-page-coverage-unique",
        )
        self.assertFalse(artifact["runtime_initial_page_confirmed"])

    def test_rejects_published_candidate_pages_or_text(self) -> None:
        artifact = build_confirmed_group_unicode(
            target_sha256="1" * 64,
            source_group_extract_sha256="2" * 64,
            source_visible_mapping_sha256="3" * 64,
            source_font_catalog_sha256="4" * 64,
            selector=2,
            record_count=2,
            mapping={
                "candidate_page_count_before": 2,
                "candidate_page_count_after": 2,
                "best_candidate_bank_count": 2,
                "visible_glyph_count": 2,
                "unique_glyph_count": 1,
                "ambiguous_glyph_count": 0,
                "unmatched_glyph_count": 1,
                "control_symbol_count": 2,
                "terminator_count": 2,
                "page_select_count": 0,
                "records_with_page_select": 0,
            },
            captured_utc="2026-07-30T14:00:00Z",
        )
        for field, value in (
            ("candidate_pages", [0, 4]),
            ("decoded_text", "가나"),
            ("codepoints", ["U+AC00"]),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_confirmed_group_unicode(unsafe)


if __name__ == "__main__":
    unittest.main()
