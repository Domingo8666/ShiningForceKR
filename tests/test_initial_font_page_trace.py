from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_initial_font_page_trace import (  # noqa: E402
    build_initial_font_page_trace,
    resolve_pages_from_font_bank,
    runtime_entry_matches,
    validate_initial_font_page_trace,
)


def _runtime_entry() -> dict[str, object]:
    return {
        "physical_start": 0x20913,
        "logical_start": 0x4913,
        "mapped_bank": 8,
        "record_length_bytes": 16,
    }


class InitialFontPageTraceTests(unittest.TestCase):
    def test_renderer_runtime_entry_may_include_provenance_fields(self) -> None:
        renderer_entry = {
            **_runtime_entry(),
            "selector_de": 2,
            "entry_ordinal": 147,
        }
        self.assertTrue(
            runtime_entry_matches(renderer_entry, _runtime_entry())
        )

    def test_filters_pages_by_the_observed_font_bank(self) -> None:
        self.assertEqual(
            resolve_pages_from_font_bank(
                [21, 22, 40, 80],
                0x22 + 21 // 4,
            ),
            [21, 22],
        )

    def test_builds_a_confirmed_page_artifact(self) -> None:
        artifact = build_initial_font_page_trace(
            target_sha256="1" * 64,
            source_mapping_sha256="2" * 64,
            runtime_entry=_runtime_entry(),
            candidate_pages=[21, 40, 80],
            mapped_font_bank=0x22 + 40 // 4,
            captured_utc="2026-07-30T12:00:00Z",
        )
        validate_initial_font_page_trace(artifact)
        self.assertEqual(artifact["status"], "initial-font-page-confirmed")
        self.assertTrue(artifact["runtime_initial_page_confirmed"])
        self.assertNotIn("mapped_font_bank", artifact)
        self.assertNotIn("confirmed_initial_page", artifact)

    def test_keeps_multiple_pages_unconfirmed(self) -> None:
        artifact = build_initial_font_page_trace(
            target_sha256="1" * 64,
            source_mapping_sha256="2" * 64,
            runtime_entry=_runtime_entry(),
            candidate_pages=[20, 21, 22],
            mapped_font_bank=0x22 + 20 // 4,
            captured_utc="2026-07-30T12:00:00Z",
        )
        self.assertEqual(
            artifact["status"],
            "initial-font-page-candidates-remain",
        )
        self.assertEqual(artifact["candidate_page_count_after"], 3)
        self.assertFalse(artifact["runtime_initial_page_confirmed"])

    def test_rejects_published_candidate_pages(self) -> None:
        artifact = build_initial_font_page_trace(
            target_sha256="1" * 64,
            source_mapping_sha256="2" * 64,
            runtime_entry=_runtime_entry(),
            candidate_pages=[21, 40],
            mapped_font_bank=0x22 + 21 // 4,
            captured_utc="2026-07-30T12:00:00Z",
        )
        unsafe = deepcopy(artifact)
        unsafe["candidate_pages"] = [21]
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            validate_initial_font_page_trace(unsafe)


if __name__ == "__main__":
    unittest.main()
