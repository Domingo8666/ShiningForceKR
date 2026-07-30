from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_group_runtime_context import (  # noqa: E402
    build_group_runtime_context,
    validate_group_runtime_context,
)


class GroupRuntimeContextTests(unittest.TestCase):
    def test_builds_partial_runtime_context_coverage(self) -> None:
        artifact = build_group_runtime_context(
            target_sha256="1" * 64,
            source_group_extract_sha256="2" * 64,
            source_context_resolution_sha256="3" * 64,
            source_renderer_observation_sha256="4" * 64,
            selector=2,
            declared_record_count=148,
            selected_entry_ordinal=147,
            counts={
                "first_vector_access_resolved": True,
                "runtime_context_is_available_tree": True,
                "runtime_context_matches_unique_best": True,
                "selected_record_compatible": True,
                "runtime_context_exact_entry_count": 118,
                "runtime_context_unresolved_entry_count": 30,
            },
            captured_utc="2026-07-30T15:30:00Z",
        )
        validate_group_runtime_context(artifact)
        self.assertEqual(
            artifact["status"],
            "runtime-group-context-partial-coverage",
        )
        self.assertEqual(
            artifact["coverage"]["runtime_context_exact_entry_count"],
            118,
        )
        self.assertFalse(artifact["translation_build_eligible"])

    def test_rejects_published_context_or_symbols(self) -> None:
        artifact = build_group_runtime_context(
            target_sha256="1" * 64,
            source_group_extract_sha256="2" * 64,
            source_context_resolution_sha256="3" * 64,
            source_renderer_observation_sha256="4" * 64,
            selector=2,
            declared_record_count=3,
            selected_entry_ordinal=2,
            counts={
                "first_vector_access_resolved": True,
                "runtime_context_is_available_tree": True,
                "runtime_context_matches_unique_best": False,
                "selected_record_compatible": True,
                "runtime_context_exact_entry_count": 2,
                "runtime_context_unresolved_entry_count": 1,
            },
            captured_utc="2026-07-30T15:30:00Z",
        )
        for field, value in (
            ("runtime_initial_context_hex", "0xDB"),
            ("symbols_hex", ["0x02", "0xC9"]),
            ("decoded_text", "테스트"),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_group_runtime_context(unsafe)


if __name__ == "__main__":
    unittest.main()
