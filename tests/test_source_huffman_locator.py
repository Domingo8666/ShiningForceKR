from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_source_huffman_locator import (  # noqa: E402
    build_source_huffman_locator,
    find_structural_vector_windows,
    validate_source_huffman_locator,
)


class SourceHuffmanLocatorTests(unittest.TestCase):
    def test_finds_an_odd_offset_monotonic_vector_window(self) -> None:
        vector = b"".join(
            (0x5000 + index).to_bytes(2, "little")
            for index in range(256)
        )
        data = b"\x00" * 3 + vector + b"\x00" * 5
        self.assertEqual(find_structural_vector_windows(data), [3])

    def test_builds_safe_selection_and_rejects_offsets(self) -> None:
        artifact = build_source_huffman_locator(
            source_sha256="1" * 64,
            target_sha256="2" * 64,
            source_group_delta_sha256="3" * 64,
            scan={
                "structural_window_count": 2,
                "parseable_vector_count": 1,
                "unique_vector_selected": True,
                "selected_populated_context_count": 221,
                "selected_empty_context_count": 35,
            },
            captured_utc="2026-07-30T19:00:00Z",
        )
        validate_source_huffman_locator(artifact)
        self.assertEqual(
            artifact["status"],
            "source-huffman-vector-uniquely-located",
        )
        for field, value in (
            ("vector_offset", 0x29C3F),
            ("bank_base", 0x28000),
            ("pointers", [0x5E40]),
            ("symbols", [0x01, 0xC9]),
        ):
            unsafe = deepcopy(artifact)
            unsafe[field] = value
            with self.assertRaisesRegex(ValueError, "fields do not match"):
                validate_source_huffman_locator(unsafe)


if __name__ == "__main__":
    unittest.main()
