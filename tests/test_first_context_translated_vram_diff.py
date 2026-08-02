from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from tools.patch_io import sha256_bytes
from tools.v5_1_first_context_translated_vram_diff import (
    _anchor_frame_schedule,
    _anchor_hit_limit,
    _record_failure_stage,
    analyze_translated_vram_diff,
    build_first_context_translated_vram_diff,
    validate_first_context_translated_vram_diff,
)


class FirstContextTranslatedVramDiffTests(unittest.TestCase):
    def test_anchor_hunt_reuses_the_proven_frame_step_policy(self) -> None:
        self.assertEqual(_anchor_hit_limit(), 64)
        schedule = _anchor_frame_schedule()
        self.assertEqual(len(schedule), 12)
        self.assertTrue(all(step == (1_000, None) for step in schedule))

    def test_records_only_the_current_bounded_failure_phase(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failure-stage.txt"
            _record_failure_stage(path, "baseline-anchor")
            _record_failure_stage(path, "test-vram")
            self.assertEqual(path.read_text(encoding="utf-8"), "test-vram\n")

    def test_confirms_changed_custom_glyph_tile(self) -> None:
        baseline = bytes(64)
        glyph = bytes(range(32))
        translated = bytes(32) + glyph
        counts, local = analyze_translated_vram_diff(
            baseline=baseline,
            translated=translated,
            custom_glyph_hashes={sha256_bytes(glyph)},
        )
        self.assertEqual(counts["changed_tile_count"], 1)
        self.assertEqual(counts["changed_custom_glyph_tile_match_count"], 1)
        self.assertEqual(local["changed_custom_glyph_match_tiles"], [1])

        value = build_first_context_translated_vram_diff(
            baseline_target_sha256="a" * 64,
            test_target_sha256="b" * 64,
            first_context_translation_test_build_sha256="c" * 64,
            local_encoding_sha256="d" * 64,
            local_capture_sha256="e" * 64,
            analysis=counts,
            same_runtime_entry_confirmed=True,
            same_initial_context_confirmed=True,
            captured_utc="2026-08-02T00:00:00Z",
        )
        validate_first_context_translated_vram_diff(value)
        self.assertEqual(
            value["status"], "translated-custom-glyph-vram-confirmed"
        )
        self.assertTrue(value["custom_glyph_vram_observed"])

    def test_routes_non_glyph_difference_to_font_lookup(self) -> None:
        baseline = bytes(64)
        translated = bytes([1]) + bytes(63)
        counts, _ = analyze_translated_vram_diff(
            baseline=baseline,
            translated=translated,
            custom_glyph_hashes={"f" * 64},
        )
        value = build_first_context_translated_vram_diff(
            baseline_target_sha256="a" * 64,
            test_target_sha256="b" * 64,
            first_context_translation_test_build_sha256="c" * 64,
            local_encoding_sha256="d" * 64,
            local_capture_sha256="e" * 64,
            analysis=counts,
            same_runtime_entry_confirmed=True,
            same_initial_context_confirmed=True,
            captured_utc="2026-08-02T00:00:00Z",
        )
        self.assertEqual(value["status"], "translated-vram-difference-observed")
        self.assertEqual(
            value["next_checkpoint"],
            "repair-font-tile-lookup-before-dialogue-rebuild",
        )

    def test_rejects_inconsistent_safe_receipt(self) -> None:
        counts, _ = analyze_translated_vram_diff(
            baseline=bytes(32),
            translated=bytes(32),
            custom_glyph_hashes={"f" * 64},
        )
        value = build_first_context_translated_vram_diff(
            baseline_target_sha256="a" * 64,
            test_target_sha256="b" * 64,
            first_context_translation_test_build_sha256="c" * 64,
            local_encoding_sha256="d" * 64,
            local_capture_sha256="e" * 64,
            analysis=counts,
            same_runtime_entry_confirmed=True,
            same_initial_context_confirmed=True,
            captured_utc="2026-08-02T00:00:00Z",
        )
        unsafe = copy.deepcopy(value)
        unsafe["custom_glyph_vram_observed"] = True
        with self.assertRaises(ValueError):
            validate_first_context_translated_vram_diff(unsafe)


if __name__ == "__main__":
    unittest.main()
