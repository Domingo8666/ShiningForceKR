from __future__ import annotations

import base64
import copy
from pathlib import Path
import tempfile
import unittest

from tools.patch_io import PatchError, sha256_bytes
from tools.v5_1_test_display_capture import (
    ATTRACT_CAPTURE_SCHEDULE,
    CAPTURE_FRAMES_AFTER_HIT,
    _build_safe_capture,
    _write_human_review_bundle,
    _next_step_text,
    _paired_pixel_comparisons,
    _parse_screenshot,
    _resolve_entry_selector,
    _target_hit_matches,
    validate_display_capture,
)


PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC"
    "AAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def build_report() -> dict[str, object]:
    return {
        "baseline_target_sha256": "1" * 64,
        "test_target_sha256": "2" * 64,
    }


def resolution() -> dict[str, object]:
    return {
        "target_read": {
            "slot": 2,
            "logical_access": 0x8123,
            "expected_bank": 0x2A,
        }
    }


class TestDisplayCaptureTests(unittest.TestCase):
    def test_runtime_stream_capture_waits_for_the_attract_intro(self) -> None:
        self.assertEqual(ATTRACT_CAPTURE_SCHEDULE, ((1_000, None),) * 12)
        self.assertEqual(
            sum(frames for frames, _ in ATTRACT_CAPTURE_SCHEDULE),
            12_000,
        )

    def test_target_hit_requires_mapper_bank_and_decoder_pc(self) -> None:
        target = {
            "slot": 1,
            "expected_bank": 8,
            "instruction_pc": 0x3406,
        }
        state = {
            "slot1_bank": 8,
            "pc_after": 0x3407,
        }
        self.assertTrue(_target_hit_matches(state, target))
        state["slot1_bank"] = 7
        self.assertFalse(_target_hit_matches(state, target))
        state["slot1_bank"] = 8
        state["pc_after"] = 0x5000
        self.assertFalse(_target_hit_matches(state, target))

    def test_png_payload_is_verified_before_hashing(self) -> None:
        png, metadata = _parse_screenshot(
            {
                "mimeType": "image/png",
                "data": base64.b64encode(PNG_1X1).decode("ascii"),
                "width": 1,
                "height": 1,
            }
        )
        self.assertEqual(png, PNG_1X1)
        self.assertEqual(metadata["width"], 1)
        self.assertEqual(metadata["height"], 1)
        self.assertEqual(metadata["png_sha256"], sha256_bytes(PNG_1X1))

    def test_png_dimensions_are_recovered_from_image_content(self) -> None:
        png, metadata = _parse_screenshot(
            {
                "mimeType": "image/png",
                "data": base64.b64encode(PNG_1X1).decode("ascii"),
            }
        )
        self.assertEqual(png, PNG_1X1)
        self.assertEqual(metadata["width"], 1)
        self.assertEqual(metadata["height"], 1)

    def test_malformed_or_mismatched_png_fails_closed(self) -> None:
        with self.assertRaisesRegex(PatchError, "PNG header"):
            _parse_screenshot(
                {
                    "mimeType": "image/png",
                    "data": base64.b64encode(b"not a png").decode("ascii"),
                    "width": 1,
                    "height": 1,
                }
            )
        with self.assertRaisesRegex(PatchError, "dimensions disagree"):
            _parse_screenshot(
                {
                    "mimeType": "image/png",
                    "data": base64.b64encode(PNG_1X1).decode("ascii"),
                    "width": 2,
                    "height": 1,
                }
            )

    def test_confirmed_target_read_requires_local_visual_review(self) -> None:
        capture = _build_safe_capture(
            build_report=build_report(),
            resolution=resolution(),
            emulator_version="3.9.14",
            mapped_bank=0x2A,
            captures=[
                {
                    "frame_after_hit": 30,
                    "width": 160,
                    "height": 144,
                    "png_sha256": "3" * 64,
                }
            ],
            post_advance_capture={
                "button": "1",
                "frames_after_press": 60,
                "width": 160,
                "height": 144,
                "png_sha256": "4" * 64,
            },
        )
        self.assertEqual(
            capture["status"],
            "capture-ready-human-review-required",
        )
        self.assertTrue(capture["target_read"]["confirmed"])
        self.assertIsNone(capture["visual_review"]["result"])
        self.assertFalse(capture["translation_build_eligible"])
        validate_display_capture(capture)
        self.assertEqual(capture["schema_version"], 2)
        self.assertIsNone(capture["entry_selector"])

    def test_decoder_entry_selector_is_bound_to_the_runtime_target(self) -> None:
        baseline = bytearray(0x5000)
        baseline[0x3FEA:0x3FEC] = (0x43DE).to_bytes(2, "little")
        baseline[0x3FEC:0x3FEE] = (0x4863).to_bytes(2, "little")
        selector = _resolve_entry_selector(
            local_capture={
                "target_hit": {
                    "registers": {
                        "de": 2,
                    }
                }
            },
            baseline_rom=bytes(baseline),
            target_read={
                "slot": 1,
                "logical_access": 0x44B1,
                "instruction_bank": 0,
                "instruction_pc": 0x3406,
            },
        )
        self.assertEqual(
            selector,
            {
                "lookup_table_base": 0x3FE8,
                "selector_offset": 2,
                "entry_index": 1,
                "pointer_address": 0x43DE,
                "next_pointer_address": 0x4863,
                "target_offset_within_entry": 0xD3,
                "pointer_bounds_target": True,
            },
        )

    def test_decoder_entry_selector_rejects_a_wrong_pointer(self) -> None:
        baseline = bytearray(0x5000)
        baseline[0x3FEA:0x3FEC] = (0x4500).to_bytes(2, "little")
        baseline[0x3FEC:0x3FEE] = (0x4863).to_bytes(2, "little")
        with self.assertRaisesRegex(PatchError, "does not bound"):
            _resolve_entry_selector(
                local_capture={
                    "target_hit": {
                        "registers": {
                            "de": 2,
                        }
                    }
                },
                baseline_rom=bytes(baseline),
                target_read={
                    "slot": 1,
                    "logical_access": 0x44B1,
                    "instruction_bank": 0,
                    "instruction_pc": 0x3406,
                },
            )

    def test_schema_one_display_capture_remains_valid_during_upgrade(self) -> None:
        capture = _build_safe_capture(
            build_report=build_report(),
            resolution=resolution(),
            emulator_version="3.9.14",
            mapped_bank=None,
            captures=[],
            post_advance_capture=None,
        )
        capture["schema_version"] = 1
        capture.pop("entry_selector")
        validate_display_capture(capture)

    def test_missing_runtime_read_does_not_claim_capture_success(self) -> None:
        capture = _build_safe_capture(
            build_report=build_report(),
            resolution=resolution(),
            emulator_version="3.9.14",
            mapped_bank=None,
            captures=[],
            post_advance_capture=None,
        )
        self.assertEqual(
            capture["status"],
            "runtime-target-read-not-observed",
        )
        self.assertFalse(capture["target_read"]["confirmed"])
        validate_display_capture(capture)

    def test_inconsistent_ready_state_is_rejected(self) -> None:
        capture = _build_safe_capture(
            build_report=build_report(),
            resolution=resolution(),
            emulator_version="3.9.14",
            mapped_bank=0x2A,
            captures=[
                {
                    "frame_after_hit": 30,
                    "width": 160,
                    "height": 144,
                    "png_sha256": "3" * 64,
                }
            ],
            post_advance_capture={
                "button": "1",
                "frames_after_press": 60,
                "width": 160,
                "height": 144,
                "png_sha256": "4" * 64,
            },
        )
        broken = copy.deepcopy(capture)
        broken["captures"] = []
        with self.assertRaisesRegex(
            ValueError,
            "post-advance capture requires confirmed display captures",
        ):
            validate_display_capture(broken)

    def test_paired_capture_compares_normalized_pixels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_paths = []
            test_paths = []
            for frame in CAPTURE_FRAMES_AFTER_HIT:
                baseline_path = root / f"baseline-{frame}.png"
                test_path = root / f"test-{frame}.png"
                baseline_path.write_bytes(PNG_1X1)
                test_path.write_bytes(PNG_1X1)
                baseline_paths.append(
                    {
                        "file": str(baseline_path),
                        "frame_after_hit": frame,
                        "png_sha256": sha256_bytes(PNG_1X1),
                    }
                )
                test_paths.append(
                    {
                        "file": str(test_path),
                        "frame_after_hit": frame,
                        "png_sha256": sha256_bytes(PNG_1X1),
                    }
                )
            baseline_post = root / "baseline-post.png"
            test_post = root / "test-post.png"
            baseline_post.write_bytes(PNG_1X1)
            test_post.write_bytes(PNG_1X1)
            frames, post = _paired_pixel_comparisons(
                {
                    "captures": baseline_paths,
                    "post_advance_capture": {
                        "file": str(baseline_post),
                        "png_sha256": sha256_bytes(PNG_1X1),
                    },
                },
                {
                    "captures": test_paths,
                    "post_advance_capture": {
                        "file": str(test_post),
                        "png_sha256": sha256_bytes(PNG_1X1),
                    },
                },
            )
        self.assertEqual(len(frames), 4)
        self.assertTrue(all(item["changed_pixels"] == 0 for item in frames))
        self.assertIsNotNone(post)
        assert post is not None
        self.assertEqual(post["changed_pixels"], 0)

    def test_next_step_names_only_three_pngs_for_human_review(self) -> None:
        text = _next_step_text(
            {"result": "visible-pixel-change-human-review-required"},
            evidence_dir=Path("C:/project/evidence/local/run"),
            root=Path("C:/project"),
        )
        self.assertIn("reports > HUMAN_REVIEW", text)
        self.assertIn("PNG 3개", text)
        self.assertIn("ROM 또는 생성 ROM은 올리지 마세요", text)

    def test_visible_change_stages_a_verified_human_review_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "baseline.png"
            test_path = root / "test.png"
            post_path = root / "post.png"
            for path in (baseline_path, test_path, post_path):
                path.write_bytes(PNG_1X1)
            staged = _write_human_review_bundle(
                {
                    "result": "visible-pixel-change-human-review-required",
                    "frame_comparisons": [
                        {
                            "frame_after_hit": 30,
                            "changed_pixels": 2,
                        },
                        {
                            "frame_after_hit": 90,
                            "changed_pixels": 5,
                        },
                    ],
                },
                baseline_local={
                    "captures": [
                        {
                            "file": str(baseline_path),
                            "frame_after_hit": 90,
                            "png_sha256": sha256_bytes(PNG_1X1),
                        }
                    ],
                },
                test_local={
                    "captures": [
                        {
                            "file": str(test_path),
                            "frame_after_hit": 90,
                            "png_sha256": sha256_bytes(PNG_1X1),
                        }
                    ],
                    "post_advance_capture": {
                        "file": str(post_path),
                        "png_sha256": sha256_bytes(PNG_1X1),
                    },
                },
                review_dir=root / "review",
            )
            self.assertEqual(
                [path.name for path in staged],
                [
                    "1_BASELINE.png",
                    "2_TEST.png",
                    "3_AFTER_ADVANCE.png",
                    "README.txt",
                ],
            )
            self.assertTrue(all(path.is_file() for path in staged))
            self.assertIn(
                "시험 문구 '한다'",
                staged[-1].read_text(encoding="utf-8"),
            )

    def test_review_bundle_is_not_written_without_visible_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            review_dir = Path(directory) / "review"
            staged = _write_human_review_bundle(
                {
                    "result": "no-visible-pixel-change",
                    "frame_comparisons": [],
                },
                baseline_local={},
                test_local={},
                review_dir=review_dir,
            )
            self.assertEqual(staged, ())
            self.assertFalse(review_dir.exists())

    def test_next_step_requires_no_user_action_for_exact_no_change(self) -> None:
        text = _next_step_text(
            {"result": "no-visible-pixel-change"},
            evidence_dir=Path("C:/project/evidence/local/run"),
            root=Path("C:/project"),
        )
        self.assertIn("지금 사용자가 할 일은 없습니다", text)


if __name__ == "__main__":
    unittest.main()
