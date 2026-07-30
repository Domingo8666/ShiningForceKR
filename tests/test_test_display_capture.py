from __future__ import annotations

import base64
import copy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.patch_io import PatchError, sha256_bytes
from tools.v5_1_test_display_capture import (
    ATTRACT_CAPTURE_SCHEDULE,
    ATTRACT_CAPTURE_TIMEOUT_SECONDS,
    CAPTURE_FRAMES_AFTER_HIT,
    _build_safe_capture,
    _continue_until_breakpoint,
    _display_watch_target,
    _display_watch_range,
    _observed_target_address,
    _set_unlimited_fast_forward,
    _build_entry_selector_observation,
    _write_human_review_bundle,
    _next_step_text,
    _paired_pixel_comparisons,
    _parse_screenshot,
    _static_entry_selector_offset,
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
        self.assertEqual(ATTRACT_CAPTURE_TIMEOUT_SECONDS, 30.0)

    def test_attract_capture_uses_unlimited_fast_forward(self) -> None:
        class Client:
            def __init__(self) -> None:
                self.calls: list[tuple[str, dict[str, object]]] = []

            def call(
                self,
                name: str,
                arguments: dict[str, object] | None = None,
            ) -> dict[str, object]:
                self.calls.append((name, arguments or {}))
                return {}

        client = Client()
        _set_unlimited_fast_forward(client, True)
        _set_unlimited_fast_forward(client, False)
        self.assertEqual(
            client.calls,
            [
                ("set_fast_forward_speed", {"speed": 4}),
                ("toggle_fast_forward", {"enabled": True}),
                ("toggle_fast_forward", {"enabled": False}),
            ],
        )

    def test_continuous_capture_stops_at_the_runtime_breakpoint(self) -> None:
        class Client:
            def __init__(self) -> None:
                self.calls: list[str] = []
                self.statuses = [
                    {"paused": False, "at_breakpoint": False},
                    {"paused": True, "at_breakpoint": True},
                ]

            def call(
                self,
                name: str,
                arguments: dict[str, object] | None = None,
            ) -> dict[str, object]:
                self.calls.append(name)
                if name == "debug_get_status":
                    return self.statuses.pop(0)
                return {}

        client = Client()
        status = _continue_until_breakpoint(
            client, 10.0, poll_interval_seconds=0.0
        )
        self.assertTrue(status["at_breakpoint"])
        self.assertEqual(
            client.calls,
            ["debug_continue", "debug_get_status", "debug_get_status"],
        )

    def test_continuous_capture_pauses_at_its_deadline(self) -> None:
        class Client:
            def __init__(self) -> None:
                self.calls: list[str] = []
                self.paused = False

            def call(
                self,
                name: str,
                arguments: dict[str, object] | None = None,
            ) -> dict[str, object]:
                self.calls.append(name)
                if name == "debug_pause":
                    self.paused = True
                    return {}
                return {"paused": self.paused}

        client = Client()
        with mock.patch(
            "tools.v5_1_test_display_capture.time.monotonic",
            side_effect=[0.0, 2.0],
        ):
            status = _continue_until_breakpoint(client, 1.0)
        self.assertTrue(status["paused"])
        self.assertEqual(
            client.calls,
            ["debug_continue", "debug_pause", "debug_get_status"],
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

    def test_group_capture_watches_the_confirmed_interior_read(self) -> None:
        self.assertEqual(
            _display_watch_target(
                {
                    "kind": "runtime-group-observed-entry",
                    "pointer_address": 0x449F,
                    "target_file_offset": 0x2049F,
                    "intermediate_observed_target_logical_address": 0x44B1,
                    "intermediate_observed_target_file_offset": 0x204B1,
                }
            ),
            (0x44B1, 0x204B1),
        )

    def test_unknown_decoder_pc_accepts_bank_and_address_filtered_read(self) -> None:
        target = {
            "slot": 1,
            "logical_access": 0x4913,
            "logical_start": 0x4913,
            "logical_end": 0x4920,
            "expected_bank": 8,
            "instruction_pc": -1,
            "operand_kind": "hl-indirect",
        }
        state = {
            "slot1_bank": 8,
            "executing_bank": 8,
            "pc_after": 0x400B,
            "registers": {"hl": 0x4913},
        }
        self.assertTrue(_target_hit_matches(state, target))
        self.assertEqual(_observed_target_address(state, target), 0x4913)
        state["registers"]["hl"] = 0x4921
        self.assertIsNone(_observed_target_address(state, target))

    def test_group_capture_watches_the_complete_rewritten_entry(self) -> None:
        entry = {
            "kind": "runtime-group-observed-entry",
            "pointer_address": 0x449F,
            "group_entry_start_bit_in_byte": 6,
            "runtime_encoded_bits": 200,
        }
        self.assertEqual(
            _display_watch_range(entry, 0x44B1),
            (0x449F, 0x44B8),
        )

    def test_fixed_output_block_capture_watches_the_reencoded_prefix(
        self,
    ) -> None:
        entry = {
            "kind": "runtime-decoder-block",
            "pointer_address": 0x43DE,
            "target_file_offset": 0x203DE,
            "replacement_encoded_bits": 81,
        }
        self.assertEqual(
            _display_watch_target(entry),
            (0x43DE, 0x203DE),
        )
        self.assertEqual(
            _display_watch_range(entry, 0x43DE),
            (0x43DE, 0x43E8),
        )

    def test_range_hit_records_the_actual_hl_read(self) -> None:
        target = {
            "slot": 1,
            "expected_bank": 8,
            "instruction_pc": 0x3406,
            "logical_access": 0x44B1,
            "logical_start": 0x449F,
            "logical_end": 0x44B8,
            "operand_kind": "hl-indirect",
        }
        state = {
            "slot1_bank": 8,
            "pc_after": 0x3407,
            "registers": {"hl": 0x44A5},
        }
        self.assertEqual(_observed_target_address(state, target), 0x44A5)
        state["registers"]["hl"] = 0x4500
        self.assertIsNone(_observed_target_address(state, target))

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
        self.assertEqual(capture["schema_version"], 5)
        self.assertIsNone(capture["entry_selector"])
        self.assertIsNone(capture["group_entry"])

    def test_decoder_entry_selector_is_bound_to_the_runtime_target(self) -> None:
        baseline = bytearray(0x5000)
        baseline[0x3FEA:0x3FEC] = (0x43DE).to_bytes(2, "little")
        baseline[0x3FEC:0x3FEE] = (0x4863).to_bytes(2, "little")
        selector = _build_entry_selector_observation(
            baseline_local={
                "entry_selector_hit": {
                    "registers": {
                        "de": 2,
                        "bc": 0x1A37,
                    }
                }
            },
            test_local={
                "entry_selector_hit": {
                    "registers": {
                        "de": 2,
                        "bc": 0x1A99,
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
                "status": "resolved",
                "lookup_table_base": 0x3FE8,
                "baseline_selector_offset": 2,
                "test_selector_offset": 2,
                "selectors_match": True,
                "baseline_entry_ordinal": 0x1A,
                "test_entry_ordinal": 0x1A,
                "ordinals_match": True,
                "entry_index": 1,
                "pointer_address": 0x43DE,
                "next_pointer_address": 0x4863,
                "target_offset_within_entry": 0xD3,
                "pointer_bounds_target": True,
            },
        )

    def test_decoder_entry_selector_preserves_unresolved_observation(self) -> None:
        baseline = bytearray(0x5000)
        baseline[0x3FEA:0x3FEC] = (0x4500).to_bytes(2, "little")
        baseline[0x3FEC:0x3FEE] = (0x4863).to_bytes(2, "little")
        selector = _build_entry_selector_observation(
                baseline_local={
                    "entry_selector_hit": {
                        "registers": {
                            "de": 2,
                            "bc": 0x1A00,
                        }
                    }
                },
                test_local={
                    "entry_selector_hit": {
                        "registers": {
                            "de": 4,
                            "bc": 0x1B00,
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
        self.assertEqual(selector["status"], "unresolved")
        self.assertEqual(selector["baseline_selector_offset"], 2)
        self.assertEqual(selector["test_selector_offset"], 4)
        self.assertFalse(selector["selectors_match"])
        self.assertEqual(selector["baseline_entry_ordinal"], 0x1A)
        self.assertEqual(selector["test_entry_ordinal"], 0x1B)
        self.assertFalse(selector["ordinals_match"])
        self.assertIsNone(selector["entry_index"])

    def test_decoder_entry_selector_treats_next_pointer_as_an_anchor(self) -> None:
        baseline = bytearray(0x5000)
        baseline[0x3FEA:0x3FEC] = (0x43DE).to_bytes(2, "little")
        baseline[0x3FEC:0x3FEE] = (0x4863).to_bytes(2, "little")
        local = {
            "entry_selector_hit": {
                "registers": {
                    "de": 2,
                    "bc": 0x9300,
                }
            }
        }
        selector = _build_entry_selector_observation(
            baseline_local=local,
            test_local=local,
            baseline_rom=bytes(baseline),
            target_read={
                "slot": 1,
                "logical_access": 0x49E0,
                "instruction_bank": 0,
                "instruction_pc": 0x3406,
            },
        )
        self.assertEqual(selector["status"], "resolved")
        self.assertEqual(selector["pointer_address"], 0x43DE)
        self.assertEqual(selector["next_pointer_address"], 0x4863)
        self.assertEqual(selector["target_offset_within_entry"], 0x602)

    def test_static_selector_finds_the_block_that_bounds_the_target(self) -> None:
        baseline = bytearray(0x5000)
        pointers = (0x401E, 0x43DE, 0x4863, 0x5044)
        for index, pointer in enumerate(pointers):
            offset = 0x3FE8 + index * 2
            baseline[offset : offset + 2] = pointer.to_bytes(2, "little")
        self.assertEqual(
            _static_entry_selector_offset(bytes(baseline), 0x44B1),
            2,
        )
        self.assertIsNone(
            _static_entry_selector_offset(bytes(baseline), 0x7000),
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
        capture.pop("group_entry")
        validate_display_capture(capture)

    def test_schema_two_display_capture_remains_valid_during_upgrade(self) -> None:
        capture = _build_safe_capture(
            build_report=build_report(),
            resolution=resolution(),
            emulator_version="3.9.14",
            mapped_bank=None,
            captures=[],
            post_advance_capture=None,
        )
        capture["schema_version"] = 2
        capture.pop("group_entry")
        validate_display_capture(capture)

    def test_schema_three_display_capture_remains_valid_during_upgrade(self) -> None:
        capture = _build_safe_capture(
            build_report=build_report(),
            resolution=resolution(),
            emulator_version="3.9.14",
            mapped_bank=None,
            captures=[],
            post_advance_capture=None,
        )
        capture["schema_version"] = 3
        capture.pop("group_entry")
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

    def test_missing_runtime_read_drops_unbound_selector_evidence(self) -> None:
        selector = {
            "status": "unresolved",
            "lookup_table_base": 0x3FE8,
            "baseline_selector_offset": 2,
            "test_selector_offset": 2,
            "selectors_match": True,
            "baseline_entry_ordinal": 147,
            "test_entry_ordinal": 147,
            "ordinals_match": True,
            "entry_index": None,
            "pointer_address": None,
            "next_pointer_address": None,
            "target_offset_within_entry": None,
            "pointer_bounds_target": False,
        }
        capture = _build_safe_capture(
            build_report=build_report(),
            resolution=resolution(),
            emulator_version="3.9.14",
            mapped_bank=None,
            captures=[],
            post_advance_capture=None,
            entry_selector=selector,
            group_entry={"untrusted": True},
        )
        self.assertIsNone(capture["entry_selector"])
        self.assertIsNone(capture["group_entry"])
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
