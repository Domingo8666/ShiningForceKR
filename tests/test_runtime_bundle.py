import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.patch_io import sha256_file  # noqa: E402
from tools.v5_1_runtime_bundle import (  # noqa: E402
    SAFE_ARTIFACTS,
    SAFE_BINARY_ARTIFACTS,
    _load_validated_artifacts,
    _porcelain_path,
    publish_runtime_bundle,
)
from tools.v5_1_runtime_diagnostic import (  # noqa: E402
    write_runtime_diagnostic,
)
from tools.v5_1_runtime_observation import (  # noqa: E402
    write_runtime_observation,
)
from tools.v5_1_renderer_observation import (  # noqa: E402
    build_renderer_observation,
    write_renderer_observation,
)
from tools.v5_1_route_capture import (  # noqa: E402
    build_route_capture,
    write_route_capture,
)
from tools.v5_1_test_display_capture import _build_safe_capture  # noqa: E402
from tools.v5_1_test_display_review import write_display_review  # noqa: E402


class RuntimeBundleTests(unittest.TestCase):
    def test_keeps_consumer_trace_bound_to_direct_renderer_capture(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        relative_paths = (
            Path("analysis/device/v5_1_latest_first_context_translation_test_build.json"),
            Path("analysis/device/v5_1_latest_first_context_direct_renderer_capture.json"),
            Path("analysis/device/v5_1_latest_first_context_direct_renderer_capture.png"),
            Path("analysis/device/v5_1_latest_first_context_consumer_trace.json"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative_path in set(SAFE_ARTIFACTS) | set(SAFE_BINARY_ARTIFACTS):
                source = repository / relative_path
                if not source.is_file():
                    continue
                target = root / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
            build_path, capture_path, _, trace_path = (
                root / relative_path for relative_path in relative_paths
            )
            capture = json.loads(capture_path.read_text(encoding="utf-8"))
            trace = json.loads(trace_path.read_text(encoding="utf-8"))
            trace["baseline_target_sha256"] = capture[
                "baseline_target_sha256"
            ]
            trace["test_target_sha256"] = capture["test_target_sha256"]
            trace["first_context_translation_test_build_sha256"] = (
                capture["first_context_translation_test_build_sha256"]
            )
            trace["first_context_translation_runtime_capture_sha256"] = (
                sha256_file(capture_path)
            )
            trace["first_context_translation_visual_review_sha256"] = (
                sha256_file(capture_path)
            )
            trace_path.write_text(
                json.dumps(trace, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            artifacts = _load_validated_artifacts(root)
        self.assertIn(relative_paths[3], artifacts)

    def test_commit_only_publish_never_pushes_before_reconciliation(self) -> None:
        diagnostic = {
            "artifact_kind": "sanitized-runtime-stage-diagnostic",
            "schema_version": 3,
            "status": "runtime-stage-not-ready",
            "trigger": "setup",
            "exit_code": 1,
            "attempt_utc": "2026-07-29T05:00:00Z",
            "checks": {
                "proot_available": False,
                "ubuntu_available": False,
                "gearsystem_binary_available": False,
                "dynamic_dependencies_ready": False,
                "mcp_initialize_ready": False,
                "required_tools_ready": False,
                "local_target_present": True,
                "trace_plan_present": True,
                "target_identity_ready": True,
            },
            "failed_stage": "proot-available",
            "runtime_observation_present": False,
            "runtime_failure": None,
            "next_checkpoint": "repair-first-failed-runtime-stage",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_runtime_diagnostic(root, diagnostic)

            def fake_git(_root: Path, *args: str):
                class Result:
                    stdout = ""

                result = Result()
                if args == ("rev-parse", "--show-toplevel"):
                    result.stdout = str(root)
                elif args == ("branch", "--show-current"):
                    result.stdout = "main\n"
                elif args == ("remote", "get-url", "origin"):
                    result.stdout = (
                        "https://github.com/Domingo8666/ShiningForceKR.git\n"
                    )
                elif args == ("rev-parse", "HEAD"):
                    result.stdout = "1" * 40 + "\n"
                return result

            with patch(
                "tools.v5_1_runtime_bundle._git",
                side_effect=fake_git,
            ) as git_mock:
                result = publish_runtime_bundle(root, push=False)

        self.assertFalse(result["pushed"])
        self.assertFalse(
            any(call.args[1:3] == ("push", "origin") for call in git_mock.call_args_list)
        )

    def test_porcelain_path_accepts_normal_and_rename_entries(self) -> None:
        self.assertEqual(
            _porcelain_path(
                "?? analysis/device/v5_1_latest_runtime_diagnostic.json"
            ),
            "analysis/device/v5_1_latest_runtime_diagnostic.json",
        )
        self.assertEqual(
            _porcelain_path("R  old.json -> analysis/device/new.json"),
            "analysis/device/new.json",
        )

    def test_loads_multiple_valid_safe_artifacts(self) -> None:
        diagnostic = {
            "artifact_kind": "sanitized-runtime-stage-diagnostic",
            "schema_version": 3,
            "status": "runtime-stage-not-ready",
            "trigger": "setup",
            "exit_code": 1,
            "attempt_utc": "2026-07-29T05:00:00Z",
            "checks": {
                "proot_available": False,
                "ubuntu_available": False,
                "gearsystem_binary_available": False,
                "dynamic_dependencies_ready": False,
                "mcp_initialize_ready": False,
                "required_tools_ready": False,
                "local_target_present": True,
                "trace_plan_present": True,
                "target_identity_ready": True,
            },
            "failed_stage": "proot-available",
            "runtime_observation_present": False,
            "runtime_failure": None,
            "next_checkpoint": "repair-first-failed-runtime-stage",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_runtime_diagnostic(root, diagnostic)
            artifacts = _load_validated_artifacts(root)
        self.assertEqual(len(artifacts), 1)

    def test_rejects_directory_without_safe_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                ValueError, "no sanitized runtime artifacts"
            ):
                _load_validated_artifacts(Path(directory))

    def test_loads_sanitized_display_capture_without_local_png(self) -> None:
        capture = _build_safe_capture(
            build_report={
                "baseline_target_sha256": "1" * 64,
                "test_target_sha256": "2" * 64,
            },
            resolution={
                "target_read": {
                    "slot": 2,
                    "logical_access": 0x8123,
                    "expected_bank": 0x2A,
                }
            },
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
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = (
                root
                / "analysis/device/v5_1_latest_display_capture.json"
            )
            path.parent.mkdir(parents=True)
            path.write_text(
                json.dumps(capture, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            artifacts = _load_validated_artifacts(root)
        self.assertIn(path.relative_to(root), artifacts)

    def test_display_review_is_bound_to_exact_capture_hashes(self) -> None:
        capture = _build_safe_capture(
            build_report={
                "baseline_target_sha256": "1" * 64,
                "test_target_sha256": "2" * 64,
            },
            resolution={
                "target_read": {
                    "slot": 1,
                    "logical_access": 0x43DE,
                    "expected_bank": 8,
                }
            },
            emulator_version="3.9.14",
            mapped_bank=8,
            captures=[
                {
                    "frame_after_hit": 1,
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
        review = {
            "artifact_kind": "sanitized-s25u-test-display-review",
            "schema_version": 1,
            "baseline_target_sha256": "1" * 64,
            "test_target_sha256": "2" * 64,
            "capture_png_sha256s": ["3" * 64, "4" * 64],
            "reviewed_stream": {
                "physical_start": 0x203DE,
                "logical_start": 0x43DE,
                "mapped_bank": 8,
            },
            "rejected_physical_starts": [0x203DE],
            "result": "phrase-absent-fail",
            "observations": {
                "test_phrase_visible": False,
                "surrounding_text_readable": True,
                "portrait_intact": True,
                "dialogue_box_intact": True,
                "post_advance_cleared": True,
            },
            "translation_build_eligible": False,
            "next_checkpoint": "try-next-runtime-observed-stream",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture_path = (
                root
                / "analysis/device/v5_1_latest_display_capture.json"
            )
            capture_path.parent.mkdir(parents=True)
            capture_path.write_text(
                json.dumps(capture, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            review_path = write_display_review(root, review)
            artifacts = _load_validated_artifacts(root)
        self.assertIn(capture_path.relative_to(root), artifacts)
        self.assertIn(review_path.relative_to(root), artifacts)

    def test_prior_review_does_not_block_a_new_test_capture(self) -> None:
        capture = _build_safe_capture(
            build_report={
                "baseline_target_sha256": "1" * 64,
                "test_target_sha256": "5" * 64,
            },
            resolution={
                "target_read": {
                    "slot": 1,
                    "logical_access": 0x43E8,
                    "expected_bank": 8,
                }
            },
            emulator_version="3.9.14",
            mapped_bank=8,
            captures=[
                {
                    "frame_after_hit": 1,
                    "width": 160,
                    "height": 144,
                    "png_sha256": "6" * 64,
                }
            ],
            post_advance_capture={
                "button": "1",
                "frames_after_press": 60,
                "width": 160,
                "height": 144,
                "png_sha256": "7" * 64,
            },
        )
        prior_review = {
            "artifact_kind": "sanitized-s25u-test-display-review",
            "schema_version": 1,
            "baseline_target_sha256": "1" * 64,
            "test_target_sha256": "2" * 64,
            "capture_png_sha256s": ["3" * 64, "4" * 64],
            "reviewed_stream": {
                "physical_start": 0x203DE,
                "logical_start": 0x43DE,
                "mapped_bank": 8,
            },
            "rejected_physical_starts": [0x203DE],
            "result": "phrase-absent-fail",
            "observations": {
                "test_phrase_visible": False,
                "surrounding_text_readable": True,
                "portrait_intact": True,
                "dialogue_box_intact": True,
                "post_advance_cleared": True,
            },
            "translation_build_eligible": False,
            "next_checkpoint": "try-next-runtime-observed-stream",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture_path = (
                root
                / "analysis/device/v5_1_latest_display_capture.json"
            )
            capture_path.parent.mkdir(parents=True)
            capture_path.write_text(
                json.dumps(capture, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            review_path = write_display_review(root, prior_review)
            artifacts = _load_validated_artifacts(root)
        self.assertIn(capture_path.relative_to(root), artifacts)
        self.assertIn(review_path.relative_to(root), artifacts)

    def test_loads_sanitized_renderer_observation(self) -> None:
        observation = build_renderer_observation(
            target_sha256="5" * 64,
            emulator_version="3.9.14",
            route="cold-boot-start-confirm-story",
            anchor_kind="huffman-vector-read",
            frame_budget=3_300,
            mappings_attempted=[
                {
                    "probe_file_offset": 0x80100,
                    "slot": 1,
                    "expected_bank": 0x20,
                    "logical_address": 0x4100,
                },
                {
                    "probe_file_offset": 0x80100,
                    "slot": 2,
                    "expected_bank": 0x20,
                    "logical_address": 0x8100,
                },
            ],
            hit=None,
            decoder_reads=[],
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_renderer_observation(root, observation)
            artifacts = _load_validated_artifacts(root)
        self.assertIn(path.relative_to(root), artifacts)

    def test_loads_sanitized_route_capture_without_local_png(self) -> None:
        captures = [
            {
                "stage": stage,
                "frame_total": frame,
                "input_count": inputs,
                "width": 160,
                "height": 144,
                "png_sha256": str(index + 1) * 64,
            }
            for index, (stage, frame, inputs) in enumerate(
                (
                    ("boot-idle", 180, 0),
                    ("post-start", 420, 1),
                    ("confirm-01", 600, 2),
                    ("confirm-04", 1140, 5),
                    ("confirm-16", 3300, 17),
                )
            )
        ]
        observation = build_route_capture(
            target_sha256="6" * 64,
            emulator_version="3.9.14",
            route="cold-boot-start-confirm-story",
            frame_budget=3300,
            captures=captures,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_route_capture(root, observation)
            artifacts = _load_validated_artifacts(root)
        self.assertIn(path.relative_to(root), artifacts)

    def test_skips_stale_artifact_when_another_is_valid(self) -> None:
        diagnostic = {
            "artifact_kind": "sanitized-runtime-stage-diagnostic",
            "schema_version": 3,
            "status": "runtime-stage-not-ready",
            "trigger": "setup",
            "exit_code": 1,
            "attempt_utc": "2026-07-29T05:00:00Z",
            "checks": {
                "proot_available": False,
                "ubuntu_available": False,
                "gearsystem_binary_available": False,
                "dynamic_dependencies_ready": False,
                "mcp_initialize_ready": False,
                "required_tools_ready": False,
                "local_target_present": True,
                "trace_plan_present": True,
                "target_identity_ready": True,
            },
            "failed_stage": "proot-available",
            "runtime_observation_present": False,
            "runtime_failure": None,
            "next_checkpoint": "repair-first-failed-runtime-stage",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_runtime_diagnostic(root, diagnostic)
            stale = (
                root
                / "analysis/device/v5_1_latest_consumer_resolution.json"
            )
            stale.write_text('{"schema_version": 1}\n', encoding="utf-8")
            artifacts = _load_validated_artifacts(root)
        self.assertEqual(len(artifacts), 1)
        self.assertNotIn(stale.relative_to(root), artifacts)


if __name__ == "__main__":
    unittest.main()
