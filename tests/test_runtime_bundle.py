import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_runtime_bundle import (  # noqa: E402
    _load_validated_artifacts,
    _porcelain_path,
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


class RuntimeBundleTests(unittest.TestCase):
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
