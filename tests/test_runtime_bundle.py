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
            "schema_version": 1,
            "status": "runtime-stage-not-ready",
            "trigger": "setup",
            "exit_code": 1,
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


if __name__ == "__main__":
    unittest.main()
