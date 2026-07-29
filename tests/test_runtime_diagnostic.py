from __future__ import annotations

import unittest
from unittest.mock import patch

from tools.v5_1_runtime_diagnostic import (
    CHECK_KEYS,
    collect_runtime_diagnostic,
    validate_runtime_diagnostic,
)


class RuntimeDiagnosticTests(unittest.TestCase):
    @patch("tools.v5_1_runtime_diagnostic.shutil.which", return_value=None)
    def test_first_failed_stage_is_path_free(self, _which: object) -> None:
        diagnostic = collect_runtime_diagnostic(
            root=__import__("pathlib").Path("."),
            trigger="setup",
            exit_code=7,
        )
        self.assertEqual(diagnostic["failed_stage"], "proot-available")
        self.assertEqual(set(diagnostic["checks"]), CHECK_KEYS)
        self.assertNotIn("/", str(diagnostic))
        self.assertRegex(
            diagnostic["attempt_utc"],
            r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
            r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
        )
        validate_runtime_diagnostic(diagnostic)

    def test_extra_fields_are_rejected(self) -> None:
        diagnostic = {
            "artifact_kind": "sanitized-runtime-stage-diagnostic",
            "schema_version": 2,
            "status": "runtime-stage-not-ready",
            "trigger": "probe",
            "exit_code": 1,
            "attempt_utc": "2026-07-29T05:00:00Z",
            "checks": {
                "proot_available": True,
                "ubuntu_available": False,
                "gearsystem_binary_available": False,
                "dynamic_dependencies_ready": False,
                "mcp_initialize_ready": False,
                "required_tools_ready": False,
                "local_target_present": True,
                "trace_plan_present": True,
                "target_identity_ready": True,
            },
            "failed_stage": "ubuntu-available",
            "runtime_observation_present": False,
            "next_checkpoint": "repair-first-failed-runtime-stage",
            "stderr": "must not be shared",
        }
        with self.assertRaises(ValueError):
            validate_runtime_diagnostic(diagnostic)

    def test_nonzero_runtime_command_cannot_report_ready(self) -> None:
        diagnostic = {
            "artifact_kind": "sanitized-runtime-stage-diagnostic",
            "schema_version": 2,
            "status": "runtime-stage-not-ready",
            "trigger": "probe",
            "exit_code": 1,
            "attempt_utc": "2026-07-29T05:00:00Z",
            "checks": {key: True for key in CHECK_KEYS},
            "failed_stage": "runtime-command",
            "runtime_observation_present": True,
            "next_checkpoint": "repair-runtime-command",
        }
        validate_runtime_diagnostic(diagnostic)
        diagnostic["status"] = "runtime-stage-ready"
        with self.assertRaisesRegex(ValueError, "exit code"):
            validate_runtime_diagnostic(diagnostic)


if __name__ == "__main__":
    unittest.main()
