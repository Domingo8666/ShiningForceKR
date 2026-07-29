from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.v5_1_runtime_diagnostic import (
    CHECK_KEYS,
    REQUIRED_TOOLS,
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
            "schema_version": 3,
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
            "runtime_failure": None,
            "next_checkpoint": "repair-first-failed-runtime-stage",
            "stderr": "must not be shared",
        }
        with self.assertRaises(ValueError):
            validate_runtime_diagnostic(diagnostic)

    def test_nonzero_runtime_command_cannot_report_ready(self) -> None:
        diagnostic = {
            "artifact_kind": "sanitized-runtime-stage-diagnostic",
            "schema_version": 3,
            "status": "runtime-stage-not-ready",
            "trigger": "probe",
            "exit_code": 1,
            "attempt_utc": "2026-07-29T05:00:00Z",
            "checks": {key: True for key in CHECK_KEYS},
            "failed_stage": "runtime-command",
            "runtime_observation_present": True,
            "runtime_failure": {
                "schema_version": 1,
                "failure_stage": "candidate-probe",
                "failure_kind": "mcp-timeout",
                "mcp_method": "debug_step_frame",
            },
            "next_checkpoint": "repair-runtime-command",
        }
        validate_runtime_diagnostic(diagnostic)
        diagnostic["status"] = "runtime-stage-ready"
        with self.assertRaisesRegex(ValueError, "exit code"):
            validate_runtime_diagnostic(diagnostic)

    @patch("tools.v5_1_runtime_diagnostic.verify_target_identity")
    @patch("tools.v5_1_runtime_diagnostic.sha256_file", return_value="a" * 64)
    @patch("tools.v5_1_runtime_diagnostic._run_check", return_value=True)
    @patch(
        "tools.v5_1_runtime_diagnostic.shutil.which",
        return_value="/data/data/com.termux/files/usr/bin/proot-distro",
    )
    @patch("tools.v5_1_runtime_diagnostic.McpStdioClient")
    def test_collects_sanitized_local_failure_receipt(
        self,
        client_class: object,
        _which: object,
        _run_check_mock: object,
        _sha256_mock: object,
        _verify_mock: object,
    ) -> None:
        client = client_class.return_value  # type: ignore[attr-defined]
        client.initialize.return_value = REQUIRED_TOOLS
        receipt = {
            "schema_version": 1,
            "failure_stage": "candidate-probe",
            "failure_kind": "mcp-timeout",
            "mcp_method": "debug_step_frame",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build").mkdir()
            (root / "build/Final_Conflict_Korean_v5.1.gg").write_bytes(b"target")
            (root / "reports/local").mkdir(parents=True)
            (root / "reports/v5_1_emucap_trace_plan.json").write_text(
                json.dumps({"source_analysis_sha256": "a" * 64}),
                encoding="utf-8",
            )
            (root / "reports/local/v5_1_runtime_failure.json").write_text(
                json.dumps(receipt),
                encoding="utf-8",
            )
            diagnostic = collect_runtime_diagnostic(root, "probe", 1)
        self.assertEqual(diagnostic["runtime_failure"], receipt)
        validate_runtime_diagnostic(diagnostic)


if __name__ == "__main__":
    unittest.main()
