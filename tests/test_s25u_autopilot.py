from __future__ import annotations

import re
import unittest
from pathlib import Path

from tools.v5_1_runtime_bundle import SAFE_ARTIFACTS


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "tools" / "run_s25u_autopilot.sh").read_text(encoding="utf-8")


class S25UAutopilotTests(unittest.TestCase):
    def test_shell_safe_artifact_allowlist_matches_runtime_bundle(self) -> None:
        shell_paths = set(
            re.findall(
                r"analysis/device/v5_1_latest_[a-z_]+\.json",
                SCRIPT,
            )
        )
        bundle_paths = {
            str(path).replace("\\", "/") for path in SAFE_ARTIFACTS
        }
        self.assertEqual(shell_paths, bundle_paths)

    def test_autopilot_has_fail_closed_repository_guards(self) -> None:
        self.assertIn(
            "https://github.com/Domingo8666/ShiningForceKR",
            SCRIPT,
        )
        self.assertIn('git branch --show-current)" != "main"', SCRIPT)
        self.assertIn("refusing automatic push", SCRIPT)
        self.assertNotIn("git reset", SCRIPT)
        self.assertNotIn("git clean", SCRIPT)

    def test_autopilot_keeps_rom_in_s25u_shared_storage(self) -> None:
        self.assertIn("/storage/emulated/0/", SCRIPT)
        self.assertIn('"$HOME"/storage/shared/*', SCRIPT)
        self.assertNotIn("adb pull", SCRIPT)


if __name__ == "__main__":
    unittest.main()
