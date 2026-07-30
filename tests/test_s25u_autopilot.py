from __future__ import annotations

import re
import unittest
from pathlib import Path

from tools.v5_1_runtime_bundle import SAFE_ARTIFACTS, SAFE_BINARY_ARTIFACTS


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "tools" / "run_s25u_autopilot.sh").read_text(encoding="utf-8")
RUNTIME_STAGE = (ROOT / "tools" / "run_s25u_runtime_stage.sh").read_text(
    encoding="utf-8"
)
MANAGER = (ROOT / "tools" / "manage_s25u_autopilot.sh").read_text(
    encoding="utf-8"
)


class S25UAutopilotTests(unittest.TestCase):
    def test_shell_safe_artifact_allowlist_matches_runtime_bundle(self) -> None:
        shell_paths = set(
            re.findall(
                r"analysis/device/v5_1_latest_[a-z_]+\.(?:json|png)",
                SCRIPT,
            )
        )
        bundle_paths = {
            str(path).replace("\\", "/")
            for path in set(SAFE_ARTIFACTS) | set(SAFE_BINARY_ARTIFACTS)
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

    def test_autopilot_recovers_only_a_dead_stale_lock(self) -> None:
        self.assertIn('kill -0 "$existing_pid"', SCRIPT)
        self.assertIn('if [ "$lock_owner" = "$$" ]', SCRIPT)
        self.assertIn("stale autopilot lock could not be recovered safely", SCRIPT)

    def test_manager_installs_private_boot_launcher(self) -> None:
        self.assertIn(
            '$HOME/.termux/boot/shiningforcekr-autopilot',
            MANAGER,
        )
        self.assertIn("chmod 700", MANAGER)
        self.assertIn("run_s25u_autopilot.sh", MANAGER)
        self.assertIn("AUTOPILOT_STATUS.txt", MANAGER)
        self.assertNotIn("adb pull", MANAGER)
        self.assertNotIn("git push", MANAGER)

    def test_manager_requires_termux_and_s25u_local_rom(self) -> None:
        self.assertIn("/data/data/com.termux/files/usr", MANAGER)
        self.assertIn("/storage/emulated/0/", MANAGER)
        self.assertIn('"$HOME"/storage/shared/*', MANAGER)
        self.assertIn('kill -0 "$candidate"', MANAGER)
        self.assertIn("/proc/$candidate/cmdline", MANAGER)

    def test_manager_restart_stops_only_the_owned_process_tree(self) -> None:
        self.assertIn("restart  Stop the owned process tree", MANAGER)
        self.assertIn("collect_owned_descendants", MANAGER)
        self.assertIn("*run_s25u_autopilot.sh*", MANAGER)
        self.assertIn('kill -TERM "$owned_pid"', MANAGER)
        self.assertIn('kill -KILL "$owned_pid"', MANAGER)

    def test_default_poll_interval_is_thirty_seconds(self) -> None:
        self.assertIn('SFKR_AUTOPILOT_INTERVAL:-30', SCRIPT)
        self.assertIn('SFKR_AUTOPILOT_INTERVAL:-30', MANAGER)
        self.assertIn('if [ "$interval" -lt 30 ]', SCRIPT)
        self.assertIn('if [ "$interval" -lt 30 ]', MANAGER)

    def test_runtime_stage_batches_exact_no_change_rejections(self) -> None:
        self.assertIn("comparison_attempt_limit=8", RUNTIME_STAGE)
        self.assertIn(
            "no-visible-pixel-change",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "v5_1_test_display_comparison.py --result-only",
            RUNTIME_STAGE,
        )
        self.assertIn(
            'entry.get("kind") == "runtime-decoder-block"',
            RUNTIME_STAGE,
        )
        self.assertIn(
            'if [ "$fixed_block_probe" = "yes" ]',
            RUNTIME_STAGE,
        )

    def test_confirmed_stream_skips_redundant_runtime_research(self) -> None:
        self.assertIn("decoder_selection_ready()", RUNTIME_STAGE)
        self.assertIn("group_selection_ready()", RUNTIME_STAGE)
        self.assertIn(
            "analysis/evidence/v5_1_confirmed_group_capture.json",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "using the confirmed decoder stream",
            RUNTIME_STAGE,
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "if decoder_selection_ready || group_selection_ready; then"
            ),
            RUNTIME_STAGE.index("python tools/run_s25u_runtime_probe.py"),
        )

    def test_runtime_stage_cannot_reuse_stale_test_build_outputs(self) -> None:
        stale_removal = RUNTIME_STAGE.index(
            "build/Final_Conflict_Korean_test_phrase.gg"
        )
        build = RUNTIME_STAGE.index("python tools/v5_1_test_patch.py")
        missing_output_guard = RUNTIME_STAGE.index(
            "[ ! -f build/Final_Conflict_Korean_test_phrase.gg ]"
        )
        capture = RUNTIME_STAGE.index(
            "python tools/v5_1_test_display_capture.py"
        )
        self.assertLess(stale_removal, build)
        self.assertLess(build, missing_output_guard)
        self.assertLess(missing_output_guard, capture)

    def test_runtime_stage_bounds_display_capture_wall_time(self) -> None:
        self.assertIn("timeout -k 15s 180s", RUNTIME_STAGE)

    def test_runtime_stage_records_precise_substage_failures(self) -> None:
        self.assertIn("v5_1_runtime_stage_failure.py", RUNTIME_STAGE)
        for stage in (
            "runtime-probe",
            "runtime-hit-resolver",
            "renderer-probe",
            "decoder-stream-resolution",
            "route-capture",
            "test-patch",
            "test-display-capture",
            "display-comparison",
        ):
            self.assertIn(f"record_stage_failure {stage}", RUNTIME_STAGE)

    def test_manager_logs_include_launcher_details(self) -> None:
        self.assertIn("tail -n 40 \"$private_log\"", MANAGER)
        self.assertIn("tail -n 80 \"$launcher_log\"", MANAGER)

    def test_runtime_stage_replaces_stale_next_step_text(self) -> None:
        self.assertIn("새 후보를 자동 검사하고 있습니다", RUNTIME_STAGE)
        self.assertIn("자동 검사 실패 지점을 안전하게 기록했습니다", RUNTIME_STAGE)


if __name__ == "__main__":
    unittest.main()
