from __future__ import annotations

import re
import unittest
from pathlib import Path

from tools.run_s25u_runtime_probe import RUNTIME_FAILURE_STAGES
from tools.v5_1_runtime_bundle import (
    SAFE_ARTIFACTS,
    SAFE_BINARY_ARTIFACTS,
    SAFE_TEXT_ARTIFACTS,
)


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
                r"analysis/device/v5_1_latest_[a-z_]+\.(?:json|png|txt)",
                SCRIPT,
            )
        )
        bundle_paths = {
            str(path).replace("\\", "/")
            for path in (
                set(SAFE_ARTIFACTS)
                | set(SAFE_BINARY_ARTIFACTS)
                | set(SAFE_TEXT_ARTIFACTS)
            )
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

    def test_manager_can_force_one_rerun_after_local_input_changes(self) -> None:
        self.assertIn("--force", MANAGER)
        self.assertIn("autopilot_args+=(--force)", MANAGER)
        self.assertIn('"${autopilot_args[@]}"', MANAGER)

    def test_default_poll_interval_is_thirty_seconds(self) -> None:
        self.assertIn('SFKR_AUTOPILOT_INTERVAL:-30', SCRIPT)
        self.assertIn('SFKR_AUTOPILOT_INTERVAL:-30', MANAGER)
        self.assertIn('if [ "$interval" -lt 30 ]', SCRIPT)
        self.assertIn('if [ "$interval" -lt 30 ]', MANAGER)

    def test_background_work_yields_to_android_input(self) -> None:
        self.assertIn('SFKR_AUTOPILOT_NICE:-15', SCRIPT)
        self.assertIn('renice -n "$nice_level" -p "$$"', SCRIPT)
        self.assertIn("git config --local pack.threads 1", SCRIPT)
        self.assertIn("git config --local index.threads 1", SCRIPT)
        self.assertIn("git config --local checkout.workers 1", SCRIPT)
        self.assertIn('SFKR_AUTOPILOT_NICE:-15', MANAGER)
        self.assertIn('nice -n "$nice_level" bash', MANAGER)
        self.assertIn("백그라운드 우선순위: nice $nice_level", MANAGER)

    def test_screen_off_runtime_keeps_a_managed_termux_wake_lock(self) -> None:
        self.assertIn("termux-wake-lock", RUNTIME_STAGE)
        self.assertIn('touch "$wake_lock_file"', RUNTIME_STAGE)
        self.assertIn("acquire_wake_lock()", MANAGER)
        self.assertIn("release_wake_lock()", MANAGER)
        self.assertIn("termux-wake-unlock", MANAGER)
        self.assertIn("화면 꺼짐 작업 유지: $wake_lock_state", MANAGER)

    def test_runtime_stage_accepts_only_whitelisted_commit_requests(self) -> None:
        self.assertIn("git log -1 --pretty=%s", RUNTIME_STAGE)
        self.assertIn(
            '"Run stage: first-context-translated-glyph-route"',
            RUNTIME_STAGE,
        )
        self.assertIn(
            '"Run stage: first-context-direct-renderer-capture"',
            RUNTIME_STAGE,
        )
        self.assertNotIn("eval", RUNTIME_STAGE)

    def test_runtime_stage_request_survives_safe_artifact_rebase_once(self) -> None:
        self.assertIn(
            "analysis/control/s25u_runtime_stage_request.json",
            RUNTIME_STAGE,
        )
        self.assertIn("last_runtime_stage_request", RUNTIME_STAGE)
        self.assertIn('set(value)=={"request_id", "stage"}', RUNTIME_STAGE)
        self.assertIn('stage in allowed', RUNTIME_STAGE)
        self.assertIn(
            'if [ "$stage_request_token" != "$last_stage_request" ]',
            RUNTIME_STAGE,
        )
        self.assertIn(
            'critical_path_request_id="${stage_request_token:-}"',
            RUNTIME_STAGE,
        )
        self.assertIn(
            'python - "$direct_capture_request_id"',
            RUNTIME_STAGE,
        )

    def test_direct_renderer_trace_reuses_identical_execution_inputs(self) -> None:
        self.assertIn(
            "PUBLISH_RELATIVE_PATH as ENCODING_PATH",
            RUNTIME_STAGE,
        )
        self.assertIn(
            'capture["test_target_sha256"] == build["test_target_sha256"]',
            RUNTIME_STAGE,
        )
        self.assertIn(
            'capture["renderer_route"] == "direct-observed-page"',
            RUNTIME_STAGE,
        )
        self.assertIn(
            'capture["local_encoding_sha256"]\n'
            '    == published_encoding["local_encoding_sha256"]',
            RUNTIME_STAGE,
        )
        self.assertIn(
            'capture["local_encoding_sha256"]\n'
            '    == sha256_file(paths["encoding"])',
            RUNTIME_STAGE,
        )
        self.assertIn(
            'local_rows[0].get("direct_renderer_proof") is True',
            RUNTIME_STAGE,
        )
        self.assertIn(
            'capture.get("runtime_stage_request_id") == sys.argv[1]',
            RUNTIME_STAGE,
        )

    def test_direct_renderer_stage_rebuilds_without_inline_page_token(self) -> None:
        direct_branch = RUNTIME_STAGE.index(
            'elif [ "$critical_path_focus" = "first-context-direct-renderer-capture" ]'
        )
        next_branch = RUNTIME_STAGE.index(
            'elif [ "$critical_path_focus" = "active-rom-cursor-reset" ]',
            direct_branch,
        )
        branch = RUNTIME_STAGE[direct_branch:next_branch]
        self.assertIn("--direct-renderer-observed-page", branch)
        encoding_call = branch.index(
            "python tools/v5_1_first_context_translation_encoding.py"
        )
        capture_call = branch.index(
            "python tools/v5_1_first_context_direct_renderer_capture.py"
        )
        self.assertNotIn(
            "--proven-visible-page",
            branch[encoding_call:capture_call],
        )
        capture_segment = branch[capture_call:]
        capture_line = capture_segment.splitlines()[0]
        self.assertNotIn("--proven-visible-page", capture_line)
        self.assertNotIn(
            "--proven-visible-page",
            capture_segment.split("python tools/v5_1_first_context_consumer_trace.py", 1)[0],
        )

    def test_direct_renderer_consumer_stage_requires_current_trace_output(self) -> None:
        self.assertIn(
            "validate_first_context_consumer_trace(trace)",
            RUNTIME_STAGE,
        )
        self.assertIn(
            'trace["test_target_sha256"] == build["test_target_sha256"]',
            RUNTIME_STAGE,
        )
        self.assertIn(
            'trace["first_context_translation_runtime_capture_sha256"]\n'
            '    == capture_sha256',
            RUNTIME_STAGE,
        )
        self.assertIn(
            'trace["first_context_translation_visual_review_sha256"]\n'
            '    == capture_sha256',
            RUNTIME_STAGE,
        )

    def test_direct_renderer_consumer_trace_has_its_own_wall_limit(self) -> None:
        trace_branch = RUNTIME_STAGE.index(
            'elif [ "$critical_path_focus" = "first-context-direct-renderer-consumer-trace" ]'
        )
        next_branch = RUNTIME_STAGE.index(
            'elif [ "$critical_path_focus" = "active-rom-cursor-reset" ]',
            trace_branch,
        )
        branch = RUNTIME_STAGE[trace_branch:next_branch]
        self.assertIn("timeout -k 15s 180s", branch)
        self.assertIn("first-context-consumer-trace-timeout", branch)

    def test_direct_renderer_capture_publishes_before_consumer_trace(self) -> None:
        direct_branch = RUNTIME_STAGE.index(
            'elif [ "$critical_path_focus" = "first-context-direct-renderer-capture" ]'
        )
        trace_branch = RUNTIME_STAGE.index(
            'elif [ "$critical_path_focus" = "first-context-direct-renderer-consumer-trace" ]',
            direct_branch,
        )
        branch = RUNTIME_STAGE[direct_branch:trace_branch]
        self.assertNotIn("v5_1_first_context_consumer_trace.py", branch)
        self.assertIn(
            'capture["capture_png_sha256"] == sha256_file(paths["image"])',
            branch,
        )

    def test_direct_renderer_capture_is_single_and_bounded(self) -> None:
        direct_branch = RUNTIME_STAGE.index(
            'elif [ "$critical_path_focus" = "first-context-direct-renderer-capture" ]'
        )
        next_branch = RUNTIME_STAGE.index(
            'elif [ "$critical_path_focus" = "active-rom-cursor-reset" ]',
            direct_branch,
        )
        branch = RUNTIME_STAGE[direct_branch:next_branch]
        self.assertIn("run_direct_renderer_capture_bounded", branch)
        self.assertIn("timeout -k 10s 360s", branch)
        self.assertEqual(
            branch.count(
                "python tools/v5_1_first_context_direct_renderer_capture.py"
            ),
            2,
        )
        self.assertNotIn("retrying", branch)

    def test_direct_renderer_large_payloads_use_separate_sessions(self) -> None:
        direct_branch = RUNTIME_STAGE.index(
            'elif [ "$critical_path_focus" = "first-context-direct-renderer-capture" ]'
        )
        next_branch = RUNTIME_STAGE.index(
            'elif [ "$critical_path_focus" = "active-rom-cursor-reset" ]',
            direct_branch,
        )
        branch = RUNTIME_STAGE[direct_branch:next_branch]
        self.assertIn('direct_capture_request_id="$critical_path_request_id"', branch)
        self.assertIn("direct_capture_file_request", branch)
        self.assertIn('case "$direct_capture_request_id" in', branch)
        self.assertIn("*-screenshot)", branch)
        self.assertIn("direct_capture_mode_args=(--screenshot-only)", branch)
        self.assertIn("*-vram)", branch)
        self.assertIn("direct_capture_mode_args=(--vram-only)", branch)
        self.assertIn("validate_first_context_direct_renderer_screenshot", branch)
        self.assertIn("SCREENSHOT_IMAGE_PATH", branch)

    def test_direct_renderer_failure_stage_is_safe_to_publish(self) -> None:
        self.assertIn(
            "analysis/device/"
            "v5_1_latest_first_context_direct_renderer_capture_failure_stage.txt",
            SCRIPT,
        )

    def test_consumer_trace_failures_can_always_write_a_diagnostic(self) -> None:
        for stage in (
            "first-context-consumer-trace",
            "first-context-consumer-trace-timeout",
            "first-context-consumer-trace-identity",
            "first-context-consumer-trace-anchor",
            "first-context-consumer-trace-input",
            "first-context-consumer-trace-validation",
        ):
            self.assertIn(stage, RUNTIME_FAILURE_STAGES)

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
            "      run_display_capture",
            missing_output_guard,
        )
        self.assertLess(stale_removal, build)
        self.assertLess(build, missing_output_guard)
        self.assertLess(missing_output_guard, capture)

    def test_runtime_stage_bounds_display_capture_wall_time(self) -> None:
        self.assertIn("timeout -k 15s 180s", RUNTIME_STAGE)

    def test_runtime_stage_bounds_runtime_sequence_wall_time(self) -> None:
        self.assertIn("timeout -k 15s 240s", RUNTIME_STAGE)
        self.assertIn("timeout -k 5s 120s", RUNTIME_STAGE)
        self.assertIn(
            "run_source_target_runtime_sequence 2>&1",
            RUNTIME_STAGE,
        )

    def test_runtime_stage_bounds_active_rom_source_wall_time(self) -> None:
        self.assertIn("run_active_register_rom_source()", RUNTIME_STAGE)
        self.assertIn("timeout -k 15s 150s", RUNTIME_STAGE)
        self.assertIn("run_active_register_rom_source", RUNTIME_STAGE)

    def test_runtime_stage_classifies_source_before_treating_it_as_text(self) -> None:
        self.assertIn('"active-rom-source-role"', RUNTIME_STAGE)
        self.assertIn("v5_1_active_rom_source_role.py", RUNTIME_STAGE)
        self.assertIn('"active-rom-read-block"', RUNTIME_STAGE)
        self.assertIn("v5_1_active_rom_read_block.py", RUNTIME_STAGE)
        self.assertIn('"active-rom-lookup-index-producer"', RUNTIME_STAGE)
        self.assertIn("v5_1_active_rom_lookup_index_producer.py", RUNTIME_STAGE)
        self.assertIn('"active-rom-cursor-reset"', RUNTIME_STAGE)
        self.assertIn("v5_1_active_rom_cursor_reset.py", RUNTIME_STAGE)
        self.assertIn("v5_1_active_rom_path_scope.py", RUNTIME_STAGE)
        self.assertLess(
            RUNTIME_STAGE.index('"active-rom-source-role"'),
            RUNTIME_STAGE.index('"active-rom-read-block"'),
        )
        self.assertLess(
            RUNTIME_STAGE.index('"active-rom-read-block"'),
            RUNTIME_STAGE.index('"active-rom-lookup-index-producer"'),
        )
        self.assertLess(
            RUNTIME_STAGE.index('"active-rom-lookup-index-producer"'),
            RUNTIME_STAGE.index('"active-rom-path-scope"'),
        )
        self.assertLess(
            RUNTIME_STAGE.index('"active-rom-path-scope"'),
            RUNTIME_STAGE.index('"active-rom-cursor-reset"'),
        )
        self.assertLess(
            RUNTIME_STAGE.index('"active-rom-cursor-reset"'),
            RUNTIME_STAGE.index("if decoder_selection_ready || group_selection_ready; then"),
        )

    def test_translated_vram_failure_records_exact_bounded_phase(self) -> None:
        token = (
            "reports/local/"
            "v5_1_first_context_translated_vram_failure_stage.txt"
        )
        self.assertIn(token, RUNTIME_STAGE)
        for phase in (
            "baseline-initialize",
            "baseline-media",
            "baseline-anchor",
            "baseline-context",
            "baseline-vram",
            "baseline-screenshot",
            "test-initialize",
            "test-media",
            "test-anchor",
            "test-context",
            "test-vram",
            "test-screenshot",
            "analysis",
            "artifact",
        ):
            self.assertIn(
                f"first-context-translated-vram-{phase}",
                RUNTIME_STAGE,
            )

    def test_autopilot_publishes_sanitized_active_rom_read_block(self) -> None:
        self.assertIn(
            "analysis/device/v5_1_latest_active_rom_read_block.json",
            SCRIPT,
        )
        self.assertIn(
            "analysis/device/v5_1_latest_active_rom_lookup_index_producer.json",
            SCRIPT,
        )
        self.assertIn(
            "analysis/device/v5_1_latest_active_rom_cursor_reset.json",
            SCRIPT,
        )
        self.assertIn(
            "analysis/device/v5_1_latest_active_rom_path_scope.json",
            SCRIPT,
        )

    def test_autopilot_retries_only_transient_runtime_failures(self) -> None:
        self.assertIn('SFKR_RUNTIME_TIMEOUT:-480', SCRIPT)
        self.assertIn('if [ "$runtime_timeout" -lt 300 ]', SCRIPT)
        self.assertIn('timeout -k 30s "$runtime_timeout"', SCRIPT)
        self.assertIn("runtime_failure_is_retryable", SCRIPT)
        self.assertIn('"mcp-timeout"', SCRIPT)
        self.assertIn('"subprocess-timeout"', SCRIPT)
        self.assertIn("transient runtime diagnostic", SCRIPT)
        self.assertIn("deterministic runtime diagnostic recorded", SCRIPT)
        self.assertIn('record_processed_head "$post_head"', SCRIPT)
        self.assertIn('if [ "$stage_status" -eq 0 ]', SCRIPT)
        self.assertNotIn(
            '"$stage_status" -eq 0 ] || [ "$post_head" != "$input_head"',
            SCRIPT,
        )

    def test_one_shot_publishes_new_runtime_artifacts_before_exit(self) -> None:
        loop_start = SCRIPT.index('log "S25U autopilot started"')
        stage_run = SCRIPT.index("      run_current_head", loop_start)
        once_branch = SCRIPT.index('  if [ "$once" -eq 1 ]; then', stage_run)
        final_sync = SCRIPT.index("    sync_main", once_branch)
        once_exit = SCRIPT.index('    exit "$cycle_status"', final_sync)
        self.assertLess(stage_run, once_branch)
        self.assertLess(once_branch, final_sync)
        self.assertLess(final_sync, once_exit)
        self.assertIn("one-shot runtime artifacts synchronized", SCRIPT)

    def test_autopilot_defers_bundle_push_until_after_safe_rebase(self) -> None:
        self.assertIn(
            "python tools/v5_1_runtime_bundle.py --publish --no-push",
            SCRIPT,
        )
        self.assertIn("SFKR_DEFER_RUNTIME_BUNDLE_PUSH=1", SCRIPT)
        self.assertLess(
            SCRIPT.index("publish_pending_safe_artifacts"),
            SCRIPT.index("git fetch origin main"),
        )

    def test_autopilot_quarantines_only_residual_safe_artifacts(self) -> None:
        publish = SCRIPT.index(
            "python tools/v5_1_runtime_bundle.py --publish --no-push"
        )
        quarantine = SCRIPT.index("git stash push -u", publish)
        fetch = SCRIPT.index("git fetch origin main", quarantine)
        self.assertLess(publish, quarantine)
        self.assertLess(quarantine, fetch)
        self.assertIn(
            "refusing to quarantine a residual change outside the safe artifact set",
            SCRIPT,
        )
        self.assertIn(
            "residual unvalidated safe artifacts quarantined in local git stash",
            SCRIPT,
        )
        self.assertNotIn("git stash pop", SCRIPT)

    def test_runtime_stage_publishes_progress_then_continues_comparison(
        self,
    ) -> None:
        self.assertIn("if ! display_comparison_ready; then", RUNTIME_STAGE)
        self.assertIn(
            "python tools/v5_1_runtime_bundle.py --publish",
            RUNTIME_STAGE,
        )
        self.assertGreaterEqual(RUNTIME_STAGE.count("run_display_capture"), 3)

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
            "initial-font-page-trace",
            "font-transfer-source",
            "confirmed-group-extract",
            "target-group-usage",
            "target-group-stream-map",
            "target-group-population",
            "target-group-population-decode",
            "target-group-expanded-glyphs",
            "target-group-expanded-corpus",
            "decoder-caller-resolution",
            "group-context-resolution",
            "group-runtime-context",
            "group-source-delta",
            "source-huffman-locator",
            "source-group-codec-probe",
            "group-text-candidate-resolution",
            "unmatched-glyph-fuzzy",
            "group-script-corpus",
            "source-record-pairing",
            "confirmed-group-unicode",
        ):
            self.assertIn(f"record_stage_failure {stage}", RUNTIME_STAGE)

    def test_every_literal_runtime_failure_stage_has_a_safe_token(self) -> None:
        literal_stages = set(
            re.findall(
                r"record_stage_failure ([a-z0-9-]+)",
                RUNTIME_STAGE,
            )
        )
        self.assertTrue(literal_stages)
        self.assertLessEqual(literal_stages, RUNTIME_FAILURE_STAGES)

    def test_runtime_stage_classifies_group_tail_build_failures(self) -> None:
        for message, stage in (
            ("confirmed group alias is ambiguous", "first-context-build-group-alias"),
            ("not a contiguous group tail", "first-context-build-group-tail"),
            ("packed group tail exceeds", "first-context-build-group-overflow"),
            ("group identity is invalid", "first-context-build-group-identity"),
        ):
            self.assertIn(message, RUNTIME_STAGE)
            self.assertIn(stage, RUNTIME_STAGE)
            self.assertIn(stage, RUNTIME_FAILURE_STAGES)

    def test_runtime_stage_prepares_the_verified_local_font_catalog(self) -> None:
        self.assertIn("visible_font_catalog_ready()", RUNTIME_STAGE)
        self.assertIn("tools/fetch_galmuri7_bdf.py --force", RUNTIME_STAGE)
        self.assertIn("python tools/v5_1_font_catalog.py", RUNTIME_STAGE)
        self.assertLess(
            RUNTIME_STAGE.index("prepare_visible_font_catalog"),
            RUNTIME_STAGE.index(
                "python tools/v5_1_visible_unicode_mapping.py --if-ready"
            ),
        )
        self.assertIn(
            "python tools/v5_1_initial_font_page_trace.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_visible_unicode_mapping.py --if-ready"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_initial_font_page_trace.py --if-ready"
            ),
        )
        self.assertIn(
            "python tools/v5_1_font_transfer_source.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_initial_font_page_trace.py --if-ready"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_font_transfer_source.py --if-ready"
            ),
        )
        self.assertIn(
            "python tools/v5_1_confirmed_group_extract.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_target_group_usage.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_decoder_caller_resolution.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_target_group_stream_map.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_target_group_population.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_target_group_population_decode.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_target_group_expanded_corpus.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_target_group_expanded_glyphs.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_group_context_resolution.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_group_runtime_context.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_group_source_delta.py",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_source_huffman_locator.py",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_source_group_codec_probe.py",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_group_text_candidate_resolution.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_unmatched_glyph_fuzzy.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_group_script_corpus.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_source_record_pairing.py",
            RUNTIME_STAGE,
        )
        self.assertIn(
            "python tools/v5_1_confirmed_group_unicode.py --if-ready",
            RUNTIME_STAGE,
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_confirmed_group_extract.py --if-ready"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_target_group_usage.py --if-ready"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_target_group_usage.py --if-ready"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_target_group_stream_map.py --if-ready"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_target_group_stream_map.py --if-ready"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_target_group_population.py --if-ready"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_target_group_population.py --if-ready"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_target_group_population_decode.py --if-ready"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_target_group_population_decode.py --if-ready"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_target_group_expanded_glyphs.py --if-ready"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_target_group_expanded_glyphs.py --if-ready"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_target_group_expanded_corpus.py --if-ready"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_target_group_expanded_corpus.py --if-ready"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_decoder_caller_resolution.py --if-ready"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_decoder_caller_resolution.py --if-ready"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_group_context_resolution.py --if-ready"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_group_context_resolution.py --if-ready"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_group_runtime_context.py --if-ready"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_group_runtime_context.py --if-ready"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_group_source_delta.py"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_group_source_delta.py"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_source_huffman_locator.py"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_source_huffman_locator.py"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_source_group_codec_probe.py"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_source_group_codec_probe.py"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_group_text_candidate_resolution.py --if-ready"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_group_text_candidate_resolution.py --if-ready"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_unmatched_glyph_fuzzy.py --if-ready"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_unmatched_glyph_fuzzy.py --if-ready"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_group_script_corpus.py --if-ready"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_group_script_corpus.py --if-ready"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_source_record_pairing.py"
            ),
        )
        self.assertLess(
            RUNTIME_STAGE.index(
                "python tools/v5_1_source_record_pairing.py"
            ),
            RUNTIME_STAGE.index(
                "python tools/v5_1_confirmed_group_unicode.py --if-ready"
            ),
        )

    def test_manager_logs_include_launcher_details(self) -> None:
        self.assertIn("tail -n 40 \"$private_log\"", MANAGER)
        self.assertIn("tail -n 80 \"$launcher_log\"", MANAGER)

    def test_runtime_stage_replaces_stale_next_step_text(self) -> None:
        self.assertIn("새 후보를 자동 검사하고 있습니다", RUNTIME_STAGE)
        self.assertIn("자동 검사 실패 지점을 안전하게 기록했습니다", RUNTIME_STAGE)


if __name__ == "__main__":
    unittest.main()
