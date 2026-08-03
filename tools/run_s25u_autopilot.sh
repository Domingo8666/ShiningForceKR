#!/data/data/com.termux/files/usr/bin/bash
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_rom="${SFKR_SOURCE_ROM:-/storage/emulated/0/ROM/Shining Force Gaiden - Final Conflict (Japan).gg}"
interval="${SFKR_AUTOPILOT_INTERVAL:-30}"
runtime_timeout="${SFKR_RUNTIME_TIMEOUT:-480}"
nice_level="${SFKR_AUTOPILOT_NICE:-15}"
state_dir="${SFKR_AUTOPILOT_STATE_DIR:-$HOME/.local/state/shiningforcekr}"
once=0
force=0

usage() {
  cat <<'EOF'
Usage: bash tools/run_s25u_autopilot.sh [options]

Options:
  --source-rom PATH  S25U-local original ROM path
  --interval SEC     GitHub poll interval (minimum/default 30)
  --runtime-timeout SEC
                      Runtime-stage wall limit (minimum/default 480)
  --state-dir PATH   Termux-private state directory
  --force            Run once even if the current commit was already processed
  --once             Exit after one synchronization/run decision
  --help              Show this help

The original ROM and generated ROM remain on the S25U. Only the repository's
validated sanitized runtime bundle may be committed and pushed.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --source-rom)
      if [ "$#" -lt 2 ]; then
        echo "--source-rom requires a path" >&2
        exit 2
      fi
      source_rom="$2"
      shift 2
      ;;
    --interval)
      if [ "$#" -lt 2 ]; then
        echo "--interval requires seconds" >&2
        exit 2
      fi
      interval="$2"
      shift 2
      ;;
    --runtime-timeout)
      if [ "$#" -lt 2 ]; then
        echo "--runtime-timeout requires seconds" >&2
        exit 2
      fi
      runtime_timeout="$2"
      shift 2
      ;;
    --state-dir)
      if [ "$#" -lt 2 ]; then
        echo "--state-dir requires a path" >&2
        exit 2
      fi
      state_dir="$2"
      shift 2
      ;;
    --force)
      force=1
      shift
      ;;
    --once)
      once=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

case "$interval" in
  ''|*[!0-9]*)
    echo "--interval must be an integer" >&2
    exit 2
    ;;
esac
if [ "$interval" -lt 30 ]; then
  echo "--interval must be at least 30 seconds" >&2
  exit 2
fi
case "$runtime_timeout" in
  ''|*[!0-9]*)
    echo "--runtime-timeout must be an integer" >&2
    exit 2
    ;;
esac
if [ "$runtime_timeout" -lt 300 ]; then
  echo "--runtime-timeout must be at least 300 seconds" >&2
  exit 2
fi
case "$nice_level" in
  ''|*[!0-9]*)
    echo "SFKR_AUTOPILOT_NICE must be an integer from 0 to 19" >&2
    exit 2
    ;;
esac
if [ "$nice_level" -gt 19 ]; then
  echo "SFKR_AUTOPILOT_NICE must be an integer from 0 to 19" >&2
  exit 2
fi

mkdir -p "$state_dir"
log_file="$state_dir/autopilot.log"
last_head_file="$state_dir/last_processed_head"
stop_file="$state_dir/STOP"
lock_dir="$state_dir/lock"
lock_pid_file="$lock_dir/pid"
status_file="${SFKR_AUTOPILOT_STATUS_FILE:-$root/reports/AUTOPILOT_STATUS.txt}"
runtime_state="실행 중"
last_status_message="시작 준비 중"

write_runtime_status() {
  local current_head="확인 중"
  local processed_head="아직 없음"
  local next_step="확인 중"
  local status_temp=""
  if git -C "$root" rev-parse HEAD >/dev/null 2>&1; then
    current_head="$(git -C "$root" rev-parse HEAD)"
  fi
  if [ -s "$last_head_file" ]; then
    processed_head="$(cat "$last_head_file")"
  fi
  if [ -s "$root/reports/NEXT_STEP.txt" ]; then
    next_step="$(head -n 1 "$root/reports/NEXT_STEP.txt")"
  fi

  mkdir -p "$(dirname "$status_file")"
  status_temp="$status_file.$$"
  {
    printf '%s\n' "Shining Force KR S25U 자동작업 상태"
    printf '%s\n' "상태: $runtime_state"
    printf '%s\n' "프로세스: $$"
    printf '%s\n' "현재 Git 커밋: $current_head"
    printf '%s\n' "마지막 처리 커밋: $processed_head"
    printf '%s\n' "현재 작업: $next_step"
    printf '%s\n' "최근 활동: $last_status_message"
    printf '%s\n' "자동 갱신 시각: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf '%s\n' "화면을 꺼도 Termux wake lock으로 계속 실행됩니다."
  } >"$status_temp" && mv "$status_temp" "$status_file"
}

log() {
  local line="$(date -u '+%Y-%m-%dT%H:%M:%SZ') $*"
  printf '%s\n' "$line"
  printf '%s\n' "$line" >>"$log_file"
  last_status_message="$*"
  write_runtime_status || true
}

acquire_lock() {
  if mkdir "$lock_dir" 2>/dev/null; then
    printf '%s\n' "$$" >"$lock_pid_file"
    return 0
  fi

  existing_pid=""
  if [ -f "$lock_pid_file" ]; then
    existing_pid="$(cat "$lock_pid_file" 2>/dev/null || true)"
  fi
  case "$existing_pid" in
    ''|*[!0-9]*)
      ;;
    *)
      if kill -0 "$existing_pid" 2>/dev/null; then
        log "another S25U autopilot process already owns the lock"
        return 3
      fi
      ;;
  esac

  rm -f "$lock_pid_file"
  if ! rmdir "$lock_dir" 2>/dev/null ||
    ! mkdir "$lock_dir" 2>/dev/null; then
    log "stale autopilot lock could not be recovered safely"
    return 3
  fi
  printf '%s\n' "$$" >"$lock_pid_file"
}

if ! acquire_lock; then
  exit 3
fi

wake_lock=0
cleanup() {
  cleanup_status=$?
  if [ "$cleanup_status" -eq 0 ]; then
    runtime_state="중지됨"
    last_status_message="자동작업이 정상 종료되었습니다."
  else
    runtime_state="오류 종료 ($cleanup_status)"
    last_status_message="자동작업이 오류 상태로 종료되었습니다."
  fi
  write_runtime_status || true
  if [ "$wake_lock" -eq 1 ] && command -v termux-wake-unlock >/dev/null 2>&1; then
    termux-wake-unlock >/dev/null 2>&1 || true
  fi
  lock_owner=""
  if [ -f "$lock_pid_file" ]; then
    lock_owner="$(cat "$lock_pid_file" 2>/dev/null || true)"
  fi
  if [ "$lock_owner" = "$$" ]; then
    rm -f "$lock_pid_file"
    rmdir "$lock_dir" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

if command -v termux-wake-lock >/dev/null 2>&1; then
  if termux-wake-lock >/dev/null 2>&1; then
    wake_lock=1
  fi
fi

cd "$root"

if command -v renice >/dev/null 2>&1; then
  renice -n "$nice_level" -p "$$" >/dev/null 2>&1 || true
fi

if [ ! -f "$source_rom" ]; then
  log "source ROM is not available at the configured S25U-local path"
  exit 4
fi
case "$source_rom" in
  /storage/emulated/0/*|"$HOME"/storage/shared/*)
    ;;
  *)
    log "source ROM must remain in S25U shared storage"
    exit 4
    ;;
esac

if [ "$(git branch --show-current)" != "main" ]; then
  log "autopilot requires the main branch"
  exit 5
fi
remote_url="$(git remote get-url origin)"
case "$remote_url" in
  https://github.com/Domingo8666/ShiningForceKR|\
  https://github.com/Domingo8666/ShiningForceKR.git|\
  git@github.com:Domingo8666/ShiningForceKR|\
  git@github.com:Domingo8666/ShiningForceKR.git)
    ;;
  *)
    log "origin is not the canonical ShiningForceKR repository"
    exit 5
    ;;
esac

git config --local pack.threads 1
git config --local index.threads 1
git config --local checkout.workers 1
log "background priority nice=$nice_level; git worker threads=1"

is_safe_artifact() {
  case "$1" in
    analysis/device/v5_1_latest_runtime_observation.json|\
    analysis/device/v5_1_latest_renderer_observation.json|\
    analysis/device/v5_1_latest_decoder_register_trace.json|\
    analysis/device/v5_1_latest_decoder_stream_resolution.json|\
    analysis/device/v5_1_latest_route_capture.json|\
    analysis/device/v5_1_latest_runtime_diagnostic.json|\
    analysis/device/v5_1_latest_consumer_resolution.json|\
    analysis/device/v5_1_latest_display_capture.json|\
    analysis/device/v5_1_latest_display_comparison.json|\
    analysis/device/v5_1_latest_display_review.json|\
    analysis/device/v5_1_latest_visible_entry_proof.json|\
    analysis/device/v5_1_latest_poc_expansion_proof.json|\
    analysis/device/v5_1_latest_visible_script_roundtrip.json|\
    analysis/device/v5_1_latest_renderer_output_trace.json|\
    analysis/device/v5_1_latest_active_vram_route.json|\
    analysis/device/v5_1_latest_active_ram_producer.json|\
    analysis/device/v5_1_latest_active_ram_writer_source.json|\
    analysis/device/v5_1_latest_active_ram_register_trace.json|\
    analysis/device/v5_1_latest_active_register_rom_source.json|\
    analysis/device/v5_1_latest_active_rom_source_role.json|\
    analysis/device/v5_1_latest_active_rom_read_block.json|\
    analysis/device/v5_1_latest_active_rom_lookup_index_producer.json|\
    analysis/device/v5_1_latest_active_rom_path_scope.json|\
    analysis/device/v5_1_latest_first_context_translated_vram_diff.json|\
    analysis/device/v5_1_latest_first_context_translated_glyph_route.json|\
    analysis/device/v5_1_latest_first_context_direct_renderer_capture.json|\
    analysis/device/v5_1_latest_first_context_direct_renderer_capture.png|\
    analysis/device/v5_1_latest_first_context_direct_renderer_screenshot.json|\
    analysis/device/v5_1_latest_first_context_direct_renderer_screenshot.png|\
    analysis/device/v5_1_latest_first_context_direct_renderer_capture_failure_stage.txt|\
    analysis/device/v5_1_latest_active_rom_cursor_reset.json|\
    analysis/device/v5_1_latest_critical_path.json|\
    analysis/device/v5_1_latest_visible_unicode_mapping.json|\
    analysis/device/v5_1_latest_initial_font_page_trace.json|\
    analysis/device/v5_1_latest_font_transfer_source.json|\
    analysis/device/v5_1_latest_confirmed_group_extract.json|\
    analysis/device/v5_1_latest_target_group_usage.json|\
    analysis/device/v5_1_latest_decoder_caller_resolution.json|\
    analysis/device/v5_1_latest_target_group_stream_map.json|\
    analysis/device/v5_1_latest_target_group_population.json|\
    analysis/device/v5_1_latest_target_group_population_decode.json|\
    analysis/device/v5_1_latest_target_group_expanded_corpus.json|\
    analysis/device/v5_1_latest_target_group_expanded_glyphs.json|\
    analysis/device/v5_1_latest_target_group_non_hangul_glyphs.json|\
    analysis/device/v5_1_latest_target_group_record_quality.json|\
    analysis/device/v5_1_latest_source_script_reference.json|\
    analysis/device/v5_1_latest_source_target_anchor.json|\
    analysis/device/v5_1_latest_source_target_section_projection.json|\
    analysis/device/v5_1_latest_source_target_structural_corroboration.json|\
    analysis/device/v5_1_latest_source_target_runtime_sequence.json|\
    analysis/device/v5_1_latest_source_target_runtime_context.json|\
    analysis/device/v5_1_latest_runtime_context_glyph_demand.json|\
    analysis/device/v5_1_latest_runtime_context_glyph_candidates.json|\
    analysis/device/v5_1_latest_runtime_context_glyph_review.json|\
    analysis/device/v5_1_latest_runtime_context_glyph_preservation.json|\
    analysis/device/v5_1_latest_first_context_translation_review.json|\
    analysis/device/v5_1_latest_first_context_translation_approval.json|\
    analysis/device/v5_1_latest_first_context_translation_capacity.json|\
    analysis/device/v5_1_latest_first_context_translation_encoding.json|\
    analysis/device/v5_1_latest_first_context_translation_encoding_failure.json|\
    analysis/device/v5_1_latest_first_context_record_reinsertion.json|\
    analysis/device/v5_1_latest_first_context_translation_test_build.json|\
    analysis/device/v5_1_latest_first_context_translation_runtime_capture.json|\
    analysis/device/v5_1_latest_first_context_translation_runtime_capture_failure.json|\
    analysis/device/v5_1_latest_first_context_translation_visual_review.json|\
    analysis/device/v5_1_latest_first_context_consumer_trace.json|\
    analysis/device/v5_1_latest_group_context_resolution.json|\
    analysis/device/v5_1_latest_group_runtime_context.json|\
    analysis/device/v5_1_latest_group_source_delta.json|\
    analysis/device/v5_1_latest_source_huffman_locator.json|\
    analysis/device/v5_1_latest_source_group_codec_probe.json|\
    analysis/device/v5_1_latest_group_text_candidate_resolution.json|\
    analysis/device/v5_1_latest_unmatched_glyph_fuzzy.json|\
    analysis/device/v5_1_latest_group_script_corpus.json|\
    analysis/device/v5_1_latest_source_record_pairing.json|\
    analysis/device/v5_1_latest_confirmed_group_unicode.json|\
    analysis/device/v5_1_latest_progress_preview.json|\
    analysis/device/v5_1_latest_progress_preview.png)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

publish_pending_safe_artifacts() {
  changed="$(git status --porcelain --untracked-files=all)"
  if [ -z "$changed" ]; then
    return 0
  fi

  while IFS= read -r entry; do
    path="${entry:3}"
    case "$path" in
      *" -> "*)
        path="${path##* -> }"
        ;;
    esac
    if ! is_safe_artifact "$path"; then
      log "refusing to touch a tracked local change outside the safe artifact set"
      return 6
    fi
  done <<EOF
$changed
EOF

  log "publishing validated pending safe artifacts"
  python tools/v5_1_runtime_bundle.py --publish --no-push
  publish_status=$?
  if [ "$publish_status" -ne 0 ]; then
    return "$publish_status"
  fi

  residual="$(git status --porcelain --untracked-files=all)"
  if [ -z "$residual" ]; then
    return 0
  fi

  residual_paths=()
  while IFS= read -r entry; do
    path="${entry:3}"
    case "$path" in
      *" -> "*)
        path="${path##* -> }"
        ;;
    esac
    if ! is_safe_artifact "$path"; then
      log "refusing to quarantine a residual change outside the safe artifact set"
      return 6
    fi
    residual_paths+=("$path")
  done <<EOF
$residual
EOF

  log "quarantining residual unvalidated safe artifacts locally"
  if ! git stash push -u \
    -m "SFKR unvalidated safe artifacts $(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    -- "${residual_paths[@]}" >/dev/null; then
    log "residual safe artifacts could not be quarantined"
    return 6
  fi
  if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
    log "repository is still dirty after safe artifact quarantine"
    return 6
  fi
  log "residual unvalidated safe artifacts quarantined in local git stash"
}

safe_local_commits_only() {
  range="$1"
  commits="$(git rev-list "$range")"
  if [ -z "$commits" ]; then
    return 1
  fi
  for commit in $commits; do
    if [ "$(git show -s --format=%s "$commit")" != \
      "Record sanitized S25U runtime bundle" ]; then
      return 1
    fi
    paths="$(git diff-tree --no-commit-id --name-only -r "$commit")"
    if [ -z "$paths" ]; then
      return 1
    fi
    while IFS= read -r path; do
      if ! is_safe_artifact "$path"; then
        return 1
      fi
    done <<EOF
$paths
EOF
  done
  return 0
}

sync_main() {
  publish_pending_safe_artifacts
  pending_status=$?
  if [ "$pending_status" -ne 0 ]; then
    return "$pending_status"
  fi
  if ! git fetch origin main; then
    log "GitHub fetch failed"
    return 7
  fi

  local_head="$(git rev-parse HEAD)"
  remote_head="$(git rev-parse origin/main)"
  if [ "$local_head" = "$remote_head" ]; then
    return 0
  fi

  if git merge-base --is-ancestor "$local_head" "$remote_head"; then
    git merge --ff-only "$remote_head"
    return $?
  fi

  if git merge-base --is-ancestor "$remote_head" "$local_head"; then
    if ! safe_local_commits_only "origin/main..HEAD"; then
      log "local branch is ahead with non-runtime changes; refusing automatic push"
      return 8
    fi
    git push origin HEAD:main
    return $?
  fi

  merge_base="$(git merge-base HEAD origin/main)"
  if ! safe_local_commits_only "$merge_base..HEAD"; then
    log "local and remote branches diverged with non-runtime changes"
    return 8
  fi
  if ! git rebase origin/main; then
    git rebase --abort >/dev/null 2>&1 || true
    log "safe runtime bundle could not be rebased automatically"
    return 8
  fi
  git push origin HEAD:main
}

record_processed_head() {
  head="$1"
  temp="$last_head_file.tmp"
  printf '%s\n' "$head" >"$temp"
  mv "$temp" "$last_head_file"
}

runtime_failure_is_retryable() {
  diagnostic="$root/analysis/device/v5_1_latest_runtime_diagnostic.json"
  [ -f "$diagnostic" ] || return 1
  python - "$diagnostic" <<'PY'
import json
from pathlib import Path
import sys

retryable = {
    "subprocess-timeout",
    "process-io",
    "mcp-timeout",
    "frame-step-timeout",
    "instruction-step-timeout",
    "mcp-error",
    "tool-error",
}
try:
    value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    failure = value["runtime_failure"]
    kind = failure["failure_kind"]
except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0 if kind in retryable else 1)
PY
}

runtime_diagnostic_sha() {
  diagnostic="$root/analysis/device/v5_1_latest_runtime_diagnostic.json"
  if [ -f "$diagnostic" ]; then
    git hash-object -- "$diagnostic"
  fi
}

run_current_head() {
  input_head="$(git rev-parse HEAD)"
  diagnostic_before="$(runtime_diagnostic_sha)"
  log "starting S25U runtime stage for commit $input_head"
  SFKR_DEFER_RUNTIME_BUNDLE_PUSH=1 \
    timeout -k 30s "$runtime_timeout" \
    bash tools/run_s25u_runtime_stage.sh --source-rom "$source_rom"
  stage_status=$?
  if [ "$stage_status" -eq 124 ] || [ "$stage_status" -eq 137 ]; then
    log "S25U runtime stage exceeded ${runtime_timeout}s; it will be retried"
  fi

  post_head="$(git rev-parse HEAD)"
  remote_head=""
  if git fetch origin main >/dev/null 2>&1; then
    remote_head="$(git rev-parse origin/main)"
  else
    log "could not verify the published runtime result against origin/main"
  fi

  if [ "$stage_status" -eq 0 ]; then
    # The runtime stage may create a validated local bundle commit. Mark that
    # output commit as processed now so the next synchronization pushes it but
    # does not feed the generated bundle back through the entire pipeline.
    record_processed_head "$post_head"
    if [ -n "$remote_head" ] && [ "$post_head" != "$remote_head" ]; then
      log "successful runtime result $post_head is queued for synchronization"
    fi
  elif [ "$stage_status" -eq 124 ] || [ "$stage_status" -eq 137 ]; then
    log "transient runtime timeout keeps commit $post_head eligible for retry"
  elif [ -z "$(runtime_diagnostic_sha)" ] || \
    [ "$(runtime_diagnostic_sha)" = "$diagnostic_before" ]; then
    log "runtime stage produced no fresh diagnostic; keeping commit $post_head eligible for retry"
  elif runtime_failure_is_retryable; then
    log "transient runtime diagnostic keeps commit $post_head eligible for retry"
  else
    record_processed_head "$post_head"
    log "deterministic runtime diagnostic recorded; waiting for a new commit after $post_head"
  fi

  log "S25U runtime stage finished with status $stage_status"
  return "$stage_status"
}

log "S25U autopilot started"
while true; do
  cycle_status=0
  if [ -e "$stop_file" ]; then
    log "STOP marker found; autopilot is exiting"
    exit 0
  fi

  if sync_main; then
    current_head="$(git rev-parse HEAD)"
    last_head=""
    if [ -f "$last_head_file" ]; then
      last_head="$(cat "$last_head_file")"
    fi
    if [ "$force" -eq 1 ]; then
      run_current_head
      cycle_status=$?
      force=0
    elif [ -n "$last_head" ] && [ "$current_head" != "$last_head" ] &&
      git merge-base --is-ancestor "$last_head" "$current_head" &&
      safe_local_commits_only "$last_head..$current_head"; then
      # A successful stage can leave a few validated artifacts for the next
      # synchronization pass. If that pass creates only sanitized runtime
      # bundle commits, they are outputs of the completed stage, not new work.
      record_processed_head "$current_head"
      log "synchronized generated runtime artifacts through $current_head; waiting for a new source commit"
    elif [ "$current_head" != "$last_head" ]; then
      run_current_head
      cycle_status=$?
    else
      log "commit $current_head was already processed"
    fi
  else
    sync_status=$?
    cycle_status="$sync_status"
    log "repository synchronization stopped with status $sync_status"
  fi

  if [ "$once" -eq 1 ]; then
    log "finalizing one-shot runtime artifacts"
    sync_main
    final_sync_status=$?
    if [ "$final_sync_status" -ne 0 ]; then
      log "one-shot runtime artifact synchronization stopped with status $final_sync_status"
      if [ "$cycle_status" -eq 0 ]; then
        cycle_status="$final_sync_status"
      fi
    else
      log "one-shot runtime artifacts synchronized"
    fi
    exit "$cycle_status"
  fi
  sleep "$interval"
done
