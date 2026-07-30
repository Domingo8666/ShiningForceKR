#!/data/data/com.termux/files/usr/bin/bash
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_rom="${SFKR_SOURCE_ROM:-/storage/emulated/0/ROM/Shining Force Gaiden - Final Conflict (Japan).gg}"
interval="${SFKR_AUTOPILOT_INTERVAL:-30}"
state_dir="${SFKR_AUTOPILOT_STATE_DIR:-$HOME/.local/state/shiningforcekr}"
once=0
force=0

usage() {
  cat <<'EOF'
Usage: bash tools/run_s25u_autopilot.sh [options]

Options:
  --source-rom PATH  S25U-local original ROM path
  --interval SEC     GitHub poll interval (minimum/default 30)
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

mkdir -p "$state_dir"
log_file="$state_dir/autopilot.log"
last_head_file="$state_dir/last_processed_head"
stop_file="$state_dir/STOP"
lock_dir="$state_dir/lock"
lock_pid_file="$lock_dir/pid"

log() {
  line="$(date -u '+%Y-%m-%dT%H:%M:%SZ') $*"
  printf '%s\n' "$line"
  printf '%s\n' "$line" >>"$log_file"
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
  changed="$(git status --porcelain --untracked-files=no)"
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
  python tools/v5_1_runtime_bundle.py --publish
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

run_current_head() {
  input_head="$(git rev-parse HEAD)"
  log "starting S25U runtime stage for commit $input_head"
  bash tools/run_s25u_runtime_stage.sh --source-rom "$source_rom"
  stage_status=$?

  if git fetch origin main >/dev/null 2>&1; then
    post_head="$(git rev-parse HEAD)"
    remote_head="$(git rev-parse origin/main)"
    if [ "$post_head" = "$remote_head" ]; then
      record_processed_head "$post_head"
    else
      log "runtime result is not synchronized with origin/main"
    fi
  else
    log "could not verify the published runtime result against origin/main"
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
    if [ "$force" -eq 1 ] || [ "$current_head" != "$last_head" ]; then
      run_current_head
      cycle_status=$?
      force=0
    else
      log "commit $current_head was already processed"
    fi
  else
    sync_status=$?
    cycle_status="$sync_status"
    log "repository synchronization stopped with status $sync_status"
  fi

  if [ "$once" -eq 1 ]; then
    exit "$cycle_status"
  fi
  sleep "$interval"
done
