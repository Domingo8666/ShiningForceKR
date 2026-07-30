#!/data/data/com.termux/files/usr/bin/bash
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_rom="${SFKR_SOURCE_ROM:-/storage/emulated/0/ROM/Shining Force Gaiden - Final Conflict (Japan).gg}"
interval="${SFKR_AUTOPILOT_INTERVAL:-30}"
state_dir="${SFKR_AUTOPILOT_STATE_DIR:-$HOME/.local/state/shiningforcekr}"
status_file="$root/reports/AUTOPILOT_STATUS.txt"
action="status"

usage() {
  cat <<'EOF'
Usage: bash tools/manage_s25u_autopilot.sh ACTION [options]

Actions:
  install  Install the private Termux:Boot launcher and start the autopilot
  start    Start the autopilot in the background
  restart  Stop the owned process tree, then start the autopilot
  stop     Request a safe stop and signal the current autopilot process
  status   Write and print the current status (default)
  logs     Print the last 40 private log lines

Options:
  --source-rom PATH  S25U-local original ROM path
  --interval SEC     GitHub poll interval (minimum/default 30)
  --state-dir PATH   Termux-private state directory
  --status-file PATH Human-readable status file
  --help             Show this help

The launcher stores only paths and process state in Termux-private storage.
ROMs and generated ROMs remain in S25U shared storage and are never pushed.
EOF
}

if [ "$#" -gt 0 ]; then
  case "$1" in
    install|start|restart|stop|status|logs)
      action="$1"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown action: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
fi

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
    --status-file)
      if [ "$#" -lt 2 ]; then
        echo "--status-file requires a path" >&2
        exit 2
      fi
      status_file="$2"
      shift 2
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
lock_pid_file="$state_dir/lock/pid"
launcher_pid_file="$state_dir/launcher_pid"
stop_file="$state_dir/STOP"
private_log="$state_dir/autopilot.log"
launcher_log="$state_dir/launcher.log"
boot_launcher="$HOME/.termux/boot/shiningforcekr-autopilot"

read_live_pid() {
  local candidate=""
  local candidate_command=""
  if [ -f "$lock_pid_file" ]; then
    candidate="$(cat "$lock_pid_file" 2>/dev/null || true)"
  fi
  case "$candidate" in
    ''|*[!0-9]*)
      return 1
      ;;
  esac
  if ! kill -0 "$candidate" 2>/dev/null; then
    return 1
  fi
  if [ ! -r "/proc/$candidate/cmdline" ]; then
    return 1
  fi
  candidate_command="$(
    tr '\000' ' ' <"/proc/$candidate/cmdline" 2>/dev/null || true
  )"
  case "$candidate_command" in
    *run_s25u_autopilot.sh*)
      ;;
    *)
      return 1
      ;;
  esac
  printf '%s\n' "$candidate"
}

collect_owned_descendants() {
  local parent_pid="$1"
  local process_status=""
  local child_pid=""
  local child_parent=""
  for process_status in /proc/[0-9]*/status; do
    [ -r "$process_status" ] || continue
    child_pid="${process_status#/proc/}"
    child_pid="${child_pid%/status}"
    [ "$child_pid" = "$parent_pid" ] && continue
    child_parent="$(
      awk '$1 == "PPid:" { print $2; exit }' \
        "$process_status" 2>/dev/null || true
    )"
    if [ "$child_parent" = "$parent_pid" ]; then
      collect_owned_descendants "$child_pid"
      owned_descendants="$owned_descendants $child_pid"
    fi
  done
}

stop_autopilot() {
  touch "$stop_file"
  running_pid=""
  if running_pid="$(read_live_pid)"; then
    owned_descendants=""
    collect_owned_descendants "$running_pid"
    for owned_pid in $owned_descendants; do
      kill -TERM "$owned_pid" 2>/dev/null || true
    done
    kill -TERM "$running_pid" 2>/dev/null || true

    stop_attempt=0
    while [ "$stop_attempt" -lt 10 ] &&
      kill -0 "$running_pid" 2>/dev/null; do
      sleep 1
      stop_attempt=$((stop_attempt + 1))
    done
    if read_live_pid >/dev/null 2>&1; then
      owned_descendants=""
      collect_owned_descendants "$running_pid"
      for owned_pid in $owned_descendants; do
        kill -KILL "$owned_pid" 2>/dev/null || true
      done
      kill -KILL "$running_pid" 2>/dev/null || true
    fi
    echo "Stopped owned S25U autopilot process tree for PID $running_pid"
  else
    echo "S25U autopilot is not running"
  fi
  write_status
}

write_status() {
  live_pid=""
  state="중지됨"
  if live_pid="$(read_live_pid)"; then
    if [ -e "$stop_file" ]; then
      state="중지 처리 중"
    else
      state="실행 중"
    fi
  elif [ -e "$stop_file" ]; then
    state="중지 요청됨"
  fi

  current_head="확인 불가"
  if git -C "$root" rev-parse HEAD >/dev/null 2>&1; then
    current_head="$(git -C "$root" rev-parse HEAD)"
  fi
  last_head="아직 없음"
  if [ -s "$state_dir/last_processed_head" ]; then
    last_head="$(cat "$state_dir/last_processed_head")"
  fi
  last_log="아직 없음"
  if [ -s "$private_log" ]; then
    last_log="$(tail -n 1 "$private_log")"
  elif [ -s "$launcher_log" ]; then
    last_log="$(tail -n 1 "$launcher_log")"
  fi
  boot_state="미설치"
  if [ -x "$boot_launcher" ]; then
    boot_state="설치됨"
  fi

  status_parent="$(dirname "$status_file")"
  mkdir -p "$status_parent"
  status_temp="$status_file.tmp"
  {
    printf '%s\n' "Shining Force KR S25U 자동작업 상태"
    printf '%s\n' "상태: $state"
    if [ -n "$live_pid" ]; then
      printf '%s\n' "프로세스: $live_pid"
    fi
    printf '%s\n' "부팅 실행기: $boot_state"
    printf '%s\n' "현재 Git 커밋: $current_head"
    printf '%s\n' "마지막 처리 커밋: $last_head"
    printf '%s\n' "마지막 기록: $last_log"
    printf '%s\n' "확인 시각: $(date '+%Y-%m-%d %H:%M:%S %Z')"
  } >"$status_temp"
  mv "$status_temp" "$status_file"
  cat "$status_file"
}

validate_start_inputs() {
  case "${PREFIX:-}" in
    /data/data/com.termux/files/usr)
      ;;
    *)
      echo "This command must run inside Termux on the S25U" >&2
      return 4
      ;;
  esac
  if [ ! -f "$source_rom" ]; then
    echo "Source ROM is not available at the configured S25U-local path" >&2
    return 4
  fi
  case "$source_rom" in
    /storage/emulated/0/*|"$HOME"/storage/shared/*)
      ;;
    *)
      echo "Source ROM must remain in S25U shared storage" >&2
      return 4
      ;;
  esac
  if [ ! -f "$root/tools/run_s25u_autopilot.sh" ]; then
    echo "S25U autopilot script is missing" >&2
    return 4
  fi
}

start_autopilot() {
  validate_start_inputs
  input_status=$?
  if [ "$input_status" -ne 0 ]; then
    return "$input_status"
  fi
  running_pid=""
  if running_pid="$(read_live_pid)"; then
    echo "S25U autopilot is already running as PID $running_pid"
    write_status
    return 0
  fi

  rm -f "$stop_file"
  nohup bash "$root/tools/run_s25u_autopilot.sh" \
    --source-rom "$source_rom" \
    --interval "$interval" \
    --state-dir "$state_dir" \
    >>"$launcher_log" 2>&1 </dev/null &
  launched_pid=$!
  printf '%s\n' "$launched_pid" >"$launcher_pid_file"

  attempt=0
  while [ "$attempt" -lt 10 ]; do
    if read_live_pid >/dev/null 2>&1; then
      echo "S25U autopilot started"
      write_status
      return 0
    fi
    if ! kill -0 "$launched_pid" 2>/dev/null; then
      echo "S25U autopilot exited during startup" >&2
      write_status
      return 5
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  echo "S25U autopilot did not publish a live lock in time" >&2
  write_status
  return 5
}

case "$action" in
  install)
    validate_start_inputs
    input_status=$?
    if [ "$input_status" -ne 0 ]; then
      exit "$input_status"
    fi
    mkdir -p "$(dirname "$boot_launcher")"
    boot_temp="$boot_launcher.tmp"
    {
      printf '%s\n' '#!/data/data/com.termux/files/usr/bin/bash'
      printf '%s\n' 'sleep 20'
      printf 'exec bash %q start --source-rom %q --interval %q --state-dir %q --status-file %q\n' \
        "$root/tools/manage_s25u_autopilot.sh" \
        "$source_rom" \
        "$interval" \
        "$state_dir" \
        "$status_file"
    } >"$boot_temp"
    chmod 700 "$boot_temp"
    mv "$boot_temp" "$boot_launcher"
    echo "Installed private Termux:Boot launcher: $boot_launcher"
    start_autopilot
    exit $?
    ;;
  start)
    start_autopilot
    exit $?
    ;;
  restart)
    stop_autopilot
    start_autopilot
    exit $?
    ;;
  stop)
    stop_autopilot
    ;;
  status)
    write_status
    ;;
  logs)
    printed=0
    if [ -s "$private_log" ]; then
      echo "=== 자동작업 요약 ==="
      tail -n 40 "$private_log"
      printed=1
    fi
    if [ -s "$launcher_log" ]; then
      echo "=== 실행 상세(마지막 80줄) ==="
      tail -n 80 "$launcher_log"
      printed=1
    fi
    if [ "$printed" -eq 0 ]; then
      echo "No S25U autopilot log is available yet"
    fi
    ;;
esac
