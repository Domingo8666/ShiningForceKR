#!/data/data/com.termux/files/usr/bin/bash
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
state_dir="${SFKR_AUTOPILOT_STATE_DIR:-$HOME/.local/state/shiningforcekr}"
status_file="${SFKR_AUTOPILOT_STATUS_FILE:-$root/reports/AUTOPILOT_STATUS.txt}"
private_log="$state_dir/autopilot.log"
launcher_log="$state_dir/launcher.log"
lock_pid_file="$state_dir/lock/pid"

while true; do
  battery_status="$(getprop debug.tracing.battery_status 2>/dev/null || true)"
  case "$battery_status" in
    2)
      refresh_interval=2
      power_label="충전 중"
      ;;
    5)
      refresh_interval=2
      power_label="충전 완료"
      ;;
    *)
      refresh_interval=10
      power_label="충전 중 아님"
      ;;
  esac

  printf '\033[2J\033[H'
  printf '%s\n' 'Shining Force KR - S25U 실시간 자동작업'
  printf '%s\n' '이 화면은 보기 전용이며 닫아도 자동작업은 계속됩니다.'
  printf '%s\n\n' "$power_label: ${refresh_interval}초마다 자동 새로고침합니다. 종료: Ctrl+C"

  live_pid=""
  if [ -s "$lock_pid_file" ]; then
    candidate="$(cat "$lock_pid_file" 2>/dev/null || true)"
    case "$candidate" in
      ''|*[!0-9]*)
        ;;
      *)
        candidate_command="$(tr '\000' ' ' <"/proc/$candidate/cmdline" 2>/dev/null || true)"
        if kill -0 "$candidate" 2>/dev/null &&
          [ "${candidate_command#*run_s25u_autopilot.sh}" != "$candidate_command" ]; then
          live_pid="$candidate"
        fi
        ;;
    esac
  fi

  if [ -n "$live_pid" ]; then
    printf '실제 프로세스: 실행 중 (PID %s)\n\n' "$live_pid"
  else
    printf '%s\n\n' '실제 프로세스: 실행 확인 불가'
  fi

  printf '%s\n' '----- 현재 상태 -----'
  if [ -s "$status_file" ]; then
    sed -n '1,12p' "$status_file"
  else
    printf '%s\n' '상태 파일을 기다리고 있습니다.'
  fi

  printf '\n%s\n' '----- 최근 실시간 로그 -----'
  if [ -s "$launcher_log" ]; then
    tail -n 18 "$launcher_log"
  elif [ -s "$private_log" ]; then
    tail -n 18 "$private_log"
  else
    printf '%s\n' '로그를 기다리고 있습니다.'
  fi
  sleep "$refresh_interval"
done
