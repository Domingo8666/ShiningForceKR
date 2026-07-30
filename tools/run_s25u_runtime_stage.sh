#!/data/data/com.termux/files/usr/bin/bash
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

source_rom=""
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
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

stage_status=0
diagnostic_trigger=manual
failure_report="$root/reports/local/v5_1_runtime_failure.json"
next_step_file="$root/reports/NEXT_STEP.txt"
rm -f "$failure_report"

write_next_step() {
  next_step_temp="$next_step_file.tmp"
  mkdir -p "$(dirname "$next_step_file")"
  printf '%s\n' "$1" >"$next_step_temp"
  mv "$next_step_temp" "$next_step_file"
}

decoder_selection_ready() {
  selection_ready="$(
    python -c 'import json; from pathlib import Path; from tools.patch_io import sha256_file; from tools.v5_1_decoder_stream_resolution import validate_decoder_stream_resolution; path=Path("analysis/device/v5_1_latest_decoder_stream_resolution.json"); target=Path("build/Final_Conflict_Korean_v5.1.gg"); value=json.loads(path.read_text(encoding="utf-8")); validate_decoder_stream_resolution(value); print("yes" if target.is_file() and value.get("target_sha256") == sha256_file(target) and value.get("consumer_evidence_confirmed") is True and isinstance(value.get("selected_stream_index"), int) else "no")' 2>/dev/null || true
  )"
  [ "$selection_ready" = "yes" ]
}

group_selection_ready() {
  group_ready="$(
    python -c 'import json; from pathlib import Path; from tools.patch_io import sha256_file; from tools.v5_1_test_display_capture import validate_display_capture; path=Path("analysis/evidence/v5_1_confirmed_group_capture.json"); target=Path("build/Final_Conflict_Korean_v5.1.gg"); value=json.loads(path.read_text(encoding="utf-8")); validate_display_capture(value); group=value.get("group_entry"); print("yes" if target.is_file() and value.get("baseline_target_sha256") == sha256_file(target) and isinstance(group, dict) and group.get("status") == "resolved" and group.get("prefix_roundtrip_exact") is True else "no")' 2>/dev/null || true
  )"
  [ "$group_ready" = "yes" ]
}

record_stage_failure() {
  python tools/v5_1_runtime_stage_failure.py \
    --stage "$1" \
    --if-missing >/dev/null 2>&1 || true
}

write_next_step \
  "새 후보를 자동 검사하고 있습니다. 지금 사용자가 할 일은 없습니다."

bash tools/setup_s25u_gearsystem.sh
setup_status=$?
if [ "$setup_status" -ne 0 ]; then
  stage_status="$setup_status"
  diagnostic_trigger=setup
else
  if decoder_selection_ready || group_selection_ready; then
    echo "SFKR runtime stage: using the confirmed decoder stream."
  else
    python tools/run_s25u_runtime_probe.py
    probe_status=$?
    if [ "$probe_status" -ne 0 ]; then
      stage_status="$probe_status"
      diagnostic_trigger=probe
      record_stage_failure runtime-probe
    else
      python tools/v5_1_runtime_hit_resolver.py
      resolver_status=$?
      if [ "$resolver_status" -ne 0 ]; then
        stage_status="$resolver_status"
        diagnostic_trigger=probe
        record_stage_failure runtime-hit-resolver
      else
        python tools/run_s25u_renderer_probe.py --if-needed
        renderer_probe_status=$?
        if [ "$renderer_probe_status" -ne 0 ]; then
          stage_status="$renderer_probe_status"
          diagnostic_trigger=probe
          record_stage_failure renderer-probe
        else
          python tools/v5_1_decoder_stream_resolution.py
          stream_resolver_status=$?
          if [ "$stream_resolver_status" -ne 0 ]; then
            stage_status="$stream_resolver_status"
            diagnostic_trigger=probe
            record_stage_failure decoder-stream-resolution
          else
            python tools/run_s25u_route_capture.py --if-needed
            route_capture_status=$?
            if [ "$route_capture_status" -ne 0 ]; then
              stage_status="$route_capture_status"
              diagnostic_trigger=probe
              record_stage_failure route-capture
            fi
          fi
        fi
      fi
    fi
  fi

  if [ "$stage_status" -eq 0 ] && [ -n "$source_rom" ]; then
    comparison_attempt=1
    comparison_attempt_limit=8
    while [ "$comparison_attempt" -le "$comparison_attempt_limit" ]; do
      if ! decoder_selection_ready && ! group_selection_ready; then
        break
      fi

      rm -f \
        build/Final_Conflict_Korean_test_phrase.gg \
        build/Final_Conflict_Korean_test_phrase_overlay.ips \
        reports/local/v5_1_test_patch_build.json
      python tools/v5_1_test_patch.py \
        --source-rom "$source_rom" \
        --if-ready
      test_build_status=$?
      if [ "$test_build_status" -ne 0 ]; then
        stage_status="$test_build_status"
        diagnostic_trigger=probe
        record_stage_failure test-patch
        break
      fi
      if [ ! -f build/Final_Conflict_Korean_test_phrase.gg ] || \
        [ ! -f reports/local/v5_1_test_patch_build.json ]; then
        stage_status=1
        diagnostic_trigger=probe
        record_stage_failure test-patch
        break
      fi

      if command -v timeout >/dev/null 2>&1; then
        timeout -k 15s 720s \
          python tools/v5_1_test_display_capture.py --if-ready
      else
        python tools/v5_1_test_display_capture.py --if-ready
      fi
      display_capture_status=$?
      if [ "$display_capture_status" -ne 0 ]; then
        stage_status="$display_capture_status"
        diagnostic_trigger=probe
        record_stage_failure test-display-capture
        break
      fi

      comparison_result="$(
        python tools/v5_1_test_display_comparison.py --result-only
      )"
      comparison_status=$?
      if [ "$comparison_status" -ne 0 ]; then
        stage_status="$comparison_status"
        diagnostic_trigger=probe
        record_stage_failure display-comparison
        break
      fi
      if [ "$comparison_result" != "no-visible-pixel-change" ] && \
        [ "$comparison_result" != "technical-marker-absent-auto-rejected" ]; then
        break
      fi

      python tools/v5_1_decoder_stream_resolution.py
      stream_resolver_status=$?
      if [ "$stream_resolver_status" -ne 0 ]; then
        stage_status="$stream_resolver_status"
        diagnostic_trigger=probe
        record_stage_failure decoder-stream-resolution
        break
      fi
      comparison_attempt=$((comparison_attempt + 1))
    done
  fi
fi

python tools/v5_1_runtime_diagnostic.py \
  --trigger "$diagnostic_trigger" \
  --exit-code "$stage_status"
diagnostic_status=$?
if [ "$diagnostic_status" -ne 0 ] && [ "$stage_status" -eq 0 ]; then
  stage_status="$diagnostic_status"
fi
if [ "$stage_status" -ne 0 ]; then
  write_next_step \
    "자동 검사 실패 지점을 안전하게 기록했습니다. 자동실행기를 끄지 말고 다음 수정이 올 때까지 기다려주세요."
fi

python tools/v5_1_runtime_bundle.py --publish
publish_status=$?
if [ "$publish_status" -ne 0 ]; then
  exit "$publish_status"
fi
exit "$stage_status"
