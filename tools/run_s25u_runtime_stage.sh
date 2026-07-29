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

bash tools/setup_s25u_gearsystem.sh
setup_status=$?
if [ "$setup_status" -ne 0 ]; then
  stage_status="$setup_status"
  diagnostic_trigger=setup
else
  python tools/run_s25u_runtime_probe.py
  probe_status=$?
  if [ "$probe_status" -ne 0 ]; then
    stage_status="$probe_status"
    diagnostic_trigger=probe
  else
    python tools/v5_1_runtime_hit_resolver.py
    resolver_status=$?
    if [ "$resolver_status" -ne 0 ]; then
      stage_status="$resolver_status"
      diagnostic_trigger=probe
    else
      python tools/run_s25u_renderer_probe.py --if-needed
      renderer_probe_status=$?
      if [ "$renderer_probe_status" -ne 0 ]; then
        stage_status="$renderer_probe_status"
        diagnostic_trigger=probe
      else
        python tools/run_s25u_route_capture.py --if-needed
        route_capture_status=$?
        if [ "$route_capture_status" -ne 0 ]; then
          stage_status="$route_capture_status"
          diagnostic_trigger=probe
        fi
      fi
    fi
    if [ "$stage_status" -eq 0 ] && [ -n "$source_rom" ]; then
      python tools/v5_1_test_patch.py \
        --source-rom "$source_rom" \
        --if-ready
      test_build_status=$?
      if [ "$test_build_status" -ne 0 ]; then
        stage_status="$test_build_status"
        diagnostic_trigger=probe
      else
        python tools/v5_1_test_display_capture.py --if-ready
        display_capture_status=$?
        if [ "$display_capture_status" -ne 0 ]; then
          stage_status="$display_capture_status"
          diagnostic_trigger=probe
        fi
      fi
    fi
  fi
fi

python tools/v5_1_runtime_diagnostic.py \
  --trigger "$diagnostic_trigger" \
  --exit-code "$stage_status"
diagnostic_status=$?
if [ "$diagnostic_status" -ne 0 ] && [ "$stage_status" -eq 0 ]; then
  stage_status="$diagnostic_status"
fi

python tools/v5_1_runtime_bundle.py --publish
publish_status=$?
if [ "$publish_status" -ne 0 ]; then
  exit "$publish_status"
fi
exit "$stage_status"
