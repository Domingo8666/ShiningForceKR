#!/data/data/com.termux/files/usr/bin/bash
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

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
