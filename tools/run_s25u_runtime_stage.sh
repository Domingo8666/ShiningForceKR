#!/data/data/com.termux/files/usr/bin/bash
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

bash tools/setup_s25u_gearsystem.sh
setup_status=$?
if [ "$setup_status" -ne 0 ]; then
  python tools/v5_1_runtime_diagnostic.py \
    --trigger setup \
    --exit-code "$setup_status" \
    --publish
  exit "$setup_status"
fi

python tools/run_s25u_runtime_probe.py --publish-safe-observation
probe_status=$?
if [ "$probe_status" -ne 0 ]; then
  python tools/v5_1_runtime_diagnostic.py \
    --trigger probe \
    --exit-code "$probe_status" \
    --publish
  exit "$probe_status"
fi

python tools/v5_1_runtime_hit_resolver.py --publish-safe-resolution
resolver_status=$?
if [ "$resolver_status" -ne 0 ]; then
  python tools/v5_1_runtime_diagnostic.py \
    --trigger probe \
    --exit-code "$resolver_status" \
    --publish
  exit "$resolver_status"
fi

exit 0
