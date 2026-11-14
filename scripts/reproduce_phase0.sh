#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:?Usage: bash scripts/reproduce_phase0.sh NEW_OUTPUT_DIRECTORY [HOST_MANIFEST]}"
host_manifest="${2:-experiments/phase0/host.json}"
if [[ -e "$out" ]]; then
  printf '%s\n' "Evidence directory already exists: $out" >&2
  exit 2
fi
if [[ -x .tools/uv-x86_64-unknown-linux-gnu/uv ]]; then
  uv_bin=.tools/uv-x86_64-unknown-linux-gnu/uv
else
  uv_bin=uv
fi
# Keep ML dependencies on the Linux filesystem under WSL; source/evidence stay
# in the project. Override IDS_VENV for a different isolated environment.
venv_path="${IDS_VENV:-${XDG_CACHE_HOME:-$HOME/.cache}/ai-soc-phase0/venv}"
UV_PROJECT_ENVIRONMENT="$venv_path" "$uv_bin" sync --frozen --extra test --extra records
export PATH="$venv_path/bin:$PATH"
export OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
"$venv_path/bin/python" -m pytest -q
"$venv_path/bin/python" -m ids.export.smoke --output "$out" --host-manifest "$host_manifest"
