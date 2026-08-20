#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE=static
FRESH=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime) PROFILE=runtime ;;
    --full) PROFILE=full ;;
    --fresh) FRESH=1 ;;
    *) echo "ci_argument_invalid" >&2; exit 64 ;;
  esac
  shift
done
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
ARGS=("$PROFILE")
[[ "$FRESH" == 1 ]] && ARGS+=(--fresh)
exec python3 -m xenoid.gates "${ARGS[@]}"
