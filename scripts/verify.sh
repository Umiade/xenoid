#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
PROFILE="verify"
if [[ $# -gt 0 && "$1" != -* ]]; then
  PROFILE="$1"
  shift
fi
exec python3 -m xenoid.gates "$PROFILE" "$@"
