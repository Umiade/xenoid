#!/usr/bin/env bash
set -euo pipefail

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required: https://brew.sh" >&2
  exit 1
fi
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install -e .
./xenoid install-runtime
mkdir -p .xenoid
xenoid init || true
cat <<'MSG'
Next:
  ./xenoid up
  ./xenoid doctor --require-runtime
MSG
