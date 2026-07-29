#!/usr/bin/env bash
set -euo pipefail

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required: https://brew.sh" >&2
  exit 1
fi
brew install colima docker android-platform-tools scrcpy || true
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install -e .
mkdir -p .xenoid
xenoid init || true
cat <<'MSG'
Next:
  colima start --arch aarch64 --vm-type vz --memory 8 --cpu 8
  xenoid doctor
  xenoid start --dry-run
  xenoid start
MSG
