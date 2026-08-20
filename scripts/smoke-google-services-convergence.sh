#!/usr/bin/env bash
# Prove that two automatic no-op convergences keep the same container, image,
# rootfs source, data filesystem, and immutable Google binding.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
INSTANCE="${XENOID_INSTANCE:-default}"
if [[ "${1:-}" == "--instance" ]]; then
  [[ $# -eq 2 ]] || { echo "--instance requires a name" >&2; exit 2; }
  INSTANCE="$2"
  shift 2
fi
[[ $# -eq 0 ]] || { echo "unknown argument: $1" >&2; exit 2; }
xenoid_cli() { ./xenoid --instance "$INSTANCE" "$@"; }
TMP="$(mktemp -d "${TMPDIR:-/tmp}/xenoid-google-convergence.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

capture() {
  local phase="$1"
  xenoid_cli status > "$TMP/status-$phase.json"
  xenoid_cli google-services status --require-runtime > "$TMP/google-$phase.json"
}

capture before
for pass in 1 2; do
  echo "[google-convergence] reuse pass $pass" >&2
  xenoid_cli up --skip-build >/dev/null \
    || { echo "automatic reuse convergence pass $pass failed" >&2; exit 1; }
  capture "pass$pass"
done

python3 - "$TMP" <<'PY'
import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
phases = ("before", "pass1", "pass2")
statuses = {
    phase: json.loads((root / f"status-{phase}.json").read_text())
    for phase in phases
}
google = {
    phase: json.loads((root / f"google-{phase}.json").read_text())
    for phase in phases
}

def container_id(status):
    rows = status.get("rows")
    if not isinstance(rows, list) or len(rows) != 1:
        raise SystemExit("status did not report exactly one owned container")
    row = json.loads(rows[0])
    value = row.get("ID") or row.get("Id")
    if not value:
        raise SystemExit("status did not report a container ID")
    return value

def filesystem_uuid(status):
    value = status.get("storage", {}).get("filesystemUuid")
    if not value:
        raise SystemExit("status did not report the data filesystem UUID")
    return value

baseline_container = container_id(statuses["before"])
baseline_uuid = filesystem_uuid(statuses["before"])
baseline_binding = google["before"].get("binding")
baseline_identity = google["before"].get("runtimeIdentity")
if not isinstance(baseline_binding, dict) or baseline_binding.get("state") != "committed":
    raise SystemExit("Google services binding is not committed")
if not isinstance(baseline_identity, dict):
    raise SystemExit("Google runtime identity is unavailable")
for phase in phases:
    status = statuses[phase]
    state = google[phase]
    if status.get("ok") is not True or status.get("running") is not True:
        raise SystemExit(f"runtime status failed in {phase}")
    if status.get("runtimeSpecMatches") is not True:
        raise SystemExit(f"runtime spec mismatch in {phase}")
    if state.get("ok") is not True or state.get("ready") is not True:
        raise SystemExit(f"Google services readiness failed in {phase}")
    if container_id(status) != baseline_container:
        raise SystemExit(f"container was recreated in {phase}")
    if filesystem_uuid(status) != baseline_uuid:
        raise SystemExit(f"data filesystem changed in {phase}")
    if state.get("binding") != baseline_binding:
        raise SystemExit(f"Google services binding changed in {phase}")
    if state.get("runtimeIdentity") != baseline_identity:
        raise SystemExit(f"runtime image identity changed in {phase}")
print(json.dumps({
    "schema": "dev.xenoid.google-services-convergence/v1",
    "ok": True,
    "passes": 2,
    "containerId": baseline_container,
    "filesystemUuid": baseline_uuid,
    "binding": baseline_binding,
    "runtimeIdentity": baseline_identity,
}, indent=2, sort_keys=True))
PY

"$ROOT/scripts/smoke-google-services-runtime.sh" --instance "$INSTANCE" >/dev/null
echo "[google-convergence] repeated reuse convergence passed" >&2
