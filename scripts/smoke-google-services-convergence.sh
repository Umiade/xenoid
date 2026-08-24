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
  xenoid_cli up --skip-build > "$TMP/up-pass$pass.json" \
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
    phase: json.loads((root / f"status-{phase}.json").read_text(encoding="utf-8"))
    for phase in phases
}
google = {
    phase: json.loads((root / f"google-{phase}.json").read_text(encoding="utf-8"))
    for phase in phases
}
up_results = [
    json.loads((root / f"up-pass{number}.json").read_text(encoding="utf-8"))
    for number in (1, 2)
]

def runtime_identity(status):
    value = status.get("runtimeIdentity")
    if not isinstance(value, dict):
        raise SystemExit("status did not report runtime identity")
    required = ("containerId", "imageId", "dataUuid")
    if any(not isinstance(value.get(key), str) or not value[key] for key in required):
        raise SystemExit("status reported an incomplete runtime identity")
    return value

for number, result in enumerate(up_results, 1):
    plan = result.get("plan")
    if (
        result.get("schema") != "dev.xenoid.convergence/v1"
        or result.get("ok") is not True
        or result.get("dryRun") is not False
        or not isinstance(plan, dict)
        or plan.get("artifactTargets") != []
        or plan.get("imageAction") != "reuse-selected"
        or plan.get("runtimeAction") != "reuse"
        or plan.get("bootSeedAction") != "none"
        or plan.get("recreateReasons") != []
    ):
        raise SystemExit(f"up --skip-build pass {number} was not a no-op reuse")

baseline_runtime = runtime_identity(statuses["before"])
baseline_container = baseline_runtime["containerId"]
baseline_uuid = baseline_runtime["dataUuid"]
baseline_binding = google["before"].get("binding")
baseline_identity = google["before"].get("runtimeIdentity")
baseline_components = google["before"].get("effectiveComponents")
if not isinstance(baseline_binding, dict) or baseline_binding.get("state") != "committed":
    raise SystemExit("Google services binding is not committed")
if not isinstance(baseline_identity, dict):
    raise SystemExit("Google runtime identity is unavailable")
if not isinstance(baseline_components, dict):
    raise SystemExit("effective Google components are unavailable")
for phase in phases:
    status = statuses[phase]
    state = google[phase]
    runtime = runtime_identity(status)
    if status.get("ok") is not True or status.get("running") is not True:
        raise SystemExit(f"runtime status failed in {phase}")
    if status.get("containerContractMatches") is not True:
        raise SystemExit(f"runtime container contract mismatch in {phase}")
    if state.get("schema") != "dev.xenoid.google-services-status/v2":
        raise SystemExit(f"Google services status schema mismatch in {phase}")
    if (
        state.get("ok") is not True
        or state.get("ready") is not True
        or state.get("provider") != "microg"
    ):
        raise SystemExit(f"microG readiness failed in {phase}")
    if runtime["containerId"] != baseline_container:
        raise SystemExit(f"container was recreated in {phase}")
    if runtime["dataUuid"] != baseline_uuid:
        raise SystemExit(f"data filesystem changed in {phase}")
    if state.get("binding") != baseline_binding:
        raise SystemExit(f"Google services binding changed in {phase}")
    if state.get("runtimeIdentity") != baseline_identity:
        raise SystemExit(f"runtime image identity changed in {phase}")
    if state.get("effectiveComponents") != baseline_components:
        raise SystemExit(f"effective Google components changed in {phase}")

report = {
    "schema": "dev.xenoid.google-services-convergence/v1",
    "ok": True,
    "passes": 2,
    "containerId": baseline_container,
    "filesystemUuid": baseline_uuid,
    "binding": baseline_binding,
    "runtimeIdentity": baseline_identity,
}
sys.stdout.write(
    json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    + "\n"
)
PY
echo "[google-convergence] repeated microG reuse convergence passed" >&2
