#!/usr/bin/env bash
# Verify persistent /data identity and Android app state across runtime recreation.
# Uses an ordinary, non-system app to read Settings, SharedPreferences, SQLite,
# KeyStore, credential-encrypted and device-protected storage.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
INSTANCE="${XENOID_INSTANCE:-default}"
xenoid_cli() { ./xenoid --instance "$INSTANCE" "$@"; }
PACKAGE="org.example.persistenceruntimeprobe"
SECOND_INSTANCE="${XENOID_SECOND_INSTANCE:-phone-b}"
PROBE_DIR="$ROOT/tests/persistence-runtime-probe"
PROBE_BUILD="$PROBE_DIR/build.sh"
OUT_DIR="${XENOID_STATE_ROOT:-$HOME/.xenoid/instances}/persistence-probe"
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/report.json"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/xenoid-persistence.XXXXXX")"
cleanup() {
  ./xenoid --instance "$INSTANCE" adb uninstall "$PACKAGE" >/dev/null 2>&1 || true
  ./xenoid --instance "$SECOND_INSTANCE" adb uninstall "$PACKAGE" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

json_ok() { python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("ok") else 1)' </dev/null; }
json_get() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get(sys.argv[1],""))' "$1"; }

log() { echo "[persistence] $*"; }
fail() { echo "[persistence] FAIL: $*" >&2; exit 1; }

adb_shell() { xenoid_cli adb shell "$@"; }

collect_probe() {
  local phase="$1"
  local out="$TMP/probe-$phase.json"
  adb_shell "am start -W -n $PACKAGE/.ProbeActivity" >/dev/null 2>&1 || true
  sleep 2
  adb_shell "logcat -d -s XenoidPersistenceProbe:I" | python3 -c '
import json, sys
response = json.load(sys.stdin)
raw = response.get("stdout", "") if isinstance(response, dict) else ""
for line in reversed(raw.splitlines()):
    if "{" in line and "}" in line:
        payload = line[line.index("{"):line.rindex("}") + 1]
        try:
            data = json.loads(payload)
            if data.get("ok"):
                print(json.dumps(data))
                sys.exit(0)
        except Exception:
            continue
sys.exit(1)
' > "$out" || fail "probe output missing in phase $phase"
  cat "$out"
}

compare_phase() {
  local phase="$1"
  python3 - "$TMP/baseline.json" "$TMP/probe-$phase.json" "$phase" <<'PY'
import json
import sys
from pathlib import Path

baseline = json.loads(Path(sys.argv[1]).read_text())
actual = json.loads(Path(sys.argv[2]).read_text())
phase = sys.argv[3]
paths = (
    ("marker",),
    ("androidId",),
    ("firstInstallTime",),
    ("credentialEncryptedFiles", "exists"),
    ("credentialEncryptedFiles", "value"),
    ("cache", "exists"),
    ("cache", "value"),
    ("sharedPreferences", "marker"),
    ("sharedPreferences", "loginToken"),
    ("sharedPreferences", "firstInstallTime"),
    ("sqlite", "marker"),
    ("sqlite", "token"),
    ("deviceProtectedStorage", "exists"),
    ("deviceProtectedStorage", "value"),
    ("keystoreToken", "token"),
    ("appScopedExternal", "available"),
    ("appScopedExternal", "exists"),
    ("appScopedExternal", "value"),
    ("appScopedMedia", "available"),
    ("appScopedMedia", "exists"),
    ("appScopedMedia", "value"),
)

def value(document, path):
    current = document
    for item in path:
        if not isinstance(current, dict) or item not in current:
            raise KeyError(".".join(path))
        current = current[item]
    return current

for required in (
    ("credentialEncryptedFiles", "exists"),
    ("cache", "exists"),
    ("deviceProtectedStorage", "exists"),
    ("appScopedExternal", "available"),
    ("appScopedExternal", "exists"),
    ("appScopedMedia", "available"),
    ("appScopedMedia", "exists"),
):
    if value(baseline, required) is not True:
        raise SystemExit(f"baseline storage surface unavailable: {'.'.join(required)}")
for path in paths:
    expected = value(baseline, path)
    observed = value(actual, path)
    if isinstance(expected, str) and path[-1] not in {"available", "exists"} and not expected:
        raise SystemExit(f"baseline value empty: {'.'.join(path)}")
    if expected != observed:
        raise SystemExit(
            f"{phase} mismatch at {'.'.join(path)}: expected={expected!r} actual={observed!r}"
        )
PY
}

log "building persistence probe"
[[ -x "$PROBE_BUILD" ]] || fail "probe build script missing"
APK="$("$PROBE_BUILD")"
[[ -f "$APK" ]] || fail "probe APK missing"

xenoid_cli adb uninstall "$PACKAGE" >/dev/null 2>&1 || true
log "phase 0: install probe and collect baseline"
xenoid_cli adb install -r "$APK" >/dev/null 2>&1 || fail "probe install failed"
collect_probe initial > "$TMP/baseline.json"
BASE_MARKER="$(cat "$TMP/baseline.json" | json_get marker)"
BASE_ANDROID_ID="$(cat "$TMP/baseline.json" | json_get androidId)"
BASE_FIRST_INSTALL="$(cat "$TMP/baseline.json" | json_get firstInstallTime)"
compare_phase initial

log "recreate: verify persistence across running instance 'up' (container recreate)"
xenoid_cli up --skip-build >/dev/null 2>&1 || fail "up --skip-build failed"
collect_probe recreate > "$TMP/recreate.json"
compare_phase recreate

log "stop-up: verify persistence across stop -> up"
xenoid_cli stop >/dev/null 2>&1 || fail "stop failed"
xenoid_cli up --skip-build >/dev/null 2>&1 || fail "up after stop failed"
collect_probe stopped > "$TMP/stopped.json"
compare_phase stopped

log "dual: verify second instance isolation"
DUAL_VERIFIED=false
if ./xenoid --instance "$SECOND_INSTANCE" status 2>/dev/null \
  | python3 -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin).get("running") is True else 1)'
then
  ./xenoid --instance "$SECOND_INSTANCE" adb uninstall "$PACKAGE" >/dev/null 2>&1 || true
  ./xenoid --instance "$SECOND_INSTANCE" adb install -r "$APK" >/dev/null 2>&1 \
    || fail "second instance probe install failed"
  ./xenoid --instance "$SECOND_INSTANCE" adb shell "am start -W -n $PACKAGE/.ProbeActivity" >/dev/null 2>&1
  sleep 2
  ./xenoid --instance "$SECOND_INSTANCE" adb shell "logcat -d -s XenoidPersistenceProbe:I" | python3 -c '
import json, sys
response = json.load(sys.stdin)
raw = response.get("stdout", "") if isinstance(response, dict) else ""
for line in reversed(raw.splitlines()):
    if "{" in line and "}" in line:
        payload = line[line.index("{"):line.rindex("}") + 1]
        try:
            data = json.loads(payload)
            if data.get("ok"):
                print(json.dumps(data))
                sys.exit(0)
        except Exception:
            continue
sys.exit(1)
' > "$TMP/second.json" || fail "second instance probe output missing"
  B_MARKER="$(cat "$TMP/second.json" | json_get marker)"
  [[ -n "$B_MARKER" && "$B_MARKER" != "$BASE_MARKER" ]] \
    || fail "second instance marker identical to first"
  B_ANDROID_ID="$(cat "$TMP/second.json" | json_get androidId)"
  [[ -n "$B_ANDROID_ID" && "$B_ANDROID_ID" != "$BASE_ANDROID_ID" ]] \
    || fail "second instance Android ID identical to first"
  xenoid_cli hide status >/dev/null 2>&1 \
    || fail "primary instance protection changed during dual-instance run"
  ./xenoid --instance "$SECOND_INSTANCE" hide status >/dev/null 2>&1 \
    || fail "second instance protection changed during primary-instance up"
  DUAL_VERIFIED=true
else
  log "second instance not initialized; skipping dual-instance isolation check"
fi

python3 - "$REPORT" <<PY
import json, sys
from pathlib import Path
report = {
    "ok": True,
    "instance": "$INSTANCE",
    "marker": "$BASE_MARKER",
    "androidId": "$BASE_ANDROID_ID",
    "firstInstallTime": "$BASE_FIRST_INSTALL",
    "phases": {
        "initial": "ok",
        "recreate": "ok",
        "stopped": "ok",
    },
}
report["phases"]["dualIsolation"] = "verified" if "$DUAL_VERIFIED" == "true" else "skipped"
if Path("$TMP/probe-recreate.json").exists():
    report["phases"]["recreate"] = "verified"
if Path("$TMP/probe-stopped.json").exists():
    report["phases"]["stopped"] = "verified"
print(json.dumps(report, indent=2))
PY

log "all persistence phases passed"
