#!/usr/bin/env bash
# Prove that an ordinary unprivileged app can discover and use the configured
# Google runtime: packages, account authenticator, GMS Core Binder, and launcher.
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
PACKAGE="org.example.googleservicesruntimeprobe"
PROBE_BUILD="$ROOT/tests/google-services-runtime-probe/build.sh"
OUT_DIR="${XENOID_STATE_ROOT:-$HOME/.xenoid/instances}/google-services-probe"
REPORT="$OUT_DIR/report.json"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/xenoid-google-services.XXXXXX")"
mkdir -p "$OUT_DIR"
cleanup() {
  xenoid_cli adb uninstall "$PACKAGE" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

log() { echo "[google-services] $*" >&2; }
fail() { echo "[google-services] FAIL: $*" >&2; exit 1; }
adb_shell() { xenoid_cli adb shell "$@"; }

log "checking pinned runtime readiness"
xenoid_cli google-services status --require-runtime > "$TMP/status.json" \
  || fail "configured Google services runtime is not ready"
python3 - "$TMP/status.json" <<'PY' || exit 1
import json
import sys
from pathlib import Path
status = json.loads(Path(sys.argv[1]).read_text())
if not status.get("ok") or not status.get("ready"):
    raise SystemExit("Google services status is not ready")
if status.get("provider") != "mindthegapps":
    raise SystemExit("Google services provider is not mindthegapps")
PY

log "building ordinary application probe"
[[ -x "$PROBE_BUILD" ]] || fail "probe build script missing"
APK="$("$PROBE_BUILD")"
[[ -f "$APK" ]] || fail "probe APK missing"

xenoid_cli adb uninstall "$PACKAGE" >/dev/null 2>&1 || true
xenoid_cli adb install -r "$APK" >/dev/null 2>&1 || fail "probe install failed"
adb_shell "logcat -c" >/dev/null 2>&1 || fail "logcat reset failed"
adb_shell "am start -W -n $PACKAGE/.ProbeActivity" >/dev/null 2>&1 \
  || fail "probe launch failed"
sleep 7
adb_shell "logcat -d -s XenoidGoogleServicesProbe:I" | python3 -c '
import json
import sys
response = json.load(sys.stdin)
raw = response.get("stdout", "") if isinstance(response, dict) else ""
for line in reversed(raw.splitlines()):
    if "{" not in line or "}" not in line:
        continue
    payload = line[line.index("{"):line.rindex("}") + 1]
    try:
        data = json.loads(payload)
    except Exception:
        continue
    if data.get("ok") is True:
        print(json.dumps(data, sort_keys=True))
        raise SystemExit(0)
raise SystemExit(1)
' > "$TMP/probe.json" || fail "ordinary application probe did not pass"

python3 - "$TMP/status.json" "$TMP/probe.json" "$REPORT" "$INSTANCE" <<'PY'
import json
import sys
from pathlib import Path
status = json.loads(Path(sys.argv[1]).read_text())
probe = json.loads(Path(sys.argv[2]).read_text())
report = {
    "schema": "dev.xenoid.google-services-smoke/v1",
    "ok": True,
    "instance": sys.argv[4],
    "provider": status["provider"],
    "release": status["release"],
    "probe": probe,
}
Path(sys.argv[3]).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps(report, indent=2, sort_keys=True))
PY
log "ordinary Google services runtime probe passed"
