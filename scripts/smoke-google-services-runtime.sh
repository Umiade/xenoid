#!/usr/bin/env bash
# Run the ordinary, non-debuggable application probe. The aggregate
# google-services smoke/v2 document is owned by smoke-google-services-gate.sh.
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
TMP="$(mktemp -d "${TMPDIR:-/tmp}/xenoid-google-services-probe.XXXXXX")"
cleanup() {
  xenoid_cli adb uninstall "$PACKAGE" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

log() { echo "[google-services-probe] $*" >&2; }
fail() { echo "[google-services-probe] FAIL: $*" >&2; exit 1; }
adb_shell() { xenoid_cli adb shell "$@"; }

log "checking microG runtime readiness"
xenoid_cli google-services status --require-runtime > "$TMP/status.json" \
  || fail "configured Google services runtime is not ready"
python3 - "$TMP/status.json" <<'PY' || fail "microG status contract mismatch"
import json
import sys
from pathlib import Path

status = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if status.get("schema") != "dev.xenoid.google-services-status/v2":
    raise SystemExit(1)
if status.get("ok") is not True or status.get("ready") is not True:
    raise SystemExit(1)
if status.get("provider") != "microg":
    raise SystemExit(1)
if status.get("release") != "microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0":
    raise SystemExit(1)
PY

log "building ordinary application probe"
[[ -x "$PROBE_BUILD" ]] || fail "probe build script missing"
APK="$("$PROBE_BUILD")"
[[ -f "$APK" ]] || fail "probe APK missing"
python3 - "$APK" > "$TMP/apk-sha256" <<'PY'
import hashlib
import sys
from pathlib import Path

digest = hashlib.sha256()
with Path(sys.argv[1]).open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY

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
    if (
        data.get("schema") == "dev.xenoid.google-services-probe/v2"
        and data.get("provider") == "microg"
        and data.get("ok") is True
    ):
        print(json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        raise SystemExit(0)
raise SystemExit(1)
' > "$TMP/device-probe.json" || fail "ordinary application probe did not pass"

python3 - \
  "$TMP/status.json" "$TMP/device-probe.json" "$TMP/apk-sha256" \
  "$INSTANCE" "$PACKAGE" <<'PY'
import json
import re
import sys
from pathlib import Path

status = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
probe = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
apk_sha256 = Path(sys.argv[3]).read_text(encoding="ascii").strip()
if re.fullmatch(r"[0-9a-f]{64}", apk_sha256) is None:
    raise SystemExit("probe APK digest is invalid")
probe.update({
    "instance": sys.argv[4],
    "provider": status["provider"],
    "release": status["release"],
    "specSha256": status["specSha256"],
    "package": sys.argv[5],
    "apkSha256": apk_sha256,
})
sys.stdout.write(
    json.dumps(probe, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    + "\n"
)
PY
log "ordinary microG runtime probe passed"
