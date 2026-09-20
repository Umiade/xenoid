#!/usr/bin/env bash
# Build and run an ordinary Java+NDK Widevine identity probe against the live runtime.
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

ADB_BIN="$(python3 - <<'PY'
import sys
sys.path.insert(0, 'src')
from xenoid.util import which
print(which('adb') or 'adb')
PY
)"
ADB_TARGET="$(XENOID_INSTANCE="$INSTANCE" python3 - <<'PY'
import os
import pathlib
import sys
sys.path.insert(0, 'src')
from xenoid.backend import RuntimeManager
from xenoid.config import resolve_instance
name = os.environ.get('XENOID_INSTANCE') or 'default'
context, config, lease = resolve_instance(name, project_root=pathlib.Path.cwd(), env={})
print(RuntimeManager(context, config, lease).adb_target)
PY
)"
PACKAGE="org.example.drmidentityprobe"
REMOTE_RESULT="/sdcard/Android/data/$PACKAGE/files/probe-result.json"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/xenoid-drm-identity.XXXXXX")"
INSTALLED=false
RESTORE_READY=false
ORIGINAL_ID=""

log() { echo "[drm-identity] $*" >&2; }
fail() { echo "[drm-identity] FAIL: $*" >&2; exit 1; }
root_set_id() {
  local value="$1"
  [[ "$value" =~ ^([0-9a-f]{32})?$ ]] || return 2
  ./xenoid --instance "$INSTANCE" root exec "setprop persist.xenoid.drm.id '$value'" \
    > "$TMP/root-set.json"
  python3 - "$TMP/root-set.json" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding='utf-8'))
if value.get('ok') is not True:
    raise SystemExit('root property update failed')
PY
}
cleanup() {
  if [[ "$RESTORE_READY" == true ]]; then
    root_set_id "$ORIGINAL_ID" >/dev/null 2>&1 || true
  fi
  if [[ "$INSTALLED" == true ]]; then
    "$ADB_BIN" -s "$ADB_TARGET" uninstall "$PACKAGE" >/dev/null 2>&1 || true
  fi
  rm -rf "$ROOT/dist/drm-identity-probe" "$TMP"
}
trap cleanup EXIT

probe_once() {
  local expected="$1"
  local output="$2"
  "$ADB_BIN" -s "$ADB_TARGET" shell "rm -f '$REMOTE_RESULT'" >/dev/null 2>&1 || true
  "$ADB_BIN" -s "$ADB_TARGET" shell \
    am start -W -n "$PACKAGE/.ProbeActivity" --es request "$expected" >/dev/null
  for _ in $(seq 1 60); do
    "$ADB_BIN" -s "$ADB_TARGET" shell "cat '$REMOTE_RESULT' 2>/dev/null" \
      > "$output" 2>/dev/null || true
    if grep -q "\"request\":\"$expected\"" "$output" 2>/dev/null; then
      break
    fi
    sleep 1
  done
  python3 - "$output" "$expected" <<'PY'
import json
import re
import sys

value = json.load(open(sys.argv[1], encoding='utf-8'))
expected = sys.argv[2]
native = value.get('native')
checks = {
    'schema': value.get('schema') == 'dev.xenoid.drm-identity-probe/v1',
    'ok': value.get('ok') is True,
    'request': value.get('request') == expected,
    'javaSupported': value.get('javaSupported') is True,
    'javaSupportedSchemesContainsWidevine': value.get('javaSupportedSchemesContainsWidevine') is True,
    'javaSupportedSchemesContainsClearKey': value.get('javaSupportedSchemesContainsClearKey') is True,
    'javaDrmIdPropHidden': value.get('javaDrmIdPropHidden') is True,
    'javaVendor': value.get('javaVendor') == 'Google',
    'javaVersion': value.get('javaVersion') == '16.1.0',
    'javaDescription': value.get('javaDescription') == 'Widevine CDM',
    'javaAlgorithms': value.get('javaAlgorithms') == '',
    'javaSecurityLevel': value.get('javaSecurityLevel') == 'L1',
    'javaDeviceUniqueId': value.get('javaDeviceUniqueId') == expected,
    # MediaDrm.HDCP_V2_2 == 5 on Android 13 (1-based enum); coherent with
    # the hdcpLevel/maxHdcpLevel property strings.
    'javaHdcpConnectedLevel': value.get('javaHdcpConnectedLevel') == 5,
    'javaHdcpMaxLevel': value.get('javaHdcpMaxLevel') == 5,
    'javaRequiresSecureDecoderVideoAvc': isinstance(value.get('javaRequiresSecureDecoderVideoAvc'), bool),
    'javaNumberOfOpenSessionsAfterOpen': value.get('javaNumberOfOpenSessionsAfterOpen') == '1',
    'javaNumberOfOpenSessionsAfterClose': value.get('javaNumberOfOpenSessionsAfterClose') == '0',
    'javaSameObjectRepeatDeviceUniqueIdMatches': value.get('javaSameObjectRepeatDeviceUniqueIdMatches') is True,
    # The static ClearKey support query is timing-dependent on this
    # platform (lazy HAL cold/warm), so it is recorded but not asserted;
    # the bridge must forward it without crashing.
    'javaClearKeySupportedIsBool': isinstance(value.get('javaClearKeySupported'), bool),
    'javaClearKeySessionSucceeded': value.get('javaClearKeySessionSucceeded') is True,
    'javaClearKeyKeyFlowSucceeded': value.get('javaClearKeyKeyFlowSucceeded') is True,
    'javaRepeatDeviceUniqueIdMatches': value.get('javaRepeatDeviceUniqueIdMatches') is True,
    'concurrentFirstUseDeviceUniqueIdMatches': value.get('concurrentFirstUseDeviceUniqueIdMatches') is True,
    'concurrentWorkersPerApi': isinstance(value.get('concurrentWorkersPerApi'), int) and value['concurrentWorkersPerApi'] >= 2,
    'concurrentStressWaves': isinstance(value.get('concurrentStressWaves'), int) and value['concurrentStressWaves'] >= 2,
    'concurrentStressSucceeded': value.get('concurrentStressSucceeded') is True,
    'nativeObject': isinstance(native, dict),
    'nativeSupported': isinstance(native, dict) and native.get('supported') is True,
    'nativeOk': isinstance(native, dict) and native.get('ok') is True,
    'nativeVendor': isinstance(native, dict) and native.get('vendor') == 'Google',
    'nativeVersion': isinstance(native, dict) and native.get('version') == '16.1.0',
    'nativeDescription': isinstance(native, dict) and native.get('description') == 'Widevine CDM',
    'nativeAlgorithms': isinstance(native, dict) and native.get('algorithms') == '',
    'nativeSecurityLevel': isinstance(native, dict) and native.get('securityLevel') == 'L1',
    'nativeDeviceUniqueId': isinstance(native, dict) and native.get('deviceUniqueId') == expected,
    'nativeRepeatCreateSucceeded': isinstance(native, dict) and native.get('repeatCreateSucceeded') is True,
    'nativeRepeatDeviceUniqueIdMatches': isinstance(native, dict) and native.get('repeatDeviceUniqueIdMatches') is True,
    'nativeSameObjectRepeatDeviceUniqueIdMatches': isinstance(native, dict) and native.get('sameObjectRepeatDeviceUniqueIdMatches') is True,
    'nativeCloseStressIterations': isinstance(native, dict) and native.get('closeStressIterations') == 8,
    'nativeCloseStressSucceeded': isinstance(native, dict) and native.get('closeStressSucceeded') is True,
    'nativeHiddenPropFindNull': isinstance(native, dict) and native.get('hiddenPropFindNull') is True,
    'nativeHiddenPropGetLength': isinstance(native, dict) and native.get('hiddenPropGetLength') == 0,
    'nativeHiddenPropGetValueEmpty': isinstance(native, dict) and native.get('hiddenPropGetValueEmpty') is True,
    'nativeSameObjectRepeatDeviceUniqueIdBytes16': isinstance(native, dict) and native.get('sameObjectRepeatDeviceUniqueIdBytes16') is True,
}
failed = sorted(name for name, passed in checks.items() if not passed)
if failed:
    raise SystemExit('DRM probe contract failed: ' + ', '.join(failed))
if re.fullmatch(r'[0-9a-f]{32}', expected) is None:
    raise SystemExit('invalid expected identity')
PY
}

log "connecting to live runtime"
"$ADB_BIN" connect "$ADB_TARGET" >/dev/null
ORIGINAL_ID="$("$ADB_BIN" -s "$ADB_TARGET" shell getprop persist.xenoid.drm.id | tr -d '\r\n')"
[[ "$ORIGINAL_ID" =~ ^([0-9a-f]{32})?$ ]] || fail "live DRM identity property is malformed"
RESTORE_READY=true
FIRST_ID="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
while [[ "$FIRST_ID" == "$ORIGINAL_ID" ]]; do
  FIRST_ID="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
done
SECOND_ID="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
while [[ "$SECOND_ID" == "$FIRST_ID" || "$SECOND_ID" == "$ORIGINAL_ID" ]]; do
  SECOND_ID="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
done

log "building transient ordinary-app probe"
APK="$(tests/drm-identity-probe/build.sh)"
[[ -f "$APK" ]] || fail "probe APK missing"
"$ADB_BIN" -s "$ADB_TARGET" uninstall "$PACKAGE" >/dev/null 2>&1 || true
"$ADB_BIN" -s "$ADB_TARGET" install "$APK" >/dev/null
INSTALLED=true

log "asserting Java and NDK paths on first identity"
"$ADB_BIN" -s "$ADB_TARGET" shell am force-stop "$PACKAGE" >/dev/null
root_set_id "$FIRST_ID" || fail "first DRM identity update failed"
# The adbd shell is not a zygote descendant: the hidden property must keep
# reading back the staged value there even while apps see it as nonexistent.
SHELL_OBSERVED_ID="$("$ADB_BIN" -s "$ADB_TARGET" shell getprop persist.xenoid.drm.id | tr -d '\r\n')"
[[ "$SHELL_OBSERVED_ID" == "$FIRST_ID" ]] || fail "shell getprop lost the staged DRM identity"
probe_once "$FIRST_ID" "$TMP/first.json" || fail "first Java+NDK probe failed"

log "asserting per-call rotation without userspace restart"
root_set_id "$SECOND_ID" || fail "second DRM identity update failed"
probe_once "$SECOND_ID" "$TMP/second.json" || fail "rotated Java+NDK probe failed"
log "restoring live property and removing transient probe"
root_set_id "$ORIGINAL_ID" || fail "original DRM identity restore failed"
RESTORED_ID="$("$ADB_BIN" -s "$ADB_TARGET" shell getprop persist.xenoid.drm.id | tr -d '\r\n')"
[[ "$RESTORED_ID" == "$ORIGINAL_ID" ]] || fail "original DRM identity did not restore"
RESTORE_READY=false
"$ADB_BIN" -s "$ADB_TARGET" uninstall "$PACKAGE" >/dev/null \
  || fail "probe uninstall failed"
INSTALLED=false

python3 - "$TMP/first.json" "$TMP/second.json" "$INSTANCE" <<'PY'
import json
import sys

first = json.load(open(sys.argv[1], encoding='utf-8'))
second = json.load(open(sys.argv[2], encoding='utf-8'))
if first['javaDeviceUniqueId'] == second['javaDeviceUniqueId']:
    raise SystemExit('DRM identity did not rotate')
if not isinstance(first.get('processPid'), int) or first['processPid'] != second.get('processPid'):
    raise SystemExit('DRM identity rotation was not observed in the same app process')
print(json.dumps({
    'schema': 'dev.xenoid.drm-identity-smoke/v1',
    'ok': True,
    'instance': sys.argv[3],
    'javaAndNdkMatch': True,
    'rotatedInSameProcess': True,
}, sort_keys=True, separators=(',', ':')))
PY
