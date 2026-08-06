#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE=quick
DESTRUCTIVE=0
PHOTO=""
VIDEO=""
LOOP_SECONDS=0
OUT="/tmp/xenoid-camera-runtime-smoke.json"
REQUIRE_SCRCPY=0
usage() {
  cat <<'USAGE'
Usage: scripts/smoke-camera-runtime.sh [--quick|--full] [options]
  --photo FILE       use an external photo fixture (implies --full)
  --video FILE       use an external video fixture (implies --full)
  --loop-seconds N   keep each video camera open for N seconds
  --destructive      allow replacing existing configured camera sources
  --scrcpy           require a short scrcpy transport check
  --out FILE         sanitized JSON evidence destination

Full mode changes camera source state. It refuses a configured starting state
unless --destructive is explicit. A source-free starting state is restored to
source-free before exit.
USAGE
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) MODE=quick; shift ;;
    --full) MODE=full; shift ;;
    --destructive) DESTRUCTIVE=1; shift ;;
    --scrcpy) REQUIRE_SCRCPY=1; shift ;;
    --photo) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; PHOTO="$2"; MODE=full; shift 2 ;;
    --video) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; VIDEO="$2"; MODE=full; shift 2 ;;
    --loop-seconds) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; LOOP_SECONDS="$2"; shift 2 ;;
    --out) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; OUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ "$MODE" != full ]] || REQUIRE_SCRCPY=1
[[ "$LOOP_SECONDS" =~ ^[0-9]+$ ]] || { echo "--loop-seconds must be an integer" >&2; exit 2; }
if [[ -n "$PHOTO" && ( ! -f "$PHOTO" || ! -s "$PHOTO" ) ]]; then
  echo "--photo must name a nonempty regular file" >&2
  exit 2
fi
if [[ -n "$VIDEO" && ( ! -f "$VIDEO" || ! -s "$VIDEO" ) ]]; then
  echo "--video must name a nonempty regular file" >&2
  exit 2
fi
python3 - "$OUT" "$PHOTO" "$VIDEO" <<'PY'
import os
import pathlib
import sys
output = pathlib.Path(sys.argv[1]).expanduser().resolve()
for source_name in sys.argv[2:]:
    if not source_name:
        continue
    source = pathlib.Path(source_name).expanduser().resolve()
    if source == output or (output.exists() and os.path.samefile(output, source)):
        raise SystemExit("--out must not overwrite a media source")
PY

XENOID_BIN=./xenoid
[[ -x "$XENOID_BIN" ]] || XENOID_BIN=./bin/xenoid
[[ -x "$XENOID_BIN" ]] || XENOID_BIN=xenoid
ADB_BIN="$(python3 - <<'PY'
import sys
sys.path.insert(0, 'src')
from xenoid.util import which
print(which('adb') or 'adb')
PY
)"
ADB_TARGET="127.0.0.1:$(python3 - <<'PY'
import json
from pathlib import Path
path = Path('.xenoid/config.json')
print(json.loads(path.read_text()).get('adb_port', 5555) if path.exists() else 5555)
PY
)"
PACKAGE="org.example.cameraruntimeprobe"
REMOTE_FILES="/sdcard/Android/data/$PACKAGE/files"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/camera-runtime-probe.XXXXXX")"
CHECKS="$TMP/checks.jsonl"
: > "$CHECKS"
INSTALLED=0
MUTATED=0
APP_FIXTURES_CREATED=0
REMOTE_TEMP_CREATED=0
INITIAL_MODE=naturalized
REPORT_WRITTEN=0
STAGING_BASELINE_READY=0
STORAGE_BASELINE_READY=0
HOST_CONFIG_BASELINE_READY=0
REMOTE_FIXTURE_PREFIX="/data/local/tmp/.camera-runtime-probe-$$"
HOSTILE_PATHS=()

record_json() {
  local name="$1" ok="$2" payload="{}"
  [[ $# -lt 3 ]] || payload="$3"
  NAME="$name" OK_VALUE="$ok" PAYLOAD="$payload" python3 - <<'PY' >> "$CHECKS" || return 1
import json, os, re
name = os.environ['NAME']
ok = os.environ['OK_VALUE'] == 'true'
try:
    value = json.loads(os.environ['PAYLOAD'])
except Exception:
    value = {'error': 'check failed'}
private_key = re.compile(r'(?:path|name|digest|sha256|token|nonce|uri|url)$', re.I)
private_value = re.compile(r'(?<![A-Za-z0-9._-])/\S+|\b[0-9a-fA-F]{32,64}\b')
numeric_key = re.compile(
    r'(?:count|frames|width|height|duration|rotation|generation|bytes|size|seconds|ms|delta)$',
    re.I)
string_keys = {
    'mode', 'expectation', 'codec', 'videoCodec', 'photoOrigin', 'videoOrigin',
    'id', 'cameraId', 'sourceKind',
}
allowed_strings = {
    'naturalized', 'faithful', 'fallback', 'stable', 'vary',
    'photo', 'video', 'runtime', 'external', 'video/avc', 'video/hevc',
    '0', '1',
}
drop = object()
def clean(item, key=''):
    if isinstance(item, dict):
        result = {}
        for raw_key, child in item.items():
            normalized = ''.join(ch for ch in str(raw_key) if ch.isalnum())
            if private_key.search(normalized):
                continue
            cleaned = clean(child, str(raw_key))
            if cleaned is not drop:
                result[str(raw_key)] = cleaned
        return result
    if isinstance(item, list):
        return [child for value in item if (child := clean(value, key)) is not drop]
    if isinstance(item, bool):
        return item
    if isinstance(item, (int, float)) and not isinstance(item, bool):
        return item if numeric_key.search(key) else drop
    if isinstance(item, str):
        if private_value.search(item):
            return drop
        if key == 'error':
            return 'check failed'
        if key in string_keys and (item in allowed_strings or re.fullmatch(r'\d+x\d+', item)):
            return item
        return drop
    return drop
print(json.dumps(
    {'name': name, 'ok': ok, 'evidence': clean(value)},
    separators=(',', ':')))
PY
}

die() {
  local payload='{"error":"check failed"}'
  [[ $# -lt 2 ]] || payload="$2"
  record_json "$1" false "$payload" || true
  exit 1
}

cleanup() {
  local failed=0 path
  set +e
  if [[ "$MUTATED" == 1 ]]; then
    "$XENOID_BIN" camera clear all >/dev/null 2>&1 || failed=1
    "$XENOID_BIN" camera mode "$INITIAL_MODE" >/dev/null 2>&1 || failed=1
    "$XENOID_BIN" camera apply >/dev/null 2>&1 || failed=1
    if camera_status "$TMP/cleanup-status.json" >/dev/null 2>&1; then
      python3 - "$TMP/cleanup-status.json" "$INITIAL_MODE" <<'PY' >/dev/null 2>&1 || failed=1
import json, sys
value = json.load(open(sys.argv[1], encoding='utf-8'))
if (value['photoConfigured'] or value['videoConfigured']
        or value['mode'] != sys.argv[2] or not value['active']
        or value['lastError']):
    raise SystemExit(1)
PY
    else
      failed=1
    fi
  fi
  for path in "${HOSTILE_PATHS[@]}"; do
    "$XENOID_BIN" root exec "rm -f -- '$path'" >/dev/null 2>&1 || failed=1
  done
  if [[ "$STAGING_BASELINE_READY" == 1 ]]; then
    if capture_staging "$TMP/cleanup-stages-current.txt" >/dev/null 2>&1; then
      comm -13 "$TMP/stages-baseline.txt" "$TMP/cleanup-stages-current.txt" \
        > "$TMP/cleanup-stages-new.txt" || failed=1
      while IFS= read -r path; do
        [[ -z "$path" ]] || "$XENOID_BIN" root exec "rm -f -- '$path'" \
          >/dev/null 2>&1 || failed=1
      done < "$TMP/cleanup-stages-new.txt"
      capture_staging "$TMP/cleanup-stages-final.txt" >/dev/null 2>&1 || failed=1
      cmp -s "$TMP/stages-baseline.txt" "$TMP/cleanup-stages-final.txt" || failed=1
    else
      failed=1
    fi
  fi
  if [[ "$REMOTE_TEMP_CREATED" == 1 ]]; then
    "$ADB_BIN" -s "$ADB_TARGET" shell rm -f \
      "$REMOTE_FIXTURE_PREFIX-photo.png" "$REMOTE_FIXTURE_PREFIX-second.png" \
      "$REMOTE_FIXTURE_PREFIX-video.mp4" "$REMOTE_FIXTURE_PREFIX-video-second.mp4" \
      >/dev/null 2>&1 || failed=1
    "$ADB_BIN" -s "$ADB_TARGET" shell test ! -e "$REMOTE_FIXTURE_PREFIX-photo.png" \
      -a ! -e "$REMOTE_FIXTURE_PREFIX-second.png" \
      -a ! -e "$REMOTE_FIXTURE_PREFIX-video.mp4" \
      -a ! -e "$REMOTE_FIXTURE_PREFIX-video-second.mp4" \
      >/dev/null 2>&1 || failed=1
  fi
  if [[ "$APP_FIXTURES_CREATED" == 1 ]]; then
    "$ADB_BIN" -s "$ADB_TARGET" shell rm -f \
      "$REMOTE_FILES/reference-photo" "$REMOTE_FILES/reference-photo-second" \
      "$REMOTE_FILES/reference-video" "$REMOTE_FILES/reference-video-second" \
      >/dev/null 2>&1 || failed=1
    "$ADB_BIN" -s "$ADB_TARGET" shell test ! -e "$REMOTE_FILES/reference-photo" \
      -a ! -e "$REMOTE_FILES/reference-photo-second" \
      -a ! -e "$REMOTE_FILES/reference-video" \
      -a ! -e "$REMOTE_FILES/reference-video-second" \
      >/dev/null 2>&1 || failed=1
  fi
  if [[ "$STORAGE_BASELINE_READY" == 1 && "$MUTATED" == 1 ]]; then
    storage_snapshot "$TMP/cleanup-storage.json" >/dev/null 2>&1 || failed=1
    cmp -s "$TMP/storage-baseline.json" "$TMP/cleanup-storage.json" || failed=1
  fi
  if [[ "$HOST_CONFIG_BASELINE_READY" == 1 ]]; then
    assert_host_config_unchanged >/dev/null 2>&1 || failed=1
  fi
  if [[ "$INSTALLED" == 1 ]]; then
    "$ADB_BIN" -s "$ADB_TARGET" uninstall "$PACKAGE" >/dev/null 2>&1 || failed=1
    if "$ADB_BIN" -s "$ADB_TARGET" shell pm path "$PACKAGE" >/dev/null 2>&1; then
      failed=1
    fi
  fi
  return "$failed"
}

emit_report() {
  local rc="$1"
  [[ "$REPORT_WRITTEN" == 0 ]] || return
  REPORT_WRITTEN=1
  MODE_VALUE="$MODE" RC_VALUE="$rc" CHECKS_FILE="$CHECKS" OUT_FILE="$OUT" python3 - <<'PY' \
    || return 1
import json, os
checks = []
try:
    with open(os.environ['CHECKS_FILE'], encoding='utf-8') as stream:
        checks = [json.loads(line) for line in stream if line.strip()]
except Exception:
    checks = []
rc = int(os.environ['RC_VALUE'])
ok = rc == 0 and bool(checks) and all(item.get('ok') is True for item in checks)
report = {
    'schema': 'org.example.camera-runtime-smoke/v1',
    'ok': ok,
    'mode': os.environ['MODE_VALUE'],
    'checks': checks,
}
path = os.environ['OUT_FILE']
with open(path, 'w', encoding='utf-8') as stream:
    json.dump(report, stream, separators=(',', ':'))
    stream.write('\n')
print(json.dumps(report, separators=(',', ':')))
PY
}

on_exit() {
  local rc=$?
  trap - EXIT
  set +e
  if cleanup; then
    record_json fixture-cleanup true '{"remoteFixturesRemoved":true,"appStateClean":true}'
  else
    record_json fixture-cleanup false '{"error":"fixture cleanup failed"}'
    [[ "$rc" != 0 ]] || rc=1
  fi
  emit_report "$rc" || rc=1
  rm -rf "$TMP"
  exit "$rc"
}
trap on_exit EXIT

validate_status() {
  local file="$1"
  python3 - "$file" <<'PY' || return 1
import json, re, sys
status = json.load(open(sys.argv[1], encoding='utf-8'))
expected = {
    'ok', 'mode', 'generation', 'active',
    'photoConfigured', 'photoWidth', 'photoHeight',
    'videoConfigured', 'videoWidth', 'videoHeight', 'videoDurationMs',
    'videoCodec', 'videoRotation', 'lastError',
}
if set(status) != expected:
    raise SystemExit('camera status schema mismatch')
if status.get('ok') is not True or status.get('mode') not in {'naturalized', 'faithful'}:
    raise SystemExit('camera status unavailable')
if type(status['generation']) is not int or status['generation'] < 0:
    raise SystemExit('camera generation type mismatch')
for key in ('active', 'photoConfigured', 'videoConfigured'):
    if type(status[key]) is not bool:
        raise SystemExit(f'camera boolean type mismatch: {key}')
for key in ('photoWidth', 'photoHeight', 'videoWidth', 'videoHeight',
            'videoDurationMs', 'videoRotation'):
    if type(status[key]) is not int or status[key] < 0:
        raise SystemExit(f'camera numeric type mismatch: {key}')
if not isinstance(status['videoCodec'], str) or not isinstance(status['lastError'], str):
    raise SystemExit('camera string type mismatch')
if not status['photoConfigured'] and (status['photoWidth'] or status['photoHeight']):
    raise SystemExit('unconfigured photo exposes dimensions')
if not status['videoConfigured'] and any((
        status['videoWidth'], status['videoHeight'], status['videoDurationMs'],
        status['videoRotation'])):
    raise SystemExit('unconfigured video exposes metadata')
if not status['videoConfigured'] and status['videoCodec']:
    raise SystemExit('unconfigured video exposes codec')
private = re.compile(r'(?:path|digest|sha256|token|uri|url)$', re.I)
private_value = re.compile(r'(?<![A-Za-z0-9._-])/\S+|\b[0-9a-fA-F]{64}\b')
def walk(value):
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = ''.join(ch for ch in str(key) if ch.isalnum())
            if private.search(normalized):
                raise SystemExit('private camera status key')
            walk(item)
    elif isinstance(value, list):
        for item in value: walk(item)
    elif isinstance(value, str):
        if private_value.search(value):
            raise SystemExit('private camera status value')
walk(status)
PY
}

camera_status() {
  local destination="$1"
  "$XENOID_BIN" camera status > "$destination" || return 1
  validate_status "$destination" || return 1
}

state_projection() {
  python3 - "$1" <<'PY' || return 1
import json, sys
value = json.load(open(sys.argv[1], encoding='utf-8'))
value.pop('ok', None)
value.pop('lastError', None)
print(json.dumps(value, sort_keys=True, separators=(',', ':')))
PY
}

new_nonce() {
  python3 - <<'PY' || return 1
import secrets
print(secrets.token_hex(16))
PY
}

verify_probe_file() {
  local file="$1" expected="$2" expected_nonce="$3"
  local require_ok="${4:-1}" expected_camera="${5:-}"
  python3 - "$file" "$expected" "$expected_nonce" "$require_ok" "$expected_camera" <<'PY' \
    || return 1
import json, re, sys
value = json.load(open(sys.argv[1], encoding='utf-8'))
if value.get('schema') != 'org.example.camera-runtime-probe/v1':
    raise SystemExit('probe schema mismatch')
if value.get('probe') != sys.argv[2]:
    raise SystemExit('probe mismatch')
if not sys.argv[3] or value.get('runNonce') != sys.argv[3]:
    raise SystemExit('probe run mismatch')
if sys.argv[5] and str(value.get('cameraId')) != sys.argv[5]:
    raise SystemExit('probe camera mismatch')
private = re.compile(r'(?:path|digest|sha256|token|uri|url)$', re.I)
private_value = re.compile(r'(?<![A-Za-z0-9._-])/\S+|\b[0-9a-fA-F]{64}\b')
def walk(item):
    if isinstance(item, dict):
        for key, child in item.items():
            if key == 'runNonce':
                continue
            if private.search(''.join(ch for ch in str(key) if ch.isalnum())):
                raise SystemExit('private probe key')
            walk(child)
    elif isinstance(item, list):
        for child in item:
            walk(child)
    elif isinstance(item, str) and private_value.search(item):
        raise SystemExit('private probe value')
walk(value)
if sys.argv[4] == '1' and value.get('ok') is not True:
    raise SystemExit('probe failed')
PY
}

run_activity() {
  local check_name="$1" class_name="$2" result_name="$3"
  local expected_probe="$4" timeout_seconds="$5"
  shift 5
  local nonce start_file result_file poll_state payload expected_camera="" waited=0 index
  local launch_args=("$@")
  for ((index = 0; index + 2 < ${#launch_args[@]}; ++index)); do
    if [[ "${launch_args[$index]}" == --es \
          && "${launch_args[$((index + 1))]}" == cameraId ]]; then
      expected_camera="${launch_args[$((index + 2))]}"
    fi
  done
  nonce="$(new_nonce)" || return 1
  [[ -n "$nonce" ]] || return 1
  start_file="$TMP/start-$nonce.txt"
  result_file="$TMP/result-$nonce.json"
  "$ADB_BIN" -s "$ADB_TARGET" shell rm -f \
    "$REMOTE_FILES/$result_name" "$REMOTE_FILES/$result_name.new" \
    >/dev/null || return 1
  "$ADB_BIN" -s "$ADB_TARGET" shell am start -W \
    -n "$PACKAGE/.$class_name" --es runNonce "$nonce" "$@" \
    > "$start_file" || return 1
  python3 - "$start_file" <<'PY' || return 1
import sys
text = open(sys.argv[1], encoding='utf-8', errors='replace').read()
if 'Error:' in text or 'Exception' in text:
    raise SystemExit(1)
if 'Status:' in text and 'Status: ok' not in text:
    raise SystemExit(1)
PY
  while (( waited < timeout_seconds )); do
    poll_state="$("$ADB_BIN" -s "$ADB_TARGET" shell \
      "if [ -s '$REMOTE_FILES/$result_name' ]; then printf ready; else printf waiting; fi" \
      2>/dev/null)" || return 1
    poll_state="${poll_state//$'\r'/}"
    case "$poll_state" in
      ready) break ;;
      waiting) ;;
      *) return 1 ;;
    esac
    sleep 1 || return 1
    waited=$((waited + 1))
  done
  (( waited < timeout_seconds )) || return 1
  "$ADB_BIN" -s "$ADB_TARGET" exec-out cat "$REMOTE_FILES/$result_name" \
    > "$result_file" || return 1
  payload="$(cat "$result_file")" || return 1
  if verify_probe_file "$result_file" "$expected_probe" "$nonce" 1 "$expected_camera"; then
    record_json "$check_name" true "$payload" || return 1
  else
    record_json "$check_name" false "$payload" || return 1
    return 1
  fi
}

capture_staging() {
  local destination="$1"
  "$ADB_BIN" -s "$ADB_TARGET" shell \
    'for p in /data/local/tmp/.camera-upload-*; do [ -e "$p" ] && printf "%s\n" "$p"; done; true' \
    | LC_ALL=C sort > "$destination" || return 1
}

assert_staging_clean() {
  capture_staging "$TMP/stages-current.txt" || return 1
  cmp -s "$TMP/stages-baseline.txt" "$TMP/stages-current.txt" || return 1
}

snapshot_host_config() {
  python3 - "$TMP/host-config-before.bin" <<'PY' || return 1
from pathlib import Path
import sys
source = Path('.xenoid/config.json')
payload = source.read_bytes() if source.exists() else b'ABSENT'
Path(sys.argv[1]).write_bytes(payload)
PY
}

assert_host_config_unchanged() {
  python3 - "$TMP/host-config-before.bin" <<'PY' || return 1
from pathlib import Path
import sys
source = Path('.xenoid/config.json')
payload = source.read_bytes() if source.exists() else b'ABSENT'
if payload != Path(sys.argv[1]).read_bytes():
    raise SystemExit(1)
PY
}

storage_snapshot() {
  local destination="$1" raw="$TMP/storage-root-response.json"
  local command
  command="set -eu;pc=0;pb=0;rc=0;rb=0;"
  command+="for f in /data/data/dev.xenoid.daemon/files/camera-media/photo-*.png /data/data/dev.xenoid.daemon/files/camera-media/video-*.bin;do "
  command+="[ -f \$f ]||continue;s=\$(stat -c %s \$f);pc=\$((pc+1));pb=\$((pb+s));done;"
  command+="for f in /data/misc/camera/source/photo-*.png /data/misc/camera/source/video-*.bin;do "
  command+="[ -f \$f ]||continue;s=\$(stat -c %s \$f);rc=\$((rc+1));rb=\$((rb+s));done;"
  command+="echo \$pc \$pb \$rc \$rb"
  "$XENOID_BIN" root exec "$command" > "$raw" || return 1
  python3 - "$raw" "$destination" <<'PY' || return 1
import json, pathlib, sys
outer = json.load(open(sys.argv[1], encoding='utf-8'))
if outer.get('ok') is not True:
    raise SystemExit(1)
nested = json.loads(outer.get('stdout', ''))
if nested.get('ok') is not True:
    raise SystemExit(1)
parts = nested.get('stdout', '').split()
if len(parts) != 4 or any(not part.isdigit() for part in parts):
    raise SystemExit(1)
values = [int(part) for part in parts]
result = {
    'privateCount': values[0],
    'privateBytes': values[1],
    'publishedCount': values[2],
    'publishedBytes': values[3],
}
pathlib.Path(sys.argv[2]).write_text(
    json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n',
    encoding='utf-8')
PY
}

assert_source_free() {
  local file="$1" expected_mode="${2:-}"
  python3 - "$file" "$expected_mode" <<'PY' || return 1
import json, sys
value = json.load(open(sys.argv[1], encoding='utf-8'))
if (value['photoConfigured'] or value['videoConfigured']
        or not value['active'] or value['lastError']):
    raise SystemExit(1)
if sys.argv[2] and value['mode'] != sys.argv[2]:
    raise SystemExit(1)
PY
}

set_source() {
  local kind="$1" source="$2" destination="$3"
  "$XENOID_BIN" camera set "$kind" "$source" > "$destination" || return 1
  validate_status "$destination" || return 1
  assert_staging_clean || return 1
  assert_host_config_unchanged || return 1
}

set_mode() {
  local expected="$1" destination="$2" fresh="$3"
  "$XENOID_BIN" camera mode "$expected" > "$destination" || return 1
  validate_status "$destination" || return 1
  camera_status "$fresh" || return 1
  python3 - "$destination" "$fresh" "$expected" <<'PY' || return 1
import json, sys
left = json.load(open(sys.argv[1], encoding='utf-8'))
right = json.load(open(sys.argv[2], encoding='utf-8'))
if left.get('mode') != sys.argv[3] or right.get('mode') != sys.argv[3]:
    raise SystemExit(1)
if left != right:
    raise SystemExit(1)
PY
  assert_staging_clean || return 1
  assert_host_config_unchanged || return 1
}

route_source_rejected() {
  local kind="$1" staging="$2" size="$3" digest="$4" destination="$5"
  python3 - "$kind" "$staging" "$size" "$digest" "$destination" <<'PY' || return 1
import json, pathlib, sys
sys.path.insert(0, 'src')
from xenoid.backend import RuntimeManager
from xenoid.config import resolve_instance
from xenoid.daemon_client import DaemonClient
context, cfg, lease = resolve_instance()
manager = RuntimeManager(context, cfg, lease)
client = DaemonClient(context, lease, manager.docker_base_cmd())
result = client.camera_source(sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4])
pathlib.Path(sys.argv[5]).write_text(
    json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n',
    encoding='utf-8')
if result.get('ok') is not False:
    raise SystemExit(1)
PY
}

verify_fixture_png() {
  local image="$1" baseline="${2:-}"
  python3 - "$image" "$baseline" <<'PY' || return 1
import struct, sys, zlib
def decode(path):
    data = open(path, 'rb').read()
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        raise SystemExit(1)
    pos, compressed = 8, bytearray()
    width = height = depth = color = interlace = None
    while pos + 12 <= len(data):
        size = struct.unpack('>I', data[pos:pos + 4])[0]
        kind = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + size]
        pos += 12 + size
        if kind == b'IHDR':
            width, height, depth, color, _, _, interlace = struct.unpack('>IIBBBBB', body)
        elif kind == b'IDAT':
            compressed.extend(body)
        elif kind == b'IEND':
            break
    if not width or not height or depth != 8 or color not in (2, 6) or interlace:
        raise SystemExit(1)
    channels = 3 if color == 2 else 4
    packed = zlib.decompress(bytes(compressed))
    stride = width * channels
    if len(packed) != (stride + 1) * height:
        raise SystemExit(1)
    rows, previous, offset = [], bytearray(stride), 0
    for _ in range(height):
        kind = packed[offset]
        raw = bytearray(packed[offset + 1:offset + 1 + stride])
        offset += stride + 1
        for index in range(stride):
            left = raw[index - channels] if index >= channels else 0
            up = previous[index]
            upper_left = previous[index - channels] if index >= channels else 0
            if kind == 1:
                raw[index] = (raw[index] + left) & 255
            elif kind == 2:
                raw[index] = (raw[index] + up) & 255
            elif kind == 3:
                raw[index] = (raw[index] + ((left + up) >> 1)) & 255
            elif kind == 4:
                p = left + up - upper_left
                pa, pb, pc = abs(p - left), abs(p - up), abs(p - upper_left)
                predictor = left if pa <= pb and pa <= pc else up if pb <= pc else upper_left
                raw[index] = (raw[index] + predictor) & 255
            elif kind != 0:
                raise SystemExit(1)
        rows.append(raw)
        previous = raw
    def sample(x, y):
        column = min(width - 1, max(0, int(width * x)))
        row = min(height - 1, max(0, int(height * y)))
        start = column * channels
        return tuple(rows[row][start:start + 3])
    return width, height, [
        sample(.50, .25), sample(.12, .12), sample(.88, .12),
        sample(.90, .80), sample(.12, .80),
    ]
def near(value, expected, tolerance=48):
    return max(abs(left - right) for left, right in zip(value, expected)) <= tolerance
current = decode(sys.argv[1])
expected = [
    (42, 86, 196), (232, 48, 56), (48, 216, 104),
    (248, 200, 40), (224, 64, 208),
]
if current[0] <= 0 or current[1] <= 0:
    raise SystemExit(1)
if not all(near(value, target) for value, target in zip(current[2], expected)):
    raise SystemExit(1)
if len(set(current[2])) != len(current[2]):
    raise SystemExit(1)
if sys.argv[2]:
    prior = decode(sys.argv[2])
    if current[:2] != prior[:2]:
        raise SystemExit(1)
    if any(max(abs(a - b) for a, b in zip(left, right)) > 8
           for left, right in zip(current[2], prior[2])):
        raise SystemExit(1)
PY
}

load_video_claims() {
  local status_file="$1" line
  python3 - "$status_file" > "$TMP/video-claims.txt" <<'PY' || return 1
import json, sys
value = json.load(open(sys.argv[1], encoding='utf-8'))
if (not value['active'] or not value['videoConfigured']
        or value['videoWidth'] <= 0 or value['videoHeight'] <= 0
        or value['videoDurationMs'] < 500
        or value['videoCodec'] not in {'video/avc', 'video/hevc'}
        or value['videoRotation'] not in {0, 90, 180, 270}
        or value['lastError']):
    raise SystemExit(1)
print(value['videoDurationMs'], value['videoWidth'], value['videoHeight'],
      value['videoRotation'], value['videoCodec'])
PY
  IFS= read -r line < "$TMP/video-claims.txt" || return 1
  read -r DURATION_MS VIDEO_WIDTH VIDEO_HEIGHT VIDEO_ROTATION VIDEO_MIME \
    <<< "$line" || return 1
  [[ "$DURATION_MS" =~ ^[0-9]+$ && "$DURATION_MS" -ge 500 ]] || return 1
}

run_replay() {
  local check_name="$1" id="$2" expected_mode="$3"
  local timeout_seconds window_ms requested_ms
  window_ms=$((DURATION_MS + 6000))
  requested_ms=$((LOOP_SECONDS * 1000))
  (( requested_ms <= window_ms )) || window_ms="$requested_ms"
  timeout_seconds=$(( (window_ms + 999) / 1000 + 90 ))
  run_activity "$check_name" ReplayProbeActivity replay.json video-advance-loop \
    "$timeout_seconds" --es cameraId "$id" --es expectedMode "$expected_mode" \
    --es referenceVideo "$REMOTE_FILES/reference-video" \
    --el durationMs "$DURATION_MS" --ei videoWidth "$VIDEO_WIDTH" \
    --ei videoHeight "$VIDEO_HEIGHT" --ei videoRotation "$VIDEO_ROTATION" \
    --es videoMime "$VIDEO_MIME" --el windowMs "$window_ms" || return 1
}

run_video_snapshot() {
  local check_name="$1" id="$2"
  run_activity "$check_name" ReplayProbeActivity replay.json video-snapshot 60 \
    --es cameraId "$id" --es expectedMode faithful \
    --es referenceVideo "$REMOTE_FILES/reference-video" \
    --el durationMs "$DURATION_MS" --ei videoWidth "$VIDEO_WIDTH" \
    --ei videoHeight "$VIDEO_HEIGHT" --ei videoRotation "$VIDEO_ROTATION" \
    --es videoMime "$VIDEO_MIME" --ez snapshot true || return 1
}

run_update() {
  local id="$1" source_kind="$2" source_a="$3" source_b="$4"
  local reference_a="$5" reference_b="$6"
  local nonce waited=0 poll_state start_file ready_file final_file payload
  nonce="$(new_nonce)" || return 1
  [[ -n "$nonce" ]] || return 1
  start_file="$TMP/update-start-$nonce.txt"
  ready_file="$TMP/update-ready-$nonce.json"
  final_file="$TMP/update-final-$nonce.json"
  set_source "$source_kind" "$source_a" "$TMP/update-source-a-$nonce.json" || return 1
  "$ADB_BIN" -s "$ADB_TARGET" shell rm -f \
    "$REMOTE_FILES/update.json" "$REMOTE_FILES/update.json.new" \
    "$REMOTE_FILES/update-ready-$id.json" "$REMOTE_FILES/update-ready-$id.json.new" \
    >/dev/null || return 1
  "$ADB_BIN" -s "$ADB_TARGET" shell am start -W \
    -n "$PACKAGE/.UpdateProbeActivity" --es runNonce "$nonce" \
    --es cameraId "$id" --es sourceKind "$source_kind" \
    --es referenceBefore "$reference_a" --es referenceAfter "$reference_b" \
    --ei pauseMs 20000 > "$start_file" || return 1
  python3 - "$start_file" <<'PY' || return 1
import sys
text = open(sys.argv[1], encoding='utf-8', errors='replace').read()
if 'Error:' in text or 'Exception' in text:
    raise SystemExit(1)
if 'Status:' in text and 'Status: ok' not in text:
    raise SystemExit(1)
PY
  while (( waited < 15 )); do
    poll_state="$("$ADB_BIN" -s "$ADB_TARGET" shell \
      "if [ -s '$REMOTE_FILES/update-ready-$id.json' ]; then printf ready; else printf waiting; fi" \
      2>/dev/null)" || return 1
    poll_state="${poll_state//$'\r'/}"
    case "$poll_state" in
      ready) break ;;
      waiting) ;;
      *) return 1 ;;
    esac
    sleep 1 || return 1
    waited=$((waited + 1))
  done
  (( waited < 15 )) || return 1
  "$ADB_BIN" -s "$ADB_TARGET" exec-out cat "$REMOTE_FILES/update-ready-$id.json" \
    > "$ready_file" || return 1
  verify_probe_file "$ready_file" update-ready "$nonce" 1 "$id" || return 1
  payload="$(cat "$ready_file")" || return 1
  record_json "update-ready-$source_kind-camera-$id" true "$payload" || return 1
  set_source "$source_kind" "$source_b" "$TMP/update-source-b-$nonce.json" || return 1
  waited=0
  while (( waited < 60 )); do
    poll_state="$("$ADB_BIN" -s "$ADB_TARGET" shell \
      "if [ -s '$REMOTE_FILES/update.json' ]; then printf ready; else printf waiting; fi" \
      2>/dev/null)" || return 1
    poll_state="${poll_state//$'\r'/}"
    case "$poll_state" in
      ready) break ;;
      waiting) ;;
      *) return 1 ;;
    esac
    sleep 1 || return 1
    waited=$((waited + 1))
  done
  (( waited < 60 )) || return 1
  "$ADB_BIN" -s "$ADB_TARGET" exec-out cat "$REMOTE_FILES/update.json" \
    > "$final_file" || return 1
  verify_probe_file "$final_file" update-on-next-open "$nonce" 1 "$id" || return 1
  payload="$(cat "$final_file")" || return 1
  record_json "update-$source_kind-camera-$id" true "$payload" || return 1
}

assert_configured_content() {
  local tag="$1" id
  run_activity "$tag-photo" FrameSeriesProbeActivity frames.json frame-series 90 \
    --es expect stable --es format yuv \
    --es referencePhoto "$REMOTE_FILES/reference-photo" \
    --ei count 2 --ei delayMs 100 || return 1
  for id in 0 1; do
    run_video_snapshot "$tag-video-$id" "$id" || return 1
  done
}

verify_rejected_mutation() {
  local tag="$1" after projection
  after="$TMP/rejected-status-$tag.json"
  camera_status "$after" || return 1
  projection="$(state_projection "$after")" || return 1
  [[ "$projection" == "$ROLLBACK_STATE" ]] || return 1
  assert_staging_clean || return 1
  assert_host_config_unchanged || return 1
  assert_configured_content "rollback-$tag" || return 1
}

root_command_ok() {
  local command="$1" destination="$2"
  "$XENOID_BIN" root exec "$command" > "$destination" || return 1
  python3 - "$destination" <<'PY' || return 1
import json, sys
if json.load(open(sys.argv[1], encoding='utf-8')).get('ok') is not True:
    raise SystemExit(1)
PY
}

"$ADB_BIN" connect "$ADB_TARGET" >/dev/null || die adb-connect
ADB_READY=0
for ((attempt = 0; attempt < 60; ++attempt)); do
  if ADB_STATE="$("$ADB_BIN" -s "$ADB_TARGET" get-state 2>/dev/null)"; then
    if [[ "$ADB_STATE" == device ]]; then
      ADB_READY=1
      break
    fi
  fi
  sleep 1
done
[[ "$ADB_READY" == 1 ]] || die adb-connect
BOOT_STATUS="$("$ADB_BIN" -s "$ADB_TARGET" shell getprop sys.boot_completed \
  | tr -d '\r')" || die boot-ready
[[ "$BOOT_STATUS" == 1 ]] || die boot-ready
record_json adb-connect true '{"connected":true}' || die adb-connect

camera_status "$TMP/initial-status.json" || die camera-status-schema
INITIAL_MODE="$(python3 -c \
  'import json,sys;print(json.load(open(sys.argv[1]))["mode"])' \
  "$TMP/initial-status.json")" || die camera-status-schema
SOURCE_FREE="$(python3 -c \
  'import json,sys;s=json.load(open(sys.argv[1]));print("1" if not s["photoConfigured"] and not s["videoConfigured"] else "0")' \
  "$TMP/initial-status.json")" || die camera-status-schema
INITIAL_PAYLOAD="$(cat "$TMP/initial-status.json")" || die camera-status-schema
record_json camera-status-schema true "$INITIAL_PAYLOAD" || die camera-status-schema
if [[ "$MODE" == full && "$SOURCE_FREE" != 1 && "$DESTRUCTIVE" != 1 ]]; then
  die destructive-guard
fi

if "$ADB_BIN" -s "$ADB_TARGET" shell pm path "$PACKAGE" >/dev/null 2>&1; then
  die probe-package-collision
fi
"$ROOT/tests/camera-runtime-probe/build.sh" > "$TMP/build.out" || die probe-build
APK="$ROOT/dist/camera-runtime-probe/camera-runtime-probe.apk"
[[ -s "$APK" ]] || die probe-build
"$ADB_BIN" -s "$ADB_TARGET" install -r "$APK" >/dev/null || die probe-install
INSTALLED=1
"$ADB_BIN" -s "$ADB_TARGET" shell pm grant "$PACKAGE" android.permission.CAMERA \
  >/dev/null || die probe-permission
record_json probe-install true '{"ordinaryApp":true,"cameraPermission":true}' \
  || die probe-install

SURFACEFLINGER_PID="$("$ADB_BIN" -s "$ADB_TARGET" shell pidof surfaceflinger \
  | tr -d '\r[:space:]')" || die surfaceflinger
[[ -n "$SURFACEFLINGER_PID" ]] || die surfaceflinger
"$ADB_BIN" -s "$ADB_TARGET" shell am start -S -W \
  -n "$PACKAGE/.FixtureActivity" --es fixture first \
  > "$TMP/fixture-before-start.txt" || die fixture-screen-before
sleep 1
"$ADB_BIN" -s "$ADB_TARGET" exec-out screencap -p \
  > "$TMP/fixture-before.png" || die fixture-screen-before
verify_fixture_png "$TMP/fixture-before.png" || die fixture-screen-before
record_json fixture-screen-before true \
  '{"png":true,"nonemptyDimensions":true,"knownPixels":true,"asymmetric":true}' \
  || die fixture-screen-before

run_activity camera2-lifecycle Camera2ProbeActivity camera2.json camera2-lifecycle 150 \
  || die camera2-lifecycle
run_activity camcorder-profiles CamcorderProfilesProbeActivity \
  camcorder-profiles.json camcorder-profiles 30 || die camcorder-profiles
run_activity camera1-take-picture LegacyProbeActivity camera1.json \
  camera1-take-picture 60 || die camera1-take-picture
run_activity ndk-camera NdkProbeActivity ndk.json ndk-camera 60 \
  || die ndk-camera
run_activity media-recorder-codec RecorderProbeActivity recorder.json \
  media-recorder-codec 120 || die media-recorder-codec
run_activity source-privacy PrivacyProbeActivity privacy.json source-privacy 60 \
  || die source-privacy
if [[ "$SOURCE_FREE" == 1 ]]; then
  assert_source_free "$TMP/initial-status.json" || die initial-source-free-state
  run_activity fallback-frames FrameSeriesProbeActivity frames.json frame-series 60 \
    --es expect fallback --es format jpeg --ei count 3 --ei delayMs 100 \
    || die fallback-frames
fi

PROVIDER="/system/bin/hw/android.hardware.camera.provider-service-aidl"
GRALLOC="/vendor/lib64/hw/gralloc.redroid.so"
MEDIA_PROFILES="/vendor/etc/media_profiles_V1_0.xml"
"$ADB_BIN" -s "$ADB_TARGET" exec-out cat "$PROVIDER" > "$TMP/provider.bin" \
  || die camera-artifact
"$ADB_BIN" -s "$ADB_TARGET" exec-out cat "$GRALLOC" > "$TMP/gralloc.bin" \
  || die gralloc-artifact
"$ADB_BIN" -s "$ADB_TARGET" exec-out cat "$MEDIA_PROFILES" \
  > "$TMP/media-profiles.xml" || die media-profiles-artifact
"$ADB_BIN" -s "$ADB_TARGET" shell '
  test -x /system/bin/hw/android.hardware.camera.provider-service-aidl &&
  test -r /vendor/etc/media_profiles_V1_0.xml &&
  test ! -e /system/bin/xenoid-camerahal &&
  test ! -e /system/bin/hw/xenoid-camerahal &&
  test ! -e /system/etc/init/xenoid-camerahal.rc &&
  test ! -e /system/etc/init/hw/xenoid-camerahal.rc &&
  p=$(pidof android.hardware.camera.provider-service-aidl) && test -n "$p" &&
  service check media.camera >/dev/null &&
  service list | grep -q "android.hardware.camera.provider.ICameraProvider/internal/0" &&
  ! ps -A | grep -q xenoid-camerahal
' >/dev/null || die camera-runtime-names
"$ADB_BIN" -s "$ADB_TARGET" exec-out sh -c '
  found=0
  for f in /system/etc/init/*.rc /system/etc/init/hw/*.rc /vendor/etc/init/*.rc /vendor/etc/init/hw/*.rc; do
    [ -f "$f" ] || continue
    if grep -Eq "android\.hardware\.camera\.provider|camera-provider" "$f"; then
      cat "$f"
      found=1
    fi
  done
  [ "$found" -eq 1 ]
' > "$TMP/camera-init.txt" || die camera-init-artifact
"$ADB_BIN" -s "$ADB_TARGET" exec-out sh -c '
  found=0
  for f in /system/etc/vintf/*.xml /system/etc/vintf/manifest/*.xml /vendor/etc/vintf/*.xml /vendor/etc/vintf/manifest/*.xml; do
    [ -f "$f" ] || continue
    if grep -Eq "ICameraProvider|camera\.provider" "$f"; then
      cat "$f"
      found=1
    fi
  done
  [ "$found" -eq 1 ]
' > "$TMP/camera-vintf.txt" || die camera-vintf-artifact
python3 - "$TMP/provider.bin" "$TMP/gralloc.bin" "$TMP/media-profiles.xml" \
  "$TMP/camera-init.txt" "$TMP/camera-vintf.txt" <<'PY' \
  || die camera-artifact-markers
import sys
markers = (
    b'xenoid', b'mock', b'replay', b'inject', b'detector',
    b'client_sdk', b'client-sdk',
)
standard_injection_interface = (
    b'android.hardware.camera.device.icamerainjectionsession')
for name in sys.argv[1:]:
    payload = open(name, 'rb').read().lower()
    if not payload:
        raise SystemExit(1)
    payload = payload.replace(standard_injection_interface, b'')
    if any(marker in payload for marker in markers):
        raise SystemExit(1)
PY
record_json camera-runtime-names true \
  '{"providerExecutableGeneric":true,"providerProcessGeneric":true,"cameraServicePresent":true,"providerScanned":true,"grallocScanned":true,"mediaProfilesScanned":true,"initScanned":true,"vintfScanned":true,"artifactsGeneric":true}' \
  || die camera-runtime-names

if [[ "$REQUIRE_SCRCPY" == 1 ]]; then
  command -v scrcpy >/dev/null 2>&1 || die scrcpy-transport
  scrcpy --serial "$ADB_TARGET" --no-audio --no-playback \
    --record="$TMP/scrcpy.mp4" --time-limit=2 \
    >/dev/null 2>&1 || die scrcpy-transport
  [[ -s "$TMP/scrcpy.mp4" ]] || die scrcpy-transport
  record_json scrcpy-transport true '{"recorded":true,"mandatory":true}' \
    || die scrcpy-transport
fi

if [[ "$MODE" == full ]]; then
  capture_staging "$TMP/stages-baseline.txt" || die staging-baseline
  STAGING_BASELINE_READY=1
  snapshot_host_config || die host-config-baseline
  HOST_CONFIG_BASELINE_READY=1
  MUTATED=1
  "$XENOID_BIN" camera clear all > "$TMP/clear-start.json" \
    || die destructive-clear
  validate_status "$TMP/clear-start.json" || die destructive-clear
  assert_staging_clean || die destructive-clear-staging
  assert_host_config_unchanged || die destructive-clear-host-config
  "$XENOID_BIN" camera apply > "$TMP/apply-source-free.json" \
    || die source-free-apply
  validate_status "$TMP/apply-source-free.json" || die source-free-apply
  assert_source_free "$TMP/apply-source-free.json" || die source-free-state
  assert_staging_clean || die source-free-staging
  assert_host_config_unchanged || die source-free-host-config
  storage_snapshot "$TMP/storage-baseline.json" || die storage-baseline
  STORAGE_BASELINE_READY=1
  BASELINE_STORAGE_PAYLOAD="$(cat "$TMP/storage-baseline.json")" \
    || die storage-baseline
  record_json source-free-state true \
    "{\"active\":true,\"photoConfigured\":false,\"videoConfigured\":false,\"lastErrorEmpty\":true,\"storage\":$BASELINE_STORAGE_PAYLOAD}" \
    || die source-free-state
  run_activity source-free-fallback FrameSeriesProbeActivity frames.json frame-series 60 \
    --es expect fallback --es format jpeg --ei count 3 --ei delayMs 100 \
    || die source-free-fallback

  PHOTO_A="$PHOTO"
  [[ -n "$PHOTO_A" ]] || PHOTO_A="$TMP/fixture-before.png"
  PHOTO_B="$TMP/second.png"
  VIDEO_A="$VIDEO"
  VIDEO_B="$TMP/video-second.mp4"
  "$ADB_BIN" -s "$ADB_TARGET" shell am start -S -W \
    -n "$PACKAGE/.FixtureActivity" --es fixture second \
    > "$TMP/second-start.txt" || die second-photo-fixture
  sleep 1
  "$ADB_BIN" -s "$ADB_TARGET" exec-out screencap -p > "$PHOTO_B" \
    || die second-photo-fixture
  REMOTE_TEMP_CREATED=1
  if [[ -z "$VIDEO_A" ]]; then
    VIDEO_A="$TMP/video.mp4"
    "$ADB_BIN" -s "$ADB_TARGET" shell rm -f \
      "$REMOTE_FIXTURE_PREFIX-video.mp4" >/dev/null || die video-fixture
    "$ADB_BIN" -s "$ADB_TARGET" shell am start -S -W \
      -n "$PACKAGE/.FixtureActivity" --es fixture video \
      > "$TMP/video-start.txt" || die video-fixture
    sleep 1
    "$ADB_BIN" -s "$ADB_TARGET" shell screenrecord --size 640x480 \
      --bit-rate 2000000 --time-limit 6 "$REMOTE_FIXTURE_PREFIX-video.mp4" \
      >/dev/null 2>&1 || die video-fixture
    "$ADB_BIN" -s "$ADB_TARGET" exec-out cat "$REMOTE_FIXTURE_PREFIX-video.mp4" \
      > "$VIDEO_A" || die video-fixture
  fi
  "$ADB_BIN" -s "$ADB_TARGET" shell rm -f \
    "$REMOTE_FIXTURE_PREFIX-video-second.mp4" >/dev/null || die video-second-fixture
  "$ADB_BIN" -s "$ADB_TARGET" shell am start -S -W \
    -n "$PACKAGE/.FixtureActivity" --es fixture video-second \
    > "$TMP/video-second-start.txt" || die video-second-fixture
  sleep 1
  "$ADB_BIN" -s "$ADB_TARGET" shell screenrecord --size 640x480 \
    --bit-rate 2000000 --time-limit 6 "$REMOTE_FIXTURE_PREFIX-video-second.mp4" \
    >/dev/null 2>&1 || die video-second-fixture
  "$ADB_BIN" -s "$ADB_TARGET" exec-out cat \
    "$REMOTE_FIXTURE_PREFIX-video-second.mp4" > "$VIDEO_B" \
    || die video-second-fixture
  python3 - "$PHOTO_A" "$PHOTO_B" "$VIDEO_A" "$VIDEO_B" <<'PY' \
    || die runtime-fixtures
import sys
for name in sys.argv[1:]:
    with open(name, 'rb') as stream:
        if not stream.read(16):
            raise SystemExit(1)
PY
  FIXTURE_ID="$(new_nonce)" || die runtime-fixtures
  PHOTO_IMPORT_A="$TMP/photo-$FIXTURE_ID.png"
  PHOTO_IMPORT_B="$TMP/photo-second-$FIXTURE_ID.png"
  VIDEO_IMPORT_A="$TMP/video-$FIXTURE_ID.bin"
  VIDEO_IMPORT_B="$TMP/video-second-$FIXTURE_ID.bin"
  python3 - "$PHOTO_A" "$PHOTO_B" "$VIDEO_A" "$VIDEO_B" \
    "$PHOTO_IMPORT_A" "$PHOTO_IMPORT_B" "$VIDEO_IMPORT_A" "$VIDEO_IMPORT_B" <<'PY' \
    || die runtime-fixtures
from pathlib import Path
import sys
for source, destination in zip(sys.argv[1:5], sys.argv[5:9]):
    Path(destination).write_bytes(Path(source).read_bytes())
PY
  PHOTO_SIZE="$(python3 -c \
    'import os,sys;print(os.path.getsize(sys.argv[1]))' "$PHOTO_IMPORT_A")" \
    || die runtime-fixtures
  PHOTO_DIGEST="$(python3 -c \
    'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' \
    "$PHOTO_IMPORT_A")" || die runtime-fixtures
  FORBIDDEN_NAME="$(python3 -c \
    'import os,sys;print(os.path.basename(sys.argv[1]))' "$PHOTO_IMPORT_A")" \
    || die runtime-fixtures
  APP_FIXTURES_CREATED=1
  "$ADB_BIN" -s "$ADB_TARGET" push "$PHOTO_A" "$REMOTE_FILES/reference-photo" \
    >/dev/null || die reference-photo-stage
  "$ADB_BIN" -s "$ADB_TARGET" push "$PHOTO_B" \
    "$REMOTE_FILES/reference-photo-second" >/dev/null \
    || die reference-photo-stage
  "$ADB_BIN" -s "$ADB_TARGET" push "$VIDEO_A" "$REMOTE_FILES/reference-video" \
    >/dev/null || die reference-video-stage
  "$ADB_BIN" -s "$ADB_TARGET" push "$VIDEO_B" \
    "$REMOTE_FILES/reference-video-second" >/dev/null \
    || die reference-video-stage
  if [[ -n "$PHOTO" ]]; then PHOTO_ORIGIN=external; else PHOTO_ORIGIN=runtime; fi
  if [[ -n "$VIDEO" ]]; then VIDEO_ORIGIN=external; else VIDEO_ORIGIN=runtime; fi
  record_json runtime-fixtures true \
    "{\"photoOrigin\":\"$PHOTO_ORIGIN\",\"videoOrigin\":\"$VIDEO_ORIGIN\",\"photoAsymmetric\":true,\"videoTimeCoded\":true,\"secondVideoDistinct\":true}" \
    || die runtime-fixtures

  set_source photo "$PHOTO_IMPORT_A" "$TMP/set-photo.json" || die set-photo
  python3 - "$TMP/set-photo.json" <<'PY' || die set-photo-state
import json, sys
value = json.load(open(sys.argv[1], encoding='utf-8'))
if (not value['active'] or not value['photoConfigured']
        or value['photoWidth'] <= 0 or value['photoHeight'] <= 0
        or value['lastError']):
    raise SystemExit(1)
PY
  set_mode faithful "$TMP/mode-photo-faithful.json" \
    "$TMP/mode-photo-faithful-fresh.json" || die mode-photo-faithful
  record_json mode-photo-faithful true \
    '{"mode":"faithful","responseMatchesFresh":true}' || die mode-photo-faithful
  run_activity faithful-photo-content FrameSeriesProbeActivity frames.json \
    frame-series 90 --es expect stable --es format yuv \
    --es referencePhoto "$REMOTE_FILES/reference-photo" \
    --ei count 4 --ei delayMs 150 || die faithful-photo-content
  run_activity configured-camera1-photo LegacyProbeActivity camera1.json \
    camera1-take-picture 90 \
    --es referencePhoto "$REMOTE_FILES/reference-photo" \
    || die configured-camera1-photo
  run_activity configured-camera2-photo Camera2ProbeActivity camera2.json \
    camera2-lifecycle 180 \
    --es referencePhoto "$REMOTE_FILES/reference-photo" \
    || die configured-camera2-photo
  run_activity configured-ndk-photo NdkProbeActivity ndk.json ndk-camera 90 \
    --es referencePhoto "$REMOTE_FILES/reference-photo" \
    || die configured-ndk-photo
  run_update 0 photo "$PHOTO_IMPORT_A" "$PHOTO_IMPORT_B" \
    "$REMOTE_FILES/reference-photo" "$REMOTE_FILES/reference-photo-second" \
    || die update-photo-camera-0
  run_update 1 photo "$PHOTO_IMPORT_A" "$PHOTO_IMPORT_B" \
    "$REMOTE_FILES/reference-photo" "$REMOTE_FILES/reference-photo-second" \
    || die update-photo-camera-1
  set_source photo "$PHOTO_IMPORT_A" "$TMP/reset-photo.json" || die reset-photo
  set_mode naturalized "$TMP/mode-naturalized.json" \
    "$TMP/mode-naturalized-fresh.json" || die mode-naturalized
  record_json mode-naturalized true \
    '{"mode":"naturalized","responseMatchesFresh":true}' || die mode-naturalized
  run_activity naturalized-photo-variation FrameSeriesProbeActivity frames.json \
    frame-series 90 --es expect vary --es format yuv \
    --es referencePhoto "$REMOTE_FILES/reference-photo" \
    --ei count 5 --ei delayMs 150 || die naturalized-photo-variation
  run_activity naturalized-photo-reopen FrameSeriesProbeActivity frames.json \
    frame-series 90 --es expect vary --es format yuv \
    --es referencePhoto "$REMOTE_FILES/reference-photo" \
    --ei count 5 --ei delayMs 150 || die naturalized-photo-reopen
  set_source video "$VIDEO_IMPORT_A" "$TMP/set-video.json" || die set-video
  load_video_claims "$TMP/set-video.json" || die set-video-state
  for id in 0 1; do
    run_replay "video-naturalized-loop-$id" "$id" naturalized \
      || die "video-naturalized-loop-$id"
  done
  set_mode faithful "$TMP/mode-video-faithful.json" \
    "$TMP/mode-video-faithful-fresh.json" || die mode-video-faithful
  record_json mode-video-faithful true \
    '{"mode":"faithful","responseMatchesFresh":true}' || die mode-video-faithful
  for id in 0 1; do
    run_replay "video-faithful-loop-$id" "$id" faithful \
      || die "video-faithful-loop-$id"
  done
  run_update 0 video "$VIDEO_IMPORT_A" "$VIDEO_IMPORT_B" \
    "$REMOTE_FILES/reference-video" "$REMOTE_FILES/reference-video-second" \
    || die update-video-camera-0
  run_update 1 video "$VIDEO_IMPORT_A" "$VIDEO_IMPORT_B" \
    "$REMOTE_FILES/reference-video" "$REMOTE_FILES/reference-video-second" \
    || die update-video-camera-1
  set_source video "$VIDEO_IMPORT_A" "$TMP/reset-video.json" || die reset-video
  load_video_claims "$TMP/reset-video.json" || die reset-video-state
  run_activity configured-camera1-final LegacyProbeActivity camera1.json \
    camera1-take-picture 90 \
    --es referencePhoto "$REMOTE_FILES/reference-photo" \
    || die configured-camera1-final
  run_activity configured-camera2-final Camera2ProbeActivity camera2.json \
    camera2-lifecycle 180 \
    --es referencePhoto "$REMOTE_FILES/reference-photo" \
    || die configured-camera2-final
  run_activity configured-ndk-final NdkProbeActivity ndk.json ndk-camera 90 \
    --es referencePhoto "$REMOTE_FILES/reference-photo" \
    || die configured-ndk-final
  RECORD_MS=$((DURATION_MS + 6000))
  (( RECORD_MS <= 180000 )) || die configured-recorder-window
  RECORDER_TIMEOUT=$((2 * ((RECORD_MS + 999) / 1000) + 180))
  run_activity configured-recorder RecorderProbeActivity recorder.json \
    media-recorder-codec "$RECORDER_TIMEOUT" \
    --es referenceVideo "$REMOTE_FILES/reference-video" \
    --el durationMs "$DURATION_MS" --el recordMs "$RECORD_MS" \
    || die configured-recorder
  run_activity configured-source-privacy PrivacyProbeActivity privacy.json \
    source-privacy 120 --es forbiddenName "$FORBIDDEN_NAME" \
    --es forbiddenDigest "$PHOTO_DIGEST" --ez configured true \
    || die configured-source-privacy
  storage_snapshot "$TMP/storage-configured.json" || die configured-storage
  python3 - "$TMP/storage-baseline.json" "$TMP/storage-configured.json" <<'PY' \
    || die configured-storage
import json, sys
before = json.load(open(sys.argv[1], encoding='utf-8'))
after = json.load(open(sys.argv[2], encoding='utf-8'))
if (after['privateCount'] < before['privateCount'] + 2
        or after['publishedCount'] < before['publishedCount'] + 2
        or after['privateBytes'] <= before['privateBytes']
        or after['publishedBytes'] <= before['publishedBytes']):
    raise SystemExit(1)
PY
  CONFIGURED_STORAGE_PAYLOAD="$(cat "$TMP/storage-configured.json")" \
    || die configured-storage
  record_json configured-storage true "$CONFIGURED_STORAGE_PAYLOAD" \
    || die configured-storage

  camera_status "$TMP/before-restart.json" || die persistence-before
  BEFORE_RESTART="$(state_projection "$TMP/before-restart.json")" \
    || die persistence-before
  "$ADB_BIN" -s "$ADB_TARGET" shell am force-stop dev.xenoid.daemon \
    >/dev/null || die daemon-restart
  "$XENOID_BIN" daemon ensure > "$TMP/daemon-restart.json" || die daemon-restart
  "$XENOID_BIN" camera apply > "$TMP/restart-apply.json" \
    || die persistence-apply
  validate_status "$TMP/restart-apply.json" || die persistence-apply
  assert_staging_clean || die persistence-staging
  assert_host_config_unchanged || die persistence-host-config
  AFTER_RESTART="$(state_projection "$TMP/restart-apply.json")" \
    || die persistence-state
  [[ "$BEFORE_RESTART" == "$AFTER_RESTART" ]] || die persistence-state
  PROVIDER_PID_BEFORE="$("$ADB_BIN" -s "$ADB_TARGET" shell \
    pidof android.hardware.camera.provider-service-aidl \
    | tr -d '\r[:space:]')" || die persistence-provider
  [[ -n "$PROVIDER_PID_BEFORE" ]] || die persistence-provider
  "$XENOID_BIN" root exec 'setprop ctl.restart vendor.camera-provider-aidl' \
    > "$TMP/provider-restart.json" || die persistence-provider
  PROVIDER_RESTARTED=0
  for ((attempt = 0; attempt < 30; ++attempt)); do
    PROVIDER_PID_AFTER="$("$ADB_BIN" -s "$ADB_TARGET" shell \
      'p=$(pidof android.hardware.camera.provider-service-aidl 2>/dev/null || true);printf "%s" "$p"' \
      | tr -d '\r[:space:]')" || die persistence-provider
    if [[ -n "$PROVIDER_PID_AFTER" \
          && "$PROVIDER_PID_AFTER" != "$PROVIDER_PID_BEFORE" ]]; then
      PROVIDER_RESTARTED=1
      break
    fi
    sleep 1
  done
  [[ "$PROVIDER_RESTARTED" == 1 ]] || die persistence-provider
  run_activity persistence-photo-content FrameSeriesProbeActivity frames.json \
    frame-series 90 --es expect stable --es format yuv \
    --es referencePhoto "$REMOTE_FILES/reference-photo" \
    --ei count 2 --ei delayMs 100 || die persistence-photo-content
  for id in 0 1; do
    run_replay "persistence-video-content-$id" "$id" faithful \
      || die "persistence-video-content-$id"
  done
  record_json persistence-state true \
    '{"daemonRestart":true,"providerRestart":true,"apply":true,"statePreserved":true,"photoContentPreserved":true,"videoContentPreserved":true}' \
    || die persistence-state

  camera_status "$TMP/rollback-before.json" || die rollback-status
  ROLLBACK_STATE="$(state_projection "$TMP/rollback-before.json")" \
    || die rollback-status
  printf 'not camera media\n' > "$TMP/malformed.bin"
  if "$XENOID_BIN" camera set photo "$TMP/malformed.bin" \
      > "$TMP/malformed-result.json" 2>/dev/null; then
    die malformed-rollback
  fi
  verify_rejected_mutation malformed || die malformed-rollback
  truncate -s 67108865 "$TMP/oversized.bin"
  if "$XENOID_BIN" camera set photo "$TMP/oversized.bin" \
      > "$TMP/oversized-result.json" 2>/dev/null; then
    die oversized-rollback
  fi
  verify_rejected_mutation oversized || die oversized-rollback
  if "$XENOID_BIN" camera set video "$PHOTO_IMPORT_B" \
      > "$TMP/unsupported-result.json" 2>/dev/null; then
    die unsupported-rollback
  fi
  verify_rejected_mutation unsupported || die unsupported-rollback

  NONPREFIX="/data/local/tmp/camera-hostile-$FIXTURE_ID"
  HOSTILE_PATHS+=("$NONPREFIX")
  "$ADB_BIN" -s "$ADB_TARGET" push "$PHOTO_IMPORT_A" "$NONPREFIX" \
    >/dev/null || die hostile-nonprefix-stage
  route_source_rejected photo "$NONPREFIX" "$PHOTO_SIZE" "$PHOTO_DIGEST" \
    "$TMP/hostile-nonprefix.json" || die hostile-nonprefix
  "$ADB_BIN" -s "$ADB_TARGET" shell rm -f "$NONPREFIX" \
    >/dev/null || die hostile-nonprefix-cleanup
  verify_rejected_mutation hostile-nonprefix || die hostile-nonprefix

  SYMLINK_ID="$(new_nonce)" || die hostile-symlink
  SYMLINK_PATH="/data/local/tmp/.camera-upload-$SYMLINK_ID"
  SYMLINK_TARGET="/data/local/tmp/camera-hostile-target-$SYMLINK_ID"
  HOSTILE_PATHS+=("$SYMLINK_PATH" "$SYMLINK_TARGET")
  "$ADB_BIN" -s "$ADB_TARGET" push "$PHOTO_IMPORT_A" "$SYMLINK_TARGET" \
    >/dev/null || die hostile-symlink-stage
  "$ADB_BIN" -s "$ADB_TARGET" shell ln -s "$SYMLINK_TARGET" "$SYMLINK_PATH" \
    >/dev/null || die hostile-symlink-stage
  route_source_rejected photo "$SYMLINK_PATH" "$PHOTO_SIZE" "$PHOTO_DIGEST" \
    "$TMP/hostile-symlink.json" || die hostile-symlink
  "$ADB_BIN" -s "$ADB_TARGET" shell rm -f "$SYMLINK_PATH" "$SYMLINK_TARGET" \
    >/dev/null || die hostile-symlink-cleanup
  verify_rejected_mutation hostile-symlink || die hostile-symlink

  OWNER_ID="$(new_nonce)" || die hostile-owner
  OWNER_PATH="/data/local/tmp/.camera-upload-$OWNER_ID"
  HOSTILE_PATHS+=("$OWNER_PATH")
  "$ADB_BIN" -s "$ADB_TARGET" push "$PHOTO_IMPORT_A" "$OWNER_PATH" \
    >/dev/null || die hostile-owner-stage
  root_command_ok "chown 0:0 '$OWNER_PATH'" "$TMP/hostile-owner-root.json" \
    || die hostile-owner-stage
  route_source_rejected photo "$OWNER_PATH" "$PHOTO_SIZE" "$PHOTO_DIGEST" \
    "$TMP/hostile-owner.json" || die hostile-owner
  "$ADB_BIN" -s "$ADB_TARGET" shell rm -f "$OWNER_PATH" \
    >/dev/null || die hostile-owner-cleanup
  verify_rejected_mutation hostile-owner || die hostile-owner

  SIZE_ID="$(new_nonce)" || die hostile-size
  SIZE_PATH="/data/local/tmp/.camera-upload-$SIZE_ID"
  HOSTILE_PATHS+=("$SIZE_PATH")
  "$ADB_BIN" -s "$ADB_TARGET" push "$PHOTO_IMPORT_A" "$SIZE_PATH" \
    >/dev/null || die hostile-size-stage
  route_source_rejected photo "$SIZE_PATH" "$((PHOTO_SIZE + 1))" "$PHOTO_DIGEST" \
    "$TMP/hostile-size.json" || die hostile-size
  "$ADB_BIN" -s "$ADB_TARGET" shell rm -f "$SIZE_PATH" \
    >/dev/null || die hostile-size-cleanup
  verify_rejected_mutation hostile-size || die hostile-size

  HASH_ID="$(new_nonce)" || die hostile-hash
  HASH_PATH="/data/local/tmp/.camera-upload-$HASH_ID"
  HOSTILE_PATHS+=("$HASH_PATH")
  "$ADB_BIN" -s "$ADB_TARGET" push "$PHOTO_IMPORT_A" "$HASH_PATH" \
    >/dev/null || die hostile-hash-stage
  route_source_rejected photo "$HASH_PATH" "$PHOTO_SIZE" \
    0000000000000000000000000000000000000000000000000000000000000000 \
    "$TMP/hostile-hash.json" || die hostile-hash
  "$ADB_BIN" -s "$ADB_TARGET" shell rm -f "$HASH_PATH" \
    >/dev/null || die hostile-hash-cleanup
  verify_rejected_mutation hostile-hash || die hostile-hash
  record_json import-rollback true \
    '{"malformedRejected":true,"oversizedRejected":true,"unsupportedRejected":true,"nonprefixRejected":true,"symlinkRejected":true,"ownerRejected":true,"sizeRejected":true,"hashRejected":true,"statePreserved":true,"contentPreserved":true,"stagingClean":true}' \
    || die import-rollback

  "$XENOID_BIN" camera clear all > "$TMP/final-clear.json" || die final-clear
  validate_status "$TMP/final-clear.json" || die final-clear
  assert_staging_clean || die final-clear-staging
  assert_host_config_unchanged || die final-clear-host-config
  set_mode "$INITIAL_MODE" "$TMP/final-mode.json" \
    "$TMP/final-mode-fresh.json" || die final-mode
  record_json final-mode true \
    "{\"mode\":\"$INITIAL_MODE\",\"responseMatchesFresh\":true}" || die final-mode
  "$XENOID_BIN" camera apply > "$TMP/final-apply.json" || die final-apply
  validate_status "$TMP/final-apply.json" || die final-apply
  assert_source_free "$TMP/final-apply.json" "$INITIAL_MODE" \
    || die final-source-state
  camera_status "$TMP/final-status-fresh.json" || die final-source-state
  python3 - "$TMP/final-apply.json" "$TMP/final-status-fresh.json" <<'PY' \
    || die final-status-equality
import json, sys
if json.load(open(sys.argv[1], encoding='utf-8')) != json.load(
        open(sys.argv[2], encoding='utf-8')):
    raise SystemExit(1)
PY
  assert_staging_clean || die final-staging
  assert_host_config_unchanged || die final-host-config
  run_activity final-source-free-fallback FrameSeriesProbeActivity frames.json \
    frame-series 60 --es expect fallback --es format jpeg \
    --es referencePhoto "$REMOTE_FILES/reference-photo" \
    --ei count 3 --ei delayMs 100 || die final-source-free-fallback
  storage_snapshot "$TMP/storage-final.json" || die final-storage
  cmp -s "$TMP/storage-baseline.json" "$TMP/storage-final.json" \
    || die final-storage
  FINAL_STORAGE_PAYLOAD="$(cat "$TMP/storage-final.json")" || die final-storage
  record_json final-source-state true \
    "{\"sourceFree\":true,\"active\":true,\"lastErrorEmpty\":true,\"mode\":\"$INITIAL_MODE\",\"stagingClean\":true,\"hostConfigUnchanged\":true,\"storage\":$FINAL_STORAGE_PAYLOAD}" \
    || die final-source-state
  MUTATED=0
fi

"$ADB_BIN" -s "$ADB_TARGET" shell am start -S -W \
  -n "$PACKAGE/.FixtureActivity" --es fixture first \
  > "$TMP/fixture-after-start.txt" || die fixture-screen-after
sleep 1
"$ADB_BIN" -s "$ADB_TARGET" exec-out screencap -p \
  > "$TMP/fixture-after.png" || die fixture-screen-after
verify_fixture_png "$TMP/fixture-after.png" "$TMP/fixture-before.png" \
  || die fixture-screen-after
record_json fixture-screen-after true \
  '{"png":true,"nonemptyDimensions":true,"knownPixels":true,"asymmetric":true,"pixelsStable":true}' \
  || die fixture-screen-after
CURRENT_SURFACEFLINGER_PID="$("$ADB_BIN" -s "$ADB_TARGET" shell \
  pidof surfaceflinger | tr -d '\r[:space:]')" || die surfaceflinger-stability
[[ "$CURRENT_SURFACEFLINGER_PID" == "$SURFACEFLINGER_PID" ]] \
  || die surfaceflinger-stability
record_json surfaceflinger-stability true \
  '{"alive":true,"pidStable":true,"knownPixelsBefore":true,"knownPixelsAfter":true}' \
  || die surfaceflinger-stability
exit 0
