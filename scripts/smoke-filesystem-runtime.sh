#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
ADB_BIN="$(python3 - <<'PY'
import sys
sys.path.insert(0, 'src')
from xenoid.util import which
print(which('adb') or 'adb')
PY
)"
ADB_TARGET="$(python3 - <<'PY'
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
PACKAGE="org.example.filesystemruntimeprobe"
LOG="/tmp/xenoid-filesystem-probe.log"
RESULT="/tmp/xenoid-filesystem-probe.json"
INSTALLED=false
cleanup() {
  if [[ "$INSTALLED" == true ]]; then
    "$ADB_BIN" -s "$ADB_TARGET" uninstall "$PACKAGE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

APK="$(tests/filesystem-runtime-probe/build.sh)"
"$ADB_BIN" connect "$ADB_TARGET" >/dev/null
"$ADB_BIN" -s "$ADB_TARGET" uninstall "$PACKAGE" >/dev/null 2>&1 || true
"$ADB_BIN" -s "$ADB_TARGET" install "$APK" >/dev/null
INSTALLED=true
"$ADB_BIN" -s "$ADB_TARGET" logcat -c
"$ADB_BIN" -s "$ADB_TARGET" shell am start -W -n "$PACKAGE/.ProbeActivity" >/dev/null
for _ in $(seq 1 30); do
  "$ADB_BIN" -s "$ADB_TARGET" logcat -d -s XenoidFilesystemProbe:I > "$LOG"
  if grep -q 'dev.xenoid.filesystem-runtime-probe/v1' "$LOG"; then break; fi
  sleep 1
done
python3 - "$LOG" "$RESULT" <<'PY'
import json
import pathlib
import sys
text = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace')
marker = 'XenoidFilesystemProbe: '
rows = [line.split(marker, 1)[1] for line in text.splitlines() if marker in line]
if not rows:
    raise SystemExit('filesystem probe did not emit a result')
value = json.loads(rows[-1])
pathlib.Path(sys.argv[2]).write_text(json.dumps(value, sort_keys=True), encoding='utf-8')
PY

"$ADB_BIN" -s "$ADB_TARGET" shell '
  test -L /dev/block/platform/14700000.ufs/by-name/userdata &&
  test "$(readlink /dev/block/platform/14700000.ufs/by-name/userdata)" = ../../../sda &&
  test -b /dev/block/platform/14700000.ufs/by-name/userdata &&
  grep -q "f2fs" /proc/filesystems &&
  grep -qE " - f2fs /dev/block/platform/14700000[.]ufs/by-name/userdata " /proc/1/mountinfo &&
  grep -qE "^/dev/block/platform/14700000[.]ufs/by-name/userdata /data f2fs " /proc/1/mounts &&
  grep -q "mounted on /data with fstype f2fs" /proc/1/mountstats
' >/tmp/xenoid-filesystem-mount-evidence.out

python3 - "$RESULT" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding='utf-8'))
F2FS = '0xf2f52010'
EXT4 = '0xef53'

def require(condition, message):
    if not condition:
        raise AssertionError(message)

def require_operation(operation, expected, label):
    require(operation.get('return') == 0, f'{label} failed: {operation}')
    require(operation.get('errno') == 0, f'{label} errno mismatch: {operation}')
    require(str(operation.get('type', '')).lower() == expected,
            f'{label} magic mismatch: {operation}')

def require_path(surface, expected, label, require_fd):
    require_operation(surface['libc'], expected, f'{label} libc statfs')
    require_operation(surface['raw'], expected, f'{label} raw statfs')
    if require_fd:
        require_operation(surface['rawFd'], expected, f'{label} raw fstatfs')

require(value.get('schema') == 'dev.xenoid.filesystem-runtime-probe/v1', 'schema mismatch')
require(value.get('ok') is True, f'probe failed: {value}')
ordinary = value['ordinary']
require(10000 <= ordinary['uid'] % 100000 < 90000, 'ordinary probe did not use an app UID')
require_path(ordinary['data'], F2FS, 'ordinary /data', False)
require_path(ordinary['appData'], F2FS, 'ordinary app data', True)
require_path(ordinary['system'], EXT4, 'ordinary /system', True)
isolated = value['isolated']
require(isolated.get('ok') is True, f'isolated probe failed: {isolated}')
isolated_native = isolated['native']
require(90000 <= isolated_native['uid'] % 100000 < 100000,
        'isolated probe did not use an isolated UID')
require_path(isolated_native['data'], F2FS, 'isolated /data', False)
require(ordinary['uid'] != isolated_native['uid'], 'isolated UID was not distinct')
print(json.dumps({
    'ok': True,
    'schema': value['schema'],
    'ordinaryUid': ordinary['uid'],
    'isolatedUid': isolated_native['uid'],
    'dataMagic': ordinary['data']['raw']['type'],
    'appDataFdMagic': ordinary['appData']['rawFd']['type'],
    'systemMagic': ordinary['system']['raw']['type'],
    'mountSource': '/dev/block/platform/14700000.ufs/by-name/userdata',
}, sort_keys=True))
PY
