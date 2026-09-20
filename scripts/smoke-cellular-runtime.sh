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
import pathlib
import sys
sys.path.insert(0, 'src')
from xenoid.backend import RuntimeManager
from xenoid.config import resolve_instance
context, config, lease = resolve_instance(project_root=pathlib.Path.cwd())
print(RuntimeManager(context, config, lease).adb_target)
PY
)"
PACKAGE="org.example.cellularruntimeprobe"
EXPECTED="/tmp/xenoid-cellular-expected.json"
LOG="/tmp/xenoid-cellular-probe.log"
RESULT="/tmp/xenoid-cellular-probe.json"
INSTALLED=false
cleanup() {
  if [[ "$INSTALLED" == true ]]; then "$ADB_BIN" -s "$ADB_TARGET" uninstall "$PACKAGE" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

./xenoid cellular status > "$EXPECTED"
python3 - "$EXPECTED" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding='utf-8'))
if value.get('ok') is not True or value.get('host', {}).get('state') != 'active':
    raise SystemExit('active location identity is required')
profile = value['host'].get('active', {}).get('profile') or {}
required = ('operatorNumeric', 'band', 'earfcn', 'msisdn', 'locationKey')
if any(not profile.get(key) for key in required):
    raise SystemExit('active location profile is incomplete')
PY
APK="$(tests/cellular-runtime-probe/build.sh)"
"$ADB_BIN" connect "$ADB_TARGET" >/dev/null
# The probe is signed with a local debug key that rotates between checkouts,
# so a previous run's install can block -r with INSTALL_FAILED_UPDATE_INCOMPATIBLE;
# drop it first, matching the persistence smoke convention.
"$ADB_BIN" -s "$ADB_TARGET" uninstall "$PACKAGE" >/dev/null 2>&1 || true
"$ADB_BIN" -s "$ADB_TARGET" install -r "$APK" >/dev/null
INSTALLED=true
for permission in android.permission.READ_PHONE_STATE android.permission.READ_PHONE_NUMBERS android.permission.ACCESS_COARSE_LOCATION android.permission.ACCESS_FINE_LOCATION; do
  "$ADB_BIN" -s "$ADB_TARGET" shell pm grant "$PACKAGE" "$permission"
done
"$ADB_BIN" -s "$ADB_TARGET" logcat -c
"$ADB_BIN" -s "$ADB_TARGET" shell am start -W -n "$PACKAGE/.ProbeActivity" >/dev/null
for _ in $(seq 1 30); do
  "$ADB_BIN" -s "$ADB_TARGET" logcat -d -s XenoidCellularProbe:I > "$LOG"
  if grep -q 'dev.xenoid.cellular-runtime-probe/v2' "$LOG"; then break; fi
  sleep 1
done
python3 - "$LOG" "$RESULT" <<'PY'
import json
import pathlib
import sys
text = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace')
marker = 'XenoidCellularProbe: '
rows = [line.split(marker, 1)[1] for line in text.splitlines() if marker in line]
if not rows:
    raise SystemExit('cellular probe did not emit a result')
value = json.loads(rows[-1])
pathlib.Path(sys.argv[2]).write_text(json.dumps(value, sort_keys=True), encoding='utf-8')
PY
python3 - "$EXPECTED" "$RESULT" <<'PY'
import json
import sys
host = json.load(open(sys.argv[1], encoding='utf-8'))['host']
profile = host['active']['profile']
expected = {
    'operatorNumeric': profile['operatorNumeric'],
    'cell': {'earfcn': profile['earfcn'], 'band': profile['band']},
    'dataIface': 'rmnet_data0',
    'msisdn': profile['msisdn'],
}
result = json.load(open(sys.argv[2], encoding='utf-8'))

def require(value, message):
    if not value:
        raise AssertionError(message)

def mask(value):
    return '*' * max(0, len(value) - 4) + value[-4:]

require(result.get('ok') is True, 'ordinary probe failed')
telephony = result['telephony']
require(telephony['simState'] == 5, 'SIM is not READY')
require(telephony['simOperator'] == expected['operatorNumeric'], 'SIM operator mismatch')
require(telephony['networkOperator'] == expected['operatorNumeric'], 'network operator mismatch')
require(telephony['dataNetworkType'] == 13, 'data network is not LTE')
require(telephony['subscriptionCount'] == 1, 'expected exactly one active subscription')
line1 = telephony.get('line1Number') or ''
require(line1.startswith('+'), 'line1Number missing from UICC MSISDN')
require(mask(line1) == expected['msisdn'], 'line1Number mismatch')
subscription_number = telephony.get('subscriptionNumber') or ''
require(mask(subscription_number) == expected['msisdn'], 'subscription number mismatch')
mcc, mnc = expected['operatorNumeric'][:3], expected['operatorNumeric'][3:]
cells = [cell for cell in telephony['lteCells'] if cell.get('registered')]
require(len(cells) == 1, 'expected exactly one registered LTE cell')
cell = cells[0]
require(cell['mcc'] == mcc and cell['mnc'] == mnc, 'LTE PLMN mismatch')
require(cell['earfcn'] == expected['cell']['earfcn'], 'LTE EARFCN mismatch')
require(expected['cell']['band'] in cell['bands'], 'LTE band mismatch')
connectivity = result['connectivity']
require(connectivity['cellularCount'] == 1, 'expected exactly one cellular network')
require(connectivity['ethernetCount'] == 0, 'Ethernet network leaked')
require(connectivity['activeCellular'] is True and connectivity['activeEthernet'] is False,
        'active network transport mismatch')
require(expected['dataIface'] in connectivity['interfaces'], 'cellular LinkProperties interface mismatch')
require(expected['dataIface'] in result['javaIfaces'] and 'eth0' not in result['javaIfaces'],
        'Java interface enumeration mismatch')

def require_operation(operation, stage, expected_return, expected_errno, context):
    require(operation.get('attempted') is True, f'{context} {stage} was not attempted')
    require(operation.get('return') == expected_return,
            f'{context} {stage} returned {operation.get("return")}, expected {expected_return}')
    require(operation.get('errno') == expected_errno,
            f'{context} {stage} errno {operation.get("errno")}, expected {expected_errno}')

def require_skipped(operation, context):
    require(operation.get('attempted') is False, f'{context} unexpectedly attempted after socket denial')

def require_identity(name, operation, required=True):
    if operation.get('attempted') is not True or operation.get('return') not in (0, None) and operation.get('return') < 0:
        require(not required, f'{name} unexpectedly denied')
        return
    require('eth0' not in operation['ifaces'], f'{name} leaked eth0')
    if required:
        require(expected['dataIface'] in operation['ifaces'], f'{name} omitted cellular interface')
    elif operation['ifaces']:
        require(expected['dataIface'] in operation['ifaces'], f'{name} exposed a non-cellular interface')

ordinary = result['native']
require(10000 <= ordinary['uid'] % 100000 < 90000, 'ordinary probe did not use an app UID')
for name in ('inet', 'inet6'):
    operation = ordinary['sockets'][name]
    require(operation.get('attempted') is True and operation.get('return') >= 0 and operation.get('errno') == 0,
            f'ordinary {name} socket creation failed')
require_operation(ordinary['sockets']['unix'], 'ordinary unix', 0, 0, 'ordinary socket')
require_operation(ordinary['getifaddrs'], 'ordinary getifaddrs', 0, 0, 'ordinary getifaddrs')
require_identity('ordinary getifaddrs', ordinary['getifaddrs'])
require_operation(ordinary['ioctl'], 'ordinary ioctl', 0, 0, 'ordinary ioctl')
require_identity('ordinary ioctl', ordinary['ioctl'])
ordinary_getlink = ordinary['netlink']['getlink']
require(ordinary_getlink['socket']['return'] >= 0 and ordinary_getlink['socket']['errno'] == 0,
        'ordinary GETLINK route socket was denied')
require_operation(ordinary_getlink['bind'], 'ordinary GETLINK', 0, 0, 'ordinary GETLINK')
require_operation(ordinary_getlink['sendto'], 'ordinary GETLINK', -1, 13, 'ordinary GETLINK')
require_skipped(ordinary_getlink['receive'], 'ordinary GETLINK receive')
for request in ('getaddr', 'getroute'):
    operation = ordinary['netlink'][request]
    require(operation['socket']['return'] >= 0 and operation['socket']['errno'] == 0,
            f'ordinary {request} route socket was denied')
    require_operation(operation['bind'], f'ordinary {request}', 0, 0, f'ordinary {request}')
    require(operation['sendto']['return'] > 0 and operation['sendto']['errno'] == 0,
            f'ordinary {request} send failed')
    require_operation(operation['receive'], f'ordinary {request}', 0, 0, f'ordinary {request}')
    require_identity(f'ordinary {request}', operation['receive'])
require_identity('ordinary procRoutes', ordinary['procRoutes'])
require_identity('ordinary procIpv6', ordinary['procIpv6'])
require_identity('ordinary sysfs', ordinary['sysfs'])

isolated = result['isolated']
require(isolated.get('ok') is True, 'isolated process probe failed')
isolated_native = isolated['native']
require(90000 <= isolated_native['uid'] % 100000 < 100000, 'isolated probe did not use an isolated UID')
for name in ('inet', 'inet6'):
    require_operation(isolated_native['sockets'][name], f'isolated {name}', -1, 13, 'isolated socket')
require_operation(isolated_native['sockets']['unix'], 'isolated unix', 0, 0, 'isolated socket')
for request in ('getlink', 'getaddr', 'getroute'):
    operation = isolated_native['netlink'][request]
    require_operation(operation['socket'], f'isolated {request}', -1, 13, f'isolated {request}')
    require_skipped(operation['bind'], f'isolated {request} bind')
    require_skipped(operation['sendto'], f'isolated {request} sendto')
    require_skipped(operation['receive'], f'isolated {request} receive')
for surface in ('getifaddrs', 'ioctl', 'procRoutes', 'procIpv6', 'sysfs'):
    require_identity(f'isolated {surface}', isolated_native[surface], required=False)
require(result['native']['uid'] != isolated_native['uid'], 'isolated probe did not use a distinct UID')
print(json.dumps({
    'ok': True,
    'schema': result['schema'],
    'operatorNumeric': expected['operatorNumeric'],
    'dataIface': expected['dataIface'],
    'cellularNetworks': connectivity['cellularCount'],
    'ethernetNetworks': connectivity['ethernetCount'],
    'ordinaryUid': result['native']['uid'],
    'isolatedUid': isolated_native['uid'],
}, sort_keys=True))
PY
NETCTL="$("$ADB_BIN" -s "$ADB_TARGET" shell /system/bin/xenoid-netctl status rmnet_data0)"
python3 - "$EXPECTED" "$NETCTL" <<'PY'
import json
import sys
host = json.load(open(sys.argv[1], encoding='utf-8'))['host']
expected_iface = 'rmnet_data0'
status = json.loads(sys.argv[2])
if not (status.get('ok') is True and status.get('ifname') == expected_iface):
    raise SystemExit('privileged xenoid-netctl status failed')
if status.get('ioctlErrno') != 0 or status.get('netlinkErrno') != 0:
    raise SystemExit('privileged netlink control path was denied')
if not status.get('ioctl') or status.get('ioctl') != status.get('netlink'):
    raise SystemExit('privileged ioctl/netlink MAC mismatch')
PY
