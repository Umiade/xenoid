#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [[ -x ./xenoid ]]; then XENOID_BIN=./xenoid; elif [[ -x ./bin/xenoid ]]; then XENOID_BIN=./bin/xenoid; else XENOID_BIN=xenoid; fi
OUT="${1:-/tmp/xenoid-runtime-smoke.json}"
ADB_TARGET="$(python3 - <<'PY'
import os, sys
sys.path.insert(0, 'src')
from pathlib import Path
from xenoid.config import resolve_instance
name = os.environ.get('XENOID_INSTANCE') or 'default'
try:
    context, cfg, lease = resolve_instance(name, project_root=Path.cwd(), env={})
    print(f"127.0.0.1:{lease.host_adb_port}")
except Exception:
    print('127.0.0.1:5555')
PY
)"
ADB_BIN="$(python3 - <<'PY'
import sys; sys.path.insert(0, 'src')
from xenoid.util import which
print(which('adb') or 'adb')
PY
)"
json_quote() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }
checks=()
OK=true
# Production root access is token-gated through daemon/rootd. Prefer that path so
# remote Docker contexts and non-debuggable adbd behave exactly like user commands.
CONTAINER_NAME="$(python3 - <<'PY'
import os, sys
sys.path.insert(0, 'src')
from pathlib import Path
from xenoid.config import resolve_instance
name = os.environ.get('XENOID_INSTANCE') or 'default'
try:
    context, cfg, lease = resolve_instance(name, project_root=Path.cwd(), env={})
    print(lease.container_name)
except Exception:
    print('xenoid-android')
PY
)"
ROOT_CH=adb
if "$XENOID_BIN" root status >/tmp/xenoid-smoke-root-channel.out 2>&1 && ./scripts/json-ok.py </tmp/xenoid-smoke-root-channel.out; then
  ROOT_CH=rootd
elif command -v docker >/dev/null 2>&1 && docker exec "$CONTAINER_NAME" true >/dev/null 2>&1; then
  ROOT_CH=docker
fi
as_root() { # as_root <shell-command-string>
  if [[ "$ROOT_CH" == rootd ]]; then
    "$XENOID_BIN" root exec "$1"
  elif [[ "$ROOT_CH" == docker ]]; then
    docker exec "$CONTAINER_NAME" sh -c "$1"
  else
    "$ADB_BIN" -s "$ADB_TARGET" shell "$1"
  fi
}
add() { local name="$1" ok="$2" detail="$3"; [[ "$ok" == true ]] || OK=false; checks+=("$(printf '{"name":%s,"ok":%s,"detail":%s}' "$(printf '%s' "$name"|json_quote)" "$ok" "$(printf '%s' "$detail"|json_quote)")"); }
if "$ADB_BIN" connect "$ADB_TARGET" >/tmp/xenoid-smoke-adb-connect.out 2>&1; then add adb_connect true "$(cat /tmp/xenoid-smoke-adb-connect.out)"; else add adb_connect false "$(cat /tmp/xenoid-smoke-adb-connect.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell getprop sys.boot_completed >/tmp/xenoid-smoke-boot.out 2>&1 && grep -q 1 /tmp/xenoid-smoke-boot.out; then add boot_completed true "$(cat /tmp/xenoid-smoke-boot.out)"; else add boot_completed false "$(cat /tmp/xenoid-smoke-boot.out 2>/dev/null || true)"; fi
$XENOID_BIN daemon ensure >/tmp/xenoid-smoke-daemon-ensure.out 2>&1 || true
if $XENOID_BIN daemon health >/tmp/xenoid-smoke-daemon-health.out 2>&1 && ./scripts/json-ok.py </tmp/xenoid-smoke-daemon-health.out; then add daemon_health true "$(cat /tmp/xenoid-smoke-daemon-health.out)"; else add daemon_health false "$(cat /tmp/xenoid-smoke-daemon-health.out) | ensure=$(cat /tmp/xenoid-smoke-daemon-ensure.out 2>/dev/null)"; fi
for cmd in "root status" "profile status" "profile env" "hide status" "ota check"; do
  name="${cmd// /_}"
  if $XENOID_BIN $cmd >/tmp/xenoid-smoke-$name.out 2>&1 && ./scripts/json-ok.py </tmp/xenoid-smoke-$name.out; then add "$name" true "$(cat /tmp/xenoid-smoke-$name.out)"; else add "$name" false "$(cat /tmp/xenoid-smoke-$name.out)"; fi
done
if $XENOID_BIN frida status >/tmp/xenoid-smoke-frida-status.out 2>&1 && ./scripts/json-ok.py </tmp/xenoid-smoke-frida-status.out; then
  if [[ "${XENOID_SMOKE_REQUIRE_FRIDA:-0}" == 1 ]]; then add frida_status true "$(cat /tmp/xenoid-smoke-frida-status.out)"; else add frida_status false "frida-server is running in production validation"; fi
elif python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("httpStatus")==200 and d.get("rootdReachable") is True else 1)' /tmp/xenoid-smoke-frida-status.out 2>/dev/null; then
  if [[ "${XENOID_SMOKE_REQUIRE_FRIDA:-0}" == 1 ]]; then add frida_status false "$(cat /tmp/xenoid-smoke-frida-status.out)"; else add frida_status true "frida-server absent (production state)"; fi
else
  add frida_status false "$(cat /tmp/xenoid-smoke-frida-status.out)"
fi
if $XENOID_BIN input tap 1 1 >/tmp/xenoid-smoke-input-tap.out 2>&1 \
    && python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); s=str(d.get("stdout","")); sys.exit(0 if d.get("ok") is True and d.get("driverLayer") is True and d.get("fallback") is False and d.get("eventNode")=="/dev/uinput" and "dev.input-action/v2" in s and "pressurePeak" in s and "touchMajorPeak" in s and "touchMinorPeak" in s else 1)' /tmp/xenoid-smoke-input-tap.out; then
  add input_tap true "$(cat /tmp/xenoid-smoke-input-tap.out)"
else
  add input_tap false "$(cat /tmp/xenoid-smoke-input-tap.out)"
fi
if $XENOID_BIN input swipe 2 2 3 3 64 >/tmp/xenoid-smoke-input-swipe.out 2>&1 \
    && python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); s=str(d.get("stdout","")); sys.exit(0 if d.get("ok") is True and d.get("driverLayer") is True and d.get("fallback") is False and d.get("eventNode")=="/dev/uinput" and "dev.input-action/v2" in s and "contactDurationMs\\\":64" in s and "cubic-bezier+smoothstep" in s else 1)' /tmp/xenoid-smoke-input-swipe.out; then
  add input_swipe true "$(cat /tmp/xenoid-smoke-input-swipe.out)"
else
  add input_swipe false "$(cat /tmp/xenoid-smoke-input-swipe.out)"
fi
if "$ADB_BIN" -s "$ADB_TARGET" shell dumpsys input >/tmp/xenoid-smoke-input-driver.out 2>&1 \
    && grep -q 'sec_touchscreen' /tmp/xenoid-smoke-input-driver.out \
    && grep -q 'Path: /dev/input/event' /tmp/xenoid-smoke-input-driver.out \
    && grep -q 'Sources: TOUCHSCREEN' /tmp/xenoid-smoke-input-driver.out \
    && grep -q 'Touch Input Mapper (mode - DIRECT)' /tmp/xenoid-smoke-input-driver.out \
    && grep -q 'TouchMajor: min=0, max=31' /tmp/xenoid-smoke-input-driver.out \
    && grep -q 'TouchMinor: min=0, max=31' /tmp/xenoid-smoke-input-driver.out \
    && grep -q 'ToolMajor: min=0, max=31' /tmp/xenoid-smoke-input-driver.out \
    && grep -q 'ToolMinor: min=0, max=31' /tmp/xenoid-smoke-input-driver.out \
    && grep -q 'Pressure: min=0, max=255' /tmp/xenoid-smoke-input-driver.out; then
  add input_driver true "persistent direct touchscreen exposes pressure and contact/tool major/minor axes"
else
  add input_driver false "$(cat /tmp/xenoid-smoke-input-driver.out)"
fi
if $XENOID_BIN device collect --out /tmp/xenoid-runtime-fingerprint.json >/tmp/xenoid-smoke-device.out 2>&1 && ./scripts/json-ok.py </tmp/xenoid-smoke-device.out; then add device_collect true "$(cat /tmp/xenoid-smoke-device.out)"; else add device_collect false "$(cat /tmp/xenoid-smoke-device.out)"; fi

# Camera2 static metadata must describe the same ordered output tuples across
# stream configurations, minimum frame durations, and stall durations.
if "$ADB_BIN" -s "$ADB_TARGET" shell dumpsys media.camera >/tmp/xenoid-smoke-camera-metadata.out 2>&1; then
  if python3 - <<'PY' >/tmp/xenoid-smoke-camera-metadata-summary.out 2>&1
import json
import re
import sys

raw = open("/tmp/xenoid-smoke-camera-metadata.out").read()
contracts = {
    "0": {
        "facing": "Back",
        "jpeg": [
            (4080, 3072), (3840, 2160), (1920, 1080),
            (1440, 1080), (1280, 960), (1280, 720),
            (1024, 768), (800, 600), (640, 480), (320, 240),
        ],
        "nonstall": [
            (1920, 1080), (1440, 1080), (1280, 960),
            (1280, 720), (1024, 768), (800, 600),
            (640, 480), (320, 240),
        ],
        "blobStalls": [
            220000000, 180000000, 100000000, 90000000, 80000000,
            70000000, 50000000, 40000000, 30000000, 15000000,
        ],
    },
    "1": {
        "facing": "Front",
        "jpeg": [
            (3840, 2880), (1920, 1080), (1280, 720),
            (640, 480), (320, 240),
        ],
        "nonstall": [
            (1920, 1080), (1280, 720), (640, 480), (320, 240),
        ],
        "blobStalls": [
            200000000, 100000000, 70000000, 30000000, 15000000,
        ],
    },
}
formats = [33, 35, 34]

try:
    marker_pattern = re.compile(
        r"== Camera HAL device device@1\.0/internal/(\d+) "
        r"\(v3\.0\) static information: =="
    )
    markers = list(marker_pattern.finditer(raw))
    if len(markers) != 2:
        raise ValueError(f"expected 2 static camera sections, found {len(markers)}")

    sections = {}
    for index, marker in enumerate(markers):
        if index + 1 < len(markers):
            end = markers[index + 1].start()
        else:
            end = raw.find("== Vendor tags:", marker.end())
            if end < 0:
                raise ValueError("camera metadata terminator is missing")
        sections[marker.group(1)] = raw[marker.end():end]
    if set(sections) != {"0", "1"}:
        raise ValueError(f"unexpected camera IDs: {sorted(sections)}")

    def tag_rows(section, name):
        match = re.search(
            re.escape(name)
            + r" \([^\n]+\): [^\n]+\n((?:        \[[^\n]+\]\n)+)",
            section,
        )
        if not match:
            raise ValueError(f"missing {name}")
        return [
            row.split()
            for row in re.findall(r"\[([^\]]+)\]", match.group(1))
        ]

    def stream_tuples(section):
        rows = tag_rows(
            section, "android.scaler.availableStreamConfigurations"
        )
        if any(len(row) != 4 for row in rows):
            raise ValueError("malformed stream configuration tuple")
        return [
            (int(fmt), int(width), int(height), direction)
            for fmt, width, height, direction in rows
        ]

    def duration_tuples(section, name):
        values = [token for row in tag_rows(section, name) for token in row]
        if len(values) % 4:
            raise ValueError(f"{name} has {len(values)} scalar values")
        return [
            tuple(map(int, values[offset:offset + 4]))
            for offset in range(0, len(values), 4)
        ]

    camera_summary = {}
    for camera_id, contract in contracts.items():
        expected_keys = (
            [(33, width, height) for width, height in contract["jpeg"]]
            + [
                (fmt, width, height)
                for fmt in (35, 34)
                for width, height in contract["nonstall"]
            ]
        )
        expected_stalls = (
            contract["blobStalls"]
            + [0] * (2 * len(contract["nonstall"]))
        )
        expected_facing = contract["facing"]
        section = sections[camera_id]
        facing_match = re.search(r"\n    Facing: (\w+)", section)
        if not facing_match:
            raise ValueError(f"camera {camera_id} facing is missing")
        facing = facing_match.group(1)
        stream = stream_tuples(section)
        minimum = duration_tuples(
            section, "android.scaler.availableMinFrameDurations"
        )
        stall = duration_tuples(
            section, "android.scaler.availableStallDurations"
        )
        stream_keys = [(fmt, width, height) for fmt, width, height, _ in stream]
        minimum_keys = [(fmt, width, height) for fmt, width, height, _ in minimum]
        stall_keys = [(fmt, width, height) for fmt, width, height, _ in stall]

        if facing != expected_facing:
            raise ValueError(
                f"camera {camera_id} facing {facing}, expected {expected_facing}"
            )
        if stream_keys != expected_keys:
            raise ValueError(f"camera {camera_id} stream tuples differ")
        if minimum_keys != expected_keys or stall_keys != expected_keys:
            raise ValueError(f"camera {camera_id} duration keys differ")
        if len(set(stream_keys)) != len(expected_keys):
            raise ValueError(f"camera {camera_id} stream tuples are duplicated")
        if any(direction != "OUTPUT" for *_, direction in stream):
            raise ValueError(f"camera {camera_id} contains a non-output tuple")
        if any(duration != 33333333 for *_, duration in minimum):
            raise ValueError(f"camera {camera_id} minimum duration differs")
        if [duration for *_, duration in stall] != expected_stalls:
            raise ValueError(f"camera {camera_id} stall durations differ")

        camera_summary[camera_id] = {
            "facing": facing,
            "streamTupleCount": len(stream),
        }

    print(
        json.dumps(
            {
                "ok": True,
                "cameras": camera_summary,
                "formats": formats,
                "sizesByCamera": {
                    camera_id: [
                        f"{width}x{height}"
                        for width, height in contract["jpeg"]
                    ]
                    for camera_id, contract in contracts.items()
                },
                "minFrameDurationNs": 33333333,
            },
            separators=(",", ":"),
        )
    )
except Exception as error:
    print(json.dumps({"ok": False, "error": str(error)}, separators=(",", ":")))
    sys.exit(1)
PY
  then
    add camera_metadata true "$(cat /tmp/xenoid-smoke-camera-metadata-summary.out)"
  else
    add camera_metadata false "$(cat /tmp/xenoid-smoke-camera-metadata-summary.out)"
  fi
else
  add camera_metadata false "$(cat /tmp/xenoid-smoke-camera-metadata.out)"
fi
# Exercise the real provider through an ordinary-app Camera2 client. The daemon
# self-test uses generated fallback frames when no operator media is configured.
if "$XENOID_BIN" camera status --check >/tmp/xenoid-smoke-camera-session.out 2>&1; then
  if python3 - <<'PY' >/tmp/xenoid-smoke-camera-session-summary.out 2>&1
import json
import sys

result = json.load(open("/tmp/xenoid-smoke-camera-session.out"))
cameras = result.get("cameras")
if result.get("ok") is not True or result.get("state") != "success":
    raise ValueError("camera self-test did not succeed")
if not isinstance(cameras, dict) or set(cameras) != {"back", "front"}:
    raise ValueError("camera self-test did not cover both cameras")
required = (
    "captureCompleted",
    "jpegNonempty",
    "timestampsMatched",
    "yuvNonempty",
)
for camera, evidence in cameras.items():
    if not isinstance(evidence, dict):
        raise ValueError(f"{camera} camera evidence is malformed")
    if any(evidence.get(key) is not True for key in required):
        raise ValueError(f"{camera} camera capture evidence is incomplete")
    if evidence.get("width") != 320 or evidence.get("height") != 240:
        raise ValueError(f"{camera} camera capture dimensions differ")
print(json.dumps({
    "ok": True,
    "state": "success",
    "cameras": {
        name: {key: value for key, value in evidence.items() if key != "facing"}
        for name, evidence in cameras.items()
    },
}, separators=(",", ":")))
PY
  then
    add camera_session true "$(cat /tmp/xenoid-smoke-camera-session-summary.out)"
  else
    add camera_session false "$(cat /tmp/xenoid-smoke-camera-session-summary.out)"
  fi
else
  add camera_session false "$(cat /tmp/xenoid-smoke-camera-session.out)"
fi

# Build and drive the public ordinary-app runtime probe without changing
# configured operator media. Configured replay coverage remains an explicit
# full-mode gate in scripts/ci.sh.
if ./scripts/smoke-camera-runtime.sh --quick \
    --out /tmp/xenoid-smoke-camera-runtime.json \
    >/tmp/xenoid-smoke-camera-runtime.out 2>&1; then
  add camera_runtime_probe true "$(cat /tmp/xenoid-smoke-camera-runtime.json)"
else
  add camera_runtime_probe false "$(cat /tmp/xenoid-smoke-camera-runtime.json 2>/dev/null || printf '%s' '{"ok":false,"error":"camera runtime probe failed"}')"
fi
# PackageManager must expose only hardware implemented by the active camera,
# sensor, and cellular HALs. Validate the installed contract as well as the
# merged feature set so a stale or inherited base-image declaration fails.
if "$ADB_BIN" -s "$ADB_TARGET" exec-out \
    cat /system/etc/permissions/xenoid-hardware-features.xml \
    >/tmp/xenoid-smoke-hardware-features.xml 2>/tmp/xenoid-smoke-hardware-features.err \
    && "$ADB_BIN" -s "$ADB_TARGET" shell pm list features \
    >/tmp/xenoid-smoke-package-features.out 2>&1 \
    && python3 ./scripts/smoke-hardware-features.py \
    --contract /tmp/xenoid-smoke-hardware-features.xml \
    --pm-features /tmp/xenoid-smoke-package-features.out \
    >/tmp/xenoid-smoke-hardware-features-summary.out 2>&1; then
  add hardware_features true "$(cat /tmp/xenoid-smoke-hardware-features-summary.out)"
else
  add hardware_features false "$(cat /tmp/xenoid-smoke-hardware-features-summary.out 2>/dev/null || cat /tmp/xenoid-smoke-hardware-features.err 2>/dev/null || cat /tmp/xenoid-smoke-package-features.out 2>/dev/null)"
fi



# Apply native overlays/hide helpers if they are deployed; these commands are idempotent.
# These need uid=0 (bind mounts + /dev/__properties__ patches), so route through the root channel.
as_root 'test -x /system/bin/xenoid-overlay-helper && /system/bin/xenoid-overlay-helper apply >/data/local/tmp/xenoid-overlay-smoke.log 2>&1 || true; test -x /data/local/tmp/xenoid-hide-helper && /data/local/tmp/xenoid-hide-helper apply >/data/local/tmp/xenoid-hide-apply-smoke.log 2>&1 || true; PROP=$( { test -x /system/bin/xenoid-prop-area && echo /system/bin/xenoid-prop-area; } || { test -x /data/local/tmp/xenoid-prop-area && echo /data/local/tmp/xenoid-prop-area; } ) && "$PROP" --identity >/data/local/tmp/xenoid-prop-area-smoke.log 2>&1 || true' >/dev/null 2>&1 || true

# Native hide status: su/zygisk file surfaces must be clean after apply (zygisk!=SELinux attr/prev).
if as_root 'test -x /data/local/tmp/xenoid-hide-helper && /data/local/tmp/xenoid-hide-helper status' >/tmp/xenoid-smoke-hide-files.out 2>&1; then
  if python3 - <<'PY' >/tmp/xenoid-smoke-hide-files-summary.out 2>&1
import json,re,sys
raw=open("/tmp/xenoid-smoke-hide-files.out").read().strip()
try: j=json.loads(raw)
except Exception: j=None
for _ in range(3):
    if not isinstance(j,dict) or "files" in j or not isinstance(j.get("stdout"),str):
        break
    try: j=json.loads(j["stdout"])
    except Exception: break
if not isinstance(j,dict) or "files" not in j:
    m=re.search(r"\{.*\}", raw, re.S)
    j=json.loads(m.group(0)) if m else {}
files=j.get("files") or {}
procs=j.get("processes") or {}
ok=(files.get("su_system_xbin") is False and files.get("su_system_bin") is False
    and files.get("zygisk") is False and files.get("magisk_tmp") is False
    and procs.get("zygisk") is False)
print(json.dumps({"ok":ok,"files":files,"processes":procs}, separators=(",",":")))
sys.exit(0 if ok else 1)
PY
  then add hide_root_surfaces true "$(cat /tmp/xenoid-smoke-hide-files-summary.out)"; else add hide_root_surfaces false "$(cat /tmp/xenoid-smoke-hide-files-summary.out 2>/dev/null || cat /tmp/xenoid-smoke-hide-files.out)"; fi
else add hide_root_surfaces false "$(cat /tmp/xenoid-smoke-hide-files.out)"; fi


if "$ADB_BIN" -s "$ADB_TARGET" shell 'test -x /system/bin/xenoid-netctl && /system/bin/xenoid-netctl status rmnet_data0' >/tmp/xenoid-smoke-netctl.out 2>&1; then
  netctl_summary=$(python3 - <<'PY2'
import json
try:
    j=json.load(open('/tmp/xenoid-smoke-netctl.out'))
    print(json.dumps({'ioctl':j.get('ioctl'),'netlink':j.get('netlink'),'consistent':j.get('ioctl')==j.get('netlink') and bool(j.get('netlink'))}, separators=(',',':')))
except Exception as e:
    print(json.dumps({'error':str(e)}, separators=(',',':')))
PY2
)
  if python3 -c 'import json,sys; j=json.loads(sys.argv[1]); sys.exit(0 if j.get("consistent") else 1)' "$netctl_summary"; then add netctl_identity true "$netctl_summary"; else add netctl_identity false "$netctl_summary"; fi
else
  add netctl_identity false "$(cat /tmp/xenoid-smoke-netctl.out)"
fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'if [ -e /proc/net/dev ]; then grep -q "rmnet_data0:" /proc/net/dev && ! grep -q "eth0:" /proc/net/dev && grep -q "rmnet_data0" /proc/net/route && { [ ! -e /sys/class/net/rmnet_data0/mtu ] || test "$(cat /sys/class/net/rmnet_data0/mtu 2>/dev/null)" = 1500; } && { [ ! -e /sys/class/net/rmnet_data0/operstate ] || test "$(cat /sys/class/net/rmnet_data0/operstate 2>/dev/null)" = up; } && { [ ! -e /sys/class/net/rmnet_data0/addr_assign_type ] || test "$(cat /sys/class/net/rmnet_data0/addr_assign_type 2>/dev/null)" = 3; }; else exit 77; fi' >/tmp/xenoid-smoke-network-overlay.out 2>&1; then add network_overlay true "rmnet_data0 is the only data interface across procfs and sysfs"; else rc=$?; if [ "$rc" = 77 ]; then add network_overlay true "no /proc/net/dev on this runtime; skip"; else add network_overlay false "$(cat /tmp/xenoid-smoke-network-overlay.out)"; fi; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'ip rule show | grep -Eq "^999:.*to .*lookup main[[:space:]]*$" && ip -6 rule show | grep -Eq "^999:.*to .*lookup main[[:space:]]*$"' >/tmp/xenoid-smoke-cellular-control-routes.out 2>&1; then add cellular_control_routes true "IPv4/IPv6 connected-prefix rules preserve host control before netd ownership"; else add cellular_control_routes false "$(cat /tmp/xenoid-smoke-cellular-control-routes.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'bad="frida|xenoid|magisk|zygisk|lsposed|riru|27042|15B3|69A2|69A3"; ! grep -Eiq "$bad" /proc/net/unix /proc/net/udp /proc/net/udp6 /proc/net/raw /proc/net/raw6 2>/dev/null' >/tmp/xenoid-smoke-proc-net.out 2>&1; then add proc_net_tables true "unix/udp/raw tables sanitized"; else add proc_net_tables false "$(cat /tmp/xenoid-smoke-proc-net.out)"; fi

if ./scripts/smoke-prop-files.sh >/tmp/xenoid-smoke-prop-files.out 2>&1; then add prop_files true "$(cat /tmp/xenoid-smoke-prop-files.out)"; else add prop_files false "$(cat /tmp/xenoid-smoke-prop-files.out)"; fi

# Summarize missing or duplicate overlay targets.
if as_root 'test -x /system/bin/xenoid-overlay-helper && /system/bin/xenoid-overlay-helper status-json' >/tmp/xenoid-smoke-overlay-status.out 2>&1; then
  overlay_summary=$(python3 - <<'PY2'
import json
try:
    j=json.load(open('/tmp/xenoid-smoke-overlay-status.out'))
    for _ in range(3):
        if not isinstance(j, dict) or not isinstance(j.get('stdout'), str):
            break
        j=json.loads(j['stdout'])
    targets=j.get('targets',[])
    missing=[t['target'] for t in targets if t.get('expected') and not t.get('overlay')]
    dup=[t['target'] for t in targets if t.get('mountCount',0)>1]
    print(json.dumps({'ok':bool(j.get('ok')),'expected':j.get('expectedCount',0),'active':j.get('activeCount',0),'missing':missing[:10],'duplicates':dup[:10]}, separators=(',',':')))
except Exception as e:
    print(json.dumps({'error':str(e)}, separators=(',',':')))
PY2
)
  if python3 -c 'import json,sys; j=json.loads(sys.argv[1]); sys.exit(0 if j.get("ok") and not j.get("missing") and not j.get("duplicates") else 1)' "$overlay_summary"; then add overlay_status true "$overlay_summary"; else add overlay_status false "$overlay_summary"; fi
else
  add overlay_status false "$(cat /tmp/xenoid-smoke-overlay-status.out)"
fi

# App-visible adb.tcp.port=-1 comes from the shim only; the global property must stay usable for host TCP adb.
if "$ADB_BIN" -s "$ADB_TARGET" shell 'test "$(getprop ro.debuggable)" = 0 && test "$(getprop ro.adb.secure)" = 1 && { test -z "$(getprop init.svc.adbd)" || test "$(getprop init.svc.adbd)" = stopped; } && LD_PRELOAD=/data/local/tmp/.ld/core.so getprop service.adb.tcp.port | grep -qx -- -1' >/tmp/xenoid-smoke-adb-hide.out 2>&1; then add adb_debug_hidden true "ro.debuggable=$("$ADB_BIN" -s "$ADB_TARGET" shell getprop ro.debuggable 2>/dev/null), ro.adb.secure=$("$ADB_BIN" -s "$ADB_TARGET" shell getprop ro.adb.secure 2>/dev/null), app service.adb.tcp.port=$("$ADB_BIN" -s "$ADB_TARGET" shell 'LD_PRELOAD=/data/local/tmp/.ld/core.so getprop service.adb.tcp.port' 2>/dev/null), global service.adb.tcp.port=$("$ADB_BIN" -s "$ADB_TARGET" shell getprop service.adb.tcp.port 2>/dev/null), init.svc.adbd=$("$ADB_BIN" -s "$ADB_TARGET" shell getprop init.svc.adbd 2>/dev/null)"; else add adb_debug_hidden false "$(cat /tmp/xenoid-smoke-adb-hide.out)"; fi

# Raven hardware identity is present before graphics and framework startup.
if "$ADB_BIN" -s "$ADB_TARGET" shell 'test "$(getprop ro.boot.verifiedbootstate)" = green && test "$(getprop ro.boot.flash.locked)" = 1 && test "$(getprop ro.boot.vbmeta.device_state)" = locked && test "$(getprop ro.boot.veritymode)" = enforcing && test "$(getprop ro.boot.hardware)" = raven && test "$(getprop ro.boot.hardware.sku)" = G8V0U && test "$(getprop ro.boot.bootreason)" = reboot,normal && test "$(getprop ro.bootmode)" = normal' >/tmp/xenoid-smoke-boot-verified.out 2>&1; then add boot_verified_state true "verifiedbootstate=green flash.locked=1 vbmeta=locked verity=enforcing hardware=raven sku=G8V0U bootreason=reboot,normal bootmode=normal"; else add boot_verified_state false "$(cat /tmp/xenoid-smoke-boot-verified.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'test "$(LD_PRELOAD=/data/local/tmp/.ld/core.so getprop ro.hardware)" = raven && test "$(getprop ro.product.device)" = raven && test "$(getprop ro.product.model)" = "Pixel 6 Pro"' >/tmp/xenoid-smoke-hardware-identity.out 2>&1; then add hardware_identity true "app ro.hardware=raven (global=$("$ADB_BIN" -s "$ADB_TARGET" shell getprop ro.hardware 2>/dev/null)) device=raven model=Pixel 6 Pro"; else add hardware_identity false "$(cat /tmp/xenoid-smoke-hardware-identity.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'test ! -e /system/xbin/su && test ! -e /system/bin/su && ! ls /data/local/tmp/libxenoid_*.so >/dev/null 2>&1' >/tmp/xenoid-smoke-leak-surfaces.out 2>&1; then add hide_leak_surfaces true "su paths and retired top-level libraries absent"; else add hide_leak_surfaces false "$(cat /tmp/xenoid-smoke-leak-surfaces.out)"; fi

if "$ADB_BIN" -s "$ADB_TARGET" shell 'test "$(getprop ro.oem_unlock_supported)" = 1 && test "$(getprop sys.oem_unlock_allowed)" = 0 && test "$(getprop ro.boot.warranty_bit)" = 0 && test "$(getprop ro.warranty_bit)" = 0 && test "$(getprop ro.build.version.security_patch)" = 2022-10-05 && test "$(getprop ro.vendor.build.security_patch)" = 2022-10-05' >/tmp/xenoid-smoke-oem.out 2>&1; then add oem_unlock_attestation_props true "oem_unlock_supported=1 oem_unlock_allowed=0 warranty=0 security_patch=2022-10-05"; else add oem_unlock_attestation_props false "$(cat /tmp/xenoid-smoke-oem.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'if [ -e /sys/fs/selinux/enforce ]; then test "$(cat /sys/fs/selinux/enforce 2>/dev/null)" = 1 && test "$(cat /sys/fs/selinux/policyvers 2>/dev/null)" = 33 && test "$(cat /sys/fs/selinux/class/process/index 2>/dev/null)" = 51 && test "$(cat /sys/fs/selinux/class/security/index 2>/dev/null)" = 58 && test ! -e /sys/fs/selinux/class/index/process && printf "%s" "u:r:app_zygote:s0" > /sys/fs/selinux/context && ! printf "%s" "u:r:adbroot:s0" > /sys/fs/selinux/context; else exit 77; fi' >/tmp/xenoid-smoke-selinux.out 2>&1; then add selinuxfs true "enforce=1 policyvers=33 class indices at stock paths and context controls agree"; else rc=$?; if [ "$rc" = 77 ]; then add selinuxfs true "no /sys/fs/selinux on this runtime; skip"; else add selinuxfs false "$(cat /tmp/xenoid-smoke-selinux.out)"; fi; fi

if "$ADB_BIN" -s "$ADB_TARGET" shell '! grep -q :15B3 /proc/net/tcp /proc/net/tcp6 2>/dev/null' >/tmp/xenoid-smoke-proc-5555.out 2>&1; then add proc_tcp_5555_hidden true "no :15B3"; else add proc_tcp_5555_hidden false "$(cat /tmp/xenoid-smoke-proc-5555.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'if [ -e /proc/sys/kernel/random/entropy_avail ]; then test "$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null)" = 4096 && test "$(cat /proc/sys/kernel/random/poolsize 2>/dev/null)" = 4096 && test "$(cat /proc/sys/kernel/random/urandom_min_reseed_secs 2>/dev/null)" = 60; else exit 77; fi' >/tmp/xenoid-smoke-random-sysctl.out 2>&1; then add random_sysctls true "random entropy/pool/reseed sanitized"; else rc=$?; if [ "$rc" = 77 ]; then add random_sysctls true "no random sysctl files on this runtime; skip"; else add random_sysctls false "$(cat /tmp/xenoid-smoke-random-sysctl.out)"; fi; fi

if "$ADB_BIN" -s "$ADB_TARGET" shell '! grep -Eiq "AuthenticAMD|EPYC|x86_64|hypervisor" /proc/cpuinfo && ! grep -Eiq "Ubuntu|generic|x86_64" /proc/version && ! grep -Eiq "BOOT_IMAGE|UUID|vmlinuz" /proc/cmdline' >/tmp/xenoid-smoke-proc-identity.out 2>&1; then add proc_identity_overlay true "cpuinfo/version/cmdline sanitized"; else add proc_identity_overlay false "$(cat /tmp/xenoid-smoke-proc-identity.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'bad="virtio|xen|vbox|vmw|kvm|qemu|openstack|hypervisor"; ! grep -Eiq "$bad" /proc/modules /proc/interrupts /proc/iomem /proc/ioports 2>/dev/null && { [ ! -e /sys/class/dmi/id/product_name ] || ! grep -Eiq "$bad" /sys/class/dmi/id/product_name /sys/class/dmi/id/sys_vendor 2>/dev/null; } && { [ ! -e /sys/hypervisor/type ] || ! grep -Eiq ".+" /sys/hypervisor/type 2>/dev/null; }' >/tmp/xenoid-smoke-virtualization.out 2>&1; then add virtualization_overlay true "proc modules/interrupts/iomem/ioports and dmi/hypervisor sanitized"; else add virtualization_overlay false "$(cat /tmp/xenoid-smoke-virtualization.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'bad="virtio|xen|vbox|vmw|kvm|qemu|openstack|hypervisor"; if [ -e /proc/device-tree/model ]; then grep -Eiq "pixel|google|raven" /proc/device-tree/model && ! grep -Eiq "$bad" /proc/device-tree/model /proc/device-tree/compatible 2>/dev/null; elif [ -e /sys/firmware/devicetree/base/model ]; then grep -Eiq "pixel|google|raven" /sys/firmware/devicetree/base/model && ! grep -Eiq "$bad" /sys/firmware/devicetree/base/model /sys/firmware/devicetree/base/compatible 2>/dev/null; else exit 77; fi' >/tmp/xenoid-smoke-devicetree.out 2>&1; then add devicetree true "device-tree identity sanitized"; else rc=$?; if [ "$rc" = 77 ]; then add devicetree true "no device-tree sysfs/proc on this runtime; skip"; else add devicetree false "$(cat /tmp/xenoid-smoke-devicetree.out)"; fi; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'bad="ksu|kernelsu|apatch|magisk|frida|virtio|xen|vbox|vmw|qemu|kvm"; ! grep -Eiq "$bad" /proc/kallsyms /sys/kernel/debug/tracing/kprobe_events /sys/kernel/debug/tracing/uprobe_events /sys/kernel/tracing/kprobe_events /sys/kernel/tracing/uprobe_events 2>/dev/null' >/tmp/xenoid-smoke-kallsyms-tracing.out 2>&1; then add kallsyms_tracing true "kallsyms/tracing sanitized"; else add kallsyms_tracing false "$(cat /tmp/xenoid-smoke-kallsyms-tracing.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'bad="virtio|qemu|vbox|xen|vmw|hvc|xvc"; ! grep -Eiq "$bad" /proc/devices /proc/misc /proc/tty/drivers /proc/driver/rtc 2>/dev/null && grep -q binder /proc/devices 2>/dev/null && grep -q ashmem /proc/misc 2>/dev/null' >/tmp/xenoid-smoke-kernel-devices.out 2>&1; then add kernel_device_tables true "proc devices/misc/tty/driver tables sanitized"; else add kernel_device_tables false "$(cat /tmp/xenoid-smoke-kernel-devices.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'if [ -e /sys/class/rtc/rtc0/name ]; then test "$(cat /sys/class/rtc/rtc0/name 2>/dev/null)" = rtc-pm8xxx && test "$(cat /sys/class/rtc/rtc0/hctosys 2>/dev/null)" = 1 && test "$(cat /sys/class/rtc/rtc0/since_epoch 2>/dev/null)" = 1715040000; else exit 77; fi' >/tmp/xenoid-smoke-rtc.out 2>&1; then add rtc_sysfs true "rtc0 sysfs sanitized"; else rc=$?; if [ "$rc" = 77 ]; then add rtc_sysfs true "no /sys/class/rtc/rtc0 on this runtime; skip"; else add rtc_sysfs false "$(cat /tmp/xenoid-smoke-rtc.out)"; fi; fi

if "$ADB_BIN" -s "$ADB_TARGET" shell 'test "$(awk "/MemTotal/ {print \$2}" /proc/meminfo)" = 12582912 && test "$(cat /sys/devices/system/cpu/online)" = "0-7"' >/tmp/xenoid-smoke-resource-overlay.out 2>&1; then add resource_overlay true "memory=12582912 KiB, cpu online=0-7"; else add resource_overlay false "$(cat /tmp/xenoid-smoke-resource-overlay.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'grep -q "nr_free_pages" /proc/vmstat 2>/dev/null && grep -q "Node 0, zone" /proc/zoneinfo 2>/dev/null && grep -q "Node 0" /proc/buddyinfo 2>/dev/null && ! grep -q "Node 1" /proc/zoneinfo /proc/buddyinfo /proc/pagetypeinfo 2>/dev/null' >/tmp/xenoid-smoke-memory-proc.out 2>&1; then add memory_proc_details true "vmstat/zoneinfo/buddyinfo single-node sanitized"; else add memory_proc_details false "$(cat /tmp/xenoid-smoke-memory-proc.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'test "$(grep -E "^cpu[0-9]+ " /proc/stat 2>/dev/null | wc -l | tr -d " ")" = 8 && grep -q "CPU7" /proc/softirqs 2>/dev/null && ! grep -q "CPU8" /proc/softirqs /proc/schedstat 2>/dev/null' >/tmp/xenoid-smoke-cpu-proc-stats.out 2>&1; then add cpu_proc_stats true "proc/stat softirqs schedstat expose 8 CPUs"; else add cpu_proc_stats false "$(cat /tmp/xenoid-smoke-cpu-proc-stats.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'test "$(cat /proc/sys/kernel/ostype 2>/dev/null)" = Linux && grep -q android13 /proc/sys/kernel/osrelease 2>/dev/null && ! grep -Eiq "overlay|docker|container|ubuntu|generic|x86_64|epyc" /proc/filesystems /proc/swaps /proc/sys/kernel/osrelease /proc/sys/kernel/version 2>/dev/null' >/tmp/xenoid-smoke-kernel-proc.out 2>&1; then add kernel_proc_misc true "kernel proc/sysctl misc sanitized"; else add kernel_proc_misc false "$(cat /tmp/xenoid-smoke-kernel-proc.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'test "$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)" = 2 && test "$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)" = 1 && test "$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)" = 3' >/tmp/xenoid-smoke-kernel-hardening.out 2>&1; then add kernel_hardening true "kptr/dmesg/perf hardened"; else add kernel_hardening false "$(cat /tmp/xenoid-smoke-kernel-hardening.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'dev="$(cat /sys/block/sda/dev 2>/dev/null)" && test "$(grep -E "[[:space:]]sda$" /proc/partitions | tr -s " " | cut -d" " -f4)" = 125000000 && grep -Eq "[[:space:]]sda[[:space:]]" /proc/diskstats && test -b /dev/block/sda && test -L /dev/block/platform/14700000.ufs/by-name/userdata && test "$(readlink /dev/block/platform/14700000.ufs/by-name/userdata)" = ../../../sda && test -b /dev/block/platform/14700000.ufs/by-name/userdata && test -L /sys/block/sda && test "$(readlink /sys/block/sda)" = ../devices/virtual/block/sda && test -L /sys/class/block/sda && test "$(readlink /sys/class/block/sda)" = ../../devices/virtual/block/sda && test -n "$dev" && test -L "/sys/dev/block/$dev" && test "$(cat /sys/block/sda/size 2>/dev/null)" = 250000000 && test "$(cat /sys/block/sda/queue/logical_block_size 2>/dev/null)" = 512 && test "$(cat /sys/block/sda/queue/rotational 2>/dev/null)" = 0 && set -- /sys/block/* && test "$#" = 1 && test "${1##*/}" = sda' >/tmp/xenoid-smoke-storage-surfaces.out 2>&1; then add storage_surfaces true "proc/dev/sysfs expose one coherent 128000000000-byte non-rotational Raven userdata contract"; else add storage_surfaces false "$(cat /tmp/xenoid-smoke-storage-surfaces.out)"; fi
# Mount namespace: two views. (a) Global fixed-path view via /proc/1/* (bind-mount overlay works there).
# (b) App-process view via shim-injected reader (LD_PRELOAD) — what a hooked app sees.
# Plain-shell /proc/mounts and /proc/self/* are per-reader-resolved and need the P2 kernel module; tracked as known gap.
if "$ADB_BIN" -s "$ADB_TARGET" shell 'bad="docker|containerd|overlayfs|upperdir|lowerdir|workdir|/var/lib|xenoid|colima|lxc"; ! grep -Eiq "$bad" /proc/1/cgroup /proc/1/mounts /proc/1/mountinfo /proc/1/mountstats /proc/cgroups 2>/dev/null && grep -q "/system" /proc/1/mountinfo 2>/dev/null && grep -qE " - f2fs /dev/block/platform/14700000[.]ufs/by-name/userdata " /proc/1/mountinfo 2>/dev/null && grep -q "mounted on /data with fstype f2fs" /proc/1/mountstats 2>/dev/null && grep -q "cpuset" /proc/cgroups 2>/dev/null' >/tmp/xenoid-smoke-mount-ns.out 2>&1; then
  if "$ADB_BIN" -s "$ADB_TARGET" shell 'bad="docker|containerd|overlayfs|upperdir|lowerdir|workdir|/var/lib|xenoid|colima|lxc"; ! XENOID_TEST_FORCE_APP_UID=1 LD_PRELOAD=/data/local/tmp/.ld/core.so grep -Eiq "$bad" /proc/self/cgroup /proc/self/mounts /proc/self/mountinfo /proc/self/mountstats 2>/dev/null && XENOID_TEST_FORCE_APP_UID=1 LD_PRELOAD=/data/local/tmp/.ld/core.so grep -qE " /data f2fs | - f2fs /dev/block/platform/14700000[.]ufs/by-name/userdata " /proc/self/mounts /proc/self/mountinfo 2>/dev/null'; then add mount_namespace true "global(pid1) and app-process(shim) mount views expose Raven f2fs; raw mountinfo remains kernel-owned"; else add mount_namespace false "shim view dirty: $(cat /tmp/xenoid-smoke-mount-ns.out)"; fi
else add mount_namespace false "pid1 view dirty: $(cat /tmp/xenoid-smoke-mount-ns.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'grep -q "TracerPid:[[:space:]]*0" /proc/1/status && grep -q "NSpid:[[:space:]]*1" /proc/1/status && grep -q "Cpus_allowed_list:[[:space:]]*0-7" /proc/1/status && grep -q "0[[:space:]]*0[[:space:]]*4294967295" /proc/1/uid_map && grep -q "u:r:init:s0" /proc/1/attr/current 2>/dev/null' >/tmp/xenoid-smoke-proc-identity-tables.out 2>&1; then
  if "$ADB_BIN" -s "$ADB_TARGET" shell 'LD_PRELOAD=/data/local/tmp/.ld/core.so grep -q "TracerPid:[[:space:]]*0" /proc/self/status 2>/dev/null && LD_PRELOAD=/data/local/tmp/.ld/core.so grep -q "Cpus_allowed_list:[[:space:]]*0-7" /proc/self/status 2>/dev/null' >>/tmp/xenoid-smoke-proc-identity-tables.out 2>&1; then add proc_identity_tables true "proc status/id-map/attr sanitized (pid1 global + shim app view)"; else add proc_identity_tables false "shim app view mismatch: $(cat /tmp/xenoid-smoke-proc-identity-tables.out)"; fi
else add proc_identity_tables false "pid1 view mismatch: $(cat /tmp/xenoid-smoke-proc-identity-tables.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'if [ -e /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq ]; then test "$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null)" = 2995000 && test "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null)" = schedutil; else exit 77; fi; if [ -e /sys/devices/system/cpu/cpu0/topology/core_id ]; then test "$(cat /sys/devices/system/cpu/cpu0/topology/core_id 2>/dev/null)" = 0; fi' >/tmp/xenoid-smoke-cpu-sysfs.out 2>&1; then add cpu_sysfs true "cpu0 cpufreq/topology sanitized"; else rc=$?; if [ "$rc" = 77 ]; then add cpu_sysfs true "no cpu0 cpufreq on this runtime; skip"; else add cpu_sysfs false "$(cat /tmp/xenoid-smoke-cpu-sysfs.out)"; fi; fi

# Battery service shaping smoke: reapply the complete canonical profile so
# capacity-dependent fields remain coherent across the HAL and sysfs views.
"$XENOID_BIN" device apply examples/fingerprints/pixel-raven-android13.json --keep-unique >/tmp/xenoid-smoke-battery-profile.out 2>&1 || true
./xenoid root exec 'stop vendor.health-default >/dev/null 2>&1 || true; sleep 1; start vendor.health-default >/dev/null 2>&1 || true; sleep 1; dumpsys battery reset >/dev/null 2>&1 || true' >/tmp/xenoid-smoke-battery-health.out 2>&1 || true
if "$ADB_BIN" -s "$ADB_TARGET" shell 'dumpsys battery | grep -q "status: 3" && dumpsys battery | grep -q "present: true" && dumpsys battery | grep -q "level: 83" && dumpsys battery | grep -q "voltage: 4100" && dumpsys battery | grep -q "temperature: 310" && dumpsys battery | grep -q "technology: Li-ion"' >/tmp/xenoid-smoke-battery.out 2>&1; then add battery_service true "status=3 present=true level=83 voltage=4100 temperature=310 technology=Li-ion"; else add battery_service false "$(cat /tmp/xenoid-smoke-battery.out)"; fi
if "$ADB_BIN" -s "$ADB_TARGET" shell 'if [ -e /sys/class/power_supply/battery/capacity ]; then test "$(cat /sys/class/power_supply/battery/capacity 2>/dev/null)" = 83 && test "$(cat /sys/class/power_supply/battery/temp 2>/dev/null)" = 310 && test "$(cat /sys/class/power_supply/battery/voltage_now 2>/dev/null)" = 4100000 && test "$(cat /sys/class/power_supply/battery/charge_full_design 2>/dev/null)" = 5003000 && test "$(cat /sys/class/power_supply/battery/charge_full 2>/dev/null)" = 5003000 && test "$(cat /sys/class/power_supply/battery/charge_counter 2>/dev/null)" = 4152490; else exit 77; fi' >/tmp/xenoid-smoke-battery-sysfs.out 2>&1; then add battery_sysfs true "capacity=83 temp=310 voltage_now=4100000 charge_full=5003000 charge_counter=4152490"; else rc=$?; if [ "$rc" = 77 ]; then add battery_sysfs true "no /sys/class/power_supply/battery on this runtime; skip"; else add battery_sysfs false "$(cat /tmp/xenoid-smoke-battery-sysfs.out)"; fi; fi
"$XENOID_BIN" device set thermal.zone0.temp 32000 >/tmp/xenoid-smoke-thermal-temp.out 2>&1 || true
"$XENOID_BIN" device set thermal.zone0.type skin >/tmp/xenoid-smoke-thermal-type.out 2>&1 || true
if "$ADB_BIN" -s "$ADB_TARGET" shell 'if [ -e /sys/class/thermal/thermal_zone0/temp ]; then test "$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null)" = 32000 && test "$(cat /sys/class/thermal/thermal_zone0/type 2>/dev/null)" = skin; else exit 77; fi' >/tmp/xenoid-smoke-thermal-sysfs.out 2>&1; then add thermal_sysfs true "thermal_zone0 temp=32000 type=skin"; else rc=$?; if [ "$rc" = 77 ]; then add thermal_sysfs true "no /sys/class/thermal/thermal_zone0 on this runtime; skip"; else add thermal_sysfs false "$(cat /tmp/xenoid-smoke-thermal-sysfs.out)"; fi; fi
"$XENOID_BIN" device set input.name sec_touchscreen >/tmp/xenoid-smoke-input-name.out 2>&1 || true
if "$ADB_BIN" -s "$ADB_TARGET" shell 'if [ -e /proc/bus/input/devices ]; then grep -q "sec_touchscreen" /proc/bus/input/devices && grep -q "gpio-keys" /proc/bus/input/devices && ! grep -Eiq "xenoid|frida|minitouch|uinput" /proc/bus/input/devices; else exit 77; fi' >/tmp/xenoid-smoke-input-devices.out 2>&1; then add input_devices_proc true "sec_touchscreen and gpio-keys present; no xenoid/frida/minitouch/uinput"; else rc=$?; if [ "$rc" = 77 ]; then add input_devices_proc true "no /proc/bus/input/devices on this runtime; skip"; else add input_devices_proc false "$(cat /tmp/xenoid-smoke-input-devices.out)"; fi; fi
"$XENOID_BIN" device apply examples/fingerprints/pixel-raven-android13.json --keep-unique >/tmp/xenoid-smoke-display-profile.out 2>&1 || true
if "$ADB_BIN" -s "$ADB_TARGET" shell 'wm size | grep -q "1440x3120" && wm density | grep -q "560" && if [ -e /proc/fb ]; then grep -q "msmfb" /proc/fb; else exit 77; fi; if [ -e /sys/class/graphics/fb0/virtual_size ]; then test "$(cat /sys/class/graphics/fb0/virtual_size 2>/dev/null)" = "1440,3120" && grep -q "1440x3120p-60" /sys/class/graphics/fb0/modes && grep -q "1440x3120p-120" /sys/class/graphics/fb0/modes; fi' >/tmp/xenoid-smoke-framebuffer.out 2>&1; then add framebuffer_sysfs true "wm/fb0 converge at 1440x3120/560 with 60/120 Hz modes"; else rc=$?; if [ "$rc" = 77 ]; then add framebuffer_sysfs true "no /proc/fb on this runtime; wm profile verified"; else add framebuffer_sysfs false "$(cat /tmp/xenoid-smoke-framebuffer.out)"; fi; fi
"$XENOID_BIN" device set serial 3A4940E5EDFA >/tmp/xenoid-smoke-usb-serial.out 2>&1 || true
if "$ADB_BIN" -s "$ADB_TARGET" shell 'p=/config/usb_gadget/g1/strings/0x409/serialnumber; if [ -e "$p" ]; then test "$(cat "$p" 2>/dev/null)" = 3A4940E5EDFA && test "$(cat /config/usb_gadget/g1/strings/0x409/manufacturer 2>/dev/null)" = Google && grep -q "Pixel" /config/usb_gadget/g1/strings/0x409/product 2>/dev/null; else exit 77; fi' >/tmp/xenoid-smoke-usb.out 2>&1; then add usb_identity true "usb gadget serial/manufacturer/product sanitized"; else rc=$?; if [ "$rc" = 77 ]; then add usb_identity true "no usb gadget configfs on this runtime; skip"; else add usb_identity false "$(cat /tmp/xenoid-smoke-usb.out)"; fi; fi

# The profile helper updates the device-wide secure android_id without rewriting
# Android's app-scoped SSAIDs. Both files require uid=0 access.
if as_root 'test -x /data/local/tmp/xenoid-ssaid && before=$(sha256sum /data/system/users/0/settings_ssaid.xml | cut -c 1-64) && /data/local/tmp/xenoid-ssaid 1234567890abcdef >/data/local/tmp/xenoid-ssaid-smoke.log 2>&1 && after=$(sha256sum /data/system/users/0/settings_ssaid.xml | cut -c 1-64) && test "$before" = "$after" && strings /data/system/users/0/settings_secure.xml 2>/dev/null | grep -q 1234567890abcdef' >/tmp/xenoid-smoke-ssaid.out 2>&1; then add ssaid_file true "settings_ssaid.xml preserved; settings_secure.xml contains 1234567890abcdef"; else add ssaid_file false "$(cat /tmp/xenoid-smoke-ssaid.out)"; fi

# Live Frida injection is opt-in because production `up` deliberately removes
# frida-server and payloads. Static hook surfaces remain mandatory in full doctor.
if [[ "${XENOID_SMOKE_REQUIRE_FRIDA:-0}" == 1 ]]; then
  "$ADB_BIN" -s "$ADB_TARGET" shell am force-stop dev.xenoid.daemon 2>/dev/null || true
  FRIDA_LOAD="$(./xenoid frida load-script dev.xenoid.daemon frida/scripts/xenoid-default.js --spawn --oneshot 2>&1 || true)"
  if printf '%s' "$FRIDA_LOAD" | grep -q '"hooksProven": *true'; then add frida_script_load true "xenoid-default.js hooks hit in spawned dev.xenoid.daemon (oneshot)"; else add frida_script_load false "$(printf '%s' "$FRIDA_LOAD" | tail -2)"; fi
  for _ in 1 2 3 4 5 6 7 8 9 10; do ./xenoid daemon health >/dev/null 2>&1 && break; sleep 1; done
else
  add frida_script_load true "skipped; production state requires Frida absent"
fi

# eBPF attach smoke: proves the system-layer hook is attached on the engine host.
EBPF_STATUS="$(./xenoid ebpf status 2>&1 || true)"
if printf '%s' "$EBPF_STATUS" | grep -q '"loaded":true\|"loaded": true'; then add ebpf_attach true "$(printf '%s' "$EBPF_STATUS" | tail -1)"; else add ebpf_attach false "$(printf '%s' "$EBPF_STATUS" | tail -2)"; fi


# Native shim/linker/libc surface smoke.
if ./scripts/smoke-native-surfaces.sh >/tmp/xenoid-smoke-native-surfaces.out 2>&1; then add native_surfaces true "$(cat /tmp/xenoid-smoke-native-surfaces.out)"; else add native_surfaces false "$(cat /tmp/xenoid-smoke-native-surfaces.out)"; fi
if ./scripts/smoke-filesystem-runtime.sh >/tmp/xenoid-smoke-filesystem-runtime.out 2>&1; then
  add filesystem_raw_statfs true "$(cat /tmp/xenoid-smoke-filesystem-runtime.out)"
else
  add filesystem_raw_statfs false "$(cat /tmp/xenoid-smoke-filesystem-runtime.out)"
fi

# Package denylist smoke: use a harmless debug package if present.
if "$ADB_BIN" -s "$ADB_TARGET" shell 'pm list packages dev.xenoid.sensorpatch >/dev/null 2>&1 && pm unhide --user 0 dev.xenoid.sensorpatch >/dev/null 2>&1 || true; pm list packages | grep -q dev.xenoid.sensorpatch' >/tmp/xenoid-smoke-pkg-pre.out 2>&1; then
  cat > /tmp/xenoid-hide-pkg-smoke.json <<'JSON'
{"schema":"dev.xenoid.hide/v1","packageDenylist":["dev.xenoid.sensorpatch"]}
JSON
  "$XENOID_BIN" hide apply /tmp/xenoid-hide-pkg-smoke.json >/tmp/xenoid-smoke-pkg-apply.out 2>&1 || true
  if "$ADB_BIN" -s "$ADB_TARGET" shell '! pm list packages | grep -q dev.xenoid.sensorpatch' >/tmp/xenoid-smoke-pkg-post.out 2>&1; then add package_denylist true "dev.xenoid.sensorpatch hidden"; else add package_denylist false "$(cat /tmp/xenoid-smoke-pkg-post.out)"; fi
  "$ADB_BIN" -s "$ADB_TARGET" shell 'pm unhide --user 0 dev.xenoid.sensorpatch >/dev/null 2>&1 || true' >/dev/null 2>&1 || true
else
  add package_denylist true "dev.xenoid.sensorpatch not installed; skip harmless package hide smoke"
fi
printf '{"ok":%s,"adbTarget":%s,"checks":[%s]}\n' "$OK" "$(printf '%s' "$ADB_TARGET"|json_quote)" "$(IFS=,; echo "${checks[*]}")" > "$OUT"
python3 - "$OUT" <<'PY'
import json, subprocess, sys
p=sys.argv[1]
data=json.load(open(p))
proc=subprocess.run(['python3','scripts/classify-runtime-failure.py',p],text=True,capture_output=True)
try: data['classification']=json.loads(proc.stdout)
except Exception: data['classification']={'ok':False,'category':'classification-error','stderr':proc.stderr}
open(p,'w').write(json.dumps(data,separators=(',',':'))+'\n')
print(json.dumps(data,separators=(',',':')))
PY
[[ "$OK" == true ]]
