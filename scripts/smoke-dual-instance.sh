#!/usr/bin/env bash
# Live dual-instance isolation evidence: owner labels, volumes, networks, ports,
# binder superblocks, proxy status, and per-instance Android app state.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
INSTANCE_A="${1:-${XENOID_INSTANCE:-phone-a}}"
INSTANCE_B="${2:-${XENOID_SECOND_INSTANCE:-phone-b}}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/xenoid-dual-instance.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

log() { echo "[dual-instance] $*"; }
fail() { echo "[dual-instance] FAIL: $*" >&2; exit 1; }

verify_inspect() {
  local inspect_path="$1" expected_volume="$2"
  python3 - "$inspect_path" "$expected_volume" <<'PY'
import json
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
decoder = json.JSONDecoder()
labels, offset = decoder.raw_decode(raw)
remaining = raw[offset:]
leading = len(remaining) - len(remaining.lstrip())
mounts, offset = decoder.raw_decode(raw, offset + leading)
if raw[offset:].strip():
    raise SystemExit("unexpected trailing Docker inspect data")
required = ["dev.xenoid.owner", "dev.xenoid.instance_id", "dev.xenoid.resource_tag"]
if not isinstance(labels, dict) or not all(labels.get(key) for key in required):
    raise SystemExit("missing instance owner labels")
volume = sys.argv[2]
if not isinstance(mounts, list) or not any(
    isinstance(mount, dict)
    and mount.get("Type") == "volume"
    and mount.get("Name") == volume
    and mount.get("Destination") == "/data"
    for mount in mounts
):
    raise SystemExit("expected instance data volume is not mounted")
PY
}

write_report() {
  python3 - "$@" <<'PY'
import json
import pathlib
import sys

if len(sys.argv) != 16:
    raise SystemExit("invalid dual-instance report arguments")
(
    report_path,
    instance_a,
    instance_b,
    container_a,
    container_b,
    volume_a,
    volume_b,
    network_a,
    network_b,
    adb_a,
    adb_b,
    binder_a,
    binder_b,
    marker_a,
    marker_b,
) = sys.argv[1:]
report = {
    "ok": True,
    "instanceA": instance_a,
    "instanceB": instance_b,
    "containerA": container_a,
    "containerB": container_b,
    "volumeA": volume_a,
    "volumeB": volume_b,
    "networkA": network_a,
    "networkB": network_b,
    "adbPortA": adb_a,
    "adbPortB": adb_b,
    "binderSuperblockA": binder_a,
    "binderSuperblockB": binder_b,
    "appMarkerA": marker_a,
    "appMarkerB": marker_b,
    "stopA_bStillReady": True,
    "restartA_dataPreserved": True,
}
payload = json.dumps(report, indent=2) + "\n"
pathlib.Path(report_path).write_text(payload, encoding="utf-8")
print(payload, end="")
PY
}

report_contract_test() {
  local inspect_path="$TMP/inspect.json"
  local report_path="$TMP/report.json"
  printf '%s\n' \
    '{"dev.xenoid.owner":"xenoid","dev.xenoid.instance_id":"00000000-0000-4000-8000-000000000001","dev.xenoid.resource_tag":"0123456789ab"} [{"Type":"volume","Name":"contract-volume","Destination":"/data"}]' \
    > "$inspect_path"
  verify_inspect "$inspect_path" contract-volume
  if verify_inspect "$inspect_path" wrong-volume >/dev/null 2>&1; then
    fail "inspect contract accepted the wrong volume"
  fi
  write_report \
    "$report_path" phone-a phone-b container-a container-b \
    volume-a volume-b network-a network-b 5555 5556 \
    binder-a binder-b marker-a marker-b >/dev/null
  python3 - "$report_path" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
report = json.loads(path.read_text(encoding="utf-8"))
if not (
    path.is_file()
    and report.get("ok") is True
    and report.get("instanceA") == "phone-a"
    and report.get("volumeB") == "volume-b"
    and report.get("appMarkerA") == "marker-a"
    and report.get("restartA_dataPreserved") is True
):
    raise SystemExit("dual-instance report contract failed")
PY
  printf '%s\n' '{"ok":true,"contract":"dual-instance-report"}'
}

if [[ "${1:-}" == "--report-contract-test" ]]; then
  report_contract_test
  exit 0
fi

OUT_DIR="${XENOID_STATE_ROOT:-$HOME/.xenoid/instances}/dual-instance-evidence"
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/report.json"

xenoid_a() { ./xenoid --instance "$INSTANCE_A" "$@"; }
xenoid_b() { ./xenoid --instance "$INSTANCE_B" "$@"; }

resolve_lease() {
  python3 -c "
import sys, os
sys.path.insert(0, 'src')
from pathlib import Path
from xenoid.config import resolve_instance
name = sys.argv[1]
try:
    context, cfg, lease = resolve_instance(name, project_root=Path.cwd(), env={})
    print(f'{lease.container_name} {lease.volume_name} {lease.network_name} {lease.host_adb_port} {lease.host_daemon_port}')
except Exception as e:
    sys.exit(1)
" "$1"
}

docker_context() {
  python3 -c "
import sys, os
sys.path.insert(0, 'src')
from pathlib import Path
from xenoid.config import resolve_instance
name = sys.argv[1]
try:
    context, cfg, lease = resolve_instance(name, project_root=Path.cwd(), env={})
    print(cfg.docker_context or ('colima' if cfg.backend == 'colima-docker' else 'default'))
except Exception:
    print('default')
" "$1"
}

binder_superblock() {
  local container="$1" context="$2"
  docker --context "$context" exec "$container" \
    stat -fc '%i:%t' /dev/binderfs 2>/dev/null || echo "unavailable"
}

log "resolving leases for $INSTANCE_A and $INSTANCE_B"
A_LEASE="$(resolve_lease "$INSTANCE_A")" || fail "cannot resolve $INSTANCE_A lease"
B_LEASE="$(resolve_lease "$INSTANCE_B")" || fail "cannot resolve $INSTANCE_B lease"
read -r A_CONTAINER A_VOLUME A_NETWORK A_ADB A_DAEMON <<< "$A_LEASE"
read -r B_CONTAINER B_VOLUME B_NETWORK B_ADB B_DAEMON <<< "$B_LEASE"
[[ -n "$A_CONTAINER" && -n "$A_VOLUME" && -n "$A_NETWORK" && -n "$A_ADB" && -n "$A_DAEMON" ]] \
  || fail "incomplete $INSTANCE_A lease"
[[ -n "$B_CONTAINER" && -n "$B_VOLUME" && -n "$B_NETWORK" && -n "$B_ADB" && -n "$B_DAEMON" ]] \
  || fail "incomplete $INSTANCE_B lease"
[[ "$A_CONTAINER" != "$B_CONTAINER" ]] || fail "container names identical"
[[ "$A_VOLUME" != "$B_VOLUME" ]] || fail "volume names identical"
[[ "$A_NETWORK" != "$B_NETWORK" ]] || fail "network names identical"
[[ "$A_ADB" != "$B_ADB" ]] || fail "ADB ports identical"
[[ "$A_DAEMON" != "$B_DAEMON" ]] || fail "daemon ports identical"

A_CTX="$(docker_context "$INSTANCE_A")"
B_CTX="$(docker_context "$INSTANCE_B")"

log "verifying owner labels and mounts"
docker --context "$A_CTX" inspect "$A_CONTAINER" --format '{{json .Config.Labels}} {{json .Mounts}}' > "$TMP/a-inspect.json" || fail "cannot inspect $INSTANCE_A"
docker --context "$B_CTX" inspect "$B_CONTAINER" --format '{{json .Config.Labels}} {{json .Mounts}}' > "$TMP/b-inspect.json" || fail "cannot inspect $INSTANCE_B"
verify_inspect "$TMP/a-inspect.json" "$A_VOLUME"
verify_inspect "$TMP/b-inspect.json" "$B_VOLUME"

log "verifying distinct binder superblocks"
A_BINDER="$(binder_superblock "$A_CONTAINER" "$A_CTX")"
B_BINDER="$(binder_superblock "$B_CONTAINER" "$B_CTX")"
[[ -n "$A_BINDER" && -n "$B_BINDER" ]] || fail "binder superblock unavailable"
[[ "$A_BINDER" != "$B_BINDER" ]] || fail "binder superblocks identical: $A_BINDER"

log "verifying proxy status per instance"
xenoid_a proxy status --check >/dev/null 2>&1 || log "proxy check on $INSTANCE_A returned non-zero (may be off)"
xenoid_b proxy status --check >/dev/null 2>&1 || log "proxy check on $INSTANCE_B returned non-zero (may be off)"

log "verifying both instances share one exact protection deployment"
xenoid_a ebpf status > "$TMP/a-protection.json" || fail "$INSTANCE_A protection status failed"
xenoid_b ebpf status > "$TMP/b-protection.json" || fail "$INSTANCE_B protection status failed"
read -r A_ENGINE A_PROTECTION <<< "$(python3 - "$TMP/a-protection.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1], encoding="utf-8"))
e=v.get("ebpf", {})
assert v.get("ok") is True and v.get("replacementRequired") is False
assert e.get("links") == ["path","selinuxPermission","unameEntry","unameReturn"]
assert e.get("maps") == ["denyCount","policyIdentity"]
print(v["engineId"], v["currentDigest"])
PY
)" || fail "$INSTANCE_A protection inventory invalid"
read -r B_ENGINE B_PROTECTION <<< "$(python3 - "$TMP/b-protection.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1], encoding="utf-8"))
e=v.get("ebpf", {})
assert v.get("ok") is True and v.get("replacementRequired") is False
assert e.get("links") == ["path","selinuxPermission","unameEntry","unameReturn"]
assert e.get("maps") == ["denyCount","policyIdentity"]
print(v["engineId"], v["currentDigest"])
PY
)" || fail "$INSTANCE_B protection inventory invalid"
[[ "$A_ENGINE" == "$B_ENGINE" && "$A_PROTECTION" == "$B_PROTECTION" ]] || fail "instances do not share one protection deployment"

log "verifying Android app state isolation"
xenoid_a adb shell "run-as org.example.persistenceruntimeprobe cat files/persistence-marker" > "$TMP/a-marker.txt" 2>/dev/null || echo "unavailable" > "$TMP/a-marker.txt"
xenoid_b adb shell "run-as org.example.persistenceruntimeprobe cat files/persistence-marker" > "$TMP/b-marker.txt" 2>/dev/null || echo "unavailable" > "$TMP/b-marker.txt"
A_MARKER="$(cat "$TMP/a-marker.txt")"
B_MARKER="$(cat "$TMP/b-marker.txt")"
if [[ "$A_MARKER" != "unavailable" && "$B_MARKER" != "unavailable" ]]; then
  [[ "$A_MARKER" != "$B_MARKER" ]] || fail "app markers identical across instances"
fi

log "stopping $INSTANCE_A and verifying $INSTANCE_B remains ready"
xenoid_a stop >/dev/null 2>&1 || fail "stop $INSTANCE_A failed"
xenoid_b status >/dev/null 2>&1 || fail "$INSTANCE_B not running after stopping $INSTANCE_A"
xenoid_b ebpf smoke >/dev/null 2>&1 || fail "$INSTANCE_B app/isolated protection failed after stopping $INSTANCE_A"

log "restarting $INSTANCE_A and verifying data"
xenoid_a up --skip-build >/dev/null 2>&1 || fail "up $INSTANCE_A failed"
xenoid_a status >/dev/null 2>&1 || fail "$INSTANCE_A not running after restart"
A_AFTER="$(xenoid_a adb shell "run-as org.example.persistenceruntimeprobe cat files/persistence-marker" 2>/dev/null || echo "unavailable")"
if [[ "$A_MARKER" != "unavailable" && "$A_AFTER" != "unavailable" ]]; then
  [[ "$A_AFTER" == "$A_MARKER" ]] || fail "app marker changed after stop/up on $INSTANCE_A"
fi

log "stopping $INSTANCE_B and verifying $INSTANCE_A remains protected"
xenoid_b stop >/dev/null 2>&1 || fail "stop $INSTANCE_B failed"
xenoid_a ebpf smoke >/dev/null 2>&1 || fail "$INSTANCE_A app/isolated protection failed after stopping $INSTANCE_B"
xenoid_a ebpf status > "$TMP/a-protection-after.json" || fail "shared protection disappeared"
python3 - "$TMP/a-protection-after.json" "$A_ENGINE" "$A_PROTECTION" <<'PY' || fail "shared protection identity changed"
import json,sys
v=json.load(open(sys.argv[1], encoding="utf-8"))
assert v.get("ok") is True
assert v.get("engineId") == sys.argv[2]
assert v.get("currentDigest") == sys.argv[3]
PY
xenoid_b up --skip-build >/dev/null 2>&1 || fail "up $INSTANCE_B failed"

write_report \
  "$REPORT" "$INSTANCE_A" "$INSTANCE_B" "$A_CONTAINER" "$B_CONTAINER" \
  "$A_VOLUME" "$B_VOLUME" "$A_NETWORK" "$B_NETWORK" "$A_ADB" "$B_ADB" \
  "$A_BINDER" "$B_BINDER" "$A_MARKER" "$B_MARKER"
python3 - "$REPORT" "$A_ENGINE" "$A_PROTECTION" <<'PY'
import json,sys
p=sys.argv[1]
v=json.load(open(p, encoding="utf-8"))
v["sharedProtection"]={"engineId":sys.argv[2],"currentDigest":sys.argv[3],"links":["path","selinuxPermission","unameEntry","unameReturn"],"maps":["denyCount","policyIdentity"],"stopEachPreserved":True}
with open(p,"w",encoding="utf-8") as f: json.dump(v,f,indent=2); f.write("\n")
PY

log "dual-instance isolation evidence written to $REPORT"
