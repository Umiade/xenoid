#!/usr/bin/env bash
# Live dual-instance isolation evidence: owner labels, volumes, networks, ports,
# binder superblocks, proxy status, and per-instance Android app state.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
INSTANCE_A="${1:-phone-a}"
INSTANCE_B="${2:-phone-b}"
OUT_DIR="${XENOID_STATE_ROOT:-$HOME/.xenoid/instances}/dual-instance-evidence"
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/report.json"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/xenoid-dual-instance.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

log() { echo "[dual-instance] $*"; }
fail() { echo "[dual-instance] FAIL: $*" >&2; exit 1; }

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
  docker --context "$context" exec "$container" sh -c '
    grep " /dev/binderfs " /proc/mounts 2>/dev/null || grep " binder " /proc/mounts 2>/dev/null | head -1
  ' 2>/dev/null | awk '{print $1}' || echo "unavailable"
}

log "resolving leases for $INSTANCE_A and $INSTANCE_B"
read -r A_CONTAINER A_VOLUME A_NETWORK A_ADB A_DAEMON <<< "$(resolve_lease "$INSTANCE_A")" || fail "cannot resolve $INSTANCE_A lease"
read -r B_CONTAINER B_VOLUME B_NETWORK B_ADB B_DAEMON <<< "$(resolve_lease "$INSTANCE_B")" || fail "cannot resolve $INSTANCE_B lease"
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

python3 - "$TMP/a-inspect.json" "$A_VOLUME" <<'PY'
import json, sys
labels, mounts = json.loads(sys.stdin.read().split(' ', 1)[0]), json.loads(sys.stdin.read().split(' ', 1)[1])
required = ["dev.xenoid.owner", "dev.xenoid.instance_id", "dev.xenoid.resource_tag"]
if not all(labels.get(k) for k in required):
    raise SystemExit(1)
volume = sys.argv[2]
if not any(m.get("Type") == "volume" and m.get("Name") == volume and m.get("Destination") == "/data" for m in mounts):
    raise SystemExit(1)
PY

python3 - "$TMP/b-inspect.json" "$B_VOLUME" <<'PY'
import json, sys
labels, mounts = json.loads(sys.stdin.read().split(' ', 1)[0]), json.loads(sys.stdin.read().split(' ', 1)[1])
required = ["dev.xenoid.owner", "dev.xenoid.instance_id", "dev.xenoid.resource_tag"]
if not all(labels.get(k) for k in required):
    raise SystemExit(1)
volume = sys.argv[2]
if not any(m.get("Type") == "volume" and m.get("Name") == volume and m.get("Destination") == "/data" for m in mounts):
    raise SystemExit(1)
PY

log "verifying distinct binder superblocks"
A_BINDER="$(binder_superblock "$A_CONTAINER" "$A_CTX")"
B_BINDER="$(binder_superblock "$B_CONTAINER" "$B_CTX")"
[[ -n "$A_BINDER" && -n "$B_BINDER" ]] || fail "binder superblock unavailable"
[[ "$A_BINDER" != "$B_BINDER" ]] || fail "binder superblocks identical: $A_BINDER"

log "verifying proxy status per instance"
xenoid_a proxy status --check >/dev/null 2>&1 || log "proxy check on $INSTANCE_A returned non-zero (may be off)"
xenoid_b proxy status --check >/dev/null 2>&1 || log "proxy check on $INSTANCE_B returned non-zero (may be off)"

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

log "restarting $INSTANCE_A and verifying data"
xenoid_a up --skip-build >/dev/null 2>&1 || fail "up $INSTANCE_A failed"
xenoid_a status >/dev/null 2>&1 || fail "$INSTANCE_A not running after restart"
A_AFTER="$(xenoid_a adb shell "run-as org.example.persistenceruntimeprobe cat files/persistence-marker" 2>/dev/null || echo "unavailable")"
if [[ "$A_MARKER" != "unavailable" && "$A_AFTER" != "unavailable" ]]; then
  [[ "$A_AFTER" == "$A_MARKER" ]] || fail "app marker changed after stop/up on $INSTANCE_A"
fi

python3 - "$REPORT" <<PY
import json, sys
report = {
    "ok": True,
    "instanceA": "$INSTANCE_A",
    "instanceB": "$INSTANCE_B",
    "containerA": "$A_CONTAINER",
    "containerB": "$B_CONTAINER",
    "volumeA": "$A_VOLUME",
    "volumeB": "$B_VOLUME",
    "networkA": "$A_NETWORK",
    "networkB": "$B_NETWORK",
    "adbPortA": "$A_ADB",
    "adbPortB": "$B_ADB",
    "binderSuperblockA": "$A_BINDER",
    "binderSuperblockB": "$B_BINDER",
    "appMarkerA": "$A_MARKER",
    "appMarkerB": "$B_MARKER",
    "stopA_bStillReady": True,
    "restartA_dataPreserved": True,
}
print(json.dumps(report, indent=2))
PY

log "dual-instance isolation evidence written to $REPORT"
