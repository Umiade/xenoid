#!/usr/bin/env bash
# Stage, prove, atomically activate, inspect, or maintenance-unload eBPF.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ! "${XENOID_SHARED_PROTECTION_CAPABILITY:-}" =~ ^[0-9a-f]{64}$ ]]; then
  exec python3 "$ROOT/scripts/with-shared-protection-lock.py" "$0" "$@"
fi
MODE=""
SSH_TARGET=""
SSH_PORT=""
INPUT_DIGEST=""
ARTIFACT_SHA=""
TRANSACTION=""
ACTION=""
MAINTENANCE=0
PRESERVE_RECORD=0
DRY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --colima) MODE=colima; shift ;;
    --local) MODE=local; shift ;;
    --ssh) MODE=ssh; SSH_TARGET="${2:-}"; shift 2 ;;
    --ssh-port) SSH_PORT="${2:-}"; shift 2 ;;
    --input-digest) INPUT_DIGEST="${2:-}"; shift 2 ;;
    --artifact-sha256) ARTIFACT_SHA="${2:-}"; shift 2 ;;
    --transaction) TRANSACTION="${2:-}"; shift 2 ;;
    --maintenance) MAINTENANCE=1; shift ;;
    --preserve-record) PRESERVE_RECORD=1; shift ;;
    --dry-run) DRY=1; shift ;;
    stage|prove|activate|discard|load|status|unload) ACTION="$1"; shift ;;
    *) echo '{"ok":false,"error":"shared_protection_command_invalid"}'; exit 2 ;;
  esac
done
[[ -n "$ACTION" ]] || ACTION=status
[[ -n "$MODE" ]] || { [[ "$(uname -s)" == Darwin ]] && MODE=colima || MODE=local; }
[[ "$MODE" != ssh || -n "$SSH_TARGET" ]] || { echo '{"ok":false,"error":"shared_protection_engine_unavailable"}'; exit 2; }
case "$ACTION" in
  stage|prove|activate|load)
    [[ "$INPUT_DIGEST" =~ ^[0-9a-f]{64}$ && "$ARTIFACT_SHA" =~ ^[0-9a-f]{64}$ ]] || { echo '{"ok":false,"error":"shared_protection_manager_required"}'; exit 2; }
    ;;
  discard|unload)
    [[ -z "$INPUT_DIGEST" || "$INPUT_DIGEST" =~ ^[0-9a-f]{64}$ ]] || { echo '{"ok":false,"error":"shared_protection_command_invalid"}'; exit 2; }
    [[ -z "$ARTIFACT_SHA" || "$ARTIFACT_SHA" =~ ^[0-9a-f]{64}$ ]] || { echo '{"ok":false,"error":"shared_protection_command_invalid"}'; exit 2; }
    ;;
esac
case "$ACTION" in
  stage|prove|activate|discard)
    [[ "$TRANSACTION" =~ ^[0-9a-f]{32}$ ]] || { echo '{"ok":false,"error":"shared_protection_command_invalid"}'; exit 2; }
    ;;
esac
SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
[[ -z "$SSH_PORT" ]] || SSH+=(-p "$SSH_PORT")
[[ -z "$SSH_TARGET" ]] || SSH+=("$SSH_TARGET")
WATCHDOG='cap=$1; shift; parent=$PPID; target=$$; (trap "" TERM; while kill -0 "$parent" 2>/dev/null && sudo -n test -f "$cap" 2>/dev/null; do sleep 0.1; done; kill -TERM -- -"$target" 2>/dev/null || true; sleep 5; kill -KILL -- -"$target" 2>/dev/null || true) & watcher=$!; set +e; "$@"; rc=$?; set -e; kill -KILL "$watcher" 2>/dev/null || true; wait "$watcher" 2>/dev/null || true; exit "$rc"'
host() {
  case "$MODE" in
    colima) colima ssh -- setsid --wait sh -c "$WATCHDOG" xenoid-protection "$CAP_PATH" "$@" ;;
    ssh) local command; printf -v command '%q ' setsid --wait sh -c "$WATCHDOG" xenoid-protection "$CAP_PATH" "$@"; "${SSH[@]}" "$command" ;;
    local) setsid --wait sh -c "$WATCHDOG" xenoid-protection "$CAP_PATH" "$@" ;;
  esac
}
host_root() { host sudo -n "$@"; }
CAP="${XENOID_SHARED_PROTECTION_CAPABILITY:-}"
CAP_PATH="/run/xenoid/shared-protection-capabilities/$CAP"
[[ "$CAP" =~ ^[0-9a-f]{64}$ ]] &&
  host_root test -f "$CAP_PATH" &&
  host_root test ! -L "$CAP_PATH" &&
  [[ "$(host_root stat -c '%u:%g:%a:%h' "$CAP_PATH")" == "0:0:600:1" ]] ||
  { echo '{"ok":false,"error":"shared_protection_lock_lost"}'; exit 1; }
active_runtime_count() {
  host_root sh -c "command -v docker >/dev/null 2>&1 && docker ps -q --filter label=dev.xenoid.owner=xenoid | wc -l" | tr -d ' '
}
CURRENT_DIR=/var/lib/xenoid/shared-protection/current
CURRENT_LOADER="$CURRENT_DIR/xenoid-ebpf-loader"
if [[ -n "$INPUT_DIGEST" ]]; then
  ARTIFACT="/var/lib/xenoid/shared-protection/artifacts/ebpf/$INPUT_DIGEST/xenoid-ebpf-loader"
else
  ARTIFACT="$CURRENT_LOADER"
fi
if [[ "$DRY" == 1 ]]; then
  printf '{"ok":true,"schema":"dev.xenoid.ebpf-deployment/v1","action":"%s","dryRun":true}\n' "$ACTION"
  exit 0
fi
if ! host_root test -x "$ARTIFACT"; then
  if [[ "$ACTION" == status ]]; then
    echo '{"schema":"dev.xenoid.ebpf-deployment/v1","ok":false,"loaded":false,"digest":null,"attach":null,"links":[],"maps":[],"probes":[],"replacementRequiresMaintenance":false,"error":"ebpf_not_loaded"}'
    exit 1
  fi
  echo '{"ok":false,"error":"shared_protection_artifact_invalid"}'
  exit 1
fi
host_root test ! -L "$ARTIFACT" || { echo '{"ok":false,"error":"shared_protection_artifact_invalid"}'; exit 1; }
[[ "$(host_root stat -c '%u:%g:%a:%h' "$ARTIFACT")" == "0:0:700:1" ]] || { echo '{"ok":false,"error":"shared_protection_artifact_invalid"}'; exit 1; }
if [[ -n "$ARTIFACT_SHA" ]]; then
  [[ "$(host_root sha256sum "$ARTIFACT" | cut -d ' ' -f 1)" == "$ARTIFACT_SHA" ]] || { echo '{"ok":false,"error":"shared_protection_artifact_invalid"}'; exit 1; }
fi
case "$ACTION" in
  status)
    host_root "$CURRENT_LOADER" status
    ;;
  stage)
    host_root "$ARTIFACT" stage "$TRANSACTION" "$INPUT_DIGEST" "$ARTIFACT_SHA"
    ;;
  prove)
    host_root "$ARTIFACT" prove "$TRANSACTION" "$INPUT_DIGEST" "$ARTIFACT_SHA"
    ;;
  discard)
    host_root "$ARTIFACT" discard "$TRANSACTION"
    ;;
  activate)
    output="$(host_root "$ARTIFACT" activate "$TRANSACTION" "$INPUT_DIGEST" "$ARTIFACT_SHA")" || { printf '%s\n' "$output"; exit 1; }
    host_root install -d -o root -g root -m 0700 /var/lib/xenoid/shared-protection "$CURRENT_DIR"
    temp="$CURRENT_DIR/.loader-$TRANSACTION.tmp"
    host_root install -o root -g root -m 0700 "$ARTIFACT" "$temp"
    host_root sync -f "$temp"
    host_root mv -f "$temp" "$CURRENT_LOADER"
    host_root sync -f "$CURRENT_DIR"
    printf '%s\n' "$output"
    ;;
  load)
    output="$(host_root "$ARTIFACT" load "$INPUT_DIGEST" "$ARTIFACT_SHA")" || { printf '%s\n' "$output"; exit 1; }
    host_root install -d -o root -g root -m 0700 /var/lib/xenoid/shared-protection "$CURRENT_DIR"
    temp="$CURRENT_DIR/.loader-load.tmp"
    host_root install -o root -g root -m 0700 "$ARTIFACT" "$temp"
    host_root sync -f "$temp"
    host_root mv -f "$temp" "$CURRENT_LOADER"
    host_root sync -f "$CURRENT_DIR"
    printf '%s\n' "$output"
    ;;
  unload)
    [[ "$MAINTENANCE" == 1 ]] || { echo '{"ok":false,"error":"shared_protection_maintenance_required"}'; exit 2; }
    count="$(active_runtime_count)" || { echo '{"ok":false,"error":"shared_protection_ownership_ambiguous"}'; exit 1; }
    [[ "$count" == 0 ]] || { echo '{"ok":false,"error":"shared_protection_in_use"}'; exit 1; }
    output="$(host_root "$CURRENT_LOADER" unload)" || { printf '%s\n' "$output"; exit 1; }
    printf '%s\n' "$output"
    ;;
esac
