#!/usr/bin/env bash
# Stage or publish a digest-bound eBPF loader on the selected engine host.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/native/xenoid-ebpf"
if [[ ! "${XENOID_SHARED_PROTECTION_CAPABILITY:-}" =~ ^[0-9a-f]{64}$ ]]; then
  exec python3 "$ROOT/scripts/with-shared-protection-lock.py" "$0" "$@"
fi
MODE=""; SSH_TARGET=""; SSH_PORT=""; INPUT_DIGEST=""; TRANSACTION=""; ARTIFACT_SHA=""; ACTION=stage; DRY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --colima) MODE=colima; shift ;;
    --local) MODE=local; shift ;;
    --ssh) MODE=ssh; SSH_TARGET="${2:-}"; shift 2 ;;
    --ssh-port) SSH_PORT="${2:-}"; shift 2 ;;
    --input-digest) INPUT_DIGEST="${2:-}"; shift 2 ;;
    --transaction) TRANSACTION="${2:-}"; shift 2 ;;
    --artifact-sha256) ARTIFACT_SHA="${2:-}"; shift 2 ;;
    --stage-only) ACTION=stage; shift ;;
    --publish-staged) ACTION=publish; shift ;;
    --dry-run) DRY=1; shift ;;
    *) echo '{"ok":false,"error":"shared_protection_command_invalid"}'; exit 2 ;;
  esac
done
[[ -n "$MODE" ]] || { [[ "$(uname -s)" == Darwin ]] && MODE=colima || MODE=local; }
[[ "$INPUT_DIGEST" =~ ^[0-9a-f]{64}$ && "$TRANSACTION" =~ ^[0-9a-f]{32}$ ]] || { echo '{"ok":false,"error":"shared_protection_manager_required"}'; exit 2; }
[[ "$MODE" != ssh || -n "$SSH_TARGET" ]] || { echo '{"ok":false,"error":"shared_protection_engine_unavailable"}'; exit 2; }
[[ "$ACTION" != publish || "$ARTIFACT_SHA" =~ ^[0-9a-f]{64}$ ]] || { echo '{"ok":false,"error":"shared_protection_artifact_invalid"}'; exit 2; }
SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new); [[ -z "$SSH_PORT" ]] || SSH+=(-p "$SSH_PORT"); [[ -z "$SSH_TARGET" ]] || SSH+=("$SSH_TARGET")
WATCHDOG='cap=$1; shift; parent=$PPID; target=$$; (trap "" TERM; while kill -0 "$parent" 2>/dev/null && sudo -n test -f "$cap" 2>/dev/null; do sleep 0.1; done; kill -TERM -- -"$target" 2>/dev/null || true; sleep 5; kill -KILL -- -"$target" 2>/dev/null || true) & watcher=$!; set +e; "$@"; rc=$?; set -e; kill -KILL "$watcher" 2>/dev/null || true; wait "$watcher" 2>/dev/null || true; exit "$rc"'
host() { case "$MODE" in colima) colima ssh -- setsid --wait sh -c "$WATCHDOG" xenoid-protection "$CAP_PATH" "$@" ;; ssh) local c; printf -v c '%q ' setsid --wait sh -c "$WATCHDOG" xenoid-protection "$CAP_PATH" "$@"; "${SSH[@]}" "$c" ;; local) setsid --wait sh -c "$WATCHDOG" xenoid-protection "$CAP_PATH" "$@" ;; esac; }
host_root() { host sudo -n "$@"; }
CAP="${XENOID_SHARED_PROTECTION_CAPABILITY:-}"; CAP_PATH="/run/xenoid/shared-protection-capabilities/$CAP"
[[ "$CAP" =~ ^[0-9a-f]{64}$ ]] || { echo '{"ok":false,"error":"shared_protection_lock_lost"}'; exit 1; }
host_root test -f "$CAP_PATH" && host_root test ! -L "$CAP_PATH" && [[ "$(host_root stat -c '%u:%g:%a:%h' "$CAP_PATH")" == 0:0:600:1 ]] || { echo '{"ok":false,"error":"shared_protection_lock_lost"}'; exit 1; }
BASE=/var/lib/xenoid/shared-protection; STAGE_PARENT="$BASE/staging/ebpf"; STAGE="$STAGE_PARENT/$TRANSACTION"; STAGED="$STAGE/xenoid-ebpf-loader"
ARTIFACT_DIR="$BASE/artifacts/ebpf/$INPUT_DIGEST"; ARTIFACT="$ARTIFACT_DIR/xenoid-ebpf-loader"
safe_dir() { local p="$1" mode="$2" expected="${2#0}"; if host_root test -e "$p"; then host_root test -d "$p" && host_root test ! -L "$p" && [[ "$(host_root stat -c '%u:%g:%a' "$p")" == "0:0:$expected" ]]; else host_root install -d -o root -g root -m "$mode" "$p"; fi; }
safe_dir /var/lib/xenoid 0755 || { echo '{"ok":false,"error":"shared_protection_artifact_invalid"}'; exit 1; }
for d in "$BASE" "$BASE/staging" "$STAGE_PARENT"; do safe_dir "$d" 0700 || { echo '{"ok":false,"error":"shared_protection_artifact_invalid"}'; exit 1; }; done
if [[ "$DRY" == 1 ]]; then printf '{"ok":true,"schema":"dev.xenoid.protection-build/v1","component":"ebpf","inputDigest":"%s","transaction":"%s","action":"%s","dryRun":true}\n' "$INPUT_DIGEST" "$TRANSACTION" "$ACTION"; exit 0; fi
if [[ "$ACTION" == stage ]]; then
  host_root test ! -e "$STAGE" || { echo '{"ok":false,"error":"shared_protection_staging_conflict"}'; exit 1; }
  host_root install -d -o root -g root -m 0700 "$STAGE"
  for name in Makefile loader.c xenoid_pathhide.bpf.c; do host_root sh -c "umask 077; cat > '$STAGE/$name'" < "$SRC/$name"; host_root chmod 0600 "$STAGE/$name"; done
  host_root sh -c "cd '$STAGE' && make clean >/dev/null 2>&1 || true; SOURCE_DATE_EPOCH=0 make" >&2 || { echo '{"ok":false,"error":"shared_protection_ebpf_build_failed"}'; exit 1; }
  host_root test -f "$STAGED" && host_root test ! -L "$STAGED" || { echo '{"ok":false,"error":"shared_protection_ebpf_build_failed"}'; exit 1; }
  host_root chown root:root "$STAGED"; host_root chmod 0700 "$STAGED"
  SHA="$(host_root sha256sum "$STAGED" | cut -d ' ' -f 1)"
  [[ "$SHA" =~ ^[0-9a-f]{64}$ && "$(host_root stat -c '%u:%g:%a:%h' "$STAGED")" == 0:0:700:1 ]] || { echo '{"ok":false,"error":"shared_protection_artifact_invalid"}'; exit 1; }
  printf '{"ok":true,"schema":"dev.xenoid.protection-build/v1","component":"ebpf","inputDigest":"%s","transaction":"%s","artifactSha256":"%s","staged":true}\n' "$INPUT_DIGEST" "$TRANSACTION" "$SHA"
  exit 0
fi
safe_dir "$BASE/artifacts" 0700; safe_dir "$BASE/artifacts/ebpf" 0700; safe_dir "$ARTIFACT_DIR" 0700
host_root test -f "$STAGED" && host_root test ! -L "$STAGED" && [[ "$(host_root stat -c '%u:%g:%a:%h' "$STAGED")" == 0:0:700:1 ]] && [[ "$(host_root sha256sum "$STAGED" | cut -d ' ' -f 1)" == "$ARTIFACT_SHA" ]] || { echo '{"ok":false,"error":"shared_protection_artifact_invalid"}'; exit 1; }
if host_root test -e "$ARTIFACT"; then
  host_root test -f "$ARTIFACT" && host_root test ! -L "$ARTIFACT" && [[ "$(host_root stat -c '%u:%g:%a:%h' "$ARTIFACT")" == 0:0:700:1 ]] && [[ "$(host_root sha256sum "$ARTIFACT" | cut -d ' ' -f 1)" == "$ARTIFACT_SHA" ]] || { echo '{"ok":false,"error":"shared_protection_artifact_conflict"}'; exit 1; }
else
  TEMP="$ARTIFACT_DIR/.loader-$TRANSACTION.tmp"; host_root test ! -e "$TEMP"; host_root install -o root -g root -m 0700 "$STAGED" "$TEMP"; [[ "$(host_root sha256sum "$TEMP" | cut -d ' ' -f 1)" == "$ARTIFACT_SHA" ]] || { host_root rm -f "$TEMP"; echo '{"ok":false,"error":"shared_protection_artifact_invalid"}'; exit 1; }; host_root sync -f "$TEMP"; host_root mv -n "$TEMP" "$ARTIFACT" || true; host_root rm -f "$TEMP"
fi
[[ "$(host_root sha256sum "$ARTIFACT" | cut -d ' ' -f 1)" == "$ARTIFACT_SHA" ]] || { echo '{"ok":false,"error":"shared_protection_artifact_invalid"}'; exit 1; }
host_root rm -rf --one-file-system "$STAGE"; host_root sync -f "$ARTIFACT_DIR"
printf '{"ok":true,"schema":"dev.xenoid.protection-build/v1","component":"ebpf","inputDigest":"%s","artifactSha256":"%s","published":true}\n' "$INPUT_DIGEST" "$ARTIFACT_SHA"
