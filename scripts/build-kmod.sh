#!/usr/bin/env bash
# Build xenoid kernel module on the Docker engine host:
#   --colima           local Colima VM (macOS default path)
#   --ssh user@host    remote engine via docker context SSH
#   --local            native Linux host
# Produces dist/kmod/xenoid_kmod.ko (host-side cache) when local; always loads into the engine.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/native/xenoid-kmod"

if [[ "${XENOID_SHARED_PROTECTION_LOCKED:-0}" != 1 ]]; then
  exec python3 "$ROOT/scripts/with-shared-protection-lock.py" "$0" "$@"
fi
BUILD_DIR="/var/tmp/xenoid-kmod-build"
LKG_DIR="/var/tmp/xenoid-kmod-lkg"
DRY=0
MODE=""
SSH_TARGET=""
SSH_PORT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --colima) MODE=colima; shift ;;
    --local) MODE=local; shift ;;
    --ssh) SSH_TARGET="${2:-}"; MODE=ssh; shift 2 ;;
    --ssh-port) SSH_PORT="${2:-}"; shift 2 ;;
    *) shift ;;
  esac
done

if [[ -z "$MODE" ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    MODE=colima
  else
    MODE=local
  fi
fi


refresh_android_battery() {
  local command='stop vendor.health-default >/dev/null 2>&1 || true; start vendor.health-default >/dev/null 2>&1 || true; sleep 1; dumpsys battery reset >/dev/null 2>&1 || true'
  if [[ "$DRY" == 1 ]]; then
    echo "+ $ROOT/xenoid root exec '$command'"
    return
  fi
  [[ -x "$ROOT/xenoid" ]] || return
  if "$ROOT/xenoid" root exec "$command" >/dev/null 2>&1; then
    echo "[kmod] Android health HAL restarted; BatteryService reset to live power_supply data" >&2
  else
    echo "[kmod] Android runtime unavailable; health HAL refresh deferred until xenoid-up" >&2
  fi
}

if [[ "$MODE" == "colima" ]]; then
  command -v colima >/dev/null 2>&1 || { echo '{"ok":false,"error":"colima not found"}'; exit 1; }
  run_ssh() { if [[ "$DRY" == 1 ]]; then echo "+ colima ssh -- $*"; else colima ssh -- "$@"; fi; }
  run_ssh sh -c 'sudo apt-get install -y -qq linux-headers-$(uname -r) build-essential >/dev/null 2>&1; mkdir -p '"$BUILD_DIR"' '"$LKG_DIR"'; rm -rf '"$BUILD_DIR"'/*'
  for f in "$SRC"/*; do
    base="$(basename "$f")"
    if [[ "$DRY" == 1 ]]; then echo "+ copy $base"; else colima ssh -- sh -c "cat > $BUILD_DIR/$base" < "$f"; fi
  done
  run_ssh sh -c "cd $BUILD_DIR && make"
  run_ssh sh -c "if test -d /sys/module/xenoid_kmod; then if test -f '$LKG_DIR/xenoid_kmod.ko'; then sudo cp '$LKG_DIR/xenoid_kmod.ko' '$BUILD_DIR/xenoid_kmod.lkg'; else echo 'xenoid_kmod is loaded but no last-known-good module exists' >&2; exit 1; fi; fi"
  run_ssh sh -c "if test -d /sys/module/xenoid_kmod; then sudo rmmod xenoid_kmod; fi"
  if run_ssh sh -c "cd $BUILD_DIR && sudo insmod xenoid_kmod.ko && test -d /sys/module/xenoid_kmod"; then
    run_ssh sh -c "sudo cp '$BUILD_DIR/xenoid_kmod.ko' '$LKG_DIR/xenoid_kmod.ko'"
  else
    run_ssh sh -c "if test -f '$BUILD_DIR/xenoid_kmod.lkg'; then sudo insmod '$BUILD_DIR/xenoid_kmod.lkg' && test -d /sys/module/xenoid_kmod; fi" || true
    echo '{"ok":false,"error":"kernel module load failed; last-known-good restore attempted"}'
    exit 1
  fi
  refresh_android_battery
  echo '{"ok":true,"platform":"colima","note":"module built and loaded in VM"}'
elif [[ "$MODE" == "ssh" ]]; then
  [[ -n "$SSH_TARGET" ]] || { echo '{"ok":false,"error":"missing --ssh target"}'; exit 1; }
  command -v ssh >/dev/null 2>&1 || { echo '{"ok":false,"error":"ssh not found"}'; exit 1; }
  SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
  if [[ -n "$SSH_PORT" ]]; then SSH+=(-p "$SSH_PORT"); fi
  SSH+=("$SSH_TARGET")
  run_ssh() { if [[ "$DRY" == 1 ]]; then echo "+ ${SSH[*]} $*"; else "${SSH[@]}" "$@"; fi; }
  run_ssh sh -c 'sudo apt-get install -y -qq linux-headers-$(uname -r) build-essential >/dev/null 2>&1; mkdir -p '"$BUILD_DIR"' '"$LKG_DIR"'; rm -rf '"$BUILD_DIR"'/*'
  for f in "$SRC"/*; do
    base="$(basename "$f")"
    if [[ "$DRY" == 1 ]]; then echo "+ copy $base"; else "${SSH[@]}" sh -c "cat > $BUILD_DIR/$base" < "$f"; fi
  done
  run_ssh sh -c "cd $BUILD_DIR && make"
  run_ssh sh -c "if test -d /sys/module/xenoid_kmod; then if test -f '$LKG_DIR/xenoid_kmod.ko'; then sudo cp '$LKG_DIR/xenoid_kmod.ko' '$BUILD_DIR/xenoid_kmod.lkg'; else echo 'xenoid_kmod is loaded but no last-known-good module exists' >&2; exit 1; fi; fi"
  run_ssh sh -c "if test -d /sys/module/xenoid_kmod; then sudo rmmod xenoid_kmod; fi"
  if run_ssh sh -c "cd $BUILD_DIR && sudo insmod xenoid_kmod.ko && test -d /sys/module/xenoid_kmod"; then
    run_ssh sh -c "sudo cp '$BUILD_DIR/xenoid_kmod.ko' '$LKG_DIR/xenoid_kmod.ko'"
  else
    run_ssh sh -c "if test -f '$BUILD_DIR/xenoid_kmod.lkg'; then sudo insmod '$BUILD_DIR/xenoid_kmod.lkg' && test -d /sys/module/xenoid_kmod; fi" || true
    echo "{\"ok\":false,\"error\":\"kernel module load failed; last-known-good restore attempted\",\"ssh\":\"$SSH_TARGET\"}"
    exit 1
  fi
  refresh_android_battery
  echo "{\"ok\":true,\"platform\":\"remote-ssh\",\"ssh\":\"$SSH_TARGET\",\"note\":\"module built and loaded on docker engine host\"}"
else
  if [[ "$DRY" == 1 ]]; then
    echo "+ make -C $SRC && sudo insmod $SRC/xenoid_kmod.ko"
  else
    mkdir -p "$LKG_DIR"
    ( cd "$SRC" && make )
    if [[ -d /sys/module/xenoid_kmod ]]; then
      [[ -f "$LKG_DIR/xenoid_kmod.ko" ]] || { echo '{"ok":false,"error":"loaded module has no last-known-good copy"}'; exit 1; }
      cp "$LKG_DIR/xenoid_kmod.ko" "$SRC/xenoid_kmod.lkg"
      sudo rmmod xenoid_kmod
    fi
    if sudo insmod "$SRC/xenoid_kmod.ko" && test -d /sys/module/xenoid_kmod; then
      cp "$SRC/xenoid_kmod.ko" "$LKG_DIR/xenoid_kmod.ko"
    else
      if [[ -f "$SRC/xenoid_kmod.lkg" ]]; then
        sudo insmod "$SRC/xenoid_kmod.lkg" || true
        test -d /sys/module/xenoid_kmod || true
      fi
      echo '{"ok":false,"error":"kernel module load failed; last-known-good restore attempted"}'
      exit 1
    fi
  fi
  refresh_android_battery
  echo '{"ok":true,"platform":"linux","note":"module built and loaded on host"}'
fi
