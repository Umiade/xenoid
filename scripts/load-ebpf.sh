#!/usr/bin/env bash
# Load / status / unload xenoid-ebpf on the Docker engine host.
# Usage: load-ebpf.sh [--colima|--local|--ssh user@host] [--ssh-port N] load|status|unload
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="/var/tmp/xenoid-ebpf-build"
SRC="$ROOT/native/xenoid-ebpf"
DRY=0
MODE=""
SSH_TARGET=""
SSH_PORT=""
ACTION=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --colima) MODE=colima; shift ;;
    --local) MODE=local; shift ;;
    --ssh) SSH_TARGET="${2:-}"; MODE=ssh; shift 2 ;;
    --ssh-port) SSH_PORT="${2:-}"; shift 2 ;;
    load|status|unload) ACTION="$1"; shift ;;
    *) shift ;;
  esac
done

ACTION="${ACTION:-status}"

if [[ -z "$MODE" ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    MODE=colima
  else
    MODE=local
  fi
fi

if [[ "$MODE" == "colima" ]]; then
  command -v colima >/dev/null 2>&1 || { echo '{"ok":false,"error":"colima not found"}'; exit 1; }
  if [[ "$DRY" == 1 ]]; then
    echo "+ colima ssh -- sudo $BUILD_DIR/xenoid-ebpf-loader $ACTION"
    echo "{\"ok\":true,\"platform\":\"colima\",\"action\":\"$ACTION\",\"dryRun\":true}"
    exit 0
  fi
  if ! colima ssh -- sh -c "test -x $BUILD_DIR/xenoid-ebpf-loader"; then
    "$ROOT/scripts/build-ebpf.sh" --colima >/dev/null
  fi
  for f in Makefile loader.c xenoid_pathhide.bpf.c; do
    colima ssh -- sh -c "cat > $BUILD_DIR/$f" < "$SRC/$f"
  done
  colima ssh -- sh -c "cd $BUILD_DIR && (make -q xenoid-ebpf-loader 2>/dev/null || make >/dev/null)"
  colima ssh -- sh -c "sudo $BUILD_DIR/xenoid-ebpf-loader $ACTION"
elif [[ "$MODE" == "ssh" ]]; then
  [[ -n "$SSH_TARGET" ]] || { echo '{"ok":false,"error":"missing --ssh target"}'; exit 1; }
  SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
  if [[ -n "$SSH_PORT" ]]; then SSH+=(-p "$SSH_PORT"); fi
  SSH+=("$SSH_TARGET")
  if [[ "$DRY" == 1 ]]; then
    echo "+ ${SSH[*]} sudo $BUILD_DIR/xenoid-ebpf-loader $ACTION"
    echo "{\"ok\":true,\"platform\":\"remote-ssh\",\"action\":\"$ACTION\",\"dryRun\":true}"
    exit 0
  fi
  if ! "${SSH[@]}" sh -c "test -x $BUILD_DIR/xenoid-ebpf-loader"; then
    args=(--ssh "$SSH_TARGET")
    [[ -n "$SSH_PORT" ]] && args+=(--ssh-port "$SSH_PORT")
    "$ROOT/scripts/build-ebpf.sh" "${args[@]}" >/dev/null
  fi
  "${SSH[@]}" sh -c "sudo $BUILD_DIR/xenoid-ebpf-loader $ACTION"
else
  if [[ "$DRY" == 1 ]]; then
    echo "+ sudo $BUILD_DIR/xenoid-ebpf-loader $ACTION"
    echo "{\"ok\":true,\"platform\":\"linux\",\"action\":\"$ACTION\",\"dryRun\":true}"
    exit 0
  fi
  if [[ ! -x "$BUILD_DIR/xenoid-ebpf-loader" ]]; then
    "$ROOT/scripts/build-ebpf.sh" --local >/dev/null
  fi
  sudo "$BUILD_DIR/xenoid-ebpf-loader" "$ACTION"
fi
