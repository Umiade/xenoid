#!/usr/bin/env bash
# Build xenoid-ebpf on the Docker engine host:
#   --colima           local Colima VM (macOS default path)
#   --ssh user@host    remote engine via docker context SSH
#   --local            native Linux host
# Emits JSON status on stdout.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/native/xenoid-ebpf"
BUILD_DIR="/var/tmp/xenoid-ebpf-build"
DIST="$ROOT/dist/ebpf"
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

install_deps_cmd='sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang llvm libbpf-dev libelf-dev zlib1g-dev linux-tools-common linux-tools-$(uname -r) >/dev/null 2>&1 || true'
build_cmd="cd $BUILD_DIR && make clean >/dev/null 2>&1 || true; make 2>&1 | tail -20"

copy_sources() {
  local runner=("$@")
  "${runner[@]}" sh -c "mkdir -p $BUILD_DIR"
  for f in "$SRC"/*; do
    [[ -f "$f" ]] || continue
    base="$(basename "$f")"
    case "$base" in
      *.o|*.skel.h|vmlinux.h|xenoid-ebpf-loader) continue ;;
    esac
    if [[ "$DRY" == 1 ]]; then
      echo "+ copy $base"
    else
      "${runner[@]}" sh -c "cat > $BUILD_DIR/$base" < "$f"
    fi
  done
}

if [[ "$MODE" == "colima" ]]; then
  command -v colima >/dev/null 2>&1 || { echo '{"ok":false,"error":"colima not found"}'; exit 1; }
  run_ssh() { if [[ "$DRY" == 1 ]]; then echo "+ colima ssh -- $*"; else colima ssh -- "$@"; fi; }
  run_ssh sh -c "$install_deps_cmd; mkdir -p $BUILD_DIR"
  if [[ "$DRY" == 1 ]]; then
    echo "+ copy sources"
  else
    copy_sources colima ssh --
  fi
  if [[ "$DRY" == 1 ]]; then
    run_ssh sh -c "$build_cmd"
  else
    out="$(run_ssh sh -c "$build_cmd" 2>&1 || true)"
    if ! run_ssh sh -c "test -x $BUILD_DIR/xenoid-ebpf-loader"; then
      python3 -c 'import json,sys; print(json.dumps({"ok":False,"platform":"colima","error":"build failed","log":sys.stdin.read()[-800:]}))' <<<"$out"
      exit 1
    fi
    mkdir -p "$DIST"
    colima ssh -- sh -c "cat $BUILD_DIR/xenoid-ebpf-loader" > "$DIST/xenoid-ebpf-loader" || true
    chmod +x "$DIST/xenoid-ebpf-loader" 2>/dev/null || true
  fi
  echo '{"ok":true,"platform":"colima","buildDir":"'"$BUILD_DIR"'","note":"eBPF program and loader built in VM"}'
elif [[ "$MODE" == "ssh" ]]; then
  [[ -n "$SSH_TARGET" ]] || { echo '{"ok":false,"error":"missing --ssh target"}'; exit 1; }
  command -v ssh >/dev/null 2>&1 || { echo '{"ok":false,"error":"ssh not found"}'; exit 1; }
  SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
  if [[ -n "$SSH_PORT" ]]; then SSH+=(-p "$SSH_PORT"); fi
  SSH+=("$SSH_TARGET")
  run_ssh() { if [[ "$DRY" == 1 ]]; then echo "+ ${SSH[*]} $*"; else "${SSH[@]}" "$@"; fi; }
  run_ssh sh -c "$install_deps_cmd; mkdir -p $BUILD_DIR"
  copy_sources "${SSH[@]}"
  if [[ "$DRY" != 1 ]]; then
    out="$(run_ssh sh -c "$build_cmd" 2>&1 || true)"
    if ! run_ssh sh -c "test -x $BUILD_DIR/xenoid-ebpf-loader"; then
      echo '{"ok":false,"platform":"remote-ssh","error":"build failed"}'
      exit 1
    fi
  fi
  echo "{\"ok\":true,\"platform\":\"remote-ssh\",\"ssh\":\"$SSH_TARGET\",\"buildDir\":\"$BUILD_DIR\",\"note\":\"eBPF built on docker engine host\"}"
else
  if [[ "$DRY" == 1 ]]; then
    echo "+ make -C $SRC"
  else
    eval "$install_deps_cmd"
    mkdir -p "$BUILD_DIR"
    for f in "$SRC"/*; do
      [[ -f "$f" ]] || continue
      base="$(basename "$f")"
      case "$base" in *.o|*.skel.h|vmlinux.h|xenoid-ebpf-loader) continue ;; esac
      cp "$f" "$BUILD_DIR/$base"
    done
    ( cd "$BUILD_DIR" && make 2>&1 | tail -20 )
    mkdir -p "$DIST"
    cp -f "$BUILD_DIR/xenoid-ebpf-loader" "$DIST/" 2>/dev/null || true
  fi
  echo '{"ok":true,"platform":"linux","buildDir":"'"$BUILD_DIR"'","note":"eBPF program and loader built on host"}'
fi
