#!/usr/bin/env bash
set -euo pipefail
json_escape() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }
find_cmd() { command -v "$1" 2>/dev/null || { [[ "$1" == docker && -x /Applications/Docker.app/Contents/Resources/bin/docker ]] && echo /Applications/Docker.app/Contents/Resources/bin/docker; } || { [[ "$1" == colima && -x /opt/homebrew/bin/colima ]] && echo /opt/homebrew/bin/colima; } || { [[ "$1" == brew && -x /opt/homebrew/bin/brew ]] && echo /opt/homebrew/bin/brew; } || true; }
check_cmd() { [[ -n "$(find_cmd "$1")" ]]; }
OS="$(uname -s)"
ARCH="$(uname -m)"
OK=true
checks=()
add_check() {
  local name="$1" ok="$2" detail="$3" fix="${4:-}"
  [[ "$ok" == true ]] || OK=false
  checks+=("$(printf '{"name":%s,"ok":%s,"detail":%s,"fix":%s}' \
    "$(printf '%s' "$name" | json_escape)" "$ok" "$(printf '%s' "$detail" | json_escape)" "$(printf '%s' "$fix" | json_escape)")")
}
add_check host true "$OS $ARCH" ""
DOCKER_BIN="$(find_cmd docker)"
if [[ -n "$DOCKER_BIN" ]]; then
  if "$DOCKER_BIN" info >/tmp/xenoid-docker-info.out 2>/tmp/xenoid-docker-info.err; then add_check docker true "$(head -5 /tmp/xenoid-docker-info.out | tr '\n' ' ')" ""
  else add_check docker false "$(cat /tmp/xenoid-docker-info.err)" "start Docker/Colima daemon"
  fi
else add_check docker false "not found" "macOS: brew install docker colima; Linux: install docker"
fi
if [[ "$OS" == Darwin ]]; then
  COLIMA_BIN="$(find_cmd colima)"
  if [[ -n "$COLIMA_BIN" ]]; then add_check colima true "$COLIMA_BIN" ""; else add_check colima false "not found" "brew install colima"; fi
  add_check binder true "macOS has no host binder; the Colima Linux VM provides it and xenoid start ensures it automatically" ""

  if [[ -n "${COLIMA_BIN:-}" ]]; then
    BINDER_PROBE="$($COLIMA_BIN ssh -- sh -c 'test -e /dev/binderfs/binder-control && echo binderfs-ready || (sudo modprobe binder_linux 2>/dev/null && echo modprobe-ok) || echo missing' 2>/dev/null || true)"
    case "$BINDER_PROBE" in
      *binderfs-ready*) add_check colima_binder true "binderfs mounted inside Colima VM" "" ;;
      *modprobe-ok*) add_check colima_binder true "binder_linux module loaded inside Colima VM (binderfs mount pending)" "" ;;
      *) add_check colima_binder false "The Colima VM lacks the binder_linux module" "xenoid start automatically installs linux-modules-extra-$(uname -r), loads binder_linux, and mounts binderfs" ;;
    esac
  fi
else
  if [[ -e /dev/binderfs || -e /dev/binder ]]; then add_check binder true "binder device present" ""; else add_check binder false "no /dev/binderfs or /dev/binder" "load binder_linux and mount binderfs at /dev/binderfs; xenoid start performs this automatically"
  fi
  if [[ -e /dev/ashmem ]]; then add_check ashmem true "/dev/ashmem present" ""; else add_check ashmem true "/dev/ashmem absent; redroid boots with androidboot.use_memfd=true (forced in run/compose)" ""; fi
  if [[ "$ARCH" == aarch64 || "$ARCH" == arm64 ]]; then add_check linux_arm true "$ARCH" ""; else add_check linux_arm false "$ARCH" "use Linux ARM server for target deployment"
  fi
fi

if [[ "$OS" == Darwin && -n "${DOCKER_BIN:-}" && -z "${COLIMA_BIN:-}" ]]; then
  if "$DOCKER_BIN" image inspect redroid/redroid:13.0.0_64only-latest >/dev/null 2>&1; then
    PROBE_JSON="$(./scripts/probe-redroid-docker.sh 2>/dev/null || true)"
    if echo "$PROBE_JSON" | grep -q '"ExitCode": 129'; then
      add_check redroid_docker_desktop false "redroid exits 129 under Docker Desktop; use Colima/Linux binderfs backend" "brew install colima && colima start --arch aarch64 --vm-type vz --memory 8 --cpu 8"
    fi
  fi
fi

if check_cmd adb || [[ -x "${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb" ]]; then add_check adb true "available" ""; else add_check adb false "not found" "install Android platform-tools"; fi
printf '{"ok":%s,"checks":[%s]}\n' "$OK" "$(IFS=,; echo "${checks[*]}")"
