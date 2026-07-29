#!/usr/bin/env bash
set -euo pipefail
DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1
if [[ "$(uname -s)" != "Linux" ]]; then echo "binderfs setup is for Linux hosts" >&2; exit 2; fi
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then SUDO=(); else SUDO=(sudo); fi
if [[ "$DRY" == 1 ]]; then
  # Pure plan: no probes with side effects, no mountpoint checks.
  cat <<PLAN
+ ${SUDO[*]} modprobe binder_linux
+ ${SUDO[*]} apt-get update -qq                                # only if modprobe fails and apt-get exists
+ ${SUDO[*]} apt-get install -y -qq linux-modules-extra-VERSION # uname -r substituted at runtime
+ ${SUDO[*]} mkdir -p /dev/binderfs
+ ${SUDO[*]} mount -t binder binder /dev/binderfs
PLAN
  exit 0
fi
if [[ "${EUID:-$(id -u)}" -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
  echo "need root or sudo for binderfs setup" >&2; exit 1
fi
run() { echo "+ $*"; "$@"; }
# Ubuntu/Debian (incl. ARM ECS): binder_linux lives in linux-modules-extra.
if ! "${SUDO[@]}" modprobe binder_linux 2>/dev/null; then
  if command -v apt-get >/dev/null 2>&1; then
    run "${SUDO[@]}" apt-get update -qq || true
    run "${SUDO[@]}" apt-get install -y -qq "linux-modules-extra-$(uname -r)" || true
  fi
  run "${SUDO[@]}" modprobe binder_linux || true
fi
run "${SUDO[@]}" mkdir -p /dev/binderfs
if ! mountpoint -q /dev/binderfs; then run "${SUDO[@]}" mount -t binder binder /dev/binderfs; fi
[[ -e /dev/binderfs/binder-control ]] || { echo "missing /dev/binderfs/binder-control" >&2; exit 1; }
if [[ ! -e /dev/ashmem ]]; then echo "note: /dev/ashmem missing; Xenoid redroid uses androidboot.use_memfd=true" >&2; fi
