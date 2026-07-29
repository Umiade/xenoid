#!/usr/bin/env bash
# Build /data/xenoid-rootfs.img (real ext4 image of the Android rootfs) and ensure
# /data/xenoid-data.img exists. The container entrypoint (xenoid-init) pivot_roots
# into these images so the in-container mount table contains no overlayfs/docker
# artifacts at all.
#
# Usage: make-rootfs-image.sh [source-image] [volume] [size_mb]
# Requires: docker, e2fsprogs (mkfs.ext4) on the docker host (colima on macOS).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_IMAGE="${1:-xenoid/redroid:local}"
VOLUME="${2:-xenoid-data}"
SIZE_MB="${3:-3072}"
DATA_SIZE_MB="${4:-8192}"
DOCKER=(docker)
if [[ -n "${XENOID_DOCKER_CONTEXT:-}" ]]; then
  DOCKER+=(--context "$XENOID_DOCKER_CONTEXT")
fi

ENGINE_SSH="${XENOID_ENGINE_SSH:-}"
ENGINE_SSH_PORT="${XENOID_ENGINE_SSH_PORT:-}"
SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
[[ -n "$ENGINE_SSH_PORT" ]] && SSH+=(-p "$ENGINE_SSH_PORT")

is_darwin() { [[ "$(uname -s)" == "Darwin" ]]; }
host_sh() {
  if [[ -n "$ENGINE_SSH" ]]; then
    printf '%s\n' "$1" | "${SSH[@]}" "$ENGINE_SSH" sudo sh -s
  elif is_darwin; then
    colima ssh -- sudo sh -c "$1"
  else
    sudo sh -c "$1"
  fi
}
host_copy() {
  local source="$1" destination="$2"
  [[ -n "$ENGINE_SSH" ]] || return 0
  "${SSH[@]}" "$ENGINE_SSH" "cat > '$destination'" < "$source"
}

"${DOCKER[@]}" volume create "$VOLUME" >/dev/null
VOL_PATH="$("${DOCKER[@]}" volume inspect "$VOLUME" --format '{{.Mountpoint}}')"
[[ -n "$VOL_PATH" ]] || { echo "cannot resolve Docker volume $VOLUME" >&2; exit 1; }

digest="$("${DOCKER[@]}" image inspect "$SRC_IMAGE" --format '{{.Id}}')"
[[ -n "$digest" ]] || { echo "image $SRC_IMAGE not found" >&2; exit 1; }

cur="$(host_sh "cat '$VOL_PATH/xenoid-rootfs.img.sha256' 2>/dev/null" || true)"
if [[ "$cur" == "$digest" ]] && host_sh "test -s '$VOL_PATH/xenoid-rootfs.img'" >/dev/null 2>&1; then
  echo "rootfs image current ($digest)"
else
  echo "building rootfs image from $SRC_IMAGE ($digest)"
  cid="$("${DOCKER[@]}" create "$SRC_IMAGE")"
  trap '"${DOCKER[@]}" rm -f "$cid" >/dev/null 2>&1 || true' EXIT
  build_dir="$ROOT/dist/rootfs-build"
  rm -rf "$build_dir"; mkdir -p "$build_dir"
  "${DOCKER[@]}" export "$cid" -o "$build_dir/rootfs.tar"
  "${DOCKER[@]}" rm -f "$cid" >/dev/null 2>&1 || true
  trap - EXIT
  host_tar="$build_dir/rootfs.tar"
  if [[ -n "$ENGINE_SSH" ]]; then
    host_tar="/tmp/xenoid-rootfs-$$.tar"
    host_copy "$build_dir/rootfs.tar" "$host_tar"
  fi
  # The build dir must be reachable from the docker host. On macOS colima mounts
  # /Users; on Linux it is a local path.
  host_sh "$(cat <<EOF
set -e
rm -rf /tmp/xenoid-rf && mkdir -p /tmp/xenoid-rf
cd /tmp/xenoid-rf
tar -xf '$host_tar'
rm -rf proc sys dev data mnt tmp run oldroot .dockerenv
mkdir -p proc sys dev data mnt tmp oldroot xenoid
# remove the setuid su binary: root lives exclusively in the token-gated rootd
rm -f system/xbin/su
mkfs.ext4 -q -F -d /tmp/xenoid-rf '$VOL_PATH/xenoid-rootfs.img.new' ${SIZE_MB}M
mv '$VOL_PATH/xenoid-rootfs.img.new' '$VOL_PATH/xenoid-rootfs.img'
printf '%s' '$digest' > '$VOL_PATH/xenoid-rootfs.img.sha256'
rm -rf /tmp/xenoid-rf '$host_tar'
EOF
)"
  rm -f "$build_dir/rootfs.tar"
  rmdir "$build_dir" 2>/dev/null || true
  echo "rootfs image rebuilt"
fi

if ! host_sh "test -s '$VOL_PATH/xenoid-data.img'" >/dev/null 2>&1; then
  echo "creating empty data image (${DATA_SIZE_MB}M sparse; Android populates on first boot)"
  host_sh "dd if=/dev/zero of='$VOL_PATH/xenoid-data.img' bs=1M count=0 seek=$DATA_SIZE_MB status=none && mkfs.ext4 -q -F '$VOL_PATH/xenoid-data.img'"
fi
echo "OK rootfs=$VOL_PATH/xenoid-rootfs.img data=$VOL_PATH/xenoid-data.img"
