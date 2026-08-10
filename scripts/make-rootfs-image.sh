#!/usr/bin/env bash
# Build /data/xenoid-rootfs.img and perform one explicit operation on the
# persistent /data/xenoid-data.img. The caller owns the Docker volume and keeps
# a crash-safe storage transaction in private instance state.
#
# Usage: make-rootfs-image.sh IMAGE VOLUME ROOTFS_MB DATA_MB ACTION EXPECTED_UUID TRANSACTION [LEGACY_VOLUME] [BACKUP_IMAGE] [BACKUP_UUID]
# ACTION is initialize, preserve, or migrate. There is deliberately no implicit
# "missing means mkfs" fallback.
# Requires: docker, e2fsprogs (mkfs.ext4/blkid) on the Docker engine host.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_IMAGE="${1:-xenoid/redroid:local}"
VOLUME="${2:-xenoid-data}"
SIZE_MB="${3:-3072}"
DATA_SIZE_MB="${4:-8192}"
DATA_ACTION="${5:-}"
EXPECTED_UUID="${6:--}"
STORAGE_TRANSACTION="${7:--}"
LEGACY_VOLUME="${8:--}"
BACKUP_IMAGE="${9:--}"
BACKUP_UUID="${10:--}"
[[ "$DATA_ACTION" =~ ^(initialize|preserve|migrate)$ ]] || { echo "explicit data action required" >&2; exit 2; }
[[ "$EXPECTED_UUID" == "-" || "$EXPECTED_UUID" =~ ^[0-9a-fA-F-]{36}$ ]] || { echo "invalid expected data UUID" >&2; exit 2; }
[[ "$STORAGE_TRANSACTION" == "-" || "$STORAGE_TRANSACTION" =~ ^[0-9a-f]{32}$ ]] || { echo "invalid storage transaction" >&2; exit 2; }
[[ "$LEGACY_VOLUME" == "-" || "$LEGACY_VOLUME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || { echo "invalid legacy volume" >&2; exit 2; }
[[ "$BACKUP_IMAGE" == "-" || "$BACKUP_IMAGE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || { echo "invalid backup image" >&2; exit 2; }
[[ "$BACKUP_UUID" == "-" || "$BACKUP_UUID" =~ ^[0-9a-fA-F-]{36}$ ]] || { echo "invalid backup UUID" >&2; exit 2; }
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
host_extract() {
  local container="$1" destination="$2"
  host_sh "rm -rf '$destination'; mkdir -p '$destination'"
  if [[ -n "$ENGINE_SSH" ]]; then
    "${DOCKER[@]}" export "$container" |
      "${SSH[@]}" "$ENGINE_SSH" "sudo tar -C '$destination' -xf -"
  elif is_darwin; then
    "${DOCKER[@]}" export "$container" |
      colima ssh -- sudo tar -C "$destination" -xf -
  else
    "${DOCKER[@]}" export "$container" |
      sudo tar -C "$destination" -xf -
  fi
}

VOL_PATH="$("${DOCKER[@]}" volume inspect "$VOLUME" --format '{{.Mountpoint}}')"
[[ -n "$VOL_PATH" ]] || { echo "cannot resolve Docker volume $VOLUME" >&2; exit 1; }

digest="$("${DOCKER[@]}" image inspect "$SRC_IMAGE" --format '{{.Id}}')"
[[ -n "$digest" ]] || { echo "image $SRC_IMAGE not found" >&2; exit 1; }

cur="$(host_sh "cat '$VOL_PATH/xenoid-rootfs.img.sha256' 2>/dev/null" || true)"
if [[ "$cur" == "$digest" ]] && host_sh "test -s '$VOL_PATH/xenoid-rootfs.img'" >/dev/null 2>&1; then
  echo "rootfs image current ($digest)"
else
  echo "building rootfs image from $SRC_IMAGE ($digest)"
  work_dir="/tmp/xenoid-rf-${VOLUME}-$$"
  rootfs_new="$VOL_PATH/.xenoid-rootfs.img.$$"
  cid="$("${DOCKER[@]}" create "$SRC_IMAGE")"
  cleanup_rootfs_build() {
    if [[ -n "${cid:-}" ]]; then
      "${DOCKER[@]}" rm -f "$cid" >/dev/null 2>&1 || true
    fi
    host_sh "rm -rf '$work_dir' '$rootfs_new'" >/dev/null 2>&1 || true
  }
  trap cleanup_rootfs_build EXIT
  host_extract "$cid" "$work_dir"
  "${DOCKER[@]}" rm -f "$cid" >/dev/null 2>&1 || true
  cid=""
  host_sh "$(cat <<EOF
set -e
cd '$work_dir'
rm -rf proc sys dev data mnt tmp run oldroot .dockerenv
mkdir -p proc sys dev data mnt tmp oldroot xenoid
# remove the setuid su binary: root lives exclusively in the token-gated rootd
rm -f system/xbin/su
mkfs.ext4 -q -F -d '$work_dir' '$rootfs_new' ${SIZE_MB}M
mv '$rootfs_new' '$VOL_PATH/xenoid-rootfs.img'
printf '%s' '$digest' > '$VOL_PATH/xenoid-rootfs.img.sha256'
rm -rf '$work_dir'
EOF
)"
  trap - EXIT
  echo "rootfs image rebuilt"
fi

DATA_PATH="$VOL_PATH/xenoid-data.img"
SOURCE_VOL_PATH=""
if [[ "$DATA_ACTION" == "migrate" ]]; then
  [[ "$LEGACY_VOLUME" != "-" ]] || { echo "legacy volume required for migrate" >&2; exit 2; }
  SOURCE_VOL_PATH="$("${DOCKER[@]}" volume inspect "$LEGACY_VOLUME" --format '{{.Mountpoint}}')"
  [[ -n "$SOURCE_VOL_PATH" ]] || { echo "cannot resolve legacy Docker volume" >&2; exit 1; }
fi

data_info="$(host_sh "$(cat <<EOF
set -eu
target='$DATA_PATH'
tmp='$VOL_PATH/.xenoid-data.img.$STORAGE_TRANSACTION.new'
action='$DATA_ACTION'
expected_uuid='$EXPECTED_UUID'
legacy_volume_path='$SOURCE_VOL_PATH'
backup_image='$BACKUP_IMAGE'
backup_uuid='$BACKUP_UUID'
volume_path='$VOL_PATH'
data_size_mb='$DATA_SIZE_MB'

lower_uuid() { printf '%s' "\$1" | tr 'A-F' 'a-f'; }
valid_image() {
  [ -f "\$1" ] && [ ! -L "\$1" ] && [ -s "\$1" ] &&
    [ "\$(blkid -p -s TYPE -o value -- "\$1" 2>/dev/null)" = ext4 ]
}
image_uuid() { blkid -p -s UUID -o value -- "\$1" | tr 'A-F' 'a-f'; }
image_size() { stat -c %s -- "\$1"; }
emit() {
  printf 'XENOID_DATA_UUID=%s\n' "\$(image_uuid "\$1")"
  printf 'XENOID_DATA_SIZE=%s\n' "\$(image_size "\$1")"
}

case "\$action" in
  preserve)
    valid_image "\$target" || { echo 'persistent data image missing or invalid' >&2; exit 41; }
    actual="\$(image_uuid "\$target")"
    [ "\$expected_uuid" = - ] || [ "\$actual" = "\$(lower_uuid "\$expected_uuid")" ] ||
      { echo 'persistent data image UUID mismatch' >&2; exit 42; }
    emit "\$target"
    ;;
  initialize)
    [ '$STORAGE_TRANSACTION' != - ] || { echo 'storage transaction required' >&2; exit 43; }
    if valid_image "\$target"; then
      emit "\$target"
      exit 0
    fi
    [ ! -e "\$target" ] || { echo 'refusing to replace invalid data image' >&2; exit 44; }
    for candidate in "\$volume_path"/.xenoid-data.img.*.new; do
      [ ! -e "\$candidate" ] || [ "\$candidate" = "\$tmp" ] ||
        { echo 'unexpected data-image transaction file' >&2; exit 45; }
    done
    if [ -e "\$tmp" ] && ! valid_image "\$tmp"; then
      rm -f -- "\$tmp"
    fi
    if [ ! -e "\$tmp" ]; then
      truncate -s "\${data_size_mb}M" "\$tmp"
      mkfs.ext4 -q -F "\$tmp"
      sync -f "\$tmp"
    fi
    valid_image "\$tmp" || { echo 'initialized data image is invalid' >&2; exit 46; }
    mv -- "\$tmp" "\$target"
    sync -f "\$volume_path"
    emit "\$target"
    ;;
  migrate)
    [ '$STORAGE_TRANSACTION' != - ] || { echo 'storage transaction required' >&2; exit 47; }
    source="\$legacy_volume_path/xenoid-data.img"
    valid_image "\$source" || { echo 'legacy data image missing or invalid' >&2; exit 48; }
    source_uuid="\$(image_uuid "\$source")"
    [ "\$expected_uuid" != - ] && [ "\$source_uuid" = "\$(lower_uuid "\$expected_uuid")" ] ||
      { echo 'legacy data image UUID mismatch' >&2; exit 49; }
    if valid_image "\$target" && [ "\$(image_uuid "\$target")" = "\$source_uuid" ]; then
      emit "\$target"
      exit 0
    fi
    if [ -e "\$target" ]; then
      valid_image "\$target" || { echo 'target data image is invalid' >&2; exit 50; }
      [ "\$backup_image" != - ] && [ "\$backup_uuid" != - ] ||
        { echo 'target backup identity required' >&2; exit 51; }
      backup="\$volume_path/\$backup_image"
      if [ -e "\$backup" ]; then
        valid_image "\$backup" && [ "\$(image_uuid "\$backup")" = "\$(lower_uuid "\$backup_uuid")" ] ||
          { echo 'target backup identity mismatch' >&2; exit 52; }
        { echo 'target and backup both exist' >&2; exit 53; }
      fi
      [ "\$(image_uuid "\$target")" = "\$(lower_uuid "\$backup_uuid")" ] ||
        { echo 'target data image changed before backup' >&2; exit 54; }
      mv -- "\$target" "\$backup"
      sync -f "\$volume_path"
    elif [ "\$backup_image" != - ]; then
      backup="\$volume_path/\$backup_image"
      valid_image "\$backup" && [ "\$(image_uuid "\$backup")" = "\$(lower_uuid "\$backup_uuid")" ] ||
        { echo 'pending target backup is missing or invalid' >&2; exit 55; }
    fi
    for candidate in "\$volume_path"/.xenoid-data.img.*.new; do
      [ ! -e "\$candidate" ] || [ "\$candidate" = "\$tmp" ] ||
        { echo 'unexpected data-image transaction file' >&2; exit 56; }
    done
    if [ -e "\$tmp" ] && { ! valid_image "\$tmp" || [ "\$(image_uuid "\$tmp")" != "\$source_uuid" ]; }; then
      rm -f -- "\$tmp"
    fi
    if [ ! -e "\$tmp" ]; then
      cp --sparse=always -- "\$source" "\$tmp"
      sync -f "\$tmp"
    fi
    valid_image "\$tmp" && [ "\$(image_uuid "\$tmp")" = "\$source_uuid" ] ||
      { echo 'copied legacy data image is invalid' >&2; exit 57; }
    mv -- "\$tmp" "\$target"
    sync -f "\$volume_path"
    emit "\$target"
    ;;
esac
EOF
)" )"
printf '%s\n' "$data_info"
echo "OK rootfs=$VOL_PATH/xenoid-rootfs.img data=$DATA_PATH action=$DATA_ACTION"
