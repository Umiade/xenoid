#!/usr/bin/env bash
# Rotate per-device filesystem identity on one stopped instance's persistent
# images: data/rootfs ext4 UUIDs, the per-app SSAID store, and the live storage
# sentinel. The caller owns the Docker volume and the crash-safe storage
# transaction in private instance state; this script is idempotent so an
# interrupted rotation converges on retry.
#
# Usage: rotate-storage-identity.sh VOLUME EXPECTED_DATA_UUID TARGET_DATA_UUID EXPECTED_ROOTFS_UUID EXPECTED_ROOTFS_SOURCE_SHA256 EXPECTED_ROOTFS_SIZE TARGET_ROOTFS_UUID
# Each image accepts only its recorded EXPECTED→TARGET transition (or an
# already-TARGET resume). Any third identity, source, geometry, missing image,
# geometry mismatch fails closed.
# Requires: docker, e2fsprogs (blkid/tune2fs/e2fsck/debugfs) on the Docker
# engine host. The owned Android container must be absent.
set -euo pipefail
VOLUME="${1:-}"
EXPECTED_UUID="${2:-}"
TARGET_UUID="${3:-}"
EXPECTED_ROOTFS_UUID="${4:-}"
EXPECTED_ROOTFS_SOURCE_SHA256="${5:-}"
EXPECTED_ROOTFS_SIZE="${6:-}"
TARGET_ROOTFS_UUID="${7:-}"
[[ "$VOLUME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || { echo "invalid volume" >&2; exit 2; }
UUID36_RE='^[0-9a-fA-F-]{36}$'
[[ "$EXPECTED_UUID" =~ $UUID36_RE ]] || { echo "invalid expected data UUID" >&2; exit 2; }
[[ "$TARGET_UUID" =~ $UUID36_RE ]] || { echo "invalid target data UUID" >&2; exit 2; }
[[ "$EXPECTED_ROOTFS_UUID" =~ $UUID36_RE ]] || { echo "invalid expected rootfs UUID" >&2; exit 2; }
[[ "$EXPECTED_ROOTFS_SOURCE_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid expected rootfs source" >&2; exit 2; }
[[ "$EXPECTED_ROOTFS_SIZE" =~ ^[1-9][0-9]*$ ]] || { echo "invalid expected rootfs size" >&2; exit 2; }
[[ "$TARGET_ROOTFS_UUID" =~ $UUID36_RE ]] || { echo "invalid target rootfs UUID" >&2; exit 2; }
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

VOL_PATH="$("${DOCKER[@]}" volume inspect "$VOLUME" --format '{{.Mountpoint}}')"
[[ -n "$VOL_PATH" ]] || { echo "cannot resolve Docker volume $VOLUME" >&2; exit 1; }

host_sh "$(cat <<EOF
set -eu
data='$VOL_PATH/xenoid-data.img'
rootfs='$VOL_PATH/xenoid-rootfs.img'
expected='$EXPECTED_UUID'
target='$TARGET_UUID'
expected_rootfs='$EXPECTED_ROOTFS_UUID'
expected_rootfs_source='$EXPECTED_ROOTFS_SOURCE_SHA256'
expected_rootfs_size='$EXPECTED_ROOTFS_SIZE'
target_rootfs='$TARGET_ROOTFS_UUID'

lower_uuid() { printf '%s' "\$1" | tr 'A-F' 'a-f'; }
image_uuid() { blkid -p -s UUID -o value -- "\$1" | tr 'A-F' 'a-f'; }
logical_size() { stat -c %s -- "\$1"; }
filesystem_size() {
  set -- \$(tune2fs -l "\$1" 2>/dev/null | awk -F: '
    /Block count:/ { gsub(/[[:space:]]/, "", \$2); blocks=\$2 }
    /Block size:/ { gsub(/[[:space:]]/, "", \$2); size=\$2 }
    END { print blocks, size }
  ')
  [ "\$#" -eq 2 ] && [ "\$1" -gt 0 ] && [ "\$2" -gt 0 ] || return 1
  printf '%s\n' "\$((\$1 * \$2))"
}
fsck_image() {
  set +e
  e2fsck -pf "\$1"
  fsck_status=\$?
  set -e
  [ "\$fsck_status" -le 1 ] || { echo "e2fsck failed for \$1" >&2; exit 59; }
}

[ -f "\$data" ] && [ ! -L "\$data" ] && [ -s "\$data" ] &&
  [ "\$(blkid -p -s TYPE -o value -- "\$data" 2>/dev/null)" = ext4 ] ||
  { echo 'persistent data image missing or invalid' >&2; exit 41; }

expected="\$(lower_uuid "\$expected")"
target="\$(lower_uuid "\$target")"
expected_rootfs="\$(lower_uuid "\$expected_rootfs")"
target_rootfs="\$(lower_uuid "\$target_rootfs")"
current="\$(image_uuid "\$data")"
[ "\$current" = "\$expected" ] || [ "\$current" = "\$target" ] ||
  { echo 'persistent data image UUID matches neither the pending expectation nor the rotation target' >&2; exit 42; }
[ "\$(logical_size "\$data")" = 128000000000 ] &&
  [ "\$(filesystem_size "\$data")" = 128000000000 ] ||
  { echo 'persistent data geometry mismatch' >&2; exit 58; }
[ -f "\$rootfs" ] && [ ! -L "\$rootfs" ] && [ -s "\$rootfs" ] &&
  [ "\$(blkid -p -s TYPE -o value -- "\$rootfs" 2>/dev/null)" = ext4 ] ||
  { echo 'persistent rootfs image missing or invalid' >&2; exit 41; }
rootfs_current="\$(image_uuid "\$rootfs")"
[ "\$rootfs_current" = "\$expected_rootfs" ] ||
  [ "\$rootfs_current" = "\$target_rootfs" ] ||
  { echo 'persistent rootfs image UUID matches neither the pending expectation nor the rotation target' >&2; exit 42; }
source_marker='$VOL_PATH/xenoid-rootfs.img.source.sha256'
[ -f "\$source_marker" ] && [ ! -L "\$source_marker" ] &&
  [ "\$(stat -c %u -- "\$source_marker")" = 0 ] ||
  { echo 'persistent rootfs source marker is unsafe' >&2; exit 41; }
[ "\$(cat "\$source_marker")" = "\$expected_rootfs_source" ] ||
  { echo 'persistent rootfs source marker mismatch' >&2; exit 41; }
[ "\$(logical_size "\$rootfs")" = "\$expected_rootfs_size" ] &&
  [ "\$(filesystem_size "\$rootfs")" = "\$expected_rootfs_size" ] ||
  { echo 'persistent rootfs geometry mismatch' >&2; exit 58; }
rotated=0
fsck_image "\$data"
if [ "\$current" = "\$expected" ]; then
  tune2fs -U "\$target" "\$data" >/dev/null ||
    { echo 'data image UUID rotation failed' >&2; exit 60; }
  sync -f "\$data"
  current="\$(image_uuid "\$data")"
  [ "\$current" = "\$target" ] ||
    { echo 'data image UUID rotation verification failed' >&2; exit 60; }
  rotated=1
elif [ "\$current" != "\$target" ]; then
  echo 'persistent data image UUID matches neither the pending expectation nor the rotation target' >&2
  exit 42
fi

# Per-app SSAID store: deleting the file makes SettingsProvider mint fresh
# per-signing-identity values on next boot. The device-wide secure Android ID
# is re-applied by normal profile convergence. Absence is already-rotated.
remove_data_file() {
  debugfs -w -R "rm \$1" "\$data" >/dev/null 2>&1 || true
  if debugfs -R "stat \$1" "\$data" 2>/dev/null | grep -q 'Inode: '; then
    echo "failed to remove \$1 from the data image" >&2
    exit 63
  fi
}
remove_data_file 'system/users/0/settings_ssaid.xml'
# The live sentinel binds the instance to the previous filesystem UUID; the
# next start recreates it against the rotated identity.
remove_data_file 'local/tmp/runtime-state/storage-sentinel.v1'
sync -f "\$data"

fsck_image "\$rootfs"
if [ "\$rootfs_current" = "\$expected_rootfs" ]; then
  tune2fs -U "\$target_rootfs" "\$rootfs" >/dev/null ||
    { echo 'rootfs image UUID rotation failed' >&2; exit 60; }
  sync -f "\$rootfs"
  rootfs_current="\$(image_uuid "\$rootfs")"
  [ "\$rootfs_current" = "\$target_rootfs" ] ||
    { echo 'rootfs image UUID rotation verification failed' >&2; exit 60; }
  rotated=1
[ "\$(logical_size "\$data")" = 128000000000 ] &&
  [ "\$(filesystem_size "\$data")" = 128000000000 ] ||
  { echo 'rotated data geometry mismatch' >&2; exit 58; }
fi
[ "\$(logical_size "\$rootfs")" = "\$expected_rootfs_size" ] &&
  [ "\$(filesystem_size "\$rootfs")" = "\$expected_rootfs_size" ] ||
  { echo 'rotated rootfs geometry mismatch' >&2; exit 58; }

logical="\$(logical_size "\$data")"
filesystem="\$(filesystem_size "\$data")"
allocated="\$(( \$(stat -c %b -- "\$data") * 512 ))"
set -- \$(df -B1 --output=size,avail "$VOL_PATH" | awk 'NR==2 {print \$1, \$2}')
[ "\$#" -eq 2 ] || { echo 'cannot inspect Docker backing filesystem' >&2; exit 58; }
printf 'XENOID_DATA_UUID=%s\n' "\$current"
printf 'XENOID_DATA_LOGICAL_SIZE=%s\n' "\$logical"
printf 'XENOID_DATA_FILESYSTEM_SIZE=%s\n' "\$filesystem"
printf 'XENOID_DATA_ALLOCATED_SIZE=%s\n' "\$allocated"
printf 'XENOID_DATA_BACKING_TOTAL=%s\n' "\$1"
printf 'XENOID_DATA_BACKING_AVAILABLE=%s\n' "\$2"
printf 'XENOID_DATA_ROTATED=%s\n' "\$rotated"
printf 'XENOID_ROOTFS_UUID=%s\n' "\$rootfs_current"
printf 'XENOID_ROOTFS_SOURCE_SHA256=%s\n' "\$(cat '$VOL_PATH/xenoid-rootfs.img.source.sha256')"
printf 'XENOID_ROOTFS_LOGICAL_SIZE=%s\n' "\$(logical_size "\$rootfs")"
EOF
)"
echo "OK storage identity rotated for $VOLUME"
