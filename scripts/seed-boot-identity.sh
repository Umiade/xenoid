#!/usr/bin/env bash
# Pre-seed boot-scoped device identity (boot_id) into a stopped
# instance's data image, so the zygote boot snapshot and the post-boot live
# apply present the same values. Idempotent: safe to re-run before a create.
#
# Usage: seed-boot-identity.sh VOLUME BOOT_ID
# Requires: docker, e2fsprogs (e2fsck/debugfs) on the Docker engine host.
set -euo pipefail
VOLUME="${1:-}"
BOOT_ID="${2:-}"
[[ "$VOLUME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || { echo "invalid volume" >&2; exit 2; }
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
[[ "$BOOT_ID" =~ $UUID_RE ]] || { echo "invalid boot id" >&2; exit 2; }
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
[ -f "\$data" ] && [ ! -L "\$data" ] && [ -s "\$data" ] &&
  [ "\$(blkid -p -s TYPE -o value -- "\$data" 2>/dev/null)" = ext4 ] ||
  { echo 'persistent data image missing or invalid' >&2; exit 41; }
set +e
e2fsck -pf "\$data"
fsck_status=\$?
set -e
[ "\$fsck_status" -le 1 ] || { echo 'data image e2fsck failed' >&2; exit 59; }

# Only a previously-converged image has a zygote snapshot to stay coherent
# with. On a fresh image there is nothing to match: the first device apply
# writes these files live, and debugfs-created directories would carry no
# SELinux label, so never create the tree offline. The caller forces one extra
# recreate after first convergence to close the first-boot window.
if ! debugfs -R 'stat local/tmp/xenoid-profile' "\$data" 2>/dev/null | grep -q 'Inode: '; then
  echo 'profile directory absent; skipping boot identity seed' >&2
  echo 'XENOID_BOOT_SEED=skipped'
  exit 0
fi

write_data_file() {
  # write_data_file <image-path> <content>
  stage="/tmp/.xenoid-seed-\$\$"
  printf '%s\n' "\$2" > "\$stage"
  debugfs -w -R "rm \$1" "\$data" >/dev/null 2>&1 || true
  debugfs -w -R "write \$stage \$1" "\$data" >/dev/null 2>&1 ||
    { rm -f "\$stage"; echo "failed to write \$1 into the data image" >&2; exit 63; }
  rm -f "\$stage"
  actual="\$(debugfs -R "cat \$1" "\$data" 2>/dev/null || true)"
  [ "\$actual" = "\$2" ] || { echo "failed to verify \$1 in the data image" >&2; exit 63; }
}
write_data_file 'local/tmp/xenoid-profile/boot_id' '$BOOT_ID'
sync -f "\$data"
EOF
)"
echo "OK boot identity seeded for $VOLUME"
