#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
cd "$ROOT/native/xenoid-input"
NDK="$(xenoid_ndk_require "$SDK")" || exit 127
CC_BIN="$(xenoid_ndk_tool "$NDK" aarch64-linux-android21-clang)" \
  || { echo "aarch64-linux-android21-clang not found in $NDK" >&2; exit 127; }
JOBS="${XENOID_BUILD_JOBS:-1}"
FORCE="${XENOID_FORCE_REBUILD:-0}"
[[ "$JOBS" =~ ^[1-9][0-9]*$ && "$FORCE" =~ ^[01]$ ]] || {
  echo "invalid artifact build allocation" >&2
  exit 64
}
MAKE_ARGS=(-j"$JOBS")
[[ "$FORCE" == "1" ]] && MAKE_ARGS+=(-B)
make "${MAKE_ARGS[@]}" all CC="$CC_BIN"
printf '%s\n' "$ROOT/native/xenoid-input/xenoid-input"
