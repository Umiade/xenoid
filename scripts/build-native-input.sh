#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
cd "$ROOT/native/xenoid-input"
try_add_ndk_bin() {
  local ndk="$1"
  for prebuilt in darwin-x86_64 darwin-arm64 linux-x86_64; do
    local candidate="$ndk/toolchains/llvm/prebuilt/$prebuilt/bin"
    if [[ -x "$candidate/aarch64-linux-android21-clang" ]]; then
      export PATH="$candidate:$PATH"
      return 0
    fi
  done
  return 1
}
if ! command -v aarch64-linux-android21-clang >/dev/null 2>&1; then
  if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then try_add_ndk_bin "$ANDROID_NDK_HOME" || true; fi
fi
if ! command -v aarch64-linux-android21-clang >/dev/null 2>&1 && [[ -d "$SDK/ndk" ]]; then
  while IFS= read -r ndk; do
    try_add_ndk_bin "$ndk" && break || true
  done < <(find "$SDK/ndk" -mindepth 1 -maxdepth 1 -type d | sort -Vr)
fi
if ! command -v aarch64-linux-android21-clang >/dev/null 2>&1; then
  printf >&2 '%s\n' \
    'aarch64-linux-android21-clang not found.' \
    'Install Android NDK and set ANDROID_NDK_HOME, for example:' \
    "  export ANDROID_NDK_HOME=\"$SDK/ndk/<version>\""
  exit 127
fi
JOBS="${XENOID_BUILD_JOBS:-1}"
FORCE="${XENOID_FORCE_REBUILD:-0}"
[[ "$JOBS" =~ ^[1-9][0-9]*$ && "$FORCE" =~ ^[01]$ ]] || {
  echo "invalid artifact build allocation" >&2
  exit 64
}
MAKE_ARGS=(-j"$JOBS")
[[ "$FORCE" == "1" ]] && MAKE_ARGS+=(-B)
make "${MAKE_ARGS[@]}" all CC=aarch64-linux-android21-clang
printf '%s\n' "$ROOT/native/xenoid-input/xenoid-input"
