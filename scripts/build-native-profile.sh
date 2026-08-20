#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
cd "$ROOT/native/xenoid-profile"
try_add_ndk_bin() {
  local ndk="$1"
  for prebuilt in darwin-x86_64 darwin-arm64 linux-x86_64; do
    local candidate="$ndk/toolchains/llvm/prebuilt/$prebuilt/bin"
    [[ -x "$candidate/aarch64-linux-android21-clang" ]] && export PATH="$candidate:$PATH" && return 0
  done
  return 1
}
if ! command -v aarch64-linux-android21-clang >/dev/null 2>&1; then [[ -n "${ANDROID_NDK_HOME:-}" ]] && try_add_ndk_bin "$ANDROID_NDK_HOME" || true; fi
if ! command -v aarch64-linux-android21-clang >/dev/null 2>&1 && [[ -d "$SDK/ndk" ]]; then while IFS= read -r ndk; do try_add_ndk_bin "$ndk" && break || true; done < <(find "$SDK/ndk" -mindepth 1 -maxdepth 1 -type d | sort -Vr); fi
command -v aarch64-linux-android21-clang >/dev/null 2>&1 || { echo "aarch64-linux-android21-clang not found" >&2; exit 127; }
JOBS="${XENOID_BUILD_JOBS:-1}"
FORCE="${XENOID_FORCE_REBUILD:-0}"
[[ "$JOBS" =~ ^[1-9][0-9]*$ && "$FORCE" =~ ^[01]$ ]] || {
  echo "invalid artifact build allocation" >&2
  exit 64
}
MAKE_ARGS=(-j"$JOBS")
[[ "$FORCE" == "1" ]] && MAKE_ARGS+=(-B)
make "${MAKE_ARGS[@]}" all CC=aarch64-linux-android21-clang
printf '%s\n' "$ROOT/native/xenoid-profile/xenoid-profile"
