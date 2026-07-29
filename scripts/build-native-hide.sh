#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
cd "$ROOT/native/xenoid-hide"
try_add_ndk_bin() {
  local ndk="$1"
  for prebuilt in darwin-x86_64 darwin-arm64 linux-x86_64; do
    local candidate="$ndk/toolchains/llvm/prebuilt/$prebuilt/bin"
    if [[ -x "$candidate/aarch64-linux-android21-clang" ]]; then export PATH="$candidate:$PATH"; return 0; fi
  done
  return 1
}
if ! command -v aarch64-linux-android21-clang >/dev/null 2>&1; then
  [[ -n "${ANDROID_NDK_HOME:-}" ]] && try_add_ndk_bin "$ANDROID_NDK_HOME" || true
fi
if ! command -v aarch64-linux-android21-clang >/dev/null 2>&1 && [[ -d "$SDK/ndk" ]]; then
  while IFS= read -r ndk; do try_add_ndk_bin "$ndk" && break || true; done < <(find "$SDK/ndk" -mindepth 1 -maxdepth 1 -type d | sort -Vr)
fi
command -v aarch64-linux-android21-clang >/dev/null 2>&1 || { echo "aarch64-linux-android21-clang not found" >&2; exit 127; }
make clean all CC=aarch64-linux-android21-clang
printf '%s\n' "$ROOT/native/xenoid-hide/xenoid-hide"
