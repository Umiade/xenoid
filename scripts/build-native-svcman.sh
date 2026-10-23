#!/usr/bin/env bash
# Build the servicemanager dependency that restores the stock isolated_app
# service inventory restriction on kernels without SELinux.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="${1:-arm64}"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
NDK="$(xenoid_ndk_require "$SDK")" || exit 1
if [[ "$ARCH" == x86_64 ]]; then TOOL=x86_64-linux-android24-clang; else TOOL=aarch64-linux-android24-clang; fi
BIN="$(xenoid_ndk_tool "$NDK" "$TOOL")" || true
if [[ -z "$BIN" ]]; then # fall back to the API21 toolchain if the host NDK omits API24
  if [[ "$ARCH" == x86_64 ]]; then TOOL=x86_64-linux-android21-clang; else TOOL=aarch64-linux-android21-clang; fi
  BIN="$(xenoid_ndk_tool "$NDK" "$TOOL")" || true
fi
[[ -n "$BIN" ]] || { echo "$TOOL not found in $NDK" >&2; exit 1; }
SUF=""; [[ "$ARCH" == x86_64 ]] && SUF="-x86_64"
OUT="$ROOT/native/xenoid-svcman/libxenoid_svcman$SUF.so"
"$BIN" -O2 -fPIC -shared -Wall -Wextra -fstack-protector-strong \
  -Wl,-z,global -D_FORTIFY_SOURCE=2 \
  -o "$OUT" \
  "$ROOT/native/xenoid-svcman/xenoid_svcman.c" \
  -ldl
echo "$OUT"
