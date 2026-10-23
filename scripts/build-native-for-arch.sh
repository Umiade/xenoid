#!/usr/bin/env bash
set -euo pipefail
NAME="$1"; SRC="$2"; OUT="$3"; ARCH="${4:-x86_64}"; LINK="${5:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
API="${XENOID_ANDROID_API:-21}"
if [[ "$LINK" == "static" && "$API" -lt 29 ]]; then
  # Android's arm64 loader rejects a static executable whose PT_TLS segment is
  # underaligned. NDK 27's static Bionic emits alignment 8 below API 29; Xenoid
  # targets Android 13, so static helpers use the first native-TLS API level.
  API=29
fi
case "$ARCH" in x86_64) TOOL="x86_64-linux-android${API}-clang";; arm64|aarch64) TOOL="aarch64-linux-android${API}-clang";; *) echo "bad arch $ARCH" >&2; exit 2;; esac
NDK="$(xenoid_ndk_require "$SDK")" || exit 127
BIN="$(xenoid_ndk_tool "$NDK" "$TOOL")" || { echo "$TOOL not found in $NDK" >&2; exit 127; }
EXTRA=()
[[ "$LINK" == "static" ]] && EXTRA+=(-static)
"$BIN" -O2 -s -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 "${EXTRA[@]}" -o "$OUT" "$SRC"
echo "$OUT"
