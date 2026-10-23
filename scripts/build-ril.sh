#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
ARCH="${1:-arm64}"
if [[ "$ARCH" == "x86_64" ]]; then
  TOOL="x86_64-linux-android30-clang"
else
  TOOL="aarch64-linux-android30-clang"
fi
NDK="$(xenoid_ndk_require "$SDK")" || exit 127
COMPILER="$(xenoid_ndk_tool "$NDK" "$TOOL")" || { echo "$TOOL not found in $NDK" >&2; exit 127; }
OUT="$ROOT/native/xenoid-ril/libxenoid-ril.so"
"$COMPILER" -std=c11 -O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
  -fvisibility=hidden -ffunction-sections -fdata-sections \
  -I"$ROOT/native/xenoid-ril/include" \
  -shared -Wl,-soname,libxenoid-ril.so,-z,defs,--gc-sections,-z,relro,-z,now \
  -o "$OUT" "$ROOT/native/xenoid-ril/xenoid_ril.c" -llog
"$COMPILER" -std=c11 -O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
  -DXENOID_RIL_HOST_TEST -I"$ROOT/native/xenoid-ril/include" \
  -Wl,-z,defs,-z,relro,-z,now \
  -o "$ROOT/native/xenoid-ril/xenoid-ril-profile-test" \
  "$ROOT/native/xenoid-ril/xenoid_ril.c" -llog
printf '%s\n' "$OUT"
