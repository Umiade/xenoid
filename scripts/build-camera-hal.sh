#!/usr/bin/env bash
# Build the Android AIDL camera provider service for arm64.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HAL="$ROOT/native/xenoid-camerahal"
SERVICE="android.hardware.camera.provider-service-aidl"
ARCH="${1:-arm64}"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
AIDL_BIN="$SDK/build-tools/35.0.0/aidl"
[[ -x "$AIDL_BIN" ]] || AIDL_BIN="$(ls -d "$SDK"/build-tools/*/aidl 2>/dev/null | sort -V | tail -1)"
if [[ "$ARCH" == x86_64 ]]; then
  TOOL=x86_64-linux-android30-clang++
  TRIPLE=x86_64-linux-android
else
  TOOL=aarch64-linux-android30-clang++
  TRIPLE=aarch64-linux-android
fi
NDK=""
PRE=""
for candidate in "$SDK"/ndk/* "${ANDROID_NDK_HOME:-}"; do
  [[ -d "$candidate" ]] || continue
  for prebuilt in "$candidate"/toolchains/llvm/prebuilt/*; do
    if [[ -f "$prebuilt/sysroot/usr/include/android/binder_enums.h" && -x "$prebuilt/bin/$TOOL" ]]; then
      NDK="$candidate"
      PRE="$prebuilt"
    fi
  done
done
[[ -n "$NDK" && -n "$PRE" ]] || { echo "no compatible NDK with android/binder_enums.h and $TOOL found under $SDK" >&2; exit 1; }
CXX="$PRE/bin/$TOOL"
SYSROOT="$PRE/sysroot"

GEN="$HAL/gen"
rm -rf "$GEN"
mkdir -p "$GEN"
while IFS= read -r aidl; do
  case "$aidl" in
    */android/hardware/camera/provider/*)
      version=1; hash=5904a53ea55472ca9b45b731cb148c65d1090ba5 ;;
    */android/hardware/camera/device/*)
      version=1; hash=ef5889d8da1473ff5dfc481b9ce32a3f173ea048 ;;
    */android/hardware/camera/common/*)
      version=1; hash=d1a423213d80e15de2b10e54d908ac5c29644fef ;;
    */android/hardware/camera/metadata/*)
      version=1; hash=070719d32c4dd88360ee5ccc25f70280374a0a89 ;;
    */android/hardware/common/fmq/*)
      version=1; hash=6a780550f6e6965d6969fd7964c3ca81b6b0ccdf ;;
    */android/hardware/common/*)
      version=2; hash=c32ddfdeb69c6e4a8a45519e6f9a39c4b66fd99f ;;
    */android/hardware/graphics/common/*)
      version=3; hash=e7e8b0bd7cd27ab4f1998700ef19ebc82e022d87 ;;
    *)
      echo "unknown AIDL package: $aidl" >&2
      exit 1 ;;
  esac
  "$AIDL_BIN" --lang=ndk --structured --stability=vintf --min_sdk_version=30 \
    --version "$version" --hash "$hash" \
    -o"$GEN" -h"$GEN" -p"$HAL/framework-min.aidl" -I"$HAL/aidl" "$aidl"
done < <(find "$HAL/aidl" -name '*.aidl' | sort)
python3 "$ROOT/scripts/sanitize-aidl-output.py" "$GEN"


pull_system_lib() {
  local name="$1"
  [[ -f "$HAL/$name" ]] && return
  local container_name
  container_name="$(PYTHONPATH="$ROOT/src" python3 -c 'import os; from pathlib import Path; from xenoid.config import resolve_instance; c,g,l=resolve_instance(project_root=Path.cwd(), env={}); print(l.container_name)' 2>/dev/null || echo xenoid-android)"
  docker cp "${container_name}:/system/lib64/$name" "$HAL/$name" >/dev/null 2>&1 || {
    local image="${XENOID_BASE_IMAGE:-redroid/redroid:13.0.0_64only-latest}"
    local cid
    cid="$(docker create "$image")"
    docker cp "$cid:/system/lib64/$name" "$HAL/$name"
    docker rm "$cid" >/dev/null
  }
}
pull_system_lib libbinder_ndk.so
pull_system_lib libcamera_metadata.so

SRCS=(
  "$HAL/camera_provider.cpp"
  "$HAL/camera_device.cpp"
  "$HAL/camera_session.cpp"
  "$HAL/camera_metadata.cpp"
  "$HAL/camera_buffer.cpp"
  "$HAL/camera_renderer.cpp"
  "$HAL/camera_source.cpp"
)
while IFS= read -r source; do
  SRCS+=("$source")
done < <(find "$GEN" -name '*.cpp' | sort)
OUTPUT="$HAL/$SERVICE"
rm -f "$HAL/xenoid-camerahal"
CXXFLAGS=(
  -std=c++17
  -O2
  -fPIC
  -ffunction-sections
  -fdata-sections
  -fstack-protector-strong
  -fvisibility=hidden
  -fvisibility-inlines-hidden
  -fno-rtti
  -D_FORTIFY_SOURCE=2
  "-ffile-prefix-map=$HAL=android/hardware/camera/provider/default"
  "-fmacro-prefix-map=$HAL=android/hardware/camera/provider/default"
  "-ffile-prefix-map=$SDK=android-sdk"
  "-fmacro-prefix-map=$SDK=android-sdk"
  --sysroot="$SYSROOT"
  -I"$GEN"
  -I"$SYSROOT/usr/include"
)
"$CXX" "${CXXFLAGS[@]}" -o "$OUTPUT" "${SRCS[@]}" \
  -L"$SYSROOT/usr/lib/$TRIPLE/30" \
  "$HAL/libcamera_metadata.so" "$HAL/libbinder_ndk.so" \
  -landroid -llog -lmediandk -ljnigraphics -static-libstdc++ \
  -Wl,-z,defs,--gc-sections,--exclude-libs,ALL,-s

for marker in xenoid mock replay; do
  if LC_ALL=C strings "$OUTPUT" | grep -Fi "$marker" >/dev/null; then
    echo "provider artifact contains prohibited marker: $marker" >&2
    exit 1
  fi
done

echo "$OUTPUT"
