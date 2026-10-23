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
NDK="$(xenoid_ndk_require "$SDK")" || exit 1
PRE="$(xenoid_ndk_prebuilt "$NDK")" \
  || { printf 'no compatible Android NDK prebuilt under %s\n' "$NDK" >&2; exit 1; }
if [[ ! -f "$PRE/sysroot/usr/include/android/binder_enums.h" ]]; then
  printf 'Android NDK %s does not provide android/binder_enums.h required by the camera provider AIDL build; use NDK %s\n' \
    "$NDK" "$(xenoid_ndk_version)" >&2
  exit 1
fi
[[ -x "$PRE/bin/$TOOL" ]] || { printf '%s not found in %s\n' "$TOOL" "$NDK" >&2; exit 1; }
CXX="$PRE/bin/$TOOL"
SYSROOT="$PRE/sysroot"

GEN="$HAL/gen"
rm -rf "$GEN"
mkdir -p "$GEN"
source "$ROOT/scripts/hal-build-lib.sh"
camera_aidl_package() {
  case "$1" in
    */android/hardware/camera/provider/*)
      echo "--version 1 --hash 5904a53ea55472ca9b45b731cb148c65d1090ba5" ;;
    */android/hardware/camera/device/*)
      echo "--version 1 --hash ef5889d8da1473ff5dfc481b9ce32a3f173ea048" ;;
    */android/hardware/camera/common/*)
      echo "--version 1 --hash d1a423213d80e15de2b10e54d908ac5c29644fef" ;;
    */android/hardware/camera/metadata/*)
      echo "--version 1 --hash 070719d32c4dd88360ee5ccc25f70280374a0a89" ;;
    */android/hardware/common/fmq/*)
      echo "--version 1 --hash 6a780550f6e6965d6969fd7964c3ca81b6b0ccdf" ;;
    */android/hardware/common/*)
      echo "--version 2 --hash c32ddfdeb69c6e4a8a45519e6f9a39c4b66fd99f" ;;
    */android/hardware/graphics/common/*)
      echo "--version 3 --hash e7e8b0bd7cd27ab4f1998700ef19ebc82e022d87" ;;
    *)
      echo "unknown AIDL package: $1" >&2
      return 1 ;;
  esac
}
find "$HAL/aidl" -name '*.aidl' -print0 | LC_ALL=C sort -z \
  | xenoid_aidl_generate "$AIDL_BIN" "$GEN" camera_aidl_package \
      --lang=ndk --structured --stability=vintf --min_sdk_version=30 \
      -p"$HAL/framework-min.aidl" -I"$HAL/aidl"
python3 "$ROOT/scripts/sanitize-aidl-output.py" "$GEN"

# Service-side binder and camera metadata symbols are absent from the NDK stubs;
# link the pinned on-device libraries (cached outside the source tree).
PLATFORM_LIBS=()
while IFS= read -r lib; do PLATFORM_LIBS+=("$lib"); done \
  < <("$ROOT/scripts/platform-libs.sh" libcamera_metadata.so libbinder_ndk.so)
[[ ${#PLATFORM_LIBS[@]} -eq 2 ]] || { echo "failed to resolve platform libraries" >&2; exit 1; }

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
done < <(find "$GEN" -name '*.cpp' | LC_ALL=C sort)
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
LDFLAGS=(
  -L"$SYSROOT/usr/lib/$TRIPLE/30"
  "${PLATFORM_LIBS[@]}"
  -landroid -llog -lmediandk -ljnigraphics -static-libstdc++
  -Wl,-z,defs,--gc-sections,--exclude-libs,ALL,-s
)
xenoid_compile_link "$CXX" "$OUTPUT" "${XENOID_BUILD_JOBS:-1}"

for marker in xenoid mock replay; do
  if LC_ALL=C strings "$OUTPUT" | grep -Fi "$marker" >/dev/null; then
    echo "provider artifact contains prohibited marker: $marker" >&2
    exit 1
  fi
done

echo "$OUTPUT"
