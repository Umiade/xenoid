#!/usr/bin/env bash

# Print the configured Android SDK root, or the host's conventional location.
xenoid_android_sdk_root() {
  if [[ -n "${ANDROID_HOME:-}" ]]; then
    printf '%s\n' "$ANDROID_HOME"
    return
  fi
  if [[ -n "${ANDROID_SDK_ROOT:-}" ]]; then
    printf '%s\n' "$ANDROID_SDK_ROOT"
    return
  fi
  if [[ "$(uname -s)" == "Darwin" ]]; then
    printf '%s\n' "$HOME/Library/Android/sdk"
  else
    printf '%s\n' "$HOME/Android/Sdk"
  fi
}

# Xenoid builds against one pinned NDK: the camera, sensors, and radio stable
# AIDL HALs need android/binder_enums.h, which NDK 28 and newer no longer ship.
# ANDROID_NDK_HOME/ANDROID_NDK_ROOT are explicit operator overrides.
xenoid_ndk_version() {
  printf '%s\n' "${XENOID_NDK_VERSION:-27.2.12479018}"
}

# Print the selected NDK root, or fail with an install hint.
xenoid_ndk_require() {
  local sdk="$1" ndk candidate
  for candidate in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}"; do
    if [[ -n "$candidate" && -d "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  ndk="$sdk/ndk/$(xenoid_ndk_version)"
  if [[ ! -d "$ndk" ]]; then
    printf 'Android NDK %s not found at %s; install it with: sdkmanager "ndk;%s"\n' \
      "$(xenoid_ndk_version)" "$ndk" "$(xenoid_ndk_version)" >&2
    return 1
  fi
  printf '%s\n' "$ndk"
}

# Print the host LLVM prebuilt directory for one NDK.
xenoid_ndk_prebuilt() {
  local ndk="$1" tag
  for tag in darwin-arm64 darwin-x86_64 linux-x86_64; do
    if [[ -x "$ndk/toolchains/llvm/prebuilt/$tag/bin/llvm-strip" ]]; then
      printf '%s\n' "$ndk/toolchains/llvm/prebuilt/$tag"
      return 0
    fi
  done
  return 1
}

# Print one target tool from the selected NDK's host prebuilt.
xenoid_ndk_tool() {
  local ndk="$1" tool="$2" prebuilt
  prebuilt="$(xenoid_ndk_prebuilt "$ndk")" || return 1
  [[ -x "$prebuilt/bin/$tool" ]] || return 1
  printf '%s\n' "$prebuilt/bin/$tool"
}
