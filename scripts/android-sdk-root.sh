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
