#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/daemon"
if [[ "${XENOID_STANDALONE_APK:-0}" == "1" ]]; then
  exec "$ROOT/scripts/build-daemon-standalone.sh"
elif [[ -x ./gradlew ]]; then
  ./gradlew assembleDebug
elif command -v gradle >/dev/null 2>&1; then
  gradle assembleDebug
else
  echo "Gradle not found; falling back to standalone Android SDK build." >&2
  exec "$ROOT/scripts/build-daemon-standalone.sh"
fi
APK="$ROOT/daemon/app/build/outputs/apk/debug/app-debug.apk"
if [[ -f "$APK" ]]; then
  echo "$APK"
else
  echo "APK not produced at $APK" >&2
  exit 1
fi
