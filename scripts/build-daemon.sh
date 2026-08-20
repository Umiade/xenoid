#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/daemon"
JOBS="${XENOID_BUILD_JOBS:-1}"
FORCE="${XENOID_FORCE_REBUILD:-0}"
[[ "$JOBS" =~ ^[1-9][0-9]*$ && "$FORCE" =~ ^[01]$ ]] || {
  echo "invalid artifact build allocation" >&2
  exit 64
}
GRADLE_ARGS=(--no-daemon "--max-workers=$JOBS")
[[ "$FORCE" == "1" ]] && GRADLE_ARGS+=(--rerun-tasks)
if [[ "${XENOID_STANDALONE_APK:-0}" == "1" ]]; then
  exec "$ROOT/scripts/build-daemon-standalone.sh"
elif [[ -x ./gradlew ]]; then
  ./gradlew "${GRADLE_ARGS[@]}" assembleDebug
elif command -v gradle >/dev/null 2>&1; then
  gradle "${GRADLE_ARGS[@]}" assembleDebug
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
