#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1
SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
NDK_VERSION="${XENOID_NDK_VERSION:-27.2.12479018}"
BINDER_SETUP='set -e; if ! sudo modprobe binder_linux 2>/dev/null; then sudo apt-get update -qq && sudo apt-get install -y -qq linux-modules-extra-$(uname -r) && sudo modprobe binder_linux; fi; sudo mkdir -p /dev/binderfs; mountpoint -q /dev/binderfs || sudo mount -t binder binder /dev/binderfs; test -e /dev/binderfs/binder-control'

sdkmanager_path() {
  if command -v sdkmanager >/dev/null 2>&1; then
    command -v sdkmanager
    return 0
  fi
  for candidate in \
    /opt/homebrew/bin/sdkmanager \
    /usr/local/bin/sdkmanager \
    /opt/homebrew/share/android-commandlinetools/cmdline-tools/latest/bin/sdkmanager \
    /usr/local/share/android-commandlinetools/cmdline-tools/latest/bin/sdkmanager; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

cmds=(
  "brew install docker colima android-platform-tools scrcpy"
  "brew install --cask temurin@17 android-commandlinetools"
  "sdkmanager --sdk_root=$SDK_ROOT --licenses"
  "sdkmanager --sdk_root=$SDK_ROOT platform-tools platforms;android-35 build-tools;35.0.0 ndk;$NDK_VERSION"
  "colima start --arch aarch64 --vm-type vz --memory 8 --cpu 8"
  "colima ssh -- sh -c '<ensure binder_linux and mount binderfs>'"
  "create .xenoid/config.json from examples/config-macos-colima.json when absent"
)
if [[ "$DRY" == 1 ]]; then
  printf '{"ok":true,"dryRun":true,"commands":['
  first=1
  for command in "${cmds[@]}"; do
    [[ $first -eq 0 ]] && printf ','
    first=0
    python3 -c 'import json,sys; print(json.dumps(sys.argv[1]), end="")' "$command"
  done
  printf ']}\n'
  exit 0
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "install-runtime supports macOS only; install Docker, ADB, JDK, Android SDK, and Android NDK with the Linux package manager" >&2
  exit 2
fi
if [[ "$(uname -m)" != "arm64" ]]; then
  echo "install-runtime requires Apple Silicon" >&2
  exit 2
fi
if ! command -v brew >/dev/null 2>&1; then
  cat >&2 <<'MSG'
Homebrew is required for automatic macOS runtime installation.
Install Homebrew first: https://brew.sh
MSG
  exit 127
fi

brew install docker colima android-platform-tools scrcpy
brew install --cask temurin@17 android-commandlinetools
SDKMANAGER="$(sdkmanager_path)" || {
  echo "sdkmanager was not installed by the android-commandlinetools cask" >&2
  exit 127
}
mkdir -p "$SDK_ROOT"
(
  set +o pipefail
  yes | "$SDKMANAGER" --sdk_root="$SDK_ROOT" --licenses >/dev/null
)
"$SDKMANAGER" --sdk_root="$SDK_ROOT" \
  "platform-tools" \
  "platforms;android-35" \
  "build-tools;35.0.0" \
  "ndk;$NDK_VERSION"

colima start --arch aarch64 --vm-type vz --memory 8 --cpu 8
colima ssh -- sh -c "$BINDER_SETUP"

mkdir -p .xenoid
if [[ ! -f .xenoid/config.json ]]; then
  cp examples/config-macos-colima.json .xenoid/config.json
fi

for command in docker colima adb scrcpy javac; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required command is unavailable after installation: $command" >&2
    exit 127
  }
done
[[ -x "$SDK_ROOT/build-tools/35.0.0/aapt2" ]] || {
  echo "Android build-tools 35.0.0 are unavailable under $SDK_ROOT" >&2
  exit 127
}
[[ -f "$SDK_ROOT/platforms/android-35/android.jar" ]] || {
  echo "Android platform 35 is unavailable under $SDK_ROOT" >&2
  exit 127
}
NDK_CLANG="$(find "$SDK_ROOT/ndk/$NDK_VERSION/toolchains/llvm/prebuilt" -type f -name aarch64-linux-android21-clang -perm -111 -print -quit 2>/dev/null || true)"
[[ -n "$NDK_CLANG" ]] || {
  echo "Android NDK $NDK_VERSION does not provide aarch64-linux-android21-clang" >&2
  exit 127
}
docker info >/dev/null
colima ssh -- test -e /dev/binderfs/binder-control

cat <<'MSG'
Runtime dependencies are ready. Start Xenoid with:
  ./xenoid up
MSG
