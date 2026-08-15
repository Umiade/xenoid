#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROBE="$ROOT/tests/gms-identity-probe"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"

latest_dir() {
  python3 - "$@" <<'PY'
import pathlib
import re
import sys
parent = pathlib.Path(sys.argv[1])
required = sys.argv[2:]
candidates = [
    value for value in parent.iterdir()
    if value.is_dir() and all((value / name).exists() for name in required)
] if parent.is_dir() else []
if not candidates:
    raise SystemExit(1)
def version_key(value):
    return tuple(int(part) for part in re.findall(r'\d+', value.name)), value.name
print(max(candidates, key=version_key))
PY
}

BUILD_TOOLS="$(latest_dir "$SDK/build-tools" aapt2 d8 zipalign apksigner)"
PLATFORM="$(latest_dir "$SDK/platforms" android.jar)"
ANDROID_JAR="$PLATFORM/android.jar"
for tool in aapt2 d8 zipalign apksigner; do
  [[ -x "$BUILD_TOOLS/$tool" ]] || { echo "Android build tool is unavailable: $tool" >&2; exit 1; }
done

OUT="$ROOT/dist/gms-identity-probe"
WORK="$OUT/work"
APK="$OUT/gms-identity-probe.apk"
rm -rf "$WORK"
mkdir -p "$WORK/classes" "$WORK/dex"
"$BUILD_TOOLS/aapt2" link -o "$WORK/base.apk" -I "$ANDROID_JAR" --manifest "$PROBE/AndroidManifest.xml"
find "$PROBE/java" -type f -name '*.java' -print | LC_ALL=C sort > "$WORK/sources.txt"
[[ -s "$WORK/sources.txt" ]] || { echo "GMS identity probe Java sources are unavailable" >&2; exit 1; }
javac -encoding UTF-8 -source 8 -target 8 -classpath "$ANDROID_JAR" \
  -d "$WORK/classes" @"$WORK/sources.txt"
classes=()
while IFS= read -r class_file; do classes+=("$class_file"); done < <(
  find "$WORK/classes" -type f -name '*.class' -print | LC_ALL=C sort
)
"$BUILD_TOOLS/d8" --lib "$ANDROID_JAR" --output "$WORK/dex" "${classes[@]}"

cp "$WORK/base.apk" "$WORK/unaligned.apk"
(
  cd "$WORK/dex"
  zip -q -u "$WORK/unaligned.apk" classes.dex
)
"$BUILD_TOOLS/zipalign" -f 4 "$WORK/unaligned.apk" "$WORK/aligned.apk"
KEYSTORE="$OUT/probe.keystore"
if [[ ! -f "$KEYSTORE" ]]; then
  keytool -genkeypair -noprompt -keystore "$KEYSTORE" -storepass android -keypass android \
    -alias probe -keyalg RSA -keysize 2048 -validity 3650 \
    -dname "CN=GMS Identity Probe,O=Example,C=US" >/dev/null 2>&1
fi
"$BUILD_TOOLS/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:android \
  --key-pass pass:android --out "$APK" "$WORK/aligned.apk"
"$BUILD_TOOLS/apksigner" verify "$APK"
printf '%s\n' "$APK"
