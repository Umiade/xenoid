#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
API="${ANDROID_API:-35}"
BT="${ANDROID_BUILD_TOOLS:-$SDK/build-tools/35.0.0}"
ANDROID_JAR="$SDK/platforms/android-$API/android.jar"
APP="$ROOT/daemon/app/src/main"
OUT="$ROOT/daemon/build/standalone"
APK_OUT="$ROOT/daemon/app/build/outputs/apk/debug/app-debug.apk"

for tool in "$BT/aapt2" "$BT/d8" "$BT/zipalign" "$BT/apksigner" javac keytool zip; do
  if [[ "$tool" == */* ]]; then [[ -x "$tool" ]] || { echo "missing $tool" >&2; exit 127; }
  else command -v "$tool" >/dev/null 2>&1 || { echo "missing $tool" >&2; exit 127; }
  fi
done
[[ -f "$ANDROID_JAR" ]] || { echo "missing $ANDROID_JAR" >&2; exit 127; }

rm -rf "$OUT"
mkdir -p "$OUT/res" "$OUT/classes" "$OUT/dex" "$(dirname "$APK_OUT")" "$ROOT/.xenoid"

"$BT/aapt2" compile --dir "$APP/res" -o "$OUT/res.zip"
"$BT/aapt2" link -o "$OUT/linked.apk" -I "$ANDROID_JAR" --manifest "$APP/AndroidManifest.xml" -R "$OUT/res.zip" --auto-add-overlay --rename-manifest-package dev.xenoid.daemon

find "$APP/java" -name '*.java' | sort > "$OUT/sources.txt"
javac -source 8 -target 8 -classpath "$ANDROID_JAR" -d "$OUT/classes" @"$OUT/sources.txt"
"$BT/d8" --lib "$ANDROID_JAR" --output "$OUT/dex" $(find "$OUT/classes" -name '*.class' | sort)
cp "$OUT/linked.apk" "$OUT/unaligned.apk"
(cd "$OUT/dex" && zip -q -u "$OUT/unaligned.apk" classes.dex)
"$BT/zipalign" -f 4 "$OUT/unaligned.apk" "$OUT/aligned.apk"
KEYSTORE="$ROOT/.xenoid/debug.keystore"
if [[ ! -f "$KEYSTORE" ]]; then
  keytool -genkeypair -keystore "$KEYSTORE" -storepass android -keypass android -alias androiddebugkey -dname "CN=Android Debug,O=Android,C=US" -keyalg RSA -keysize 2048 -validity 10000 >/dev/null
fi
"$BT/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:android --key-pass pass:android --out "$APK_OUT" "$OUT/aligned.apk"
"$BT/apksigner" verify "$APK_OUT"
printf '%s\n' "$APK_OUT"
