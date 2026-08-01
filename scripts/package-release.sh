#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-dev}"
REL="$ROOT/dist/release/xenoid-$VERSION"
ARCHIVE="$ROOT/dist/release/xenoid-$VERSION.tar.gz"
rm -rf "$REL"
mkdir -p "$REL" "$REL/bin" "$REL/artifacts" "$REL/config" "$REL/docs" "$REL/skills" "$REL/examples"
cd "$ROOT"
./xenoid build all >/tmp/xenoid-release-build.json
./xenoid ota make --version "$VERSION" >/tmp/xenoid-release-ota.json
./xenoid runtime-context >/tmp/xenoid-release-runtime-context.json
./xenoid runtime-compose --out dist/docker-compose.yml >/tmp/xenoid-release-compose.json
./xenoid doctor --out "$REL/doctor.json" >/tmp/xenoid-release-doctor.json || true
ROOT_PATH="$ROOT" DOCTOR_PATH="$REL/doctor.json" python3 - <<'PY'
import json, os, pathlib
p = pathlib.Path(os.environ["DOCTOR_PATH"])
root = os.environ["ROOT_PATH"]
home = os.path.expanduser("~")
def scrub(value):
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, str):
        return value.replace(root, "<repo>").replace(home, "~")
    return value
p.write_text(json.dumps(scrub(json.loads(p.read_text())), indent=2) + "\n")
PY
REL="$REL" ROOT="$ROOT" python3 - <<'PY'
import os, pathlib, shutil, subprocess
root = pathlib.Path(os.environ["ROOT"])
release = pathlib.Path(os.environ["REL"])
raw = subprocess.check_output(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    cwd=root,
)
for item in raw.split(b"\0"):
    if not item:
        continue
    relative = pathlib.Path(item.decode())
    source = root / relative
    if not source.is_file():
        continue
    destination = release / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
PY
cp xenoid xenoid-mcp "$REL/bin/"
mkdir -p "$REL/daemon/app/build/outputs/apk/debug"
cp daemon/app/build/outputs/apk/debug/app-debug.apk "$REL/daemon/app/build/outputs/apk/debug/app-debug.apk"
cp daemon/app/build/outputs/apk/debug/app-debug.apk "$REL/artifacts/xenoid-daemon.apk"
cp native/xenoid-input/xenoid-input "$REL/artifacts/xenoid-input"
cp native/xenoid-hide/xenoid-hide "$REL/artifacts/xenoid-hide-helper"
cp native/xenoid-profile/xenoid-profile "$REL/artifacts/xenoid-profile-helper"
cp native/xenoid-netctl/xenoid-netctl "$REL/artifacts/xenoid-netctl"
cp native/xenoid-rootd/xenoid-rootd-arm64 "$REL/artifacts/xenoid-rootd-arm64"
cp native/xenoid-zygote/libxenoid_zygote.so "$REL/artifacts/libxenoid_zygote.so"
cp native/xenoid-shim/libxenoid_shim-arm64.so "$REL/artifacts/libxenoid_shim-arm64.so"
cp native/xenoid-pivot/xenoid-pivot "$REL/artifacts/xenoid-pivot"
cp native/xenoid-sensorshal/xenoid-sensorshal "$REL/artifacts/xenoid-sensorshal"
cp native/xenoid-sensorshal/android.hardware.sensors.ISensors.xml "$REL/artifacts/android.hardware.sensors.ISensors.xml"
cp native/xenoid-camerahal/android.hardware.camera.provider-service-aidl "$REL/artifacts/android.hardware.camera.provider-service-aidl"
cp native/xenoid-camerahal/android.hardware.camera.provider.ICameraProvider.xml "$REL/artifacts/android.hardware.camera.provider.ICameraProvider.xml"
cp native/xenoid-camerahal/media_profiles_V1_0.xml "$REL/artifacts/media_profiles_V1_0.xml"
cp native/xenoid-gralloc/gralloc.redroid.so "$REL/artifacts/gralloc.redroid.so"
cp native/xenoid-hide/xenoid-overlay "$REL/artifacts/xenoid-overlay-helper"
cp native/xenoid-hide/xenoid-prop-area "$REL/artifacts/xenoid-prop-area"
cp native/xenoid-hide/xenoid-ssaid "$REL/artifacts/xenoid-ssaid"
cp native/xenoid-input/xenoid-input "$REL/native/xenoid-input/xenoid-input"
cp native/xenoid-hide/xenoid-hide "$REL/native/xenoid-hide/xenoid-hide"
cp native/xenoid-hide/xenoid-overlay "$REL/native/xenoid-hide/xenoid-overlay"
cp native/xenoid-hide/xenoid-prop-area "$REL/native/xenoid-hide/xenoid-prop-area"
cp native/xenoid-hide/xenoid-ssaid "$REL/native/xenoid-hide/xenoid-ssaid"
cp native/xenoid-profile/xenoid-profile "$REL/native/xenoid-profile/xenoid-profile"
cp native/xenoid-netctl/xenoid-netctl "$REL/native/xenoid-netctl/xenoid-netctl"
cp native/xenoid-rootd/xenoid-rootd-arm64 "$REL/native/xenoid-rootd/xenoid-rootd-arm64"
cp native/xenoid-zygote/libxenoid_zygote.so "$REL/native/xenoid-zygote/libxenoid_zygote.so"
cp native/xenoid-shim/libxenoid_shim-arm64.so "$REL/native/xenoid-shim/libxenoid_shim-arm64.so"
cp native/xenoid-pivot/xenoid-pivot "$REL/native/xenoid-pivot/xenoid-pivot"
cp native/xenoid-sensorshal/xenoid-sensorshal "$REL/native/xenoid-sensorshal/xenoid-sensorshal"
cp native/xenoid-camerahal/android.hardware.camera.provider-service-aidl "$REL/native/xenoid-camerahal/android.hardware.camera.provider-service-aidl"
cp native/xenoid-camerahal/media_profiles_V1_0.xml "$REL/native/xenoid-camerahal/media_profiles_V1_0.xml"
cp native/xenoid-gralloc/gralloc.redroid.so "$REL/native/xenoid-gralloc/gralloc.redroid.so"
cp "$(python3 -c 'import json;print(json.load(open("/tmp/xenoid-release-ota.json"))["bundle"])')" "$REL/artifacts/"
cp examples/config-macos-colima.json examples/config-linux-arm.json "$REL/config/"
cp dist/docker-compose.yml "$REL/config/"
cat > "$REL/RUNBOOK.md" <<'RUNBOOK'
# Xenoid Release Runbook

1. Install runtime dependencies on Apple Silicon macOS:

```bash
./bin/xenoid install-runtime
```

2. Start the complete runtime with prebuilt release artifacts:

```bash
./bin/xenoid up --skip-build
```

`up` performs the startup checks, converges the complete product state, and
finishes with live-runtime validation. Run `./bin/xenoid doctor` separately
only when additional diagnostic evidence is needed.

3. Linux ARM direct Docker:

```bash
mkdir -p .xenoid
cp config/config-linux-arm.json .xenoid/config.json
sudo scripts/setup-linux-binderfs.sh
./bin/xenoid up --skip-build
```
RUNBOOK
REL="$REL" python3 - <<'PY' > "$REL/manifest.json"
import hashlib, json, os, pathlib, time
root=pathlib.Path(os.environ['REL'])
files=[]
for p in sorted(root.rglob('*')):
    if p.is_file():
        h=hashlib.sha256(p.read_bytes()).hexdigest()
        files.append({'path': str(p.relative_to(root)), 'sha256': h, 'size': p.stat().st_size})
print(json.dumps({'schema':'dev.xenoid.release/v1','createdAt':int(time.time()),'files':files}, indent=2))
PY
rm -f "$ARCHIVE"
COPYFILE_DISABLE=1 tar -C "$ROOT/dist/release" -czf "$ARCHIVE" "xenoid-$VERSION"
printf '%s\n' "$ARCHIVE"
