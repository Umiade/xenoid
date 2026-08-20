#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-dev}"
if [[ ${#VERSION} -gt 64 || ! "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "release_version_invalid" >&2
  exit 64
fi
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
if ! [[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]]; then
  echo "source_date_epoch_invalid" >&2
  exit 64
fi
export PYTHONDONTWRITEBYTECODE=1
RELEASE_DEADLINE="$(python3 -c 'import time; print(time.monotonic()+7200)')"
RELEASE_ROOT="$ROOT/dist/release"
mkdir -p "$RELEASE_ROOT"
STAGE="$(mktemp -d "$RELEASE_ROOT/.release-stage.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
REL="$STAGE/xenoid-$VERSION"
ARTIFACT_STAGE="$STAGE/artifact-snapshot"
CANDIDATE="$STAGE/xenoid-$VERSION.tar.gz"
ARCHIVE="$RELEASE_ROOT/xenoid-$VERSION.tar.gz"
mkdir -p "$REL" "$ARTIFACT_STAGE"

capture_inventory() {
  ROOT="$ROOT" OUTPUT="$1" PYTHONPATH="$ROOT/src" python3 - <<'PY'
import json
import os
from pathlib import Path
import sys
import time
from xenoid.process import run_bounded

root = Path(os.environ["ROOT"])
result = run_bounded(
    [sys.executable, "scripts/audit-sensitive-data.py", "--inventory-digest"],
    cwd=root,
    deadline=time.monotonic() + 180.0,
    project_root=root,
)
if not result.ok:
    raise SystemExit("release_source_inventory_unavailable")
evidence = json.loads(result.stdout_tail)
if set(evidence) != {"count", "sha256"}:
    raise SystemExit("release_source_inventory_invalid")
Path(os.environ["OUTPUT"]).write_text(
    json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
}
capture_inventory "$STAGE/source-before.json"
# Direct release calls consume the same fresh, non-recursive gate owner as CI.
PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}" \
  python3 -m xenoid.gates release --fresh > "$STAGE/raw-gate-evidence.json"
RAW_GATES="$STAGE/raw-gate-evidence.json" OUTPUT="$REL/gate-evidence.json" python3 - <<'PY'
import json
import os
from pathlib import Path

raw = json.loads(Path(os.environ["RAW_GATES"]).read_text(encoding="utf-8"))
if (
    raw.get("schema") != "dev.xenoid.gates/v1"
    or raw.get("ok") is not True
    or raw.get("profile") != "release"
    or raw.get("fresh") is not True
    or raw.get("failedGate") is not None
    or not isinstance(raw.get("gates"), dict)
):
    raise SystemExit("release_gate_evidence_invalid")
gates = {}
for name, result in sorted(raw["gates"].items()):
    if not isinstance(name, str) or not isinstance(result, dict):
        raise SystemExit("release_gate_evidence_invalid")
    gates[name] = {
        "state": result.get("state"),
        "cacheHit": result.get("cacheHit"),
        "inputSha256": result.get("inputSha256"),
    }
evidence = {
    "schema": "dev.xenoid.gates/v1",
    "ok": True,
    "profile": "release",
    "fresh": True,
    "failedGate": None,
    "gates": gates,
}
Path(os.environ["OUTPUT"]).write_text(
    json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY

ROOT="$ROOT" ARTIFACT_STAGE="$ARTIFACT_STAGE" RELEASE_DEADLINE="$RELEASE_DEADLINE" PYTHONPATH="$ROOT/src" python3 - <<'PY'
import os
from pathlib import Path
from xenoid.artifacts import ArtifactBuilder, CONSUMER_TARGETS

root = Path(os.environ["ROOT"])
destination = Path(os.environ["ARTIFACT_STAGE"])
builder = ArtifactBuilder(root)
result = builder.ensure(
    CONSUMER_TARGETS["release"],
    deadline=float(os.environ["RELEASE_DEADLINE"]),
)
if result.get("ok") is not True:
    raise SystemExit("release_artifacts_failed")
snapshot = builder.snapshot("release")
builder.stage(snapshot, destination)
PY


XENOID_ARTIFACT_ROOT="$ARTIFACT_STAGE" XENOID_OTA_OUTPUT_ROOT="$STAGE/ota" \
  SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  "$ROOT/scripts/run-bounded-command.py" --deadline "$RELEASE_DEADLINE" \
  "$ROOT/scripts/make-ota-bundle.sh" "$VERSION" >/dev/null
OTA_BUNDLE="$STAGE/ota/xenoid-$VERSION.tar.gz"

ROOT="$ROOT" REL="$REL" ARTIFACT_STAGE="$ARTIFACT_STAGE" \
OTA_BUNDLE="$OTA_BUNDLE" SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" python3 - <<'PY'
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import time

sys.path.insert(0, str(Path(os.environ["ROOT"]) / "src"))
from xenoid.process import run_bounded

root = Path(os.environ["ROOT"])
release = Path(os.environ["REL"])
artifact_root = Path(os.environ["ARTIFACT_STAGE"])
epoch = int(os.environ["SOURCE_DATE_EPOCH"], 10)

allowed_files = {
    ".gitignore",
    "AGENTS.md",
    "LICENSE",
    "NOTICE",
    "README.md",
    "README_CN.md",
    "pyproject.toml",
    "setup.py",
    "xenoid",
    "xenoid-mcp",
    "xenoid-service",
}
allowed_prefixes = (
    ".githooks/",
    ".github/",
    "LICENSES/",
    "daemon/",
    "data/",
    "docs/",
    "examples/",
    "frida/",
    "mcp/",
    "modules/",
    "native/",
    "runtime/",
    "scripts/",
    "skills/",
    "src/",
    "tests/",
)
def copy_stable_source(source: Path, destination: Path) -> None:
    try:
        before = source.lstat()
        descriptor = os.open(
            source,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise SystemExit("release_source_type_invalid") from exc
    try:
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or identity
            != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            )
        ):
            raise SystemExit("release_source_type_invalid")
        destination.parent.mkdir(parents=True, exist_ok=True)
        output = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_TRUNC
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(output, view)
                    view = view[written:]
        finally:
            os.close(output)
        after = os.fstat(descriptor)
        current = source.lstat()
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or identity != (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
        ):
            raise SystemExit("release_source_changed")
        destination.chmod(0o755 if before.st_mode & 0o111 else 0o644)
    finally:
        os.close(descriptor)


captured = bytearray()
inventory = run_bounded(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    cwd=root,
    deadline=time.monotonic() + 60.0,
    project_root=root,
    stdout_consumer=captured.extend,
)
if not inventory.ok:
    raise SystemExit("release_source_inventory_unavailable")
tracked = bytes(captured)
missing_sources: list[Path] = []
for raw in tracked.split(b"\0"):
    if not raw:
        continue
    relative = raw.decode("utf-8")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts:
        raise SystemExit("release_source_inventory_invalid")
    if relative not in allowed_files and not relative.startswith(allowed_prefixes):
        raise SystemExit("release_source_not_allowlisted")
    source = root / relative
    destination = release / relative
    try:
        source.lstat()
    except FileNotFoundError:
        missing_sources.append(source)
        continue
    except OSError as exc:
        raise SystemExit("release_source_type_invalid") from exc
    copy_stable_source(source, destination)
for source in missing_sources:
    try:
        source.lstat()
    except FileNotFoundError:
        continue
    except OSError as exc:
        raise SystemExit("release_source_changed") from exc
    raise SystemExit("release_source_changed")

# Materialize the validated immutable artifact snapshot over source-tree paths.
for source in sorted(artifact_root.rglob("*"), key=lambda item: item.as_posix().encode()):
    if not source.is_file() or source.is_symlink():
        continue
    relative = source.relative_to(artifact_root)
    destination = release / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)

(release / "bin").mkdir(exist_ok=True)
for name in ("xenoid", "xenoid-mcp", "xenoid-service"):
    shutil.copyfile(root / name, release / "bin" / name)
    (release / "bin" / name).chmod(0o755)

aliases = {
    "artifacts/xenoid-daemon.apk": "daemon/app/build/outputs/apk/debug/app-debug.apk",
    "artifacts/xenoid-input": "native/xenoid-input/xenoid-input",
    "artifacts/xenoid-hide-helper": "native/xenoid-hide/xenoid-hide",
    "artifacts/xenoid-profile-helper": "native/xenoid-profile/xenoid-profile",
    "artifacts/xenoid-netctl": "native/xenoid-netctl/xenoid-netctl",
    "artifacts/xenoid-rootd-arm64": "native/xenoid-rootd/xenoid-rootd-arm64",
    "artifacts/libxenoid_zygote.so": "native/xenoid-zygote/libxenoid_zygote.so",
    "artifacts/libxenoid_shim-arm64.so": "native/xenoid-shim/libxenoid_shim-arm64.so",
    "artifacts/xenoid-pivot": "native/xenoid-pivot/xenoid-pivot",
    "artifacts/xenoid-sensorshal": "native/xenoid-sensorshal/xenoid-sensorshal",
    "artifacts/android.hardware.sensors.ISensors.xml": "native/xenoid-sensorshal/android.hardware.sensors.ISensors.xml",
    "artifacts/android.hardware.camera.provider-service-aidl": "native/xenoid-camerahal/android.hardware.camera.provider-service-aidl",
    "artifacts/android.hardware.camera.provider.ICameraProvider.xml": "native/xenoid-camerahal/android.hardware.camera.provider.ICameraProvider.xml",
    "artifacts/media_profiles_V1_0.xml": "native/xenoid-camerahal/media_profiles_V1_0.xml",
    "artifacts/gralloc.redroid.so": "native/xenoid-gralloc/gralloc.redroid.so",
    "artifacts/hwcomposer.raven.so": "native/xenoid-hwcomposer/hwcomposer.raven.so",
    "artifacts/xenoid-overlay-helper": "native/xenoid-hide/xenoid-overlay",
    "artifacts/xenoid-prop-area": "native/xenoid-hide/xenoid-prop-area",
    "artifacts/xenoid-ssaid": "native/xenoid-hide/xenoid-ssaid",
    "artifacts/xenoid-proxy-sandbox": "native/xenoid-proxy-sandbox/xenoid-proxy-sandbox",
    "artifacts/libxenoid-ril.so": "native/xenoid-ril/libxenoid-ril.so",
    "artifacts/android.hardware.radio.config-service.xenoid": "native/xenoid-radio-config/android.hardware.radio.config-service.xenoid",
    "artifacts/xenoid-keymint": "native/xenoid-keymint/xenoid-keymint",
    "scripts/xenoid-proxy-sandbox": "native/xenoid-proxy-sandbox/xenoid-proxy-sandbox",
}
for destination_name, source_name in aliases.items():
    source = artifact_root / source_name
    if not source.is_file() or source.is_symlink():
        raise SystemExit("release_artifact_snapshot_invalid")
    destination = release / destination_name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)

ota = Path(os.environ["OTA_BUNDLE"])
if not ota.is_file() or ota.is_symlink():
    raise SystemExit("release_ota_invalid")
(release / "artifacts").mkdir(exist_ok=True)
shutil.copyfile(ota, release / "artifacts" / ota.name)
(release / "artifacts" / ota.name).chmod(0o644)

(release / "config").mkdir(exist_ok=True)
for name in ("config-macos-colima.json", "config-linux-arm.json"):
    shutil.copyfile(root / "examples" / name, release / "config" / name)
    (release / "config" / name).chmod(0o644)

runbook = """# Xenoid Release Runbook

Use `./bin/xenoid up --skip-build` for production convergence from validated
release artifacts. Use `./bin/xenoid doctor --require-runtime` for a fresh,
strictly observational runtime report. Keep credentials and private runtime
state outside this extracted release directory.
"""
(release / "RUNBOOK.md").write_text(runbook, encoding="utf-8")
(release / "RUNBOOK.md").chmod(0o644)

gate_bytes = (release / "gate-evidence.json").read_bytes()
doctor = {
    "schema": "dev.xenoid.doctor/v1",
    "ok": True,
    "complete": False,
    "full": False,
    "runtimeRequired": False,
    "runtimeAvailable": False,
    "checks": [{"name": "offlineBuildEvidence", "ok": True}],
    "sections": {
        "offlineBuildEvidence": {
            "ok": True,
            "complete": False,
            "gateEvidenceSha256": hashlib.sha256(gate_bytes).hexdigest(),
            "reason": "offline-release-no-live-runtime-observation",
        }
    },
    "nextActions": [],
}
(release / "doctor.json").write_text(
    json.dumps(doctor, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
(release / "doctor.json").chmod(0o644)

# Normalize before manifesting; the archive writer independently enforces this.
for path in sorted(release.rglob("*"), key=lambda item: item.as_posix().encode()):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
        raise SystemExit("release_member_type_invalid")
    path.chmod(0o755 if stat.S_ISDIR(info.st_mode) or info.st_mode & 0o111 else 0o644)
    os.utime(path, (epoch, epoch), follow_symlinks=False)

files = []
for path in sorted(
    (item for item in release.rglob("*") if item.is_file()),
    key=lambda item: item.relative_to(release).as_posix().encode(),
):
    relative = path.relative_to(release).as_posix()
    if relative == "manifest.json":
        continue
    info = path.stat()
    files.append(
        {
            "path": relative,
            "mode": stat.S_IMODE(info.st_mode),
            "size": info.st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    )
manifest = {
    "schema": "dev.xenoid.release/v1",
    "sourceDateEpoch": epoch,
    "gateEvidenceSha256": hashlib.sha256(gate_bytes).hexdigest(),
    "files": files,
}
(release / "manifest.json").write_text(
    json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
(release / "manifest.json").chmod(0o644)
os.utime(release / "manifest.json", (epoch, epoch))
os.utime(release, (epoch, epoch))
PY
capture_inventory "$STAGE/source-after.json"
BEFORE="$STAGE/source-before.json" AFTER="$STAGE/source-after.json" python3 - <<'PY'
from pathlib import Path
import os
if Path(os.environ["BEFORE"]).read_bytes() != Path(os.environ["AFTER"]).read_bytes():
    raise SystemExit("release_source_changed")
PY


SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  "$ROOT/scripts/run-bounded-command.py" --deadline "$RELEASE_DEADLINE" \
  "$ROOT/scripts/canonical-tar.py" "$REL" "$CANDIDATE"
if ! "$ROOT/scripts/run-bounded-command.py" --deadline "$RELEASE_DEADLINE" \
  "$ROOT/scripts/verify-release.py" "$CANDIDATE" > "$STAGE/verify-release.json"; then
  VERIFY="$STAGE/verify-release.json" python3 - <<'PY'
import json
import os
from pathlib import Path
try:
    value = json.loads(Path(os.environ["VERIFY"]).read_text(encoding="utf-8"))
except (OSError, ValueError):
    value = {}
code = value.get("errorCode") or value.get("error")
paths = value.get("privateContentPaths")
result = {
    "errorCode": (
        code if isinstance(code, str) else "release_verification_failed"
    ),
}
if isinstance(paths, list) and all(isinstance(path, str) for path in paths):
    result["paths"] = paths[:64]
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
PY
  exit 1
fi
CANDIDATE="$CANDIDATE" VERIFY="$STAGE/verify-release.json" python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

archive = Path(os.environ["CANDIDATE"])
report = json.loads(Path(os.environ["VERIFY"]).read_text())
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
if report.get("ok") is not True or report.get("archiveSha256") != digest:
    raise SystemExit("release_verification_failed")
PY
mv -f "$CANDIDATE" "$ARCHIVE"
ARCHIVE="$ARCHIVE" python3 - <<'PY'
import os
from pathlib import Path
path = Path(os.environ["ARCHIVE"])
fd = os.open(path.parent, os.O_RDONLY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
printf 'dist/release/xenoid-%s.tar.gz\n' "$VERSION"
