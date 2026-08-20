#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
from typing import Any
import zipfile
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from xenoid.sensitive import SensitiveByteScanner

RELEASE_SCHEMA = "dev.xenoid.release/v1"
VERIFY_SCHEMA = "dev.xenoid.release-verification/v1"
_MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
_MAX_MEMBERS = 20_000
_MAX_TEXT_BYTES = 8 * 1024 * 1024
_MAX_OTA_BYTES = 512 * 1024 * 1024
_MAX_EXPANDED_BYTES = 4 * 1024 * 1024 * 1024
_REQUIRED = {
    "LICENSE",
    "NOTICE",
    "LICENSES/Apache-2.0.txt",
    "LICENSES/GPL-2.0-only.txt",
    "README.md",
    "README_CN.md",
    "RUNBOOK.md",
    "doctor.json",
    "gate-evidence.json",
    "manifest.json",
    "bin/xenoid",
    "bin/xenoid-mcp",
    "bin/xenoid-service",
    "src/xenoid/gates.py",
    "src/xenoid/sensitive.py",
    "src/xenoid/process.py",
    "src/xenoid/doctor.py",
    "src/xenoid/live_observe.py",
    "scripts/verify.sh",
    "scripts/ci.sh",
    "scripts/audit-sensitive-data.py",
    "scripts/canonical-tar.py",
    "scripts/run-bounded-command.py",
    "scripts/make-ota-bundle.sh",
    "scripts/package-release.sh",
    "scripts/verify-release.py",
    "daemon/app/build/outputs/apk/debug/app-debug.apk",
    "artifacts/xenoid-daemon.apk",
    "artifacts/xenoid-rootd-arm64",
    "artifacts/xenoid-keymint",
    "artifacts/xenoid-proxy-sandbox",
    "native/xenoid-keymint/xenoid-keymint",
    "native/xenoid-proxy-sandbox/xenoid-proxy-sandbox",
}
_ARTIFACT_PAIRS = {
    "artifacts/xenoid-daemon.apk": "daemon/app/build/outputs/apk/debug/app-debug.apk",
    "artifacts/xenoid-input": "native/xenoid-input/xenoid-input",
    "artifacts/xenoid-hide-helper": "native/xenoid-hide/xenoid-hide",
    "artifacts/xenoid-profile-helper": "native/xenoid-profile/xenoid-profile",
    "artifacts/xenoid-netctl": "native/xenoid-netctl/xenoid-netctl",
    "artifacts/xenoid-rootd-arm64": "native/xenoid-rootd/xenoid-rootd-arm64",
    "artifacts/xenoid-keymint": "native/xenoid-keymint/xenoid-keymint",
    "artifacts/xenoid-proxy-sandbox": "native/xenoid-proxy-sandbox/xenoid-proxy-sandbox",
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
    "scripts/xenoid-proxy-sandbox": "native/xenoid-proxy-sandbox/xenoid-proxy-sandbox",
    "artifacts/libxenoid-ril.so": "native/xenoid-ril/libxenoid-ril.so",
    "artifacts/android.hardware.radio.config-service.xenoid": "native/xenoid-radio-config/android.hardware.radio.config-service.xenoid",
}
_TEXT_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".java", ".json", ".md", ".py", ".sh", ".txt", ".xml", ".yml", ".yaml"}


def _check(checks: list[dict[str, Any]], name: str, ok: bool, error: str | None = None) -> None:
    value: dict[str, Any] = {"name": name, "ok": bool(ok)}
    if not ok:
        value["errorCode"] = error or "release_check_failed"
    checks.append(value)


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _sha_stream(
    stream: Any,
    capture_limit: int = _MAX_TEXT_BYTES,
    *,
    scan_private: bool = False,
) -> tuple[str, bytes | None, bytes, bool]:
    digest = hashlib.sha256()
    captured = bytearray()
    prefix = bytearray()
    scanner = SensitiveByteScanner() if scan_private else None
    keep = True
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        if scanner is not None:
            scanner.feed(chunk)
        if len(prefix) < 64:
            prefix.extend(chunk[: 64 - len(prefix)])
        if keep and len(captured) + len(chunk) <= capture_limit:
            captured.extend(chunk)
        else:
            keep = False
            captured.clear()
    return (
        digest.hexdigest(),
        bytes(captured) if keep else None,
        bytes(prefix),
        bool(scanner and scanner.findings),
    )


def _arm64_elf(data: bytes | None) -> bool:
    return bool(
        data is not None
        and len(data) >= 64
        and data[:6] == b"\x7fELF\x02\x01"
        and int.from_bytes(data[18:20], "little") == 183
    )



def _canonical_nested_archive(data: bytes | None, epoch: int) -> bool:
    if (
        data is None
        or len(data) < 10
        or data[:2] != b"\x1f\x8b"
        or int.from_bytes(data[4:8], "little") != epoch
    ):
        return False
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            members = archive.getmembers()
    except (OSError, tarfile.TarError):
        return False
    names = [member.name for member in members]
    safe_names = all(
        not PurePosixPath(name).is_absolute()
        and ".." not in PurePosixPath(name).parts
        and bool(PurePosixPath(name).parts)
        for name in names
    )
    roots = {
        PurePosixPath(name).parts[0]
        for name in names
        if PurePosixPath(name).parts
    }
    return bool(
        members
        and len(members) <= _MAX_MEMBERS
        and safe_names
        and len(roots) == 1
        and names == sorted(names, key=lambda value: value.encode("utf-8"))
        and len(names) == len(set(names))
        and all(
            not member.issym()
            and not member.islnk()
            and (member.isdir() or member.isfile())
            and member.uid == 0
            and member.gid == 0
            and member.uname == ""
            and member.gname == ""
            and member.mtime == epoch
            and not member.pax_headers
            and member.mode
            == (0o755 if member.isdir() or member.mode & 0o111 else 0o644)
            for member in members
        )
    )



def _zip_private_content(data: bytes | None) -> bool:
    if data is None:
        return True
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if (
                len(entries) > _MAX_MEMBERS
                or sum(entry.file_size for entry in entries) > _MAX_OTA_BYTES
            ):
                return True
            for entry in entries:
                path = PurePosixPath(entry.filename)
                if path.is_absolute() or ".." in path.parts or entry.is_dir():
                    continue
                with archive.open(entry) as stream:
                    if _sha_stream(stream, 0, scan_private=True)[3]:
                        return True
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile):
        return True
    return False


def _ota_payloads_valid(data: bytes | None) -> bool:
    if data is None:
        return False
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            members = {
                member.name: member
                for member in archive.getmembers()
                if member.isfile()
            }
            manifest_names = [
                name for name in members if name.endswith("/manifest.json")
            ]
            if len(manifest_names) != 1:
                return False
            root = manifest_names[0].rsplit("/", 1)[0]
            stream = archive.extractfile(members[manifest_names[0]])
            manifest_bytes = stream.read() if stream is not None else b""
            manifest = json.loads(manifest_bytes) if manifest_bytes else None
            if (
                not isinstance(manifest, dict)
                or manifest.get("schema") != "dev.xenoid.ota/v1"
            ):
                return False
            payloads = manifest.get("payloads")
            expected_paths = {
                "daemonApk": "payload/xenoid-daemon.apk",
                "inputHelper": "payload/xenoid-input",
                "hideHelper": "payload/xenoid-hide-helper",
                "profileHelper": "payload/xenoid-profile-helper",
                "netctlHelper": "payload/xenoid-netctl",
            }
            if manifest.get("apply") != list(expected_paths):
                return False
            expected_members = {manifest_names[0]} | {
                f"{root}/{relative}" for relative in expected_paths.values()
            }
            if set(members) != expected_members:
                return False
            if _canonical_json(manifest) != manifest_bytes:
                return False
            if not isinstance(payloads, dict) or set(payloads) != set(expected_paths):
                return False
            for key, relative in expected_paths.items():
                value = payloads.get(key)
                if not isinstance(value, dict) or value.get("path") != relative:
                    return False
                expected = value.get("sha256")
                member = members.get(f"{root}/{relative}")
                payload_stream = (
                    archive.extractfile(member) if member is not None else None
                )
                if payload_stream is None or not isinstance(expected, str):
                    return False
                payload = payload_stream.read()
                scanner = SensitiveByteScanner()
                scanner.feed(payload)
                if (
                    scanner.findings
                    or hashlib.sha256(payload).hexdigest() != expected
                ):
                    return False
    except (OSError, ValueError, tarfile.TarError):
        return False
    return True


def _self_check(root: Path) -> int:
    checks: list[dict[str, Any]] = []
    package = (root / "scripts/package-release.sh").read_text(encoding="utf-8")
    verifier = (root / "scripts/verify-release.py").read_text(encoding="utf-8")
    canonical = root / "scripts/canonical-tar.py"
    _check(checks, "fresh-gate-owner", "xenoid.gates release --fresh" in package)
    _check(checks, "artifact-snapshot", "ArtifactBuilder" in package and ".stage(" in package)
    _check(checks, "canonical-ota", "make-ota-bundle.sh" in package and canonical.is_file())
    _check(checks, "canonical-release", "canonical-tar.py" in package)
    _check(checks, "mandatory-verification", "verify-release.py" in package and "archiveSha256" in verifier)
    _check(
        checks,
        "bounded-release-tools",
        package.count("run-bounded-command.py") >= 3,
    )
    _check(checks, "no-audit-bypass", ("XENOID_" + "SKIP_AUDIT") not in package + verifier)
    report = {
        "schema": "dev.xenoid.release-source-check/v1",
        "ok": all(item["ok"] for item in checks),
        "checks": checks,
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["ok"] else 1


def verify(archive: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "schema": VERIFY_SCHEMA,
        "ok": False,
        "archive": archive.name,
        "checks": checks,
    }
    try:
        descriptor = os.open(
            archive,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        stream = os.fdopen(descriptor, "rb")
        info = os.fstat(stream.fileno())
    except OSError:
        report["errorCode"] = "release_archive_missing"
        return report
    if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_ARCHIVE_BYTES:
        stream.close()
        report["errorCode"] = "release_archive_invalid"
        return report
    digest = hashlib.sha256()
    prefix = b""
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        if not prefix:
            prefix = chunk[:10]
        digest.update(chunk)
    report["archiveSha256"] = digest.hexdigest()
    if len(prefix) < 10 or prefix[:2] != b"\x1f\x8b":
        stream.close()
        report["errorCode"] = "release_gzip_invalid"
        return report
    gzip_mtime = int.from_bytes(prefix[4:8], "little")
    stream.seek(0)
    try:
        tar = tarfile.open(fileobj=stream, mode="r:gz")
    except (OSError, tarfile.TarError):
        stream.close()
        report["errorCode"] = "release_tar_invalid"
        return report
    with stream, tar:
        members = tar.getmembers()
        if not members or len(members) > _MAX_MEMBERS:
            report["errorCode"] = "release_member_count_invalid"
            return report
        if sum(member.size for member in members if member.isfile()) > _MAX_EXPANDED_BYTES:
            report["errorCode"] = "release_expanded_size_invalid"
            return report
        names = [member.name for member in members]
        _check(checks, "canonical-member-order", names == sorted(names, key=lambda value: value.encode("utf-8")), "release_member_order_invalid")
        _check(checks, "unique-members", len(names) == len(set(names)), "release_duplicate_member")
        roots = {PurePosixPath(name).parts[0] for name in names if PurePosixPath(name).parts}
        if len(roots) != 1:
            report["errorCode"] = "release_root_invalid"
            return report
        root_name = next(iter(roots))
        files: dict[str, dict[str, Any]] = {}
        file_bytes: dict[str, bytes] = {}
        file_prefixes: dict[str, bytes] = {}
        canonical_metadata = True
        safe_members = True
        private_content = False
        private_content_paths: list[str] = []
        for member in members:
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] != root_name:
                safe_members = False
                continue
            if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                safe_members = False
                continue
            expected_mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
            canonical_metadata = canonical_metadata and (
                member.uid == 0
                and member.gid == 0
                and member.uname == ""
                and member.gname == ""
                and member.mode == expected_mode
                and member.mtime == gzip_mtime
                and not member.pax_headers
            )
            if not member.isfile():
                continue
            relative = PurePosixPath(*pure.parts[1:]).as_posix()
            stream = tar.extractfile(member)
            if stream is None:
                safe_members = False
                continue
            if (
                (
                    relative.startswith("artifacts/xenoid-")
                    and relative.endswith(".tar.gz")
                )
                or relative.endswith(".apk")
            ):
                capture_limit = _MAX_OTA_BYTES
            elif PurePosixPath(relative).suffix.lower() in _TEXT_SUFFIXES:
                capture_limit = _MAX_TEXT_BYTES
            else:
                capture_limit = 0
            digest, captured, prefix, marker_found = _sha_stream(
                stream,
                capture_limit,
                scan_private=True,
            )
            if marker_found:
                private_content_paths.append(relative)
                private_content = True
            files[relative] = {
                "sha256": digest,
                "size": member.size,
                "mode": member.mode,
            }
            if captured is not None:
                file_bytes[relative] = captured
            file_prefixes[relative] = prefix
        _check(checks, "safe-members", safe_members, "release_member_unsafe")
        _check(checks, "canonical-member-metadata", canonical_metadata, "release_member_metadata_invalid")

    manifest_bytes = file_bytes.get("manifest.json")
    try:
        manifest = json.loads(manifest_bytes) if manifest_bytes is not None else None
    except json.JSONDecodeError:
        manifest = None
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "sourceDateEpoch", "gateEvidenceSha256", "files"}:
        report["errorCode"] = "release_manifest_invalid"
        return report
    _check(checks, "manifest-canonical-json", manifest_bytes == _canonical_json(manifest), "release_manifest_not_canonical")
    epoch = manifest.get("sourceDateEpoch")
    _check(checks, "source-date-epoch", isinstance(epoch, int) and not isinstance(epoch, bool) and epoch >= 0 and gzip_mtime == epoch, "release_epoch_mismatch")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        report["errorCode"] = "release_manifest_invalid"
        return report
    listed: dict[str, dict[str, Any]] = {}
    valid_entries = True
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "mode", "size", "sha256"}:
            valid_entries = False
            continue
        path = entry.get("path")
        if not isinstance(path, str) or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts or path in listed:
            valid_entries = False
            continue
        listed[path] = entry
    _check(checks, "manifest-entries", valid_entries and list(listed) == sorted(listed, key=lambda value: value.encode("utf-8")), "release_manifest_entries_invalid")
    actual_without_manifest = set(files) - {"manifest.json"}
    _check(checks, "manifest-complete", set(listed) == actual_without_manifest, "release_manifest_incomplete")
    manifest_hashes_ok = all(
        path in files
        and files[path]["sha256"] == entry.get("sha256")
        and files[path]["size"] == entry.get("size")
        and files[path]["mode"] == entry.get("mode")
        for path, entry in listed.items()
    )
    _check(checks, "manifest-hashes", manifest_hashes_ok, "release_manifest_hash_mismatch")
    _check(checks, "required-files", _REQUIRED <= set(files), "release_required_file_missing")

    gate_bytes = file_bytes.get("gate-evidence.json")
    try:
        gate_evidence = json.loads(gate_bytes) if gate_bytes is not None else None
    except json.JSONDecodeError:
        gate_evidence = None
    gate_ok = (
        isinstance(gate_evidence, dict)
        and gate_evidence.get("schema") == "dev.xenoid.gates/v1"
        and gate_evidence.get("ok") is True
        and gate_evidence.get("profile") == "release"
        and gate_evidence.get("fresh") is True
        and gate_evidence.get("failedGate") is None
        and isinstance(gate_evidence.get("gates"), dict)
        and gate_evidence["gates"].get("sensitive-data", {}).get("cacheHit") is False
    )
    gate_digest = hashlib.sha256(gate_bytes or b"").hexdigest()
    _check(checks, "fresh-gate-evidence", gate_ok and manifest.get("gateEvidenceSha256") == gate_digest, "release_gate_evidence_invalid")

    doctor_bytes = file_bytes.get("doctor.json")
    try:
        doctor = json.loads(doctor_bytes) if doctor_bytes is not None else None
    except json.JSONDecodeError:
        doctor = None
    doctor_ok = (
        isinstance(doctor, dict)
        and doctor.get("schema") == "dev.xenoid.doctor/v1"
        and doctor.get("complete") is False
        and doctor.get("runtimeAvailable") is False
        and doctor.get("runtimeRequired") is False
        and doctor.get("sections", {}).get("offlineBuildEvidence", {}).get("complete") is False
        and doctor.get("sections", {}).get("offlineBuildEvidence", {}).get("gateEvidenceSha256") == gate_digest
    )
    _check(checks, "offline-doctor-evidence", doctor_ok, "release_doctor_evidence_invalid")

    pair_ok = all(
        alias in files and source in files and files[alias]["sha256"] == files[source]["sha256"]
        for alias, source in _ARTIFACT_PAIRS.items()
    )
    _check(checks, "artifact-aliases", pair_ok, "release_artifact_mismatch")
    _check(checks, "keymint-arm64", _arm64_elf(file_prefixes.get("artifacts/xenoid-keymint")), "release_keymint_invalid")
    _check(checks, "proxy-sandbox-arm64", _arm64_elf(file_prefixes.get("artifacts/xenoid-proxy-sandbox")), "release_proxy_sandbox_invalid")
    non_elf_aliases = {
        "artifacts/xenoid-daemon.apk",
        "artifacts/android.hardware.sensors.ISensors.xml",
        "artifacts/android.hardware.camera.provider.ICameraProvider.xml",
        "artifacts/media_profiles_V1_0.xml",
    }
    elf_aliases = set(_ARTIFACT_PAIRS) - non_elf_aliases
    _check(
        checks,
        "all-arm64-artifacts",
        all(
            _arm64_elf(file_prefixes.get(path))
            and files.get(path, {}).get("mode") == 0o755
            for path in elf_aliases
        ),
        "release_artifact_architecture_invalid",
    )

    private_paths = [
        path
        for path in files
        if path.startswith(".xenoid/")
        or PurePosixPath(path).suffix.lower() in {".pem", ".zip"}
        or ".keybox-upload-" in path.lower()
        or PurePosixPath(path).name.lower()
        in {"keybox.xml", "keybox.json", "keybox.pem", "keybox.der"}
    ]
    _check(checks, "private-path-exclusion", not private_paths, "release_private_path")
    nested_private_paths = [
        path
        for path in files
        if path.endswith(".apk")
        and _zip_private_content(file_bytes.get(path))
    ]
    if nested_private_paths:
        private_content = True
        private_content_paths.extend(nested_private_paths)
    if private_content_paths:
        report["privateContentPaths"] = sorted(
            set(private_content_paths),
            key=lambda value: value.encode("utf-8"),
        )[:64]
    _check(checks, "private-content-exclusion", not private_content, "release_private_content")

    ota_paths = sorted(path for path in files if path.startswith("artifacts/xenoid-") and path.endswith(".tar.gz"))
    _check(checks, "canonical-ota-present", len(ota_paths) == 1, "release_ota_missing")
    if len(ota_paths) == 1:
        ota_ok = (
            _canonical_nested_archive(file_bytes.get(ota_paths[0]), epoch)
            and _ota_payloads_valid(file_bytes.get(ota_paths[0]))
        )
        _check(checks, "canonical-ota", ota_ok, "release_ota_not_canonical")

    report["releaseSchema"] = manifest.get("schema")
    report["fileCount"] = len(files)
    report["ok"] = manifest.get("schema") == RELEASE_SCHEMA and all(item["ok"] for item in checks)
    if not report["ok"]:
        report["errorCode"] = next((item["errorCode"] for item in checks if not item["ok"]), "release_verification_failed")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", nargs="?", type=Path)
    parser.add_argument("--self-check", action="store_true")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if arguments.self_check:
        return _self_check(root)
    if arguments.archive is None:
        parser.error("archive is required")
    report = verify(arguments.archive.resolve())
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report.get("ok") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
