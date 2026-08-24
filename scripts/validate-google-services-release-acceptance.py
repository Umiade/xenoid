#!/usr/bin/env python3
"""Validate the once-per-release microG Google services acceptance evidence.

GateRunner pipes exactly one ``dev.xenoid.gate-dependency-snapshot/v1``
document on stdin (maximum 256 KiB) carrying the current invocation's
normalized ``google-runtime``, ``google-reproducibility``, and
``google-provider-cutover-contract`` results. This validator reads the
operator-owned private evidence document at
``.xenoid/acceptance/google-services/<release>/release-acceptance.json``,
re-observes the live instance, cross-checks every identity, and writes one
bounded canonical ``dev.xenoid.google-release-acceptance-normalized/v1``
document on stdout. It never prints private evidence content.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import zipfile
from pathlib import Path
from subprocess import run
from typing import Any, Mapping, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from xenoid.backend import RuntimeManager  # noqa: E402
from xenoid.config import resolve_instance  # noqa: E402
from xenoid.google_services import (  # noqa: E402
    MICROG_PLAY_RELEASE,
    PROVIDER_MICROG,
    GoogleBindingStore,
    asset_paths,
    load_release_spec,
    public_binding,
)
from xenoid.storage import StorageStateStore  # noqa: E402
from xenoid.util import which  # noqa: E402

EVIDENCE_SCHEMA = "dev.xenoid.google-services-release-acceptance/v1"
SNAPSHOT_SCHEMA = "dev.xenoid.gate-dependency-snapshot/v1"
NORMALIZED_SCHEMA = "dev.xenoid.google-release-acceptance-normalized/v1"
APK_SET_SCHEMA = "dev.xenoid.apk-set/v1"
DEPENDENCY_LOCK_SCHEMA = "dev.xenoid.google-probe-dependencies/v1"
REPRODUCIBILITY_SCHEMA = "dev.xenoid.google-reproducibility/v1"
SMOKE_SCHEMA = "dev.xenoid.google-services-smoke/v2"
CUTOVER_SCHEMA = "dev.xenoid.google-provider-cutover/v1"

RUNTIME_PROBE_PACKAGE = "org.example.googleservicesruntimeprobe"
CLOUD_PROBE_PACKAGE = "org.example.googleservicescapabilityprobe"
COORDINATES = [
    "com.google.android.gms:play-services-auth:21.6.0",
    "com.google.android.gms:play-services-base:18.10.1",
    "com.google.android.gms:play-services-location:21.4.0",
    "com.google.android.gms:play-services-maps:20.0.0",
    "com.google.firebase:firebase-messaging:25.1.2",
]

EVIDENCE_KEYS = {
    "schema",
    "provider",
    "release",
    "specSha256",
    "runtimeInputSha256",
    "imageId",
    "freshData",
    "testArtifacts",
    "reproducibility",
    "effectivePlayStoreVersionCode",
    "effectivePlayStoreSignerMatches",
    "checks",
}
FRESH_DATA_KEYS = {
    "instanceId",
    "resourceTag",
    "dataUuid",
    "googleBindingTransactionId",
    "storageTransactionId",
    "bindingSource",
    "storageSource",
    "volumeOwnerMatches",
    "legacyRecordAbsent",
}
TEST_ARTIFACT_KEYS = {
    "runtimeProbePackage",
    "runtimeProbeApkSha256",
    "cloudProbePackage",
    "cloudProbeApkSha256",
    "dependencyLockSha256",
    "coordinates",
}
REPRODUCIBILITY_KEYS = {
    "artifactManifestSha256A",
    "artifactManifestSha256B",
    "contextManifestSha256A",
    "contextManifestSha256B",
    "inputSha256A",
    "inputSha256B",
    "bootInputSha256A",
    "bootInputSha256B",
    "imageIdA",
    "imageIdB",
}
CHECK_KEYS = {
    "fcmTokenRegistration",
    "fcmForeground",
    "fcmBackgroundDoze",
    "fcmAfterReboot",
    "fusedCoarse",
    "fusedFineContinuous",
    "fusedPermissionDenied",
    "fusedProviderUnavailable",
    "mapsInitialize",
    "mapsRender",
    "authSuccess",
    "authDenied",
    "playStoreSelfUpdate",
    "playStoreLogin",
    "playStoreInstallFree",
    "playStoreForegroundUpdate",
    "playStoreBackgroundUpdate",
    "playStoreAfterReboot",
    "gmsCoreDifferentSignerRejected",
    "providerNoAnr",
    "providerNoCrashLoop",
    "gmsCoreProcessStable",
    "playStoreStableOrDormant",
    "artifactReproducible",
    "runtimeImageReproducible",
    "contentTagReused",
    "noOpConvergencePass1",
    "noOpConvergencePass2",
    "instrumentationInactive",
}
NORMALIZED_KEYS = {
    "schema",
    "provider",
    "release",
    "specSha256",
    "runtimeInputSha256",
    "imageId",
    "privateEvidenceSha256",
    "freshDataProofSha256",
    "testArtifacts",
    "reproducibility",
    "effectivePlayStoreVersionCode",
    "effectivePlayStoreSignerMatches",
    "checks",
}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_TRANSACTION = re.compile(r"^[0-9a-f]{32}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class AcceptanceError(Exception):
    """Stable release-acceptance validation failure."""


def _fail(message: str) -> None:
    raise AcceptanceError(message)


def _canonical(data: Mapping[str, Any]) -> bytes:
    return json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def _require_hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        _fail(f"invalid {label}")
    return value


def _read_snapshot() -> Mapping[str, Any]:
    payload = sys.stdin.buffer.read(256 * 1024 + 1)
    if len(payload) > 256 * 1024:
        _fail("dependency snapshot exceeds the size bound")
    try:
        document = json.loads(payload)
    except (ValueError, UnicodeError) as exc:
        _fail(f"invalid dependency snapshot: {exc}")
    if not isinstance(document, Mapping) or set(document) != {"schema", "dependencies"}:
        _fail("invalid dependency snapshot keys")
    if document["schema"] != SNAPSHOT_SCHEMA:
        _fail("unsupported dependency snapshot schema")
    dependencies = document["dependencies"]
    if not isinstance(dependencies, Mapping) or set(dependencies) != {
        "google-runtime",
        "google-reproducibility",
        "google-provider-cutover-contract",
    }:
        _fail("dependency snapshot must carry exactly the three declared dependencies")
    for name, entry in dependencies.items():
        if not isinstance(entry, Mapping) or set(entry) != {"state", "inputSha256", "result"}:
            _fail(f"dependency {name} has an invalid shape")
        if entry["state"] != "passed":
            _fail(f"dependency {name} did not pass in this invocation")
        _require_hex64(entry["inputSha256"], f"{name} input hash")
        if not isinstance(entry["result"], Mapping):
            _fail(f"dependency {name} lacks a normalized result")
    expected_schemas = {
        "google-runtime": SMOKE_SCHEMA,
        "google-reproducibility": REPRODUCIBILITY_SCHEMA,
        "google-provider-cutover-contract": CUTOVER_SCHEMA,
    }
    for name, schema in expected_schemas.items():
        if dependencies[name]["result"].get("schema") != schema:
            _fail(f"dependency {name} result schema mismatch")
    if dependencies["google-provider-cutover-contract"]["result"].get("mode") != "production":
        _fail("provider cutover contract is not in production mode")
    return document


def _read_evidence(project_root: Path) -> tuple[Mapping[str, Any], bytes]:
    path = (
        project_root
        / ".xenoid"
        / "acceptance"
        / "google-services"
        / MICROG_PLAY_RELEASE
        / "release-acceptance.json"
    )
    try:
        info = path.lstat()
    except FileNotFoundError:
        _fail("private release acceptance evidence is missing")
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o077:
        _fail("private release acceptance evidence permissions are unsafe")
    if info.st_size > 256 * 1024:
        _fail("private release acceptance evidence is too large")
    payload = path.read_bytes()
    try:
        document = json.loads(payload)
    except (ValueError, UnicodeError) as exc:
        _fail(f"invalid private evidence document: {exc}")
    if not isinstance(document, Mapping) or set(document) != EVIDENCE_KEYS:
        _fail("private evidence keys are invalid")
    if document["schema"] != EVIDENCE_SCHEMA:
        _fail("unsupported private evidence schema")
    return document, payload


def _adb(args: list[str], target: str, timeout: int = 30) -> str:
    adb_bin = which("adb")
    if adb_bin is None:
        _fail("adb is unavailable")
    completed = run(
        [adb_bin, "-s", target, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        _fail(f"adb observation failed: {args[0]}")
    return completed.stdout


def _adb_read(target: str, device_path: str, max_bytes: int) -> bytes:
    adb_bin = which("adb")
    if adb_bin is None:
        _fail("adb is unavailable")
    completed = run(
        [adb_bin, "-s", target, "exec-out", "cat", "--", device_path],
        capture_output=True,
        timeout=300,
    )
    if completed.returncode != 0 or not completed.stdout or len(completed.stdout) > max_bytes:
        _fail("unable to stream an installed probe APK")
    return bytes(completed.stdout)


def _apk_set_sha256(target: str, package: str) -> tuple[str, bytes]:
    dump = _adb(["dumpsys", "package", package], target, timeout=30)
    version_match = re.search(r"^\s*versionCode=(\d+)", dump, flags=re.MULTILINE)
    if version_match is None:
        _fail("cloud probe version is unavailable")
    code_match = re.search(r"^\s*codePath=(\S+)", dump, flags=re.MULTILINE)
    if code_match is None:
        _fail("cloud probe codePath is unavailable")
    code_path = code_match.group(1)
    splits_match = re.search(r"^\s*splits=\[(.*?)\]", dump, flags=re.MULTILINE)
    entries = []
    base_bytes = _adb_read(target, f"{code_path}/base.apk", 512 * 1024 * 1024)
    entries.append(
        ("base", base_bytes),
    )
    if splits_match and splits_match.group(1).strip():
        for split in sorted(item.strip() for item in splits_match.group(1).split(",") if item.strip()):
            split_bytes = _adb_read(target, f"{code_path}/split_{split}.apk", 512 * 1024 * 1024)
            entries.append((f"split:{split}", split_bytes))
    entries.sort(key=lambda pair: pair[0].encode("utf-8"))
    document = {
        "schema": APK_SET_SCHEMA,
        "package": package,
        "versionCode": int(version_match.group(1)),
        "entries": [
            {"name": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
            for name, payload in entries
        ],
    }
    canonical = _canonical(document) + b"\n"
    return hashlib.sha256(canonical).hexdigest(), base_bytes


def _validate_identity_bindings(
    evidence: Mapping[str, Any],
    smoke: Mapping[str, Any],
    repro: Mapping[str, Any],
) -> None:
    """Bind the same-invocation smoke report to the evidence identities.

    A passed smoke on an older runtime must never attest a separately rebuilt
    image: the smoke's spec/runtime input, both no-op pass identities, and the
    reproducibility record must all equal the evidence identities exactly.
    """
    spec_sha = _require_hex64(evidence["specSha256"], "spec hash")
    runtime_input = _require_hex64(evidence["runtimeInputSha256"], "runtime input hash")
    image_id = evidence["imageId"]
    data_uuid = evidence["freshData"]["dataUuid"]
    if smoke.get("specSha256") != spec_sha:
        _fail("smoke spec fingerprint does not match the evidence")
    if smoke.get("runtimeInputSha256") != runtime_input:
        _fail("smoke runtime input does not match the evidence")
    if repro.get("inputSha256A") != runtime_input or repro.get("inputSha256B") != runtime_input:
        _fail("reproducibility runtime input does not match the evidence")
    if repro.get("imageIdA") != image_id or repro.get("imageIdB") != image_id:
        _fail("reproducibility image identity does not match the evidence")
    no_op = smoke.get("noOpPasses")
    if not isinstance(no_op, list) or len(no_op) != 2:
        _fail("no-op convergence passes are missing")
    first: Optional[Mapping[str, Any]] = None
    for item in no_op:
        if not isinstance(item, Mapping):
            _fail("no-op convergence pass shape is invalid")
        if item.get("runtimeInputSha256") != runtime_input:
            _fail("no-op pass runtime input does not match the evidence")
        if item.get("imageId") != image_id:
            _fail("no-op pass image identity does not match the evidence")
        if item.get("dataUuid") != data_uuid:
            _fail("no-op pass data UUID does not match the fresh-data proof")
        for key in ("containerId", "bindingSha256", "effectiveComponentsSha256"):
            if not isinstance(item.get(key), str) or not item[key]:
                _fail("no-op pass identity fields are invalid")
        if first is not None:
            for key in ("containerId", "dataUuid", "bindingSha256", "runtimeInputSha256", "imageId", "effectiveComponentsSha256"):
                if item.get(key) != first.get(key):
                    _fail("no-op passes disagree on the runtime identity")
        first = item


def _dependency_lock_sha256(base_apk: bytes) -> str:
    with tempfile.TemporaryDirectory(prefix="xenoid-acceptance-") as temp:
        apk_path = Path(temp) / "cloud-probe.apk"
        apk_path.write_bytes(base_apk)
        try:
            with zipfile.ZipFile(apk_path) as bundle:
                payload = bundle.read("assets/xenoid-dependency-lock.json")
        except (KeyError, OSError, zipfile.BadZipFile):
            _fail("cloud probe dependency lock is missing")
    try:
        document = json.loads(payload)
    except (ValueError, UnicodeError):
        _fail("cloud probe dependency lock is invalid")
    if not isinstance(document, Mapping) or set(document) != {"schema", "coordinates", "artifacts"}:
        _fail("cloud probe dependency lock keys are invalid")
    if document["schema"] != DEPENDENCY_LOCK_SCHEMA:
        _fail("cloud probe dependency lock schema is unsupported")
    if document["coordinates"] != COORDINATES:
        _fail("cloud probe dependency coordinates mismatch")
    artifacts = document["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        _fail("cloud probe dependency artifacts are invalid")
    previous: Optional[tuple[bytes, bytes]] = None
    for artifact in artifacts:
        if not isinstance(artifact, Mapping) or set(artifact) != {"coordinate", "filename", "size", "sha256"}:
            _fail("cloud probe dependency artifact entry is invalid")
        _require_hex64(artifact["sha256"], "artifact hash")
        if artifact["coordinate"] not in COORDINATES:
            _fail("cloud probe dependency artifact coordinate mismatch")
        if not isinstance(artifact["filename"], str) or not isinstance(artifact["size"], int):
            _fail("cloud probe dependency artifact identity is invalid")
        key = (artifact["coordinate"].encode("utf-8"), artifact["filename"].encode("utf-8"))
        if previous is not None and key <= previous:
            _fail("cloud probe dependency artifacts are not bytewise sorted")
        previous = key
    if payload != _canonical(document) + b"\n":
        _fail("cloud probe dependency lock is not canonical")
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    snapshot = _read_snapshot()
    project_root = Path(os.environ.get("XENOID_PROJECT", Path.cwd())).resolve()
    evidence, evidence_bytes = _read_evidence(project_root)

    context, config, lease = resolve_instance(
        os.environ.get("XENOID_INSTANCE"),
        project_root=project_root,
        env=os.environ,
        migrate_legacy=False,
    )
    spec = load_release_spec(project_root, MICROG_PLAY_RELEASE)
    if evidence["provider"] != PROVIDER_MICROG or evidence["release"] != MICROG_PLAY_RELEASE:
        _fail("evidence provider/release mismatch")
    _require_hex64(evidence["specSha256"], "spec hash")
    if evidence["specSha256"] != spec.fingerprint:
        _fail("evidence spec fingerprint mismatch")
    _require_hex64(evidence["runtimeInputSha256"], "runtime input hash")
    if not isinstance(evidence["imageId"], str) or not evidence["imageId"].startswith("sha256:") or _HEX64.fullmatch(evidence["imageId"][7:]) is None:
        _fail("evidence image identity is invalid")

    reproducibility = evidence["reproducibility"]
    if not isinstance(reproducibility, Mapping) or set(reproducibility) != REPRODUCIBILITY_KEYS:
        _fail("evidence reproducibility keys are invalid")
    for key in REPRODUCIBILITY_KEYS:
        if key.startswith("imageId"):
            value = reproducibility[key]
            if not isinstance(value, str) or not value.startswith("sha256:"):
                _fail("reproducibility image identity is invalid")
        else:
            _require_hex64(reproducibility[key], key)
    for pair in (
        ("artifactManifestSha256A", "artifactManifestSha256B"),
        ("contextManifestSha256A", "contextManifestSha256B"),
        ("inputSha256A", "inputSha256B"),
        ("bootInputSha256A", "bootInputSha256B"),
        ("imageIdA", "imageIdB"),
    ):
        if reproducibility[pair[0]] != reproducibility[pair[1]]:
            _fail("reproducibility A/B pair mismatch")
    gate_repro = snapshot["dependencies"]["google-reproducibility"]["result"]
    for key in REPRODUCIBILITY_KEYS:
        if gate_repro.get(key) != reproducibility[key]:
            _fail("reproducibility evidence does not match the same-invocation gate result")
    if gate_repro.get("contentTagReused") is not True:
        _fail("content tag reuse was not observed")
    if evidence["runtimeInputSha256"] != reproducibility["inputSha256A"]:
        _fail("evidence runtime input does not match reproducibility")
    if evidence["imageId"] != reproducibility["imageIdA"]:
        _fail("evidence image identity does not match reproducibility")

    fresh_data = evidence["freshData"]
    if not isinstance(fresh_data, Mapping) or set(fresh_data) != FRESH_DATA_KEYS:
        _fail("fresh data proof keys are invalid")
    if fresh_data["instanceId"] != context.instance_id:
        _fail("fresh data instance mismatch")
    if not isinstance(fresh_data["resourceTag"], str) or fresh_data["resourceTag"] != context.resource_tag:
        _fail("fresh data resource tag mismatch")
    for key in ("googleBindingTransactionId", "storageTransactionId"):
        if not isinstance(fresh_data[key], str) or _TRANSACTION.fullmatch(fresh_data[key]) is None:
            _fail(f"fresh data {key} is invalid")
    if fresh_data["bindingSource"] != "fresh" or fresh_data["storageSource"] != "fresh":
        _fail("fresh data sources must be fresh")
    if fresh_data["volumeOwnerMatches"] is not True or fresh_data["legacyRecordAbsent"] is not True:
        _fail("fresh data ownership booleans must be true")
    binding = GoogleBindingStore(context, lease).load()
    if (
        binding is None
        or binding.get("state") != "committed"
        or binding.get("transactionId") != fresh_data["googleBindingTransactionId"]
        or binding.get("provider") != PROVIDER_MICROG
        or binding.get("release") != MICROG_PLAY_RELEASE
    ):
        _fail("committed Google binding does not match the fresh data proof")
    storage = StorageStateStore(context, lease).load()
    if (
        not isinstance(storage, Mapping)
        or storage.get("state") != "committed"
        or storage.get("transactionId") != fresh_data["storageTransactionId"]
        or storage.get("source") != "fresh"
    ):
        _fail("committed storage state does not match the fresh data proof")
    data_uuid = storage.get("filesystemUuid")
    if not isinstance(data_uuid, str) or _UUID.fullmatch(data_uuid) is None or data_uuid != fresh_data["dataUuid"]:
        _fail("fresh data filesystem UUID mismatch")
    fresh_proof = hashlib.sha256(_canonical(fresh_data) + b"\n").hexdigest()

    test_artifacts = evidence["testArtifacts"]
    if not isinstance(test_artifacts, Mapping) or set(test_artifacts) != TEST_ARTIFACT_KEYS:
        _fail("test artifact keys are invalid")
    if test_artifacts["runtimeProbePackage"] != RUNTIME_PROBE_PACKAGE:
        _fail("runtime probe package mismatch")
    if test_artifacts["cloudProbePackage"] != CLOUD_PROBE_PACKAGE:
        _fail("cloud probe package mismatch")
    if test_artifacts["coordinates"] != COORDINATES:
        _fail("dependency coordinates mismatch")
    for key in ("runtimeProbeApkSha256", "cloudProbeApkSha256", "dependencyLockSha256"):
        _require_hex64(test_artifacts[key], key)

    smoke = snapshot["dependencies"]["google-runtime"]["result"]
    probe = smoke.get("probe")
    if not isinstance(probe, Mapping) or probe.get("package") != RUNTIME_PROBE_PACKAGE:
        _fail("runtime probe identity is missing from the same-invocation smoke result")
    if probe.get("apkSha256") != test_artifacts["runtimeProbeApkSha256"]:
        _fail("runtime probe hash does not match the same-invocation smoke result")
    negative = smoke.get("negativeSignature")
    if not isinstance(negative, Mapping) or any(negative.get(key) is not True for key in ("unlistedPackageNotSpoofed", "differentSignerUpdateRejected", "effectiveGmsCoreUnchanged")):
        _fail("negative signature checks did not pass in this invocation")
    stability = smoke.get("processStability")
    if not isinstance(stability, Mapping) or stability.get("gmsCoreStable") is not True or stability.get("noAnr") is not True or stability.get("noCrashLoop") is not True:
        _fail("process stability checks did not pass in this invocation")
    if stability.get("playStoreState") not in {"stable", "dormant"}:
        _fail("Play Store process state is invalid in this invocation")
    no_op = smoke.get("noOpPasses")
    if (
        not isinstance(no_op, list)
        or len(no_op) != 2
        or any(
            not isinstance(item, Mapping)
            or any(item.get(key) is not True for key in ("pass", "noBuild", "noRecreate"))
            for item in no_op
        )
    ):
        _fail("no-op convergence passes did not succeed in this invocation")
    if smoke.get("instrumentationInactive") is not True:
        _fail("instrumentation inactivity was not proven in this invocation")

    _validate_identity_bindings(evidence, smoke, gate_repro)
    expected_binding_sha = hashlib.sha256(_canonical(public_binding(binding))).hexdigest()
    if any(item["bindingSha256"] != expected_binding_sha for item in no_op):
        _fail("no-op pass binding does not match the committed binding")

    manager = RuntimeManager(context, config, lease)
    current = manager.google_services_status(require_runtime=True)
    if current.get("ok") is not True or current.get("ready") is not True:
        _fail("current runtime is not ready for release acceptance")
    identity = current.get("runtimeIdentity")
    if not isinstance(identity, Mapping):
        _fail("current runtime identity is unavailable")
    if (
        identity.get("imageMatch") != "exact"
        or identity.get("rootfsBootInputMatches") is not True
        or identity.get("labelsMatch") is not True
        or identity.get("commandMatch") is not True
    ):
        _fail("current runtime identity does not match the verified image")
    if identity.get("desiredInputSha256") != evidence["runtimeInputSha256"]:
        _fail("current runtime input does not match the evidence")
    if identity.get("desiredImageSha256") != evidence["imageId"]:
        _fail("current runtime image does not match the evidence")
    effective = current.get("effectiveComponents")
    if not isinstance(effective, Mapping) or set(effective) != {"gmsCore", "gsfProxy", "playStoreSeed"}:
        _fail("current effective components are incomplete")
    if effective["gmsCore"].get("processState") != "stable" or effective["playStoreSeed"].get("processState") not in {"stable", "dormant"}:
        _fail("current provider process state is unstable")

    target = f"127.0.0.1:{lease.host_adb_port}"
    cloud_sha, cloud_base = _apk_set_sha256(target, CLOUD_PROBE_PACKAGE)
    if cloud_sha != test_artifacts["cloudProbeApkSha256"]:
        _fail("installed cloud probe APK set hash mismatch")
    lock_sha = _dependency_lock_sha256(cloud_base)
    if lock_sha != test_artifacts["dependencyLockSha256"]:
        _fail("installed cloud probe dependency lock hash mismatch")

    vending_dump = _adb(["dumpsys", "package", "com.android.vending"], target, timeout=30)
    version_match = re.search(r"^\s*versionCode=(\d+)", vending_dump, flags=re.MULTILINE)
    if version_match is None:
        _fail("effective Play Store version is unavailable")
    effective_version = int(version_match.group(1))
    if not isinstance(evidence["effectivePlayStoreVersionCode"], int) or evidence["effectivePlayStoreVersionCode"] <= 83041710:
        _fail("effective Play Store version does not prove self-update")
    if effective_version != evidence["effectivePlayStoreVersionCode"]:
        _fail("effective Play Store version changed since the evidence was recorded")
    if evidence["effectivePlayStoreSignerMatches"] is not True:
        _fail("effective Play Store signer must match the Google certificate")

    checks = evidence["checks"]
    if not isinstance(checks, Mapping) or set(checks) != CHECK_KEYS:
        _fail("acceptance check keys are invalid")
    if any(value is not True for value in checks.values()):
        _fail("every acceptance check must be true")
    if checks["gmsCoreDifferentSignerRejected"] and negative.get("differentSignerUpdateRejected") is not True:
        _fail("wrong-signer rejection evidence is inconsistent")
    if (checks["noOpConvergencePass1"] or checks["noOpConvergencePass2"]) and not no_op:
        _fail("no-op convergence evidence is inconsistent")
    if checks["contentTagReused"] and gate_repro.get("contentTagReused") is not True:
        _fail("content tag reuse evidence is inconsistent")
    if checks["instrumentationInactive"] and smoke.get("instrumentationInactive") is not True:
        _fail("instrumentation inactivity evidence is inconsistent")

    normalized = {
        "schema": NORMALIZED_SCHEMA,
        "provider": PROVIDER_MICROG,
        "release": MICROG_PLAY_RELEASE,
        "specSha256": spec.fingerprint,
        "runtimeInputSha256": evidence["runtimeInputSha256"],
        "imageId": evidence["imageId"],
        "privateEvidenceSha256": hashlib.sha256(evidence_bytes).hexdigest(),
        "freshDataProofSha256": fresh_proof,
        "testArtifacts": dict(test_artifacts),
        "reproducibility": dict(reproducibility),
        "effectivePlayStoreVersionCode": evidence["effectivePlayStoreVersionCode"],
        "effectivePlayStoreSignerMatches": True,
        "checks": dict(checks),
    }
    if set(normalized) != NORMALIZED_KEYS:
        _fail("normalized acceptance shape is invalid")
    sys.stdout.write(json.dumps(normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AcceptanceError as exc:
        print(f"google_release_acceptance_invalid: {exc}", file=sys.stderr)
        raise SystemExit(1)
