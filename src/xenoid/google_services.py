from __future__ import annotations

import base64
import errno
import fcntl
import hashlib
import json
import http.client
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import unicodedata
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Optional

from .config import InstanceContext, InstanceError, InstanceLease, XenoidConfig
from .util import which
from .process import run_bounded

GOOGLE_RELEASE_SCHEMA_V1 = "dev.xenoid.google-release/v1"
GOOGLE_RELEASE_SCHEMA_V2 = "dev.xenoid.google-release/v2"
GOOGLE_RELEASE_SCHEMA = GOOGLE_RELEASE_SCHEMA_V1
GOOGLE_BINDING_SCHEMA = "dev.xenoid.google-runtime-binding/v1"
GOOGLE_STATUS_SCHEMA = "dev.xenoid.google-services-status/v2"
GOOGLE_IMPORT_SCHEMA_V1 = "dev.xenoid.google-services-import/v1"
GOOGLE_IMPORT_SCHEMA_V2 = "dev.xenoid.google-services-import/v2"
GOOGLE_IMPORT_SCHEMA = GOOGLE_IMPORT_SCHEMA_V1
GOOGLE_PROBE_SCHEMA = "dev.xenoid.google-services-probe/v2"
GOOGLE_SMOKE_SCHEMA = "dev.xenoid.google-services-smoke/v2"

PROVIDER_NONE = "none"
PROVIDER_MINDTHEGAPPS = "mindthegapps"
PROVIDER_MICROG = "microg"
MINDTHEGAPPS_RELEASE = "MindTheGapps-13.0.0-arm64-20231025_200931"
MICROG_PLAY_RELEASE = "microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0"
INTEGRATION_REVISION = 1
INTEGRATION_REVISION_V2 = 2

AVAILABILITY_PRODUCTION = "production"
AVAILABILITY_RETIRED_SOURCE = "retired-source"

# Pinned signer identities for the composite microG release. The real
# certificate is the official microG NOGAPPS release key; the fake certificate
# is the Google Android certificate requested through GmsCore's
# ``fake-signature`` metadata and presented only through the restricted
# signature-spoofing framework policy.
MICROG_REAL_CERT_SHA256 = "9bd06727e62796c0130eb6dab39b73157451582cbd138e86c468acc395d14165"
MICROG_FAKE_CERT_SHA256 = "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83"
PHONESKY_CERT_SHA256 = "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83"
MICROG_GMSCORE_DOWNLOAD_URL = (
    "https://github.com/microg/GmsCore/releases/download/"
    "v0.3.15.250932/com.google.android.gms-250932030.apk"
)
MICROG_GSFPROXY_DOWNLOAD_URL = (
    "https://github.com/microg/GsfProxy/releases/download/v0.1.0/GsfProxy.apk"
)
MICROG_GMSCORE_BASENAME = "com.google.android.gms-250932030.apk"
MICROG_GSFPROXY_BASENAME = "com.google.android.gsf-8.apk"
PHONESKY_ARCHIVE_PATH = "system/product/priv-app/Phonesky/Phonesky.apk"
LINEAGE_SPOOFING_BASE_COMMIT = "6d2955f0bd55e9938d5d49415182c27b50900b95"
LINEAGE_SPOOFING_SIGNING_INFO_COMMIT = "53e2f4b85ce836360dd58bdb2f0d7f42dc796443"
MICROG_POLICY_UPSTREAM_COMMIT = "bd95ffe12653c1e8e695c841efa847af06d32a15"

GOOGLE_LABEL_PROVIDER = "dev.xenoid.google_provider"
GOOGLE_LABEL_RELEASE = "dev.xenoid.google_release"
GOOGLE_LABEL_SPEC = "dev.xenoid.google_spec_sha256"
GOOGLE_LABEL_DATA_COMPAT = "dev.xenoid.google_data_compat_sha256"
GOOGLE_LABEL_KEYS = (
    GOOGLE_LABEL_PROVIDER,
    GOOGLE_LABEL_RELEASE,
    GOOGLE_LABEL_SPEC,
    GOOGLE_LABEL_DATA_COMPAT,
)

_CORE_PACKAGES = (
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.android.vending",
)

_RELEASE_REGISTRY: dict[str, dict[str, str]] = {
    MINDTHEGAPPS_RELEASE: {
        "provider": PROVIDER_MINDTHEGAPPS,
        "metadata": "data/google-services/mindthegapps-13.0.0-arm64-20231025_200931.json",
        "metadataSha256": "7ce33b19c10d2aa7f4c8a9ece164765fd0ceddfcfb479457b5fcf07aa4244eab",
        "availability": AVAILABILITY_RETIRED_SOURCE,
    },
    MICROG_PLAY_RELEASE: {
        "provider": PROVIDER_MICROG,
        "metadata": "data/google-services/microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0.json",
        "metadataSha256": "f21706e7152c480239b569b353a87a8ff2869d0e368e9e317d0c4eb8b41dd656",
        "availability": AVAILABILITY_PRODUCTION,
    },
}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_TRANSACTION = re.compile(r"^[0-9a-f]{32}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_RESOURCE_TAG = re.compile(r"^[0-9a-f]{12}$")
_BINDING_KEYS = {
    "schema",
    "instanceId",
    "resourceTag",
    "provider",
    "release",
    "specSha256",
    "dataCompatibilitySha256",
    "state",
    "transactionId",
    "source",
}
_IMPORT_KEYS_V1 = {
    "schema",
    "provider",
    "release",
    "integrationRevision",
    "metadataSha256",
    "zipBasename",
    "zipSize",
    "zipSha256",
    "certificateBasename",
    "certificateSize",
    "certificateSha256",
    "certificateDerSha256",
}
_IMPORT_KEYS_V2 = {
    "schema",
    "provider",
    "release",
    "integrationRevision",
    "metadataSha256",
    "components",
    "sourceDependencies",
}
_IMPORT_COMPONENT_KEYS_V2 = {"id", "basename", "size", "sha256", "signingCertificateHistorySha256"}
_IMPORT_SOURCE_DEPENDENCY_KEYS_V2 = {"release", "metadataSha256", "importManifestSha256", "archivePath", "memberSha256"}
_IMPORT_OWNER_V1 = "dev.xenoid.google-services-import/v1\n"
_IMPORT_OWNER_V2 = "dev.xenoid.google-services-import/v2\n"
_RUNTIME_CONTEXT_OWNER = "dev.xenoid.google-runtime-context/v1\n"
_MAX_COMPONENT_BYTES = 255
_MAX_PATH_BYTES = 1024
_COPY_CHUNK = 1024 * 1024
_RUNTIME_CONTEXT_SCHEMA = "dev.xenoid.runtime-context/v1"
_RUNTIME_CONTEXT_KEYS = {"schema", "entries"}
_RUNTIME_CONTEXT_ENTRY_KEYS = {"path", "type", "mode", "size", "sha256"}
_MAX_CONTEXT_MANIFEST_BYTES = 16 * 1024 * 1024


class GoogleServicesError(InstanceError):
    """Stable, secret-free Google runtime failure."""


@dataclass(frozen=True)
class ReleaseSpec:
    release: str
    metadata_path: Path
    metadata_sha256: str
    metadata: Mapping[str, Any]
    fingerprint: str
    data_compatibility_fingerprint: str

    @property
    def schema(self) -> str:
        return str(self.metadata["schema"])

    @property
    def provider(self) -> str:
        return str(self.metadata["provider"])

    @property
    def availability(self) -> str:
        entry = _RELEASE_REGISTRY.get(self.release)
        if entry is None:
            raise GoogleServicesError("google_services_spec_mismatch", "unsupported Google services release")
        return entry["availability"]

    @property
    def archive(self) -> Mapping[str, Any]:
        return self.metadata["archive"]

    @property
    def android(self) -> Mapping[str, Any]:
        return self.metadata["android"]

    @property
    def selection(self) -> Mapping[str, Any]:
        return self.metadata["selection"]

    @property
    def members(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.metadata["members"])

    @property
    def apks(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.metadata["apks"])

    @property
    def sources(self) -> Mapping[str, Any]:
        return self.metadata["sources"]

    @property
    def components(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.metadata["components"])

    @property
    def signature_policy(self) -> Mapping[str, Any]:
        return self.metadata["signaturePolicy"]

    @property
    def product_policy(self) -> Mapping[str, Any]:
        return self.metadata["productPolicy"]

    @property
    def runtime_requirements(self) -> Mapping[str, Any]:
        return self.metadata["runtimeRequirements"]

    def component(self, component_id: str) -> Mapping[str, Any]:
        for item in self.components:
            if item["id"] == component_id:
                return item
        raise GoogleServicesError("google_services_spec_mismatch", "unknown Google services component")

    @property
    def labels(self) -> dict[str, str]:
        return {
            GOOGLE_LABEL_PROVIDER: self.provider,
            GOOGLE_LABEL_RELEASE: self.release,
            GOOGLE_LABEL_SPEC: self.fingerprint,
            GOOGLE_LABEL_DATA_COMPAT: self.data_compatibility_fingerprint,
        }

    @property
    def asset_dirname(self) -> str:
        return self.release

    def public_dict(self) -> dict[str, Any]:
        result = {
            "provider": self.provider,
            "release": self.release,
            "specSha256": self.fingerprint,
            "dataCompatibilitySha256": self.data_compatibility_fingerprint,
            "androidRelease": self.android["release"],
            "api": self.android["api"],
            "abi": self.android["runtimeAbis"][0],
            "targetProduct": self.android["targetProduct"],
            "integrationRevision": self.metadata["integrationRevision"],
            "availability": self.availability,
        }
        if self.schema == GOOGLE_RELEASE_SCHEMA_V1:
            result["selectionProfile"] = self.selection["profile"]
        return result


@dataclass(frozen=True)
class StageHandle:
    root: Path
    tree: Path
    token: str
    file_manifest: Mapping[str, Mapping[str, Any]]
    directory_manifest: Mapping[str, Mapping[str, Any]]
    metadata_digest: str


@dataclass(frozen=True)
class RuntimeContextHandle:
    root: Path
    output: Path
    token: str


def registered_releases(*, selectable_only: bool = False) -> tuple[str, ...]:
    if not selectable_only:
        return tuple(sorted(_RELEASE_REGISTRY))
    return tuple(
        sorted(
            release
            for release, entry in _RELEASE_REGISTRY.items()
            if entry["availability"] == AVAILABILITY_PRODUCTION
        )
    )


def registered_metadata_files() -> dict[str, str]:
    return {
        entry["metadata"]: entry["metadataSha256"]
        for entry in _RELEASE_REGISTRY.values()
    }


def release_availability(release: str) -> Optional[str]:
    entry = _RELEASE_REGISTRY.get(release)
    return None if entry is None else entry["availability"]


def registry_public() -> list[dict[str, str]]:
    return [
        {
            "provider": _RELEASE_REGISTRY[release]["provider"],
            "release": release,
            "metadata": _RELEASE_REGISTRY[release]["metadata"],
            "metadataSha256": _RELEASE_REGISTRY[release]["metadataSha256"],
            "availability": _RELEASE_REGISTRY[release]["availability"],
        }
        for release in registered_releases()
    ]


def validate_provider_release(provider: Any, release: Any) -> tuple[str, str]:
    if not isinstance(provider, str) or not isinstance(release, str):
        raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services provider configuration")
    if provider == PROVIDER_NONE and release == PROVIDER_NONE:
        return provider, release
    entry = _RELEASE_REGISTRY.get(release)
    if entry is None or entry["provider"] != provider:
        raise GoogleServicesError("google_services_spec_mismatch", "unsupported Google services provider or release")
    return provider, release


def _stream_sha256(path: Path, expected_size: Optional[int] = None) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise GoogleServicesError("google_services_asset_invalid", "Google services asset is not a safe regular file") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise GoogleServicesError("google_services_asset_invalid", "Google services asset is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while True:
                chunk = stream.read(_COPY_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if expected_size is not None and size > expected_size:
                    raise GoogleServicesError("google_services_asset_invalid", "Google services asset size does not match its pin")
                digest.update(chunk)
    finally:
        os.close(descriptor)
    if expected_size is not None and size != expected_size:
        raise GoogleServicesError("google_services_asset_invalid", "Google services asset size does not match its pin")
    return size, digest.hexdigest()


def _canonical_json(data: Mapping[str, Any]) -> bytes:
    return json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def _spec_payload(metadata: Mapping[str, Any], metadata_sha256: str) -> dict[str, Any]:
    if metadata.get("schema") == GOOGLE_RELEASE_SCHEMA_V2:
        return {
            key: metadata[key]
            for key in (
                "schema",
                "provider",
                "release",
                "integrationRevision",
                "android",
                "sources",
                "components",
                "signaturePolicy",
                "productPolicy",
                "runtimeRequirements",
            )
        }
    android = metadata["android"]
    archive = metadata["archive"]
    selection = metadata["selection"]
    requirements = metadata["runtimeRequirements"]
    return {
        "schema": "dev.xenoid.google-runtime-spec/v1",
        "provider": metadata["provider"],
        "release": metadata["release"],
        "releaseManifestSha256": metadata_sha256,
        "androidRelease": android["release"],
        "api": android["api"],
        "abi": android["runtimeAbis"][0],
        "targetProduct": android["targetProduct"],
        "partitionAliases": android["partitionAliases"],
        "zipSha256": archive["sha256"],
        "outerSignerCertificateSha256": archive["certificate"]["derSha256"],
        "selectionProfile": selection["profile"],
        "integrationRevision": metadata["integrationRevision"],
        "runtimeRequirements": {
            "requiredCapabilities": requirements["requiredCapabilities"],
            "setupWizardMode": android["setupWizardMode"],
        },
    }


def disabled_runtime_spec_fingerprint() -> str:
    payload = {
        "schema": "dev.xenoid.google-runtime-spec/v1",
        "provider": PROVIDER_NONE,
        "release": PROVIDER_NONE,
        "integrationRevision": INTEGRATION_REVISION,
        "runtimeRequirements": {"requiredCapabilities": []},
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _require_mapping(value: Any, *, code: str = "google_services_spec_mismatch") -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GoogleServicesError(code, "invalid Google services release metadata")
    return value


def _validate_release_metadata(data: Any, release: str) -> Mapping[str, Any]:
    value = _require_mapping(data)
    schema = value.get("schema")
    if schema == GOOGLE_RELEASE_SCHEMA_V1:
        return _validate_release_metadata_v1(value, release)
    if schema == GOOGLE_RELEASE_SCHEMA_V2:
        return _validate_release_metadata_v2(value, release)
    raise GoogleServicesError("google_services_spec_mismatch", "unsupported Google services release metadata")


def _require_exact_keys(value: Any, keys: frozenset[str] | set[str]) -> Mapping[str, Any]:
    item = _require_mapping(value)
    if set(item) != set(keys):
        raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services release metadata")
    return item


def _require_hex64(value: Any) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services digest pin")
    return value


def _require_sorted_unique_strings(value: Any) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services string list")
    encoded = [item.encode("utf-8") for item in value]
    if encoded != sorted(encoded) or len(set(encoded)) != len(encoded):
        raise GoogleServicesError("google_services_spec_mismatch", "Google services list is not bytewise sorted")
    return list(value)


def _validate_release_metadata_v2(value: Mapping[str, Any], release: str) -> Mapping[str, Any]:
    if set(value) != {
        "schema",
        "provider",
        "release",
        "integrationRevision",
        "android",
        "sources",
        "components",
        "signaturePolicy",
        "productPolicy",
        "runtimeRequirements",
    }:
        raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services release metadata")
    if (
        value["provider"] != PROVIDER_MICROG
        or value["release"] != release
        or value["integrationRevision"] != INTEGRATION_REVISION_V2
        or release != MICROG_PLAY_RELEASE
    ):
        raise GoogleServicesError("google_services_spec_mismatch", "unsupported Google services release metadata")
    android = _require_exact_keys(
        value["android"],
        {"release", "api", "archiveArch", "runtimeAbis", "targetProduct", "partitionAliases", "setupWizardMode"},
    )
    if (
        android["release"] != "13.0.0"
        or android["api"] != 33
        or android["archiveArch"] != "arm64"
        or android["runtimeAbis"] != ["arm64-v8a"]
        or android["targetProduct"] != "raven"
        or android["partitionAliases"] != {"/product": "/system/product", "/system_ext": "/system/system_ext"}
        or android["setupWizardMode"] != "UNCHANGED"
    ):
        raise GoogleServicesError("google_services_spec_mismatch", "unsupported Google services Android target")
    sources = _require_exact_keys(value["sources"], {"mindthegapps", "microg", "gsfproxy"})
    mindthegapps = _require_exact_keys(sources["mindthegapps"], {"kind", "release", "metadata", "metadataSha256"})
    if (
        mindthegapps["kind"] != "release-v1"
        or mindthegapps["release"] != MINDTHEGAPPS_RELEASE
        or mindthegapps["metadata"] != _RELEASE_REGISTRY[MINDTHEGAPPS_RELEASE]["metadata"]
        or mindthegapps["metadataSha256"] != _RELEASE_REGISTRY[MINDTHEGAPPS_RELEASE]["metadataSha256"]
    ):
        raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services source pin")
    for key, tag, commit in (
        ("microg", "v0.3.15.250932", "352f2d72fa52c6c3c4fdd79d575a071a0da72ad1"),
        ("gsfproxy", "v0.1.0", "2fb4385a04d73f66385b325e97ac6cc40339db48"),
    ):
        source = _require_exact_keys(sources[key], {"kind", "tag", "commit", "releaseUrl"})
        if source["kind"] != "github-release-apk" or source["tag"] != tag or source["commit"] != commit:
            raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services source pin")
        if source["releaseUrl"] != f"https://github.com/microg/{'GmsCore' if key == 'microg' else 'GsfProxy'}/releases/tag/{tag}":
            raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services source URL")
    components = value["components"]
    if not isinstance(components, list) or [item.get("id") if isinstance(item, Mapping) else None for item in components] != ["gmsCore", "gsfProxy", "playStoreSeed"]:
        raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services component inventory")
    expected_components = {
        "gmsCore": {
            "source": "microg",
            "sourcePath": MICROG_GMSCORE_BASENAME,
            "runtimePath": "/system/product/priv-app/GmsCore/GmsCore.apk",
            "basename": MICROG_GMSCORE_BASENAME,
            "package": "com.google.android.gms",
            "versionCode": 250932030,
            "versionName": "0.3.15.250932",
            "size": 105948577,
            "sha256": "52597e77fd25fdd347574d0457ed1936a4b9561cf4c8d34e7ac8dd8191dfd4b9",
            "signingCertificateHistorySha256": [MICROG_REAL_CERT_SHA256],
            "nativeAbis": ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"],
        },
        "gsfProxy": {
            "source": "gsfproxy",
            "sourcePath": MICROG_GSFPROXY_BASENAME,
            "runtimePath": "/system/product/priv-app/GsfProxy/GsfProxy.apk",
            "basename": MICROG_GSFPROXY_BASENAME,
            "package": "com.google.android.gsf",
            "versionCode": 8,
            "versionName": "v0.1.0",
            "size": 21872,
            "sha256": "86891b174301f06a1c84187b545a0a2a57044c6b768f3e84e865908743349692",
            "signingCertificateHistorySha256": [MICROG_REAL_CERT_SHA256],
            "nativeAbis": [],
        },
        "playStoreSeed": {
            "source": "mindthegapps",
            "sourcePath": PHONESKY_ARCHIVE_PATH,
            "runtimePath": "/system/product/priv-app/Phonesky/Phonesky.apk",
            "basename": "Phonesky.apk",
            "package": "com.android.vending",
            "versionCode": 83041710,
            "versionName": "30.4.17-21 [0] [PR] 445549118",
            "size": 62447827,
            "sha256": "a2eba7f37baf3d50fd373c8436cd99acd7589835c9d2b0c9ec4c3dca830d337b",
            "signingCertificateHistorySha256": [PHONESKY_CERT_SHA256],
            "nativeAbis": ["arm64-v8a"],
        },
    }
    for item in components:
        component = _require_exact_keys(
            item,
            {
                "id",
                "source",
                "sourcePath",
                "runtimePath",
                "basename",
                "package",
                "versionCode",
                "versionName",
                "size",
                "sha256",
                "signingCertificateHistorySha256",
                "nativeAbis",
                "privileged",
            },
        )
        expected = expected_components[str(component["id"])]
        for field, pinned in expected.items():
            if component[field] != pinned:
                raise GoogleServicesError("google_services_spec_mismatch", "Google services component pin mismatch")
        _require_hex64(component["sha256"])
        if component["privileged"] is not True:
            raise GoogleServicesError("google_services_spec_mismatch", "Google services component privilege pin mismatch")
        _require_sorted_unique_strings(component["signingCertificateHistorySha256"])
        for digest in component["signingCertificateHistorySha256"]:
            _require_hex64(digest)
        _require_sorted_unique_strings(component["nativeAbis"])
        if not isinstance(component["versionCode"], int) or isinstance(component["versionCode"], bool) or component["versionCode"] <= 0:
            raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services component version")
        if not isinstance(component["size"], int) or isinstance(component["size"], bool) or component["size"] <= 0:
            raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services component size")
    signature_policy = _require_exact_keys(
        value["signaturePolicy"],
        {"mode", "packages", "realSignerSha256", "fakeSignerSha256", "sourceCommits", "apiFields"},
    )
    if (
        signature_policy["mode"] != "restricted-spoofing"
        or signature_policy["packages"] != ["com.google.android.gms"]
        or signature_policy["realSignerSha256"] != MICROG_REAL_CERT_SHA256
        or signature_policy["fakeSignerSha256"] != MICROG_FAKE_CERT_SHA256
        or signature_policy["sourceCommits"] != [LINEAGE_SPOOFING_BASE_COMMIT, LINEAGE_SPOOFING_SIGNING_INFO_COMMIT]
        or signature_policy["apiFields"] != ["signatures", "signingInfo", "forceQueryable"]
    ):
        raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services signature policy")
    product_policy = _require_exact_keys(value["productPolicy"], {"generator", "sourceCommit", "inputs", "outputs"})
    if (
        product_policy["generator"] != "scripts/generate-microg-product-policy.py"
        or product_policy["sourceCommit"] != MICROG_POLICY_UPSTREAM_COMMIT
    ):
        raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services product policy")
    for field in ("inputs", "outputs"):
        records = product_policy[field]
        if not isinstance(records, list) or not records:
            raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services product policy inventory")
        paths: list[bytes] = []
        for record in records:
            item = _require_exact_keys(record, {"path", "sha256"})
            if not isinstance(item["path"], str) or not item["path"]:
                raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services product policy path")
            _require_hex64(item["sha256"])
            paths.append(item["path"].encode("utf-8"))
        if paths != sorted(paths) or len(set(paths)) != len(paths):
            raise GoogleServicesError("google_services_spec_mismatch", "Google services product policy paths are not bytewise sorted")
    requirements = _require_exact_keys(
        value["runtimeRequirements"],
        {"corePackages", "runtimeCapabilities", "releaseCapabilities", "mapsImplementation", "unsupportedCapabilities"},
    )
    core_packages = requirements["corePackages"]
    if not isinstance(core_packages, list) or len(core_packages) != 3:
        raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services core package inventory")
    expected_core = {
        "com.google.android.gms": ("/system/product/priv-app/GmsCore/GmsCore.apk", 250932030),
        "com.google.android.gsf": ("/system/product/priv-app/GsfProxy/GsfProxy.apk", 8),
        "com.android.vending": ("/system/product/priv-app/Phonesky/Phonesky.apk", 83041710),
    }
    seen_packages: set[str] = set()
    for record in core_packages:
        item = _require_exact_keys(record, {"package", "factoryPath", "minVersionCode", "privileged"})
        pinned = expected_core.get(item["package"])
        if pinned is None or item["package"] in seen_packages:
            raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services core package")
        seen_packages.add(item["package"])
        if item["factoryPath"] != pinned[0] or item["minVersionCode"] != pinned[1] or item["privileged"] is not True:
            raise GoogleServicesError("google_services_spec_mismatch", "Google services core package pin mismatch")
    if (
        requirements["runtimeCapabilities"] != ["googlePlayServices", "accountAuth", "cloudMessaging", "fusedLocation", "playStore"]
        or requirements["releaseCapabilities"] != ["fcmDelivery", "fusedLocationBehavior", "maps", "auth", "playStoreOperations"]
        or requirements["mapsImplementation"] != "microg-mapbox-maplibre"
        or requirements["unsupportedCapabilities"] != ["playIntegrity", "deviceCertification", "drm", "antiCheat"]
    ):
        raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services capability requirements")
    return value


def _validate_release_metadata_v1(value: Mapping[str, Any], release: str) -> Mapping[str, Any]:
    required = {
        "schema",
        "provider",
        "release",
        "integrationRevision",
        "source",
        "android",
        "selection",
        "archive",
        "runtimeRequirements",
        "members",
        "apks",
    }
    if set(value) != required:
        raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services release metadata")
    if (
        value["schema"] != GOOGLE_RELEASE_SCHEMA
        or value["provider"] != PROVIDER_MINDTHEGAPPS
        or value["release"] != release
        or value["integrationRevision"] != INTEGRATION_REVISION
    ):
        raise GoogleServicesError("google_services_spec_mismatch", "unsupported Google services release metadata")
    android = _require_mapping(value["android"])
    if (
        android.get("release") != "13.0.0"
        or android.get("api") != 33
        or android.get("archiveArch") != "arm64"
        or android.get("runtimeAbis") != ["arm64-v8a"]
        or android.get("targetProduct") != "raven"
        or android.get("setupWizardMode") != "DISABLED"
        or android.get("partitionAliases") != {
            "/product": "/system/product",
            "/system_ext": "/system/system_ext",
        }
    ):
        raise GoogleServicesError("google_services_spec_mismatch", "unsupported Google services Android target")
    archive = _require_mapping(value["archive"])
    certificate = _require_mapping(archive.get("certificate"))
    for field in ("sha256",):
        if not isinstance(archive.get(field), str) or _HEX64.fullmatch(str(archive[field])) is None:
            raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services archive pin")
    for field in ("sha256", "derSha256"):
        if not isinstance(certificate.get(field), str) or _HEX64.fullmatch(str(certificate[field])) is None:
            raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services certificate pin")
    members = value["members"]
    apks = value["apks"]
    if not isinstance(members, list) or len(members) != archive.get("entryCount") or not isinstance(apks, list):
        raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services release inventory")
    paths: set[str] = set()
    selected = 0
    selected_bytes = 0
    for member in members:
        item = _require_mapping(member)
        path = item.get("archivePath")
        if not isinstance(path, str) or path in paths:
            raise GoogleServicesError("google_services_spec_mismatch", "duplicate Google services release member")
        paths.add(path)
        if not isinstance(item.get("sha256"), str) or _HEX64.fullmatch(str(item["sha256"])) is None:
            raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services member pin")
        if item.get("classification") not in {"runtime", "recovery-only", "conditional", "architecture-inapplicable"}:
            raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services member classification")
        if item.get("selected") is True:
            selected += 1
            selected_bytes += int(item.get("size", -1))
            if not isinstance(item.get("runtimePath"), str):
                raise GoogleServicesError("google_services_spec_mismatch", "selected Google services member lacks runtime path")
    selection = _require_mapping(value["selection"])
    if selected != selection.get("selectedMemberCount") or selected_bytes != selection.get("selectedBytes"):
        raise GoogleServicesError("google_services_spec_mismatch", "Google services selection summary mismatch")
    apk_paths: set[str] = set()
    selected_packages: set[str] = set()
    selected_apks = 0
    for apk in apks:
        item = _require_mapping(apk)
        path = item.get("path")
        package = item.get("package")
        if path not in paths or path in apk_paths or not isinstance(package, str):
            raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services APK inventory")
        apk_paths.add(str(path))
        histories = item.get("signingCertificateHistorySha256")
        if not isinstance(histories, list) or not histories or any(not isinstance(x, str) or _HEX64.fullmatch(x) is None for x in histories):
            raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services APK signer pin")
        if item.get("selected") is True:
            selected_apks += 1
            if package in selected_packages:
                raise GoogleServicesError("google_services_spec_mismatch", "selected Google services package is duplicated")
            selected_packages.add(package)
    if len(apks) != selection.get("archiveApkCount") or selected_apks != selection.get("selectedApkCount"):
        raise GoogleServicesError("google_services_spec_mismatch", "Google services APK selection summary mismatch")
    if not set(_CORE_PACKAGES).issubset(selected_packages):
        raise GoogleServicesError("google_services_spec_mismatch", "Google services core packages are incomplete")
    return value


def load_release_spec(project_root: Path, release: str = MICROG_PLAY_RELEASE) -> ReleaseSpec:
    entry = _RELEASE_REGISTRY.get(release)
    if entry is None:
        raise GoogleServicesError("google_services_spec_mismatch", "unsupported Google services release")
    metadata_path = project_root / entry["metadata"]
    try:
        payload = metadata_path.read_bytes()
    except OSError as exc:
        raise GoogleServicesError("google_services_spec_mismatch", "Google services public release metadata is missing") from exc
    actual = hashlib.sha256(payload).hexdigest()
    if actual != entry["metadataSha256"]:
        raise GoogleServicesError("google_services_spec_mismatch", "Google services public release metadata pin mismatch")
    try:
        parsed = json.loads(payload)
    except (ValueError, UnicodeError) as exc:
        raise GoogleServicesError("google_services_spec_mismatch", "invalid Google services public release metadata") from exc
    metadata = _validate_release_metadata(parsed, release)
    fingerprint = hashlib.sha256(_canonical_json(_spec_payload(metadata, actual))).hexdigest()
    return ReleaseSpec(
        release=release,
        metadata_path=metadata_path,
        metadata_sha256=actual,
        metadata=metadata,
        fingerprint=fingerprint,
        data_compatibility_fingerprint=fingerprint,
    )


def asset_directory(project_root: Path, release: str) -> Path:
    return project_root / ".xenoid" / "artifacts" / "google-services" / release


def asset_paths(project_root: Path, spec: ReleaseSpec) -> dict[str, Path]:
    directory = asset_directory(project_root, spec.release)
    if spec.schema == GOOGLE_RELEASE_SCHEMA_V2:
        return {
            "gmsCore": directory / str(spec.component("gmsCore")["basename"]),
            "gsfProxy": directory / str(spec.component("gsfProxy")["basename"]),
            "manifest": directory / "import.json",
        }
    archive = spec.archive
    return {
        "archive": directory / str(archive["basename"]),
        "certificate": directory / str(archive["certificate"]["basename"]),
        "manifest": directory / "import.json",
    }


def _parse_pem(payload: bytes, expected_der_sha256: str) -> bytes:
    if len(payload) > 16 * 1024:
        raise GoogleServicesError("google_services_asset_invalid", "Google services certificate is too large")
    try:
        text = payload.decode("ascii")
    except UnicodeError as exc:
        raise GoogleServicesError("google_services_asset_invalid", "invalid Google services certificate") from exc
    match = re.fullmatch(
        r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\r\n]+)\s*-----END CERTIFICATE-----\s*",
        text,
    )
    if match is None:
        raise GoogleServicesError("google_services_asset_invalid", "Google services certificate must contain exactly one certificate")
    try:
        der = base64.b64decode(re.sub(r"\s+", "", match.group(1)), validate=True)
    except ValueError as exc:
        raise GoogleServicesError("google_services_asset_invalid", "invalid Google services certificate encoding") from exc
    if hashlib.sha256(der).hexdigest() != expected_der_sha256:
        raise GoogleServicesError("google_services_asset_invalid", "Google services certificate identity does not match its pin")
    return der


def _expected_import_manifest_v1(spec: ReleaseSpec) -> dict[str, Any]:
    archive = spec.archive
    certificate = archive["certificate"]
    return {
        "schema": GOOGLE_IMPORT_SCHEMA_V1,
        "provider": spec.provider,
        "release": spec.release,
        "integrationRevision": spec.metadata["integrationRevision"],
        "metadataSha256": spec.metadata_sha256,
        "zipBasename": archive["basename"],
        "zipSize": archive["size"],
        "zipSha256": archive["sha256"],
        "certificateBasename": certificate["basename"],
        "certificateSize": certificate["size"],
        "certificateSha256": certificate["sha256"],
        "certificateDerSha256": certificate["derSha256"],
    }


def _read_validated_v1_import_manifest(project_root: Path) -> tuple[ReleaseSpec, bytes]:
    spec = load_release_spec(project_root, MINDTHEGAPPS_RELEASE)
    paths = asset_paths(project_root, spec)
    manifest_path = paths["manifest"]
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(manifest_path, flags)
    except OSError as exc:
        raise GoogleServicesError("google_services_assets_missing", "import the pinned Google services source release first") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise GoogleServicesError("google_services_asset_invalid", "Google services import manifest permissions are unsafe")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read()
    finally:
        os.close(descriptor)
    try:
        parsed = json.loads(payload)
    except (ValueError, UnicodeError) as exc:
        raise GoogleServicesError("google_services_asset_invalid", "invalid Google services import manifest") from exc
    if (
        not isinstance(parsed, Mapping)
        or set(parsed) != _IMPORT_KEYS_V1
        or dict(parsed) != _expected_import_manifest_v1(spec)
        or payload != _canonical_json(parsed) + b"\n"
    ):
        raise GoogleServicesError("google_services_asset_invalid", "Google services import manifest does not match imported bytes")
    return spec, payload


def _mindthegapps_source_dependency(project_root: Path, spec: ReleaseSpec) -> dict[str, Any]:
    _, manifest_payload = _read_validated_v1_import_manifest(project_root)
    component = spec.component("playStoreSeed")
    return {
        "release": MINDTHEGAPPS_RELEASE,
        "metadataSha256": _RELEASE_REGISTRY[MINDTHEGAPPS_RELEASE]["metadataSha256"],
        "importManifestSha256": hashlib.sha256(manifest_payload).hexdigest(),
        "archivePath": str(component["sourcePath"]),
        "memberSha256": str(component["sha256"]),
    }


def _expected_import_manifest_v2(project_root: Path, spec: ReleaseSpec) -> dict[str, Any]:
    components = []
    for component_id in ("gmsCore", "gsfProxy"):
        component = spec.component(component_id)
        components.append(
            {
                "id": component_id,
                "basename": str(component["basename"]),
                "size": int(component["size"]),
                "sha256": str(component["sha256"]),
                "signingCertificateHistorySha256": list(component["signingCertificateHistorySha256"]),
            }
        )
    return {
        "schema": GOOGLE_IMPORT_SCHEMA_V2,
        "provider": spec.provider,
        "release": spec.release,
        "integrationRevision": spec.metadata["integrationRevision"],
        "metadataSha256": spec.metadata_sha256,
        "components": components,
        "sourceDependencies": [_mindthegapps_source_dependency(project_root, spec)],
    }


def _quick_validate_directory(directory: Path, expected_names: set[str]) -> None:
    try:
        directory_info = directory.lstat()
    except FileNotFoundError as exc:
        raise GoogleServicesError("google_services_assets_missing", "import the pinned Google services release first") from exc
    if not stat.S_ISDIR(directory_info.st_mode) or stat.S_ISLNK(directory_info.st_mode) or directory_info.st_mode & 0o077:
        raise GoogleServicesError("google_services_asset_invalid", "Google services asset directory permissions are unsafe")
    try:
        actual_names = {entry.name for entry in os.scandir(directory)}
    except OSError as exc:
        raise GoogleServicesError("google_services_asset_invalid", "Google services asset directory cannot be read") from exc
    if actual_names != expected_names:
        raise GoogleServicesError("google_services_asset_invalid", "Google services asset directory contains unexpected files")


def _require_safe_asset_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o077:
        raise GoogleServicesError("google_services_asset_invalid", "Google services asset permissions are unsafe")


def _quick_validate_manifest(manifest_path: Path, expected: Mapping[str, Any], keys: set[str]) -> None:
    try:
        raw_manifest = json.loads(manifest_path.read_bytes())
    except (OSError, ValueError, UnicodeError) as exc:
        raise GoogleServicesError("google_services_asset_invalid", "invalid Google services import manifest") from exc
    if not isinstance(raw_manifest, Mapping) or set(raw_manifest) != keys or dict(raw_manifest) != dict(expected):
        raise GoogleServicesError("google_services_asset_invalid", "Google services import manifest does not match imported bytes")


def quick_validate_assets(project_root: Path, spec: ReleaseSpec) -> dict[str, Any]:
    if spec.schema == GOOGLE_RELEASE_SCHEMA_V2:
        return _quick_validate_assets_v2(project_root, spec)
    return _quick_validate_assets_v1(project_root, spec)


def _quick_validate_assets_v2(project_root: Path, spec: ReleaseSpec) -> dict[str, Any]:
    paths = asset_paths(project_root, spec)
    _quick_validate_directory(paths["manifest"].parent, {path.name for path in paths.values()})
    for path in paths.values():
        _require_safe_asset_file(path)
    sizes: dict[str, int] = {}
    for component_id in ("gmsCore", "gsfProxy"):
        component = spec.component(component_id)
        size, digest = _stream_sha256(paths[component_id], int(component["size"]))
        if digest != component["sha256"]:
            raise GoogleServicesError("google_services_asset_invalid", "Google services asset pin mismatch")
        sizes[component_id] = size
    _quick_validate_manifest(paths["manifest"], _expected_import_manifest_v2(project_root, spec), _IMPORT_KEYS_V2)
    return {
        "ok": True,
        "provider": spec.provider,
        "release": spec.release,
        "specSha256": spec.fingerprint,
        "componentSizes": sizes,
    }


def _quick_validate_assets_v1(project_root: Path, spec: ReleaseSpec) -> dict[str, Any]:
    paths = asset_paths(project_root, spec)
    zip_path, pem_path, manifest_path = paths["archive"], paths["certificate"], paths["manifest"]
    _quick_validate_directory(zip_path.parent, {path.name for path in paths.values()})
    for path in paths.values():
        _require_safe_asset_file(path)
    zip_size, zip_sha = _stream_sha256(zip_path, int(spec.archive["size"]))
    pem_size, pem_sha = _stream_sha256(pem_path, int(spec.archive["certificate"]["size"]))
    if zip_sha != spec.archive["sha256"] or pem_sha != spec.archive["certificate"]["sha256"]:
        raise GoogleServicesError("google_services_asset_invalid", "Google services asset pin mismatch")
    pem_payload = pem_path.read_bytes()
    _parse_pem(pem_payload, str(spec.archive["certificate"]["derSha256"]))
    _quick_validate_manifest(manifest_path, _expected_import_manifest_v1(spec), _IMPORT_KEYS_V1)
    return {
        "ok": True,
        "provider": spec.provider,
        "release": spec.release,
        "specSha256": spec.fingerprint,
        "zipSize": zip_size,
        "certificateSize": pem_size,
    }


def _safe_member_name(name: str) -> tuple[str, ...]:
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        raise GoogleServicesError("google_services_asset_invalid", "unsafe path in Google services archive")
    if unicodedata.normalize("NFC", name) != name:
        raise GoogleServicesError("google_services_asset_invalid", "non-canonical path in Google services archive")
    try:
        encoded = name.encode("utf-8")
    except UnicodeError as exc:
        raise GoogleServicesError("google_services_asset_invalid", "invalid path in Google services archive") from exc
    if len(encoded) > _MAX_PATH_BYTES:
        raise GoogleServicesError("google_services_asset_invalid", "Google services archive path is too long")
    components = tuple(name.split("/"))
    if any(component in {"", ".", ".."} or len(component.encode("utf-8")) > _MAX_COMPONENT_BYTES for component in components):
        raise GoogleServicesError("google_services_asset_invalid", "unsafe path component in Google services archive")
    return components


def _validate_zip_inventory(bundle: zipfile.ZipFile, spec: ReleaseSpec) -> dict[str, zipfile.ZipInfo]:
    expected = {str(item["archivePath"]): item for item in spec.members}
    infos = bundle.infolist()
    if len(infos) != spec.archive["entryCount"] or sum(info.file_size for info in infos) != spec.archive["expandedBytes"]:
        raise GoogleServicesError("google_services_asset_invalid", "Google services archive inventory size mismatch")
    if len(infos) != len(expected):
        raise GoogleServicesError("google_services_asset_invalid", "Google services archive inventory mismatch")
    names: dict[str, zipfile.ZipInfo] = {}
    folded: set[str] = set()
    file_paths: set[tuple[str, ...]] = set()
    for info in infos:
        components = _safe_member_name(info.filename)
        normalized_fold = "/".join(components).casefold()
        if normalized_fold in folded or components in file_paths:
            raise GoogleServicesError("google_services_asset_invalid", "duplicate Google services archive path")
        folded.add(normalized_fold)
        file_paths.add(components)
        item = expected.get(info.filename)
        if item is None:
            raise GoogleServicesError("google_services_asset_invalid", "unknown Google services archive member")
        if info.is_dir():
            raise GoogleServicesError("google_services_asset_invalid", "unexpected directory entry in Google services archive")
        mode = (info.external_attr >> 16) & 0xFFFF
        if mode and not stat.S_ISREG(mode):
            raise GoogleServicesError("google_services_asset_invalid", "special file in Google services archive")
        expected_method = zipfile.ZIP_STORED if item["compression"] == "stored" else zipfile.ZIP_DEFLATED
        if info.compress_type != expected_method or info.flag_bits != item["flagBits"]:
            raise GoogleServicesError("google_services_asset_invalid", "Google services archive compression metadata mismatch")
        if info.flag_bits & 0x1 or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            raise GoogleServicesError("google_services_asset_invalid", "unsupported Google services archive member")
        if (
            info.file_size != item["size"]
            or info.compress_size != item["compressedSize"]
            or f"{info.CRC:08x}" != item["crc32"]
            or info.file_size > spec.archive["maxMemberBytes"]
        ):
            raise GoogleServicesError("google_services_asset_invalid", "Google services archive member metadata mismatch")
        names[info.filename] = info
    for path in file_paths:
        for length in range(1, len(path)):
            if path[:length] in file_paths:
                raise GoogleServicesError("google_services_asset_invalid", "file and directory paths collide in Google services archive")
    if set(names) != set(expected):
        raise GoogleServicesError("google_services_asset_invalid", "Google services archive inventory mismatch")
    return names


def _manifest_sections(payload: bytes) -> dict[str, Mapping[str, str]]:
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise GoogleServicesError("google_services_asset_invalid", "invalid signed manifest encoding") from exc
    physical = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    logical: list[str] = []
    for line in physical:
        if line.startswith(" "):
            if not logical:
                raise GoogleServicesError("google_services_asset_invalid", "invalid signed manifest continuation")
            logical[-1] += line[1:]
        else:
            logical.append(line)
    sections: dict[str, Mapping[str, str]] = {}
    current: dict[str, str] = {}
    for line in logical + [""]:
        if line == "":
            if current:
                name = current.get("Name", "")
                if name:
                    if name in sections:
                        raise GoogleServicesError("google_services_asset_invalid", "duplicate signed manifest entry")
                    sections[name] = dict(current)
                current = {}
            continue
        if ": " not in line:
            raise GoogleServicesError("google_services_asset_invalid", "invalid signed manifest field")
        key, value = line.split(": ", 1)
        if key in current:
            raise GoogleServicesError("google_services_asset_invalid", "duplicate signed manifest field")
        current[key] = value
    return sections


def _verify_signed_member_coverage(bundle: zipfile.ZipFile, spec: ReleaseSpec) -> None:
    signature = spec.archive["jarSignature"]
    try:
        manifest_sections = _manifest_sections(bundle.read(signature["manifestPath"]))
        signature_sections = _manifest_sections(bundle.read(signature["signatureFilePath"]))
    except KeyError as exc:
        raise GoogleServicesError("google_services_asset_invalid", "Google services signed manifest is missing") from exc
    for item in spec.members:
        if item["selected"] is not True:
            continue
        name = str(item["archivePath"])
        manifest = manifest_sections.get(name)
        signed = signature_sections.get(name)
        if manifest is None or signed is None:
            raise GoogleServicesError("google_services_asset_invalid", "selected Google services member is unsigned")
        digest_value = manifest.get("SHA-256-Digest")
        if not isinstance(digest_value, str):
            raise GoogleServicesError("google_services_asset_invalid", "selected Google services member lacks a SHA-256 signature digest")
        try:
            expected = base64.b64decode(digest_value, validate=True)
        except ValueError as exc:
            raise GoogleServicesError("google_services_asset_invalid", "invalid signed member digest") from exc
        actual = hashlib.sha256(bundle.read(name)).digest()
        if actual != expected:
            raise GoogleServicesError("google_services_asset_invalid", "selected Google services member digest mismatch")


def _run_checked(command: list[str], code: str, message: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    try:
        bounded = run_bounded(
            command,
            cwd=Path.cwd(),
            deadline=time.monotonic() + timeout,
            project_root=Path.cwd(),
        )
    except OSError as exc:
        raise GoogleServicesError(code, message) from exc
    if not bounded.ok:
        raise GoogleServicesError(code, message)
    return subprocess.CompletedProcess(
        command,
        bounded.returncode or 0,
        bounded.stdout_tail,
        bounded.stderr_tail,
    )


def _tool_paths() -> dict[str, str]:
    result: dict[str, str] = {}
    for name in ("keytool", "jarsigner", "aapt2", "apksigner"):
        path = which(name)
        if path is None:
            raise GoogleServicesError("google_services_tools_missing", "install the Android signing and Java verification tools")
        result[name] = path
    return result


def _certificate_blocks(text: str) -> list[bytes]:
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\r\n]+?)\s*-----END CERTIFICATE-----",
        text,
    )
    result: list[bytes] = []
    for block in blocks:
        try:
            result.append(base64.b64decode(re.sub(r"\s+", "", block), validate=True))
        except ValueError as exc:
            raise GoogleServicesError("google_services_asset_invalid", "invalid signer certificate output") from exc
    return result


def _verify_outer_signature(zip_path: Path, pem_path: Path, spec: ReleaseSpec, tools: Mapping[str, str]) -> None:
    pem_der = _parse_pem(pem_path.read_bytes(), str(spec.archive["certificate"]["derSha256"]))
    printed = _run_checked(
        [tools["keytool"], "-printcert", "-rfc", "-jarfile", str(zip_path)],
        "google_services_asset_invalid",
        "Google services archive signer cannot be read",
    )
    signer_blocks = _certificate_blocks(printed.stdout)
    if len(signer_blocks) != 1 or signer_blocks[0] != pem_der:
        raise GoogleServicesError("google_services_asset_invalid", "Google services archive signer does not match the companion certificate")
    with tempfile.TemporaryDirectory(prefix="xenoid-gapps-trust-") as temp:
        root = Path(temp)
        root.chmod(0o700)
        store = root / "release.p12"
        password = secrets.token_urlsafe(24)
        _run_checked(
            [
                tools["keytool"],
                "-importcert",
                "-noprompt",
                "-alias",
                "release",
                "-file",
                str(pem_path),
                "-keystore",
                str(store),
                "-storetype",
                "PKCS12",
                "-storepass",
                password,
            ],
            "google_services_asset_invalid",
            "Google services companion certificate cannot be imported",
        )
        verified = _run_checked(
            [
                tools["jarsigner"],
                "-verify",
                "-strict",
                "-keystore",
                str(store),
                "-storetype",
                "PKCS12",
                "-storepass",
                password,
                str(zip_path),
            ],
            "google_services_asset_invalid",
            "Google services archive signature verification failed",
            timeout=600,
        )
        if "jar verified" not in (verified.stdout + verified.stderr).lower():
            raise GoogleServicesError("google_services_asset_invalid", "Google services archive signature was not verified")


def _parse_badging(output: str) -> tuple[str, int, str]:
    match = re.search(
        r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']*)'",
        output,
        flags=re.MULTILINE,
    )
    if match is None:
        raise GoogleServicesError("google_services_asset_invalid", "Google services APK identity cannot be read")
    return match.group(1), int(match.group(2)), match.group(3)


def _signer_histories(output: str) -> list[str]:
    result: list[str] = []
    for line in output.splitlines():
        if line.startswith("Signer ") and " certificate SHA-256 digest: " in line:
            digest = line.rsplit(": ", 1)[1].strip().lower()
            if digest not in result:
                result.append(digest)
    if not result:
        raise GoogleServicesError("google_services_asset_invalid", "Google services APK signer cannot be read")
    return result


def _elf_identity(payload: bytes) -> tuple[int, int]:
    if len(payload) < 20 or payload[:4] != b"\x7fELF":
        raise GoogleServicesError("google_services_asset_invalid", "invalid native library in Google services payload")
    elf_class = payload[4]
    endian = payload[5]
    if endian not in {1, 2}:
        raise GoogleServicesError("google_services_asset_invalid", "invalid native library byte order")
    machine = int.from_bytes(payload[18:20], "little" if endian == 1 else "big")
    return elf_class, machine


def _validate_apk_native_payload(
    apk_path: Path,
    expected_apk: Mapping[str, Any],
) -> None:
    expected_abis = list(expected_apk["nativeAbis"])
    exceptions = expected_apk.get("abiPathExceptions", {})
    if not isinstance(exceptions, Mapping):
        raise GoogleServicesError("google_services_asset_invalid", "invalid Google services APK ABI exceptions")
    try:
        with zipfile.ZipFile(apk_path) as bundle:
            native_infos = [
                info
                for info in bundle.infolist()
                if info.filename.startswith("lib/") and info.filename.endswith(".so")
            ]
            actual_abis = sorted({info.filename.split("/")[1] for info in native_infos if len(info.filename.split("/")) > 2})
            if actual_abis != sorted(expected_abis):
                raise GoogleServicesError("google_services_asset_invalid", "Google services APK native ABI mismatch")
            seen_exceptions: set[str] = set()
            for info in native_infos:
                abi = info.filename.split("/")[1]
                elf_class, machine = _elf_identity(bundle.read(info)[:64])
                expected = {
                    "arm64-v8a": (2, 183),
                    "armeabi-v7a": (1, 40),
                    "x86": (1, 3),
                    "x86_64": (2, 62),
                }.get(abi)
                exception = exceptions.get(info.filename)
                if exception is not None:
                    pinned = _require_mapping(exception, code="google_services_asset_invalid")
                    expected = (pinned.get("elfClass"), pinned.get("machine"))
                    seen_exceptions.add(info.filename)
                if expected is None or (elf_class, machine) != expected:
                    raise GoogleServicesError("google_services_asset_invalid", "unsupported native ABI in Google services APK")
            if seen_exceptions != set(exceptions):
                raise GoogleServicesError("google_services_asset_invalid", "Google services APK ABI exception path mismatch")
    except (OSError, zipfile.BadZipFile) as exc:
        raise GoogleServicesError("google_services_asset_invalid", "invalid Google services APK") from exc


def _verify_apks(bundle: zipfile.ZipFile, spec: ReleaseSpec, tools: Mapping[str, str]) -> None:
    with tempfile.TemporaryDirectory(prefix="xenoid-gapps-apks-") as temp:
        root = Path(temp)
        root.chmod(0o700)
        for index, expected in enumerate(spec.apks):
            path = str(expected["path"])
            apk_path = root / f"{index:02d}.apk"
            with bundle.open(path) as source, apk_path.open("wb") as target:
                shutil.copyfileobj(source, target, _COPY_CHUNK)
                target.flush()
                os.fsync(target.fileno())
            apk_path.chmod(0o600)
            if hashlib.sha256(apk_path.read_bytes()).hexdigest() != expected["sha256"]:
                raise GoogleServicesError("google_services_asset_invalid", "Google services APK pin mismatch")
            badging = _run_checked(
                [tools["aapt2"], "dump", "badging", str(apk_path)],
                "google_services_asset_invalid",
                "Google services APK package identity verification failed",
            )
            package, version_code, version_name = _parse_badging(badging.stdout)
            if (
                package != expected["package"]
                or version_code != expected["versionCode"]
                or version_name != expected["versionName"]
            ):
                raise GoogleServicesError("google_services_asset_invalid", "Google services APK identity mismatch")
            command = [tools["apksigner"], "verify", "--verbose", "--print-certs"]
            verification_range = _require_mapping(expected["verificationRange"], code="google_services_asset_invalid")
            if verification_range.get("minSdk") is not None:
                command.extend(["--min-sdk-version", str(verification_range["minSdk"])])
            if verification_range.get("maxSdk") is not None:
                command.extend(["--max-sdk-version", str(verification_range["maxSdk"])])
            command.append(str(apk_path))
            signer = _run_checked(
                command,
                "google_services_asset_invalid",
                "Google services APK signature verification failed",
            )
            histories = _signer_histories(signer.stdout)
            if histories != expected["signingCertificateHistorySha256"] or histories[0] != expected["signerSha256"]:
                raise GoogleServicesError("google_services_asset_invalid", "Google services APK signer mismatch")
            _validate_apk_native_payload(apk_path, expected)


def _verify_member_streams(bundle: zipfile.ZipFile, spec: ReleaseSpec) -> None:
    total = 0
    for expected in spec.members:
        digest = hashlib.sha256()
        count = 0
        try:
            with bundle.open(str(expected["archivePath"])) as stream:
                while True:
                    chunk = stream.read(_COPY_CHUNK)
                    if not chunk:
                        break
                    count += len(chunk)
                    total += len(chunk)
                    if count > expected["size"] or total > spec.archive["maxExpandedBytes"]:
                        raise GoogleServicesError("google_services_asset_invalid", "Google services archive exceeds pinned limits")
                    digest.update(chunk)
        except (KeyError, OSError, zipfile.BadZipFile) as exc:
            raise GoogleServicesError("google_services_asset_invalid", "Google services archive member cannot be read") from exc
        if count != expected["size"] or digest.hexdigest() != expected["sha256"]:
            raise GoogleServicesError("google_services_asset_invalid", "Google services archive member pin mismatch")


def deep_validate_assets(zip_path: Path, pem_path: Path, spec: ReleaseSpec) -> dict[str, Any]:
    tools = _tool_paths()
    zip_size, zip_sha = _stream_sha256(zip_path, int(spec.archive["size"]))
    pem_size, pem_sha = _stream_sha256(pem_path, int(spec.archive["certificate"]["size"]))
    if zip_sha != spec.archive["sha256"] or pem_sha != spec.archive["certificate"]["sha256"]:
        raise GoogleServicesError("google_services_asset_invalid", "Google services asset pin mismatch")
    _verify_outer_signature(zip_path, pem_path, spec, tools)
    try:
        with zipfile.ZipFile(zip_path) as bundle:
            _validate_zip_inventory(bundle, spec)
            if bundle.read("build.prop") != b"arch=arm64\nversion=33\nversion_nice=13.0.0\n":
                raise GoogleServicesError("google_services_asset_invalid", "Google services archive Android target mismatch")
            _verify_signed_member_coverage(bundle, spec)
            _verify_member_streams(bundle, spec)
            _verify_apks(bundle, spec, tools)
            for member in spec.members:
                if member["archivePath"].endswith("libjni_latinimegoogle.so"):
                    elf_class, machine = _elf_identity(bundle.read(str(member["archivePath"]))[:64])
                    expected = (2, 183) if "/lib64/" in member["archivePath"] else (1, 40)
                    if (elf_class, machine) != expected:
                        raise GoogleServicesError("google_services_asset_invalid", "standalone Google services native library ABI mismatch")
    except GoogleServicesError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise GoogleServicesError("google_services_asset_invalid", "invalid Google services archive") from exc
    return {
        "ok": True,
        "provider": spec.provider,
        "release": spec.release,
        "specSha256": spec.fingerprint,
        "zipSize": zip_size,
        "certificateSize": pem_size,
        "deepVerified": True,
    }


def _copy_regular_source(source: Path, destination: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise GoogleServicesError("google_services_asset_invalid", "Google services import source is not a safe regular file") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise GoogleServicesError("google_services_asset_invalid", "Google services import source is not a regular file")
        target_descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as source_stream, os.fdopen(target_descriptor, "wb", closefd=False) as target_stream:
                while True:
                    chunk = source_stream.read(_COPY_CHUNK)
                    if not chunk:
                        break
                    size += len(chunk)
                    digest.update(chunk)
                    target_stream.write(chunk)
                target_stream.flush()
                os.fsync(target_stream.fileno())
            os.fchmod(target_descriptor, 0o600)
        finally:
            os.close(target_descriptor)
    finally:
        os.close(descriptor)
    return size, digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_private_json(path: Path, data: Mapping[str, Any]) -> None:
    payload = _canonical_json(data) + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def _cleanup_abandoned_imports(parent: Path) -> None:
    for entry in os.scandir(parent):
        if not entry.name.startswith(".import-") or not entry.is_dir(follow_symlinks=False):
            continue
        candidate = parent / entry.name
        marker = candidate / ".owner"
        try:
            if marker.is_symlink() or marker.read_text(encoding="ascii") not in {_IMPORT_OWNER_V1, _IMPORT_OWNER_V2}:
                continue
        except (OSError, UnicodeError):
            continue
        shutil.rmtree(candidate)


def import_mindthegapps(project_root: Path, source_zip: Path, source_pem: Path) -> dict[str, Any]:
    if source_zip.name != f"{MINDTHEGAPPS_RELEASE}.zip" or source_pem.name != "release.x509.pem":
        raise GoogleServicesError("google_services_asset_invalid", "Google services import filenames do not match the pinned release")
    spec = load_release_spec(project_root, MINDTHEGAPPS_RELEASE)
    parent = project_root / ".xenoid" / "artifacts" / "google-services"
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    parent.chmod(0o700)
    lock_path = parent / ".import.lock"
    lock_descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(lock_descriptor, 0o600)
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        _cleanup_abandoned_imports(parent)
        final = parent / spec.asset_dirname
        if final.exists():
            quick_validate_assets(project_root, spec)
            return {"ok": True, **spec.public_dict(), "imported": False, "existing": True}
        temp = Path(tempfile.mkdtemp(prefix=".import-mindthegapps-", dir=parent))
        temp.chmod(0o700)
        marker = temp / ".owner"
        marker.write_text(_IMPORT_OWNER_V1, encoding="ascii")
        marker.chmod(0o600)
        try:
            target_zip = temp / str(spec.archive["basename"])
            target_pem = temp / str(spec.archive["certificate"]["basename"])
            zip_size, zip_sha = _copy_regular_source(source_zip, target_zip)
            pem_size, pem_sha = _copy_regular_source(source_pem, target_pem)
            if (
                zip_size != spec.archive["size"]
                or zip_sha != spec.archive["sha256"]
                or pem_size != spec.archive["certificate"]["size"]
                or pem_sha != spec.archive["certificate"]["sha256"]
            ):
                raise GoogleServicesError("google_services_asset_invalid", "Google services import source does not match the pinned release")
            deep_validate_assets(target_zip, target_pem, spec)
            _write_private_json(temp / "import.json", _expected_import_manifest_v1(spec))
            marker.unlink()
            _fsync_directory(temp)
            try:
                os.rename(temp, final)
            except OSError as exc:
                if exc.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                    raise
                quick_validate_assets(project_root, spec)
                shutil.rmtree(temp, ignore_errors=True)
                return {"ok": True, **spec.public_dict(), "imported": False, "existing": True}
            final.chmod(0o700)
            _fsync_directory(parent)
            quick_validate_assets(project_root, spec)
            return {"ok": True, **spec.public_dict(), "imported": True, "existing": False}
        except Exception:
            if temp.exists():
                shutil.rmtree(temp, ignore_errors=True)
            raise
    finally:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(lock_descriptor)


_MICROG_SDK_PINS = {
    "gmsCore": (19, 29),
    "gsfProxy": (10, 23),
}


def _parse_sdk_levels(output: str) -> tuple[Optional[int], Optional[int]]:
    min_sdk = re.search(r"^minSdkVersion:'([0-9]+)'", output, flags=re.MULTILINE)
    target_sdk = re.search(r"^targetSdkVersion:'([0-9]+)'", output, flags=re.MULTILINE)
    return (
        int(min_sdk.group(1)) if min_sdk is not None else None,
        int(target_sdk.group(1)) if target_sdk is not None else None,
    )


class _XmltreeMetadataScanner:
    """Bounded streaming extractor for meta-data name/value pairs."""

    def __init__(self, wanted: str) -> None:
        self.wanted = wanted
        self.value: Optional[str] = None
        self._block: Optional[list[str]] = None
        self._pending = bytearray()

    def _close_block(self) -> None:
        block, self._block = self._block, None
        if not block or not any(f'="{self.wanted}"' in line for line in block):
            return
        for line in block:
            match = re.search(r":value\(0x[0-9a-f]+\)=(@0x[0-9a-f]+|\"[0-9a-fA-F]+\")", line)
            if match is not None:
                self.value = match.group(1)
                return

    def __call__(self, chunk: bytes) -> None:
        self._pending.extend(chunk)
        while True:
            newline = self._pending.find(b"\n")
            if newline < 0:
                if len(self._pending) > 64 * 1024:
                    raise GoogleServicesError("google_services_asset_invalid", "Google services APK manifest line is too long")
                return
            line = bytes(self._pending[:newline]).decode("utf-8", "replace")
            del self._pending[: newline + 1]
            if "E: meta-data" in line:
                self._close_block()
                self._block = []
            elif "E: " in line:
                self._close_block()
            elif self._block is not None and " A: " in line:
                if len(self._block) >= 8:
                    raise GoogleServicesError("google_services_asset_invalid", "Google services APK meta-data block is too large")
                self._block.append(line)


class _ResourceValueScanner:
    """Bounded streaming extractor for one string resource value."""

    def __init__(self, resource_id: str, name: str) -> None:
        self.anchor = f"resource {resource_id} string/{name}"
        self.candidates: set[str] = set()
        self._armed = 0
        self._pending = bytearray()

    def __call__(self, chunk: bytes) -> None:
        self._pending.extend(chunk)
        while True:
            newline = self._pending.find(b"\n")
            if newline < 0:
                if len(self._pending) > 64 * 1024:
                    raise GoogleServicesError("google_services_asset_invalid", "Google services resource line is too long")
                return
            line = bytes(self._pending[:newline]).decode("utf-8", "replace")
            del self._pending[: newline + 1]
            if self.anchor in line:
                self._armed = 2
                continue
            if self._armed > 0:
                self._armed -= 1
                match = re.search(r'\(\) "([0-9a-fA-F]+)"', line.strip())
                if match is not None:
                    self.candidates.add(match.group(1))
                    self._armed = 0
                    if len(self.candidates) > 2:
                        raise GoogleServicesError("google_services_asset_invalid", "Google services fake-signature resource is ambiguous")


def _run_scanner(command: list[str], scanner: Callable[[bytes], None], message: str) -> None:
    try:
        bounded = run_bounded(
            command,
            cwd=Path.cwd(),
            deadline=time.monotonic() + 300,
            project_root=Path.cwd(),
            stdout_consumer=scanner,
        )
    except OSError as exc:
        raise GoogleServicesError("google_services_asset_invalid", message) from exc
    if not bounded.ok:
        raise GoogleServicesError("google_services_asset_invalid", message)


def _microg_fake_signature_der(apk_path: Path, tools: Mapping[str, str]) -> bytes:
    scanner = _XmltreeMetadataScanner("fake-signature")
    _run_scanner(
        [tools["aapt2"], "dump", "xmltree", "--file", "AndroidManifest.xml", str(apk_path)],
        scanner,
        "Google services APK manifest cannot be read",
    )
    scanner._close_block()
    value = scanner.value
    if value is None:
        raise GoogleServicesError("google_services_asset_invalid", "Google services GmsCore fake-signature metadata is missing")
    if value.startswith("@0x"):
        resources = _ResourceValueScanner(value[1:], "fake_signature")
        _run_scanner(
            [tools["aapt2"], "dump", "resources", str(apk_path)],
            resources,
            "Google services GmsCore resources cannot be read",
        )
        if len(resources.candidates) != 1:
            raise GoogleServicesError("google_services_asset_invalid", "Google services GmsCore fake-signature resource is missing")
        value = f'"{resources.candidates.pop()}"'
    hex_value = value.strip('"')
    try:
        return bytes.fromhex(hex_value)
    except ValueError as exc:
        raise GoogleServicesError("google_services_asset_invalid", "invalid Google services fake-signature encoding") from exc


def _validate_microg_maps_payload(apk_path: Path) -> None:
    try:
        with zipfile.ZipFile(apk_path) as bundle:
            names = set(bundle.namelist())
    except (OSError, zipfile.BadZipFile) as exc:
        raise GoogleServicesError("google_services_asset_invalid", "invalid Google services APK") from exc
    required = {
        "lib/arm64-v8a/libmapbox-gl.so",
        "lib/armeabi-v7a/libmapbox-gl.so",
        "lib/x86/libmapbox-gl.so",
        "lib/x86_64/libmapbox-gl.so",
        "assets/sdk_versions/com.mapbox.mapboxsdk",
    }
    if not required.issubset(names):
        raise GoogleServicesError(
            "google_services_asset_invalid",
            "Google services GmsCore does not contain the pinned Mapbox/MapLibre Maps implementation",
        )


def _validate_microg_apk(
    apk_path: Path,
    component: Mapping[str, Any],
    spec: ReleaseSpec,
    tools: Mapping[str, str],
) -> None:
    badging = _run_checked(
        [tools["aapt2"], "dump", "badging", str(apk_path)],
        "google_services_asset_invalid",
        "Google services APK package identity verification failed",
    )
    package, version_code, version_name = _parse_badging(badging.stdout)
    if (
        package != component["package"]
        or version_code != component["versionCode"]
        or version_name != component["versionName"]
    ):
        raise GoogleServicesError("google_services_asset_invalid", "Google services APK identity mismatch")
    min_sdk, target_sdk = _parse_sdk_levels(badging.stdout)
    if (min_sdk, target_sdk) != _MICROG_SDK_PINS[str(component["id"])]:
        raise GoogleServicesError("google_services_asset_invalid", "Google services APK SDK inventory mismatch")
    signer = _run_checked(
        [tools["apksigner"], "verify", "--verbose", "--print-certs", str(apk_path)],
        "google_services_asset_invalid",
        "Google services APK signature verification failed",
    )
    histories = _signer_histories(signer.stdout)
    if histories != list(component["signingCertificateHistorySha256"]):
        raise GoogleServicesError("google_services_asset_invalid", "Google services APK signer mismatch")
    _validate_apk_native_payload(apk_path, component)
    if component["id"] == "gmsCore":
        der = _microg_fake_signature_der(apk_path, tools)
        if hashlib.sha256(der).hexdigest() != spec.signature_policy["fakeSignerSha256"]:
            raise GoogleServicesError("google_services_asset_invalid", "Google services GmsCore fake certificate mismatch")
        _validate_microg_maps_payload(apk_path)


def import_microg(project_root: Path, source_gmscore: Path, source_gsfproxy: Path) -> dict[str, Any]:
    if source_gmscore.name != MICROG_GMSCORE_BASENAME or source_gsfproxy.name != MICROG_GSFPROXY_BASENAME:
        raise GoogleServicesError("google_services_asset_invalid", "Google services import filenames do not match the pinned release")
    spec = load_release_spec(project_root, MICROG_PLAY_RELEASE)
    source_spec = load_release_spec(project_root, MINDTHEGAPPS_RELEASE)
    quick_validate_assets(project_root, source_spec)
    parent = project_root / ".xenoid" / "artifacts" / "google-services"
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    parent.chmod(0o700)
    lock_path = parent / ".import.lock"
    lock_descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(lock_descriptor, 0o600)
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        _cleanup_abandoned_imports(parent)
        final = parent / spec.asset_dirname
        if final.exists():
            quick_validate_assets(project_root, spec)
            return {"ok": True, **spec.public_dict(), "imported": False, "existing": True}
        temp = Path(tempfile.mkdtemp(prefix=".import-microg-", dir=parent))
        temp.chmod(0o700)
        marker = temp / ".owner"
        marker.write_text(_IMPORT_OWNER_V2, encoding="ascii")
        marker.chmod(0o600)
        try:
            targets: dict[str, Path] = {}
            for component_id, source in (("gmsCore", source_gmscore), ("gsfProxy", source_gsfproxy)):
                component = spec.component(component_id)
                target = temp / str(component["basename"])
                size, digest = _copy_regular_source(source, target)
                if size != component["size"] or digest != component["sha256"]:
                    raise GoogleServicesError("google_services_asset_invalid", "Google services import source does not match the pinned release")
                targets[component_id] = target
            tools = _tool_paths()
            for component_id in ("gmsCore", "gsfProxy"):
                _validate_microg_apk(targets[component_id], spec.component(component_id), spec, tools)
            _write_private_json(temp / "import.json", _expected_import_manifest_v2(project_root, spec))
            marker.unlink()
            _fsync_directory(temp)
            try:
                os.rename(temp, final)
            except OSError as exc:
                if exc.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                    raise
                quick_validate_assets(project_root, spec)
                shutil.rmtree(temp, ignore_errors=True)
                return {"ok": True, **spec.public_dict(), "imported": False, "existing": True}
            final.chmod(0o700)
            _fsync_directory(parent)
            quick_validate_assets(project_root, spec)
            return {"ok": True, **spec.public_dict(), "imported": True, "existing": False}
        except Exception:
            if temp.exists():
                shutil.rmtree(temp, ignore_errors=True)
            raise
    finally:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(lock_descriptor)


_ACQUISITION_OWNER = "dev.xenoid.google-services-acquisition/v1\n"


def _asset_set_ready(project_root: Path, spec: ReleaseSpec) -> bool:
    try:
        quick_validate_assets(project_root, spec)
        return True
    except GoogleServicesError as exc:
        if exc.code == "google_services_assets_missing":
            return False
        raise


def _download_pinned_asset(
    url: str,
    destination: Path,
    *,
    expected_size: int,
    expected_sha256: str,
) -> None:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise GoogleServicesError(
            "google_services_asset_download_failed",
            "automatic Google services asset acquisition failed",
        )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    created = False
    success = False
    try:
        descriptor = os.open(destination, flags, 0o600)
        created = True
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": "xenoid-google-services-acquisition/1",
            },
        )
        with urllib.request.urlopen(request, timeout=600) as response:
            final = urllib.parse.urlsplit(response.geturl())
            final_host = final.hostname or ""
            if (
                final.scheme != "https"
                or not (
                    final_host == "github.com"
                    or final_host.endswith(".githubusercontent.com")
                )
                or response.getcode() != 200
                or response.headers.get("Content-Encoding") not in {
                    None,
                    "identity",
                }
            ):
                raise GoogleServicesError(
                    "google_services_asset_download_failed",
                    "automatic Google services asset acquisition failed",
                )
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared_size = int(content_length)
                except ValueError as exc:
                    raise GoogleServicesError(
                        "google_services_asset_download_failed",
                        "automatic Google services asset acquisition failed",
                    ) from exc
                if declared_size != expected_size:
                    raise GoogleServicesError(
                        "google_services_asset_download_failed",
                        "automatic Google services asset acquisition failed",
                    )
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = response.read(_COPY_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > expected_size:
                    raise GoogleServicesError(
                        "google_services_asset_download_failed",
                        "automatic Google services asset acquisition failed",
                    )
                digest.update(chunk)
                _write_all(descriptor, chunk)
        if size != expected_size or digest.hexdigest() != expected_sha256:
            raise GoogleServicesError(
                "google_services_asset_download_failed",
                "automatic Google services asset acquisition failed",
            )
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        success = True
    except GoogleServicesError:
        raise
    except (
        OSError,
        urllib.error.URLError,
        http.client.HTTPException,
        ValueError,
    ) as exc:
        raise GoogleServicesError(
            "google_services_asset_download_failed",
            "automatic Google services asset acquisition failed",
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if created and not success:
            try:
                destination.unlink()
            except FileNotFoundError:
                pass


def _cleanup_abandoned_acquisitions(parent: Path) -> None:
    for entry in os.scandir(parent):
        if (
            not entry.name.startswith(".acquire-")
            or not entry.is_dir(follow_symlinks=False)
        ):
            continue
        candidate = parent / entry.name
        marker = candidate / ".owner"
        try:
            if (
                marker.is_symlink()
                or marker.read_text(encoding="ascii") != _ACQUISITION_OWNER
            ):
                continue
        except (OSError, UnicodeError):
            continue
        shutil.rmtree(candidate)



def ensure_google_services_assets(
    project_root: Path,
    spec: ReleaseSpec,
) -> dict[str, Any]:
    if (
        spec.provider != PROVIDER_MICROG
        or spec.availability != AVAILABILITY_PRODUCTION
    ):
        raise GoogleServicesError(
            "google_services_spec_mismatch",
            "automatic acquisition supports only the production Google services release",
        )
    if _asset_set_ready(project_root, spec):
        return {
            "ok": True,
            **spec.public_dict(),
            "downloaded": False,
            "existing": True,
        }

    parent = project_root / ".xenoid" / "artifacts" / "google-services"
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    parent.chmod(0o700)
    lock_descriptor = os.open(
        parent / ".acquire.lock",
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(lock_descriptor, 0o600)
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        _cleanup_abandoned_acquisitions(parent)
        if _asset_set_ready(project_root, spec):
            return {
                "ok": True,
                **spec.public_dict(),
                "downloaded": False,
                "existing": True,
            }

        temporary = Path(
            tempfile.mkdtemp(prefix=".acquire-", dir=parent)
        )
        temporary.chmod(0o700)
        marker = temporary / ".owner"
        marker.write_text(_ACQUISITION_OWNER, encoding="ascii")
        marker.chmod(0o600)
        downloaded = False
        try:
            source_spec = load_release_spec(
                project_root,
                MINDTHEGAPPS_RELEASE,
            )
            if not _asset_set_ready(project_root, source_spec):
                source = source_spec.metadata["source"]
                archive = source_spec.archive
                certificate = archive["certificate"]
                zip_path = (
                    temporary / f"{MINDTHEGAPPS_RELEASE}.zip"
                )
                pem_path = temporary / "release.x509.pem"
                _download_pinned_asset(
                    str(source["zipUrl"]),
                    zip_path,
                    expected_size=int(archive["size"]),
                    expected_sha256=str(archive["sha256"]),
                )
                _download_pinned_asset(
                    str(source["certificateUrl"]),
                    pem_path,
                    expected_size=int(certificate["size"]),
                    expected_sha256=str(certificate["sha256"]),
                )
                import_mindthegapps(
                    project_root,
                    zip_path,
                    pem_path,
                )
                downloaded = True

            if not _asset_set_ready(project_root, spec):
                gmscore = spec.component("gmsCore")
                gsfproxy = spec.component("gsfProxy")
                gmscore_path = temporary / MICROG_GMSCORE_BASENAME
                gsfproxy_path = temporary / MICROG_GSFPROXY_BASENAME
                _download_pinned_asset(
                    MICROG_GMSCORE_DOWNLOAD_URL,
                    gmscore_path,
                    expected_size=int(gmscore["size"]),
                    expected_sha256=str(gmscore["sha256"]),
                )
                _download_pinned_asset(
                    MICROG_GSFPROXY_DOWNLOAD_URL,
                    gsfproxy_path,
                    expected_size=int(gsfproxy["size"]),
                    expected_sha256=str(gsfproxy["sha256"]),
                )
                import_microg(
                    project_root,
                    gmscore_path,
                    gsfproxy_path,
                )
                downloaded = True
            quick_validate_assets(project_root, spec)
            return {
                "ok": True,
                **spec.public_dict(),
                "downloaded": downloaded,
                "existing": not downloaded,
            }
        finally:
            shutil.rmtree(temporary, ignore_errors=True)
    finally:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(lock_descriptor)


def resolve_google_runtime_spec(
    context: InstanceContext,
    cfg: XenoidConfig,
    purpose: str,
    *,
    require_assets: bool = True,
) -> Optional[ReleaseSpec]:
    provider, release = validate_provider_release(
        getattr(cfg, "google_services_provider", PROVIDER_NONE),
        getattr(cfg, "google_services_release", PROVIDER_NONE),
    )
    if provider == PROVIDER_NONE:
        return None
    if _RELEASE_REGISTRY[release]["availability"] != AVAILABILITY_PRODUCTION:
        raise GoogleServicesError(
            "google_services_release_retired",
            "the configured Google services release is retired; create a new instance with a production release",
        )
    if not cfg.auto_build_runtime_image:
        raise GoogleServicesError("google_services_auto_build_required", "Google services requires auto_build_runtime_image=true")
    if cfg.extra_docker_args:
        raise GoogleServicesError(
            "google_services_container_customization_unsupported",
            "Google services requires an unmodified managed container command",
        )
    spec = load_release_spec(context.project_root, release)
    if require_assets:
        quick_validate_assets(context.project_root, spec)
    return spec


def effective_google_image(base: str, spec: Optional[ReleaseSpec]) -> str:
    return base if spec is None else f"{base}-google-{spec.fingerprint[:12]}"


def _open_directory_chain(root_descriptor: int, components: tuple[str, ...], create: bool) -> int:
    current = os.dup(root_descriptor)
    try:
        for component in components:
            try:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current,
                )
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, 0o700, dir_fd=current)
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current,
                )
            os.close(current)
            current = next_descriptor
        return current
    except Exception:
        os.close(current)
        raise


def _stage_manifests(spec: ReleaseSpec) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    files: dict[str, dict[str, Any]] = {}
    directories: dict[str, dict[str, Any]] = {}
    for member in spec.members:
        if member["selected"] is not True:
            continue
        relative = str(member["runtimePath"]).lstrip("/")
        source_mode = int(member["mode"])
        mode = 0o755 if source_mode & 0o111 else 0o644
        files[relative] = {
            "sha256": member["sha256"],
            "size": member["size"],
            "mode": mode,
        }
        components = relative.split("/")[:-1]
        for length in range(1, len(components) + 1):
            directory = "/".join(components[:length])
            directories.setdefault(directory, {"mode": 0o755})
    return files, directories


def _stage_manifests_v2(spec: ReleaseSpec) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    files: dict[str, dict[str, Any]] = {}
    directories: dict[str, dict[str, Any]] = {}

    def add(relative: str, entry: dict[str, Any]) -> None:
        files[relative] = entry
        parts = relative.split("/")[:-1]
        for length in range(1, len(parts) + 1):
            directories.setdefault("/".join(parts[:length]), {"mode": 0o755})

    for component in spec.components:
        relative = str(component["runtimePath"]).lstrip("/")
        add(
            relative,
            {
                "sha256": str(component["sha256"]),
                "size": int(component["size"]),
                "mode": 0o644,
            },
        )
    for output in spec.product_policy["outputs"]:
        relative = str(output["path"]).lstrip("/")
        add(
            relative,
            {
                "sha256": str(output["sha256"]),
                "size": None,
                "mode": 0o644,
                "policy": True,
            },
        )
    return files, directories


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError(errno.EIO, "short write")
        view = view[written:]




def _stage_stream_into(
    stream: Any,
    descriptor: int,
    *,
    size: int,
    sha256: str,
    budget: list[int],
    limit: int,
) -> None:
    digest = hashlib.sha256()
    count = 0
    while True:
        chunk = stream.read(_COPY_CHUNK)
        if not chunk:
            break
        count += len(chunk)
        budget[0] += len(chunk)
        if count > size or budget[0] > limit:
            raise GoogleServicesError("google_services_asset_invalid", "Google services stage exceeds pinned limits")
        digest.update(chunk)
        _write_all(descriptor, chunk)
    if count != size or digest.hexdigest() != sha256:
        raise GoogleServicesError("google_services_asset_invalid", "Google services staged member pin mismatch")


def _stage_one(
    root_descriptor: int,
    relative: str,
    stream: Any,
    expected: Mapping[str, Any],
    budget: list[int],
    limit: int,
) -> None:
    components = _safe_member_name(relative)
    parent_descriptor = _open_directory_chain(root_descriptor, components[:-1], True)
    descriptor = -1
    try:
        descriptor = os.open(
            components[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        with stream:
            _stage_stream_into(
                stream,
                descriptor,
                size=int(expected["size"]),
                sha256=str(expected["sha256"]),
                budget=budget,
                limit=limit,
            )
        os.fchmod(descriptor, int(expected["mode"]))
        os.utime(descriptor, ns=(0, 0))
        os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.fsync(parent_descriptor)
        os.close(parent_descriptor)


def _stage_payload_v1(project_root: Path, spec: ReleaseSpec, root_descriptor: int, files: Mapping[str, Any]) -> None:
    zip_path = asset_paths(project_root, spec)["archive"]
    with zipfile.ZipFile(zip_path) as bundle:
        _validate_zip_inventory(bundle, spec)
        budget = [0]
        for member in sorted((item for item in spec.members if item["selected"] is True), key=lambda item: item["runtimePath"]):
            relative = str(member["runtimePath"]).lstrip("/")
            _stage_one(
                root_descriptor,
                relative,
                bundle.open(str(member["archivePath"])),
                files[relative],
                budget,
                int(spec.archive["maxExpandedBytes"]),
            )


def _stage_payload_v2(project_root: Path, spec: ReleaseSpec, root_descriptor: int, files: Mapping[str, Any]) -> None:
    paths = asset_paths(project_root, spec)
    source_spec = load_release_spec(project_root, MINDTHEGAPPS_RELEASE)
    source_zip = asset_paths(project_root, source_spec)["archive"]
    limit = sum(int(component["size"]) for component in spec.components)
    budget = [0]
    with zipfile.ZipFile(source_zip) as bundle:
        _validate_zip_inventory(bundle, source_spec)
        for component in sorted(spec.components, key=lambda item: str(item["runtimePath"])):
            relative = str(component["runtimePath"]).lstrip("/")
            component_id = str(component["id"])
            if component_id in {"gmsCore", "gsfProxy"}:
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(paths[component_id], flags)
                try:
                    info = os.fstat(descriptor)
                    if not stat.S_ISREG(info.st_mode):
                        raise GoogleServicesError("google_services_asset_invalid", "Google services asset is not a regular file")
                    stream = os.fdopen(descriptor, "rb", closefd=False)
                except Exception:
                    os.close(descriptor)
                    raise
                try:
                    _stage_one(root_descriptor, relative, stream, files[relative], budget, limit)
                finally:
                    os.close(descriptor)
            else:
                _stage_one(
                    root_descriptor,
                    relative,
                    bundle.open(str(component["sourcePath"])),
                    files[relative],
                    budget,
                    limit,
                )


def _stage_payload(project_root: Path, spec: ReleaseSpec) -> StageHandle:
    root = Path(tempfile.mkdtemp(prefix="xenoid-gapps-stage-"))
    root.chmod(0o700)
    token = secrets.token_hex(16)
    marker = root / ".owner"
    marker.write_text(f"dev.xenoid.google-stage/v1 {token}\n", encoding="ascii")
    marker.chmod(0o600)
    tree = root / "tree"
    tree.mkdir(mode=0o700)
    if spec.schema == GOOGLE_RELEASE_SCHEMA_V2:
        files, directories = _stage_manifests_v2(spec)
    else:
        files, directories = _stage_manifests(spec)
    root_descriptor = os.open(tree, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        if spec.schema == GOOGLE_RELEASE_SCHEMA_V2:
            _stage_payload_v2(project_root, spec, root_descriptor, files)
        else:
            _stage_payload_v1(project_root, spec, root_descriptor, files)
        for relative, expected in sorted(directories.items(), key=lambda pair: pair[0].count("/"), reverse=True):
            try:
                descriptor = _open_directory_chain(root_descriptor, tuple(relative.split("/")), False)
            except FileNotFoundError:
                if spec.schema == GOOGLE_RELEASE_SCHEMA_V2:
                    # Generated product-policy directories are materialized and
                    # normalized inside the runtime context, not the stage tree.
                    continue
                raise
            try:
                os.fchmod(descriptor, int(expected["mode"]))
                os.utime(descriptor, ns=(0, 0))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fsync(root_descriptor)
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise
    finally:
        os.close(root_descriptor)
    digest_payload = {
        "schema": "dev.xenoid.google-stage-manifest/v1",
        "specSha256": spec.fingerprint,
        "files": files,
        "directories": directories,
    }
    metadata_digest = hashlib.sha256(_canonical_json(digest_payload)).hexdigest()
    return StageHandle(root, tree, token, files, directories, metadata_digest)


def cleanup_stage(handle: StageHandle) -> None:
    try:
        info = handle.root.lstat()
        marker = handle.root / ".owner"
        expected = f"dev.xenoid.google-stage/v1 {handle.token}\n"
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or marker.is_symlink() or marker.read_text(encoding="ascii") != expected:
            raise GoogleServicesError("google_services_context_cleanup_failed", "refusing to remove a non-owned Google services stage")
        shutil.rmtree(handle.root)
    except GoogleServicesError:
        raise
    except OSError as exc:
        raise GoogleServicesError("google_services_context_cleanup_failed", "Google services stage cleanup failed") from exc


@contextmanager
def staged_google_payload(context: InstanceContext, spec: ReleaseSpec) -> Iterator[StageHandle]:
    quick_validate_assets(context.project_root, spec)
    if spec.schema == GOOGLE_RELEASE_SCHEMA_V2:
        source_spec = load_release_spec(context.project_root, MINDTHEGAPPS_RELEASE)
        quick_validate_assets(context.project_root, source_spec)
    handle = _stage_payload(context.project_root, spec)
    try:
        yield handle
    finally:
        cleanup_stage(handle)


def _walk_tree(root: Path) -> tuple[dict[str, os.stat_result], dict[str, os.stat_result]]:
    files: dict[str, os.stat_result] = {}
    directories: dict[str, os.stat_result] = {}
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(current)
        for name in list(dirnames):
            path = base / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise GoogleServicesError("google_services_asset_invalid", "unsafe directory in staged Google services payload")
            directories[path.relative_to(root).as_posix()] = info
        for name in filenames:
            path = base / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise GoogleServicesError("google_services_asset_invalid", "unsafe file in staged Google services payload")
            files[path.relative_to(root).as_posix()] = info
    return files, directories


def _load_context_manifest_entries(context_root: Path) -> dict[str, Mapping[str, Any]]:
    manifest_path = context_root / "context-manifest.json"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(manifest_path, flags)
    except OSError as exc:
        raise GoogleServicesError("google_services_asset_invalid", "runtime context manifest is missing or unsafe") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o644
            or info.st_mtime_ns != 0
            or info.st_size > _MAX_CONTEXT_MANIFEST_BYTES
        ):
            raise GoogleServicesError("google_services_asset_invalid", "runtime context manifest metadata is invalid")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(_MAX_CONTEXT_MANIFEST_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(payload) > _MAX_CONTEXT_MANIFEST_BYTES:
        raise GoogleServicesError("google_services_asset_invalid", "runtime context manifest is too large")
    try:
        value = json.loads(payload)
    except (UnicodeError, ValueError) as exc:
        raise GoogleServicesError("google_services_asset_invalid", "runtime context manifest is invalid") from exc
    if (
        not isinstance(value, Mapping)
        or set(value) != _RUNTIME_CONTEXT_KEYS
        or value.get("schema") != _RUNTIME_CONTEXT_SCHEMA
        or not isinstance(value.get("entries"), list)
        or payload
        != (
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
    ):
        raise GoogleServicesError("google_services_asset_invalid", "runtime context manifest is not canonical")
    entries: dict[str, Mapping[str, Any]] = {}
    previous: Optional[bytes] = None
    for raw in value["entries"]:
        if not isinstance(raw, Mapping) or set(raw) != _RUNTIME_CONTEXT_ENTRY_KEYS:
            raise GoogleServicesError("google_services_asset_invalid", "runtime context manifest entry is invalid")
        relative = raw.get("path")
        if not isinstance(relative, str) or relative == "context-manifest.json":
            raise GoogleServicesError("google_services_asset_invalid", "runtime context manifest path is invalid")
        _safe_member_name(relative)
        encoded = relative.encode("utf-8")
        if previous is not None and encoded <= previous:
            raise GoogleServicesError("google_services_asset_invalid", "runtime context manifest entries are not bytewise sorted")
        previous = encoded
        entry_type = raw.get("type")
        mode = raw.get("mode")
        size = raw.get("size")
        digest = raw.get("sha256")
        if entry_type == "directory":
            valid = (
                mode == "0755"
                and isinstance(size, int)
                and not isinstance(size, bool)
                and size == 0
                and digest is None
            )
        elif entry_type == "file":
            valid = (
                mode in {"0644", "0755"}
                and isinstance(size, int)
                and not isinstance(size, bool)
                and size >= 0
                and isinstance(digest, str)
                and _HEX64.fullmatch(digest) is not None
            )
        else:
            valid = False
        if not valid:
            raise GoogleServicesError("google_services_asset_invalid", "runtime context manifest entry metadata is invalid")
        entries[relative] = raw
    return entries


def _policy_stage_entries(spec: ReleaseSpec) -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    if spec.schema != GOOGLE_RELEASE_SCHEMA_V2:
        return entries
    for output in spec.product_policy["outputs"]:
        relative = str(output["path"]).lstrip("/")
        entries[relative] = {"sha256": str(output["sha256"]), "mode": 0o644, "policy": True}
    return entries


def verify_context_copy(context_root: Path, spec: ReleaseSpec, stage: StageHandle) -> dict[str, Any]:
    payload_root = context_root / "payload" / "google-services"
    actual_files, actual_directories = _walk_tree(payload_root)
    policy_entries = _policy_stage_entries(spec)
    expected_files = dict(stage.file_manifest)
    if set(policy_entries) - set(expected_files):
        raise GoogleServicesError("google_services_asset_invalid", "Google services product policy is not staged")
    if set(actual_files) != set(expected_files) or set(actual_directories) != set(stage.directory_manifest):
        raise GoogleServicesError("google_services_asset_invalid", "Google services runtime context inventory mismatch")
    manifest_entries = _load_context_manifest_entries(context_root)
    manifest_prefix = "payload/google-services/"
    google_entries = {
        path: entry
        for path, entry in manifest_entries.items()
        if path.startswith(manifest_prefix)
    }
    expected_paths = {
        *(f"{manifest_prefix}{relative}" for relative in expected_files),
        *(f"{manifest_prefix}{relative}" for relative in stage.directory_manifest),
    }
    if set(google_entries) != expected_paths:
        raise GoogleServicesError("google_services_asset_invalid", "Google services runtime context manifest inventory mismatch")
    for relative, expected in expected_files.items():
        path = payload_root / relative
        info = actual_files[relative]
        digest = _stream_sha256(path)[1] if policy_entries.get(relative) else _stream_sha256(path, int(expected["size"]))[1]
        if digest != expected["sha256"]:
            raise GoogleServicesError("google_services_asset_invalid", "Google services runtime context file mismatch")
        manifest_entry = google_entries[f"{manifest_prefix}{relative}"]
        expected_entry = {
            "path": f"{manifest_prefix}{relative}",
            "type": "file",
            "mode": f"0{int(expected['mode']):03o}",
            "size": info.st_size,
            "sha256": expected["sha256"],
        }
        if relative not in policy_entries and (
            info.st_size != expected["size"]
            or stat.S_IMODE(info.st_mode) != expected["mode"]
            or info.st_mtime_ns != 0
            or manifest_entry != expected_entry
        ):
            raise GoogleServicesError("google_services_asset_invalid", "Google services runtime context file mismatch")
        if relative in policy_entries and (
            stat.S_IMODE(info.st_mode) != expected["mode"]
            or info.st_mtime_ns != 0
            or manifest_entry != expected_entry
        ):
            raise GoogleServicesError("google_services_asset_invalid", "Google services runtime context policy mismatch")
    for relative, expected in stage.directory_manifest.items():
        info = actual_directories[relative]
        manifest_entry = google_entries[f"{manifest_prefix}{relative}"]
        if (
            stat.S_IMODE(info.st_mode) != expected["mode"]
            or info.st_mtime_ns != 0
            or manifest_entry
            != {
                "path": f"{manifest_prefix}{relative}",
                "type": "directory",
                "mode": "0755",
                "size": 0,
                "sha256": None,
            }
        ):
            raise GoogleServicesError("google_services_asset_invalid", "Google services runtime context directory mismatch")
    dockerfile = context_root / "Dockerfile"
    try:
        text = dockerfile.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise GoogleServicesError("google_services_asset_invalid", "Google services runtime Dockerfile is missing") from exc
    copy_line = "COPY --chown=0:0 payload/google-services/ /"
    if text.count(copy_line) != 1:
        raise GoogleServicesError("google_services_asset_invalid", "Google services runtime Dockerfile COPY contract mismatch")
    for key, value in spec.labels.items():
        if text.count(f'{key}="{value}"') != 1:
            raise GoogleServicesError("google_services_asset_invalid", "Google services runtime Dockerfile label mismatch")
    props_path = context_root / "payload" / "props" / "system_build.prop"
    try:
        props = props_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise GoogleServicesError("google_services_asset_invalid", "Google services runtime system properties are missing") from exc
    if spec.android["setupWizardMode"] == "UNCHANGED":
        if any(line.startswith("ro.setupwizard.mode=") for line in props.splitlines()):
            raise GoogleServicesError("google_services_asset_invalid", "Google services setup-wizard mode must remain unchanged")
    else:
        setup_mode = f"ro.setupwizard.mode={spec.android['setupWizardMode']}"
        if props.splitlines().count(setup_mode) != 1:
            raise GoogleServicesError("google_services_asset_invalid", "Google services setup-wizard mode mismatch")
    owned_copy_positions = [
        position
        for marker in ("COPY payload/daemon", "COPY payload/xenoid", "COPY --chmod")
        if (position := text.find(marker)) >= 0
    ]
    if owned_copy_positions and text.find(copy_line) > min(owned_copy_positions):
        raise GoogleServicesError("google_services_asset_invalid", "Google services payload must precede Xenoid-owned payloads")
    return {
        "ok": True,
        "specSha256": spec.fingerprint,
        "stageMetadataSha256": stage.metadata_digest,
        "files": len(stage.file_manifest),
    }


def create_runtime_context_handle() -> RuntimeContextHandle:
    root = Path(tempfile.mkdtemp(prefix="xenoid-runtime-context-"))
    root.chmod(0o700)
    token = secrets.token_hex(16)
    marker = root / ".owner"
    marker.write_text(f"{_RUNTIME_CONTEXT_OWNER.strip()} {token}\n", encoding="ascii")
    marker.chmod(0o600)
    output = root / "context"
    return RuntimeContextHandle(root=root, output=output, token=token)


def cleanup_runtime_context(handle: RuntimeContextHandle) -> dict[str, Any]:
    try:
        info = handle.root.lstat()
        marker = handle.root / ".owner"
        expected = f"{_RUNTIME_CONTEXT_OWNER.strip()} {handle.token}\n"
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or marker.is_symlink() or marker.read_text(encoding="ascii") != expected:
            raise GoogleServicesError("google_services_context_cleanup_failed", "refusing to remove a non-owned runtime context")
        shutil.rmtree(handle.root)
        return {"retained": False, "removed": True}
    except GoogleServicesError:
        raise
    except OSError as exc:
        raise GoogleServicesError("google_services_context_cleanup_failed", "runtime context cleanup failed") from exc


class GoogleBindingStore:
    def __init__(self, context: InstanceContext, lease: InstanceLease):
        self.context = context
        self.lease = lease
        self.path = context.state_root / "google-runtime.json"

    def validate(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, Mapping) or set(raw) != _BINDING_KEYS:
            raise GoogleServicesError("google_services_spec_mismatch", "invalid Google runtime binding")
        value = dict(raw)
        if value["schema"] != GOOGLE_BINDING_SCHEMA:
            raise GoogleServicesError("google_services_spec_mismatch", "unsupported Google runtime binding")
        if not isinstance(value["instanceId"], str) or _UUID.fullmatch(value["instanceId"]) is None or value["instanceId"] != self.context.instance_id:
            raise GoogleServicesError("google_services_spec_mismatch", "Google runtime binding belongs to another instance")
        if not isinstance(value["resourceTag"], str) or _RESOURCE_TAG.fullmatch(value["resourceTag"]) is None or value["resourceTag"] != self.context.resource_tag:
            raise GoogleServicesError("google_services_spec_mismatch", "Google runtime resource tag mismatch")
        validate_provider_release(value["provider"], value["release"])
        for key in ("specSha256", "dataCompatibilitySha256"):
            if not isinstance(value[key], str) or _HEX64.fullmatch(value[key]) is None:
                raise GoogleServicesError("google_services_spec_mismatch", "invalid Google runtime fingerprint")
        if value["state"] not in {"pending", "committed"} or value["source"] not in {"fresh", "legacy"}:
            raise GoogleServicesError("google_services_spec_mismatch", "invalid Google runtime binding state")
        if not isinstance(value["transactionId"], str) or _TRANSACTION.fullmatch(value["transactionId"]) is None or value["transactionId"] != self.lease.transaction_id:
            raise GoogleServicesError("google_services_spec_mismatch", "Google runtime transaction mismatch")
        return value

    def load(self) -> Optional[dict[str, Any]]:
        try:
            info = self.path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o077:
                raise GoogleServicesError("google_services_spec_mismatch", "Google runtime binding permissions are unsafe")
            raw = json.loads(self.path.read_bytes())
        except FileNotFoundError:
            return None
        except GoogleServicesError:
            raise
        except (OSError, ValueError, UnicodeError) as exc:
            raise GoogleServicesError("google_services_spec_mismatch", "invalid Google runtime binding") from exc
        return self.validate(raw)

    def save(self, state: Mapping[str, Any]) -> dict[str, Any]:
        value = self.validate(state)
        self.context.state_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.context.state_root.chmod(0o700)
        payload = _canonical_json(value) + b"\n"
        descriptor, temporary = tempfile.mkstemp(prefix=".google-runtime.json.", dir=self.context.state_root)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            self.path.chmod(0o600)
            _fsync_directory(self.path.parent)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        return value

    def pending(self, spec: Optional[ReleaseSpec], source: str) -> dict[str, Any]:
        provider = spec.provider if spec else PROVIDER_NONE
        release = spec.release if spec else PROVIDER_NONE
        fingerprint = spec.fingerprint if spec else disabled_runtime_spec_fingerprint()
        return self.save(
            {
                "schema": GOOGLE_BINDING_SCHEMA,
                "instanceId": self.context.instance_id,
                "resourceTag": self.context.resource_tag,
                "provider": provider,
                "release": release,
                "specSha256": fingerprint,
                "dataCompatibilitySha256": spec.data_compatibility_fingerprint if spec else fingerprint,
                "state": "pending",
                "transactionId": self.lease.transaction_id,
                "source": source,
            }
        )

    def commit(self, pending: Mapping[str, Any]) -> dict[str, Any]:
        value = self.validate(pending)
        if value["state"] != "pending":
            return value
        return self.save({**value, "state": "committed"})


def expected_binding_identity(spec: Optional[ReleaseSpec]) -> dict[str, str]:
    fingerprint = spec.fingerprint if spec else disabled_runtime_spec_fingerprint()
    return {
        "provider": spec.provider if spec else PROVIDER_NONE,
        "release": spec.release if spec else PROVIDER_NONE,
        "specSha256": fingerprint,
        "dataCompatibilitySha256": spec.data_compatibility_fingerprint if spec else fingerprint,
    }


def binding_matches(binding: Mapping[str, Any], spec: Optional[ReleaseSpec]) -> bool:
    expected = expected_binding_identity(spec)
    return all(binding.get(key) == value for key, value in expected.items())


def public_binding(binding: Optional[Mapping[str, Any]], *, inferred: bool = False) -> Optional[dict[str, Any]]:
    if binding is None:
        return None
    return {
        "provider": binding.get("provider"),
        "release": binding.get("release"),
        "specSha256": binding.get("specSha256"),
        "dataCompatibilitySha256": binding.get("dataCompatibilitySha256"),
        "state": binding.get("state"),
        "source": binding.get("source"),
        "inferred": inferred,
    }


def transition_decision(
    spec: Optional[ReleaseSpec],
    binding: Optional[Mapping[str, Any]],
    *,
    freshness_known: bool,
    fresh: bool,
    legacy_actual_none: bool,
) -> dict[str, Any]:
    if binding is not None:
        if not binding_matches(binding, spec):
            raise GoogleServicesError("google_services_new_instance_required", "Google services changes require a new instance and do not erase existing data")
        return {"allowed": True, "transition": "resume" if binding["state"] == "pending" else "reuse", "bindingState": binding["state"]}
    if not freshness_known:
        raise GoogleServicesError("google_services_freshness_unknown", "cannot prove that this instance has no existing Android data")
    if fresh:
        return {"allowed": True, "transition": "fresh", "bindingState": None}
    if legacy_actual_none and spec is None:
        return {"allowed": True, "transition": "legacy-none", "bindingState": "committed"}
    raise GoogleServicesError("google_services_new_instance_required", "Google services changes require a new instance and do not erase existing data")


_RUNTIME_CAPABILITY_SHAPES = {
    "googlePlayServices": ("runtime", "minimal-live"),
    "accountAuth": ("runtime-release", "authenticator"),
    "cloudMessaging": ("runtime-release", "fcm-registrar"),
    "fusedLocation": ("runtime-release", "fused-provider"),
    "playStore": ("runtime-release", "launcher"),
}
_UNSUPPORTED_CAPABILITIES = ("playIntegrity", "deviceCertification", "drm", "antiCheat")


def capability_model(provider: str, runtime_state: str) -> dict[str, Any]:
    configured = provider in {PROVIDER_MICROG, PROVIDER_MINDTHEGAPPS}
    capabilities: dict[str, Any] = {}
    if configured:
        state = runtime_state if runtime_state in {"ready", "failed"} else "notEvaluated"
        required = (
            ["googlePlayServices", "accountAuth", "cloudMessaging", "fusedLocation", "playStore"]
            if provider == PROVIDER_MICROG
            else ["googlePlayServices", "playStore"]
        )
        for name, (scope, evidence) in _RUNTIME_CAPABILITY_SHAPES.items():
            capabilities[name] = {
                "scope": scope,
                "runtimeState": state,
                "releaseState": "notEvaluated",
                "evidence": evidence,
            }
        capabilities["maps"] = {
            "scope": "release",
            "runtimeState": "notEvaluated",
            "releaseState": "notEvaluated",
            "evidence": "release-attestation",
        }
    else:
        required = []
        for name, (scope, _) in _RUNTIME_CAPABILITY_SHAPES.items():
            capabilities[name] = {
                "scope": scope,
                "runtimeState": "absent",
                "releaseState": "notEvaluated",
                "evidence": "none",
            }
        capabilities["maps"] = {
            "scope": "release",
            "runtimeState": "absent",
            "releaseState": "notEvaluated",
            "evidence": "none",
        }
    for name in _UNSUPPORTED_CAPABILITIES:
        capabilities[name] = {
            "scope": "application",
            "runtimeState": "unsupported",
            "releaseState": "unsupported",
            "evidence": "unsupported",
        }
    return {"requiredCapabilities": required, "capabilities": capabilities}


def _implementation_literals(provider: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    if provider == PROVIDER_MICROG:
        return "microg", "restricted-spoofing", "google-play"
    if provider == PROVIDER_MINDTHEGAPPS:
        return "mindthegapps", "coherent", "google-play"
    return None, None, None


def factory_components(spec: Optional[ReleaseSpec]) -> Optional[dict[str, Any]]:
    if spec is None or spec.schema != GOOGLE_RELEASE_SCHEMA_V2:
        return None
    result: dict[str, Any] = {}
    for component in spec.components:
        result[str(component["id"])] = {
            "package": str(component["package"]),
            "path": str(component["runtimePath"]),
            "versionCode": int(component["versionCode"]),
            "sha256": str(component["sha256"]),
            "signingCertificateHistorySha256": list(component["signingCertificateHistorySha256"]),
            "privileged": bool(component["privileged"]),
        }
    return result


def base_status(provider: str, release: str, spec: Optional[ReleaseSpec]) -> dict[str, Any]:
    configured = provider != PROVIDER_NONE
    model = capability_model(provider, "configured" if configured else "absent")
    implementation, signature_model, store_implementation = _implementation_literals(provider)
    return {
        "schema": GOOGLE_STATUS_SCHEMA,
        "ok": True,
        "provider": provider,
        "release": release,
        "configured": configured,
        "state": "configured" if configured else "disabled",
        "hostReady": not configured,
        "runtimeRequired": False,
        "runtimeChecked": False,
        "ready": False,
        "skipped": True,
        "implementation": implementation,
        "signatureModel": signature_model,
        "storeImplementation": store_implementation,
        "specSha256": spec.fingerprint if spec else disabled_runtime_spec_fingerprint(),
        "dataCompatibilitySha256": spec.data_compatibility_fingerprint if spec else disabled_runtime_spec_fingerprint(),
        "binding": None,
        "runtimeIdentity": {
            "desiredImageSha256": None,
            "containerImageSha256": None,
            "rootfsSourceImageSha256": None,
            "desiredInputSha256": None,
            "desiredBootInputSha256": None,
            "containerInputSha256": None,
            "containerBootInputSha256": None,
            "imageMatch": None,
            "rootfsBootInputMatches": None,
            "labelsMatch": None,
            "commandMatch": None,
            "skipped": True,
        },
        "factoryComponents": factory_components(spec),
        "effectiveComponents": None,
        "live": None,
        **model,
        "error": None,
        "nextActions": [],
    }
