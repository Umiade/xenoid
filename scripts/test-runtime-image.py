#!/usr/bin/env python3
"""Runtime-free contracts for deterministic runtime contexts and images.

The tests use synthetic ZIPs, temporary source trees, immutable artifact snapshots,
and an in-memory Docker peer. They never contact a Docker daemon, download a tool,
or compile a repository artifact.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import sys
import tempfile
import threading
import time
import warnings
import zipfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import xenoid_archive  # noqa: E402
from xenoid import artifacts, runtime_image  # noqa: E402


Case = Callable[[], None]
CASES: dict[str, Case] = {}
HEX = "0123456789abcdef"
BASE_ID = "sha256:" + "1" * 64
BUILT_ID = "sha256:" + "2" * 64
LAYER_ID = "sha256:" + "3" * 64
BASE_DIGEST = "4" * 64


class ContractFailure(AssertionError):
    pass


def contract_case(name: str) -> Callable[[Case], Case]:
    def register(function: Case) -> Case:
        if name in CASES:
            raise RuntimeError(f"duplicate case: {name}")
        CASES[name] = function
        return function

    return register


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractFailure(message)


def expect_code(code: str, function: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
    try:
        function(*args, **kwargs)
    except Exception as error:
        require(getattr(error, "code", str(error)) == code, f"expected {code}, got {error}")
        return
    raise ContractFailure(f"expected {code}")


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()

PAYLOAD_CONTENT_A = b"payload-A-content" + b"\x00" * 8
PAYLOAD_CONTENT_B = b"payload-B-content" + b"\x01" * 8
PAYLOAD_TREE_ONE = b"directory payload one"
PAYLOAD_TREE_TWO = b"directory payload two"


def payload_expected_files() -> dict[str, bytes]:
    return {
        "system/lib64/libx.so": PAYLOAD_CONTENT_A,
        "vendor/lib64/libx.so": PAYLOAD_CONTENT_A,
        "system/etc/xenoid/one.txt": PAYLOAD_TREE_ONE,
        "system/etc/xenoid/two.txt": PAYLOAD_TREE_TWO,
    }


def payload_layer_members() -> list[dict[str, Any]]:
    members: list[dict[str, Any]] = [
        {"name": directory, "type": "dir"}
        for directory in (
            "system",
            "system/lib64",
            "system/etc",
            "system/etc/xenoid",
            "vendor",
            "vendor/lib64",
        )
    ]
    members.extend(
        {"name": name, "data": payload}
        for name, payload in sorted(payload_expected_files().items())
    )
    return members

def pax_records(values: Mapping[str, str]) -> bytes:
    payload = bytearray()
    for key, value in values.items():
        body = f" {key}={value}\n".encode("utf-8")
        length = len(body) + 1
        while len(str(length)) + len(body) != length:
            length = len(str(length)) + len(body)
        payload.extend(str(length).encode("ascii"))
        payload.extend(body)
    return bytes(payload)


def build_payload_context(root: Path) -> Path:
    context = root / "context"
    tree = context / "payload" / "tree"
    tree.mkdir(parents=True)
    (context / "payload" / "libx.so").write_bytes(PAYLOAD_CONTENT_A)
    (tree / "one.txt").write_bytes(PAYLOAD_TREE_ONE)
    (tree / "two.txt").write_bytes(PAYLOAD_TREE_TWO)
    (context / "Dockerfile").write_text(
        "FROM scratch\n"
        "COPY payload/libx.so /system/lib64/libx.so\n"
        "COPY payload/libx.so /vendor/lib64/libx.so\n"
        "COPY payload/tree/ /system/etc/xenoid/\n",
        encoding="utf-8",
    )
    entries: list[dict[str, Any]] = [
        {
            "path": "payload",
            "type": "directory",
            "mode": "0755",
            "size": 0,
            "sha256": None,
        },
        {
            "path": "payload/tree",
            "type": "directory",
            "mode": "0755",
            "size": 0,
            "sha256": None,
        },
    ]
    for path, payload in (
        ("payload/libx.so", PAYLOAD_CONTENT_A),
        ("payload/tree/one.txt", PAYLOAD_TREE_ONE),
        ("payload/tree/two.txt", PAYLOAD_TREE_TWO),
    ):
        entries.append(
            {
                "path": path,
                "type": "file",
                "mode": "0644",
                "size": len(payload),
                "sha256": sha256(payload),
            }
        )
    (context / "context-manifest.json").write_text(
        json.dumps(
            {"schema": "dev.xenoid.runtime-context/v1", "entries": entries},
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return context


def write_oci_image_archive(
    path: Path,
    layers: list[list[dict[str, Any]]],
    *,
    corrupt: str | None = None,
    layer_media_type: str = "application/vnd.docker.image.rootfs.diff.tar.gzip",
) -> None:
    descriptors: list[dict[str, Any]] = []
    blobs: list[tuple[str, bytes]] = []
    for members in layers:
        layer_buffer = io.BytesIO()
        layer_mode = (
            "w:"
            if layer_media_type == "application/vnd.oci.image.layer.v1.tar"
            else "w:gz"
        )
        with tarfile.open(
            fileobj=layer_buffer,
            mode=layer_mode,
            format=tarfile.GNU_FORMAT,
        ) as layer:
            for spec in members:
                member = tarfile.TarInfo(spec["name"])
                member.mtime = 0
                kind = spec.get("type", "file")
                if kind == "dir":
                    member.type = tarfile.DIRTYPE
                    member.mode = 0o755
                    member.size = 0
                    layer.addfile(member)
                elif kind == "symlink":
                    member.type = tarfile.SYMTYPE
                    member.mode = 0o777
                    member.linkname = spec["target"]
                    member.size = 0
                    layer.addfile(member)
                else:
                    payload = spec["data"]
                    member.mode = 0o644
                    member.size = len(payload)
                    member.type = {
                        "pax": tarfile.XHDTYPE,
                        "global_pax": tarfile.XGLTYPE,
                        "gnu_longname": tarfile.GNUTYPE_LONGNAME,
                        "gnu_sparse": tarfile.GNUTYPE_SPARSE,
                    }.get(kind, tarfile.REGTYPE)
                    layer.addfile(member, io.BytesIO(payload))
        blob = layer_buffer.getvalue()
        digest = sha256(blob)
        size = len(blob)
        if corrupt == "digest":
            digest = "0" * 64
        elif corrupt == "size":
            size += 1
        media_type = layer_media_type
        if corrupt == "mediaType":
            media_type = "application/octet-stream"
        elif corrupt == "compression":
            media_type = (
                "application/vnd.docker.image.rootfs.diff.tar.gzip"
                if layer_media_type == "application/vnd.oci.image.layer.v1.tar"
                else "application/vnd.oci.image.layer.v1.tar"
            )
        descriptors.append(
            {
                "mediaType": media_type,
                "digest": f"sha256:{digest}",
                "size": size,
            }
        )
        blobs.append((digest, blob))
    if corrupt == "layerDescriptorFieldAlias":
        descriptors[0]["Digest"] = "sha256:" + "9" * 64
    elif corrupt == "descriptorPlatformFieldAlias":
        descriptors[0]["platform"] = {
            "architecture": "arm64",
            "Architecture": "amd64",
        }

    config = {
        "architecture": "arm64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": []},
    }
    if corrupt == "configBlobFieldAlias":
        config["Architecture"] = "amd64"
    elif corrupt == "configRootfsFieldAlias":
        config["rootfs"]["Type"] = "not-layers"
    elif corrupt == "configRunFieldAlias":
        config["config"] = {"Env": [], "env": ["SPLIT=1"]}
    config_bytes = json.dumps(
        config,
        sort_keys=corrupt
        not in {
            "configBlobFieldAlias",
            "configRootfsFieldAlias",
            "configRunFieldAlias",
        },
    ).encode("utf-8")
    config_digest = sha256(config_bytes)
    config_size = len(config_bytes)
    if corrupt == "configDigest":
        config_digest = "1" * 64
    elif corrupt == "configSize":
        config_size += 1
    manifest = {
        "schemaVersion": 1 if corrupt == "manifestSchema" else 2,
        "mediaType": (
            "application/octet-stream"
            if corrupt == "manifestMediaType"
            else "application/vnd.docker.distribution.manifest.v2+json"
        ),
        "config": {
            "mediaType": (
                "application/octet-stream"
                if corrupt == "configMediaType"
                else "application/vnd.docker.container.image.v1+json"
            ),
            "digest": f"sha256:{config_digest}",
            "size": config_size,
        },
        "layers": descriptors,
    }
    if corrupt == "manifestFieldAlias":
        manifest["Layers"] = []
    elif corrupt == "configDescriptorFieldAlias":
        manifest["config"]["Digest"] = "sha256:" + "9" * 64
    elif corrupt == "manifestSubjectDescriptorFieldAlias":
        manifest["subject"] = {
            "mediaType": "application/octet-stream",
            "digest": "sha256:" + "7" * 64,
            "size": 1,
            "Digest": "sha256:" + "8" * 64,
        }
    manifest_bytes = json.dumps(
        manifest,
        sort_keys=corrupt
        not in {
            "manifestFieldAlias",
            "configDescriptorFieldAlias",
            "layerDescriptorFieldAlias",
            "descriptorPlatformFieldAlias",
            "manifestSubjectDescriptorFieldAlias",
        },
    ).encode("utf-8")
    manifest_digest = sha256(manifest_bytes)
    index = {
        "schemaVersion": 1 if corrupt == "indexSchema" else 2,
        "manifests": [
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "digest": f"sha256:{manifest_digest}",
                "size": (
                    len(manifest_bytes) + 1
                    if corrupt == "manifestSize"
                    else len(manifest_bytes)
                ),
            }
        ],
    }
    if corrupt == "indexTopLevelFieldAlias":
        index["Manifests"] = []
    elif corrupt == "indexDescriptorFieldAlias":
        index["manifests"][0]["Digest"] = "sha256:" + "9" * 64
    elif corrupt == "indexSubjectDescriptorFieldAlias":
        index["subject"] = {
            "mediaType": "application/octet-stream",
            "digest": "sha256:" + "5" * 64,
            "size": 1,
            "Digest": "sha256:" + "6" * 64,
        }
    index_bytes = json.dumps(
        index,
        sort_keys=corrupt
        not in {
            "indexTopLevelFieldAlias",
            "indexDescriptorFieldAlias",
            "indexSubjectDescriptorFieldAlias",
        },
    ).encode("utf-8")
    if corrupt == "duplicateExactIndexField":
        index_bytes = index_bytes[:-1] + b',"schemaVersion":2}'
    layer_paths = [
        f"blobs/sha256/{descriptor['digest'][7:]}"
        for descriptor in descriptors
    ]
    docker_entry: dict[str, Any] = {
        "Config": f"blobs/sha256/{config_digest}",
        "RepoTags": ["xenoid/runtime:fixture"],
        "Layers": layer_paths,
    }
    if corrupt == "dockerConfig":
        docker_entry["Config"] = "blobs/sha256/" + "9" * 64
    elif corrupt == "dockerLayers":
        docker_entry["Layers"] = ["blobs/sha256/" + "8" * 64]
    elif corrupt == "dockerLayerOrder":
        docker_entry["Layers"] = list(reversed(layer_paths))
    elif corrupt == "dockerManifestFieldAlias":
        docker_entry["layers"] = []
    elif corrupt == "dockerLayerSourceDescriptorFieldAlias":
        docker_entry["LayerSources"] = {
            "sha256:" + "3" * 64: {
                "mediaType": "application/octet-stream",
                "digest": "sha256:" + "3" * 64,
                "size": 1,
                "Digest": "sha256:" + "4" * 64,
            }
        }
    docker_manifest: list[dict[str, Any]] = [docker_entry]
    if corrupt == "dockerManifestMultiple":
        docker_manifest.append(copy.deepcopy(docker_entry))
    oci_layout = {
        "imageLayoutVersion": (
            "0.9.0" if corrupt == "ociLayout" else "1.0.0"
        )
    }
    if corrupt == "ociLayoutFieldAlias":
        oci_layout["ImageLayoutVersion"] = "0.9.0"
    oci_layout_bytes = json.dumps(
        oci_layout,
        sort_keys=corrupt != "ociLayoutFieldAlias",
    ).encode("utf-8")
    docker_manifest_bytes = json.dumps(
        docker_manifest,
        sort_keys=corrupt
        not in {
            "dockerManifestFieldAlias",
            "dockerLayerSourceDescriptorFieldAlias",
        },
    ).encode("utf-8")

    entries = [
        ("oci-layout", oci_layout_bytes),
        ("index.json", index_bytes),
        ("manifest.json", docker_manifest_bytes),
        (f"blobs/sha256/{config_digest}", config_bytes),
        (f"blobs/sha256/{manifest_digest}", manifest_bytes),
    ]
    entries.extend((f"blobs/sha256/{digest}", blob) for digest, blob in blobs)
    if corrupt == "missingOciLayout":
        entries = [entry for entry in entries if entry[0] != "oci-layout"]
    elif corrupt == "missingDockerManifest":
        entries = [entry for entry in entries if entry[0] != "manifest.json"]
    elif corrupt == "aliasIndex":
        entries.append(("./index.json", json.dumps(index, sort_keys=True).encode("utf-8")))
    elif corrupt == "aliasBlob":
        digest, blob = blobs[0]
        entries.append((f"./blobs/sha256/{digest}", blob))
    elif corrupt == "absoluteOuter":
        entries.append(("/index.json", json.dumps(index, sort_keys=True).encode("utf-8")))
    elif corrupt == "parentOuter":
        entries.append(("../index.json", json.dumps(index, sort_keys=True).encode("utf-8")))
    elif corrupt == "dotOuter":
        digest, blob = blobs[0]
        entries.append((f"blobs/./sha256/{digest}", blob))
    elif corrupt == "slashOuter":
        digest, blob = blobs[0]
        entries.append((f"blobs//sha256/{digest}", blob))
    elif corrupt == "trailingSlashOuter":
        entries.append(("index.json/", json.dumps(index, sort_keys=True).encode("utf-8")))
    with tarfile.open(path, mode="w:") as archive:
        for name, payload in entries:
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.mtime = 0
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    path.chmod(0o600)


def zip_info(
    name: str,
    *,
    mode: int = stat.S_IFREG | 0o600,
    date_time: tuple[int, int, int, int, int, int] = (2025, 7, 8, 9, 10, 12),
) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=date_time)
    info.create_system = 3
    info.external_attr = mode << 16
    info.extra = b"\x0a\x00\x00\x00"
    info.comment = b"entry comment"
    info.compress_type = zipfile.ZIP_STORED
    return info


def write_variant_zip(path: Path, *, reverse: bool) -> None:
    rows = [
        ("z-last.txt", b"compress me " * 40, stat.S_IFREG | 0o777),
        ("nested/alpha.txt", b"alpha", stat.S_IFREG | 0o400),
        ("nested/deeper/beta.bin", bytes(range(64)), stat.S_IFREG | 0o700),
        ("unicode/\u00e9.txt", b"utf8", stat.S_IFREG | 0o600),
    ]
    if reverse:
        rows.reverse()
    with zipfile.ZipFile(path, "w") as archive:
        archive.comment = b"source archive comment"
        if not reverse:
            archive.writestr(
                zip_info(
                    "nested/",
                    mode=stat.S_IFDIR | 0o700,
                    date_time=(2001, 2, 3, 4, 5, 6),
                ),
                b"",
            )
        for index, (name, payload, mode) in enumerate(rows):
            archive.writestr(
                zip_info(name, mode=mode, date_time=(2002 + index, 3, 4, 5, 6, 8)),
                payload,
            )


@contract_case("canonicalZipNormalizesEveryMetadataField")
def canonical_zip_normalizes_every_metadata_field() -> None:
    with tempfile.TemporaryDirectory(prefix="xenoid-archive-contract-") as raw:
        root = Path(raw)
        source_a = root / "a.jar"
        source_b = root / "b.jar"
        output_a = root / "a.canonical.jar"
        output_b = root / "b.canonical.jar"
        write_variant_zip(source_a, reverse=False)
        write_variant_zip(source_b, reverse=True)
        xenoid_archive.canonicalize_zip(source_a, output_a)
        xenoid_archive.canonicalize_zip(source_b, output_b)
        require(output_a.read_bytes() == output_b.read_bytes(), "canonical ZIP depends on source order/metadata")
        require(stat.S_IMODE(output_a.stat().st_mode) == 0o644, "canonical archive mode")
        with zipfile.ZipFile(output_a) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            require(names == sorted(names, key=lambda name: name.encode("utf-8")), "ZIP names not bytewise sorted")
            require(archive.comment == b"", "archive comment retained")
            require(names.count("nested/") == 1 and names.count("nested/deeper/") == 1, "directories not canonical")
            require(names.count("unicode/") == 1, "implicit Unicode directory missing")
            for info in infos:
                directory = info.is_dir()
                require(info.date_time == (1980, 1, 1, 0, 0, 0), "ZIP timestamp not DOS epoch")
                require(info.create_system == 3, "ZIP creator is not Unix")
                require(info.extra == b"" and info.comment == b"", "ZIP metadata retained")
                require(info.compress_type == zipfile.ZIP_DEFLATED, "ZIP entry is not fixed DEFLATE")
                require(
                    stat.S_IMODE(info.external_attr >> 16) == (0o755 if directory else 0o644),
                    "ZIP entry mode is not canonical",
                )
                require(
                    stat.S_IFMT(info.external_attr >> 16) == (stat.S_IFDIR if directory else stat.S_IFREG),
                    "ZIP entry Unix type is not canonical",
                )


@contract_case("canonicalZipRejectsUnsafeEntriesAtomically")
def canonical_zip_rejects_unsafe_entries_atomically() -> None:
    cases = (
        ("absolute", "/absolute.dex", stat.S_IFREG | 0o644, "zip_entry_unsafe_name"),
        ("parent", "safe/../escape.dex", stat.S_IFREG | 0o644, "zip_entry_unsafe_name"),
        ("backslash", "safe\\escape.dex", stat.S_IFREG | 0o644, "zip_entry_invalid_name"),
        ("symlink", "classes.dex", stat.S_IFLNK | 0o777, "zip_entry_special"),
        ("fifo", "classes.dex", stat.S_IFIFO | 0o600, "zip_entry_special"),
    )
    with tempfile.TemporaryDirectory(prefix="xenoid-archive-unsafe-") as raw:
        root = Path(raw)
        for label, name, mode, code in cases:
            source = root / f"{label}.zip"
            destination = root / f"{label}.out.zip"
            destination.write_bytes(b"prior verified bytes")
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr(zip_info(name, mode=mode), b"payload")
            expect_code(code, xenoid_archive.canonicalize_zip, source, destination)
            require(destination.read_bytes() == b"prior verified bytes", f"{label} replaced prior output")

        duplicate = root / "duplicate.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate, "w") as archive:
                archive.writestr("classes.dex", b"one")
                archive.writestr("classes.dex", b"two")
        prior = root / "duplicate.out.zip"
        prior.write_bytes(b"prior")
        expect_code("zip_entry_duplicate", xenoid_archive.canonicalize_zip, duplicate, prior)
        require(prior.read_bytes() == b"prior", "duplicate input replaced prior output")


class _Response(io.BytesIO):
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


@contract_case("patchersShareOnePinnedApktoolResolver")
def patchers_share_one_pinned_apktool_resolver() -> None:
    require(xenoid_archive.APKTOOL_VERSION == "2.10.0", "Apktool version is not pinned")
    require(
        xenoid_archive.APKTOOL_SHA256 == "c0350abbab5314248dfe2ee0c907def4edd14f6faef1f5d372d3d4abd28f0431",
        "Apktool digest changed without a contract update",
    )
    tool_bytes = b"synthetic pinned apktool bytes"
    with tempfile.TemporaryDirectory(prefix="xenoid-apktool-contract-") as raw, mock.patch.object(
        xenoid_archive, "APKTOOL_SHA256", sha256(tool_bytes)
    ), mock.patch.object(
        xenoid_archive.urllib.request,
        "urlopen",
        return_value=_Response(tool_bytes),
    ) as download:
        root = Path(raw)
        resolved = xenoid_archive.resolve_apktool(root)
        require(resolved.read_bytes() == tool_bytes, "resolved Apktool bytes differ")
        require(stat.S_IMODE(resolved.stat().st_mode) == 0o600, "Apktool cache is not private")
        require(download.call_count == 1, "Apktool was not downloaded exactly once")
        with mock.patch.object(
            xenoid_archive.urllib.request,
            "urlopen",
            side_effect=AssertionError("cache hit attempted a download"),
        ):
            require(xenoid_archive.resolve_apktool(root) == resolved, "verified Apktool cache not reused")

    for relative in (
        "scripts/patch-services-runtime.py",
        "scripts/patch-telephony-legacy-lte-band.py",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        require("from xenoid_archive import" in source, f"{relative} does not use shared archive module")
        for symbol in ("run_apktool", "canonicalize_zip", "publish_file_atomic"):
            require(symbol in source, f"{relative} misses {symbol}")
        require("shutil.which" not in source, f"{relative} selects PATH Apktool")
        require("os.environ.get(\"APKTOOL\")" not in source, f"{relative} honors an unpinned Apktool")
        require("APKTOOL_URL" not in source and "APKTOOL_SHA256" not in source, f"{relative} duplicates resolver pins")
        require(
            source.index("canonicalize_zip") < source.rindex("publish_file_atomic"),
            f"{relative} publishes before canonical verification",
        )


def write_context_fixture(root: Path, *, variant: int) -> None:
    rows = [
        ("Dockerfile", b"FROM immutable-base\n", 0o777 if variant else 0o600),
        ("payload/xenoid-input", b"executable payload\n", 0o400 if variant else 0o777),
        ("payload/ordinary.txt", b"ordinary payload\n", 0o700 if variant else 0o600),
        ("payload/unicode/\u00e9.txt", b"unicode payload\n", 0o444),
    ]
    if variant:
        rows.reverse()
    for index, (relative, payload, mode) in enumerate(rows):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(mode)
        timestamp = 1_700_000_000 + variant * 1000 + index
        os.utime(path, (timestamp, timestamp), follow_symlinks=False)
    for directory in (candidate for candidate in root.rglob("*") if candidate.is_dir()):
        directory.chmod(0o700 if variant else 0o777)
        os.utime(directory, (1_600_000_000 + variant, 1_600_000_000 + variant), follow_symlinks=False)


def canonicalize_context(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(ROOT / "scripts" / "make-runtime-context.sh"), "--canonicalize-only", str(root)],
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "0"},
    )


def context_bytes(root: Path) -> dict[str, tuple[int, int, bytes]]:
    result: dict[str, tuple[int, int, bytes]] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().encode("utf-8")):
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        payload = path.read_bytes() if stat.S_ISREG(info.st_mode) else b""
        result[relative] = (stat.S_IMODE(info.st_mode), info.st_mtime_ns, payload)
    return result


@contract_case("canonicalRuntimeContextsAreEqualAndInputSensitive")
def canonical_runtime_contexts_are_equal_and_input_sensitive() -> None:
    with tempfile.TemporaryDirectory(prefix="xenoid-context-contract-") as raw:
        parent = Path(raw)
        first = parent / "first"
        second = parent / "second"
        first.mkdir()
        second.mkdir()
        write_context_fixture(first, variant=0)
        write_context_fixture(second, variant=1)
        for root in (first, second):
            result = canonicalize_context(root)
            require(result.returncode == 0, f"context canonicalizer failed: {result.stderr}")
        require(context_bytes(first) == context_bytes(second), "canonical contexts differ by source order/metadata")

        manifest_payload = (first / "context-manifest.json").read_bytes()
        manifest = json.loads(manifest_payload)
        require(manifest["schema"] == "dev.xenoid.runtime-context/v1", "context schema")
        entries = manifest["entries"]
        paths = [entry["path"] for entry in entries]
        require(paths == sorted(paths, key=lambda item: item.encode("utf-8")), "context entries not sorted")
        require("context-manifest.json" not in paths, "context manifest includes itself")
        require(len(paths) == len(set(paths)), "context manifest has duplicates")
        for entry in entries:
            path = first / entry["path"]
            require(path.stat().st_mtime_ns == 0, "context entry mtime is not epoch zero")
            if entry["type"] == "directory":
                require(entry == {"path": entry["path"], "type": "directory", "mode": "0755", "size": 0, "sha256": None}, "directory record")
            else:
                expected_mode = "0755" if entry["path"] == "payload/xenoid-input" else "0644"
                require(entry["mode"] == expected_mode, "declared executable/ordinary mode")
                require(entry["size"] == path.stat().st_size, "context size")
                require(entry["sha256"] == sha256(path.read_bytes()), "context digest")

        before = sha256(manifest_payload)
        changed = second / "payload" / "ordinary.txt"
        changed.write_bytes(b"semantic change\n")
        changed.chmod(0o644)
        require(canonicalize_context(second).returncode == 0, "changed context did not canonicalize")
        after = sha256((second / "context-manifest.json").read_bytes())
        require(after != before, "semantic context change did not change the manifest")

        script = (ROOT / "scripts" / "make-runtime-context.sh").read_text(encoding="utf-8")
        require("XENOID_ARTIFACT_STAGE" in script, "context does not require a validated artifact stage")
        for hidden_build in ("build-xenoid-input.sh", "build-xenoid-hide.sh", "build-xenoid-profile.sh", "build-keymint.sh"):
            require(hidden_build not in script, f"context contains fallback build: {hidden_build}")


@contract_case("canonicalRuntimeContextRejectsSymlinksAndSpecialFiles")
def canonical_runtime_context_rejects_symlinks_and_special_files() -> None:
    with tempfile.TemporaryDirectory(prefix="xenoid-context-unsafe-") as raw:
        parent = Path(raw)
        linked = parent / "linked"
        linked.mkdir()
        (linked / "payload").mkdir()
        (linked / "real").write_bytes(b"real")
        (linked / "payload" / "link").symlink_to(linked / "real")
        result = canonicalize_context(linked)
        require(result.returncode != 0 and "runtime_context_unsafe_entry" in result.stderr, "context symlink accepted")
        require(not (linked / "context-manifest.json").exists(), "unsafe context published a manifest")

        special = parent / "special"
        special.mkdir()
        os.mkfifo(special / "fifo", 0o600)
        result = canonicalize_context(special)
        require(result.returncode != 0 and "runtime_context_unsafe_entry" in result.stderr, "context FIFO accepted")
        require(not (special / "context-manifest.json").exists(), "special context published a manifest")


def seed_contract(*, package: str = "dev.xenoid.daemon", shared_user: str = "android.uid.system") -> dict[str, Any]:
    return {
        "packageName": package,
        "sharedUserId": shared_user,
        "systemDestination": "/system/priv-app/XenoidDaemon/XenoidDaemon.apk",
        "signingLineage": ["a" * 64, "b" * 64],
        "privilegedPermissions": [
            "android.permission.WRITE_SECURE_SETTINGS",
            "android.permission.READ_PRIVILEGED_PHONE_STATE",
        ],
        "apkSha256": "c" * 64,
        "versionCode": 7,
    }


def artifact_tuples() -> list[dict[str, Any]]:
    return [
        {
            "target": "payload",
            "inputSha256": "d" * 64,
            "toolSha256": "e" * 64,
            "outputs": [{"path": "out/payload.bin", "mode": "0755", "size": 5, "sha256": "f" * 64}],
        },
        {
            "target": "daemon",
            "inputSha256": "1" * 64,
            "toolSha256": "2" * 64,
            "outputs": [{"path": "out/daemon.apk", "mode": "0644", "size": 6, "sha256": "c" * 64}],
        },
    ]

def synthetic_microg_facts() -> dict[str, Any]:
    return {
        "components": [
            {
                "id": "gmsCore",
                "runtimePath": "/system/product/priv-app/GmsCore/GmsCore.apk",
                "sha256": "1" * 64,
                "size": 105948577,
            },
            {
                "id": "gsfProxy",
                "runtimePath": "/system/product/priv-app/GsfProxy/GsfProxy.apk",
                "sha256": "2" * 64,
                "size": 21872,
            },
            {
                "id": "playStoreSeed",
                "runtimePath": "/system/product/priv-app/Phonesky/Phonesky.apk",
                "sha256": "3" * 64,
                "size": 62447827,
            },
        ],
        "sources": {
            "mindthegapps": {
                "metadataSha256": "4" * 64,
                "importManifestSha256": "5" * 64,
            },
            "microg": {
                "commit": "352f2d72fa52c6c3c4fdd79d575a071a0da72ad1",
                "tag": "v0.3.15.250932",
            },
            "gsfproxy": {
                "commit": "2fb4385a04d73f66385b325e97ac6cc40339db48",
                "tag": "v0.1.0",
            },
        },
        "signaturePolicy": {
            "realSignerSha256": "9bd06727e62796c0130eb6dab39b73157451582cbd138e86c468acc395d14165",
            "fakeSignerSha256": "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83",
            "sourceCommits": [
                "6d2955f0bd55e9938d5d49415182c27b50900b95",
                "53e2f4b85ce836360dd58bdb2f0d7f42dc796443",
            ],
            "apiFields": ["signatures", "signingInfo", "forceQueryable"],
        },
        "productPolicy": {
            "sourceCommit": "bd95ffe12653c1e8e695c841efa847af06d32a15",
            "inputs": [
                {
                    "path": "scripts/generate-microg-product-policy.py",
                    "sha256": "6" * 64,
                }
            ],
            "outputs": [
                {
                    "path": "system/product/etc/microg.xml",
                    "sha256": "7" * 64,
                }
            ],
        },
    }


def synthetic_digest(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    )


def synthetic_microg_google_inputs(
    facts: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    selected = copy.deepcopy(dict(facts or synthetic_microg_facts()))
    components = selected["components"]
    sources = selected["sources"]
    signature_policy = selected["signaturePolicy"]
    product_policy = selected["productPolicy"]
    projection = {
        "schema": "dev.xenoid.google-release/v2",
        "provider": "microg",
        "release": "microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0",
        **selected,
    }
    spec_sha = synthetic_digest(projection)
    play_store = next(
        item for item in components if item["id"] == "playStoreSeed"
    )
    return {
        "provider": "microg",
        "release": projection["release"],
        "specSha256": spec_sha,
        "dataCompatibilitySha256": spec_sha,
        "metadataSha256": synthetic_digest({"metadata": projection}),
        "providerSchema": projection["schema"],
        "componentSetSha256": synthetic_digest(components),
        "importManifestSha256": synthetic_digest(
            {"components": components[:2], "sources": sources}
        ),
        "sourceImportManifestSha256": sources["mindthegapps"][
            "importManifestSha256"
        ],
        "sourceMetadataSha256": sources["mindthegapps"]["metadataSha256"],
        "playStoreSeedSha256": play_store["sha256"],
        "signaturePolicySha256": synthetic_digest(signature_policy),
        "productPolicySha256": synthetic_digest(product_policy),
        "payloadSha256": synthetic_digest(
            [
                {
                    "runtimePath": item["runtimePath"],
                    "sha256": item["sha256"],
                    "size": item["size"],
                }
                for item in sorted(
                    components,
                    key=lambda value: value["runtimePath"].encode("utf-8"),
                )
            ]
        ),
    }


def compute_fixture(
    *,
    artifacts_value: Sequence[Mapping[str, Any]] | None = None,
    seed_value: Mapping[str, Any] | None = None,
    base_id: str = BASE_ID,
    context: Mapping[str, Any] | None = None,
    google: Mapping[str, Any] | None = None,
    tools: Mapping[str, Any] | None = None,
    builder: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return runtime_image.compute_input_record(
        base_image_id=base_id,
        artifact_tuples=artifacts_value or artifact_tuples(),
        context_inputs=context or {"runtimeTreeSha256": "5" * 64, "patchersSha256": "6" * 64},
        google_inputs=google or {"provider": "none", "payloadSha256": "7" * 64},
        tool_inputs=tools or {"apktoolSha256": xenoid_archive.APKTOOL_SHA256, "javaSha256": "8" * 64},
        builder_inputs=builder or {"dockerSha256": "9" * 64, "platform": "linux/arm64"},
        daemon_seed_contract=seed_value or seed_contract(),
    )


@contract_case("daemonCodeChangesOnlyTheFullImageIdentity")
def daemon_code_changes_only_the_full_image_identity() -> None:
    first = compute_fixture()
    changed_artifacts = copy.deepcopy(artifact_tuples())
    daemon = next(item for item in changed_artifacts if item["target"] == "daemon")
    daemon["inputSha256"] = "0" * 64
    daemon["toolSha256"] = "3" * 64
    daemon["outputs"][0]["sha256"] = "4" * 64
    changed_seed = seed_contract()
    changed_seed["apkSha256"] = "4" * 64
    changed_seed["versionCode"] = 8
    changed = compute_fixture(artifacts_value=changed_artifacts, seed_value=changed_seed)
    require(changed["inputSha256"] != first["inputSha256"], "daemon bytes did not change full identity")
    require(changed["bootInputSha256"] == first["bootInputSha256"], "daemon code changed boot identity")

    reordered_seed = seed_contract()
    reordered_seed["signingLineage"] = list(reversed(reordered_seed["signingLineage"]))
    reordered_seed["privilegedPermissions"] = list(reversed(reordered_seed["privilegedPermissions"]))
    reordered = compute_fixture(seed_value=reordered_seed)
    require(reordered["inputSha256"] == first["inputSha256"], "canonical daemon identity depends on order")
    require(reordered["bootInputSha256"] == first["bootInputSha256"], "canonical boot identity depends on order")


@contract_case("EveryBootCriticalInputChangesTheBootIdentity")
def every_boot_critical_input_changes_the_boot_identity() -> None:
    baseline = compute_fixture()
    mutations: list[dict[str, Any]] = []

    payload = copy.deepcopy(artifact_tuples())
    next(item for item in payload if item["target"] == "payload")["outputs"][0]["sha256"] = "0" * 64
    mutations.append(compute_fixture(artifacts_value=payload))
    mutations.append(compute_fixture(base_id="sha256:" + "0" * 64))
    mutations.append(compute_fixture(context={"runtimeTreeSha256": "0" * 64, "patchersSha256": "6" * 64}))
    mutations.append(compute_fixture(google=synthetic_microg_google_inputs()))
    mutations.append(compute_fixture(tools={"apktoolSha256": "0" * 64, "javaSha256": "8" * 64}))
    mutations.append(compute_fixture(builder={"dockerSha256": "0" * 64, "platform": "linux/arm64"}))
    mutations.append(compute_fixture(seed_value=seed_contract(package="dev.xenoid.daemon2")))
    mutations.append(compute_fixture(seed_value=seed_contract(shared_user="android.uid.system2")))
    signing = seed_contract()
    signing["signingLineage"] = ["0" * 64]
    mutations.append(compute_fixture(seed_value=signing))
    permission = seed_contract()
    permission["privilegedPermissions"] = [*permission["privilegedPermissions"], "android.permission.PACKAGE_USAGE_STATS"]
    mutations.append(compute_fixture(seed_value=permission))

    for index, value in enumerate(mutations):
        require(value["inputSha256"] != baseline["inputSha256"], f"mutation {index} kept full digest")
        require(value["bootInputSha256"] != baseline["bootInputSha256"], f"mutation {index} kept boot digest")

    bad_destination = seed_contract()
    bad_destination["systemDestination"] = "/data/local/tmp/xenoid-daemon.apk"
    expect_code("runtime_image_daemon_seed_invalid", compute_fixture, seed_value=bad_destination)


@contract_case("CompositeGoogleInputsChangeFullAndBootIdentity")
def composite_google_inputs_change_full_and_boot_identity() -> None:
    facts = synthetic_microg_facts()
    google_inputs = synthetic_microg_google_inputs(facts)
    baseline = compute_fixture(google=google_inputs)
    identical = compute_fixture(
        google=synthetic_microg_google_inputs(copy.deepcopy(facts))
    )
    require(identical == baseline, "identical composite inputs changed identity")
    configured = "registry.example/team/redroid:configured"
    baseline_tag = runtime_image.derive_tag(
        configured,
        baseline["inputSha256"],
    )
    require(
        runtime_image.derive_tag(configured, identical["inputSha256"])
        == baseline_tag,
        "identical composite inputs changed the derived tag",
    )

    mutations: list[tuple[str, dict[str, Any]]] = []
    for index, component in enumerate(facts["components"]):
        changed = copy.deepcopy(facts)
        changed["components"][index]["sha256"] = "0" * 64
        mutations.append((f"component:{component['id']}", changed))

    source_fields = {
        "mindthegapps": ("metadataSha256", "8" * 64),
        "microg": ("commit", "8" * 40),
        "gsfproxy": ("commit", "9" * 40),
    }
    for source, (field, value) in source_fields.items():
        changed = copy.deepcopy(facts)
        changed["sources"][source][field] = value
        mutations.append((f"source:{source}:{field}", changed))

    for field in ("realSignerSha256", "fakeSignerSha256"):
        changed = copy.deepcopy(facts)
        changed["signaturePolicy"][field] = "8" * 64
        mutations.append((f"certificate:{field}", changed))

    for index, _commit in enumerate(facts["signaturePolicy"]["sourceCommits"]):
        changed = copy.deepcopy(facts)
        changed["signaturePolicy"]["sourceCommits"][index] = str(index) * 40
        mutations.append((f"lineageCommit:{index}", changed))

    changed = copy.deepcopy(facts)
    changed["productPolicy"]["sourceCommit"] = "8" * 40
    mutations.append(("productPolicy:sourceCommit", changed))
    changed = copy.deepcopy(facts)
    changed["productPolicy"]["inputs"][0]["sha256"] = "8" * 64
    mutations.append(("productPolicy:input", changed))
    changed = copy.deepcopy(facts)
    changed["productPolicy"]["outputs"][0]["sha256"] = "8" * 64
    mutations.append(("productPolicy:output", changed))

    for label, changed_facts in mutations:
        changed = compute_fixture(
            google=synthetic_microg_google_inputs(changed_facts)
        )
        require(
            changed["inputSha256"] != baseline["inputSha256"],
            f"{label} kept the full image identity",
        )
        require(
            changed["bootInputSha256"] != baseline["bootInputSha256"],
            f"{label} kept the boot image identity",
        )
        require(
            runtime_image.derive_tag(configured, changed["inputSha256"])
            != baseline_tag,
            f"{label} kept the derived tag",
        )


@contract_case("PureTagsAndInputsAreCanonicalAndPathFree")
def pure_tags_and_inputs_are_canonical_and_path_free() -> None:
    first = compute_fixture()
    reordered = runtime_image.compute_input_record(
        base_image_id=BASE_ID,
        artifact_tuples=list(reversed(artifact_tuples())),
        context_inputs={"patchersSha256": "6" * 64, "runtimeTreeSha256": "5" * 64},
        google_inputs={"payloadSha256": "7" * 64, "provider": "none"},
        tool_inputs={"javaSha256": "8" * 64, "apktoolSha256": xenoid_archive.APKTOOL_SHA256},
        builder_inputs={"platform": "linux/arm64", "dockerSha256": "9" * 64},
        daemon_seed_contract=seed_contract(),
    )
    require(reordered == first, "pure input record is not canonical")
    require(first["schema"] == "dev.xenoid.runtime-image-input/v1", "input schema")
    require(len(first["inputSha256"]) == 64 and set(first["inputSha256"]) <= set(HEX), "full digest")
    require(len(first["bootInputSha256"]) == 64 and set(first["bootInputSha256"]) <= set(HEX), "boot digest")
    rendered = json.dumps(first, sort_keys=True)
    require(str(ROOT) not in rendered and "password" not in rendered, "pure identity exposes private material")

    configured = "registry.example:5000/team/redroid:operator-selected"
    expected = f"registry.example:5000/team/redroid:xenoid-{first['inputSha256'][:32]}"
    require(runtime_image.derive_tag(configured, first["inputSha256"]) == expected, "derived repository tag")
    for invalid in ("", "repo@sha256:" + "0" * 64, "UPPER/repo:tag", "repo::tag", "repo/../escape:tag"):
        expect_code("runtime_image_tag_invalid", runtime_image.derive_tag, invalid, first["inputSha256"])


class FakeArtifactBuilder:
    def __init__(self) -> None:
        self.daemon_bytes = b"daemon fixture"
        self.payload_bytes = b"payload fixture"
        self.stage_calls = 0
        self.snapshot_calls = 0

    def snapshot(self, consumer: str) -> artifacts.ArtifactSnapshot:
        require(consumer == "runtimeContext", "builder requested wrong artifact closure")
        self.snapshot_calls += 1
        daemon_output = artifacts.ArtifactOutput(
            "out/daemon.apk", 0o644, len(self.daemon_bytes), sha256(self.daemon_bytes)
        )
        payload_output = artifacts.ArtifactOutput(
            "out/payload.bin", 0o755, len(self.payload_bytes), sha256(self.payload_bytes)
        )
        records = (
            artifacts.ArtifactRecord("daemon", sha256(b"daemon-input" + self.daemon_bytes), "a" * 64, (daemon_output,), "ignored"),
            artifacts.ArtifactRecord("payload", sha256(b"payload-input" + self.payload_bytes), "b" * 64, (payload_output,), "ignored"),
        )
        manifest = sha256(
            json.dumps([record.as_dict() for record in records], sort_keys=True).encode("utf-8")
        )
        return artifacts.ArtifactSnapshot(("daemon", "payload"), records, manifest)

    def stage(self, snapshot: artifacts.ArtifactSnapshot, destination: Path) -> dict[str, Any]:
        self.stage_calls += 1
        payloads = {
            "out/daemon.apk": self.daemon_bytes,
            "out/payload.bin": self.payload_bytes,
        }
        for record in snapshot.records:
            for output in record.outputs:
                path = destination / output.path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payloads[output.path])
                path.chmod(output.mode)
        return {"ok": True, "manifestSha256": snapshot.manifest_sha256}

    def daemon_seed_contract(self, snapshot: artifacts.ArtifactSnapshot) -> dict[str, Any]:
        daemon = next(record for record in snapshot.records if record.target == "daemon")
        value = seed_contract()
        value["apkSha256"] = daemon.outputs[0].sha256
        return value

    def drift_daemon(self) -> None:
        self.daemon_bytes += b" changed"


class FakeEngineLock:
    def __init__(self) -> None:
        self._guards: dict[str, threading.Lock] = {}
        self._state = threading.Lock()
        self.depth = 0
        self.names: list[str] = []

    @contextmanager
    def __call__(self, name: str) -> Iterator[None]:
        with self._state:
            guard = self._guards.setdefault(name, threading.Lock())
        with guard:
            with self._state:
                self.depth += 1
                self.names.append(name)
            try:
                yield
            finally:
                with self._state:
                    self.depth -= 1

    def held(self) -> bool:
        with self._state:
            return self.depth > 0


class FakeDocker:
    def __init__(self, base_reference: str = "example/base:observed") -> None:
        self.base_reference = base_reference
        self.base_id = BASE_ID
        self.base_architecture = "arm64"
        self.base_repo_digests = [f"example/base@sha256:{BASE_DIGEST}"]
        self.images: dict[str, dict[str, Any]] = {}
        self.archives: dict[Path, tuple[str, dict[str, Any]]] = {}
        self.calls: list[tuple[str, ...]] = []
        self.context_calls = 0
        self.build_calls = 0
        self.build_failure = False
        self.move_base_after_build = False
        self.buildx_version = "v0.12.1"
        self.drift_artifacts_after_build: FakeArtifactBuilder | None = None
        self.lock: FakeEngineLock | None = None
        self._mutex = threading.Lock()
        self._refresh_base()

    def _refresh_base(self) -> None:
        self.images[self.base_reference] = self.image(
            self.base_id,
            labels={},
            architecture=self.base_architecture,
            repo_digests=self.base_repo_digests,
        )

    @staticmethod
    def image(
        image_id: str,
        *,
        labels: Mapping[str, str],
        architecture: str = "arm64",
        repo_digests: Sequence[str] = (),
        layers: Sequence[str] = (LAYER_ID,),
    ) -> dict[str, Any]:
        return {
            "Id": image_id,
            "Architecture": architecture,
            "RepoDigests": list(repo_digests),
            "Config": {"Labels": dict(labels)},
            "RootFS": {"Layers": list(layers)},
        }

    def _context(self, destination: Path, base_tag: str) -> None:
        destination.mkdir(parents=True)
        dockerfile = destination / "Dockerfile"
        dockerfile.write_text(
            f"FROM {base_tag}\nCOPY payload/fixture.bin /system/etc/xenoid/fixture.bin\n",
            encoding="ascii",
        )
        dockerfile.chmod(0o644)
        payload = destination / "payload"
        payload.mkdir()
        data = payload / "fixture.bin"
        data.write_bytes(b"canonical context fixture")
        data.chmod(0o644)
        for path in (dockerfile, data, payload, destination):
            os.utime(path, ns=(0, 0), follow_symlinks=False)
        entries = [
            {
                "path": "Dockerfile",
                "type": "file",
                "mode": "0644",
                "size": dockerfile.stat().st_size,
                "sha256": sha256(dockerfile.read_bytes()),
            },
            {"path": "payload", "type": "directory", "mode": "0755", "size": 0, "sha256": None},
            {
                "path": "payload/fixture.bin",
                "type": "file",
                "mode": "0644",
                "size": data.stat().st_size,
                "sha256": sha256(data.read_bytes()),
            },
        ]
        manifest = destination / "context-manifest.json"
        manifest.write_text(
            json.dumps(
                {"schema": "dev.xenoid.runtime-context/v1", "entries": entries},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        manifest.chmod(0o644)
        os.utime(manifest, ns=(0, 0), follow_symlinks=False)

    def __call__(
        self,
        command: tuple[str, ...],
        *,
        env: dict[str, str],
        cwd: str | None,
        input: bytes | None,
    ) -> subprocess.CompletedProcess[bytes]:
        del input
        with self._mutex:
            self.calls.append(command)
            if command[0].endswith("make-runtime-context.sh"):
                require(self.lock is not None and self.lock.held(), "context generated outside engine lock")
                require(env.get("SOURCE_DATE_EPOCH") == "0", "context epoch not fixed")
                require("XENOID_ARTIFACT_STAGE" in env, "context lacks artifact stage")
                self.context_calls += 1
                self._context(Path(command[2]), command[1])
                return subprocess.CompletedProcess(command, 0, b"", b"")
            if command[0] == "/fake/java":
                return subprocess.CompletedProcess(command, 0, b"", b"openjdk version 17 contract")
            require(command[0] == "fake-docker", f"unexpected child: {command}")
            suffix = command[1:]
            if suffix[:2] == ("version", "--format"):
                return subprocess.CompletedProcess(command, 0, b'{"Client":{"Version":"25.0.0"}}', b"")
            if suffix[:2] == ("buildx", "version"):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    f"github.com/docker/buildx {self.buildx_version} contract".encode("ascii"),
                    b"",
                )
            if suffix[:2] == ("image", "load"):
                archive = Path(suffix[3])
                require(
                    suffix[2:3] == ("--input",) and archive.is_file(),
                    "runtime image archive was not loaded",
                )
                pending = self.archives.pop(archive, None)
                require(pending is not None, "runtime image load did not consume its build")
                temporary_tag, image = pending
                self.images[temporary_tag] = image
                return subprocess.CompletedProcess(command, 0, b"loaded", b"")
            if suffix[:2] == ("image", "inspect"):
                reference = suffix[2]
                if ":xenoid-" in reference and not reference.startswith("xenoid/runtime-"):
                    require(self.lock is not None and self.lock.held(), "derived-tag inspect occurred outside engine lock")
                image = self.images.get(reference)
                if image is None:
                    return subprocess.CompletedProcess(command, 1, b"", b"not found")
                return subprocess.CompletedProcess(command, 0, json.dumps([image]).encode("utf-8"), b"")
            if suffix[:2] == ("image", "tag"):
                source, destination = suffix[2:4]
                if ":xenoid-" in destination and not destination.startswith("xenoid/runtime-"):
                    require(self.lock is not None and self.lock.held(), "publication occurred outside engine lock")
                source_image = self.images.get(source)
                if source_image is None:
                    source_image = next((image for image in self.images.values() if image["Id"] == source), None)
                if source_image is None:
                    return subprocess.CompletedProcess(command, 1, b"", b"missing source")
                self.images[destination] = copy.deepcopy(source_image)
                return subprocess.CompletedProcess(command, 0, b"", b"")
            if suffix[:2] == ("image", "rm"):
                self.images.pop(suffix[2], None)
                return subprocess.CompletedProcess(command, 0, b"", b"")
            if suffix[:2] == ("buildx", "build"):
                require(self.lock is not None and self.lock.held(), "build occurred outside engine lock")
                self.build_calls += 1
                if self.build_failure:
                    return subprocess.CompletedProcess(command, 17, b"", b"synthetic build failure")
                require("--platform=linux/arm64" in suffix, "build platform is not ARM64")
                require("--provenance=false" in suffix and "--sbom=false" in suffix, "reproducibility controls missing")
                require("--no-cache" in suffix, "deterministic build cache control missing")
                require(
                    "--output" in suffix
                    and suffix[suffix.index("--output") + 1]
                    == "type=docker,dest=image.tar,rewrite-timestamp=true"
                    and "--load" not in suffix,
                    "timestamp-rewritten archive exporter missing",
                )
                require("pull" not in suffix, "build implicitly pulls")
                labels: dict[str, str] = {}
                for index, value in enumerate(suffix):
                    if value == "--label":
                        key, label_value = suffix[index + 1].split("=", 1)
                        labels[key] = label_value
                temporary_tag = suffix[suffix.index("--tag") + 1]
                require(cwd is not None, "runtime image exporter has no private work directory")
                archive = Path(cwd) / "image.tar"
                context_path = Path(suffix[-1])
                write_oci_image_archive(
                    archive,
                    [
                        [
                            {
                                "name": "system/etc/xenoid/fixture.bin",
                                "data": (
                                    context_path / "payload" / "fixture.bin"
                                ).read_bytes(),
                            }
                        ]
                    ],
                )
                self.archives[archive] = (
                    temporary_tag,
                    self.image(BUILT_ID, labels=labels),
                )
                if self.move_base_after_build:
                    self.base_id = "sha256:" + "5" * 64
                    self._refresh_base()
                if self.drift_artifacts_after_build is not None:
                    self.drift_artifacts_after_build.drift_daemon()
                return subprocess.CompletedProcess(command, 0, b"", b"")
            raise ContractFailure(f"unsupported fake Docker command: {suffix}")


@contextmanager
def temporary_builder(
    *,
    base_reference: str = "example/base:observed",
    docker: FakeDocker | None = None,
) -> Iterator[tuple[Path, runtime_image.RuntimeImageBuilder, FakeDocker, FakeArtifactBuilder, FakeEngineLock]]:
    with tempfile.TemporaryDirectory(prefix="xenoid-runtime-image-contract-") as raw:
        root = Path(raw)
        for relative in (
            *runtime_image._CONTEXT_INPUT_PATHS,
            "runtime/redroid/payload.txt",
        ):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative == "scripts/xenoid_archive.py":
                path.write_bytes((ROOT / relative).read_bytes())
            else:
                path.write_text(f"fixture {relative}\n", encoding="utf-8")
        selected_docker = docker or FakeDocker(base_reference)
        selected_artifacts = FakeArtifactBuilder()
        engine_lock = FakeEngineLock()
        selected_docker.lock = engine_lock
        with mock.patch.object(runtime_image.shutil, "which", return_value="/fake/java"):
            builder = runtime_image.RuntimeImageBuilder(
                root,
                ("fake-docker",),
                {"DOCKER_HOST": "ssh" + "://operator:secret@example.invalid/engine"},
                artifact_builder=selected_artifacts,
                runner=selected_docker,
                engine_lock=engine_lock,
            )
            yield root, builder, selected_docker, selected_artifacts, engine_lock


@contract_case("builderValidatesBaseIdentityDigestAndArchitectureWithoutPull")
def builder_validates_base_identity_digest_and_architecture_without_pull() -> None:
    wrong_arch = FakeDocker()
    wrong_arch.base_architecture = "amd64"
    wrong_arch._refresh_base()
    with temporary_builder(docker=wrong_arch) as (_, builder, docker, _, _):
        expect_code("runtime_image_base_architecture_invalid", builder.input_record, docker.base_reference)
        require(not any("pull" in call for call in docker.calls), "base validation pulled an image")

    explicit = f"example/base@sha256:{BASE_DIGEST}"
    matching = FakeDocker(explicit)
    with temporary_builder(base_reference=explicit, docker=matching) as (_, builder, _, _, _):
        record = builder.input_record(explicit, configured_tag="team/runtime:operator")
        require(record["baseImageId"] == BASE_ID, "explicit base did not resolve immutable ID")

    mismatch_reference = "example/base@sha256:" + "0" * 64
    mismatch = FakeDocker(mismatch_reference)
    with temporary_builder(base_reference=mismatch_reference, docker=mismatch) as (_, builder, _, _, _):
        expect_code("runtime_image_base_digest_mismatch", builder.input_record, mismatch_reference)

    malformed = FakeDocker("example/base:observed")
    malformed.base_id = "example/base:mutable"
    malformed._refresh_base()
    with temporary_builder(docker=malformed) as (_, builder, _, _, _):
        expect_code("runtime_image_base_identity_invalid", builder.input_record, malformed.base_reference)

    unsupported = FakeDocker()
    unsupported.buildx_version = "v0.9.1"
    with temporary_builder(docker=unsupported) as (_, builder, docker, _, _):
        expect_code("runtime_image_builder_unsupported", builder.input_record, docker.base_reference)
        require(docker.build_calls == 0, "unsupported BuildKit fell back to legacy builder")


@contract_case("builderPublishesOnceThenReusesVerifiedContentTag")
def builder_publishes_once_then_reuses_verified_content_tag() -> None:
    configured = "registry.example:5000/team/runtime:operator-selected"
    with temporary_builder() as (root, builder, docker, artifacts_builder, engine_lock):
        first = builder.ensure(docker.base_reference, configured)
        require(first["schema"] == "dev.xenoid.runtime-image/v1", "runtime image schema")
        require(first["reused"] is False and first["imageId"] == BUILT_ID, "first ensure did not build")
        require(first["derivedTag"].startswith("registry.example:5000/team/runtime:xenoid-"), "derived tag namespace")
        require(docker.context_calls == 1 and docker.build_calls == 1, "miss did not create exactly one context/build")
        require(configured not in docker.images, "configured namespace tag was overwritten")
        require(not any(tag.startswith("xenoid/runtime-") for tag in docker.images), "temporary tag leaked")
        require(len(engine_lock.names) == 1 and engine_lock.names[0].startswith("xenoid-runtime-image-"), "engine lock key")

        second = builder.ensure(docker.base_reference, configured)
        require(second["reused"] is True and second["imageId"] == first["imageId"], "cache hit not reused")
        require(docker.context_calls == 1 and docker.build_calls == 1, "cache hit launched build work")
        require(artifacts_builder.stage_calls == 1, "cache hit staged artifacts")

        record = builder.lookup(first["inputSha256"])
        require(record is not None and record["derivedTag"] == first["derivedTag"], "published record unavailable")
        record_path = root / ".xenoid" / "cache" / "runtime-images" / f"{first['inputSha256']}.json"
        require(stat.S_IMODE(record_path.stat().st_mode) == 0o600, "runtime image record is not private")
        rendered = record_path.read_text(encoding="ascii")
        require(str(root) not in rendered and "operator:secret" not in rendered, "record exposes path/credential")
        require(record["labels"] == {
            runtime_image.RUNTIME_SCHEMA_LABEL: "1",
            runtime_image.RUNTIME_INPUT_LABEL: first["inputSha256"],
            runtime_image.RUNTIME_BOOT_INPUT_LABEL: first["bootInputSha256"],
            runtime_image.RUNTIME_BASE_IMAGE_LABEL: BASE_ID,
        }, "published labels are incomplete")
        require(record["contextManifestSha256"] is not None, "miss record lacks canonical context identity")

        provenance_before = first["inputSha256"]
        docker.base_repo_digests = [
            "example/base@sha256:" + "e" * 64,
            "example/base@sha256:" + "d" * 64,
        ]
        docker._refresh_base()
        provenance = builder.input_record(docker.base_reference)
        require(provenance["inputSha256"] == provenance_before, "RepoDigests affected content identity")
        require(provenance["baseRepoDigests"] == sorted(docker.base_repo_digests), "RepoDigests provenance not sorted")


@contract_case("materializedContextUsesDeterministicLockedBaseReference")
def materialized_context_uses_deterministic_locked_base_reference() -> None:
    with temporary_builder() as (_, builder, docker, _, engine_lock):
        first = builder.materialize_context(docker.base_reference)
        second = builder.materialize_context(docker.base_reference)
        first_context = Path(first["contextPath"])
        second_context = Path(second["contextPath"])
        require(
            first["contextManifestSha256"] == second["contextManifestSha256"],
            "identical materialized contexts changed digest",
        )
        require(
            (first_context / "Dockerfile").read_bytes()
            == (second_context / "Dockerfile").read_bytes(),
            "identical materialized contexts changed base reference",
        )
        require(
            first["inputSha256"] in (first_context / "Dockerfile").read_text("ascii"),
            "materialized context base reference is not content-addressed",
        )
        require(
            len(engine_lock.names) == 2 and len(set(engine_lock.names)) == 1,
            "materialized contexts used different engine locks",
        )
        require(
            not any(tag.startswith("xenoid/runtime-") for tag in docker.images),
            "materialized context leaked its base tag",
        )


@contract_case("builderRejectsOccupiedTagAndVerificationWeakness")
def builder_rejects_occupied_tag_and_verification_weakness() -> None:
    configured = "team/runtime:operator"
    with temporary_builder() as (_, builder, docker, _, _):
        desired = builder.input_record(docker.base_reference, configured_tag=configured)
        derived = desired["derivedTag"]
        docker.images[derived] = docker.image(BUILT_ID, labels={runtime_image.RUNTIME_SCHEMA_LABEL: "1"})
        expect_code("runtime_image_cache_conflict", builder.ensure, docker.base_reference, configured)
        require(docker.context_calls == 0 and docker.build_calls == 0, "collision launched a build")

    with temporary_builder() as (_, builder, docker, _, _):
        desired = builder.input_record(docker.base_reference, configured_tag=configured)
        labels = {
            runtime_image.RUNTIME_SCHEMA_LABEL: "1",
            runtime_image.RUNTIME_INPUT_LABEL: desired["inputSha256"],
            runtime_image.RUNTIME_BOOT_INPUT_LABEL: desired["bootInputSha256"],
            runtime_image.RUNTIME_BASE_IMAGE_LABEL: BASE_ID,
        }
        docker.images[desired["derivedTag"]] = docker.image(BUILT_ID, labels=labels, layers=())
        expect_code("runtime_image_cache_conflict", builder.ensure, docker.base_reference, configured)
        require(docker.build_calls == 0, "weak image verification rebuilt over occupied tag")


@contract_case("baseAndInputRacesDiscardBuildAndCleanTemporaryTags")
def base_and_input_races_discard_build_and_clean_temporary_tags() -> None:
    configured = "team/runtime:operator"
    racing_base = FakeDocker()
    racing_base.move_base_after_build = True
    with temporary_builder(docker=racing_base) as (root, builder, docker, _, _):
        expect_code("base_image_changed_during_build", builder.ensure, docker.base_reference, configured)
        require(docker.build_calls == 1 and docker.context_calls == 1, "base race not exercised")
        require(not any(tag.startswith("team/runtime:xenoid-") for tag in docker.images), "base race published derived tag")
        require(not any(tag.startswith("xenoid/runtime-") for tag in docker.images), "base race leaked temporary tag")
        require(not list((root / ".xenoid/cache/runtime-images").glob("*.json")), "base race published a record")

    with temporary_builder() as (root, builder, docker, artifact_builder, _):
        docker.drift_artifacts_after_build = artifact_builder
        expect_code("runtime_image_input_changed", builder.ensure, docker.base_reference, configured)
        require(not any(tag.startswith("team/runtime:xenoid-") for tag in docker.images), "input race published derived tag")
        require(not any(tag.startswith("xenoid/runtime-") for tag in docker.images), "input race leaked temporary tag")
        require(not list((root / ".xenoid/cache/runtime-images").glob("*.json")), "input race published a record")


@contract_case("buildFailurePreservesPublicationAndCleansOwnedState")
def build_failure_preserves_publication_and_cleans_owned_state() -> None:
    configured = "team/runtime:operator"
    failing = FakeDocker()
    failing.build_failure = True
    with temporary_builder(docker=failing) as (root, builder, docker, _, _):
        unrelated = docker.image("sha256:" + "9" * 64, labels={})
        docker.images["team/runtime:prior"] = unrelated
        expect_code("runtime_image_build_failed", builder.ensure, docker.base_reference, configured)
        require(docker.images.get("team/runtime:prior") == unrelated, "failure changed prior image")
        require(not any(tag.startswith("xenoid/runtime-") for tag in docker.images), "failure leaked temporary tag")
        require(not any(tag.startswith("team/runtime:xenoid-") for tag in docker.images), "failure published content tag")
        cache = root / ".xenoid" / "cache" / "runtime-images"
        require(not list(cache.glob("build-*")), "failure leaked build context")
        require(not list(cache.glob("*.json")), "failure published a record")


@contract_case("concurrentEnsureHasOnePublication")
def concurrent_ensure_has_one_publication() -> None:
    configured = "team/runtime:operator"
    with temporary_builder() as (_, builder, docker, _, engine_lock):
        barrier = threading.Barrier(3)
        results: list[dict[str, Any]] = []
        failures: list[BaseException] = []
        guard = threading.Lock()

        def worker() -> None:
            try:
                barrier.wait(timeout=5)
                result = builder.ensure(docker.base_reference, configured)
                with guard:
                    results.append(result)
            except BaseException as error:
                with guard:
                    failures.append(error)

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=10)
        require(not any(thread.is_alive() for thread in threads), "concurrent ensure deadlocked")
        require(not failures, f"concurrent ensure failed: {failures}")
        require(len(results) == 2, "concurrent ensure result count")
        require({result["reused"] for result in results} == {False, True}, "concurrent ensure did not build/reuse")
        require(len({result["imageId"] for result in results}) == 1, "concurrent ensure selected different images")
        require(docker.context_calls == 1 and docker.build_calls == 1, "concurrent ensure published more than once")
        require(len(engine_lock.names) == 2 and len(set(engine_lock.names)) == 1, "concurrent ensure used different locks")


@contract_case("productionCallersHaveNoLegacyMutableImagePath")
def production_callers_have_no_legacy_mutable_image_path() -> None:
    backend = (ROOT / "src" / "xenoid" / "backend.py").read_text(encoding="utf-8")
    cli = (ROOT / "src" / "xenoid" / "cli.py").read_text(encoding="utf-8")
    mcp = (ROOT / "src" / "xenoid" / "mcp_server.py").read_text(encoding="utf-8")
    require("def _build_effective_runtime_image" not in backend, "legacy backend image builder remains")
    require("runtimeSpecMatches" not in backend, "weak tag-only runtime match remains")
    require('f"{self.cfg.runtime_image_tag}-{self.context.resource_tag}"' not in backend, "instance tag suffix remains")
    require("effective_google_image(" not in backend, "mutable Google image tag remains")
    require("ensure_runtime_image" in cli and "runtime_image_input_record" in cli, "CLI does not share image builder")
    require("ensure_runtime_image" in mcp and "runtime_image_input_record" in mcp, "MCP does not share image builder")


@contract_case("archivePayloadVerificationDetectsStaleContent")
def archive_payload_verification_detects_stale_content() -> None:
    require(len(PAYLOAD_CONTENT_A) == len(PAYLOAD_CONTENT_B), "same-size fixture required")
    builder = runtime_image.RuntimeImageBuilder(Path(tempfile.gettempdir()), ("docker",), {})
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        context = build_payload_context(root)
        archive_path = root / "image.tar"
        write_oci_image_archive(archive_path, [payload_layer_members()])
        builder._verify_archive_payload(archive_path, context)
    expected_files = payload_expected_files()
    for changed in (
        {**expected_files, "vendor/lib64/libx.so": PAYLOAD_CONTENT_B},
        {**expected_files, "system/etc/xenoid/two.txt": b"stale directory payload"},
        {path: payload for path, payload in expected_files.items() if path != "vendor/lib64/libx.so"},
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context = build_payload_context(root)
            archive_path = root / "image.tar"
            members = [
                {"name": name, "data": payload}
                for name, payload in sorted(changed.items())
            ]
            write_oci_image_archive(archive_path, [members])
            expect_code(
                "runtime_image_payload_mismatch",
                builder._verify_archive_payload,
                archive_path,
                context,
            )


@contract_case("archivePayloadVerificationHardensLayerReplay")
def archive_payload_verification_hardens_layer_replay() -> None:
    builder = runtime_image.RuntimeImageBuilder(Path(tempfile.gettempdir()), ("docker",), {})

    def staged(
        members: list[list[dict[str, Any]]],
        corrupt: str | None = None,
        *,
        layer_media_type: str = "application/vnd.docker.image.rootfs.diff.tar.gzip",
    ):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        context = build_payload_context(root)
        archive_path = root / "image.tar"
        write_oci_image_archive(
            archive_path,
            members,
            corrupt=corrupt,
            layer_media_type=layer_media_type,
        )
        return temporary, archive_path, context

    # A legal "./" root directory record is a no-op.
    temporary, archive_path, context = staged(
        [[{"name": "./", "type": "dir"}] + payload_layer_members()]
    )
    with temporary:
        builder._verify_archive_payload(archive_path, context)

    # A non-directory root record is rejected.
    temporary, archive_path, context = staged(
        [[{"name": "./", "data": b"root-file"}] + payload_layer_members()]
    )
    with temporary:
        expect_code(
            "runtime_image_archive_layout_invalid",
            builder._verify_archive_payload,
            archive_path,
            context,
        )

    # Both spellings of a regular-file root record are invalid.
    temporary, archive_path, context = staged(
        [[{"name": ".", "data": b"root-file"}] + payload_layer_members()]
    )
    with temporary:
        expect_code(
            "runtime_image_archive_layout_invalid",
            builder._verify_archive_payload,
            archive_path,
            context,
        )

    # OCI whiteouts and opaque markers remove parent-layer entries only;
    # same-layer additions survive regardless of tar member order.
    whiteout = {"name": "system/lib64/.wh.libx.so", "data": b""}
    for members in (
        payload_layer_members() + [whiteout],
        [whiteout] + payload_layer_members(),
    ):
        temporary, archive_path, context = staged([members])
        with temporary:
            builder._verify_archive_payload(archive_path, context)

    opaque = {"name": "system/lib64/.wh..wh..opq", "data": b""}
    temporary, archive_path, context = staged(
        [payload_layer_members() + [opaque]]
    )
    with temporary:
        builder._verify_archive_payload(archive_path, context)

    # Tar parser failures while locating or reading OCI metadata are normalized.
    class BrokenMetadataArchive:
        def getmember(self, name: str) -> tarfile.TarInfo:
            return tarfile.TarInfo(name)

        def extractfile(self, member: tarfile.TarInfo) -> None:
            raise tarfile.ReadError("broken metadata")

    broken_member = tarfile.TarInfo("index.json")
    expect_code(
        "runtime_image_archive_layout_invalid",
        builder._archive_layer_descriptors,
        BrokenMetadataArchive(),
        {"index.json": broken_member},
    )

    class OversizedOuterArchive:
        def __iter__(self):
            yield tarfile.TarInfo("one")
            yield tarfile.TarInfo("two")

    original_outer_cap = runtime_image._MAX_IMAGE_ARCHIVE_MEMBERS
    runtime_image._MAX_IMAGE_ARCHIVE_MEMBERS = 1
    try:
        expect_code(
            "runtime_image_archive_layout_invalid",
            builder._archive_member_index,
            OversizedOuterArchive(),
        )
    finally:
        runtime_image._MAX_IMAGE_ARCHIVE_MEMBERS = original_outer_cap

    # Oversized PAX/GNU pseudo-members after a complete valid layer prefix
    # must be fatal. TarFile.next() swallows InvalidHeaderError at nonzero
    # offsets as EOF, which used to hide the later stale overwrite.
    original_metadata_cap = runtime_image._MAX_LAYER_METADATA_BYTES
    runtime_image._MAX_LAYER_METADATA_BYTES = 64
    try:
        for metadata_kind in ("pax", "gnu_longname"):
            members = payload_layer_members() + [
                {
                    "name": "extended-metadata",
                    "type": metadata_kind,
                    "data": b"x" * 65,
                },
                {
                    "name": "system/lib64/libx.so",
                    "data": PAYLOAD_CONTENT_B,
                },
            ]
            temporary, archive_path, context = staged([members])
            with temporary:
                expect_code(
                    "runtime_image_archive_layout_invalid",
                    builder._verify_archive_payload,
                    archive_path,
                    context,
                )
    finally:
        runtime_image._MAX_LAYER_METADATA_BYTES = original_metadata_cap

    # Pseudo-members do not appear in the layer-member loop, so their byte
    # budget is cumulative too. Each record fits independently; together
    # they exceed the cap before the stale second target can be processed.
    pax_metadata = pax_records({"comment": "x" * 32})
    runtime_image._MAX_LAYER_METADATA_BYTES = len(pax_metadata) + 1
    try:
        members = payload_layer_members() + [
            {
                "name": "pax-one",
                "type": "pax",
                "data": pax_metadata,
            },
            {"name": "unwanted-one", "data": b"one"},
            {
                "name": "pax-two",
                "type": "pax",
                "data": pax_metadata,
            },
            {
                "name": "system/lib64/libx.so",
                "data": PAYLOAD_CONTENT_B,
            },
        ]
        temporary, archive_path, context = staged([members])
        with temporary:
            expect_code(
                "runtime_image_archive_layout_invalid",
                builder._verify_archive_payload,
                archive_path,
                context,
            )
    finally:
        runtime_image._MAX_LAYER_METADATA_BYTES = original_metadata_cap

    # Ordinary per-file PAX metadata remains valid and budgeted.
    temporary, archive_path, context = staged(
        [
            [
                {
                    "name": "file-pax",
                    "type": "pax",
                    "data": pax_records({"comment": "ordinary"}),
                },
                {"name": "unwanted-pax-target", "data": b"ignored"},
            ]
            + payload_layer_members()
        ]
    )
    with temporary:
        builder._verify_archive_payload(archive_path, context)

    # Python tarfile persistently applies global PAX paths, but Go
    # archive/tar/containerd ignores them. A decoy must not overwrite a stale
    # lower target in the verifier's replay view only.
    global_pax_target = "system/lib64/libx.so"
    stale_lower = [
        {**member, "data": PAYLOAD_CONTENT_B}
        if member["name"] == global_pax_target
        else member
        for member in payload_layer_members()
    ]
    temporary, archive_path, context = staged(
        [
            stale_lower,
            [
                {
                    "name": "global-pax",
                    "type": "global_pax",
                    "data": pax_records({"path": global_pax_target}),
                },
                {"name": "decoy", "data": PAYLOAD_CONTENT_A},
            ],
        ]
    )
    with temporary:
        expect_code(
            "runtime_image_archive_layout_invalid",
            builder._verify_archive_payload,
            archive_path,
            context,
        )

    # GNU sparse entries and every PAX sparse encoding are rejected before
    # tarfile can allocate or synthesize logical sparse contents.
    sparse_members = (
        [{"name": "sparse.bin", "type": "gnu_sparse", "data": b"x"}],
        [
            {
                "name": "sparse-pax",
                "type": "pax",
                "data": pax_records({"GNU.sparse.map": "0,1"}),
            },
            {"name": "sparse.bin", "data": b"x"},
        ],
        [
            {
                "name": "sparse-pax-v1",
                "type": "pax",
                "data": pax_records(
                    {
                        "GNU.sparse.major": "1",
                        "GNU.sparse.minor": "0",
                        "GNU.sparse.realsize": "1",
                    }
                ),
            },
            {"name": "sparse.bin", "data": b"x"},
        ],
    )
    for sparse_prefix in sparse_members:
        temporary, archive_path, context = staged(
            [sparse_prefix + payload_layer_members()]
        )
        with temporary:
            expect_code(
                "runtime_image_archive_layout_invalid",
                builder._verify_archive_payload,
                archive_path,
                context,
            )
    temporary, archive_path, context = staged(
        [
            payload_layer_members(),
            [{"name": "system/lib64", "type": "symlink", "target": "/elsewhere"}],
        ]
    )
    with temporary:
        expect_code(
            "runtime_image_payload_mismatch",
            builder._verify_archive_payload,
            archive_path,
            context,
        )

    # A member beneath a replaced ancestor in the same layer is malformed.
    temporary, archive_path, context = staged(
        [
            [
                {"name": "system/lib64", "type": "symlink", "target": "/elsewhere"},
                {"name": "system/lib64/libx.so", "data": PAYLOAD_CONTENT_A},
            ]
            + [
                member
                for member in payload_layer_members()
                if member["name"] not in {"system/lib64", "system/lib64/libx.so"}
            ]
        ]
    )
    with temporary:
        expect_code(
            "runtime_image_archive_layout_invalid",
            builder._verify_archive_payload,
            archive_path,
            context,
        )

    # Every accepted media type is decoded with its declared compression.
    for media_type in (
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
    ):
        temporary, archive_path, context = staged(
            [payload_layer_members()], layer_media_type=media_type
        )
        with temporary:
            builder._verify_archive_payload(archive_path, context)

    # OCI descriptors, config bytes, Docker compatibility metadata, and
    # outer-member canonicalization all describe the exact same load view.
    for corrupt in (
        "digest",
        "size",
        "mediaType",
        "manifestSize",
        "compression",
        "configDigest",
        "configSize",
        "indexSchema",
        "manifestSchema",
        "manifestMediaType",
        "configMediaType",
        "ociLayoutFieldAlias",
        "indexTopLevelFieldAlias",
        "indexDescriptorFieldAlias",
        "indexSubjectDescriptorFieldAlias",
        "manifestFieldAlias",
        "configDescriptorFieldAlias",
        "layerDescriptorFieldAlias",
        "manifestSubjectDescriptorFieldAlias",
        "dockerManifestFieldAlias",
        "descriptorPlatformFieldAlias",
        "configBlobFieldAlias",
        "configRootfsFieldAlias",
        "configRunFieldAlias",
        "duplicateExactIndexField",
        "dockerLayerSourceDescriptorFieldAlias",
        "ociLayout",
        "missingOciLayout",
        "missingDockerManifest",
        "dockerConfig",
        "dockerLayers",
        "dockerManifestMultiple",
        "aliasIndex",
        "aliasBlob",
        "absoluteOuter",
        "parentOuter",
        "dotOuter",
        "slashOuter",
        "trailingSlashOuter",
    ):
        temporary, archive_path, context = staged(
            [payload_layer_members()], corrupt=corrupt
        )
        with temporary:
            expect_code(
                "runtime_image_archive_layout_invalid",
                builder._verify_archive_payload,
                archive_path,
                context,
            )

    # Layer order is part of the classic Docker manifest contract too.
    temporary, archive_path, context = staged(
        [
            [{"name": "unused-first", "data": b"first"}],
            payload_layer_members(),
        ],
        corrupt="dockerLayerOrder",
    )
    with temporary:
        expect_code(
            "runtime_image_archive_layout_invalid",
            builder._verify_archive_payload,
            archive_path,
            context,
        )

    # A non-directory ancestor remains blocking across later layers unless an
    # explicit directory record restores it.
    temporary, archive_path, context = staged(
        [
            payload_layer_members(),
            [{"name": "system/lib64", "type": "symlink", "target": "/elsewhere"}],
            [{"name": "system/lib64/libx.so", "data": PAYLOAD_CONTENT_A}],
        ]
    )
    with temporary:
        expect_code(
            "runtime_image_archive_layout_invalid",
            builder._verify_archive_payload,
            archive_path,
            context,
        )

    # Replacing an ancestor after adding its child in the same layer is also
    # malformed; member order cannot resurrect the child.
    temporary, archive_path, context = staged(
        [
            [
                {"name": "system/lib64/libx.so", "data": PAYLOAD_CONTENT_A},
                {"name": "system/lib64", "type": "symlink", "target": "/elsewhere"},
            ]
            + [
                member
                for member in payload_layer_members()
                if member["name"] not in {"system/lib64", "system/lib64/libx.so"}
            ]
        ]
    )
    with temporary:
        expect_code(
            "runtime_image_archive_layout_invalid",
            builder._verify_archive_payload,
            archive_path,
            context,
        )

    # Replay budgets fail closed.
    temporary, archive_path, context = staged([payload_layer_members()])
    with temporary:
        original = runtime_image._MAX_LAYER_MEMBERS
        runtime_image._MAX_LAYER_MEMBERS = 2
        try:
            expect_code(
                "runtime_image_archive_layout_invalid",
                builder._verify_archive_payload,
                archive_path,
                context,
            )
        finally:
            runtime_image._MAX_LAYER_MEMBERS = original

    temporary, archive_path, context = staged([payload_layer_members()])
    with temporary:
        original = runtime_image._MAX_LAYER_DECOMPRESSED_BYTES
        runtime_image._MAX_LAYER_DECOMPRESSED_BYTES = 1
        try:
            expect_code(
                "runtime_image_archive_layout_invalid",
                builder._verify_archive_payload,
                archive_path,
                context,
            )
        finally:
            runtime_image._MAX_LAYER_DECOMPRESSED_BYTES = original

    # Each tar stream is one RECORDSIZE block and fits by itself, but the
    # archive-wide decompressed budget must reject their combined replay.
    temporary, archive_path, context = staged(
        [
            [{"name": "unused-first", "data": b"first"}],
            payload_layer_members(),
        ]
    )
    with temporary:
        original = runtime_image._MAX_LAYER_DECOMPRESSED_BYTES
        runtime_image._MAX_LAYER_DECOMPRESSED_BYTES = (
            tarfile.RECORDSIZE + tarfile.BLOCKSIZE
        )
        try:
            expect_code(
                "runtime_image_archive_layout_invalid",
                builder._verify_archive_payload,
                archive_path,
                context,
            )
        finally:
            runtime_image._MAX_LAYER_DECOMPRESSED_BYTES = original

    temporary, archive_path, context = staged([payload_layer_members()])
    with temporary:
        original = runtime_image._MAX_IMAGE_LAYERS
        runtime_image._MAX_IMAGE_LAYERS = 0
        try:
            expect_code(
                "runtime_image_archive_layout_invalid",
                builder._verify_archive_payload,
                archive_path,
                context,
            )
        finally:
            runtime_image._MAX_IMAGE_LAYERS = original

    temporary, archive_path, context = staged([payload_layer_members()])
    with temporary:
        builder._deadline = time.monotonic() - 1
        expect_code(
            "runtime_image_timeout",
            builder._verify_archive_payload,
            archive_path,
            context,
        )
        builder._deadline = time.monotonic() + 3600
        cancelled = threading.Event()
        cancelled.set()
        builder._cancelled = cancelled
        try:
            expect_code(
                "runtime_image_cancelled",
                builder._verify_archive_payload,
                archive_path,
                context,
            )
        finally:
            builder._cancelled = None


@contract_case("payloadVerificationContractRotatesFullAndBootIdentity")
def payload_verification_contract_rotates_full_and_boot_identity() -> None:
    record = compute_fixture()
    original = runtime_image._PAYLOAD_VERIFICATION_CONTRACT
    runtime_image._PAYLOAD_VERIFICATION_CONTRACT = "layer-replay/v0-test"
    try:
        migrated = compute_fixture()
    finally:
        runtime_image._PAYLOAD_VERIFICATION_CONTRACT = original
    require(
        migrated["inputSha256"] != record["inputSha256"],
        "payload contract change must rotate input identity",
    )
    require(
        migrated["bootInputSha256"] != record["bootInputSha256"],
        "payload contract change must rotate boot identity",
    )


def main() -> int:
    completed: list[str] = []
    started = time.monotonic()
    for name, case in CASES.items():
        case()
        completed.append(name)
    print(
        json.dumps(
            {
                "ok": True,
                "schema": "dev.xenoid.runtime-image-contract/v1",
                "checks": completed,
                "durationMs": int((time.monotonic() - started) * 1000),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
