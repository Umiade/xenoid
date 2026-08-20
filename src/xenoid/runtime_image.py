from __future__ import annotations

import ast
import contextlib
import dataclasses
import fcntl
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import stat
import tempfile
import time
import xml.etree.ElementTree as ET
import zlib
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any
from threading import Event

from .artifacts import ArtifactBuilder, ArtifactError, ArtifactSnapshot
from .process import run_bounded


RUNTIME_IMAGE_SCHEMA = "dev.xenoid.runtime-image/v1"
RUNTIME_INPUT_SCHEMA = "dev.xenoid.runtime-image-input/v1"
RUNTIME_CONTEXT_SCHEMA = "dev.xenoid.runtime-context/v1"
RUNTIME_SCHEMA_LABEL = "dev.xenoid.runtime_schema"
RUNTIME_INPUT_LABEL = "dev.xenoid.runtime_input_sha256"
RUNTIME_BOOT_INPUT_LABEL = "dev.xenoid.runtime_boot_input_sha256"
RUNTIME_BASE_IMAGE_LABEL = "dev.xenoid.runtime_base_image_id"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MODE_RE = re.compile(r"^0[0-7]{3}$")
_BUILDX_VERSION_RE = re.compile(
    r"(?:^|\s)v?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?(?:\s|$)"
)
_SAFE_REPOSITORY_COMPONENT_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_MAX_RECORD_BYTES = 4 * 1024 * 1024
_MAX_IMAGE_ARCHIVE_BYTES = 16 * 1024 * 1024 * 1024
_COPY_CHUNK = 1024 * 1024
_APKTOOL_NAME = "APKTOOL_SHA256"
_CONTEXT_INPUT_PATHS = (
    "scripts/make-runtime-context.sh",
    "scripts/smoke-hardware-features.py",
    "scripts/patch-runtime-props.py",
    "scripts/patch-app-process-needed.py",
    "scripts/patch-runtime-libselinux.py",
    "scripts/patch-services-runtime.py",
    "scripts/patch-telephony-legacy-lte-band.py",
    "scripts/xenoid_archive.py",
    "examples/fingerprints/pixel-raven-android13.json",
)
_DAEMON_DESTINATION = "/system/priv-app/XenoidDaemon/XenoidDaemon.apk"
_RECORD_FIELDS = frozenset(
    {
        "schema",
        "inputSha256",
        "bootInputSha256",
        "derivedTag",
        "imageId",
        "architecture",
        "baseImageId",
        "baseRepoDigests",
        "artifactManifestSha256",
        "artifactTuples",
        "contextInputs",
        "googleInputs",
        "toolInputs",
        "builderInputs",
        "daemonSeedContract",
        "labels",
        "contextManifestSha256",
    }
)


class RuntimeImageError(RuntimeError):
    """A stable runtime-image failure with no private diagnostic payload."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclasses.dataclass(frozen=True, slots=True)
class _RunResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class _BaseImage:
    reference: str
    image_id: str
    repo_digests: tuple[str, ...]
    architecture: str


@dataclasses.dataclass(frozen=True, slots=True)
class _PreparedInput:
    public: Mapping[str, Any]
    snapshot: ArtifactSnapshot
    base: _BaseImage


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _require_sha256(value: Any, code: str = "runtime_image_input_invalid") -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise RuntimeImageError(code)
    return value


def _normalize_daemon_seed_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeImageError("runtime_image_daemon_seed_invalid")
    try:
        package_name = str(value["packageName"])
        shared_user = value.get("sharedUserId")
        destination = str(value["systemDestination"])
        version_code = int(value["versionCode"])
        apk_sha256 = _require_sha256(value["apkSha256"], "runtime_image_daemon_seed_invalid")
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeImageError("runtime_image_daemon_seed_invalid") from exc
    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+", package_name):
        raise RuntimeImageError("runtime_image_daemon_seed_invalid")
    if shared_user is not None:
        shared_user = str(shared_user)
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+", shared_user):
            raise RuntimeImageError("runtime_image_daemon_seed_invalid")
    if destination != _DAEMON_DESTINATION or version_code < 0:
        raise RuntimeImageError("runtime_image_daemon_seed_invalid")

    raw_lineage = value.get("signingLineage")
    if raw_lineage is None:
        lineage_sha = _require_sha256(value.get("signingLineageSha256"), "runtime_image_daemon_seed_invalid")
        lineage: list[str] | None = None
    else:
        if not isinstance(raw_lineage, Sequence) or isinstance(raw_lineage, (str, bytes)):
            raise RuntimeImageError("runtime_image_daemon_seed_invalid")
        lineage = sorted({_require_sha256(item, "runtime_image_daemon_seed_invalid") for item in raw_lineage})
        if not lineage:
            raise RuntimeImageError("runtime_image_daemon_seed_invalid")
        lineage_sha = _digest(lineage)
        supplied = value.get("signingLineageSha256")
        if supplied is not None and supplied != lineage_sha:
            raise RuntimeImageError("runtime_image_daemon_seed_invalid")

    permissions_value = value.get("privilegedPermissions", ())
    if not isinstance(permissions_value, Sequence) or isinstance(permissions_value, (str, bytes)):
        raise RuntimeImageError("runtime_image_daemon_seed_invalid")
    permissions = sorted({str(item) for item in permissions_value})
    if any(re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+", item) is None for item in permissions):
        raise RuntimeImageError("runtime_image_daemon_seed_invalid")
    allowlist_sha = _digest(permissions)
    supplied_allowlist = value.get("privilegedAllowlistSha256")
    if supplied_allowlist is not None and supplied_allowlist != allowlist_sha:
        raise RuntimeImageError("runtime_image_daemon_seed_invalid")

    boot_contract = {
        "packageName": package_name,
        "sharedUserId": shared_user,
        "systemDestination": destination,
        "signingLineageSha256": lineage_sha,
        "privilegedAllowlistSha256": allowlist_sha,
        "privilegedPermissions": permissions,
    }
    contract_sha = _digest(boot_contract)
    supplied_contract = value.get("contractSha256") or value.get("daemonSeedContractSha256")
    if supplied_contract is not None and supplied_contract != contract_sha:
        raise RuntimeImageError("runtime_image_daemon_seed_invalid")
    result: dict[str, Any] = dict(boot_contract)
    result.update(
        {
            "contractSha256": contract_sha,
            "apkSha256": apk_sha256,
            "versionCode": version_code,
        }
    )
    if lineage is not None:
        result["signingLineage"] = lineage
    return result


def _normalize_artifact_tuples(value: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in value:
        if not isinstance(raw, Mapping):
            raise RuntimeImageError("runtime_image_artifact_snapshot_invalid")
        try:
            target = str(raw["target"])
            input_sha = _require_sha256(raw["inputSha256"], "runtime_image_artifact_snapshot_invalid")
            tool_sha = _require_sha256(raw["toolSha256"], "runtime_image_artifact_snapshot_invalid")
            raw_outputs = raw["outputs"]
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeImageError("runtime_image_artifact_snapshot_invalid") from exc
        if not target or target in seen or not isinstance(raw_outputs, Sequence):
            raise RuntimeImageError("runtime_image_artifact_snapshot_invalid")
        seen.add(target)
        outputs: list[dict[str, Any]] = []
        output_names: set[str] = set()
        for output in raw_outputs:
            if not isinstance(output, Mapping):
                raise RuntimeImageError("runtime_image_artifact_snapshot_invalid")
            try:
                path = str(output["path"])
                mode_value = output["mode"]
                mode = f"0{mode_value:03o}" if isinstance(mode_value, int) else str(mode_value)
                size = int(output["size"])
                sha256 = _require_sha256(output["sha256"], "runtime_image_artifact_snapshot_invalid")
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeImageError("runtime_image_artifact_snapshot_invalid") from exc
            if (
                not path
                or PurePosixPath(path).is_absolute()
                or ".." in PurePosixPath(path).parts
                or path in output_names
                or _MODE_RE.fullmatch(mode) is None
                or size < 0
            ):
                raise RuntimeImageError("runtime_image_artifact_snapshot_invalid")
            output_names.add(path)
            outputs.append({"path": path, "mode": mode, "size": size, "sha256": sha256})
        outputs.sort(key=lambda item: item["path"].encode("utf-8"))
        normalized.append(
            {
                "target": target,
                "inputSha256": input_sha,
                "toolSha256": tool_sha,
                "outputs": outputs,
            }
        )
    normalized.sort(key=lambda item: item["target"].encode("utf-8"))
    return normalized


def _normalize_digest_mapping(value: Mapping[str, Any], code: str = "runtime_image_input_invalid") -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeImageError(code)
    # Values are deliberately restricted to canonical, path-free public identity data.
    def normalize(item: Any) -> Any:
        if item is None or isinstance(item, (bool, int)):
            return item
        if isinstance(item, str):
            if len(item.encode("utf-8")) > 4096 or "\x00" in item:
                raise RuntimeImageError(code)
            return item
        if isinstance(item, Mapping):
            return {str(key): normalize(item[key]) for key in sorted(item, key=lambda key: str(key).encode("utf-8"))}
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            return [normalize(element) for element in item]
        raise RuntimeImageError(code)

    return normalize(value)


def compute_input_record(
    *,
    base_image_id: str,
    artifact_tuples: Sequence[Mapping[str, Any]],
    context_inputs: Mapping[str, Any],
    google_inputs: Mapping[str, Any],
    tool_inputs: Mapping[str, Any],
    builder_inputs: Mapping[str, Any],
    daemon_seed_contract: Mapping[str, Any],
) -> dict[str, Any]:
    """Purely compute canonical full and boot runtime-image identities.

    The boot projection replaces the complete daemon artifact tuple with the
    integration seed contract. Consequently ordinary daemon APK/version/source
    changes affect the full identity but not boot compatibility.
    """

    if _IMAGE_ID_RE.fullmatch(base_image_id) is None:
        raise RuntimeImageError("runtime_image_base_identity_invalid")
    artifacts = _normalize_artifact_tuples(artifact_tuples)
    context = _normalize_digest_mapping(context_inputs)
    google = _normalize_digest_mapping(google_inputs)
    tools = _normalize_digest_mapping(tool_inputs)
    builder = _normalize_digest_mapping(builder_inputs)
    daemon = _normalize_daemon_seed_contract(daemon_seed_contract)
    if not any(item["target"] == "daemon" for item in artifacts):
        raise RuntimeImageError("runtime_image_daemon_seed_invalid")

    full_payload = {
        "schema": RUNTIME_INPUT_SCHEMA,
        "baseImageId": base_image_id,
        "artifactTuples": artifacts,
        "contextInputs": context,
        "googleInputs": google,
        "toolInputs": tools,
        "builderInputs": builder,
        "daemonSeedContract": daemon,
    }
    boot_artifacts: list[dict[str, Any]] = []
    for item in artifacts:
        if item["target"] == "daemon":
            boot_artifacts.append(
                {
                    "target": "daemon",
                    "daemonSeedContractSha256": daemon["contractSha256"],
                }
            )
        else:
            boot_artifacts.append(item)
    boot_daemon = {
        key: daemon[key]
        for key in (
            "packageName",
            "sharedUserId",
            "systemDestination",
            "signingLineageSha256",
            "privilegedAllowlistSha256",
            "privilegedPermissions",
            "contractSha256",
        )
    }
    boot_payload = {
        "schema": RUNTIME_INPUT_SCHEMA,
        "baseImageId": base_image_id,
        "artifactTuples": boot_artifacts,
        "contextInputs": context,
        "googleInputs": google,
        "toolInputs": tools,
        "builderInputs": builder,
        "daemonSeedContract": boot_daemon,
    }
    return {
        "schema": RUNTIME_INPUT_SCHEMA,
        "inputSha256": _digest(full_payload),
        "bootInputSha256": _digest(boot_payload),
        "baseImageId": base_image_id,
        "artifactTuples": artifacts,
        "contextInputs": context,
        "googleInputs": google,
        "toolInputs": tools,
        "builderInputs": builder,
        "daemonSeedContract": daemon,
    }


def _repository_from_configured_tag(configured_tag: str) -> str:
    if not isinstance(configured_tag, str) or not configured_tag or len(configured_tag) > 255:
        raise RuntimeImageError("runtime_image_tag_invalid")
    if configured_tag != configured_tag.strip() or "@" in configured_tag or any(ord(char) < 33 for char in configured_tag):
        raise RuntimeImageError("runtime_image_tag_invalid")
    last_slash = configured_tag.rfind("/")
    last_colon = configured_tag.rfind(":")
    repository = configured_tag[:last_colon] if last_colon > last_slash else configured_tag
    if not repository or repository.startswith("/") or repository.endswith("/") or "//" in repository:
        raise RuntimeImageError("runtime_image_tag_invalid")
    components = repository.split("/")
    for index, component in enumerate(components):
        if not component:
            raise RuntimeImageError("runtime_image_tag_invalid")
        if index == 0 and (":" in component or component == "localhost"):
            host, separator, port = component.rpartition(":")
            if separator:
                if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
                    raise RuntimeImageError("runtime_image_tag_invalid")
                host_parts = host.split(".")
            else:
                host_parts = component.split(".")
            if any(_SAFE_REPOSITORY_COMPONENT_RE.fullmatch(part) is None for part in host_parts):
                raise RuntimeImageError("runtime_image_tag_invalid")
        elif _SAFE_REPOSITORY_COMPONENT_RE.fullmatch(component) is None:
            raise RuntimeImageError("runtime_image_tag_invalid")
    return repository


def derive_tag(configured_tag: str, input_sha256: str) -> str:
    return f"{_repository_from_configured_tag(configured_tag)}:xenoid-{_require_sha256(input_sha256)[:32]}"


def _validate_repo_digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or value.count("@") != 1:
        raise RuntimeImageError(code)
    repository, digest = value.rsplit("@sha256:", 1)
    if not repository or _SHA256_RE.fullmatch(digest) is None:
        raise RuntimeImageError(code)
    try:
        if _repository_from_configured_tag(repository) != repository:
            raise RuntimeImageError(code)
    except RuntimeImageError as exc:
        raise RuntimeImageError(code) from exc
    return value


def validate_record(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _RECORD_FIELDS or value.get("schema") != RUNTIME_IMAGE_SCHEMA:
        raise RuntimeImageError("runtime_image_record_invalid")
    result = dict(value)
    input_sha = _require_sha256(result["inputSha256"], "runtime_image_record_invalid")
    _require_sha256(result["bootInputSha256"], "runtime_image_record_invalid")
    if result["derivedTag"] != derive_tag(str(result["derivedTag"]), input_sha):
        # derive_tag accepts a derived tag as namespace input and reproduces it.
        raise RuntimeImageError("runtime_image_record_invalid")
    if _IMAGE_ID_RE.fullmatch(str(result["imageId"])) is None or _IMAGE_ID_RE.fullmatch(str(result["baseImageId"])) is None:
        raise RuntimeImageError("runtime_image_record_invalid")
    if result["architecture"] != "arm64":
        raise RuntimeImageError("runtime_image_record_invalid")
    repo_digests = result["baseRepoDigests"]
    if (
        not isinstance(repo_digests, list)
        or repo_digests != sorted(set(repo_digests))
        or any(_validate_repo_digest(item, "runtime_image_record_invalid") != item for item in repo_digests)
    ):
        raise RuntimeImageError("runtime_image_record_invalid")
    _require_sha256(result["artifactManifestSha256"], "runtime_image_record_invalid")
    _normalize_artifact_tuples(result["artifactTuples"])
    _normalize_digest_mapping(result["contextInputs"], "runtime_image_record_invalid")
    _normalize_digest_mapping(result["googleInputs"], "runtime_image_record_invalid")
    _normalize_digest_mapping(result["toolInputs"], "runtime_image_record_invalid")
    _normalize_digest_mapping(result["builderInputs"], "runtime_image_record_invalid")
    _normalize_daemon_seed_contract(result["daemonSeedContract"])
    labels = result["labels"]
    if not isinstance(labels, Mapping) or labels != _expected_labels(input_sha, result["bootInputSha256"], result["baseImageId"]):
        raise RuntimeImageError("runtime_image_record_invalid")
    context_manifest = result["contextManifestSha256"]
    if context_manifest is not None:
        _require_sha256(context_manifest, "runtime_image_record_invalid")
    return result


def _expected_labels(input_sha: str, boot_sha: str, base_id: str) -> dict[str, str]:
    return {
        RUNTIME_SCHEMA_LABEL: "1",
        RUNTIME_INPUT_LABEL: input_sha,
        RUNTIME_BOOT_INPUT_LABEL: boot_sha,
        RUNTIME_BASE_IMAGE_LABEL: base_id,
    }


class RuntimeImageBuilder:
    def __init__(
        self,
        project_root: str | os.PathLike[str],
        docker_argv: Sequence[str],
        docker_env: Mapping[str, str],
        *,
        artifact_builder: ArtifactBuilder | None = None,
        runner: Callable[..., Any] | None = None,
        engine_lock: Any = None,
    ) -> None:
        try:
            root = Path(project_root).expanduser().resolve(strict=True)
            root_info = root.stat()
        except (OSError, RuntimeError) as exc:
            raise ValueError("runtime_image_project_root_invalid") from exc
        if not stat.S_ISDIR(root_info.st_mode):
            raise ValueError("runtime_image_project_root_invalid")
        argv = tuple(str(item) for item in docker_argv)
        if not argv or any(not item or "\x00" in item for item in argv):
            raise ValueError("runtime_image_docker_argv_invalid")
        self.project_root = root
        self.docker_argv = argv
        self.docker_env = {str(key): str(value) for key, value in docker_env.items()}
        self.artifact_builder = artifact_builder or ArtifactBuilder(root)
        self._runner = runner
        self._engine_lock = engine_lock
        self._cache_root = root / ".xenoid" / "cache" / "runtime-images"
        self._local_lock_root = root / ".xenoid" / "locks" / "runtime-images"
        self._ensure_private_directory(self._cache_root)
        self._ensure_private_directory(self._local_lock_root)
        self._deadline = time.monotonic() + 3600.0
        self._cancelled: Event | Callable[[], bool] | None = None

    def input_record(
        self,
        base_image: str,
        google_spec: Any = None,
        *,
        configured_tag: str | None = None,
    ) -> dict[str, Any]:
        if isinstance(google_spec, str) and configured_tag is None:
            configured_tag = google_spec
            google_spec = None
        prepared = self._prepare_input(base_image, google_spec)
        result = dict(prepared.public)
        result["baseRepoDigests"] = list(prepared.base.repo_digests)
        if configured_tag is not None:
            result["derivedTag"] = derive_tag(configured_tag, result["inputSha256"])
        return result

    def lookup(self, input_sha256: str) -> dict[str, Any] | None:
        input_sha = _require_sha256(input_sha256, "runtime_image_record_invalid")
        path = self._cache_root / f"{input_sha}.json"
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise RuntimeImageError("runtime_image_record_invalid") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > _MAX_RECORD_BYTES
        ):
            raise RuntimeImageError("runtime_image_record_invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
            try:
                payload = _read_bounded(descriptor, _MAX_RECORD_BYTES)
            finally:
                os.close(descriptor)
            value = json.loads(payload)
        except (OSError, ValueError, UnicodeError) as exc:
            raise RuntimeImageError("runtime_image_record_invalid") from exc
        record = validate_record(value)
        if record["inputSha256"] != input_sha:
            raise RuntimeImageError("runtime_image_record_invalid")
        return record

    def materialize_context(
        self,
        base_image: str,
        google_spec: Any = None,
        destination: str | os.PathLike[str] | None = None,
    ) -> dict[str, Any]:
        prepared = self._prepare_input(base_image, google_spec)
        if destination is None:
            owner_root = Path(tempfile.mkdtemp(prefix="context-", dir=self._cache_root))
            os.chmod(owner_root, 0o700)
            context_path = owner_root / "runtime-context"
        else:
            context_path = Path(destination).expanduser()
            if not context_path.is_absolute():
                context_path = self.project_root / context_path
            if context_path.exists() or context_path.is_symlink():
                raise RuntimeImageError("runtime_context_destination_exists")
            context_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        input_sha = prepared.public["inputSha256"]
        base_tag = self._base_tag(input_sha)
        lock_name = self._runtime_input_lock_name(input_sha)
        with self._acquire_engine_lock(lock_name):
            tagged = False
            try:
                self._docker_checked(
                    ("image", "tag", prepared.base.image_id, base_tag),
                    "runtime_image_base_tag_failed",
                )
                tagged = True
                manifest_sha = self._generate_context(
                    prepared,
                    base_tag,
                    context_path,
                    google_spec,
                )
                current_base = self._resolve_base(base_image)
                if current_base.image_id != prepared.base.image_id:
                    raise RuntimeImageError("base_image_changed_during_build")
                return {
                    "schema": RUNTIME_CONTEXT_SCHEMA,
                    "inputSha256": input_sha,
                    "bootInputSha256": prepared.public["bootInputSha256"],
                    "baseImageId": prepared.base.image_id,
                    "contextManifestSha256": manifest_sha,
                    "contextPath": str(context_path),
                }
            except Exception:
                self._remove_tree_if_owned(context_path)
                raise
            finally:
                if tagged:
                    self._docker_remove_tag(base_tag)

    def ensure(
        self,
        base_image: str,
        configured_tag: str,
        google_spec: Any = None,
        *,
        deadline: float | None = None,
        cancelled: Event | Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        self._deadline = deadline if deadline is not None else time.monotonic() + 3600.0
        self._cancelled = cancelled
        prepared = self._prepare_input(base_image, google_spec)
        input_sha = prepared.public["inputSha256"]
        boot_sha = prepared.public["bootInputSha256"]
        derived_tag = derive_tag(configured_tag, input_sha)
        labels = _expected_labels(input_sha, boot_sha, prepared.base.image_id)
        lock_name = self._runtime_input_lock_name(input_sha)
        with self._acquire_engine_lock(lock_name):
            existing = self._inspect_image(derived_tag, required=False)
            if existing is not None:
                self._verify_published_image(existing, labels, collision=True)
                cached = self.lookup(input_sha)
                if cached is None or cached["imageId"] != existing["Id"]:
                    record = self._record_value(
                        prepared,
                        derived_tag,
                        existing["Id"],
                        labels,
                        context_manifest_sha256=None,
                    )
                    self._publish_record(record)
                return {
                    "schema": RUNTIME_IMAGE_SCHEMA,
                    "inputSha256": input_sha,
                    "bootInputSha256": boot_sha,
                    "derivedTag": derived_tag,
                    "imageId": existing["Id"],
                    "reused": True,
                }

            work_root = Path(tempfile.mkdtemp(prefix="build-", dir=self._cache_root))
            os.chmod(work_root, 0o700)
            context_path = work_root / "context"
            archive_path = work_root / "image.tar"
            base_tag = self._base_tag(input_sha)
            temporary_tag = self._temporary_tag("build", input_sha)
            base_tagged = False
            built = False
            published = False
            built_id: str | None = None
            try:
                self._docker_checked(("image", "tag", prepared.base.image_id, base_tag), "runtime_image_base_tag_failed")
                base_tagged = True
                context_manifest_sha = self._generate_context(prepared, base_tag, context_path, google_spec)
                build_command: list[str] = [
                    "buildx",
                    "build",
                    "--platform=linux/arm64",
                    "--provenance=false",
                    "--sbom=false",
                    "--no-cache",
                    "--build-arg",
                    "SOURCE_DATE_EPOCH=0",
                ]
                for key, value in sorted(labels.items()):
                    build_command.extend(("--label", f"{key}={value}"))
                build_command.extend(
                    (
                        "--output",
                        "type=docker,dest=image.tar,rewrite-timestamp=true",
                        "--tag",
                        temporary_tag,
                        str(context_path),
                    )
                )
                self._docker_checked(
                    tuple(build_command),
                    "runtime_image_build_failed",
                    cwd=work_root,
                )
                self._validate_image_archive(archive_path)
                self._docker_checked(
                    ("image", "load", "--input", str(archive_path)),
                    "runtime_image_load_failed",
                )
                built = True
                built_image = self._inspect_image(temporary_tag, required=True)
                self._verify_published_image(built_image, labels, collision=False)
                built_id = built_image["Id"]

                current_base = self._resolve_base(base_image)
                if current_base.image_id != prepared.base.image_id:
                    raise RuntimeImageError("base_image_changed_during_build")
                current = self._prepare_input(base_image, google_spec)
                if current.public["inputSha256"] != input_sha or current.public["bootInputSha256"] != boot_sha:
                    raise RuntimeImageError("runtime_image_input_changed")
                occupied = self._inspect_image(derived_tag, required=False)
                if occupied is not None:
                    raise RuntimeImageError("runtime_image_cache_conflict")

                self._docker_checked(("image", "tag", temporary_tag, derived_tag), "runtime_image_publish_failed")
                published = True
                final_image = self._inspect_image(derived_tag, required=True)
                self._verify_published_image(final_image, labels, collision=False)
                if final_image["Id"] != built_id:
                    raise RuntimeImageError("runtime_image_publish_failed")
                record = self._record_value(
                    prepared,
                    derived_tag,
                    built_id,
                    labels,
                    context_manifest_sha256=context_manifest_sha,
                )
                self._publish_record(record)
                return {
                    "schema": RUNTIME_IMAGE_SCHEMA,
                    "inputSha256": input_sha,
                    "bootInputSha256": boot_sha,
                    "derivedTag": derived_tag,
                    "imageId": built_id,
                    "reused": False,
                }
            except Exception:
                if published and built_id is not None:
                    self._remove_tag_if_image(derived_tag, built_id)
                raise
            finally:
                if built:
                    self._docker_remove_tag(temporary_tag)
                if base_tagged:
                    self._docker_remove_tag(base_tag)
                self._remove_tree_if_owned(work_root)

    def _prepare_input(self, base_image: str, google_spec: Any) -> _PreparedInput:
        base = self._resolve_base(base_image)
        try:
            snapshot = self.artifact_builder.snapshot("runtimeContext")
        except ArtifactError as exc:
            raise RuntimeImageError("runtime_image_artifact_snapshot_invalid") from exc
        if not isinstance(snapshot, ArtifactSnapshot):
            raise RuntimeImageError("runtime_image_artifact_snapshot_invalid")
        artifact_tuples = [
            {
                "target": record.target,
                "inputSha256": record.input_sha256,
                "toolSha256": record.tool_sha256,
                "outputs": [output.as_dict() for output in record.outputs],
            }
            for record in snapshot.records
        ]
        seed_contract = self._daemon_seed_contract(snapshot, artifact_tuples)
        context_inputs = self._context_inputs()
        google_inputs = self._google_inputs(google_spec)
        tool_inputs, builder_inputs = self._tool_and_builder_inputs()
        computed = compute_input_record(
            base_image_id=base.image_id,
            artifact_tuples=artifact_tuples,
            context_inputs=context_inputs,
            google_inputs=google_inputs,
            tool_inputs=tool_inputs,
            builder_inputs=builder_inputs,
            daemon_seed_contract=seed_contract,
        )
        computed["artifactManifestSha256"] = _require_sha256(
            snapshot.manifest_sha256, "runtime_image_artifact_snapshot_invalid"
        )
        return _PreparedInput(computed, snapshot, base)

    def _resolve_base(self, reference: str) -> _BaseImage:
        if not isinstance(reference, str) or not reference or reference != reference.strip() or "\x00" in reference:
            raise RuntimeImageError("runtime_image_base_reference_invalid")
        inspected = self._inspect_image(reference, required=True)
        image_id = str(inspected.get("Id", ""))
        architecture = str(inspected.get("Architecture", ""))
        if _IMAGE_ID_RE.fullmatch(image_id) is None:
            raise RuntimeImageError("runtime_image_base_identity_invalid")
        if architecture != "arm64":
            raise RuntimeImageError("runtime_image_base_architecture_invalid")
        raw_repo_digests = inspected.get("RepoDigests") or []
        if not isinstance(raw_repo_digests, list):
            raise RuntimeImageError("runtime_image_base_identity_invalid")
        repo_digests = tuple(
            sorted(
                {
                    _validate_repo_digest(item, "runtime_image_base_identity_invalid")
                    for item in raw_repo_digests
                }
            )
        )
        if "@sha256:" in reference:
            repository, digest = reference.rsplit("@sha256:", 1)
            if not repository or _SHA256_RE.fullmatch(digest) is None:
                raise RuntimeImageError("runtime_image_base_reference_invalid")
            expected = f"{repository}@sha256:{digest}"
            if expected not in repo_digests:
                raise RuntimeImageError("runtime_image_base_digest_mismatch")
        elif "@" in reference:
            raise RuntimeImageError("runtime_image_base_reference_invalid")
        return _BaseImage(reference, image_id, repo_digests, architecture)

    def _inspect_image(self, reference: str, *, required: bool) -> dict[str, Any] | None:
        result = self._run(self.docker_argv + ("image", "inspect", reference), env=self._command_env(), cwd=self.project_root)
        if result.returncode != 0:
            if required:
                raise RuntimeImageError("runtime_image_base_unavailable")
            return None
        try:
            payload = json.loads(result.stdout)
        except (ValueError, UnicodeError) as exc:
            raise RuntimeImageError("runtime_image_inspect_invalid") from exc
        if isinstance(payload, list):
            if len(payload) != 1 or not isinstance(payload[0], Mapping):
                raise RuntimeImageError("runtime_image_inspect_invalid")
            payload = payload[0]
        if not isinstance(payload, Mapping):
            raise RuntimeImageError("runtime_image_inspect_invalid")
        return dict(payload)

    def _verify_published_image(self, image: Mapping[str, Any], labels: Mapping[str, str], *, collision: bool) -> None:
        code = "runtime_image_cache_conflict" if collision else "runtime_image_verification_failed"
        if _IMAGE_ID_RE.fullmatch(str(image.get("Id", ""))) is None or image.get("Architecture") != "arm64":
            raise RuntimeImageError(code)
        config = image.get("Config")
        rootfs = image.get("RootFS")
        if not isinstance(config, Mapping) or not isinstance(rootfs, Mapping):
            raise RuntimeImageError(code)
        actual_labels = config.get("Labels")
        if not isinstance(actual_labels, Mapping) or any(actual_labels.get(key) != value for key, value in labels.items()):
            raise RuntimeImageError(code)
        layers = rootfs.get("Layers")
        if not isinstance(layers, list) or not layers or any(_IMAGE_ID_RE.fullmatch(str(layer)) is None for layer in layers):
            raise RuntimeImageError(code)

    def _context_inputs(self) -> dict[str, Any]:
        files: list[dict[str, Any]] = []
        for relative in _CONTEXT_INPUT_PATHS:
            path = self.project_root / relative
            files.append({"path": relative, "sha256": _hash_regular_file(path)})
        runtime_root = self.project_root / "runtime" / "redroid"
        try:
            root_info = runtime_root.lstat()
        except OSError as exc:
            raise RuntimeImageError("runtime_image_input_unavailable") from exc
        if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
            raise RuntimeImageError("runtime_image_input_unavailable")
        for current, dirnames, filenames in os.walk(runtime_root, topdown=True, followlinks=False):
            base = Path(current)
            dirnames.sort(key=lambda item: item.encode("utf-8"))
            filenames.sort(key=lambda item: item.encode("utf-8"))
            for dirname in dirnames:
                info = (base / dirname).lstat()
                if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                    raise RuntimeImageError("runtime_image_input_unavailable")
            for filename in filenames:
                path = base / filename
                relative = path.relative_to(self.project_root).as_posix()
                files.append({"path": relative, "sha256": _hash_regular_file(path)})
        files.sort(key=lambda item: item["path"].encode("utf-8"))
        return {"files": files}

    def _google_inputs(self, google_spec: Any) -> dict[str, Any]:
        if google_spec is None:
            return {
                "provider": "none",
                "release": "none",
                "specSha256": _digest({"provider": "none", "release": "none"}),
                "dataCompatibilitySha256": _digest({"provider": "none", "release": "none"}),
                "payloadSha256": _digest([]),
            }
        try:
            from .google_services import quick_validate_assets

            quick_validate_assets(self.project_root, google_spec)
            provider = str(google_spec.provider)
            release = str(google_spec.release)
            spec_sha = _require_sha256(google_spec.fingerprint, "runtime_image_google_input_invalid")
            data_sha = _require_sha256(
                google_spec.data_compatibility_fingerprint, "runtime_image_google_input_invalid"
            )
            archive_sha = _require_sha256(google_spec.archive["sha256"], "runtime_image_google_input_invalid")
            certificate_sha = _require_sha256(
                google_spec.archive["certificate"]["sha256"], "runtime_image_google_input_invalid"
            )
            metadata_sha = _require_sha256(google_spec.metadata_sha256, "runtime_image_google_input_invalid")
            payload_sha = _digest(
                [
                    {
                        "archivePath": str(item["archivePath"]),
                        "runtimePath": str(item["runtimePath"]),
                        "sha256": _require_sha256(item["sha256"], "runtime_image_google_input_invalid"),
                        "size": int(item["size"]),
                    }
                    for item in sorted(google_spec.members, key=lambda entry: str(entry["runtimePath"]).encode("utf-8"))
                ]
            )
        except RuntimeImageError:
            raise
        except Exception as exc:
            raise RuntimeImageError("runtime_image_google_input_invalid") from exc
        return {
            "provider": provider,
            "release": release,
            "specSha256": spec_sha,
            "dataCompatibilitySha256": data_sha,
            "metadataSha256": metadata_sha,
            "archiveSha256": archive_sha,
            "certificateSha256": certificate_sha,
            "payloadSha256": payload_sha,
        }

    def _tool_and_builder_inputs(self) -> tuple[dict[str, Any], dict[str, Any]]:
        java_command = shutil.which("java")
        if java_command is None:
            raise RuntimeImageError("runtime_image_java_unavailable")
        java = self._run((java_command, "-version"), env=self._command_env(), cwd=self.project_root)
        if java.returncode != 0:
            raise RuntimeImageError("runtime_image_java_unavailable")
        docker = self._run(
            self.docker_argv + ("version", "--format", "{{json .}}"),
            env=self._command_env(),
            cwd=self.project_root,
        )
        if docker.returncode != 0:
            raise RuntimeImageError("runtime_image_builder_unavailable")
        buildx = self._run(self.docker_argv + ("buildx", "version"), env=self._command_env(), cwd=self.project_root)
        if buildx.returncode != 0:
            raise RuntimeImageError("runtime_image_builder_unavailable")
        buildx_text = (buildx.stdout + b"\n" + buildx.stderr).decode("utf-8", "replace")
        match = _BUILDX_VERSION_RE.search(buildx_text)
        if match is None or tuple(int(group) for group in match.groups()) < (0, 10, 0):
            raise RuntimeImageError("runtime_image_builder_unsupported")
        python_identity = {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "zlibVersion": zlib.ZLIB_VERSION,
            "zlibRuntimeVersion": zlib.ZLIB_RUNTIME_VERSION,
        }
        tools = {
            "apktoolSha256": self._pinned_apktool_digest(),
            "pythonIdentitySha256": _digest(python_identity),
            "javaIdentitySha256": hashlib.sha256(java.stdout + b"\x00" + java.stderr).hexdigest(),
        }
        builder = {
            "dockerIdentitySha256": hashlib.sha256(docker.stdout + b"\x00" + docker.stderr).hexdigest(),
            "buildxIdentitySha256": hashlib.sha256(buildx.stdout + b"\x00" + buildx.stderr).hexdigest(),
            "platform": "linux/arm64",
            "sourceDateEpoch": 0,
            "provenance": False,
            "exporter": "docker-archive",
            "rewriteTimestamp": True,
        }
        return tools, builder

    def _pinned_apktool_digest(self) -> str:
        path = self.project_root / "scripts" / "xenoid_archive.py"
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename="scripts/xenoid_archive.py")
        except (OSError, SyntaxError, UnicodeError) as exc:
            raise RuntimeImageError("runtime_image_tool_identity_invalid") from exc
        values: list[str] = []
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == _APKTOOL_NAME for target in targets):
                value = node.value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    values.append(value.value)
        if len(values) != 1:
            raise RuntimeImageError("runtime_image_tool_identity_invalid")
        return _require_sha256(values[0], "runtime_image_tool_identity_invalid")

    def _daemon_seed_contract(
        self, snapshot: ArtifactSnapshot, artifact_tuples: Sequence[Mapping[str, Any]]
    ) -> dict[str, Any]:
        provider = getattr(self.artifact_builder, "daemon_seed_contract", None)
        if callable(provider):
            return _normalize_daemon_seed_contract(provider(snapshot))
        daemon_tuple = next((item for item in artifact_tuples if item["target"] == "daemon"), None)
        if daemon_tuple is None:
            raise RuntimeImageError("runtime_image_daemon_seed_invalid")
        apk_outputs = [item for item in daemon_tuple["outputs"] if str(item["path"]).endswith(".apk")]
        if len(apk_outputs) != 1:
            raise RuntimeImageError("runtime_image_daemon_seed_invalid")
        stage_root = Path(tempfile.mkdtemp(prefix="seed-", dir=self._cache_root))
        os.chmod(stage_root, 0o700)
        try:
            try:
                self.artifact_builder.stage(snapshot, stage_root)
            except ArtifactError as exc:
                raise RuntimeImageError("runtime_image_artifact_snapshot_invalid") from exc
            apk_path = stage_root / apk_outputs[0]["path"]
            lineage, package_name, shared_user, version_code = self._verified_apk_identity(apk_path)
        finally:
            self._remove_tree_if_owned(stage_root)

        allowlist_path = (
            self.project_root
            / "runtime"
            / "redroid"
            / "xenoid-cellular-overlay"
            / "system"
            / "etc"
            / "permissions"
            / "privapp-permissions-xenoid.xml"
        )
        try:
            allowlist_root = ET.parse(allowlist_path).getroot()
        except (OSError, ET.ParseError) as exc:
            raise RuntimeImageError("runtime_image_daemon_seed_invalid") from exc
        permissions: list[str] = []
        for element in allowlist_root.findall("privapp-permissions"):
            if element.attrib.get("package") == package_name:
                permissions.extend(
                    permission.attrib["name"]
                    for permission in element.findall("permission")
                    if "name" in permission.attrib
                )
        if not permissions:
            raise RuntimeImageError("runtime_image_daemon_seed_invalid")
        return _normalize_daemon_seed_contract(
            {
                "packageName": package_name,
                "sharedUserId": shared_user,
                "systemDestination": _DAEMON_DESTINATION,
                "signingLineage": lineage,
                "privilegedPermissions": permissions,
                "apkSha256": apk_outputs[0]["sha256"],
                "versionCode": version_code,
            }
        )

    def _verified_apk_identity(self, apk_path: Path) -> tuple[list[str], str, str | None, int]:
        tool_directory = self._android_build_tool_directory()
        apksigner = tool_directory / "apksigner"
        aapt2 = tool_directory / "aapt2"
        for tool in (apksigner, aapt2):
            try:
                info = tool.stat()
            except OSError as exc:
                raise RuntimeImageError("runtime_image_android_tools_unavailable") from exc
            if not stat.S_ISREG(info.st_mode) or not os.access(tool, os.X_OK):
                raise RuntimeImageError("runtime_image_android_tools_unavailable")
        signature = self._run(
            (str(apksigner), "verify", "--verbose", "--print-certs", str(apk_path)),
            env=self._command_env(),
            cwd=self.project_root,
        )
        if signature.returncode != 0:
            raise RuntimeImageError("runtime_image_daemon_seed_invalid")
        signature_text = (signature.stdout + b"\n" + signature.stderr).decode("utf-8", "replace")
        lineage = sorted(
            {
                match.group(1).lower()
                for match in re.finditer(
                    r"certificate SHA-256 digest:\s*([0-9a-fA-F]{64})", signature_text
                )
            }
        )
        if not lineage:
            raise RuntimeImageError("runtime_image_daemon_seed_invalid")
        manifest = self._run(
            (str(aapt2), "dump", "badging", str(apk_path)),
            env=self._command_env(),
            cwd=self.project_root,
        )
        if manifest.returncode != 0:
            raise RuntimeImageError("runtime_image_daemon_seed_invalid")
        manifest_text = manifest.stdout.decode("utf-8", "replace")
        package_line = re.search(r"(?m)^package:.*$", manifest_text)
        if package_line is None:
            raise RuntimeImageError("runtime_image_daemon_seed_invalid")
        package = re.search(r"(?:^|\s)name='([^']+)'", package_line.group(0))
        version = re.search(r"(?:^|\s)versionCode='(\d+)'", package_line.group(0))
        shared = re.search(r"(?:^|\s)sharedUserId='([^']+)'", package_line.group(0))
        if package is None or version is None:
            raise RuntimeImageError("runtime_image_daemon_seed_invalid")
        return (
            lineage,
            package.group(1),
            None if shared is None else shared.group(1),
            int(version.group(1)),
        )

    def _android_build_tool_directory(self) -> Path:
        roots = [os.environ.get("ANDROID_SDK_ROOT"), os.environ.get("ANDROID_HOME")]
        candidates: list[tuple[tuple[int, ...], Path]] = []
        for raw_root in roots:
            if not raw_root:
                continue
            build_tools = Path(raw_root) / "build-tools"
            try:
                directories = list(build_tools.iterdir())
            except OSError:
                continue
            for directory in directories:
                version = tuple(int(part) for part in re.findall(r"\d+", directory.name))
                if version:
                    candidates.append((version, directory))
        if not candidates:
            raise RuntimeImageError("runtime_image_android_tools_unavailable")
        candidates.sort(reverse=True)
        return candidates[0][1]


    def _generate_context(
        self,
        prepared: _PreparedInput,
        base_tag: str,
        destination: Path,
        google_spec: Any,
    ) -> str:
        stage_root = Path(tempfile.mkdtemp(prefix="artifacts-", dir=self._cache_root))
        os.chmod(stage_root, 0o700)
        google_handle: Any = None
        google_verifier: Callable[..., Any] | None = None
        try:
            try:
                self.artifact_builder.stage(prepared.snapshot, stage_root)
            except ArtifactError as exc:
                raise RuntimeImageError("runtime_image_artifact_snapshot_invalid") from exc
            environment = self._command_env()
            environment.update(
                {
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "SOURCE_DATE_EPOCH": "0",
                    "PYTHONHASHSEED": "0",
                    "XENOID_ARTIFACT_STAGE": str(stage_root),
                    "XENOID_DOCKER_ARGV_JSON": json.dumps(
                        list(self.docker_argv), separators=(",", ":"), ensure_ascii=True
                    ),
                }
            )
            if google_spec is not None:
                try:
                    from .google_services import _asset_paths, _stage_payload, cleanup_stage, verify_context_copy

                    zip_path, _, _ = _asset_paths(self.project_root, google_spec)
                    google_handle = _stage_payload(zip_path, google_spec)
                    google_verifier = verify_context_copy
                    environment.update(
                        {
                            "XENOID_GOOGLE_PAYLOAD": str(google_handle.tree),
                            "XENOID_GOOGLE_PROVIDER": str(google_spec.provider),
                            "XENOID_GOOGLE_RELEASE": str(google_spec.release),
                            "XENOID_GOOGLE_SPEC_SHA256": str(google_spec.fingerprint),
                            "XENOID_GOOGLE_DATA_COMPAT_SHA256": str(
                                google_spec.data_compatibility_fingerprint
                            ),
                        }
                    )
                except Exception as exc:
                    raise RuntimeImageError("runtime_image_google_input_invalid") from exc
            command = (str(self.project_root / "scripts" / "make-runtime-context.sh"), base_tag, str(destination))
            result = self._run(command, env=environment, cwd=self.project_root)
            if result.returncode != 0:
                raise RuntimeImageError("runtime_context_generation_failed")
            manifest_sha256 = self._verify_context(destination)
            if google_spec is not None:
                if google_handle is None or google_verifier is None:
                    raise RuntimeImageError("runtime_image_google_input_invalid")
                try:
                    google_verifier(destination, google_spec, google_handle)
                except Exception as exc:
                    raise RuntimeImageError("runtime_image_google_context_invalid") from exc
            return manifest_sha256
        finally:
            if google_handle is not None:
                try:
                    cleanup_stage(google_handle)
                except Exception as exc:
                    raise RuntimeImageError("runtime_image_google_cleanup_failed") from exc
            self._remove_tree_if_owned(stage_root)

    def _verify_context(self, root: Path) -> str:
        manifest_path = root / "context-manifest.json"
        try:
            root_info = root.lstat()
            manifest_info = manifest_path.lstat()
        except OSError as exc:
            raise RuntimeImageError("runtime_context_manifest_invalid") from exc
        if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
            raise RuntimeImageError("runtime_context_manifest_invalid")
        if (
            not stat.S_ISREG(manifest_info.st_mode)
            or stat.S_ISLNK(manifest_info.st_mode)
            or stat.S_IMODE(manifest_info.st_mode) != 0o644
            or manifest_info.st_mtime_ns != 0
        ):
            raise RuntimeImageError("runtime_context_manifest_invalid")
        try:
            payload = manifest_path.read_bytes()
            manifest = json.loads(payload)
        except (OSError, ValueError, UnicodeError) as exc:
            raise RuntimeImageError("runtime_context_manifest_invalid") from exc
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
        if payload != canonical or not isinstance(manifest, Mapping) or set(manifest) != {"schema", "entries"}:
            raise RuntimeImageError("runtime_context_manifest_invalid")
        if manifest["schema"] != RUNTIME_CONTEXT_SCHEMA or not isinstance(manifest["entries"], list):
            raise RuntimeImageError("runtime_context_manifest_invalid")
        entries = manifest["entries"]
        paths = [entry.get("path") for entry in entries if isinstance(entry, Mapping)]
        if len(paths) != len(entries) or paths != sorted(paths, key=lambda item: str(item).encode("utf-8")) or len(paths) != len(set(paths)):
            raise RuntimeImageError("runtime_context_manifest_invalid")
        declared: set[str] = set()
        for entry in entries:
            if not isinstance(entry, Mapping) or set(entry) != {"path", "type", "mode", "size", "sha256"}:
                raise RuntimeImageError("runtime_context_manifest_invalid")
            if type(entry["size"]) is not int:
                raise RuntimeImageError("runtime_context_manifest_invalid")
            relative = entry["path"]
            if (
                not isinstance(relative, str)
                or not relative
                or relative == "context-manifest.json"
                or PurePosixPath(relative).is_absolute()
                or ".." in PurePosixPath(relative).parts
                or "\\" in relative
            ):
                raise RuntimeImageError("runtime_context_manifest_invalid")
            path = root / relative
            try:
                info = path.lstat()
            except OSError as exc:
                raise RuntimeImageError("runtime_context_manifest_invalid") from exc
            if info.st_mtime_ns != 0:
                raise RuntimeImageError("runtime_context_manifest_invalid")
            if entry["type"] == "directory":
                valid = (
                    stat.S_ISDIR(info.st_mode)
                    and not stat.S_ISLNK(info.st_mode)
                    and entry["mode"] == "0755"
                    and entry["size"] == 0
                    and entry["sha256"] is None
                )
            elif entry["type"] == "file":
                valid = (
                    stat.S_ISREG(info.st_mode)
                    and not stat.S_ISLNK(info.st_mode)
                    and entry["mode"] in {"0644", "0755"}
                    and entry["mode"] == f"0{stat.S_IMODE(info.st_mode):03o}"
                    and entry["size"] == info.st_size
                    and entry["sha256"] == _hash_regular_file(path)
                )
            else:
                valid = False
            if not valid:
                raise RuntimeImageError("runtime_context_manifest_invalid")
            declared.add(relative)
        actual: set[str] = set()
        for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            base = Path(current)
            for name in dirnames:
                actual.add((base / name).relative_to(root).as_posix())
            for name in filenames:
                relative = (base / name).relative_to(root).as_posix()
                if relative != "context-manifest.json":
                    actual.add(relative)
        if actual != declared:
            raise RuntimeImageError("runtime_context_manifest_invalid")
        return hashlib.sha256(payload).hexdigest()

    def _record_value(
        self,
        prepared: _PreparedInput,
        derived_tag: str,
        image_id: str,
        labels: Mapping[str, str],
        *,
        context_manifest_sha256: str | None,
    ) -> dict[str, Any]:
        value = {
            "schema": RUNTIME_IMAGE_SCHEMA,
            "inputSha256": prepared.public["inputSha256"],
            "bootInputSha256": prepared.public["bootInputSha256"],
            "derivedTag": derived_tag,
            "imageId": image_id,
            "architecture": "arm64",
            "baseImageId": prepared.base.image_id,
            "baseRepoDigests": list(prepared.base.repo_digests),
            "artifactManifestSha256": prepared.public["artifactManifestSha256"],
            "artifactTuples": prepared.public["artifactTuples"],
            "contextInputs": prepared.public["contextInputs"],
            "googleInputs": prepared.public["googleInputs"],
            "toolInputs": prepared.public["toolInputs"],
            "builderInputs": prepared.public["builderInputs"],
            "daemonSeedContract": prepared.public["daemonSeedContract"],
            "labels": dict(labels),
            "contextManifestSha256": context_manifest_sha256,
        }
        return validate_record(value)

    def _publish_record(self, record: Mapping[str, Any]) -> None:
        validated = validate_record(record)
        path = self._cache_root / f"{validated['inputSha256']}.json"
        payload = _canonical_json(validated) + b"\n"
        temporary = self._cache_root / f".{validated['inputSha256']}.{secrets.token_hex(8)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(temporary, flags, 0o600)
            try:
                _write_all(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
            os.chmod(path, 0o600, follow_symlinks=False)
            _fsync_directory(self._cache_root)
        except OSError as exc:
            raise RuntimeImageError("runtime_image_record_publish_failed") from exc
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _validate_image_archive(path: Path) -> None:
        try:
            info = path.lstat()
        except OSError as exc:
            raise RuntimeImageError("runtime_image_archive_invalid") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > _MAX_IMAGE_ARCHIVE_BYTES
        ):
            raise RuntimeImageError("runtime_image_archive_invalid")
        try:
            os.chmod(path, 0o600, follow_symlinks=False)
        except OSError as exc:
            raise RuntimeImageError("runtime_image_archive_invalid") from exc

    @staticmethod
    def _runtime_input_lock_name(input_sha: str) -> str:
        return "xenoid-runtime-image-" + hashlib.sha256(
            f"runtime-input:{input_sha}".encode("ascii")
        ).hexdigest()

    @staticmethod
    def _base_tag(input_sha: str) -> str:
        return f"xenoid/runtime-base:xenoid-{input_sha}"

    def _temporary_tag(self, purpose: str, input_sha: str) -> str:
        return f"xenoid/runtime-{purpose}:xenoid-{input_sha[:16]}-{secrets.token_hex(8)}"

    def _docker_checked(
        self,
        suffix: Sequence[str],
        code: str,
        *,
        cwd: Path | None = None,
    ) -> _RunResult:
        result = self._run(
            self.docker_argv + tuple(suffix),
            env=self._command_env(),
            cwd=cwd or self.project_root,
        )
        if result.returncode != 0:
            raise RuntimeImageError(code)
        return result

    def _docker_remove_tag(self, tag: str) -> None:
        self._run(self.docker_argv + ("image", "rm", tag), env=self._command_env(), cwd=self.project_root)

    def _remove_tag_if_image(self, tag: str, image_id: str) -> None:
        try:
            current = self._inspect_image(tag, required=False)
        except RuntimeImageError:
            return
        if current is not None and current.get("Id") == image_id:
            self._docker_remove_tag(tag)

    def _command_env(self) -> dict[str, str]:
        environment = dict(os.environ)
        environment.update(self.docker_env)
        environment.update(
            {
                "LC_ALL": "C",
                "TZ": "UTC",
                "SOURCE_DATE_EPOCH": "0",
                "PYTHONHASHSEED": "0",
            }
        )
        return environment

    def _run(
        self,
        command: Sequence[str],
        *,
        env: Mapping[str, str],
        cwd: Path | None,
        input: bytes | None = None,
    ) -> _RunResult:
        if self._runner is None:
            bounded = run_bounded(
                tuple(command),
                cwd=cwd or self.project_root,
                env=env,
                input_bytes=input,
                deadline=self._deadline,
                project_root=self.project_root,
                cancelled=self._cancelled,
            )
            if bounded.state == "timed_out":
                raise RuntimeImageError("runtime_image_timeout")
            if bounded.state == "cancelled":
                raise RuntimeImageError("runtime_image_cancelled")
            completed = _RunResult(
                bounded.returncode
                if bounded.returncode is not None
                else (0 if bounded.ok else 1),
                bounded.stdout_tail.encode("utf-8", "replace"),
                bounded.stderr_tail.encode("utf-8", "replace"),
            )
        else:
            completed = self._runner(
                tuple(command),
                env=dict(env),
                cwd=None if cwd is None else str(cwd),
                input=input,
            )
        return _coerce_run_result(completed)

    @contextlib.contextmanager
    def _acquire_engine_lock(self, lock_name: str) -> Iterator[None]:
        if self._engine_lock is None:
            # A local lock is a safe single-checkout fallback. RuntimeManager supplies
            # the engine-host lock for production/native/Colima/SSH operation.
            path = self._local_lock_root / f"{lock_name}.lock"
            descriptor = os.open(
                path,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                    raise RuntimeImageError("runtime_image_engine_lock_invalid")
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                os.close(descriptor)
            return
        manager = self._engine_lock(lock_name) if callable(self._engine_lock) else self._engine_lock
        try:
            with manager:
                yield
        except RuntimeImageError:
            raise
        except Exception as exc:
            raise RuntimeImageError("runtime_image_engine_lock_failed") from exc

    def _ensure_private_directory(self, path: Path) -> None:
        try:
            relative = path.relative_to(self.project_root)
        except ValueError as exc:
            raise RuntimeImageError("runtime_image_cache_unsafe") from exc
        current = self.project_root
        try:
            for component in relative.parts:
                current = current / component
                try:
                    current.mkdir(mode=0o700)
                except FileExistsError:
                    pass
                info = current.lstat()
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != os.getuid()
                ):
                    raise RuntimeImageError("runtime_image_cache_unsafe")
            os.chmod(path, 0o700, follow_symlinks=False)
            final_info = path.lstat()
        except RuntimeImageError:
            raise
        except OSError as exc:
            raise RuntimeImageError("runtime_image_cache_unsafe") from exc
        if stat.S_IMODE(final_info.st_mode) != 0o700:
            raise RuntimeImageError("runtime_image_cache_unsafe")

    def _remove_tree_if_owned(self, path: Path) -> None:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        except OSError:
            return
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid():
            return
        shutil.rmtree(path, ignore_errors=True)


def _coerce_run_result(value: Any) -> _RunResult:
    if isinstance(value, _RunResult):
        return value
    if isinstance(value, Mapping):
        returncode = value.get("returncode", 0)
        stdout = value.get("stdout", b"")
        stderr = value.get("stderr", b"")
    else:
        returncode = getattr(value, "returncode", 0)
        stdout = getattr(value, "stdout", b"")
        stderr = getattr(value, "stderr", b"")
    if isinstance(stdout, str):
        stdout = stdout.encode("utf-8", "replace")
    if isinstance(stderr, str):
        stderr = stderr.encode("utf-8", "replace")
    return _RunResult(int(returncode), bytes(stdout), bytes(stderr))


def _hash_regular_file(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeImageError("runtime_image_input_unavailable") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeImageError("runtime_image_input_unavailable")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, _COPY_CHUNK)
            if not block:
                return digest.hexdigest()
            digest.update(block)
    finally:
        os.close(descriptor)


def _read_bounded(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        block = os.read(descriptor, min(_COPY_CHUNK, remaining))
        if not block:
            break
        chunks.append(block)
        remaining -= len(block)
    payload = b"".join(chunks)
    if len(payload) > limit:
        raise RuntimeImageError("runtime_image_record_invalid")
    return payload


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "RUNTIME_BOOT_INPUT_LABEL",
    "RUNTIME_BASE_IMAGE_LABEL",
    "RUNTIME_IMAGE_SCHEMA",
    "RUNTIME_INPUT_LABEL",
    "RUNTIME_SCHEMA_LABEL",
    "RuntimeImageBuilder",
    "RuntimeImageError",
    "compute_input_record",
    "derive_tag",
    "validate_record",
]
