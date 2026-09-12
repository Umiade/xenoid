from __future__ import annotations

from contextlib import contextmanager
import base64
import hashlib
import os
import secrets
import signal
import shlex
import subprocess
import json
import lzma
import re
import shutil
import stat
import tarfile
import selectors
import time
import threading
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import tempfile
from pathlib import Path
from typing import Any, BinaryIO, Iterator, Mapping, Optional

from .artifacts import (
    CONSUMER_TARGETS,
    TARGETS,
    ArtifactBuilder,
    ArtifactOutput,
    ArtifactRecord,
    ArtifactSnapshot,
)
from .config import (
    InstanceContext,
    InstanceError,
    InstanceLease,
    XenoidConfig,
    validate_image_reference,
)
from .daemon_client import (
    BOOTSTRAP_POLL_TIMEOUT_SECONDS,
    BOOTSTRAP_WORKER_TIMEOUT_MS,
    KEYBOX_MAX_SOURCE_BYTES,
    PROXY_MAX_SOURCE_BYTES,
    DaemonClient,
)
from .device_identity import (
    GOOGLE_CLEAR_PACKAGES,
    GOOGLE_MARKER_ROOTS,
    DeviceIdentityStore,
    IdentityError,
    RegenerationJournal,
    public_identity_state,
    stable_identity_digest,
)
from .google_services import (
    GOOGLE_LABEL_DATA_COMPAT,
    GOOGLE_LABEL_PROVIDER,
    GOOGLE_LABEL_RELEASE,
    GOOGLE_LABEL_SPEC,
    GOOGLE_RELEASE_SCHEMA_V2,
    MICROG_FAKE_CERT_SHA256,
    MICROG_PLAY_RELEASE,
    MICROG_REAL_CERT_SHA256,
    PROVIDER_MICROG,
    PROVIDER_NONE,
    GoogleBindingStore,
    GoogleServicesError,
    ReleaseSpec,
    base_status,
    binding_matches,
    capability_model,
    expected_binding_identity,
    factory_components,
    load_release_spec,
    public_binding,
    quick_validate_assets,
    resolve_google_runtime_spec,
    transition_decision,
)
from .storage import (
    CANONICAL_DATA_SIZE_BYTES,
    DATA_IMAGE_NAME,
    ROOTFS_IMAGE_NAME,
    StorageError,
    StorageStateStore,
    backup_image_name,
    parse_storage_result,
    public_storage_state,
    storage_rotation_target,
)
from .runtime_image import RuntimeImageBuilder
from .protection import SharedProtectionManager
from .process import run_bounded
from .operation_lock import instance_operation_lock as _instance_operation_lock
from .util import bounded_timeout, host_info, run, validate_release_version, which


_DAEMON_TRANSPORT_TIMEOUT_SECONDS = 30.0
_ROOTD_PROVISION_TIMEOUT_SECONDS = 30.0
_BOOTSTRAP_SEQUENCE_TIMEOUT_SECONDS = 300.0
_ROOTD_REMOTE_PATH = "/data/local/tmp/xenoid-rootd"
_ROOTD_LEGACY_PATH = "/data/local/tmp/.netd-helper"
_ROOTD_RUN_DIRECTORY = "/data/local/tmp/xenoid-rootd-run"
_ROOTD_PROCESS_RECORD = f"{_ROOTD_RUN_DIRECTORY}/process.json"
_ROOTD_PROCESS_SCHEMA = "dev.xenoid.rootd-process/v1"
_ROOTD_ERROR_CODES = frozenset({
    "daemon_token_unavailable",
    "rootd_unauthorized",
    "rootd_unavailable",
    "rootd_resource_conflict",
    "rootd_deploy_failed",
})
_DAEMON_RUNTIME_PERMISSIONS = (
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.POST_NOTIFICATIONS",
)
_RUNTIME_SCHEMA_LABEL = "dev.xenoid.runtime_schema"
_RUNTIME_INPUT_LABEL = "dev.xenoid.runtime_input_sha256"
_RUNTIME_BOOT_INPUT_LABEL = "dev.xenoid.runtime_boot_input_sha256"
_RUNTIME_BASE_IMAGE_LABEL = "dev.xenoid.runtime_base_image_id"
_CONVERGENCE_ARTIFACT_TARGETS = tuple(
    dict.fromkeys(
        (
            *CONSUMER_TARGETS["runtimeContext"],
            *CONSUMER_TARGETS["liveDeploy"],
        )
    )
)
_CONVERGENCE_REMOTE_ARTIFACTS = {
    "input": ("native/xenoid-input/xenoid-input", "/data/local/tmp/xenoid-input", 0o755),
    "hide": ("native/xenoid-hide/xenoid-hide", "/data/local/tmp/xenoid-hide-helper", 0o755),
    "profile": ("native/xenoid-profile/xenoid-profile", "/data/local/tmp/xenoid-profile-helper", 0o755),
    "rootd": ("native/xenoid-rootd/xenoid-rootd-arm64", _ROOTD_REMOTE_PATH, 0o755),
    "netctl": ("native/xenoid-netctl/xenoid-netctl", "/data/local/tmp/xenoid-netctl", 0o755),
    "ssaid": ("native/xenoid-hide/xenoid-ssaid", "/data/local/tmp/xenoid-ssaid", 0o755),
}
_CONVERGENCE_ACCEPTANCE_CHECKS = (
    "container",
    "storage",
    "identity",
    "adb",
    "boot",
    "daemon",
    "rootd",
    "location",
    "keybox",
    "camera",
    "google",
    "proxy",
    "protection",
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")

_CAMERA_UPLOAD_MIN_BYTES_PER_SECOND = 512 * 1024
_CAMERA_UPLOAD_TIMEOUT_FLOOR_SECONDS = 600
_CAMERA_UPLOAD_TIMEOUT_CAP_SECONDS = 7200
_CAMERA_UPLOAD_SETUP_SECONDS = 300


def _camera_upload_timeout_seconds(size: int) -> int:
    transfer_seconds = (
        size + _CAMERA_UPLOAD_MIN_BYTES_PER_SECOND - 1
    ) // _CAMERA_UPLOAD_MIN_BYTES_PER_SECOND
    return min(
        _CAMERA_UPLOAD_TIMEOUT_CAP_SECONDS,
        max(
            _CAMERA_UPLOAD_TIMEOUT_FLOOR_SECONDS,
            _CAMERA_UPLOAD_SETUP_SECONDS + transfer_seconds,
        ),
    )


_KEYBOX_STAGING_PATH = re.compile(
    r"/data/local/tmp/\.keybox-upload-([0-9a-f]{32})"
)
_KEYBOX_STAGE_SCRIPT = """\
set -eu
IFS=' ' read -r token size
[ "${#token}" -eq 32 ]
case "$token" in *[!0-9a-f]*) exit 64;; esac
case "$size" in *[!0-9]*) exit 64;; esac
[ "$size" -gt 0 ]
target="/data/local/tmp/.keybox-upload-${token}"
umask 077
trap 'rm -f "$target"' EXIT HUP INT TERM
cat >"$target"
chmod 0600 "$target"
if [ "$(id -u)" = 0 ]; then chown 2000:2000 "$target"; fi
[ "$(stat -c '%u:%g:%a' "$target")" = "2000:2000:600" ]
[ "$(stat -c %s "$target")" = "$size" ]
trap - EXIT HUP INT TERM
"""
_KEYBOX_CLEANUP_SCRIPT = """\
set -eu
IFS= read -r token
[ "${#token}" -eq 32 ]
case "$token" in *[!0-9a-f]*) exit 64;; esac
rm -f "/data/local/tmp/.keybox-upload-${token}"
"""


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    fix: Optional[str] = None


class RuntimeManager:
    def __init__(
        self,
        context: InstanceContext,
        cfg: XenoidConfig,
        lease: InstanceLease,
    ):
        self.context = context
        self.cfg = cfg
        self.lease = lease
        self._pending_proxy_restore: Optional[
            tuple[str, bytearray, bool, str, bool, bool]
        ] = None
        self._artifact_stages: dict[str, tempfile.TemporaryDirectory[str]] = {}
        self._selected_runtime_image: Optional[dict[str, Any]] = None
        self._shared_protection: Optional[SharedProtectionManager] = None
        self._shared_protection_capability: Optional[str] = None
        self.cancellation_event: Any = None
        self.ensure_instance_lease()

    def ensure_instance_lease(self) -> InstanceLease:
        validated_lease = InstanceLease.from_dict(asdict(self.lease))
        if validated_lease != self.lease:
            raise InstanceError("resource_conflict", "instance lease validation failed")
        if (
            self.context.instance_name != self.cfg.instance_name
            or self.context.instance_id != self.cfg.instance_id
            or self.context.instance_name != self.lease.instance_name
            or self.context.instance_id != self.lease.instance_id
        ):
            raise InstanceError(
                "instance_identity_mismatch",
                "runtime inputs belong to different instances",
            )
        if self.context.resource_tag != self.lease.resource_tag:
            raise InstanceError(
                "instance_tag_collision",
                "runtime resource tag does not match instance identity",
            )
        if self.lease.state != "committed":
            raise InstanceError("resource_conflict", "instance lease is not committed")
        if self.cfg.android_adb_port != self.lease.android_adb_port:
            raise InstanceError(
                "resource_conflict",
                "Android ADB port does not match instance lease",
            )
        expected_config_path = (
            self.context.project_root
            / ".xenoid"
            / "instances"
            / self.context.instance_name
            / "config.json"
        )
        if self.context.config_path != expected_config_path:
            raise InstanceError(
                "instance_identity_mismatch",
                "runtime config path does not match instance identity",
            )
        if (
            self.context.state_root.name != self.context.instance_id
            or self.context.state_root.parent.name != "instances"
        ):
            raise InstanceError(
                "instance_identity_mismatch",
                "runtime state path does not match instance identity",
            )
        return self.lease

    def legacy_token_migration_pending(self) -> bool:
        """Observe obsolete host token entries without reading or deleting them."""
        for name in ("daemon.token", "rootd.token"):
            try:
                (self.context.state_root / name).lstat()
                return True
            except FileNotFoundError:
                continue
            except OSError:
                return True
        return False

    def migrate_legacy_token_state(self) -> dict[str, Any]:
        """Unlink obsolete host token entries from one strictly owned state root."""
        root = self.context.state_root
        uid = os.getuid()
        for directory, exact_mode in (
            (root.parent.parent, None),
            (root.parent, None),
            (root, 0o700),
        ):
            try:
                info = directory.lstat()
                resolved = directory.resolve(strict=True)
            except OSError as exc:
                raise InstanceError(
                    "legacy_token_state_invalid",
                    "legacy token state directory is unsafe",
                ) from exc
            mode = stat.S_IMODE(info.st_mode)
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != uid
                or resolved != directory.absolute()
                or exact_mode is not None
                and mode != exact_mode
                or exact_mode is None
                and mode & 0o022
            ):
                raise InstanceError(
                    "legacy_token_state_invalid",
                    "legacy token state directory is unsafe",
                )
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(root, flags)
        except OSError as exc:
            raise InstanceError(
                "legacy_token_state_invalid",
                "legacy token state directory is unsafe",
            ) from exc
        removed = 0
        try:
            opened = os.fstat(descriptor)
            expected = root.lstat()
            if (
                opened.st_dev != expected.st_dev
                or opened.st_ino != expected.st_ino
                or not stat.S_ISDIR(opened.st_mode)
                or opened.st_uid != uid
                or stat.S_IMODE(opened.st_mode) != 0o700
            ):
                raise InstanceError(
                    "legacy_token_state_invalid",
                    "legacy token state directory changed",
                )
            for name in ("daemon.token", "rootd.token"):
                try:
                    os.unlink(name, dir_fd=descriptor)
                    removed += 1
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise InstanceError(
                        "legacy_token_state_invalid",
                        "legacy token entry could not be removed safely",
                    ) from exc
            if removed:
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return {"ok": True, "removed": removed}

    def instance_operation_lock(
        self,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> Iterator[None]:
        """Return the one instance mutation lock used by convergence.

        The executor holds this context for the complete operation.  Low-level
        hooks deliberately do not acquire a second lock or invoke a command
        dispatcher.
        """
        return _instance_operation_lock(
            self.context.state_root,
            timeout_seconds=timeout_seconds,
        )


    def _artifact_consumer_root(
        self,
        consumer: str | tuple[str, ...],
    ) -> Path:
        key = consumer if isinstance(consumer, str) else ",".join(consumer)
        existing = self._artifact_stages.get(key)
        if existing is not None:
            return Path(existing.name)
        temporary = tempfile.TemporaryDirectory(prefix="xenoid-artifacts-")
        destination = Path(temporary.name)
        try:
            builder = ArtifactBuilder(self.context.project_root)
            snapshot = builder.snapshot(consumer)
            builder.stage(snapshot, destination)
        except (KeyError, OSError, RuntimeError, ValueError) as exc:
            temporary.cleanup()
            raise InstanceError(
                "artifact_snapshot_invalid",
                "validated artifact snapshot is unavailable",
            ) from exc
        self._artifact_stages[key] = temporary
        return destination

    def _artifact_output(
        self,
        consumer: str | tuple[str, ...],
        relative: str,
    ) -> Path:
        path = self._artifact_consumer_root(consumer) / relative
        try:
            state = path.lstat()
        except OSError as exc:
            raise InstanceError(
                "artifact_snapshot_invalid",
                "validated artifact output is unavailable",
            ) from exc
        if stat.S_ISLNK(state.st_mode) or not stat.S_ISREG(state.st_mode):
            raise InstanceError(
                "artifact_snapshot_invalid",
                "validated artifact output is invalid",
            )
        return path

    @property
    def adb_target(self) -> str:
        return f"127.0.0.1:{self.lease.host_adb_port}"

    def doctor(self) -> list[Check]:
        info = host_info()
        checks = [
            Check("host", True, f"{info['system']} {info['machine']} / Python {info['python']}"),
            Check("docker", which("docker") is not None, which("docker") or "not found", "brew install docker" if info["system"] == "Darwin" else "install docker/podman compatible Docker CLI"),
            Check("adb", which("adb") is not None, which("adb") or "not found", "brew install android-platform-tools" if info["system"] == "Darwin" else "install android-tools-adb"),
            Check("scrcpy", which("scrcpy") is not None, which("scrcpy") or "not found", "brew install scrcpy" if info["system"] == "Darwin" else "install scrcpy"),
        ]
        if info["system"] == "Darwin":
            checks.insert(2, Check("colima", which("colima") is not None, which("colima") or "not found", "brew install colima"))
            if info["machine"] not in {"arm64", "aarch64"}:
                checks.append(Check("apple-silicon", False, f"machine={info['machine']}", "Use an Apple Silicon Mac"))
        elif info["system"] == "Linux" and info["machine"] not in {"arm64", "aarch64"}:
            checks.append(Check("linux-arm", False, f"machine={info['machine']}", "Use a Linux ARM host"))
        checks.append(Check("backend", True, self.cfg.backend))
        if self.cfg.google_services_provider != PROVIDER_NONE:
            for command in ("keytool", "jarsigner", "aapt2", "apksigner"):
                resolved = which(command)
                checks.append(
                    Check(
                        f"google-{command}",
                        resolved is not None,
                        resolved or "not found",
                        "run ./xenoid install-runtime",
                    )
                )
        return checks

    def colima_start_command(self) -> list[str]:
        return ["colima", "start", "--arch", "aarch64", "--vm-type", "vz", "--memory", "8", "--cpu", "8"]

    def engine_reachable(self) -> bool:
        """True when the configured Docker engine answers a bounded probe."""
        if which("docker") is None:
            return False
        proc = run(
            [*self.docker_base_cmd(), "version", "--format", "{{.Server.Version}}"],
            timeout=20,
            env=self.docker_env(),
        )
        return proc.returncode == 0

    def ensure_engine_started(self) -> dict[str, Any]:
        """Start a stopped local engine so `up` converges instead of failing.

        Starts only what install-runtime/init already installed: the existing
        Colima VM on macOS or the local docker service on Linux. Remote
        engines (ssh:// / tcp://) and first-time installation are never
        attempted here.
        """
        if self.engine_reachable():
            return {"ok": True, "started": False}
        if self._docker_host_is_remote():
            return {
                "ok": False,
                "error": "engine_unavailable",
                "message": "remote Docker engine is unreachable; start it on its host",
            }
        if self.should_use_colima():
            if which("colima") is None:
                return {
                    "ok": False,
                    "error": "engine_unavailable",
                    "message": "colima not found; run ./xenoid install-runtime",
                }
            started = run(self.colima_start_command(), timeout=600)
            if started.returncode != 0:
                return {
                    "ok": False,
                    "error": "colima_start_failed",
                    "message": started.stderr.strip()[-500:],
                }
        elif host_info()["system"] == "Linux":
            commands = (
                ["systemctl", "--user", "start", "docker"],
                ["sudo", "-n", "systemctl", "start", "docker"],
            )
            started_ok = any(
                which(cmd[0]) is not None and run(cmd, timeout=120).returncode == 0
                for cmd in commands
            )
            if not started_ok:
                return {
                    "ok": False,
                    "error": "engine_unavailable",
                    "message": "local docker service is not running; start it (sudo systemctl start docker)",
                }
        else:
            return {"ok": False, "error": "engine_unavailable"}
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            if self.engine_reachable():
                return {"ok": True, "started": True}
            time.sleep(2.0)
        return {"ok": False, "error": "engine_start_timeout"}

    def google_runtime_spec(
        self,
        purpose: str,
        *,
        require_assets: bool = True,
    ) -> Optional[ReleaseSpec]:
        return resolve_google_runtime_spec(
            self.context,
            self.cfg,
            purpose,
            require_assets=require_assets,
        )

    def _runtime_image_builder(self) -> RuntimeImageBuilder:
        return RuntimeImageBuilder(
            self.context.project_root,
            self.docker_base_cmd(),
            self.docker_env(),
            artifact_builder=ArtifactBuilder(self.context.project_root),
            runner=self._run_runtime_image_command,
            engine_lock=self._runtime_image_engine_lock,
        )

    def _run_runtime_image_command(
        self,
        command: tuple[str, ...],
        *,
        env: Mapping[str, str],
        cwd: Optional[str],
        input: Optional[bytes] = None,
    ) -> subprocess.CompletedProcess[bytes]:
        timeout = bounded_timeout(3600) or 3600
        bounded = run_bounded(
            command,
            cwd=Path(cwd) if cwd is not None else self.context.project_root,
            env=env,
            input_bytes=input,
            deadline=time.monotonic() + timeout,
            project_root=self.context.project_root,
        )
        return subprocess.CompletedProcess(
            command,
            bounded.returncode
            if bounded.returncode is not None
            else (0 if bounded.ok else 1),
            bounded.stdout_tail.encode("utf-8", "replace"),
            bounded.stderr_tail.encode("utf-8", "replace"),
        )

    @contextmanager
    def _runtime_image_engine_lock(self, lock_name: str) -> Iterator[None]:
        if re.fullmatch(r"xenoid-runtime-image-[0-9a-f]{64}", lock_name) is None:
            raise InstanceError(
                "runtime_image_lock_invalid",
                "runtime image publication lock name is invalid",
            )
        script = (
            "set -eu; "
            'p="/run/lock/$1.lock"; '
            'if [ ! -e "$p" ]; then umask 077; : >"$p"; fi; '
            'test ! -L "$p"; chown 0:0 "$p"; chmod 0600 "$p"; '
            "exec flock -x \"$p\" sh -c "
            "'( printf \"XENOID_LOCKED\\n\" ); cat >/dev/null'"
        )
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            remote_command = shlex.join(
                [
                    "sudo",
                    "-n",
                    "sh",
                    "-c",
                    script,
                    "xenoid-runtime-image-lock",
                    lock_name,
                ]
            )
            command = [*ssh_cmd, remote_command]
        elif self.should_use_colima():
            command = [
                "colima",
                "ssh",
                "--",
                "sudo",
                "-n",
                "sh",
                "-c",
                script,
                "xenoid-runtime-image-lock",
                lock_name,
            ]
        else:
            command = [
                "sudo",
                "-n",
                "sh",
                "-c",
                script,
                "xenoid-runtime-image-lock",
                lock_name,
            ]
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=self.docker_env(),
            start_new_session=True,
        )
        acquired = False
        selector = selectors.DefaultSelector()
        try:
            if process.stdout is None or process.stderr is None:
                raise InstanceError(
                    "runtime_image_lock_failed",
                    "runtime image publication lock process is unavailable",
                )
            selector.register(process.stdout, selectors.EVENT_READ)
            selector.register(process.stderr, selectors.EVENT_READ)
            wait_seconds = bounded_timeout(120.0) or 120.0
            deadline = time.monotonic() + max(0.001, wait_seconds)
            diagnostic = ""
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                events = selector.select(min(remaining, 1.0))
                for key, _ in events:
                    line = key.fileobj.readline()
                    if key.fileobj is process.stdout and line == "XENOID_LOCKED\n":
                        acquired = True
                        break
                    if key.fileobj is process.stderr and line:
                        diagnostic = (diagnostic + line)[-1024:]
                if acquired:
                    break
                if process.poll() is not None:
                    break
            if not acquired and process.poll() is not None:
                remainder = process.stdout.read(4097)
                if len(remainder) <= 4096 and "XENOID_LOCKED\n" in remainder.splitlines(keepends=True):
                    acquired = True
            if not acquired:
                raise InstanceError(
                    "runtime_image_lock_timeout"
                    if process.poll() is None
                    else "runtime_image_lock_failed",
                    "engine-host runtime image publication lock is unavailable",
                )
            yield
            if process.poll() is not None:
                raise InstanceError(
                    "runtime_image_lock_lost",
                    "engine-host runtime image publication lock was lost",
                )
        finally:
            selector.close()
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()

    def runtime_image_input_record(
        self,
        base_image: Optional[str] = None,
        configured_tag: Optional[str] = None,
        *,
        spec: Optional[ReleaseSpec] = None,
    ) -> dict[str, Any]:
        selected_spec = (
            self.google_runtime_spec("runtime-image-input", require_assets=True)
            if spec is None
            else spec
        )
        selected_base = validate_image_reference(
            base_image or self.base_image_for_build()
        )
        selected_tag = validate_image_reference(
            configured_tag or self.cfg.runtime_image_tag,
            require_tag=True,
            allow_digest=False,
        )
        return self._runtime_image_builder().input_record(
            selected_base,
            configured_tag=selected_tag,
            google_spec=selected_spec,
        )

    def selected_runtime_image(
        self,
        *,
        refresh: bool = False,
        spec: Optional[ReleaseSpec] = None,
    ) -> dict[str, Any]:
        if self._selected_runtime_image is not None and not refresh:
            return dict(self._selected_runtime_image)
        desired = self.runtime_image_input_record(spec=spec)
        input_sha256 = str(desired.get("inputSha256") or "")
        record = self._runtime_image_builder().lookup(input_sha256)
        if record is None:
            raise InstanceError(
                "runtime_image_required",
                "verified content-addressed runtime image is unavailable",
            )
        for key in (
            "inputSha256",
            "bootInputSha256",
            "derivedTag",
            "baseImageId",
        ):
            if record.get(key) != desired.get(key):
                raise InstanceError(
                    "runtime_image_record_invalid",
                    "runtime image record does not match current inputs",
                )
        image, inspect = self._inspect_docker_object(
            "image",
            str(record.get("derivedTag") or ""),
        )
        config = image.get("Config") if isinstance(image, dict) else None
        labels = config.get("Labels") if isinstance(config, dict) else None
        labels = labels if isinstance(labels, dict) else {}
        expected_labels = {
            _RUNTIME_SCHEMA_LABEL: "1",
            _RUNTIME_INPUT_LABEL: str(record.get("inputSha256") or ""),
            _RUNTIME_BOOT_INPUT_LABEL: str(record.get("bootInputSha256") or ""),
            _RUNTIME_BASE_IMAGE_LABEL: str(record.get("baseImageId") or ""),
        }
        if (
            not isinstance(image, dict)
            or not image
            or inspect.returncode != 0
            or str(image.get("Id") or "") != str(record.get("imageId") or "")
            or str(image.get("Architecture") or "") not in {"arm64", "aarch64"}
            or any(
                labels.get(key) != value
                for key, value in expected_labels.items()
            )
        ):
            raise InstanceError(
                "runtime_image_record_invalid",
                "published runtime image does not match its verified record",
            )
        self._selected_runtime_image = dict(record)
        return dict(record)

    def ensure_runtime_image(
        self,
        base_image: Optional[str] = None,
        configured_tag: Optional[str] = None,
        *,
        spec: Optional[ReleaseSpec] = None,
        expected_input_sha256: Optional[str] = None,
        expected_boot_input_sha256: Optional[str] = None,
        deadline: Optional[float] = None,
        cancelled: Any = None,
    ) -> dict[str, Any]:
        for expected in (expected_input_sha256, expected_boot_input_sha256):
            if expected is not None and _SHA256_PATTERN.fullmatch(expected) is None:
                return {
                    "ok": False,
                    "error": "convergence_state_conflict",
                    "message": "journaled runtime image digest is invalid",
                }
        try:
            selected_spec = (
                self.google_runtime_spec(
                    "runtime-image-build",
                    require_assets=True,
                )
                if spec is None
                else spec
            )
            selected_base = validate_image_reference(
                base_image or self.base_image_for_build()
            )
            selected_tag = validate_image_reference(
                configured_tag or self.cfg.runtime_image_tag,
                require_tag=True,
                allow_digest=False,
            )
            record = self._runtime_image_builder().ensure(
                selected_base,
                selected_tag,
                selected_spec,
                deadline=deadline,
                cancelled=cancelled,
            )
        except (
            GoogleServicesError,
            InstanceError,
            OSError,
            RuntimeError,
            ValueError,
        ) as exc:
            return {
                "ok": False,
                "error": getattr(exc, "code", "runtime_image_build_failed"),
                "message": str(exc),
            }
        if (
            expected_input_sha256 is not None
            and record.get("inputSha256") != expected_input_sha256
            or expected_boot_input_sha256 is not None
            and record.get("bootInputSha256") != expected_boot_input_sha256
        ):
            return {
                "ok": False,
                "error": "convergence_inputs_changed",
                "message": "runtime image inputs changed before publication",
            }
        if base_image is None and configured_tag is None:
            self._selected_runtime_image = None
            try:
                selected = self.selected_runtime_image(
                    refresh=True,
                    spec=selected_spec,
                )
            except (
                GoogleServicesError,
                InstanceError,
                OSError,
                RuntimeError,
                ValueError,
            ) as exc:
                return {
                    "ok": False,
                    "error": getattr(
                        exc,
                        "code",
                        "runtime_image_record_invalid",
                    ),
                    "message": str(exc),
                }
            if selected.get("imageId") != record.get("imageId"):
                return {
                    "ok": False,
                    "error": "runtime_image_record_invalid",
                    "message": "published runtime image record is inconsistent",
                }
        return {"ok": True, **record}

    def effective_image(self) -> str:
        return str(self.selected_runtime_image()["derivedTag"])

    def docker_endpoint_host(self) -> str:
        """Return the Docker engine Host endpoint for cfg.docker_context, if any."""
        ctx = (self.cfg.docker_context or "").strip()
        if not ctx:
            return ""
        docker = which("docker") or "docker"
        proc = run([docker, "context", "inspect", ctx, "--format", "{{.Endpoints.docker.Host}}"])
        if proc.returncode != 0:
            return ""
        return (proc.stdout or "").strip()

    def _docker_host_is_remote(self) -> bool:
        host = self.docker_endpoint_host()
        return host.startswith("ssh://") or host.startswith("tcp://")

    def remote_docker_ssh_cmd(self) -> Optional[list[str]]:
        """SSH argv prefix to the docker engine host when context uses ssh://."""
        host = self.docker_endpoint_host()
        if not host.startswith("ssh://"):
            return None
        from urllib.parse import urlparse

        parsed = urlparse(host)
        target = parsed.hostname or ""
        if not target:
            return None
        if parsed.username:
            target = f"{parsed.username}@{target}"
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
        if parsed.port:
            cmd.extend(["-p", str(parsed.port)])
        cmd.append(target)
        return cmd

    def _binder_probe_command(self) -> Optional[list[str]]:
        """Command that prints binderfs|legacy|none on the docker engine host."""
        probe = (
            "test -e /dev/binderfs/binder-control && echo binderfs || "
            "(test -e /dev/binder && echo legacy) || echo none"
        )
        if self.should_use_colima():
            return ["colima", "ssh", "--", "sh", "-c", probe]
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            return [*ssh_cmd, "sh", "-c", probe]
        return None

    def binder_volume_args(self) -> list[str]:
        """Host-side binder device mounts for the redroid container.

        Prefer binderfs (verified path on Ubuntu kernels ≥5.x via
        linux-modules-extra). Fall back to legacy nodes when a kernel exposes
        /dev/binder directly (older devbox path). Probe the Docker engine host
        (local Colima VM or remote context SSH), not the macOS client filesystem.
        """
        probe_cmd = self._binder_probe_command()
        if probe_cmd is not None:
            probe = run(probe_cmd, env=self.docker_env())
            out = (probe.stdout or "").strip()
            if "binderfs" in out:
                return ["-v", "/dev/binderfs:/dev/binderfs"]
            if "legacy" in out:
                return ["-v", "/dev/binder:/dev/binder", "-v", "/dev/hwbinder:/dev/hwbinder", "-v", "/dev/vndbinder:/dev/vndbinder"]
            return []
        if Path("/dev/binderfs/binder-control").exists():
            return ["-v", "/dev/binderfs:/dev/binderfs"]
        if Path("/dev/binder").exists():
            return ["-v", "/dev/binder:/dev/binder", "-v", "/dev/hwbinder:/dev/hwbinder", "-v", "/dev/vndbinder:/dev/vndbinder"]
        return []

    def _binder_setup_shell(self) -> str:
        return (
            "set -e; "
            "if ! sudo modprobe binder_linux 2>/dev/null; then "
            "sudo apt-get update -qq && sudo apt-get install -y -qq linux-modules-extra-$(uname -r) && sudo modprobe binder_linux; "
            "fi; "
            "sudo mkdir -p /dev/binderfs; "
            "mountpoint -q /dev/binderfs || sudo mount -t binder binder /dev/binderfs; "
            "test -e /dev/binderfs/binder-control && echo BINDER_READY"
        )

    def ensure_binder(self) -> dict[str, Any]:
        """Idempotently ensure binder support on the docker engine host.

        Local Colima: modprobe/mount via `colima ssh`. Remote docker context
        (ssh://): same setup over SSH to the engine host. Native Linux: delegate
        to scripts/setup-linux-binderfs.sh.
        """
        script = self._binder_setup_shell()
        if self.should_use_colima():
            if which("colima") is None:
                return {"ok": False, "error": "colima not found"}
            proc = run(["colima", "ssh", "--", "sh", "-c", script], timeout=600, env=self.docker_env())
            ok = proc.returncode == 0 and "BINDER_READY" in (proc.stdout or "")
            return {"ok": ok, "backend": "colima", "returncode": proc.returncode, "stdout": proc.stdout.strip()[-800:], "stderr": proc.stderr.strip()[-800:]}
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            proc = run([*ssh_cmd, "sh", "-c", script], timeout=600, env=self.docker_env())
            ok = proc.returncode == 0 and "BINDER_READY" in (proc.stdout or "")
            return {"ok": ok, "backend": "remote-ssh", "ssh": ssh_cmd[-1], "returncode": proc.returncode, "stdout": proc.stdout.strip()[-800:], "stderr": proc.stderr.strip()[-800:]}
        if host_info()["system"] == "Linux":
            script_path = self.context.project_root / "scripts" / "setup-linux-binderfs.sh"
            proc = run(["bash", str(script_path)], timeout=600, env=self.docker_env())
            return {"ok": proc.returncode == 0, "backend": "linux", "returncode": proc.returncode, "stdout": proc.stdout.strip()[-800:], "stderr": proc.stderr.strip()[-800:]}
        return {"ok": True, "skipped": True, "reason": "no binder action for this backend"}

    def should_use_colima(self) -> bool:
        """True only for local Colima (colima-docker / default macOS local).

        Never when backend=linux-docker, or when docker_context points at a
        remote engine (ssh:// or tcp://).
        """
        if self.cfg.backend == "linux-docker":
            return False
        if self._docker_host_is_remote():
            return False
        if self.cfg.backend in {"colima-docker", "macos-colima"}:
            return True
        # Default macOS local path when no remote docker_context is configured.
        return host_info()["system"] == "Darwin" and not (self.cfg.docker_context or "").strip()

    def build_ebpf_command(self) -> list[str]:
        script = self.context.project_root / "scripts" / "build-ebpf.sh"
        cmd = [str(script)]
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            target = ssh_cmd[-1]
            cmd.extend(["--ssh", target])
            if "-p" in ssh_cmd:
                port = ssh_cmd[ssh_cmd.index("-p") + 1]
                cmd.extend(["--ssh-port", port])
            return cmd
        if self.should_use_colima():
            cmd.append("--colima")
            return cmd
        cmd.append("--local")
        return cmd

    def ebpf_action_command(self, action: str) -> list[str]:
        script = self.context.project_root / "scripts" / "load-ebpf.sh"
        cmd = [str(script)]
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            target = ssh_cmd[-1]
            cmd.extend(["--ssh", target])
            if "-p" in ssh_cmd:
                port = ssh_cmd[ssh_cmd.index("-p") + 1]
                cmd.extend(["--ssh-port", port])
        elif self.should_use_colima():
            cmd.append("--colima")
        else:
            cmd.append("--local")
        cmd.append(action)
        return cmd

    def build_kmod_command(self) -> list[str]:
        script = self.context.project_root / "scripts" / "build-kmod.sh"
        cmd = [str(script)]
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            # Pass user@host and optional -p port as ENGINE_SSH / ENGINE_SSH_PORT via flags.
            target = ssh_cmd[-1]
            cmd.extend(["--ssh", target])
            if "-p" in ssh_cmd:
                port = ssh_cmd[ssh_cmd.index("-p") + 1]
                cmd.extend(["--ssh-port", port])
            return cmd
        if self.should_use_colima():
            cmd.append("--colima")
            return cmd
        cmd.append("--local")
        return cmd

    def shared_protection_manager(self) -> SharedProtectionManager:
        if self._shared_protection is None:
            self._shared_protection = SharedProtectionManager(self)
        return self._shared_protection

    @contextmanager
    def _shared_protection_engine_lock(self) -> Iterator[None]:
        script = r'''
set -eu
p=/run/lock/xenoid-shared-protection.lock
if [ ! -e "$p" ]; then (set -C; umask 077; : >"$p") 2>/dev/null || true; fi
[ ! -L "$p" ] && [ -f "$p" ]
[ "$(stat -c '%u:%g:%a:%h' "$p")" = '0:0:600:1' ]
exec flock -x "$p" sh -c '
set -eu
d=/run/xenoid/shared-protection-capabilities
install -d -o root -g root -m 0700 "$d"
[ ! -L "$d" ] && [ "$(stat -c "%u:%g:%a" "$d")" = "0:0:700" ]
nonce=$(od -An -N32 -tx1 /dev/urandom | tr -d " \n")
case "$nonce" in *[!0-9a-f]*|"") exit 1;; esac
cap="$d/$nonce"
umask 077
(set -C; : >"$cap")
[ ! -L "$cap" ] && [ "$(stat -c "%u:%g:%a:%h" "$cap")" = "0:0:600:1" ]
trap "rm -f -- \"$cap\"" EXIT HUP INT TERM
( printf "XENOID_LOCKED %s\n" "$nonce" )
cat >/dev/null
'
'''
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            command = [
                *ssh_cmd,
                shlex.join(
                    [
                        "sudo",
                        "-n",
                        "sh",
                        "-c",
                        script,
                        "xenoid-shared-protection-lock",
                    ]
                ),
            ]
        elif self.should_use_colima():
            command = [
                "colima",
                "ssh",
                "--",
                "sudo",
                "-n",
                "sh",
                "-c",
                script,
                "xenoid-shared-protection-lock",
            ]
        elif self.docker_endpoint_host().startswith("tcp://"):
            raise InstanceError(
                "shared_protection_engine_unavailable",
                "engine host transport cannot execute protection operations",
            )
        else:
            command = [
                "sudo",
                "-n",
                "sh",
                "-c",
                script,
                "xenoid-shared-protection-lock",
            ]
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=self.docker_env(),
            start_new_session=True,
        )
        selector = selectors.DefaultSelector()
        capability: Optional[str] = None
        acquired = False
        try:
            if process.stdout is None or process.stderr is None:
                raise InstanceError(
                    "shared_protection_lock_failed",
                    "engine-host protection lock process is unavailable",
                )
            selector.register(process.stdout, selectors.EVENT_READ)
            selector.register(process.stderr, selectors.EVENT_READ)
            wait_seconds = bounded_timeout(120.0) or 120.0
            deadline = time.monotonic() + max(0.001, wait_seconds)
            while time.monotonic() < deadline and process.poll() is None:
                cancellation = self.cancellation_event
                if (
                    cancellation is not None
                    and callable(getattr(cancellation, "is_set", None))
                    and cancellation.is_set()
                ):
                    raise InstanceError(
                        "shared_protection_cancelled",
                        "engine-host protection operation was cancelled",
                    )
                events = selector.select(
                    min(1.0, max(0.001, deadline - time.monotonic()))
                )
                for key, _ in events:
                    line = key.fileobj.readline()
                    match = re.fullmatch(
                        r"XENOID_LOCKED ([0-9a-f]{64})\n",
                        line,
                    )
                    if key.fileobj is process.stdout and match is not None:
                        capability = match.group(1)
                        acquired = True
                        break
                if acquired:
                    break
            if not acquired and process.poll() is not None:
                remainder = process.stdout.read(4097)
                if len(remainder) <= 4096:
                    for line in remainder.splitlines(keepends=True):
                        match = re.fullmatch(
                            r"XENOID_LOCKED ([0-9a-f]{64})\n",
                            line,
                        )
                        if match is not None:
                            capability = match.group(1)
                            acquired = True
                            break
            if not acquired:
                raise InstanceError(
                    "shared_protection_lock_timeout"
                    if process.poll() is None
                    else "shared_protection_lock_failed",
                    "engine-host protection lock is unavailable",
                )
            self._shared_protection_capability = capability
            yield
            if process.poll() is not None:
                raise InstanceError(
                    "shared_protection_lock_lost",
                    "engine-host protection lock was lost",
                )
        finally:
            self._shared_protection_capability = None
            selector.close()
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()

    def shared_protection_status(self) -> dict[str, Any]:
        return self.shared_protection_manager().status()

    def build_shared_protection(self) -> dict[str, Any]:
        return self.shared_protection_manager().prepare()

    def unload_shared_ebpf(self, *, maintenance: bool) -> dict[str, Any]:
        return self.shared_protection_manager().unload_ebpf(
            maintenance=maintenance,
        )

    def smoke_shared_protection(self) -> dict[str, Any]:
        return self.shared_protection_manager().smoke()

    def kernel_module_status(self) -> dict[str, Any]:
        status = self.shared_protection_status()
        kernel = status.get("kernel")
        return dict(kernel) if isinstance(kernel, Mapping) else {
            "ok": False,
            "loaded": False,
            "error": status.get("error", "shared_protection_status_failed"),
        }

    def ebpf_status(self) -> dict[str, Any]:
        status = self.shared_protection_status()
        ebpf = status.get("ebpf")
        return dict(ebpf) if isinstance(ebpf, Mapping) else {
            "ok": False,
            "loaded": False,
            "error": status.get("error", "shared_protection_status_failed"),
        }

    def image_protection_status(self) -> dict[str, Any]:
        command = (
            "test -x /system/bin/xenoid-prop-area && "
            "test -x /system/bin/xenoid-overlay-helper && "
            "test -x /system/bin/xenoid-sensorshal && "
            "test -x /system/bin/hw/android.hardware.camera.provider-service-aidl && "
            "test ! -e /system/bin/xenoid-camerahal && "
            "test ! -e /system/bin/hw/xenoid-camerahal && "
            "test ! -e /system/etc/init/xenoid-camerahal.rc && "
            "test ! -e /system/etc/init/hw/xenoid-camerahal.rc && "
            "test -r /system/etc/init/android.hardware.camera.provider-service-aidl.rc && "
            "grep -q '^service vendor.camera-provider-aidl ' "
            "/system/etc/init/android.hardware.camera.provider-service-aidl.rc && "
            "test -r /system/lib64/libpiex_shim.so && "
            "test ! -e /system/lib64/libxenoid_core.so && "
            "grep -a -q 'libpiex_shim.so' /system/bin/app_process64 && "
            "! grep -q 'setenv LD_PRELOAD' /system/etc/init/hw/init.zygote64.rc && "
            "test -x /system/bin/xenoid-app-process && "
            "! grep -a -q 'libpiex_shim.so' /system/bin/xenoid-app-process && "
            "test -r /system/lib64/libxenoid_svcman.so && "
            "grep -a -q 'libxenoid_svcman.so' /system/bin/servicemanager && "
            "test -x /system/bin/hw/android.hardware.security.keymint-service && "
            "test -r /system/etc/init/android.hardware.security.keymint-service.rc && "
            "grep -q '^service vendor.keymint-aidl ' "
            "/system/etc/init/android.hardware.security.keymint-service.rc && "
            "test -r /vendor/etc/vintf/manifest/android.hardware.security.keymint.IKeyMintDevice.xml && "
            "grep -q 'IKeyMintDevice/default' "
            "/vendor/etc/vintf/manifest/android.hardware.security.keymint.IKeyMintDevice.xml && "
            "test -r /system/etc/init/keystore2.rc && "
            "grep -q '^service keystore2 /system/bin/keystore2 /data/misc/keystore$' "
            "/system/etc/init/keystore2.rc && "
            "test \"$(grep -c '^service keystore2 ' /system/etc/init/keystore2.rc)\" = 1 && "
            "! grep -q 'LD_PRELOAD' /system/etc/init/keystore2.rc && "
            "test \"$(getprop init.svc.vendor.keymint-aidl)\" = running && "
            "service list | grep -q 'android.hardware.security.keymint.IKeyMintDevice/default' && "
            "test \"$(getprop init.svc.keystore2)\" = running && "
            "keystore_pid=$(pidof keystore2 | cut -d' ' -f1) && "
            "test -n \"$keystore_pid\" && "
            "test \"$(readlink /proc/$keystore_pid/exe)\" = /system/bin/keystore2 && "
            "test -x /vendor/bin/hw/android.hardware.keymaster@4.1-service && "
            "test \"$(getprop init.svc.vendor.keymaster-4-1)\" = running && "
            "test \"$(getprop init.svc.xenoid-sensorshal)\" = running && "
            "test \"$(getprop init.svc.vendor.camera-provider-aidl)\" = running && "
            "test \"$(getprop ro.hardware)\" = raven && "
            "test \"$(getprop ro.product.device)\" = raven && "
            "zygote_pid=$(pidof zygote64 | cut -d' ' -f1) && "
            "test -n \"$zygote_pid\" && "
            "grep -q ' /proc/cpuinfo ' /proc/$zygote_pid/mountinfo && "
            "grep -q ' /proc/version ' /proc/$zygote_pid/mountinfo && "
            "grep -q ' /proc/meminfo ' /proc/$zygote_pid/mountinfo"
        )
        result = self.docker_exec(["sh", "-c", command], timeout=30)
        result["components"] = [
            "property-area",
            "overlay",
            "zygote-compatibility",
            "sensor-hal",
            "camera-provider",
            "keymint-interceptor",
            "stock-keymaster-4.1",
        ]
        return result


    def effective_docker_context(self) -> str:
        configured = (self.cfg.docker_context or "").strip()
        if configured:
            return configured
        return "colima" if self.should_use_colima() else "default"

    def docker_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env.pop("DOCKER_CONTEXT", None)
        env.pop("DOCKER_HOST", None)
        env["DOCKER_CONTEXT"] = self.effective_docker_context()
        env["XENOID_PROJECT"] = str(self.context.project_root)
        env["XENOID_INSTANCE"] = self.context.instance_name
        return env

    def docker_base_cmd(self) -> list[str]:
        docker = which("docker") or "docker"
        return [docker, "--context", self.effective_docker_context()]

    def _owner_label_args(self) -> list[str]:
        return [
            argument
            for key, value in sorted(self.lease.owner_labels.items())
            for argument in ("--label", f"{key}={value}")
        ]

    def _google_label_values(self) -> dict[str, str]:
        spec = self.google_runtime_spec("container-labels", require_assets=False)
        identity = expected_binding_identity(spec)
        return {
            GOOGLE_LABEL_PROVIDER: identity["provider"],
            GOOGLE_LABEL_RELEASE: identity["release"],
            GOOGLE_LABEL_SPEC: identity["specSha256"],
            GOOGLE_LABEL_DATA_COMPAT: identity["dataCompatibilitySha256"],
        }

    def _google_label_args(self) -> list[str]:
        return [
            argument
            for key, value in sorted(self._google_label_values().items())
            for argument in ("--label", f"{key}={value}")
        ]
    def _runtime_image_label_args(self) -> list[str]:
        record = self.selected_runtime_image()
        values = {
            _RUNTIME_SCHEMA_LABEL: "1",
            _RUNTIME_INPUT_LABEL: str(record["inputSha256"]),
            _RUNTIME_BOOT_INPUT_LABEL: str(record["bootInputSha256"]),
            _RUNTIME_BASE_IMAGE_LABEL: str(record["baseImageId"]),
        }
        return [
            argument
            for key, value in sorted(values.items())
            for argument in ("--label", f"{key}={value}")
        ]
    def _managed_container_labels_match(self, labels: Any) -> bool:
        if not isinstance(labels, dict):
            return False
        expected = {
            **self.lease.owner_labels,
            **self._google_label_values(),
        }
        return all(labels.get(key) == value for key, value in expected.items()) and not any(
            key.startswith("dev.xenoid.google_") and key not in expected
            for key in labels
        )


    def _inspect_docker_object(
        self,
        object_type: str,
        name: str,
        *,
        timeout: Optional[float] = None,
    ) -> tuple[Optional[dict[str, Any]], Any]:
        proc = run(
            [*self.docker_base_cmd(), object_type, "inspect", name],
            env=self.docker_env(),
            timeout=timeout,
        )
        if proc.returncode != 0:
            return None, proc
        try:
            payload = json.loads(proc.stdout)
        except (TypeError, json.JSONDecodeError):
            return {}, proc
        if (
            not isinstance(payload, list)
            or len(payload) != 1
            or not isinstance(payload[0], dict)
        ):
            return {}, proc
        return payload[0], proc

    @staticmethod
    def _runtime_record_seed_contract(
        record: Mapping[str, Any],
    ) -> Optional[dict[str, Any]]:
        direct = record.get("daemonSeedContract")
        if isinstance(direct, dict):
            return dict(direct)
        inputs = record.get("inputs")
        nested = inputs.get("daemonSeedContract") if isinstance(inputs, dict) else None
        return dict(nested) if isinstance(nested, dict) else None

    @staticmethod
    def _runtime_seed_incompatibility(
        current: Mapping[str, Any],
        desired: Mapping[str, Any],
    ) -> Optional[str]:
        current_seed = RuntimeManager._runtime_record_seed_contract(current)
        desired_seed = RuntimeManager._runtime_record_seed_contract(desired)
        if current_seed is None or desired_seed is None:
            return "runtime_image_record_invalid"
        for key in ("packageName", "sharedUserId", "signingLineageSha256"):
            if current_seed.get(key) != desired_seed.get(key):
                return "daemon_seed_contract_incompatible"
        try:
            current_version = int(current_seed["versionCode"])
            desired_version = int(desired_seed["versionCode"])
        except (KeyError, TypeError, ValueError):
            return "runtime_image_record_invalid"
        if desired_version < current_version:
            return "daemon_seed_version_downgrade"
        return None

    def _daemon_live_update_matches(
        self,
        desired: Mapping[str, Any],
    ) -> dict[str, Any]:
        seed = self._runtime_record_seed_contract(desired)
        if seed is None:
            return {"ok": False, "error": "runtime_image_record_invalid"}
        package_name = str(seed.get("packageName") or "")
        apk_sha256 = str(seed.get("apkSha256") or "")
        try:
            desired_version = int(seed["versionCode"])
        except (KeyError, TypeError, ValueError):
            desired_version = -1
        if (
            package_name != "dev.xenoid.daemon"
            or re.fullmatch(r"[0-9a-f]{64}", apk_sha256) is None
            or desired_version < 0
        ):
            return {"ok": False, "error": "runtime_image_record_invalid"}
        package_path = self.adb(
            ["shell", "pm", "path", package_name],
            timeout=15,
        )
        paths = [
            line.removeprefix("package:").strip()
            for line in str(package_path.get("stdout") or "").splitlines()
            if line.startswith("package:/")
        ]
        if package_path.get("ok") is not True or len(paths) != 1:
            return {"ok": False, "error": "daemon_live_identity_unavailable"}
        digest = self.docker_exec(["sha256sum", paths[0]], timeout=15)
        digest_value = str(digest.get("stdout") or "").split(maxsplit=1)
        if (
            digest.get("ok") is not True
            or not digest_value
            or digest_value[0] != apk_sha256
        ):
            return {"ok": False, "error": "daemon_apk_digest_mismatch"}
        package = self.adb(
            ["shell", "dumpsys", "package", package_name],
            timeout=20,
        )
        output = str(package.get("stdout") or "")
        package_match = re.search(
            rf"^\s*Package \[{re.escape(package_name)}\]",
            output,
            flags=re.MULTILINE,
        )
        version_match = re.search(r"\bversionCode=([0-9]+)\b", output)
        shared_user = seed.get("sharedUserId")
        if shared_user is None:
            shared_user_match = re.search(
                r"^\s*sharedUserId=(?!null\b)\S+",
                output,
                flags=re.MULTILINE,
            ) is None
        else:
            shared = re.escape(str(shared_user))
            shared_user_match = bool(
                re.search(
                    rf"^\s*sharedUserId={shared}\s*$",
                    output,
                    flags=re.MULTILINE,
                )
                or re.search(
                    rf"^\s*sharedUser=.*\b{shared}(?:/|\b)",
                    output,
                    flags=re.MULTILINE,
                )
            )
        installed_version = int(version_match.group(1)) if version_match else -1
        ok = bool(
            package.get("ok") is True
            and package_match
            and installed_version == desired_version
            and shared_user_match
        )
        return {
            "ok": ok,
            "apkSha256": apk_sha256 if ok else None,
            "versionCode": installed_version if installed_version >= 0 else None,
            "packageName": package_name,
            "sharedUserIdMatches": shared_user_match,
            "signingLineageMatches": ok,
            **({} if ok else {"error": "daemon_seed_contract_incompatible"}),
        }

    def _container_effective_image_identity(
        self,
        container: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            desired = self.selected_runtime_image()
        except (GoogleServicesError, InstanceError, OSError, RuntimeError, ValueError) as exc:
            return {
                "ok": False,
                "error": getattr(exc, "code", "runtime_image_record_invalid"),
                "message": str(exc),
            }
        desired_id = str(desired.get("imageId") or "")
        container_id = str(container.get("Image") or "")
        result: dict[str, Any] = {
            "ok": False,
            "match": "mismatch",
            "containerImageSha256": container_id or None,
            "desiredImageSha256": desired_id or None,
            "containerInputSha256": None,
            "desiredInputSha256": desired.get("inputSha256"),
            "containerBootInputSha256": None,
            "desiredBootInputSha256": desired.get("bootInputSha256"),
        }
        if not desired_id or not container_id:
            result["error"] = "runtime_image_record_invalid"
            return result
        if container_id == desired_id:
            result.update({"ok": True, "match": "exact"})
            return result
        current_image, inspect = self._inspect_docker_object("image", container_id)
        config = (
            current_image.get("Config")
            if isinstance(current_image, dict)
            else None
        )
        labels = config.get("Labels") if isinstance(config, dict) else None
        labels = labels if isinstance(labels, dict) else {}
        current_input = str(labels.get(_RUNTIME_INPUT_LABEL) or "")
        current_boot = str(labels.get(_RUNTIME_BOOT_INPUT_LABEL) or "")
        result.update(
            {
                "returncode": inspect.returncode,
                "containerInputSha256": current_input or None,
                "containerBootInputSha256": current_boot or None,
            }
        )
        if (
            not isinstance(current_image, dict)
            or not current_image
            or labels.get(_RUNTIME_SCHEMA_LABEL) != "1"
            or re.fullmatch(r"[0-9a-f]{64}", current_input) is None
            or re.fullmatch(r"[0-9a-f]{64}", current_boot) is None
        ):
            result["error"] = "runtime_image_identity_invalid"
            return result
        current_record = self._runtime_image_builder().lookup(current_input)
        if current_record is None:
            result["error"] = "runtime_image_record_invalid"
            return result
        expected_current_labels = current_record.get("labels")
        if (
            current_record.get("imageId") != container_id
            or not isinstance(expected_current_labels, dict)
            or any(
                labels.get(key) != value
                for key, value in expected_current_labels.items()
            )
            or str(current_image.get("Architecture") or "")
            not in {"arm64", "aarch64"}
        ):
            result["error"] = "runtime_image_identity_invalid"
            return result
        incompatibility = self._runtime_seed_incompatibility(
            current_record,
            desired,
        )
        if incompatibility is not None:
            result["error"] = incompatibility
            return result
        if current_boot != desired.get("bootInputSha256"):
            result["error"] = "runtime_boot_input_mismatch"
            return result
        live = self._daemon_live_update_matches(desired)
        result["daemonLiveIdentity"] = live
        if live.get("ok") is not True:
            result["error"] = live.get(
                "error",
                "daemon_seed_contract_incompatible",
            )
            return result
        result.update({"ok": True, "match": "daemon-only"})
        return result

    def docker_network_command(self) -> list[str]:
        return [
            *self.docker_base_cmd(),
            "network",
            "create",
            "--driver",
            "bridge",
            "--opt",
            f"com.docker.network.bridge.name={self.lease.bridge_name}",
            *self._owner_label_args(),
            "--subnet",
            self.lease.ipv4_subnet,
            "--gateway",
            self.lease.ipv4_gateway,
            "--ipv6",
            "--subnet",
            self.lease.ipv6_subnet,
            "--gateway",
            self.lease.ipv6_gateway,
            self.lease.network_name,
        ]

    def _network_matches_lease(self, network: dict[str, Any]) -> bool:
        ipam = network.get("IPAM")
        configs = ipam.get("Config") if isinstance(ipam, dict) else None
        if not isinstance(configs, list):
            return False
        allocations = {
            (entry.get("Subnet"), entry.get("Gateway"))
            for entry in configs
            if isinstance(entry, dict)
        }
        expected_allocations = {
            (self.lease.ipv4_subnet, self.lease.ipv4_gateway),
            (self.lease.ipv6_subnet, self.lease.ipv6_gateway),
        }
        options = network.get("Options")
        return (
            network.get("Name") == self.lease.network_name
            and network.get("Driver") == "bridge"
            and network.get("EnableIPv6") is True
            and network.get("Labels") == self.lease.owner_labels
            and allocations == expected_allocations
            and isinstance(options, dict)
            and options.get("com.docker.network.bridge.name") == self.lease.bridge_name
        )

    def ensure_network(self) -> dict[str, Any]:
        network, _ = self._inspect_docker_object(
            "network",
            self.lease.network_name,
        )
        if network is not None:
            if network and self._network_matches_lease(network):
                return {"ok": True, "exists": True}
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "Docker network is not owned by this instance",
            }
        command = self.docker_network_command()
        proc = run(command, env=self.docker_env())
        if proc.returncode != 0:
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "Docker network creation failed",
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "command": command,
            }
        created, _ = self._inspect_docker_object("network", self.lease.network_name)
        verified = bool(created and self._network_matches_lease(created))
        return {
            "ok": verified,
            "created": True,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "command": command,
            **(
                {}
                if verified
                else {
                    "error": "resource_conflict",
                    "message": "created Docker network identity is invalid",
                }
            ),
        }

    def docker_volume_command(self) -> list[str]:
        return [
            *self.docker_base_cmd(),
            "volume",
            "create",
            *self._owner_label_args(),
            self.lease.volume_name,
        ]

    def _volume_matches_lease(self, volume: dict[str, Any]) -> bool:
        return (
            volume.get("Name") == self.lease.volume_name
            and volume.get("Driver") == "local"
            and volume.get("Labels") == self.lease.owner_labels
            and isinstance(volume.get("Mountpoint"), str)
            and str(volume.get("Mountpoint")).startswith("/")
        )

    def ensure_volume(self) -> dict[str, Any]:
        volume, _ = self._inspect_docker_object("volume", self.lease.volume_name)
        if volume is not None:
            if volume and self._volume_matches_lease(volume):
                return {"ok": True, "exists": True, "volume": volume}
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "Docker volume is not owned by this instance",
            }
        command = self.docker_volume_command()
        proc = run(command, env=self.docker_env())
        if proc.returncode != 0:
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "Docker volume creation failed",
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "command": command,
            }
        created, _ = self._inspect_docker_object("volume", self.lease.volume_name)
        verified = bool(created and self._volume_matches_lease(created))
        return {
            "ok": verified,
            "created": True,
            "volume": created,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "command": command,
            **(
                {}
                if verified
                else {
                    "error": "resource_conflict",
                    "message": "created Docker volume identity is invalid",
                }
            ),
        }

    def _engine_host_shell(self, script: str, *, timeout: int = 120) -> Any:
        if self._shared_protection_capability is not None:
            return self._shared_protection_engine_shell(
                script,
                timeout=timeout,
            )
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            command = [
                *ssh_cmd,
                shlex.join(["sudo", "-n", "sh", "-c", script]),
            ]
        elif self.should_use_colima():
            command = ["colima", "ssh", "--", "sudo", "-n", "sh", "-c", script]
        else:
            command = ["sudo", "-n", "sh", "-c", script]
        return run(command, timeout=timeout, env=self.docker_env())

    def _shared_protection_engine_shell(
        self,
        script: str,
        *,
        timeout: int = 120,
    ) -> Any:
        capability = self._shared_protection_capability
        if (
            not isinstance(capability, str)
            or _SHA256_PATTERN.fullmatch(capability) is None
        ):
            raise InstanceError(
                "shared_protection_lock_lost",
                "engine-host protection capability is unavailable",
            )
        cap_path = (
            "/run/xenoid/shared-protection-capabilities/" + capability
        )
        watchdog = (
            'cap=$1; command=$2; parent=$PPID; target=$$; '
            '(trap "" TERM; while kill -0 "$parent" 2>/dev/null '
            '&& test -f "$cap"; do sleep 0.1; done; '
            'kill -TERM -- -"$target" 2>/dev/null || true; sleep 5; '
            'kill -KILL -- -"$target" 2>/dev/null || true) & watcher=$!; '
            'set +e; sh -c "$command"; rc=$?; set -e; '
            'set -e; kill -KILL "$watcher" 2>/dev/null || true; '
            'wait "$watcher" 2>/dev/null || true; exit "$rc"'
        )
        remote = [
            "sudo",
            "-n",
            "setsid",
            "--wait",
            "sh",
            "-c",
            watchdog,
            "xenoid-protection",
            cap_path,
            script,
        ]
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            command = [*ssh_cmd, shlex.join(remote)]
        elif self.should_use_colima():
            command = ["colima", "ssh", "--", *remote]
        elif self.docker_endpoint_host().startswith("tcp://"):
            raise InstanceError(
                "shared_protection_engine_unavailable",
                "engine host transport cannot execute protection operations",
            )
        else:
            command = remote
        seconds = bounded_timeout(float(timeout)) or float(timeout)
        bounded = run_bounded(
            command,
            cwd=self.context.project_root,
            deadline=time.monotonic() + max(0.001, seconds),
            env=self.docker_env(),
            cancelled=self.cancellation_event,
            project_root=self.context.project_root,
        )
        returncode = bounded.returncode
        if returncode is None:
            returncode = (
                124
                if bounded.state == "timed_out"
                else 130
                if bounded.state == "cancelled"
                else 1
            )
        stderr = bounded.stderr_tail
        if bounded.error_code:
            stderr = (stderr + "\n" + bounded.error_code).strip()
        return subprocess.CompletedProcess(
            command,
            returncode,
            bounded.stdout_tail,
            stderr,
        )

    @staticmethod
    def _parse_engine_meminfo(raw: str) -> Optional[dict[str, int]]:
        values: dict[str, int] = {}
        for line in raw.splitlines():
            match = re.fullmatch(r"([A-Za-z_()]+):\s+([0-9]+)\s+kB", line.strip())
            if match:
                values[match.group(1)] = int(match.group(2))
        total_kib = values.get("MemTotal", 0)
        available_kib = values.get("MemAvailable", 0)
        if total_kib <= 0 or available_kib < 0:
            return None
        warning_kib = max(512 * 1024, total_kib // 10)
        return {
            "totalBytes": total_kib * 1024,
            "availableBytes": available_kib * 1024,
            "warningThresholdBytes": warning_kib * 1024,
        }

    def runtime_memory_status(
        self,
        container: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        if container is None:
            inspected, _ = self._inspect_docker_object(
                "container",
                self.lease.container_name,
            )
            container = inspected
        state = container.get("State") if isinstance(container, Mapping) else None
        oom_killed = bool(
            isinstance(state, Mapping) and state.get("OOMKilled") is True
        )
        probe = self._engine_host_shell("cat /proc/meminfo", timeout=10)
        memory = (
            self._parse_engine_meminfo(str(probe.stdout or ""))
            if probe.returncode == 0
            else None
        )
        pressure = bool(
            memory is not None
            and memory["availableBytes"] <= memory["warningThresholdBytes"]
        )
        result: dict[str, Any] = {
            "ok": not oom_killed,
            "oomKilled": oom_killed,
            "pressure": pressure,
            "deviceMemoryIsVirtual": True,
        }
        if memory is not None:
            result["engineHost"] = memory
        else:
            result["probeError"] = (
                str(probe.stderr or "").strip() or "engine host memory unavailable"
            )
        if oom_killed:
            result["error"] = "runtime_oom_killed"
            result["message"] = (
                "Android runtime was killed by Docker/VM memory pressure; "
                "increase the host or Colima memory budget, or reduce the workload"
            )
        elif pressure and memory is not None:
            result["warning"] = (
                "Docker engine host memory is low; the Android 12 GiB device "
                "identity is virtual and does not reserve host memory"
            )
        return result

    def _inspect_volume_image(
        self,
        volume: dict[str, Any],
        image_name: str = "xenoid-data.img",
    ) -> dict[str, Any]:
        mountpoint = volume.get("Mountpoint")
        if (
            volume.get("Driver") != "local"
            or not isinstance(mountpoint, str)
            or not mountpoint.startswith("/")
            or "\n" in mountpoint
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", image_name) is None
        ):
            return {
                "ok": False,
                "error": "storage_image_invalid",
                "message": "Docker volume mountpoint is invalid",
            }
        path = f"{mountpoint.rstrip('/')}/{image_name}"
        quoted = shlex.quote(path)
        command = (
            f"set -eu; p={quoted}; "
            "[ -f \"$p\" ] && [ ! -L \"$p\" ] && [ -s \"$p\" ]; "
            "[ \"$(blkid -p -s TYPE -o value -- \"$p\" 2>/dev/null)\" = ext4 ]; "
            "set -- $(tune2fs -l \"$p\" 2>/dev/null | awk -F: "
            "'/Block count:/ {gsub(/[[:space:]]/,\"\",$2); c=$2} "
            "/Block size:/ {gsub(/[[:space:]]/,\"\",$2); s=$2} END {print c,s}'); "
            "[ \"$#\" -eq 2 ] && [ \"$1\" -gt 0 ] && [ \"$2\" -gt 0 ]; "
            "fs_bytes=$(($1 * $2)); "
            "set -- $(df -B1 --output=size,avail \"$p\" | awk 'NR==2 {print $1,$2}'); "
            "[ \"$#\" -eq 2 ] && [ \"$1\" -gt 0 ] && [ \"$2\" -ge 0 ]; "
            "printf 'XENOID_DATA_UUID=%s\\n' "
            "\"$(blkid -p -s UUID -o value -- \"$p\" | tr A-F a-f)\"; "
            "printf 'XENOID_DATA_LOGICAL_SIZE=%s\\n' \"$(stat -c %s -- \"$p\")\"; "
            "printf 'XENOID_DATA_FILESYSTEM_SIZE=%s\\n' \"$fs_bytes\"; "
            "printf 'XENOID_DATA_ALLOCATED_SIZE=%s\\n' "
            "\"$(( $(stat -c %b -- \"$p\") * 512 ))\"; "
            "printf 'XENOID_DATA_BACKING_TOTAL=%s\\n' \"$1\"; "
            "printf 'XENOID_DATA_BACKING_AVAILABLE=%s\\n' \"$2\""
        )
        proc = self._engine_host_shell(command)
        if proc.returncode != 0:
            return {
                "ok": False,
                "error": "storage_image_invalid",
                "message": "persistent data image is missing or invalid",
                "returncode": proc.returncode,
            }
        try:
            geometry = parse_storage_result(proc.stdout)
        except StorageError as exc:
            return exc.as_dict()
        warning_threshold = max(
            5 * 1024 * 1024 * 1024,
            geometry["backingTotalBytes"] // 10,
        )
        pressure = geometry["backingAvailableBytes"] <= warning_threshold
        return {
            "ok": True,
            **geometry,
            "image": image_name,
            "backingPressure": pressure,
            **(
                {
                    "warning": (
                        "Docker backing storage is low; free host or VM disk space "
                        "before write-heavy Android workloads"
                    )
                }
                if pressure
                else {}
            ),
        }

    def _run_storage_image_action(
        self,
        action: str,
        *,
        expected_uuid: str = "",
        transaction_id: str = "",
        legacy_volume: str = "",
        backup_image: str = "",
        backup_uuid: str = "",
        expected_rootfs_uuid: str = "",
    ) -> dict[str, Any]:
        try:
            runtime_image = self.selected_runtime_image()
        except (GoogleServicesError, InstanceError, OSError, RuntimeError, ValueError) as exc:
            return {
                "ok": False,
                "error": getattr(exc, "code", "runtime_image_required"),
                "message": str(exc),
            }
        script = self.context.project_root / "scripts" / "make-rootfs-image.sh"
        command = [
            str(script),
            str(runtime_image["derivedTag"]),
            self.lease.volume_name,
            "3072",
            str(CANONICAL_DATA_SIZE_BYTES),
            action,
            expected_uuid or "-",
            transaction_id or "-",
            legacy_volume or "-",
            backup_image or "-",
            backup_uuid or "-",
            self.cfg.google_services_provider,
            expected_rootfs_uuid or "-",
        ]
        env = self.docker_env()
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            env["XENOID_ENGINE_SSH"] = ssh_cmd[-1]
            if "-p" in ssh_cmd:
                env["XENOID_ENGINE_SSH_PORT"] = ssh_cmd[ssh_cmd.index("-p") + 1]
        proc = run(command, timeout=1800, env=env)
        result: dict[str, Any] = {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "runtimeImage": {
                "imageId": runtime_image["imageId"],
                "inputSha256": runtime_image["inputSha256"],
                "bootInputSha256": runtime_image["bootInputSha256"],
            },
        }
        if proc.returncode != 0:
            storage_failure = 41 <= proc.returncode <= 60
            capacity_failure = proc.returncode == 61
            backing_full = proc.returncode == 62 or "No space left on device" in (
                f"{proc.stdout}\n{proc.stderr}"
            )
            result.update({
                "error": (
                    "storage_backing_full"
                    if backing_full
                    else (
                        "storage_image_invalid"
                        if storage_failure
                        else (
                            "rootfs_capacity_insufficient"
                            if capacity_failure
                            else "rootfs_image_build_failed"
                        )
                    )
                ),
                "message": (
                    "Docker backing filesystem is full; free host or VM disk space"
                    if backing_full
                    else (
                        "persistent data image operation failed"
                        if storage_failure
                        else (
                            "generated rootfs capacity is insufficient"
                            if capacity_failure
                            else "rootfs image preparation failed"
                        )
                    )
                ),
            })
            return result
        try:
            geometry = parse_storage_result(proc.stdout, require_rootfs=True)
        except StorageError as exc:
            return {**result, **exc.as_dict(), "ok": False}
        try:
            verified_runtime = self.selected_runtime_image(refresh=True)
        except (GoogleServicesError, InstanceError, OSError, RuntimeError, ValueError) as exc:
            return {
                **result,
                "ok": False,
                "error": getattr(exc, "code", "runtime_image_input_changed"),
                "message": "runtime image identity changed during rootfs preparation",
            }
        if verified_runtime.get("imageId") != runtime_image.get("imageId"):
            return {
                **result,
                "ok": False,
                "error": "runtime_image_input_changed",
                "message": "runtime image identity changed during rootfs preparation",
            }
        result.update({
            **geometry,
            "action": action,
        })
        return result

    def _run_storage_identity_rotation(
        self,
        expected_uuid: str,
        *,
        target_uuid: str,
        expected_rootfs_source_sha256: str,
        expected_rootfs_size_bytes: int,
        expected_rootfs_uuid: str,
        target_rootfs_uuid: str,
    ) -> dict[str, Any]:
        script = self.context.project_root / "scripts" / "rotate-storage-identity.sh"
        command = [
            str(script),
            self.lease.volume_name,
            expected_uuid,
            target_uuid,
            expected_rootfs_uuid,
            expected_rootfs_source_sha256,
            str(expected_rootfs_size_bytes),
            target_rootfs_uuid,
        ]
        env = self.docker_env()
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            env["XENOID_ENGINE_SSH"] = ssh_cmd[-1]
            if "-p" in ssh_cmd:
                env["XENOID_ENGINE_SSH_PORT"] = ssh_cmd[ssh_cmd.index("-p") + 1]
        proc = run(command, timeout=1800, env=env)
        result: dict[str, Any] = {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
        }
        if proc.returncode != 0:
            result["error"] = (
                "storage_identity_mismatch"
                if proc.returncode == 42
                else (
                    "storage_image_invalid"
                    if proc.returncode in (41, 58, 59, 60, 63)
                    else "storage_rotation_failed"
                )
            )
            result["message"] = (
                "data image identity matches neither the pending expectation nor the rotation target"
                if proc.returncode == 42
                else "instance storage identity rotation failed"
            )
            return result
        try:
            geometry = parse_storage_result(proc.stdout, require_rootfs=True)
        except StorageError as exc:
            return {**result, **exc.as_dict(), "ok": False}
        rotated = any(
            line.strip() == "XENOID_DATA_ROTATED=1" for line in proc.stdout.splitlines()
        )
        result.update({**geometry, "rotated": rotated})
        return result

    def complete_legacy_pending_storage(
        self,
        legacy_evidence_sha256: str,
    ) -> dict[str, Any]:
        """Finish only an already-recorded v1 storage transition."""
        journal = RegenerationJournal(self.context)
        try:
            if journal.legacy_source_digest() != legacy_evidence_sha256:
                raise StorageError(
                    "device_regeneration_state_invalid",
                    "legacy evidence digest mismatch",
                )
            store = StorageStateStore(self.context, self.lease)
            state = store.load()
            if state is None:
                raise StorageError(
                    "storage_not_initialized",
                    "legacy storage state is missing",
                )
            if state["state"] == "committed":
                return {"ok": True, "completed": False}
            if (
                state["temporaryImage"] != ""
                or not state["rotationTargetUuid"]
            ):
                raise StorageError(
                    "storage_identity_mismatch",
                    "legacy pending storage is not a rotation window",
                )
            volume, _ = self._inspect_docker_object(
                "volume",
                self.lease.volume_name,
            )
            data = (
                self._inspect_volume_image(dict(volume))
                if isinstance(volume, Mapping)
                else {}
            )
            rootfs = (
                self._inspect_volume_image(
                    dict(volume),
                    image_name=ROOTFS_IMAGE_NAME,
                )
                if isinstance(volume, Mapping)
                else {}
            )
            if (
                data.get("ok") is not True
                or rootfs.get("ok") is not True
                or data.get("filesystemUuid")
                not in {
                    state["filesystemUuid"],
                    state["rotationTargetUuid"],
                }
            ):
                raise StorageError(
                    "storage_identity_mismatch",
                    "legacy storage matches neither old nor target",
                )
            data_uuid = str(data["filesystemUuid"])
            rootfs_uuid = str(rootfs["filesystemUuid"])
            migrated = self._run_storage_image_action(
                "preserve",
                expected_uuid=data_uuid,
                transaction_id=str(state["transactionId"]),
                expected_rootfs_uuid=rootfs_uuid,
            )
            if migrated.get("ok") is not True:
                return {
                    "ok": False,
                    "error": str(
                        migrated.get("error")
                        or "storage_v4_migration_failed"
                    ),
                }
            normalized = store.pending(
                str(state["source"]),
                transaction_id=str(state["transactionId"]),
                filesystem_uuid=data_uuid,
                observed_logical_size_bytes=int(migrated["logicalSizeBytes"]),
                observed_filesystem_size_bytes=int(
                    migrated["filesystemSizeBytes"]
                ),
                host_allocated_bytes=int(migrated["allocatedBytes"]),
                rootfs_image=ROOTFS_IMAGE_NAME,
                rootfs_filesystem_uuid=rootfs_uuid,
                rootfs_source_sha256=str(migrated["rootfsSourceSha256"]),
                observed_rootfs_size_bytes=int(migrated["rootfsSizeBytes"]),
                legacy_volume=str(state["legacyVolume"]),
                legacy_filesystem_uuid=str(state["legacyFilesystemUuid"]),
                backup_image=str(state["backupImage"]),
                backup_filesystem_uuid=str(state["backupFilesystemUuid"]),
                backup_size_bytes=int(state["backupSizeBytes"]),
                backup_rootfs_image=str(
                    migrated.get("backupRootfsImage") or ""
                ),
                backup_rootfs_filesystem_uuid=str(
                    migrated.get("backupRootfsFilesystemUuid") or ""
                ),
                backup_rootfs_size_bytes=int(
                    migrated.get("backupRootfsSizeBytes") or 0
                ),
                growth=True,
            )
            committed = store.commit(normalized, migrated)
            committed = self._cleanup_committed_rootfs_backup(
                store,
                committed,
            )
            return {
                "ok": True,
                "completed": True,
                "dataUuid": committed["filesystemUuid"],
                "rootfsUuid": committed["rootfsFilesystemUuid"],
            }
        except (IdentityError, StorageError) as exc:
            return exc.as_dict()


    def rotate_storage_identity(
        self,
        *,
        transaction_id: str,
        data_target_uuid: str,
        rootfs_target_uuid: str,
        expected_data_uuid: str,
        expected_rootfs_uuid: str,
        regeneration_capability: Any = None,
    ) -> dict[str, Any]:
        """Converge both persistent ext4 identities to journal-pinned targets."""
        self.ensure_instance_lease()
        journal = RegenerationJournal(self.context)
        try:
            regeneration = journal.load()
            if regeneration is not None:
                regeneration = journal.require_capability(regeneration_capability)
                target = regeneration["target"]
                if (
                    transaction_id != target["storageTransactionId"]
                    or data_target_uuid != target["dataFilesystemUuid"]
                    or rootfs_target_uuid != target["rootfsFilesystemUuid"]
                ):
                    raise IdentityError(
                        "device_regeneration_state_invalid",
                        "storage targets do not match the regeneration journal",
                    )
            elif regeneration_capability is not None:
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "regeneration capability has no journal",
                )
        except IdentityError as exc:
            return exc.as_dict()
        container, error = self._owned_container_record()
        if container is not None:
            return {
                "ok": False,
                "error": "storage_rotation_requires_stop",
                "message": "the owned Android container must be absent before storage identity rotation",
            }
        if error != "instance container does not exist":
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": error,
            }
        store = StorageStateStore(self.context, self.lease)
        try:
            state = store.load()
            if (
                isinstance(state, Mapping)
                and state.get("state") == "pending"
                and state.get("temporaryImage") == ""
                and not state.get("rootfsFilesystemUuid")
                and isinstance(regeneration, Mapping)
                and regeneration.get("legacyEvidenceSha256") is not None
            ):
                volume, _ = self._inspect_docker_object(
                    "volume",
                    self.lease.volume_name,
                )
                observed_data = (
                    self._inspect_volume_image(dict(volume))
                    if isinstance(volume, Mapping)
                    else {}
                )
                observed_rootfs = (
                    self._inspect_volume_image(
                        dict(volume),
                        image_name=ROOTFS_IMAGE_NAME,
                    )
                    if isinstance(volume, Mapping)
                    else {}
                )
                if (
                    observed_data.get("ok") is not True
                    or observed_rootfs.get("ok") is not True
                    or observed_data.get("filesystemUuid")
                    != expected_data_uuid
                    or observed_rootfs.get("filesystemUuid")
                    != expected_rootfs_uuid
                ):
                    raise StorageError(
                        "storage_identity_mismatch",
                        "legacy pending storage differs from its v2 snapshot",
                    )
                migrated = self._run_storage_image_action(
                    "preserve",
                    expected_uuid=expected_data_uuid,
                    transaction_id=str(state["transactionId"]),
                    expected_rootfs_uuid=expected_rootfs_uuid,
                )
                if migrated.get("ok") is not True:
                    return {
                        "ok": False,
                        "error": str(
                            migrated.get("error")
                            or "storage_v4_migration_failed"
                        ),
                    }
                migrated_backup = str(
                    migrated.get("backupRootfsImage") or ""
                )
                if migrated_backup:
                    expected_backup = (
                        f"{ROOTFS_IMAGE_NAME}.pre-source-"
                        f"{state['transactionId']}"
                    )
                    if migrated_backup != expected_backup:
                        raise StorageError(
                            "storage_state_invalid",
                            "legacy rootfs backup owner is invalid",
                        )
                    mountpoint = (
                        volume.get("Mountpoint")
                        if isinstance(volume, Mapping)
                        else None
                    )
                    if not isinstance(mountpoint, str):
                        raise StorageError(
                            "storage_image_invalid",
                            "legacy rootfs backup path is unavailable",
                        )
                    backup_path = (
                        f"{mountpoint.rstrip('/')}/{migrated_backup}"
                    )
                    cleanup = self._engine_host_shell(
                        "set -eu; p="
                        + shlex.quote(backup_path)
                        + "; if [ ! -e \"$p\" ]; then exit 0; fi; "
                        + "[ -f \"$p\" ] && [ ! -L \"$p\" ]; "
                        + "[ \"$(blkid -p -s UUID -o value -- \"$p\" | tr A-F a-f)\" = "
                        + shlex.quote(
                            str(migrated["backupRootfsFilesystemUuid"])
                        )
                        + " ]; [ \"$(stat -c %s -- \"$p\")\" = "
                        + shlex.quote(
                            str(migrated["backupRootfsSizeBytes"])
                        )
                        + " ]; rm -- \"$p\"; sync -f "
                        + shlex.quote(mountpoint)
                    )
                    if cleanup.returncode != 0:
                        raise StorageError(
                            "storage_image_invalid",
                            "legacy rootfs backup cleanup failed",
                        )
                state = store.pending(
                    str(state["source"]),
                    transaction_id=transaction_id,
                    filesystem_uuid=expected_data_uuid,
                    observed_logical_size_bytes=int(
                        migrated["logicalSizeBytes"]
                    ),
                    observed_filesystem_size_bytes=int(
                        migrated["filesystemSizeBytes"]
                    ),
                    host_allocated_bytes=int(migrated["allocatedBytes"]),
                    rootfs_image=ROOTFS_IMAGE_NAME,
                    rootfs_filesystem_uuid=expected_rootfs_uuid,
                    rootfs_source_sha256=str(
                        migrated["rootfsSourceSha256"]
                    ),
                    observed_rootfs_size_bytes=int(
                        migrated["rootfsSizeBytes"]
                    ),
                    legacy_volume=str(state["legacyVolume"]),
                    legacy_filesystem_uuid=str(
                        state["legacyFilesystemUuid"]
                    ),
                    backup_image=str(state["backupImage"]),
                    backup_filesystem_uuid=str(
                        state["backupFilesystemUuid"]
                    ),
                    backup_size_bytes=int(state["backupSizeBytes"]),
                    growth=True,
                    backup_rootfs_image="",
                    backup_rootfs_filesystem_uuid="",
                    backup_rootfs_size_bytes=0,
                    rotation_target_uuid=data_target_uuid,
                    rotation_target_rootfs_uuid=rootfs_target_uuid,
                )
            if (
                isinstance(state, Mapping)
                and state.get("state") == "committed"
                and not state.get("rootfsFilesystemUuid")
                and isinstance(regeneration, Mapping)
                and regeneration.get("legacyEvidenceSha256") is not None
            ):
                migrated = self.ensure_instance_storage()
                if migrated.get("ok") is not True:
                    return {
                        "ok": False,
                        "error": str(
                            migrated.get("error")
                            or "storage_v4_migration_failed"
                        ),
                    }
                state = store.load()
                if (
                    not isinstance(state, Mapping)
                    or state.get("rootfsFilesystemUuid")
                    != expected_rootfs_uuid
                ):
                    raise StorageError(
                        "storage_identity_mismatch",
                        "v3 rootfs migration changed the recorded identity",
                    )
            if (
                state is None
                or state["state"] == "pending"
                and state["temporaryImage"]
                or not state.get("rootfsFilesystemUuid")
                or not state.get("rootfsSourceSha256")
            ):
                raise StorageError(
                    "storage_not_initialized",
                    "instance data/rootfs storage is not committed",
                )
            if state["state"] == "committed":
                state = self._cleanup_committed_rootfs_backup(store, state)
                if (
                    state["filesystemUuid"] == data_target_uuid
                    and state["rootfsFilesystemUuid"] == rootfs_target_uuid
                ):
                    state = self._cleanup_committed_rootfs_backup(store, state)
                    return {
                        "ok": True,
                        "rotated": False,
                        "filesystemUuid": data_target_uuid,
                        "rootfsFilesystemUuid": rootfs_target_uuid,
                        "previousFilesystemUuid": expected_data_uuid,
                        "previousRootfsFilesystemUuid": expected_rootfs_uuid,
                    }
                if (
                    state["filesystemUuid"] != expected_data_uuid
                    or state["rootfsFilesystemUuid"] != expected_rootfs_uuid
                ):
                    raise StorageError(
                        "storage_identity_mismatch",
                        "storage matches neither regeneration before nor target",
                    )
                pending = store.pending(
                    str(state["source"]),
                    transaction_id=transaction_id,
                    filesystem_uuid=str(state["filesystemUuid"]),
                    observed_logical_size_bytes=int(state["observedLogicalSizeBytes"]),
                    observed_filesystem_size_bytes=int(state["observedFilesystemSizeBytes"]),
                    host_allocated_bytes=int(state["hostAllocatedBytes"]),
                    rootfs_image=str(state["rootfsImage"]),
                    rootfs_filesystem_uuid=str(state["rootfsFilesystemUuid"]),
                    rootfs_source_sha256=str(state["rootfsSourceSha256"]),
                    observed_rootfs_size_bytes=int(state["observedRootfsSizeBytes"]),
                    legacy_volume=str(state["legacyVolume"]),
                    legacy_filesystem_uuid=str(state["legacyFilesystemUuid"]),
                    backup_image=str(state["backupImage"]),
                    backup_filesystem_uuid=str(state["backupFilesystemUuid"]),
                    backup_size_bytes=int(state["backupSizeBytes"]),
                    backup_rootfs_image=str(state["backupRootfsImage"]),
                    backup_rootfs_filesystem_uuid=str(
                        state["backupRootfsFilesystemUuid"]
                    ),
                    backup_rootfs_size_bytes=int(state["backupRootfsSizeBytes"]),
                    growth=True,
                    rotation_target_uuid=data_target_uuid,
                    rotation_target_rootfs_uuid=rootfs_target_uuid,
                )
            else:
                if (
                    state["transactionId"] != transaction_id
                    or state["filesystemUuid"] != expected_data_uuid
                    or state["rootfsFilesystemUuid"] != expected_rootfs_uuid
                    or state["rotationTargetUuid"] != data_target_uuid
                    or state["rotationTargetRootfsUuid"] != rootfs_target_uuid
                ):
                    raise StorageError(
                        "storage_identity_mismatch",
                        "pending storage rotation does not match the fixed transaction",
                    )
                pending = state
        except StorageError as exc:
            return exc.as_dict()
        action = self._run_storage_identity_rotation(
            str(pending["filesystemUuid"]),
            target_uuid=str(pending["rotationTargetUuid"]),
            expected_rootfs_uuid=str(pending["rootfsFilesystemUuid"]),
            expected_rootfs_source_sha256=str(pending["rootfsSourceSha256"]),
            expected_rootfs_size_bytes=int(pending["observedRootfsSizeBytes"]),
            target_rootfs_uuid=str(pending["rotationTargetRootfsUuid"]),
        )
        if not action.get("ok"):
            return action
        try:
            committed = store.commit(pending, action)
            committed = self._cleanup_committed_rootfs_backup(store, committed)
        except (StorageError, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, StorageError):
                return exc.as_dict()
            return {
                "ok": False,
                "error": "storage_state_invalid",
                "message": "rotated storage observations are incomplete",
            }
        return {
            "ok": True,
            "rotated": action["rotated"],
            "filesystemUuid": committed["filesystemUuid"],
            "rootfsFilesystemUuid": committed["rootfsFilesystemUuid"],
            "previousFilesystemUuid": pending["filesystemUuid"],
            "previousRootfsFilesystemUuid": pending["rootfsFilesystemUuid"],
            "imageAction": action,
        }

    def _run_boot_identity_seed(self, boot_id: str, random_uuid: str) -> dict[str, Any]:
        script = self.context.project_root / "scripts" / "seed-boot-identity.sh"
        command = [str(script), self.lease.volume_name, boot_id, random_uuid]
        env = self.docker_env()
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            env["XENOID_ENGINE_SSH"] = ssh_cmd[-1]
            if "-p" in ssh_cmd:
                env["XENOID_ENGINE_SSH_PORT"] = ssh_cmd[ssh_cmd.index("-p") + 1]
        proc = run(command, timeout=900, env=env)
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "skipped": "XENOID_BOOT_SEED=skipped" in proc.stdout,
        }

    def _seed_boot_identity_into_image(self) -> dict[str, Any]:
        """Pre-seed boot-scoped identity into the data image of a container that
        is about to be created, so the zygote boot snapshot matches the values
        the identity store applies after boot (single writer for all recreates).
        """
        store = DeviceIdentityStore(self.context)
        try:
            state = store.load()
            if state is None:
                return {"ok": True, "skipped": True, "reason": "device_identity_uninitialized"}
            seeded = store.seed_next_boot()
        except IdentityError as exc:
            return exc.as_dict()
        result = self._run_boot_identity_seed(str(seeded["bootId"]), str(seeded["randomUuid"]))
        if not result.get("ok"):
            return {
                "ok": False,
                "error": "device_boot_seed_failed",
                "message": "cannot pre-seed boot identity into the persistent data image",
                "imageAction": result,
            }
        return {"ok": True, "skipped": bool(result.get("skipped"))}

    def _legacy_engine_record(self) -> Optional[dict[str, str]]:
        path = self.context.state_root / "legacy-engine.json"
        try:
            info = path.lstat()
            if not path.is_file() or info.st_mode & 0o077:
                raise StorageError(
                    "storage_legacy_invalid",
                    "legacy engine state permissions are unsafe",
                )
            raw = json.loads(path.read_text())
        except FileNotFoundError:
            return None
        except StorageError:
            raise
        except (OSError, ValueError, UnicodeError) as exc:
            raise StorageError(
                "storage_legacy_invalid",
                "legacy engine state is invalid",
            ) from exc
        if not isinstance(raw, dict):
            raise StorageError("storage_legacy_invalid", "legacy engine state is invalid")
        volume_name = raw.get("android_data_volume")
        container_name = raw.get("container_name", "")
        pattern = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"
        if (
            not isinstance(volume_name, str)
            or re.fullmatch(pattern, volume_name) is None
            or not isinstance(container_name, str)
            or (container_name and re.fullmatch(pattern, container_name) is None)
        ):
            raise StorageError("storage_legacy_invalid", "legacy engine identity is invalid")
        if volume_name == self.lease.volume_name:
            return None
        return {"volumeName": volume_name, "containerName": container_name}

    def _volume_attachments(
        self,
        volume_name: str,
    ) -> tuple[Optional[list[tuple[str, str]]], dict[str, Any]]:
        proc = run(
            [
                *self.docker_base_cmd(),
                "ps",
                "-a",
                "--filter",
                f"volume={volume_name}",
                "--format",
                "{{.ID}}\t{{.Names}}",
            ],
            env=self.docker_env(),
        )
        if proc.returncode != 0:
            return None, {
                "ok": False,
                "error": "engine_unavailable",
                "message": "cannot inspect legacy volume attachments",
            }
        rows: list[tuple[str, str]] = []
        for line in proc.stdout.splitlines():
            parts = line.split("\t", 1)
            if len(parts) != 2 or not parts[0] or not parts[1]:
                return None, {
                    "ok": False,
                    "error": "storage_legacy_invalid",
                    "message": "legacy volume attachment identity is invalid",
                }
            rows.append((parts[0], parts[1]))
        return rows, {"ok": True}

    def _storage_error(self, code: str, message: str, **details: Any) -> dict[str, Any]:
        return {"ok": False, "error": code, "message": message, **details}

    def _cleanup_committed_rootfs_backup(
        self,
        store: StorageStateStore,
        state: Mapping[str, Any],
    ) -> dict[str, Any]:
        backup = state.get("backupRootfsImage")
        if not isinstance(backup, str) or not backup:
            return dict(state)
        volume, _ = self._inspect_docker_object("volume", self.lease.volume_name)
        mountpoint = volume.get("Mountpoint") if isinstance(volume, Mapping) else None
        if not isinstance(mountpoint, str) or not mountpoint.startswith("/"):
            raise StorageError(
                "storage_image_invalid",
                "cannot locate committed rootfs backup",
            )
        rootfs = self._inspect_volume_image(
            dict(volume),
            image_name=ROOTFS_IMAGE_NAME,
        )
        source_marker = self._engine_host_shell(
            "cat "
            + shlex.quote(
                f"{mountpoint.rstrip('/')}/xenoid-rootfs.img.source.sha256"
            )
        )
        if (
            rootfs.get("ok") is not True
            or rootfs.get("filesystemUuid") != state["rootfsFilesystemUuid"]
            or rootfs.get("logicalSizeBytes") != state["observedRootfsSizeBytes"]
            or source_marker.returncode != 0
            or str(source_marker.stdout or "").strip()
            != state["rootfsSourceSha256"]
        ):
            raise StorageError(
                "storage_identity_mismatch",
                "committed rootfs changed before backup cleanup",
            )
        path = f"{mountpoint.rstrip('/')}/{backup}"
        command = (
            "set -eu; p="
            + shlex.quote(path)
            + "; if [ ! -e \"$p\" ]; then exit 0; fi; "
            + "[ -f \"$p\" ] && [ ! -L \"$p\" ] && [ -s \"$p\" ]; "
            + "[ \"$(blkid -p -s TYPE -o value -- \"$p\")\" = ext4 ]; "
            + "[ \"$(blkid -p -s UUID -o value -- \"$p\" | tr A-F a-f)\" = "
            + shlex.quote(str(state["backupRootfsFilesystemUuid"]))
            + " ]; [ \"$(stat -c %s -- \"$p\")\" = "
            + shlex.quote(str(state["backupRootfsSizeBytes"]))
            + " ]; rm -- \"$p\"; sync -f "
            + shlex.quote(mountpoint)
        )
        removed = self._engine_host_shell(command)
        if removed.returncode != 0:
            raise StorageError(
                "storage_image_invalid",
                "committed rootfs backup cleanup failed",
            )
        return store.clear_rootfs_backup(state)

    def _storage_growth_container(
        self,
    ) -> tuple[Optional[dict[str, Any]], dict[str, Any]]:
        attachments, status = self._volume_attachments(self.lease.volume_name)
        if attachments is None:
            return None, status
        if not attachments:
            return None, {"ok": True, "attached": False}
        if (
            len(attachments) != 1
            or attachments[0][1] != self.lease.container_name
        ):
            return None, self._storage_error(
                "storage_foreign_attachment",
                "data volume has a foreign container attachment",
                attachments=[
                    {"id": container_id, "name": name}
                    for container_id, name in attachments
                ],
            )
        container, _ = self._inspect_docker_object(
            "container",
            attachments[0][0],
        )
        if (
            not isinstance(container, dict)
            or not container
            or not self._container_has_lease_owner(container)
        ):
            return None, self._storage_error(
                "storage_foreign_attachment",
                "attached container is not owned by this instance",
            )
        return container, {"ok": True, "attached": True}

    def _converge_storage_growth(
        self,
        store: StorageStateStore,
        state: Mapping[str, Any],
        image: Mapping[str, Any],
    ) -> dict[str, Any]:
        container, attachment = self._storage_growth_container()
        if attachment.get("ok") is not True:
            return attachment
        proxy = (
            self._capture_proxy_desired_for_update()
            if container is not None
            else {"ok": True, "captured": False, "configured": False}
        )
        if proxy.get("ok") is not True:
            return self._storage_error(
                "proxy_state_backup_failed",
                "cannot preserve proxy desired state before storage growth",
                proxyDesired=proxy,
            )
        try:
            if state["state"] == "committed":
                pending = store.pending(
                    str(state["source"]),
                    filesystem_uuid=str(image["filesystemUuid"]),
                    observed_logical_size_bytes=int(image["logicalSizeBytes"]),
                    observed_filesystem_size_bytes=int(image["filesystemSizeBytes"]),
                    host_allocated_bytes=int(image["allocatedBytes"]),
                    rootfs_image=str(state["rootfsImage"]),
                    rootfs_filesystem_uuid=str(state["rootfsFilesystemUuid"]),
                    rootfs_source_sha256=str(state["rootfsSourceSha256"]),
                    observed_rootfs_size_bytes=int(state["observedRootfsSizeBytes"]),
                    legacy_volume=str(state["legacyVolume"]),
                    legacy_filesystem_uuid=str(state["legacyFilesystemUuid"]),
                    backup_image=str(state["backupImage"]),
                    backup_filesystem_uuid=str(state["backupFilesystemUuid"]),
                    backup_size_bytes=int(state["backupSizeBytes"]),
                    backup_rootfs_image=str(state["backupRootfsImage"]),
                    backup_rootfs_filesystem_uuid=str(
                        state["backupRootfsFilesystemUuid"]
                    ),
                    backup_rootfs_size_bytes=int(state["backupRootfsSizeBytes"]),
                    growth=True,
                )
            else:
                pending = dict(state)
        except (StorageError, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, StorageError):
                return exc.as_dict()
            return self._storage_error(
                "storage_state_invalid",
                "cannot begin storage growth transaction",
            )
        removal: dict[str, Any] = {
            "ok": True,
            "skipped": True,
            "reason": "data volume is detached",
        }
        if container is not None:
            removal = self._remove_owned_container(container)
            if removal.get("ok") is not True:
                return self._storage_error(
                    str(removal.get("error") or "container_remove_failed"),
                    "owned container could not be removed for storage growth",
                    storage=public_storage_state(
                        pending,
                        healthy=False,
                        error="storage_transaction_pending",
                    ),
                    containerRemoval=removal,
                )
        action = self._run_storage_image_action(
            "grow",
            expected_uuid=str(pending["filesystemUuid"]),
            transaction_id=str(pending["transactionId"]),
            expected_rootfs_uuid=str(pending["rootfsFilesystemUuid"]),
        )
        if (
            action.get("ok") is not True
            or action.get("filesystemUuid") != pending["filesystemUuid"]
            or action.get("logicalSizeBytes") != CANONICAL_DATA_SIZE_BYTES
            or action.get("filesystemSizeBytes") != CANONICAL_DATA_SIZE_BYTES
        ):
            code = str(action.get("error") or "storage_identity_mismatch")
            return self._storage_error(
                code,
                str(action.get("message") or "data image growth verification failed"),
                storage=public_storage_state(pending, healthy=False, error=code),
                imageAction=action,
                containerRemoval=removal,
            )
        try:
            committed = store.commit(pending, action)
            committed = self._cleanup_committed_rootfs_backup(store, committed)
        except (StorageError, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, StorageError):
                return exc.as_dict()
            return self._storage_error(
                "storage_state_invalid",
                "cannot commit storage growth transaction",
            )
        return {
            "ok": True,
            "volume": {"ok": True, "exists": True},
            "proxyDesiredBeforeGrowth": proxy,
            "containerRemoval": removal,
            "imageAction": action,
            "storage": public_storage_state(committed, healthy=True),
        }

    def ensure_instance_storage(
        self,
        *,
        expected_data_uuid: Optional[str] = None,
        expected_rootfs_uuid: Optional[str] = None,
        storage_transaction_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Converge rootfs plus the one persistent, never-silently-replaced data image."""
        self.ensure_instance_lease()
        pinned_data_uuid = expected_data_uuid
        pinned_rootfs_uuid = expected_rootfs_uuid
        if storage_transaction_id is not None and re.fullmatch(
            r"[0-9a-f]{32}",
            storage_transaction_id,
        ) is None:
            return self._storage_error(
                "storage_state_invalid",
                "storage transaction identity is invalid",
            )
        store = StorageStateStore(self.context, self.lease)
        try:
            state = store.load()
            legacy = self._legacy_engine_record()
        except StorageError as exc:
            return exc.as_dict()
        if (
            storage_transaction_id is not None
            and isinstance(state, Mapping)
            and state.get("state") == "pending"
            and state.get("source") == "fresh"
            and state.get("transactionId") != storage_transaction_id
        ):
            return self._storage_error(
                "storage_identity_mismatch",
                "pending fresh storage uses a different journal transaction",
            )

        volume, _ = self._inspect_docker_object("volume", self.lease.volume_name)
        if volume == {}:
            return self._storage_error(
                "resource_conflict",
                "Docker volume inspection returned invalid identity",
            )
        if volume is not None and not self._volume_matches_lease(volume):
            return self._storage_error(
                "resource_conflict",
                "Docker volume is not owned by this instance",
            )

        if state is not None and state["state"] == "committed":
            if volume is None:
                return self._storage_error(
                    "storage_volume_missing",
                    "committed instance data volume is missing",
                    storage=public_storage_state(state, healthy=False, error="storage_volume_missing"),
                )
            image = self._inspect_volume_image(volume)
            if not image.get("ok"):
                return self._storage_error(
                    "storage_image_invalid",
                    "committed instance data image is missing or invalid",
                    storage=public_storage_state(state, healthy=False, error="storage_image_invalid"),
                    image=image,
                )
            rootfs = self._inspect_volume_image(
                volume,
                image_name=ROOTFS_IMAGE_NAME,
            )
            if rootfs.get("ok") is not True:
                return self._storage_error(
                    "storage_image_invalid",
                    "committed rootfs image is missing or invalid",
                    storage=public_storage_state(
                        state,
                        healthy=False,
                        error="storage_image_invalid",
                    ),
                    rootfs=rootfs,
                )
            if (
                pinned_rootfs_uuid is not None
                and rootfs["filesystemUuid"] != pinned_rootfs_uuid
            ):
                return self._storage_error(
                    "storage_identity_mismatch",
                    "rootfs differs from the convergence journal pin",
                )
            expected_rootfs_uuid = str(
                state["rootfsFilesystemUuid"] or rootfs["filesystemUuid"]
            )
            if (
                state["rootfsFilesystemUuid"]
                and rootfs["filesystemUuid"] != state["rootfsFilesystemUuid"]
                or state["observedRootfsSizeBytes"]
                and int(rootfs["logicalSizeBytes"])
                != int(state["observedRootfsSizeBytes"])
            ):
                return self._storage_error(
                    "storage_identity_mismatch",
                    "committed rootfs identity or geometry changed",
                    storage=public_storage_state(
                        state,
                        healthy=False,
                        error="storage_identity_mismatch",
                    ),
                    rootfs=rootfs,
                )
            if (
                pinned_data_uuid is not None
                and image["filesystemUuid"] != pinned_data_uuid
            ):
                return self._storage_error(
                    "storage_identity_mismatch",
                    "data image differs from the convergence journal pin",
                )
            if image["filesystemUuid"] != state["filesystemUuid"]:
                return self._storage_error(
                    "storage_identity_mismatch",
                    "committed data image UUID changed",
                    storage=public_storage_state(state, healthy=False, error="storage_identity_mismatch"),
                    image=image,
                )
            logical_size = int(image["logicalSizeBytes"])
            filesystem_size = int(image["filesystemSizeBytes"])
            if (
                logical_size > CANONICAL_DATA_SIZE_BYTES
                or filesystem_size > logical_size
            ):
                return self._storage_error(
                    "storage_size_unsafe",
                    "refusing to shrink an oversized or inconsistent data image",
                    storage=public_storage_state(state, healthy=False, error="storage_size_unsafe"),
                    image=image,
                )
            observations_migrated = int(state["hostAllocatedBytes"]) == 0
            observations_match = (
                logical_size == int(state["observedLogicalSizeBytes"])
                and filesystem_size == int(state["observedFilesystemSizeBytes"])
            )
            if not observations_match and not observations_migrated:
                return self._storage_error(
                    "storage_identity_mismatch",
                    "committed data image geometry changed outside its transaction",
                    storage=public_storage_state(state, healthy=False, error="storage_identity_mismatch"),
                    image=image,
                )
            if (
                logical_size < CANONICAL_DATA_SIZE_BYTES
                or filesystem_size < CANONICAL_DATA_SIZE_BYTES
            ):
                return self._converge_storage_growth(store, state, image)
            action = self._run_storage_image_action(
                "preserve",
                expected_uuid=str(state["filesystemUuid"]),
                transaction_id=str(state["transactionId"]),
                expected_rootfs_uuid=expected_rootfs_uuid,
            )
            if not action.get("ok"):
                code = str(action.get("error") or "storage_image_invalid")
                rootfs_failed = code == "rootfs_image_build_failed"
                return self._storage_error(
                    code,
                    str(action.get("message") or "instance image preparation failed"),
                    storage=public_storage_state(
                        state,
                        healthy=rootfs_failed,
                        error="" if rootfs_failed else code,
                    ),
                    imageAction=action,
                )
            if (
                action.get("filesystemUuid") != state["filesystemUuid"]
                or action.get("logicalSizeBytes") != CANONICAL_DATA_SIZE_BYTES
                or action.get("filesystemSizeBytes") != CANONICAL_DATA_SIZE_BYTES
            ):
                return self._storage_error(
                    "storage_identity_mismatch",
                    "persistent data image validation failed",
                    storage=public_storage_state(state, healthy=False, error="storage_identity_mismatch"),
                    imageAction=action,
                )
            try:
                refreshed = store.refresh(state, action)
                refreshed = self._cleanup_committed_rootfs_backup(store, refreshed)
            except (StorageError, KeyError, TypeError, ValueError) as exc:
                if isinstance(exc, StorageError):
                    return exc.as_dict()
                return self._storage_error(
                    "storage_state_invalid",
                    "cannot refresh committed storage observations",
                )
            return {
                "ok": True,
                "volume": {"ok": True, "exists": True},
                "imageAction": action,
                "storage": public_storage_state(refreshed, healthy=True),
            }

        if (
            state is not None
            and state["state"] == "pending"
            and state["temporaryImage"] == ""
        ):
            if state.get("rotationTargetUuid"):
                # An interrupted identity rotation is not an ordinary growth in
                # either window (image still old, or already at the target):
                # fail closed and let `device regenerate` resume and commit it.
                return self._storage_error(
                    "storage_identity_mismatch",
                    "interrupted storage identity rotation; re-run `./xenoid device regenerate` to resume and commit it",
                    storage=public_storage_state(
                        state,
                        healthy=False,
                        error="storage_identity_mismatch",
                    ),
                )
            if volume is None:
                return self._storage_error(
                    "storage_volume_missing",
                    "pending growth data volume is missing",
                    storage=public_storage_state(
                        state,
                        healthy=False,
                        error="storage_volume_missing",
                    ),
                )
            image = self._inspect_volume_image(volume)
            if (
                image.get("ok") is not True
                or image.get("filesystemUuid") != state["filesystemUuid"]
            ):
                return self._storage_error(
                    "storage_identity_mismatch",
                    "pending growth data image identity changed",
                    storage=public_storage_state(
                        state,
                        healthy=False,
                        error="storage_identity_mismatch",
                    ),
                    image=image,
                )
            logical_size = int(image["logicalSizeBytes"])
            filesystem_size = int(image["filesystemSizeBytes"])
            if (
                logical_size > CANONICAL_DATA_SIZE_BYTES
                or filesystem_size > logical_size
                or logical_size < int(state["observedLogicalSizeBytes"])
                or filesystem_size < int(state["observedFilesystemSizeBytes"])
            ):
                return self._storage_error(
                    "storage_size_unsafe",
                    "pending growth image was shrunk or exceeds canonical capacity",
                    storage=public_storage_state(
                        state,
                        healthy=False,
                        error="storage_size_unsafe",
                    ),
                    image=image,
                )
            return self._converge_storage_growth(store, state, image)

        if state is None and legacy is not None:
            legacy_volume, _ = self._inspect_docker_object("volume", legacy["volumeName"])
            if (
                legacy_volume is None
                or not legacy_volume
                or legacy_volume.get("Driver") != "local"
            ):
                return self._storage_error(
                    "storage_legacy_invalid",
                    "recorded legacy data volume is missing or not local",
                )
            attachments, attachment_status = self._volume_attachments(legacy["volumeName"])
            if attachments is None:
                return attachment_status
            unexpected = [
                {"id": container_id, "name": name}
                for container_id, name in attachments
                if not legacy["containerName"] or name != legacy["containerName"]
            ]
            if unexpected:
                return self._storage_error(
                    "storage_legacy_attached",
                    "legacy data volume has an unknown container attachment",
                    attachments=unexpected,
                )
            if attachments:
                removed = self._remove_legacy_container(
                    attachments[0][0],
                    legacy["containerName"],
                    legacy["volumeName"],
                )
                if not removed.get("ok"):
                    return self._storage_error(
                        "storage_legacy_attached",
                        "legacy data container could not be stopped safely",
                        removal=removed,
                    )
            source = self._inspect_volume_image(legacy_volume)
            if not source.get("ok"):
                return self._storage_error(
                    "storage_legacy_invalid",
                    "legacy data image is missing or invalid",
                    source=source,
                )
            if (
                int(source["logicalSizeBytes"]) > CANONICAL_DATA_SIZE_BYTES
                or int(source["filesystemSizeBytes"])
                > int(source["logicalSizeBytes"])
            ):
                return self._storage_error(
                    "storage_size_unsafe",
                    "legacy data image exceeds canonical capacity",
                    source=source,
                )
            backup_image = ""
            backup_uuid = ""
            backup_size = 0
            if volume is not None:
                target = self._inspect_volume_image(volume)
                if not target.get("ok"):
                    return self._storage_error(
                        "storage_image_invalid",
                        "tagged data volume exists without a valid data image",
                        target=target,
                    )
                if (
                    int(target["logicalSizeBytes"]) > CANONICAL_DATA_SIZE_BYTES
                    or int(target["filesystemSizeBytes"])
                    > int(target["logicalSizeBytes"])
                ):
                    return self._storage_error(
                        "storage_size_unsafe",
                        "tagged data image exceeds canonical capacity",
                        target=target,
                    )
                if target["filesystemUuid"] != source["filesystemUuid"]:
                    transaction = secrets.token_hex(16)
                    backup_image = backup_image_name(transaction)
                    backup_uuid = target["filesystemUuid"]
                    backup_size = int(target["logicalSizeBytes"])
                    state = store.pending(
                        "legacy",
                        transaction_id=transaction,
                        legacy_volume=legacy["volumeName"],
                        legacy_filesystem_uuid=source["filesystemUuid"],
                        backup_image=backup_image,
                        backup_filesystem_uuid=backup_uuid,
                        backup_size_bytes=backup_size,
                    )
            if state is None:
                state = store.pending(
                    "legacy",
                    legacy_volume=legacy["volumeName"],
                    legacy_filesystem_uuid=source["filesystemUuid"],
                )

        if state is None:
            if volume is None:
                state = store.pending(
                    "fresh",
                    transaction_id=storage_transaction_id,
                )
            else:
                adopted = self._inspect_volume_image(volume)
                if not adopted.get("ok"):
                    return self._storage_error(
                        "storage_uninitialized_volume",
                        "existing instance volume has no valid data image",
                        image=adopted,
                    )
                if (
                    int(adopted["logicalSizeBytes"]) > CANONICAL_DATA_SIZE_BYTES
                    or int(adopted["filesystemSizeBytes"])
                    > int(adopted["logicalSizeBytes"])
                ):
                    return self._storage_error(
                        "storage_size_unsafe",
                        "refusing to adopt an oversized or inconsistent data image",
                        image=adopted,
                    )
                state = store.pending(
                    "adopted",
                    filesystem_uuid=str(adopted["filesystemUuid"]),
                    observed_logical_size_bytes=int(adopted["logicalSizeBytes"]),
                    observed_filesystem_size_bytes=int(adopted["filesystemSizeBytes"]),
                    host_allocated_bytes=int(adopted["allocatedBytes"]),
                    growth=True,
                )
                return self._converge_storage_growth(store, state, adopted)

        if state["source"] == "legacy":
            source_volume, _ = self._inspect_docker_object(
                "volume",
                state["legacyVolume"],
            )
            if (
                source_volume is None
                or not source_volume
                or source_volume.get("Driver") != "local"
            ):
                return self._storage_error(
                    "storage_legacy_invalid",
                    "pending legacy data volume is missing or not local",
                )
            attachments, attachment_status = self._volume_attachments(
                state["legacyVolume"],
            )
            if attachments is None:
                return attachment_status
            expected_container = (
                legacy["containerName"]
                if legacy is not None
                and legacy["volumeName"] == state["legacyVolume"]
                else ""
            )
            if attachments:
                if (
                    not expected_container
                    or len(attachments) != 1
                    or attachments[0][1] != expected_container
                ):
                    return self._storage_error(
                        "storage_legacy_attached",
                        "pending legacy volume has an unknown container attachment",
                    )
                removed = self._remove_legacy_container(
                    attachments[0][0],
                    expected_container,
                    state["legacyVolume"],
                )
                if not removed.get("ok"):
                    return self._storage_error(
                        "storage_legacy_attached",
                        "pending legacy container could not be stopped safely",
                        removal=removed,
                    )
            source_image = self._inspect_volume_image(source_volume)
            if (
                not source_image.get("ok")
                or source_image.get("filesystemUuid")
                != state["legacyFilesystemUuid"]
                or int(source_image.get("logicalSizeBytes", 0))
                > CANONICAL_DATA_SIZE_BYTES
                or int(source_image.get("filesystemSizeBytes", 0))
                > int(source_image.get("logicalSizeBytes", 0))
            ):
                return self._storage_error(
                    "storage_legacy_invalid",
                    "pending legacy data image identity changed",
                    source=source_image,
                )

        if volume is None:
            created = self.ensure_volume()
            if not created.get("ok"):
                return self._storage_error(
                    "resource_conflict",
                    "instance data volume creation failed",
                    volume=created,
                )
            volume = created.get("volume")
            if not isinstance(volume, dict) or not self._volume_matches_lease(volume):
                return self._storage_error(
                    "resource_conflict",
                    "created instance data volume identity is invalid",
                )

        if state["source"] == "fresh":
            action = self._run_storage_image_action(
                "initialize",
                expected_uuid=(
                    str(state["filesystemUuid"])
                    or storage_rotation_target(str(state["transactionId"]))
                ),
                transaction_id=state["transactionId"],
                expected_rootfs_uuid=(
                    str(state["rootfsFilesystemUuid"])
                    or storage_rotation_target(
                        str(state["transactionId"]),
                        rootfs=True,
                    )
                ),
            )
        elif state["source"] == "adopted":
            adopted = self._inspect_volume_image(volume)
            if (
                adopted.get("ok") is not True
                or int(adopted.get("logicalSizeBytes", 0)) > CANONICAL_DATA_SIZE_BYTES
                or int(adopted.get("filesystemSizeBytes", 0))
                > int(adopted.get("logicalSizeBytes", 0))
            ):
                return self._storage_error(
                    "storage_image_invalid",
                    "pending adopted data image is invalid",
                    image=adopted,
                )
            try:
                state = store.pending(
                    "adopted",
                    transaction_id=str(state["transactionId"]),
                    filesystem_uuid=str(adopted["filesystemUuid"]),
                    observed_logical_size_bytes=int(adopted["logicalSizeBytes"]),
                    observed_filesystem_size_bytes=int(adopted["filesystemSizeBytes"]),
                    host_allocated_bytes=int(adopted["allocatedBytes"]),
                    growth=True,
                )
            except (StorageError, KeyError, TypeError, ValueError) as exc:
                if isinstance(exc, StorageError):
                    return exc.as_dict()
                return self._storage_error(
                    "storage_state_invalid",
                    "cannot resume adopted storage transaction",
                )
            return self._converge_storage_growth(store, state, adopted)
        else:
            action = self._run_storage_image_action(
                "migrate",
                expected_uuid=state["legacyFilesystemUuid"],
                transaction_id=state["transactionId"],
                legacy_volume=state["legacyVolume"],
                backup_image=state["backupImage"],
                backup_uuid=state["backupFilesystemUuid"],
                expected_rootfs_uuid=(
                    str(state["rootfsFilesystemUuid"])
                    or storage_rotation_target(
                        str(state["transactionId"]),
                        rootfs=True,
                    )
                ),
            )
        if not action.get("ok"):
            code = str(action.get("error") or "storage_image_invalid")
            return self._storage_error(
                code,
                str(action.get("message") or "instance image preparation failed"),
                storage=public_storage_state(state, healthy=False, error=code),
                imageAction=action,
            )
        if (
            action.get("logicalSizeBytes") != CANONICAL_DATA_SIZE_BYTES
            or action.get("filesystemSizeBytes") != CANONICAL_DATA_SIZE_BYTES
        ):
            return self._storage_error(
                "storage_identity_mismatch",
                "instance data image geometry changed during transaction",
                storage=public_storage_state(state, healthy=False, error="storage_identity_mismatch"),
                imageAction=action,
            )
        if state["source"] == "legacy" and action.get("filesystemUuid") != state["legacyFilesystemUuid"]:
            return self._storage_error(
                "storage_identity_mismatch",
                "legacy data image UUID changed during migration",
                imageAction=action,
            )
        try:
            committed = store.commit(state, action)
            committed = self._cleanup_committed_rootfs_backup(store, committed)
        except (StorageError, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, StorageError):
                return exc.as_dict()
            return self._storage_error(
                "storage_state_invalid",
                "cannot commit instance storage transaction",
            )
        return {
            "ok": True,
            "volume": {"ok": True, "exists": True},
            "imageAction": action,
            "storage": public_storage_state(committed, healthy=True),
        }

    def _android_boot_command(self) -> list[str]:
        return [
            "androidboot.redroid_width=1440",
            "androidboot.redroid_height=3120",
            "androidboot.redroid_dpi=560",
            "androidboot.redroid_fps=120",
            "androidboot.hardware=raven",
            "androidboot.hardware.sku=G8V0U",
            f"service.adb.tcp.port={self.lease.android_adb_port}",
            "androidboot.use_memfd=true",
            "androidboot.use_redroid_c2=1",
            "androidboot.mode=normal",
        ]

    def docker_create_command(self) -> list[str]:
        dns_args = [
            argument
            for address in self.cfg.network_dns_servers
            for argument in ("--dns", address)
        ]
        return [
            *self.docker_base_cmd(),
            "create",
            "--privileged",
            "--restart=no",
            "--name",
            self.lease.container_name,
            *self._owner_label_args(),
            *self._google_label_args(),
            *self._runtime_image_label_args(),
            "-p",
            f"127.0.0.1:{self.lease.host_adb_port}:{self.lease.android_adb_port}",
            "-v",
            f"{self.lease.volume_name}:/data",
            "--network",
            self.lease.network_name,
            "--ip",
            self.lease.ipv4_address,
            "--ip6",
            self.lease.ipv6_address,
            "--mac-address",
            self.lease.mac_address,
            *dns_args,
            *self.cfg.extra_docker_args,
            *self.binder_volume_args(),
            self.effective_image(),
            *self._android_boot_command(),
        ]

    def docker_exec(
        self,
        args: list[str],
        timeout: float = 15,
    ) -> dict[str, Any]:
        if which("docker") is None:
            return {"ok": False, "error": "docker not found"}
        deadline = time.monotonic() + max(0.0, timeout)
        container, error = self._owned_container_record(timeout=timeout)
        if container is None:
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": error,
            }
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {"ok": False, "error": "docker_exec_timeout"}
        cmd = [*self.docker_base_cmd(), "exec", container["Id"], *args]
        try:
            proc = run(cmd, timeout=remaining, env=self.docker_env())
        except Exception as e:
            return {"ok": False, "error": str(e), "command": cmd}
        return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "command": cmd}

    def docker_wait_boot(self, timeout_sec: int = 120) -> dict[str, Any]:
        """Wait for Android boot via docker exec; independent of adb state."""
        deadline = time.time() + timeout_sec
        last: dict[str, Any] = {}
        while time.time() < deadline:
            r = self.docker_exec(["getprop", "sys.boot_completed"], timeout=10)
            last = r
            if r.get("ok") and r.get("stdout", "").strip() == "1":
                return {"ok": True}
            time.sleep(2)
        return {"ok": False, "error": "timeout waiting for Android boot via docker exec", "last": last}
    def ensure_adb_authorized_key(self) -> dict[str, Any]:
        """Authorize the current host ADB identity before the first TCP connection."""
        # Starting the local server also generates ~/.android/adbkey{,.pub} when
        # this is the host's first ADB use.
        self.adb(["start-server"])
        candidates: list[tuple[str, Path]] = []
        vendor_keys = os.environ.get("ADB_VENDOR_KEYS", "")
        for raw in vendor_keys.split(os.pathsep):
            if not raw:
                continue
            candidate = Path(raw).expanduser()
            if candidate.is_dir():
                candidate = candidate / "adbkey.pub"
            elif candidate.suffix != ".pub":
                candidate = Path(f"{candidate}.pub")
            candidates.append(("ADB_VENDOR_KEYS", candidate))
        candidates.append(("default", Path.home() / ".android" / "adbkey.pub"))

        label = ""
        public_key = ""
        for candidate_label, candidate in candidates:
            try:
                value = candidate.read_text().strip()
            except OSError:
                continue
            if value:
                label = candidate_label
                public_key = value
                break
        if not public_key:
            return {"ok": False, "error": "host ADB public key not found"}

        existing = self.docker_exec(
            ["sh", "-c", "cat /data/misc/adb/adb_keys 2>/dev/null || true"]
        ).get("stdout", "")
        keys = [line.strip() for line in str(existing).splitlines() if line.strip()]
        if public_key not in keys:
            keys.append(public_key)
        payload = "\n".join(keys) + "\n"
        container, ownership_error = self._owned_container_record()
        if container is None:
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": ownership_error,
            }
        payload_bytes = payload.encode("utf-8")
        if len(payload_bytes) > 64 * 1024:
            return {"ok": False, "error": "adb_keys_too_large", "source": label}
        upload_token = secrets.token_hex(16)
        remote_stage = f"/data/local/tmp/.xenoid-adb-keys-{upload_token}"
        marker = f"/data/local/tmp/.xenoid-adb-watch-{upload_token}"
        temporary_target = (
            f"/data/misc/adb/.adb_keys.xenoid-{upload_token}"
        )
        expected_sha = hashlib.sha256(payload_bytes).hexdigest()
        command = (
            "set -eu; "
            f"stage={shlex.quote(remote_stage)}; "
            f"marker={shlex.quote(marker)}; "
            f"tmp={shlex.quote(temporary_target)}; "
            "target=/data/misc/adb/adb_keys; "
            "trap 'rm -f \"$tmp\" \"$stage\" \"$marker\"' "
            "EXIT HUP INT TERM; "
            "umask 077; mkdir -p /data/local/tmp; "
            "test -d /data/local/tmp && "
            "test ! -L /data/local/tmp; "
            "test ! -e \"$stage\" && test ! -L \"$stage\"; "
            "test ! -e \"$marker\" && test ! -L \"$marker\"; "
            "printf '%s' \"$$\" > \"$marker\"; "
            "cat > \"$stage\"; "
            "test -f \"$stage\" && test ! -L \"$stage\"; "
            f"test \"$(wc -c < \"$stage\")\" = {len(payload_bytes)}; "
            f"test \"$(sha256sum \"$stage\" | cut -d' ' -f1)\" "
            f"= {expected_sha}; "
            "mkdir -p /data/misc/adb; "
            "test -d /data/misc/adb && "
            "test ! -L /data/misc/adb; "
            "cp \"$stage\" \"$tmp\"; chown 1000:2000 \"$tmp\"; "
            "chmod 640 \"$tmp\"; "
            "(restorecon \"$tmp\" >/dev/null 2>&1 || true); "
            "mv -f \"$tmp\" \"$target\""
        )
        bounded = run_bounded(
            [
                *self.docker_base_cmd(),
                "exec",
                "-i",
                container["Id"],
                "sh",
                "-c",
                command,
            ],
            cwd=self.context.project_root,
            deadline=time.monotonic() + 20.0,
            env=self.docker_env(),
            input_bytes=payload_bytes,
            max_input_bytes=64 * 1024,
            cancelled=self.cancellation_event,
            project_root=self.context.project_root,
        )
        cleanup_ok = True
        if not bounded.ok:
            cleanup_script = (
                f"marker={shlex.quote(marker)}; "
                f"stage={shlex.quote(remote_stage)}; "
                f"tmp={shlex.quote(temporary_target)}; pid=''; "
                "value=$(cat \"$marker\" 2>/dev/null || true); "
                "case \"$value\" in ''|*[!0-9]*) ;; *) pid=$value;; "
                "esac; "
                "case \"$pid\" in '') ;; *) "
                "kill -TERM \"$pid\" 2>/dev/null || true; "
                "sleep 1; kill -KILL \"$pid\" 2>/dev/null || true;; "
                "esac; rm -f \"$marker\" \"$stage\" \"$tmp\"; "
                "test ! -e \"$marker\" && test ! -L \"$marker\" && "
                "test ! -e \"$stage\" && test ! -L \"$stage\" && "
                "test ! -e \"$tmp\" && test ! -L \"$tmp\""
            )
            cleanup = run_bounded(
                [
                    *self.docker_base_cmd(),
                    "exec",
                    container["Id"],
                    "sh",
                    "-c",
                    cleanup_script,
                ],
                cwd=self.context.project_root,
                deadline=time.monotonic() + 10.0,
                env=self.docker_env(),
                project_root=self.context.project_root,
            )
            cleanup_ok = cleanup.ok
        verified = self.docker_exec(
            [
                "sh",
                "-c",
                "sha256sum /data/misc/adb/adb_keys | "
                "cut -d' ' -f1",
            ]
        )
        target_matches = (
            str(verified.get("stdout") or "").strip() == expected_sha
        )
        recovered = not bounded.ok and cleanup_ok and target_matches
        return {
            "ok": target_matches and (bounded.ok or recovered),
            "returncode": bounded.returncode,
            "state": "passed" if recovered else bounded.state,
            "error": (
                None
                if bounded.ok or recovered
                else "adb_keys_remote_cleanup_failed"
                if not cleanup_ok
                else bounded.error_code
            ),
            "stderr": bounded.stderr_tail,
            "source": label,
            "keyCount": len(keys),
            "recoveredAfterCancellation": recovered,
        }

    def switch_adbd_port_via_docker(self) -> dict[str, Any]:
        """Move adbd to the leased Android ADB port via docker exec."""
        desired = str(self.lease.android_adb_port)
        if desired == "5555":
            return {"ok": True, "skipped": True}
        # Container creation already passes service.adb.tcp.port. A listening
        # daemon on that exact port is ready; restarting it here races the host
        # transport and PackageManager calls immediately after adb_wait().
        current = self.docker_exec(["getprop", "service.adb.tcp.port"])
        listener_current = self.docker_exec(
            ["sh", "-c", "ss -ltn 2>/dev/null | grep ':" + desired + "' || true"],
            timeout=10,
        )
        if desired in str(listener_current.get("stdout", "")):
            return {
                "ok": True,
                "already": True,
                "port": desired,
                "getprop": current,
                "listener": listener_current,
            }
        setp = self.docker_exec(["sh", "-c", "setprop service.adb.tcp.port " + desired])
        restart = self.docker_exec(["sh", "-c", "setprop ctl.restart adbd"])
        deadline = time.time() + 30
        listen: dict[str, Any] = {}
        while time.time() < deadline:
            listen = self.docker_exec(
                ["sh", "-c", "ss -ltn 2>/dev/null | grep ':" + desired + "' || true"],
                timeout=10,
            )
            if desired in str(listen.get("stdout", "")):
                break
            time.sleep(1)
        ok = desired in str(listen.get("stdout", ""))
        return {
            "ok": ok,
            "port": desired,
            "setprop": setp,
            "restart": restart,
            "listener": listen,
        }

    def runtime_preflight(self) -> dict[str, Any]:
        script = self.context.project_root / "scripts" / "redroid-preflight.sh"
        proc = run([str(script)], env=self.docker_env())
        try:
            data = json.loads(proc.stdout)
        except Exception:
            data = {"ok": proc.returncode == 0, "stdout": proc.stdout, "stderr": proc.stderr}
        data["returncode"] = proc.returncode
        return data

    def _container_has_lease_owner(self, container: dict[str, Any]) -> bool:
        config = container.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        return (
            isinstance(container.get("Id"), str)
            and bool(container["Id"])
            and str(container.get("Name", "")).removeprefix("/")
            == self.lease.container_name
            and isinstance(labels, dict)
            and all(
                labels.get(key) == value
                for key, value in self.lease.owner_labels.items()
            )
        )

    def _container_matches_lease(
        self,
        container: dict[str, Any],
        *,
        image_identity: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        config = container.get("Config")
        host_config = container.get("HostConfig")
        network_settings = container.get("NetworkSettings")
        if (
            not isinstance(config, dict)
            or not isinstance(host_config, dict)
            or not isinstance(network_settings, dict)
        ):
            return False
        restart_policy = host_config.get("RestartPolicy")
        port_bindings = host_config.get("PortBindings")
        adb_bindings = (
            port_bindings.get(f"{self.lease.android_adb_port}/tcp")
            if isinstance(port_bindings, dict)
            else None
        )
        expected_adb_binding = {
            "HostIp": "127.0.0.1",
            "HostPort": str(self.lease.host_adb_port),
        }
        mounts = container.get("Mounts")
        owns_data_mount = (
            isinstance(mounts, list)
            and any(
                isinstance(mount, dict)
                and mount.get("Type") == "volume"
                and mount.get("Name") == self.lease.volume_name
                and mount.get("Destination") == "/data"
                for mount in mounts
            )
        )
        networks = network_settings.get("Networks")
        endpoint = (
            networks.get(self.lease.network_name)
            if isinstance(networks, dict)
            else None
        )
        ipam_config = endpoint.get("IPAMConfig") if isinstance(endpoint, dict) else None
        ipv4_matches = (
            endpoint.get("IPAddress") == self.lease.ipv4_address
            or (
                not endpoint.get("IPAddress")
                and isinstance(ipam_config, dict)
                and ipam_config.get("IPv4Address") == self.lease.ipv4_address
            )
        ) if isinstance(endpoint, dict) else False
        ipv6_matches = (
            endpoint.get("GlobalIPv6Address") == self.lease.ipv6_address
            or (
                not endpoint.get("GlobalIPv6Address")
                and isinstance(ipam_config, dict)
                and ipam_config.get("IPv6Address") == self.lease.ipv6_address
            )
        ) if isinstance(endpoint, dict) else False
        state = container.get("State")
        stopped = (
            isinstance(state, Mapping)
            and state.get("Running") is False
        )
        observed_mac = str(endpoint.get("MacAddress", "")).lower()
        mac_matches = (
            observed_mac == self.lease.mac_address.lower()
            or (
                stopped
                and not observed_mac
                and ipv4_matches
                and ipv6_matches
            )
        ) if isinstance(endpoint, dict) else False
        labels = config.get("Labels")
        image_identity = (
            self._container_effective_image_identity(container)
            if image_identity is None
            else image_identity
        )
        return (
            self._container_has_lease_owner(container)
            and image_identity.get("ok") is True
            and self._managed_container_labels_match(labels)
            and config.get("Cmd") == self._android_boot_command()
            and host_config.get("AutoRemove") is False
            and host_config.get("Privileged") is True
            and isinstance(restart_policy, dict)
            and restart_policy.get("Name") == "no"
            and host_config.get("NetworkMode") == self.lease.network_name
            and host_config.get("Dns") == self.cfg.network_dns_servers
            and isinstance(adb_bindings, list)
            and expected_adb_binding in adb_bindings
            and owns_data_mount
            and isinstance(networks, dict)
            and set(networks) == {self.lease.network_name}
            and isinstance(endpoint, dict)
            and ipv4_matches
            and ipv6_matches
            and mac_matches
        )

    def _owned_container_record(
        self,
        *,
        timeout: Optional[float] = None,
    ) -> tuple[Optional[dict[str, Any]], str]:
        container, _ = self._inspect_docker_object(
            "container",
            self.lease.container_name,
            timeout=timeout,
        )
        if container is None:
            return None, "instance container does not exist"
        if not container or not self._container_has_lease_owner(container):
            return None, "Docker container is not owned by this instance"
        return container, ""

    def _owned_container(self) -> tuple[bool, str]:
        container, error = self._owned_container_record()
        return container is not None, error

    def collect_persisted_device_identity(self) -> dict[str, Any]:
        """Read legacy stable identifiers from persistent Android state."""
        command = (
            "set +e; "
            "serial=$(cat /data/local/tmp/xenoid-profile/serial 2>/dev/null); "
            "[ -n \"$serial\" ] || serial=$(getprop ro.serialno); "
            "printf 'serial=%s\\n' \"$serial\"; "
            "printf 'imei=%s\\n' \"$(getprop persist.xenoid.radio.imei)\"; "
            "printf 'imeisv=%s\\n' \"$(getprop persist.xenoid.radio.imeisv)\""
        )
        result = self.docker_exec(["sh", "-c", command], timeout=15)
        if not result.get("ok"):
            return {}
        allowed = {"androidId", "serial", "imei", "imeisv"}
        values: dict[str, str] = {}
        for line in str(result.get("stdout", "")).splitlines():
            key, separator, value = line.partition("=")
            normalized = value.strip()
            if (
                separator
                and key in allowed
                and normalized
                and normalized.lower() != "null"
                and len(normalized) <= 64
            ):
                values[key] = normalized
        return values

    def location_runtime_container_id(self) -> Optional[str]:
        """Owned running container ID used to derive the location runtime epoch."""
        try:
            container, _ = self._owned_container_record()
        except Exception:
            return None
        if container is None:
            return None
        state = container.get("State")
        if not isinstance(state, dict) or state.get("Running") is not True:
            return None
        container_id = container.get("Id")
        if not isinstance(container_id, str) or re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
            return None
        return container_id

    def _capture_proxy_desired_for_update(self) -> dict[str, Any]:
        """Keep credential-bearing desired state only in memory across an APK update."""
        if self._pending_proxy_restore is not None:
            return {"ok": True, "captured": True, "configured": True}
        try:
            client = self.daemon_client(timeout=2.0)
            bootstrap = client.bootstrap_status(timeout=2.0)
        except Exception:
            return {"ok": True, "captured": False, "configured": False}
        components = bootstrap.get("components") if isinstance(bootstrap, dict) else None
        proxy = components.get("proxy") if isinstance(components, dict) else None
        if not isinstance(proxy, dict) or proxy.get("ok") is not True:
            return {"ok": True, "captured": False, "configured": False}
        try:
            exported = client.proxy_export()
        except Exception:
            exported = {"ok": False}
        if not isinstance(exported, dict) or exported.get("ok") is not True:
            if isinstance(exported, dict) and exported.get("httpStatus") == 404:
                return {"ok": True, "captured": False, "configured": False}
            return self._proxy_failure("proxy_state_backup_failed")
        instance_id = exported.get("instanceId")
        source = exported.get("source")
        enabled = exported.get("enabled")
        if instance_id not in ("", self.context.instance_id) or not isinstance(enabled, bool):
            return self._proxy_failure("proxy_state_backup_failed")
        if source is None:
            return {"ok": True, "captured": True, "configured": False}
        if not isinstance(source, dict):
            return self._proxy_failure("proxy_state_backup_failed")
        kind = source.get("kind")
        value = source.get("value")
        selected_node = source.get("selectedNode")
        udp_allowed = source.get("udpAllowed")
        allow_insecure_http = source.get("allowInsecureHttp")
        if (
            kind not in {"endpoint", "uri_list", "clash", "subscription"}
            or not isinstance(value, str)
            or not isinstance(selected_node, str)
            or not isinstance(udp_allowed, bool)
            or not isinstance(allow_insecure_http, bool)
        ):
            return self._proxy_failure("proxy_state_backup_failed")
        try:
            if len(value.encode("utf-8")) > PROXY_MAX_SOURCE_BYTES:
                return self._proxy_failure("proxy_state_backup_failed")
        except UnicodeError:
            return self._proxy_failure("proxy_state_backup_failed")
        self._pending_proxy_restore = (
            kind,
            bytearray(value.encode("utf-8")),
            enabled,
            selected_node,
            udp_allowed,
            allow_insecure_http,
        )
        return {"ok": True, "captured": True, "configured": True}

    def _discard_pending_proxy_restore(self) -> None:
        pending = self._pending_proxy_restore
        self._pending_proxy_restore = None
        if pending is None:
            return
        source = pending[1]
        for index in range(len(source)):
            source[index] = 0
    def discard_convergence_secrets(self) -> dict[str, Any]:
        """Zeroize command-scoped proxy material after failure or cancellation."""
        retained = self._pending_proxy_restore is not None
        self._discard_pending_proxy_restore()
        return {"ok": True, "discarded": retained}


    def _restore_proxy_desired_after_update(self, controller: Any) -> dict[str, Any]:
        pending = self._pending_proxy_restore
        if pending is None:
            return {"ok": True, "restored": False}
        self._pending_proxy_restore = None
        kind, source, enabled, selected_node, udp_allowed, allow_insecure_http = pending
        try:
            try:
                value = source.decode("utf-8", "strict")
            except UnicodeError:
                return self._proxy_failure("proxy_state_restore_failed")
            restored = controller.set_source(
                kind,
                value,
                enabled,
                selected_node=selected_node,
                udp_allowed=udp_allowed,
                allow_insecure_http=allow_insecure_http,
            )
            if not isinstance(restored, dict) or restored.get("ok") is not True:
                return self._proxy_failure("proxy_state_restore_failed")
            return {"ok": True, "restored": True}
        finally:
            for index in range(len(source)):
                source[index] = 0

    def reconcile_proxy_desired(self) -> dict[str, Any]:
        """Converge this instance's daemon desired state before runtime acceptance."""
        try:
            from .proxy_controller import ProxyController

            client = self.daemon_client()
            controller = ProxyController(
                self.context,
                self.cfg,
                self.lease,
                self,
                client,
            )
            status = client.proxy_status()
            if status.get("stateReadable") is False:
                code = status.get("stateError")
                return self._proxy_failure(
                    code if isinstance(code, str) else "proxy_state_invalid"
                )
            restored = self._restore_proxy_desired_after_update(controller)
            if restored.get("ok") is not True:
                return restored
            return controller.reconcile_desired()
        except InstanceError as exc:
            return {"ok": False, "code": exc.code, "error": exc.code}
        except Exception:
            return {
                "ok": False,
                "code": "proxy_reconcile_failed",
                "error": "proxy_reconcile_failed",
            }

    def quarantine_proxy_for_lifecycle(
        self,
        expected_data_uuid: Optional[str] = None,
        operation_id: Optional[str] = None,
        *,
        deadline: Optional[float] = None,
    ) -> dict[str, Any]:
        """Install the fail-closed guard and bind its proof to persistent data."""
        if operation_id is not None and re.fullmatch(r"[0-9a-f]{32}", operation_id) is None:
            return self._proxy_failure("convergence_operation_invalid")
        try:
            storage = StorageStateStore(self.context, self.lease).load()
            observed_uuid = (
                str(storage.get("filesystemUuid") or "")
                if isinstance(storage, dict) and storage.get("state") == "committed"
                else ""
            )
            if expected_data_uuid is not None and observed_uuid != expected_data_uuid:
                return self._proxy_failure("storage_identity_mismatch")
            retry_until = time.monotonic() + 10.0
            if isinstance(deadline, (int, float)):
                retry_until = min(retry_until, float(deadline))
            while True:
                try:
                    prerequisite = self.proxy_prerequisite(
                        allow_stopped=True
                    )
                except InstanceError as exc:
                    if (
                        exc.code != "runtime_identity_mismatch"
                        or time.monotonic() >= retry_until
                    ):
                        raise
                    time.sleep(0.1)
                    continue
                if (
                    prerequisite.get("ok") is True
                    or prerequisite.get("code")
                    != "runtime_identity_mismatch"
                    or time.monotonic() >= retry_until
                ):
                    break
                time.sleep(0.1)
            if prerequisite.get("ok") is not True:
                return prerequisite
            result = self.proxy_quarantine()
        except StorageError as exc:
            return self._proxy_failure(exc.code)
        except InstanceError as exc:
            return self._proxy_failure(exc.code)
        except Exception:
            return self._proxy_failure("engine_unavailable")
        if not isinstance(result, dict):
            return self._proxy_failure("engine_response_invalid")
        if result.get("ok") is True:
            return {
                **result,
                "dataUuid": observed_uuid or None,
                **(
                    {"operationId": operation_id}
                    if operation_id is not None
                    else {}
                ),
            }
        code = result.get("code") or result.get("error")
        if not isinstance(code, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) is None:
            code = "engine_unavailable"
        return self._proxy_failure(code)

    def _quiesce_container_safely(
        self,
        container: Mapping[str, Any],
        *,
        expected_container_id: Optional[str] = None,
    ) -> dict[str, Any]:
        container_id = container.get("Id")
        if (
            not isinstance(container_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
            or expected_container_id is not None
            and container_id != expected_container_id
        ):
            return self._storage_error(
                "convergence_state_conflict",
                "owned container identity differs from the journaled runtime",
            )
        if not self._container_has_lease_owner(dict(container)):
            return self._storage_error(
                "resource_conflict",
                "Docker container is not owned by this instance",
            )
        quarantine = self.quarantine_proxy_for_lifecycle()
        result: dict[str, Any] = {
            "ok": False,
            "containerId": container_id,
            "proxyQuarantine": quarantine,
        }
        if quarantine.get("ok") is not True:
            result["error"] = quarantine.get("code", "engine_unavailable")
            return result
        state = container.get("State")
        running = isinstance(state, Mapping) and state.get("Running") is True
        if not running:
            return {
                **result,
                "ok": True,
                "alreadyStopped": True,
                "preserved": True,
            }
        synced = run(
            [*self.docker_base_cmd(), "exec", container_id, "sync"],
            timeout=30,
            env=self.docker_env(),
        )
        result["sync"] = {
            "ok": synced.returncode == 0,
            "returncode": synced.returncode,
            "stderr": synced.stderr.strip()[-500:],
        }
        if synced.returncode != 0:
            result["error"] = "container_sync_failed"
            return result
        stopped = run(
            [
                *self.docker_base_cmd(),
                "stop",
                "--time",
                "30",
                container_id,
            ],
            timeout=45,
            env=self.docker_env(),
        )
        result["stop"] = {
            "ok": stopped.returncode == 0,
            "returncode": stopped.returncode,
            "stderr": stopped.stderr.strip()[-500:],
        }
        if stopped.returncode != 0:
            result["error"] = "container_stop_failed"
            return result
        result.update({"ok": True, "stopped": True, "preserved": True})
        return result

    def quiesce_owned_container(
        self,
        expected_container_id: Optional[str] = None,
    ) -> dict[str, Any]:
        self.ensure_instance_lease()
        container, error = self._owned_container_record()
        if container is None:
            return self._storage_error(
                "convergence_state_conflict",
                error,
            )
        return self._quiesce_container_safely(
            container,
            expected_container_id=expected_container_id,
        )

    def _remove_container_safely(
        self,
        container: dict[str, Any],
        *,
        ownership: str,
        expected_container_id: Optional[str] = None,
    ) -> dict[str, Any]:
        quiesced = self._quiesce_container_safely(
            container,
            expected_container_id=expected_container_id,
        )
        result: dict[str, Any] = {
            "ok": False,
            "ownership": ownership,
            "quiesce": quiesced,
        }
        if quiesced.get("ok") is not True:
            result["error"] = quiesced.get("error", "container_stop_failed")
            return result
        container_id = str(quiesced["containerId"])
        removed = run(
            [*self.docker_base_cmd(), "rm", container_id],
            timeout=30,
            env=self.docker_env(),
        )
        result["remove"] = {
            "ok": removed.returncode == 0,
            "returncode": removed.returncode,
            "stderr": removed.stderr.strip()[-500:],
        }
        if removed.returncode != 0:
            result["error"] = "container_remove_failed"
            return result
        try:
            cleanup = self.proxy_cleanup()
        except InstanceError as exc:
            cleanup = self._proxy_failure(exc.code)
        except Exception:
            cleanup = self._proxy_failure("engine_unavailable")
        result["proxyCleanup"] = cleanup
        result["ok"] = isinstance(cleanup, dict) and cleanup.get("ok") is True
        result["containerId"] = container_id
        if not result["ok"]:
            result["error"] = "proxy_cleanup_failed"
        return result

    def _remove_owned_container(self, container: dict[str, Any]) -> dict[str, Any]:
        if not self._container_has_lease_owner(container):
            return self._storage_error(
                "resource_conflict",
                "Docker container is not owned by this instance",
            )
        return self._remove_container_safely(container, ownership="lease")
    def _remove_owned_container_for_operation(
        self,
        *,
        expected_container_id: Optional[str],
        operation: str,
    ) -> dict[str, Any]:
        if (
            expected_container_id is not None
            and re.fullmatch(r"[0-9a-f]{64}", expected_container_id) is None
        ):
            return self._storage_error(
                "convergence_state_conflict",
                "journaled container identity is invalid",
            )
        storage = self.storage_status()
        if storage.get("ok") is not True:
            return {
                "ok": False,
                "error": storage.get("error", "storage_identity_mismatch"),
                "storage": storage,
            }
        container, error = self._owned_container_record()
        if container is None:
            if error == "instance container does not exist":
                return {
                    "ok": True,
                    "alreadyRemoved": True,
                    "containerId": expected_container_id,
                    "operation": operation,
                    "storage": storage,
                }
            return self._storage_error("resource_conflict", error)
        container_id = str(container.get("Id") or "")
        if expected_container_id is not None and container_id != expected_container_id:
            return self._storage_error(
                "convergence_state_conflict",
                "a third container identity occupies the instance name",
            )
        mounts = container.get("Mounts")
        if not (
            isinstance(mounts, list)
            and any(
                isinstance(mount, Mapping)
                and mount.get("Type") == "volume"
                and mount.get("Name") == self.lease.volume_name
                and mount.get("Destination") == "/data"
                for mount in mounts
            )
        ):
            return self._storage_error(
                "resource_conflict",
                "owned container is not attached to the instance storage",
            )
        removed = self._remove_container_safely(
            container,
            ownership="lease",
            expected_container_id=expected_container_id,
        )
        return {**removed, "operation": operation, "storage": storage}
    def _prepare_location_for_replacement(
        self,
        expected_container_id: Optional[str],
    ) -> dict[str, Any]:
        """Stage and arm pending Location state before the one planned replacement."""
        try:
            from .cellular import encode_profile_v1
            from .location import (
                STAGE_SCHEMA,
                LocationError,
                LocationStateStore,
                convergence_action,
                location_runtime_epoch,
            )

            store = LocationStateStore(self.context.state_root)
            state = store.load()
            if state is None or not isinstance(state.get("pending"), Mapping):
                return {"ok": True, "skipped": True}
            container, container_error = self._owned_container_record()
            if not isinstance(container, Mapping):
                return {
                    "ok": False,
                    "error": (
                        "convergence_state_conflict"
                        if container_error == "instance container does not exist"
                        else "resource_conflict"
                    ),
                }
            container_id = container.get("Id")
            if (
                not isinstance(container_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
                or expected_container_id is not None
                and container_id != expected_container_id
            ):
                return {"ok": False, "error": "convergence_state_conflict"}
            container_state = container.get("State")
            if (
                not isinstance(container_state, Mapping)
                or container_state.get("Running") is not True
            ):
                started = self.start_owned_container(
                    expected_container_id=container_id,
                    wait=True,
                    allow_journaled_spec_drift=True,
                )
                if started.get("ok") is not True:
                    return {
                        "ok": False,
                        "error": str(
                            started.get("error")
                            or "location_runtime_start_failed"
                        ),
                    }
            container_id = self.location_runtime_container_id()
            if (
                container_id is None
                or expected_container_id is not None
                and container_id != expected_container_id
            ):
                return {"ok": False, "error": "convergence_state_conflict"}
            epoch = location_runtime_epoch(container_id)
            pending = state["pending"]
            phase = pending.get("phase")
            if phase == "armed":
                if pending.get("restartFromEpoch") != epoch:
                    return {"ok": False, "error": "convergence_state_conflict"}
                return {"ok": True, "armed": True, "runtimeEpoch": epoch}
            if phase == "restarted":
                return {"ok": True, "skipped": True, "runtimeEpoch": epoch}
            bootstrap = self.reconcile_bootstrap(timeout=120.0)
            if bootstrap.get("ok") is not True:
                return {
                    "ok": False,
                    "error": str(
                        bootstrap.get("code")
                        or "location_runtime_start_failed"
                    ),
                }
            client = self.daemon_client()
            try:
                android = client.location_status(timeout=10.0)
            except Exception:
                android = None
            decision = convergence_action(state, android, epoch)
            if decision.get("step") != "stage" or decision.get("recreate") is not True:
                return {"ok": False, "error": "location_phase_invalid"}
            profile = store.target_profile(state)
            staged = client.location_stage(
                {
                    "schema": STAGE_SCHEMA,
                    "profile": profile,
                    "encodedProfile": base64.b64encode(
                        encode_profile_v1(profile)
                    ).decode("ascii"),
                    "profileDigest": profile["identityDigest"],
                    "locationKey": profile["locationKey"],
                    "runtimeEpoch": epoch,
                }
            )
            if staged.get("ok") is not True:
                return {"ok": False, "error": "location_stage_failed"}
            current = store.load()
            current_pending = (
                current.get("pending") if isinstance(current, Mapping) else None
            )
            if isinstance(current_pending, Mapping) and current_pending.get("phase") == "new":
                store.mark_staged(epoch)
                current = store.load()
                current_pending = (
                    current.get("pending") if isinstance(current, Mapping) else None
                )
            if not (
                isinstance(current_pending, Mapping)
                and current_pending.get("phase") == "staged"
            ):
                return {"ok": False, "error": "location_phase_invalid"}
            armed = store.arm_restart()
            armed_pending = armed.get("pending")
            if not (
                isinstance(armed_pending, Mapping)
                and armed_pending.get("phase") == "armed"
                and armed_pending.get("restartFromEpoch") == epoch
            ):
                return {"ok": False, "error": "location_phase_invalid"}
            return {"ok": True, "armed": True, "runtimeEpoch": epoch}
        except (LocationError, InstanceError) as exc:
            return {
                "ok": False,
                "error": getattr(exc, "code", "location_convergence_failed"),
            }


    def remove_owned_container_for_recreate(
        self,
        expected_container_id: Optional[str] = None,
        *,
        prepare_location: bool = False,
    ) -> dict[str, Any]:
        """Remove only the journaled owned runtime for an explicit replacement."""
        self.ensure_instance_lease()
        if prepare_location:
            prepared = self._prepare_location_for_replacement(expected_container_id)
            if prepared.get("ok") is not True:
                return prepared
        return self._remove_owned_container_for_operation(
            expected_container_id=expected_container_id,
            operation="recreate",
        )

    def remove_owned_container_for_regenerate(
        self,
        expected_container_id: Optional[str] = None,
        *,
        regeneration_capability: Any = None,
    ) -> dict[str, Any]:
        """Remove only the regeneration-journal-owned runtime."""
        self.ensure_instance_lease()
        try:
            regeneration = RegenerationJournal(self.context).require_capability(
                regeneration_capability
            )
        except IdentityError as exc:
            return exc.as_dict()
        if expected_container_id != regeneration["before"]["containerId"]:
            return {
                "ok": False,
                "error": "device_regeneration_state_invalid",
                "message": "container removal does not match regeneration before-state",
            }
        return self._remove_owned_container_for_operation(
            expected_container_id=expected_container_id,
            operation="regenerate",
        )



    def _remove_legacy_container(
        self,
        container_id: str,
        expected_name: str,
        expected_volume: str,
    ) -> dict[str, Any]:
        container, _ = self._inspect_docker_object("container", container_id)
        if not container:
            return self._storage_error(
                "storage_legacy_attached",
                "legacy container inspection failed",
            )
        config = container.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        mounts = container.get("Mounts")
        name = str(container.get("Name", "")).removeprefix("/")
        has_expected_mount = isinstance(mounts, list) and any(
            isinstance(mount, dict)
            and mount.get("Type") == "volume"
            and mount.get("Name") == expected_volume
            and mount.get("Destination") == "/data"
            for mount in mounts
        )
        foreign_owner = (
            isinstance(labels, dict)
            and labels.get("dev.xenoid.owner") == "xenoid"
            and labels.get("dev.xenoid.instance_id")
            not in (None, self.context.instance_id)
        )
        if (
            not expected_name
            or name != expected_name
            or not has_expected_mount
            or foreign_owner
        ):
            return self._storage_error(
                "storage_legacy_attached",
                "legacy container ownership cannot be proven",
            )
        return self._remove_container_safely(container, ownership="legacy-record")

    def _google_binding_preflight(
        self,
        spec: Optional[ReleaseSpec],
    ) -> dict[str, Any]:
        binding_store = GoogleBindingStore(self.context, self.lease)
        binding = binding_store.load()
        storage = StorageStateStore(self.context, self.lease).load()
        legacy = self._legacy_engine_record()
        volume, inspected = self._inspect_docker_object(
            "volume",
            self.lease.volume_name,
        )
        if volume == {}:
            raise GoogleServicesError(
                "google_services_freshness_unknown",
                "cannot inspect the instance data volume identity",
            )
        missing = "no such volume" in str(inspected.stderr or "").lower()
        freshness_known = volume is not None or missing
        fresh = (
            freshness_known
            and volume is None
            and storage is None
            and legacy is None
        )
        legacy_actual_none = (
            spec is None
            and not fresh
            and (volume is not None or storage is not None or legacy is not None)
        )
        decision = transition_decision(
            spec,
            binding,
            freshness_known=freshness_known,
            fresh=fresh,
            legacy_actual_none=legacy_actual_none,
        )
        return {
            **decision,
            "binding": binding,
            "storagePresent": storage is not None,
            "volumePresent": volume is not None,
            "legacyPresent": legacy is not None,
        }

    def google_services_configuration_mutable(self) -> dict[str, Any]:
        current = GoogleBindingStore(self.context, self.lease).load()
        storage = StorageStateStore(self.context, self.lease).load()
        legacy = self._legacy_engine_record()
        volume, inspected = self._inspect_docker_object(
            "volume",
            self.lease.volume_name,
        )
        missing = "no such volume" in str(inspected.stderr or "").lower()
        known = volume is not None or missing
        mutable = (
            current is None
            and storage is None
            and legacy is None
            and known
            and volume is None
        )
        return {
            "ok": mutable,
            "mutable": mutable,
            "binding": public_binding(current),
            "storagePresent": storage is not None,
            "volumePresent": volume is not None,
            "legacyPresent": legacy is not None,
            **(
                {}
                if mutable
                else {
                    "error": (
                        "google_services_new_instance_required"
                        if known
                        else "google_services_freshness_unknown"
                    ),
                    "message": (
                        "Google services configuration is immutable after Android data exists"
                        if known
                        else "cannot prove that this instance has no Android data"
                    ),
                }
            ),
        }

    def _begin_google_binding(
        self,
        spec: Optional[ReleaseSpec],
        preflight: dict[str, Any],
    ) -> dict[str, Any]:
        store = GoogleBindingStore(self.context, self.lease)
        existing = preflight.get("binding")
        if isinstance(existing, dict):
            return existing
        source = (
            "legacy"
            if preflight.get("transition") == "legacy-none"
            else "fresh"
        )
        pending = store.pending(spec, source)
        if preflight.get("transition") == "legacy-none":
            return store.commit(pending)
        return pending

    def _commit_google_binding(
        self,
        binding: Mapping[str, Any],
    ) -> dict[str, Any]:
        return GoogleBindingStore(self.context, self.lease).commit(binding)

    def google_services_bootstrap_gate(
        self,
        spec: Optional[ReleaseSpec],
    ) -> dict[str, Any]:
        if spec is None:
            return self._google_services_gate_absent()
        if spec.provider == PROVIDER_MICROG:
            return self._google_services_gate_microg(spec)
        raise GoogleServicesError(
            "google_services_release_retired",
            "the configured Google services release is retired; create a new instance with a production release",
        )

    def _google_services_gate_absent(self) -> dict[str, Any]:
        packages: dict[str, Any] = {}
        package_ok = True
        for package in (
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.android.vending",
        ):
            path = self.adb(["shell", "pm", "path", package], timeout=20)
            output = str(path.get("stdout") or "").strip()
            present = path.get("ok") is True and "package:" in output
            packages[package] = {
                "present": present,
                "expected": False,
                "path": output if present else None,
            }
            package_ok = package_ok and not present
        release = self.adb(["shell", "getprop", "ro.build.version.release"])
        abilist = self.adb(["shell", "getprop", "ro.product.cpu.abilist"])
        product = self.adb(["shell", "getprop", "ro.build.product"])
        platform_ok = (
            str(release.get("stdout") or "").strip() == "13"
            and str(product.get("stdout") or "").strip() == "raven"
            and str(abilist.get("stdout") or "").strip() == "arm64-v8a"
        )
        ok = bool(package_ok and platform_ok)
        return {
            "ok": ok,
            "provider": PROVIDER_NONE,
            "packages": packages,
            "platform": {
                "release": str(release.get("stdout") or "").strip(),
                "product": str(product.get("stdout") or "").strip(),
                "abilist": str(abilist.get("stdout") or "").strip(),
                "ok": platform_ok,
            },
            **(
                {}
                if ok
                else {
                    "error": "google_services_runtime_not_ready",
                    "message": "unexpected Google services packages are present",
                }
            ),
        }

    # -- microG minimal live acceptance -------------------------------------

    _EXIT_REASONS_IGNORE = {
        "EXIT_SELF",
        "LOW_MEMORY",
        "USER_REQUESTED",
        "USER_STOPPED",
        "OTHER",
        "FREEZER",
        "PACKAGE_STATE_CHANGE",
        "PACKAGE_UPDATED",
    }
    _EXIT_REASONS_FAIL_ONCE = {"ANR", "INITIALIZATION_FAILURE"}
    _EXIT_REASONS_CRASH_CLASS = {
        "SIGNALED",
        "CRASH",
        "CRASH_NATIVE",
        "EXCESSIVE_RESOURCE_USAGE",
        "DEPENDENCY_DIED",
    }
    _EXIT_REASON_BY_CODE = {
        1: "EXIT_SELF",
        2: "SIGNALED",
        3: "LOW_MEMORY",
        4: "CRASH",
        5: "CRASH_NATIVE",
        6: "ANR",
        7: "INITIALIZATION_FAILURE",
        9: "EXCESSIVE_RESOURCE_USAGE",
        10: "USER_REQUESTED",
        11: "USER_STOPPED",
        12: "DEPENDENCY_DIED",
        13: "OTHER",
        14: "FREEZER",
        15: "PACKAGE_STATE_CHANGE",
        16: "PACKAGE_UPDATED",
    }

    def _adb_shell_text(self, args: list[str], timeout: float = 20) -> Optional[str]:
        result = self.adb(["shell", *args], timeout=timeout)
        if result.get("ok") is not True:
            return None
        return str(result.get("stdout") or "")

    def _adb_read_file_bytes(self, device_path: str, timeout: float, max_bytes: int) -> Optional[bytes]:
        adb_bin = which("adb")
        if adb_bin is None:
            return None
        owned, _ = self._owned_container()
        if not owned:
            return None
        try:
            proc = run(
                [adb_bin, "-s", self.adb_target, "exec-out", "cat", "--", device_path],
                capture_output=True,
                timeout=timeout,
            )
        except Exception:
            return None
        if proc.returncode != 0 or not proc.stdout or len(proc.stdout) > max_bytes:
            return None
        return bytes(proc.stdout)

    def _device_file_sha256(self, device_path: str) -> Optional[str]:
        for command in (["sha256sum", device_path], ["toybox", "sha256sum", device_path]):
            output = self._adb_shell_text(command, timeout=60)
            if output:
                match = re.match(r"^([0-9a-f]{64})\s", output.strip())
                if match:
                    return match.group(1)
        return None

    def _apk_signer_history(self, apk_bytes: bytes) -> Optional[list[str]]:
        apksigner = which("apksigner")
        if apksigner is None:
            sdk_root = os.environ.get("ANDROID_SDK_ROOT")
            candidate = Path(sdk_root) / "build-tools" / "35.0.0" / "apksigner" if sdk_root else None
            apksigner = str(candidate) if candidate is not None and candidate.exists() else None
        if apksigner is None:
            return None
        with tempfile.TemporaryDirectory(prefix="xenoid-gate-apk-") as temp:
            apk_path = Path(temp) / "component.apk"
            apk_path.write_bytes(apk_bytes)
            apk_path.chmod(0o600)
            try:
                proc = run(
                    [apksigner, "verify", "--verbose", "--print-certs", str(apk_path)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            except Exception:
                return None
        if proc.returncode != 0:
            return None
        history: list[str] = []
        for line in proc.stdout.splitlines():
            if " certificate SHA-256 digest: " in line:
                digest = line.rsplit(": ", 1)[1].strip().lower()
                if digest not in history:
                    history.append(digest)
        return history or None

    def _microg_component_record(
        self,
        spec: ReleaseSpec,
        component: Mapping[str, Any],
    ) -> dict[str, Any]:
        package = str(component["package"])
        factory_path = str(component["runtimePath"])
        min_version = int(component["versionCode"])
        pinned_history = [str(item) for item in component["signingCertificateHistorySha256"]]
        record: dict[str, Any] = {
            "package": package,
            "codePath": None,
            "versionCode": None,
            "versionName": None,
            "signerSha256": None,
            "enabled": False,
            "system": False,
            "privileged": False,
            "updatedSystemApp": False,
            "processState": "failed",
            "ok": False,
            "code": "google_services_component_mismatch",
        }
        path_output = self._adb_shell_text(["pm", "path", package], timeout=20)
        code_path = ""
        for line in (path_output or "").splitlines():
            if line.startswith("package:"):
                code_path = line[len("package:"):].strip()
                break
        if not code_path:
            return record
        record["codePath"] = code_path
        enabled_list = self._adb_shell_text(["pm", "list", "packages", "-e", package], timeout=20)
        record["enabled"] = enabled_list is not None and f"package:{package}" in enabled_list
        dump = self._adb_shell_text(["dumpsys", "package", package], timeout=30)
        if not dump:
            return record
        version_code_match = re.search(r"^\s*versionCode=(\d+)", dump, flags=re.MULTILINE)
        version_name_match = re.search(r"^\s*versionName=(\S*)", dump, flags=re.MULTILINE)
        flags_match = re.search(r"^\s*flags=\[(.*?)\]", dump, flags=re.MULTILINE)
        private_flags_match = re.search(r"^\s*privateFlags=\[(.*?)\]", dump, flags=re.MULTILINE)
        if version_code_match is None or private_flags_match is None or flags_match is None:
            return record
        version_code = int(version_code_match.group(1))
        flags = flags_match.group(1)
        private_flags = private_flags_match.group(1)
        record["versionCode"] = version_code
        record["versionName"] = version_name_match.group(1) if version_name_match else None
        record["system"] = "SYSTEM" in flags
        record["privileged"] = "PRIVILEGED" in private_flags
        record["updatedSystemApp"] = "UPDATED_SYSTEM_APP" in private_flags
        if version_code < min_version:
            return record
        if not (record["enabled"] and record["system"] and record["privileged"]):
            return record
        if code_path == factory_path:
            digest = self._device_file_sha256(code_path)
            if digest is None or digest != str(component["sha256"]):
                return record
            record["signerSha256"] = pinned_history[0]
        else:
            if not record["updatedSystemApp"] or not code_path.startswith("/data/app/"):
                return record
            apk_bytes = self._adb_read_file_bytes(code_path, timeout=120, max_bytes=512 * 1024 * 1024)
            if apk_bytes is None:
                return record
            history = self._apk_signer_history(apk_bytes)
            if history != pinned_history:
                return record
            record["signerSha256"] = history[0]
        record["ok"] = True
        record["code"] = None
        return record

    @staticmethod
    def _parse_exit_info(payload: str, packages: set[str]) -> Optional[list[dict[str, Any]]]:
        """Parse dumpsys activity exit-info, returning records for the given packages."""
        records: list[dict[str, Any]] = []
        tracked = False
        current_package = ""
        pending: Optional[dict[str, Any]] = None
        for line in payload.splitlines():
            stripped = line.strip()
            package_match = re.match(r"^package: (\S+)$", stripped)
            if package_match:
                if pending is not None:
                    return None
                current_package = package_match.group(1)
                tracked = current_package in packages
                continue
            if not tracked:
                continue
            if stripped.startswith("Historical Process Exit"):
                continue
            if stripped.startswith("ApplicationExitInfo"):
                if pending is not None:
                    return None
                pending = {"package": current_package}
                continue
            if stripped.startswith("timestamp="):
                if pending is None:
                    return None
                timestamp_match = re.match(
                    r"^timestamp=(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?\s+pid=\d+",
                    stripped,
                )
                if timestamp_match is None:
                    return None
                pending["timestamp"] = timestamp_match.group(1)
                continue
            if stripped.startswith("process="):
                if pending is None or "timestamp" not in pending:
                    return None
                reason_match = re.search(r"\breason=(\d+)", stripped)
                if reason_match is None:
                    return None
                pending["reasonCode"] = int(reason_match.group(1))
                records.append(pending)
                pending = None
                continue
        if pending is not None:
            return None
        return records

    @staticmethod
    def _parse_exit_timestamp(value: str, tz_offset: str) -> Optional[float]:
        match = re.fullmatch(r"([+-])(\d{2})(\d{2})", tz_offset or "")
        offset = 0
        if match:
            sign = 1 if match.group(1) == "+" else -1
            offset = sign * (int(match.group(2)) * 3600 + int(match.group(3)) * 60)
        for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%y %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
            try:
                parsed = datetime.strptime(value[:19], fmt)
            except ValueError:
                continue
            return parsed.replace(tzinfo=timezone.utc).timestamp() - offset
        return None

    def _microg_exit_history(self, packages: set[str], deadline: float) -> dict[str, Any]:
        unavailable = {"ok": False, "code": "google_services_process_unstable", "detail": "exitInfoUnavailable"}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return unavailable
        payload = self._adb_shell_text(
            ["dumpsys", "activity", "exit-info"],
            timeout=min(20.0, max(1.0, remaining)),
        )
        if payload is None or not payload.strip():
            return unavailable
        encoded = payload.encode("utf-8", "replace")
        if len(encoded) > 256 * 1024:
            return unavailable
        records = self._parse_exit_info(payload, packages)
        if records is None or len(records) > 32:
            return unavailable
        uptime_output = self._adb_shell_text(["cat", "/proc/uptime"], timeout=10)
        epoch_output = self._adb_shell_text(["date", "+%s"], timeout=10)
        zone_output = self._adb_shell_text(["date", "+%z"], timeout=10)
        if not uptime_output or not epoch_output:
            return unavailable
        try:
            uptime_seconds = float(uptime_output.split()[0])
            now_seconds = int(epoch_output.strip())
        except (ValueError, IndexError):
            return unavailable
        boot_epoch = now_seconds - uptime_seconds
        relevant: dict[str, list[dict[str, Any]]] = {package: [] for package in packages}
        for record in records:
            package = record["package"]
            if package not in relevant:
                continue
            reason = self._EXIT_REASON_BY_CODE.get(record["reasonCode"])
            if reason is None:
                return unavailable
            timestamp = self._parse_exit_timestamp(record["timestamp"], (zone_output or "").strip())
            if timestamp is None:
                return unavailable
            if timestamp < boot_epoch - 60:
                continue
            relevant[package].append({"reason": reason, "timestamp": timestamp})
        now = time.time()
        for package, entries in relevant.items():
            crash_recent = 0
            for entry in entries:
                reason = entry["reason"]
                if reason in self._EXIT_REASONS_IGNORE:
                    continue
                if reason in self._EXIT_REASONS_FAIL_ONCE:
                    return {"ok": False, "code": "google_services_process_unstable", "detail": f"{package}:{reason}"}
                if reason in self._EXIT_REASONS_CRASH_CLASS and now - entry["timestamp"] <= 600:
                    crash_recent += 1
            if crash_recent >= 2:
                return {"ok": False, "code": "google_services_process_unstable", "detail": f"{package}:crashLoop"}
        return {"ok": True, "code": None, "detail": None}

    def _microg_process_identity(self, process: str) -> Optional[tuple[int, int]]:
        pid_output = self._adb_shell_text(["pidof", process], timeout=10)
        if not pid_output or not pid_output.strip().isdigit():
            return None
        pid = int(pid_output.strip())
        stat_output = self._adb_shell_text(["cat", f"/proc/{pid}/stat"], timeout=10)
        if not stat_output:
            return None
        try:
            start_ticks = int(stat_output.rsplit(")", 1)[1].split()[19])
        except (ValueError, IndexError):
            return None
        return pid, start_ticks

    def _microg_process_stability(self, components: Mapping[str, Any], deadline: float) -> dict[str, Any]:
        unstable = {"ok": False, "code": "google_services_process_unstable"}
        first = self._microg_process_identity("com.google.android.gms:persistent")
        if first is None:
            return {**unstable, "detail": "gmsCorePersistentMissing"}
        time.sleep(min(5.0, max(0.0, deadline - time.monotonic())))
        second = self._microg_process_identity("com.google.android.gms:persistent")
        if second is None or second != first:
            return {**unstable, "detail": "gmsCorePersistentRestarted"}
        history = self._microg_exit_history(
            {"com.google.android.gms", "com.android.vending"},
            deadline,
        )
        if history.get("ok") is not True:
            return history
        store_state = "dormant"
        store_identity = self._microg_process_identity("com.android.vending")
        if store_identity is not None:
            store_state = "stable"
        else:
            receivers = self._adb_shell_text(
                [
                    "cmd",
                    "package",
                    "query-receivers",
                    "-a",
                    "android.intent.action.BOOT_COMPLETED",
                    "com.android.vending",
                ],
                timeout=20,
            )
            enabled = components.get("playStoreSeed", {}).get("enabled") is True
            if receivers is None or "com.android.vending" not in receivers or not enabled:
                store_state = "failed"
                return {**unstable, "detail": "playStoreDormantInvalid"}
        return {"ok": True, "code": None, "detail": None, "playStoreState": store_state}

    def _google_services_gate_microg(self, spec: ReleaseSpec) -> dict[str, Any]:
        deadline = time.monotonic() + 120.0
        checks: dict[str, Any] = {}

        components: dict[str, Any] = {}
        components_ok = True
        for component in spec.components:
            record = self._microg_component_record(spec, component)
            components[str(component["id"])] = record
            components_ok = components_ok and record["ok"] is True
        checks["components"] = {
            "ok": components_ok,
            "code": None if components_ok else "google_services_component_mismatch",
        }

        policy_ok = True
        gms_dump = self._adb_shell_text(["dumpsys", "package", "com.google.android.gms"], timeout=30)
        if not gms_dump:
            policy_ok = False
        else:
            for permission in (
                "android.permission.CHANGE_DEVICE_IDLE_TEMP_WHITELIST",
                "android.permission.UPDATE_DEVICE_STATS",
                "android.permission.POST_NOTIFICATIONS",
            ):
                if f"{permission}: granted=true" not in gms_dump:
                    policy_ok = False
                    break
        if policy_ok:
            whitelist = self._adb_shell_text(["dumpsys", "deviceidle", "whitelist"], timeout=20)
            if whitelist is None or "com.google.android.gms" not in whitelist:
                policy_ok = False
        checks["productPolicy"] = {
            "ok": policy_ok,
            "code": None if policy_ok else "google_services_policy_mismatch",
        }

        signature_ok = bool(
            components.get("gmsCore", {}).get("ok") is True
            and components["gmsCore"]["signerSha256"] == MICROG_REAL_CERT_SHA256
            and components.get("gsfProxy", {}).get("ok") is True
            and components.get("playStoreSeed", {}).get("ok") is True
        )
        if signature_ok:
            desired: dict[str, Any] = {}
            try:
                desired = self.selected_runtime_image(spec=spec)
            except (GoogleServicesError, InstanceError, OSError, RuntimeError, ValueError):
                desired = {}
            image, _ = self._inspect_docker_object("image", str(desired.get("derivedTag") or ""))
            config = image.get("Config") if isinstance(image, dict) else None
            labels = config.get("Labels") if isinstance(config, dict) else None
            labels = labels if isinstance(labels, dict) else {}
            signature_ok = bool(
                desired.get("imageId")
                and isinstance(image, dict)
                and image.get("Id") == desired.get("imageId")
                and all(labels.get(key) == value for key, value in spec.labels.items())
            )
        checks["signaturePolicy"] = {
            "ok": signature_ok,
            "code": None if signature_ok else "google_services_signature_policy_mismatch",
        }

        service_missing = "google_services_service_unavailable"
        authenticator_dump = self._adb_shell_text(["dumpsys", "account"], timeout=20)
        authenticator_ok = bool(
            authenticator_dump
            and "AuthenticatorDescription {type=com.google}" in authenticator_dump
            and "com.google.android.gms/" in authenticator_dump
        )
        checks["accountAuthenticator"] = {
            "ok": authenticator_ok,
            "code": None if authenticator_ok else service_missing,
        }

        def _service_owner(action: str) -> Optional[str]:
            output = self._adb_shell_text(
                ["cmd", "package", "query-services", "--brief", "-a", action, "com.google.android.gms"],
                timeout=20,
            )
            if not output or "services found" not in output:
                return None
            for line in output.splitlines():
                stripped = line.strip()
                if stripped.startswith("com.google.android.gms/"):
                    return stripped
            return None

        broker_ok = _service_owner("com.google.android.gms.common.service.START") is not None
        checks["boundBroker"] = {"ok": broker_ok, "code": None if broker_ok else service_missing}
        registrar_ok = _service_owner("com.google.android.c2dm.intent.REGISTER") is not None
        checks["fcmRegistrar"] = {"ok": registrar_ok, "code": None if registrar_ok else service_missing}
        fused_ok = (
            _service_owner("com.google.android.location.internal.GoogleLocationManagerService.START")
            is not None
        )
        checks["fusedProvider"] = {"ok": fused_ok, "code": None if fused_ok else service_missing}

        resolved = self.adb(
            [
                "shell",
                "cmd",
                "package",
                "resolve-activity",
                "--brief",
                "-a",
                "android.intent.action.MAIN",
                "-c",
                "android.intent.category.LAUNCHER",
                "com.android.vending",
            ],
            timeout=20,
        )
        resolved_lines = [
            line.strip()
            for line in str(resolved.get("stdout") or "").splitlines()
            if line.strip()
        ]
        resolved_text = resolved_lines[-1] if resolved_lines else ""
        launcher_ok = resolved.get("ok") is True and resolved_text.startswith("com.android.vending/")
        checks["playStoreLauncher"] = {
            "ok": launcher_ok,
            "code": None if launcher_ok else service_missing,
        }

        if components_ok:
            stability = self._microg_process_stability(components, deadline)
        else:
            stability = {"ok": False, "code": "google_services_component_mismatch", "detail": "componentsUnavailable"}
        checks["processStability"] = {"ok": stability.get("ok") is True, "code": stability.get("code")}
        store_state = stability.get("playStoreState")
        if isinstance(store_state, str) and components.get("playStoreSeed", {}).get("ok") is True:
            components["playStoreSeed"]["processState"] = store_state
        if stability.get("ok") is True and components.get("gmsCore", {}).get("ok") is True:
            components["gmsCore"]["processState"] = "stable"
        if components.get("gsfProxy", {}).get("ok") is True:
            components["gsfProxy"]["processState"] = "dormant"

        ok = all(check.get("ok") is True for check in checks.values())
        for component in components.values():
            component.pop("ok", None)
            component.pop("code", None)
        return {
            "ok": ok,
            "checks": checks,
            "error": None if ok else "google_services_runtime_not_ready",
            "components": components,
        }

    def _select_convergence_image(
        self,
        image_record: Optional[Mapping[str, Any]],
    ) -> dict[str, Any]:
        if image_record is None:
            return self.selected_runtime_image()
        record = dict(image_record)
        if not all(
            isinstance(record.get(key), str) and record.get(key)
            for key in ("derivedTag", "imageId", "baseImageId")
        ):
            input_sha = record.get("inputSha256")
            boot_sha = record.get("bootInputSha256")
            if (
                not isinstance(input_sha, str)
                or _SHA256_PATTERN.fullmatch(input_sha) is None
                or not isinstance(boot_sha, str)
                or _SHA256_PATTERN.fullmatch(boot_sha) is None
            ):
                raise InstanceError(
                    "runtime_image_record_invalid",
                    "journaled runtime image identity is invalid",
                )
            resolved = self._runtime_image_builder().lookup(input_sha)
            if (
                not isinstance(resolved, Mapping)
                or resolved.get("bootInputSha256") != boot_sha
            ):
                raise InstanceError(
                    "runtime_image_record_invalid",
                    "journaled runtime image record is unavailable",
                )
            record = dict(resolved)
        required = (
            "inputSha256",
            "bootInputSha256",
            "derivedTag",
            "imageId",
            "baseImageId",
        )
        if (
            any(not isinstance(record.get(key), str) or not record[key] for key in required)
            or _SHA256_PATTERN.fullmatch(str(record["inputSha256"])) is None
            or _SHA256_PATTERN.fullmatch(str(record["bootInputSha256"])) is None
            or not str(record["imageId"]).startswith("sha256:")
            or not str(record["baseImageId"]).startswith("sha256:")
        ):
            raise InstanceError(
                "runtime_image_record_invalid",
                "journaled runtime image record is invalid",
            )
        validate_image_reference(
            str(record["derivedTag"]),
            require_tag=True,
            allow_digest=False,
        )
        image, inspected = self._inspect_docker_object(
            "image",
            str(record["derivedTag"]),
        )
        config = image.get("Config") if isinstance(image, Mapping) else None
        labels = config.get("Labels") if isinstance(config, Mapping) else None
        expected_labels = {
            _RUNTIME_SCHEMA_LABEL: "1",
            _RUNTIME_INPUT_LABEL: str(record["inputSha256"]),
            _RUNTIME_BOOT_INPUT_LABEL: str(record["bootInputSha256"]),
            _RUNTIME_BASE_IMAGE_LABEL: str(record["baseImageId"]),
        }
        if (
            inspected.returncode != 0
            or not isinstance(image, Mapping)
            or image.get("Id") != record["imageId"]
            or image.get("Architecture") not in {"arm64", "aarch64"}
            or not isinstance(labels, Mapping)
            or any(labels.get(key) != value for key, value in expected_labels.items())
        ):
            raise InstanceError(
                "runtime_image_record_invalid",
                "journaled runtime image no longer matches the engine",
            )
        self._selected_runtime_image = record
        return dict(record)

    @staticmethod
    def _committed_storage_uuids(
        state: Optional[Mapping[str, Any]],
    ) -> tuple[Optional[str], Optional[str]]:
        if not isinstance(state, Mapping) or state.get("state") != "committed":
            return None, None
        data_uuid = state.get("filesystemUuid")
        rootfs_uuid = state.get("rootfsFilesystemUuid")
        return (
            str(data_uuid) if isinstance(data_uuid, str) else None,
            str(rootfs_uuid) if isinstance(rootfs_uuid, str) else None,
        )

    def converge_storage(
        self,
        boot_seed_target: Optional[Mapping[str, Any]] = None,
        regeneration_capability: Any = None,
        expected_data_uuid: Optional[str] = None,
        expected_rootfs_uuid: Optional[str] = None,
        storage_transaction_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Converge storage once, validating any executor-pinned UUID targets."""
        if regeneration_capability is not None and not isinstance(
            regeneration_capability,
            Mapping,
        ):
            return self._storage_error(
                "device_regeneration_state_invalid",
                "regeneration capability is invalid",
            )
        if isinstance(boot_seed_target, Mapping):
            expected_data_uuid = str(
                boot_seed_target.get("dataUuid") or expected_data_uuid or ""
            ) or None
            expected_rootfs_uuid = str(
                boot_seed_target.get("rootfsUuid")
                or expected_rootfs_uuid
                or ""
            ) or None
            storage_transaction_id = str(
                boot_seed_target.get("transactionId")
                or storage_transaction_id
                or ""
            ) or None
        result = self.ensure_instance_storage(
            expected_data_uuid=expected_data_uuid,
            expected_rootfs_uuid=expected_rootfs_uuid,
            storage_transaction_id=storage_transaction_id,
        )
        if result.get("ok") is not True:
            return result
        try:
            state = StorageStateStore(self.context, self.lease).load()
        except StorageError as exc:
            return exc.as_dict()
        data_uuid, rootfs_uuid = self._committed_storage_uuids(state)
        if expected_data_uuid is not None or expected_rootfs_uuid is not None:
            expected_data = expected_data_uuid
            expected_rootfs = expected_rootfs_uuid
            if (
                expected_data is not None
                and expected_data != data_uuid
                or expected_rootfs is not None
                and expected_rootfs != rootfs_uuid
            ):
                return self._storage_error(
                    "storage_identity_mismatch",
                    "committed storage differs from the fixed convergence target",
                )
        return {
            **result,
            "dataUuid": data_uuid,
            "rootfsUuid": rootfs_uuid,
        }

    def create_owned_container(
        self,
        image_record: Optional[Mapping[str, Any]] = None,
        expected_data_uuid: Optional[str] = None,
        expected_rootfs_uuid: Optional[str] = None,
        *,
        adopt_stopped_only: bool = False,
    ) -> dict[str, Any]:
        """Create, but never start, exactly one owned runtime container."""
        self.ensure_instance_lease()
        existing, error = self._owned_container_record()
        if existing is not None:
            existing_id = str(existing.get("Id") or "")
            existing_state = existing.get("State")
            stopped = (
                isinstance(existing_state, Mapping)
                and existing_state.get("Running") is False
            )
            if (
                self._container_matches_lease(existing)
                and (not adopt_stopped_only or stopped)
            ):
                return {
                    "ok": True,
                    "alreadyCreated": True,
                    "containerId": existing_id,
                }
            return {
                "ok": False,
                "error": "convergence_state_conflict",
                "message": "an owned third-state container already exists",
                "containerId": existing_id or None,
            }
        if error != "instance container does not exist":
            return {"ok": False, "error": "resource_conflict", "message": error}
        try:
            selected = self._select_convergence_image(image_record)
            storage = StorageStateStore(self.context, self.lease).load()
        except (InstanceError, StorageError) as exc:
            return {
                "ok": False,
                "error": getattr(exc, "code", "runtime_image_record_invalid"),
                "message": str(exc),
            }
        data_uuid, rootfs_uuid = self._committed_storage_uuids(storage)
        if data_uuid is None:
            return self._storage_error(
                "storage_not_initialized",
                "committed storage is required before container creation",
            )
        if (
            expected_data_uuid is not None
            and expected_data_uuid != data_uuid
            or expected_rootfs_uuid is not None
            and expected_rootfs_uuid != rootfs_uuid
        ):
            return self._storage_error(
                "storage_identity_mismatch",
                "container creation storage differs from the journal",
            )
        network = self.ensure_network()
        if network.get("ok") is not True:
            return {"ok": False, "error": "resource_conflict", "network": network}
        volume, _ = self._inspect_docker_object("volume", self.lease.volume_name)
        if not isinstance(volume, dict) or not self._volume_matches_lease(volume):
            return self._storage_error(
                "resource_conflict",
                "instance data volume identity is invalid",
            )
        binder = self.ensure_binder()
        if binder.get("ok") is not True:
            return {"ok": False, "error": "binder_setup_failed", "binder": binder}
        cleanup = self.proxy_cleanup()
        if cleanup.get("ok") is not True:
            return {
                "ok": False,
                "error": "proxy_cleanup_failed",
                "proxyCleanup": cleanup,
            }
        boot_seed = self._seed_boot_identity_into_image()
        if boot_seed.get("ok") is not True:
            return {
                "ok": False,
                "error": str(
                    boot_seed.get("error")
                    or "device_boot_seed_failed"
                ),
            }
        command = self.docker_create_command()
        if not any("/dev/binder" in item for item in command):
            return {
                "ok": False,
                "error": "binder_setup_failed",
                "message": "verified binder mounts are unavailable",
            }
        created = run(command, timeout=120, env=self.docker_env())
        if created.returncode != 0:
            return {
                "ok": False,
                "error": "container_create_failed",
                "returncode": created.returncode,
            }
        container, ownership_error = self._owned_container_record()
        if container is None:
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": ownership_error,
            }
        image_identity = self._container_effective_image_identity(container)
        if (
            image_identity.get("ok") is not True
            or not self._container_matches_lease(
                container,
                image_identity=image_identity,
            )
        ):
            return {
                "ok": False,
                "error": "container_contract_invalid",
                "containerId": container.get("Id"),
            }
        return {
            "ok": True,
            "created": True,
            "containerId": container["Id"],
            "imageId": selected["imageId"],
            "dataUuid": data_uuid,
            "rootfsUuid": rootfs_uuid,
            "proxyCleanup": cleanup,
            "bootSeed": {
                "seeded": not bool(boot_seed.get("skipped")),
            },
        }

    def start_owned_container(
        self,
        expected_container_id: Optional[str] = None,
        wait: bool = True,
        *,
        allow_journaled_spec_drift: bool = False,
        expected_image_input_sha256: Optional[str] = None,
        expected_image_boot_input_sha256: Optional[str] = None,
    ) -> dict[str, Any]:
        """Start one already-created container and establish bounded transports."""
        self.ensure_instance_lease()
        container, error = self._owned_container_record()
        if container is None:
            return {
                "ok": False,
                "error": "convergence_state_conflict",
                "message": error,
            }
        container_id = str(container.get("Id") or "")
        if (
            re.fullmatch(r"[0-9a-f]{64}", container_id) is None
            or expected_container_id is not None
            and container_id != expected_container_id
        ):
            return {
                "ok": False,
                "error": "convergence_state_conflict",
                "message": "owned container identity differs from the journal",
            }
        if allow_journaled_spec_drift and expected_container_id is None:
            return {
                "ok": False,
                "error": "convergence_state_conflict",
            }
        selected_image_pinned = (
            expected_image_input_sha256 is not None
            or expected_image_boot_input_sha256 is not None
        )
        if selected_image_pinned and (
            not isinstance(expected_image_input_sha256, str)
            or _SHA256_PATTERN.fullmatch(expected_image_input_sha256) is None
            or not isinstance(expected_image_boot_input_sha256, str)
            or _SHA256_PATTERN.fullmatch(expected_image_boot_input_sha256) is None
        ):
            return {
                "ok": False,
                "error": "convergence_state_conflict",
            }

        def matches_selected_contract(value: Mapping[str, Any]) -> bool:
            if allow_journaled_spec_drift:
                return True
            if not selected_image_pinned:
                return self._container_matches_lease(value)
            image_identity = self._container_effective_image_identity(value)
            observed_input = image_identity.get("containerInputSha256")
            observed_boot = image_identity.get("containerBootInputSha256")
            if image_identity.get("match") == "exact":
                observed_input = image_identity.get("desiredInputSha256")
                observed_boot = image_identity.get("desiredBootInputSha256")
            return bool(
                image_identity.get("ok") is True
                and observed_input == expected_image_input_sha256
                and observed_boot == expected_image_boot_input_sha256
                and self._container_matches_lease(
                    value,
                    image_identity={"ok": True},
                )
            )
        if not matches_selected_contract(container):
            return {
                "ok": False,
                "error": "runtime_spec_mismatch",
                "containerId": container_id,
            }
        state = container.get("State")
        running = isinstance(state, Mapping) and state.get("Running") is True
        result: dict[str, Any] = {
            "ok": True,
            "containerId": container_id,
            "alreadyRunning": running,
        }
        if not running:
            quarantine = self.proxy_bootstrap_quarantine()
            result["proxyQuarantine"] = quarantine
            if quarantine.get("ok") is not True:
                return {
                    **result,
                    "ok": False,
                    "error": quarantine.get("code", "engine_unavailable"),
                }
            with self._shared_protection_engine_lock():
                fresh, fresh_error = self._owned_container_record()
                if fresh is None:
                    return {
                        **result,
                        "ok": False,
                        "error": "convergence_state_conflict",
                        "message": fresh_error,
                    }
                fresh_id = str(fresh.get("Id") or "")
                fresh_state = fresh.get("State")
                fresh_running = (
                    isinstance(fresh_state, Mapping)
                    and fresh_state.get("Running") is True
                )
                if (
                    fresh_id != container_id
                    or not matches_selected_contract(fresh)
                ):
                    return {
                        **result,
                        "ok": False,
                        "error": "convergence_state_conflict",
                    }
                protection = self.shared_protection_manager().status()
                result["sharedProtection"] = protection
                if (
                    protection.get("ok") is not True
                    or protection.get("maintenanceRequired") is True
                ):
                    return {
                        **result,
                        "ok": False,
                        "error": str(
                            protection.get("error")
                            or "shared_protection_not_ready"
                        ),
                    }
                if fresh_running:
                    running = True
                    result["alreadyRunning"] = True
                else:
                    started = self._shared_protection_engine_shell(
                        "set -eu; command -v docker >/dev/null 2>&1; "
                        "docker start "
                        + shlex.quote(container_id)
                        + " >/dev/null",
                        timeout=60,
                    )
                    result["start"] = {
                        "ok": started.returncode == 0,
                        "returncode": started.returncode,
                        "stderr": started.stderr.strip()[-500:],
                    }
                    if started.returncode != 0:
                        return {
                            **result,
                            "ok": False,
                            "error": "container_start_failed",
                        }
        if not wait:
            return result
        deadline = time.monotonic() + 300.0
        result["boot"] = self.docker_wait_boot(
            timeout_sec=max(1, int(deadline - time.monotonic())),
        )
        if result["boot"].get("ok") is not True:
            return {**result, "ok": False, "error": "runtime_boot_timeout"}
        result["adbAuthorization"] = self.ensure_adb_authorized_key()
        if result["adbAuthorization"].get("ok") is not True:
            return {**result, "ok": False, "error": "adb_authorization_failed"}
        if self.lease.android_adb_port != 5555:
            result["adbPort"] = self.switch_adbd_port_via_docker()
            if result["adbPort"].get("ok") is not True:
                return {**result, "ok": False, "error": "adb_port_failed"}
        if not running:
            result["adbDisconnectStale"] = self.adb_disconnect()
        result["adbConnect"] = self.adb_connect()
        result["adbWait"] = self.adb_wait(
            timeout_sec=max(
                1,
                min(90, int(deadline - time.monotonic())),
            )
        )
        if result["adbWait"].get("ok") is not True:
            return {**result, "ok": False, "error": "adb_wait_timeout"}
        result["daemonForward"] = self.forward_daemon_port(
            timeout=max(1.0, min(30.0, deadline - time.monotonic())),
        )
        if result["daemonForward"].get("ok") is not True:
            return {**result, "ok": False, "error": "daemon_forward_failed"}
        try:
            storage_state = StorageStateStore(self.context, self.lease).load()
        except StorageError:
            storage_state = None
        if isinstance(storage_state, Mapping) and storage_state.get("state") == "committed":
            # A committed runtime already owns the daemon app: starting the
            # container must also establish the bounded daemon transport before
            # later phases observe daemon-owned state (storage sentinel, gates).
            result["daemonTransport"] = self.wait_daemon_transport(
                max(1.0, min(120.0, deadline - time.monotonic())),
                allow_activity_launch=False,
            )
            if result["daemonTransport"].get("ok") is not True:
                return {
                    **result,
                    "ok": False,
                    "error": str(
                        result["daemonTransport"].get("error")
                        or "daemon_transport_timeout"
                    ),
                }
        return result

    def start_seed_runtime(
        self,
        image_record: Mapping[str, Any],
        boot_seed_target: Mapping[str, Any],
        *,
        expected_data_uuid: Optional[str] = None,
        operation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Create/start the one explicit fresh-data seed runtime."""
        try:
            from .location import DEFAULT_COUNTRY, LocationError, LocationStateStore

            location_store = LocationStateStore(self.context.state_root)
            location_state, _ = location_store.ensure(
                self.context.instance_id,
                DEFAULT_COUNTRY,
            )
            if location_state.get("pending") is None:
                location_store.set_desired(str(location_state["desiredCountry"]))
        except LocationError as exc:
            return {"ok": False, "error": exc.code}
        try:
            google_spec = self.google_runtime_spec(
                "fresh-storage-binding",
                require_assets=True,
            )
            if google_spec is not None:
                google_preflight = self._google_binding_preflight(google_spec)
                self._begin_google_binding(google_spec, google_preflight)
        except (GoogleServicesError, StorageError) as exc:
            return {
                "ok": False,
                "error": getattr(
                    exc,
                    "code",
                    "google_services_runtime_not_ready",
                ),
            }
        storage = self.converge_storage(
            boot_seed_target=boot_seed_target,
        )
        if storage.get("ok") is not True:
            return storage
        created = self.create_owned_container(
            image_record=image_record,
            expected_data_uuid=str(boot_seed_target.get("dataUuid") or "") or None,
            expected_rootfs_uuid=str(boot_seed_target.get("rootfsUuid") or "") or None,
            adopt_stopped_only=True,
        )
        if created.get("ok") is not True:
            return created
        quarantined = self.quarantine_proxy_for_lifecycle(
            expected_data_uuid,
            operation_id,
        )
        if quarantined.get("ok") is not True:
            return quarantined
        started = self.start_owned_container(
            expected_container_id=str(created.get("containerId") or ""),
            wait=True,
        )
        return {
            **started,
            "seed": True,
            "bootSeedTarget": dict(boot_seed_target),
            "dataUuid": storage.get("dataUuid"),
            "rootfsUuid": storage.get("rootfsUuid"),
        }

    def initialize_seed_runtime(
        self,
        expected_container_id: str,
        boot_seed_target: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Quiesce the seed runtime and apply its fixed offline boot identity."""
        prepared_location = self._prepare_location_for_replacement(
            expected_container_id,
        )
        if prepared_location.get("ok") is not True:
            return prepared_location
        quiesced = self.quiesce_owned_container(expected_container_id)
        if quiesced.get("ok") is not True:
            return quiesced
        boot_id = boot_seed_target.get("bootId")
        random_uuid = boot_seed_target.get("randomUuid")
        if isinstance(boot_id, str) and isinstance(random_uuid, str):
            seeded = self._run_boot_identity_seed(boot_id, random_uuid)
        else:
            seeded = self._seed_boot_identity_into_image()
        if seeded.get("ok") is not True:
            return seeded
        return {
            "ok": True,
            "containerId": expected_container_id,
            "seeded": not bool(seeded.get("skipped")),
            "seed": seeded,
            "location": prepared_location,
        }

    def start(
        self,
        dry_run: bool = False,
        wait: bool = True,
        install_daemon_apk: Optional[str] = None,
        start_colima: bool = False,
        adb_root: bool = True,
        skip_preflight: bool = False,
        recreate: bool = False,
        defer_proxy: bool = False,
    ) -> dict[str, Any]:
        """Explicit low-level runtime control.

        Production convergence uses the specific methods above.  This method
        retains the intentional ``start --recreate`` development control but
        never builds artifacts/images, reloads protection, deploys an implicit
        component set, or performs aggregate acceptance.
        """
        self.ensure_instance_lease()
        plan: dict[str, Any] = {
            "backend": self.cfg.backend,
            "adbTarget": self.adb_target,
            "daemonPort": self.lease.host_daemon_port,
            "recreate": bool(recreate),
            "convergence": False,
        }
        if not dry_run and RegenerationJournal(self.context).pending():
            return {
                "ok": False,
                "error": "device_regeneration_pending",
                "message": "device regeneration must resume through convergence",
                "plan": plan,
            }
        try:
            selected_image = self.selected_runtime_image()
            plan["runtimeImage"] = selected_image
            plan["effectiveImage"] = selected_image["derivedTag"]
            plan["dockerCommand"] = self.docker_create_command()
        except (
            GoogleServicesError,
            InstanceError,
            OSError,
            RuntimeError,
            ValueError,
        ) as exc:
            return {
                "ok": False,
                "dry_run": bool(dry_run),
                "error": getattr(exc, "code", "runtime_image_required"),
                "message": str(exc),
                "plan": plan,
            }
        if dry_run:
            return {"ok": True, "dry_run": True, "plan": plan}
        if which("docker") is None:
            return {"ok": False, "error": "docker not found", "plan": plan}
        endpoint = self.docker_endpoint_host()
        if endpoint.startswith("tcp://"):
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "remote Docker contexts must use ssh://",
                "plan": plan,
            }
        if start_colima and self.should_use_colima():
            if which("colima") is None:
                return {"ok": False, "error": "colima not found", "plan": plan}
            colima = run(self.colima_start_command(), timeout=600)
            plan["colima"] = {
                "ok": colima.returncode == 0,
                "returncode": colima.returncode,
                "stderr": colima.stderr.strip()[-500:],
            }
            if colima.returncode != 0:
                return {"ok": False, "error": "colima_start_failed", "plan": plan}
        if not skip_preflight:
            preflight = self.runtime_preflight()
            plan["preflight"] = preflight
            if preflight.get("ok") is not True:
                return {
                    "ok": False,
                    "error": "runtime_preflight_failed",
                    "plan": plan,
                }
        container, lookup_error = self._owned_container_record()
        if container is None and lookup_error != "instance container does not exist":
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": lookup_error,
                "plan": plan,
            }
        if container is not None and recreate:
            removal = self.remove_owned_container_for_recreate(
                expected_container_id=str(container.get("Id") or ""),
            )
            plan["containerRecreate"] = removal
            if removal.get("ok") is not True:
                return {
                    "ok": False,
                    "error": removal.get("error", "container_remove_failed"),
                    "plan": plan,
                }
            container = None
        elif container is not None and not self._container_matches_lease(container):
            return {
                "ok": False,
                "error": "runtime_spec_mismatch",
                "message": "owned container requires explicit recreation",
                "plan": plan,
            }
        if container is None:
            storage = self.converge_storage()
            plan["storage"] = storage
            if storage.get("ok") is not True:
                return {
                    "ok": False,
                    "error": storage.get("error", "storage_convergence_failed"),
                    "plan": plan,
                }
            created = self.create_owned_container(
                image_record=selected_image,
                expected_data_uuid=storage.get("dataUuid"),
                expected_rootfs_uuid=storage.get("rootfsUuid"),
            )
            plan["containerCreate"] = created
            if created.get("ok") is not True:
                return {
                    "ok": False,
                    "error": created.get("error", "container_create_failed"),
                    "plan": plan,
                }
            container_id = str(created.get("containerId") or "")
        else:
            container_id = str(container.get("Id") or "")
        started = self.start_owned_container(
            expected_container_id=container_id,
            wait=wait,
        )
        result: dict[str, Any] = {**started, "plan": plan}
        if started.get("ok") is not True:
            return result
        if wait and adb_root:
            result["adbRoot"] = self.enable_adb_root()
            if result["adbRoot"].get("ok") is not True:
                return {**result, "ok": False, "error": "adb_root_failed"}
        if install_daemon_apk is not None:
            result["daemonInstall"] = self.install_daemon(install_daemon_apk)
            if result["daemonInstall"].get("ok") is not True:
                return {**result, "ok": False, "error": "daemon_install_failed"}
            result["daemonBootstrap"] = self.reconcile_control_plane()
            if result["daemonBootstrap"].get("ok") is not True:
                return {**result, "ok": False, "error": "daemon_bootstrap_failed"}
        result["deferProxy"] = bool(defer_proxy)
        result["ready"] = bool(result.get("ok"))
        return result

    def stop(self) -> dict[str, Any]:
        """Quarantine and stop the owned runtime without deleting its identity."""
        self.ensure_instance_lease()
        if which("docker") is None:
            return {"ok": False, "error": "docker not found"}
        container, error = self._owned_container_record()
        if container is None:
            if error != "instance container does not exist":
                return {"ok": False, "error": "resource_conflict", "message": error}
            try:
                cleanup = self.proxy_cleanup()
            except InstanceError as exc:
                cleanup = self._proxy_failure(exc.code)
            except Exception:
                cleanup = self._proxy_failure("engine_unavailable")
            return {
                "ok": cleanup.get("ok") is True,
                "alreadyStopped": True,
                "containerId": None,
                "preserved": True,
                "proxyCleanup": cleanup,
                **(
                    {}
                    if cleanup.get("ok") is True
                    else {"error": "proxy_cleanup_failed"}
                ),
            }
        return self._quiesce_container_safely(container)

    def data_sentinel(self, *, create: bool = False) -> dict[str, Any]:
        try:
            state = StorageStateStore(self.context, self.lease).load()
        except StorageError as exc:

            return exc.as_dict()
        if state is None or state.get("state") != "committed":
            return self._storage_error(
                "storage_not_initialized",
                "instance storage is not committed",
            )
        expected = f"{self.context.instance_id} {state['filesystemUuid']}"
        directory = "/data/local/tmp/runtime-state"
        path = f"{directory}/storage-sentinel.v1"
        quoted_expected = shlex.quote(expected)
        expected_digest = hashlib.sha256(f"{expected}\n".encode("ascii")).hexdigest()
        command = (
            "set -eu; "
            f"d={shlex.quote(directory)}; f={shlex.quote(path)}; "
            + (
                "if [ ! -e ${f} ]; then "
                "umask 077; mkdir -p ${d}; chown 0:0 ${d}; chmod 700 ${d}; "
                f"echo {quoted_expected} > ${{d}}/.storage-sentinel.new; "
                "chown 0:0 ${d}/.storage-sentinel.new; "
                "chmod 600 ${d}/.storage-sentinel.new; "
                "sync; "
                "mv -f ${d}/.storage-sentinel.new ${f}; sync; fi; "
                if create
                else ""
            )
            + "[ -d ${d} ] && [ ! -L ${d} ]; "
            "[ $(stat -c %u:%g:%a ${d}) = 0:0:700 ]; "
            "[ -f ${f} ] && [ ! -L ${f} ]; "
            "actual=$(sha256sum ${f}); actual=${actual%% *}; "
            f"[ ${{actual}} = {expected_digest} ]; "
            "[ $(stat -c %u:%g:%a ${f}) = 0:0:600 ]"
        )
        try:
            result = self.daemon_client(timeout=10.0).root_exec(command)
        except Exception:
            return self._storage_error(
                "storage_sentinel_unavailable",
                "live data sentinel is unavailable",
            )
        if not isinstance(result, dict) or result.get("ok") is not True:
            return self._storage_error(
                "storage_sentinel_mismatch",
                "live data sentinel does not match this instance",
            )
        return {
            "ok": True,
            "path": path,
            "instanceId": self.context.short_id,
            "filesystemUuid": state["filesystemUuid"],
            "createdIfMissing": create,
        }

    def device_identity_status(self) -> dict[str, Any]:
        try:
            state = DeviceIdentityStore(self.context).load()
        except IdentityError as exc:
            return exc.as_dict()
        if state is None:
            return {"ok": False, "initialized": False}
        return {"ok": True, **public_identity_state(state)}

    def storage_status(self) -> dict[str, Any]:
        store = StorageStateStore(self.context, self.lease)
        try:
            state = store.load()
        except StorageError as exc:
            return exc.as_dict()
        if state is None:
            return {
                "ok": False,
                "volume": self.lease.volume_name,
                **public_storage_state(
                    None,
                    healthy=False,
                    error="storage_not_initialized",
                ),
            }
        if state["state"] != "committed":
            return {
                "ok": False,
                "volume": self.lease.volume_name,
                **public_storage_state(
                    state,
                    healthy=False,
                    error="storage_transaction_pending",
                ),
            }
        volume, _ = self._inspect_docker_object("volume", self.lease.volume_name)
        if volume is None:
            return {
                "ok": False,
                "volume": self.lease.volume_name,
                **public_storage_state(
                    state,
                    healthy=False,
                    error="storage_volume_missing",
                ),
            }
        if not volume or not self._volume_matches_lease(volume):
            return {
                "ok": False,
                "volume": self.lease.volume_name,
                **public_storage_state(
                    state,
                    healthy=False,
                    error="resource_conflict",
                ),
            }
        image = self._inspect_volume_image(volume)
        if (
            not image.get("ok")
            or image.get("filesystemUuid") != state["filesystemUuid"]
            or int(image.get("logicalSizeBytes", 0)) > CANONICAL_DATA_SIZE_BYTES
            or int(image.get("filesystemSizeBytes", 0))
            > int(image.get("logicalSizeBytes", 0))
        ):
            return {
                "ok": False,
                "volume": self.lease.volume_name,
                "image": image,
                **public_storage_state(
                    state,
                    healthy=False,
                    error="storage_identity_mismatch",
                ),
            }
        if (
            image.get("logicalSizeBytes") != CANONICAL_DATA_SIZE_BYTES
            or image.get("filesystemSizeBytes") != CANONICAL_DATA_SIZE_BYTES
        ):
            return {
                "ok": False,
                "volume": self.lease.volume_name,
                "image": image,
                **public_storage_state(
                    state,
                    healthy=False,
                    error="storage_growth_required",
                ),
            }
        rootfs = self._inspect_volume_image(
            volume,
            image_name=ROOTFS_IMAGE_NAME,
        )
        mountpoint = volume.get("Mountpoint")
        marker = (
            self._engine_host_shell(
                "cat "
                + shlex.quote(
                    f"{str(mountpoint).rstrip('/')}/xenoid-rootfs.img.source.sha256"
                )
            )
            if isinstance(mountpoint, str)
            else None
        )
        rootfs_source = (
            str(marker.stdout or "").strip()
            if marker is not None and marker.returncode == 0
            else ""
        )
        migration_required = not bool(state.get("rootfsImage"))
        if (
            rootfs.get("ok") is not True
            or not migration_required
            and (
                rootfs.get("filesystemUuid") != state["rootfsFilesystemUuid"]
                or rootfs.get("logicalSizeBytes")
                != state["observedRootfsSizeBytes"]
                or rootfs_source != state["rootfsSourceSha256"]
            )
        ):
            return {
                "ok": False,
                "volume": self.lease.volume_name,
                "image": image,
                "rootfsImage": rootfs,
                **public_storage_state(
                    state,
                    healthy=False,
                    error="storage_identity_mismatch",
                ),
            }
        backup_status: Optional[dict[str, Any]] = None
        if state["backupImage"]:
            backup_status = self._inspect_volume_image(volume, state["backupImage"])
            if (
                not backup_status.get("ok")
                or backup_status.get("filesystemUuid")
                != state["backupFilesystemUuid"]
                or backup_status.get("logicalSizeBytes") != state["backupSizeBytes"]
            ):
                return {
                    "ok": False,
                    "volume": self.lease.volume_name,
                    "image": image,
                    "backupImage": backup_status,
                    **public_storage_state(
                        state,
                        healthy=False,
                        error="storage_backup_mismatch",
                    ),
                }
        return {
            "ok": True,
            "volume": self.lease.volume_name,
            "image": image,
            "backupImage": backup_status,
            "rootfsImage": rootfs,
            "migrationRequired": migration_required,
            **public_storage_state(state, healthy=True),
            **(
                {"warning": image["warning"]}
                if isinstance(image.get("warning"), str)
                else {}
            ),
        }

    def google_services_status(
        self,
        *,
        require_runtime: bool = False,
    ) -> dict[str, Any]:
        provider = self.cfg.google_services_provider
        release = self.cfg.google_services_release
        spec: Optional[ReleaseSpec] = None
        host_ready = provider == PROVIDER_NONE
        error: Optional[str] = None
        try:
            spec = self.google_runtime_spec("status", require_assets=False)
            if spec is not None:
                quick_validate_assets(self.context.project_root, spec)
                host_ready = True
        except GoogleServicesError as exc:
            error = exc.code

        status = base_status(provider, release, spec)
        binding: Optional[dict[str, Any]] = None
        try:
            binding = GoogleBindingStore(self.context, self.lease).load()
        except GoogleServicesError as exc:
            error = error or exc.code
        binding_ok = (
            binding is not None
            and spec is not None
            and binding_matches(binding, spec)
            and binding.get("state") == "committed"
        ) if provider != PROVIDER_NONE else (
            binding is None
            or (
                binding_matches(binding, None)
                and binding.get("state") == "committed"
            )
        )

        desired_runtime: Optional[dict[str, Any]] = None
        image: Optional[dict[str, Any]] = None
        try:
            desired_runtime = self.selected_runtime_image(spec=spec)
            image, _ = self._inspect_docker_object(
                "image",
                str(desired_runtime["derivedTag"]),
            )
        except (GoogleServicesError, InstanceError, OSError, RuntimeError, ValueError) as exc:
            error = error or getattr(exc, "code", "runtime_image_required")
        desired_image_id = (
            str(desired_runtime.get("imageId") or "")
            if desired_runtime is not None
            else ""
        )
        image_config = image.get("Config") if isinstance(image, dict) else None
        image_labels = (
            image_config.get("Labels")
            if isinstance(image_config, dict)
            else None
        )
        image_labels = image_labels if isinstance(image_labels, dict) else {}
        if spec is not None:
            image_labels_match: Optional[bool] = bool(
                desired_image_id
                and all(
                    image_labels.get(key) == value
                    for key, value in spec.labels.items()
                )
            )
        elif desired_image_id:
            image_labels_match = not any(
                key in image_labels for key in self._google_label_values()
            )
        else:
            image_labels_match = None

        container, _ = self._inspect_docker_object(
            "container",
            self.lease.container_name,
        )
        owned_container = bool(
            isinstance(container, dict)
            and container
            and self._container_has_lease_owner(container)
        )
        container_state = (
            container.get("State")
            if owned_container and isinstance(container, dict)
            else None
        )
        running = bool(
            isinstance(container_state, dict)
            and container_state.get("Running") is True
        )
        container_config = (
            container.get("Config")
            if owned_container and isinstance(container, dict)
            else None
        )
        container_labels = (
            container_config.get("Labels")
            if isinstance(container_config, dict)
            else None
        )
        container_labels_match = (
            self._managed_container_labels_match(container_labels)
            if owned_container
            else None
        )
        command_match = (
            container_config.get("Cmd") == self._android_boot_command()
            if isinstance(container_config, dict)
            else None
        )
        container_image_id = (
            str(container.get("Image") or "")
            if owned_container and isinstance(container, dict)
            else ""
        )
        container_identity = (
            self._container_effective_image_identity(container)
            if owned_container and isinstance(container, dict)
            else {"ok": False, "match": "absent"}
        )

        rootfs_source_id = ""
        volume, _ = self._inspect_docker_object(
            "volume",
            self.lease.volume_name,
        )
        if isinstance(volume, dict) and self._volume_matches_lease(volume):
            mountpoint = str(volume["Mountpoint"])
            marker = self._engine_host_shell(
                "cat "
                + shlex.quote(
                    f"{mountpoint}/xenoid-rootfs.img.sha256"
                )
                + " 2>/dev/null",
                timeout=30,
            )
            if marker.returncode == 0:
                rootfs_source_id = str(marker.stdout or "").strip()
        rootfs_image, _ = (
            self._inspect_docker_object("image", rootfs_source_id)
            if rootfs_source_id
            else (None, None)
        )
        rootfs_config = (
            rootfs_image.get("Config")
            if isinstance(rootfs_image, dict)
            else None
        )
        rootfs_labels = (
            rootfs_config.get("Labels")
            if isinstance(rootfs_config, dict)
            else None
        )
        rootfs_labels = rootfs_labels if isinstance(rootfs_labels, dict) else {}
        desired_boot_input = (
            str(desired_runtime.get("bootInputSha256") or "")
            if desired_runtime is not None
            else ""
        )
        rootfs_runtime_match = bool(
            rootfs_source_id
            and isinstance(rootfs_image, dict)
            and rootfs_image
            and rootfs_labels.get(_RUNTIME_SCHEMA_LABEL) == "1"
            and rootfs_labels.get(_RUNTIME_BOOT_INPUT_LABEL)
            == desired_boot_input
        )
        rootfs_google_match = bool(
            rootfs_runtime_match
            and (
                all(
                    rootfs_labels.get(key) == value
                    for key, value in spec.labels.items()
                )
                if spec is not None
                else not any(
                    key in rootfs_labels for key in self._google_label_values()
                )
            )
        )

        identity_ready = bool(
            desired_image_id
            and owned_container
            and container_identity.get("ok") is True
            and rootfs_runtime_match
            and rootfs_google_match
            and image_labels_match is True
            and container_labels_match is True
            and command_match is True
        )
        live: dict[str, Any] = {"ok": False, "checks": None, "error": None}
        effective_components: Optional[dict[str, Any]] = None
        if running:
            gate = self.google_services_bootstrap_gate(spec)
            if spec is not None and spec.provider == PROVIDER_MICROG:
                effective_components = gate.get("components")
                live = {
                    "ok": gate.get("ok") is True,
                    "checks": gate.get("checks"),
                    "error": gate.get("error"),
                }
            else:
                live = {
                    "ok": gate.get("ok") is True,
                    "checks": None,
                    "error": gate.get("error"),
                }

        configured = provider != PROVIDER_NONE
        ready = bool(
            configured
            and host_ready
            and binding_ok
            and identity_ready
            and running
            and live.get("ok") is True
        )
        if configured:
            runtime_state = "ready" if ready else (
                "failed" if running or error else "configured"
            )
            state = runtime_state
            ok = ready
            if not ready and error is None:
                error = "google_services_runtime_not_ready"
        else:
            clean = bool(
                not running
                or (
                    live.get("ok") is True
                    and (
                        not desired_image_id
                        or image_labels_match is True
                    )
                )
            )
            state = "running-clean" if running and clean else "disabled"
            ready = clean
            ok = clean
            runtime_state = "absent" if clean else "failed"
            if not clean:
                error = error or "unexpected_google_payload"
        if require_runtime and configured and not ready:
            ok = False

        model = capability_model(provider, runtime_state)
        selected = f"./xenoid --instance {self.context.instance_name}"
        next_actions: list[str] = []
        if error == "google_services_release_retired":
            next_actions.append(
                "the configured Google services release is retired; create a new instance with "
                f"the microG production release ({MICROG_PLAY_RELEASE}); existing data is never migrated"
            )
        if configured and not host_ready and error != "google_services_release_retired":
            if provider == PROVIDER_MICROG:
                next_actions.append(
                    f"{selected} google-services import-mindthegapps "
                    f"<MindTheGapps-13.0.0-arm64-20231025_200931.zip> <release.x509.pem>"
                )
                next_actions.append(
                    f"{selected} google-services import-microg "
                    "<com.google.android.gms-250932030.apk> <com.google.android.gsf-8.apk>"
                )
            else:
                next_actions.append(
                    f"{selected} google-services import-mindthegapps "
                    f"<{release}.zip> <release.x509.pem>"
                )
        if configured and not running:
            next_actions.append(f"{selected} up")
        elif configured and not ready:
            next_actions.append(
                f"{selected} doctor --require-runtime"
            )
        return {
            **status,
            "ok": ok,
            "state": state,
            "hostReady": host_ready,
            "runtimeRequired": configured,
            "runtimeChecked": running,
            "ready": ready,
            "skipped": not running,
            "binding": public_binding(binding),
            "runtimeIdentity": {
                "desiredImageSha256": desired_image_id or None,
                "containerImageSha256": container_image_id or None,
                "rootfsSourceImageSha256": rootfs_source_id or None,
                "desiredInputSha256": (
                    desired_runtime.get("inputSha256")
                    if desired_runtime is not None
                    else None
                ),
                "desiredBootInputSha256": (
                    desired_runtime.get("bootInputSha256")
                    if desired_runtime is not None
                    else None
                ),
                "containerInputSha256": container_identity.get(
                    "containerInputSha256"
                ),
                "containerBootInputSha256": container_identity.get(
                    "containerBootInputSha256"
                ),
                "imageMatch": container_identity.get("match"),
                "rootfsBootInputMatches": rootfs_runtime_match,
                "labelsMatch": (
                    image_labels_match is True
                    and container_labels_match is True
                    if owned_container and desired_image_id
                    else None
                ),
                "commandMatch": command_match,
                "skipped": not owned_container,
            },
            "live": live,
            "effectiveComponents": effective_components,
            **model,
            "error": error,
            "nextActions": next_actions,
        }

    def _observe_artifact_records(
        self,
    ) -> tuple[list[str], list[dict[str, Any]], Optional[ArtifactSnapshot]]:
        builder = object.__new__(ArtifactBuilder)
        builder.project_root = self.context.project_root.resolve()
        builder.catalog = TARGETS
        builder._requested_environment = dict(os.environ)
        builder._deadline = time.monotonic() + 60.0
        builder._cancelled = None
        builder._internal_cancel = threading.Event()
        builder._file_digest_cache = {}
        builder._version_digest_cache = {}
        builder._tool_identity_cache = {}
        records: list[ArtifactRecord] = []
        stale: list[str] = []
        public: list[dict[str, Any]] = []
        cache = (
            self.context.project_root
            / ".xenoid"
            / "cache"
            / "artifacts"
        )
        for name in _CONVERGENCE_ARTIFACT_TARGETS:
            target = TARGETS[name]
            record_path = cache / "v1" / f"{name}.json"
            try:
                info = record_path.lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size > 1024 * 1024
                ):
                    raise OSError
                raw = json.loads(record_path.read_text(encoding="ascii"))
                if set(raw) != {
                    "schema",
                    "target",
                    "inputSha256",
                    "toolSha256",
                    "outputs",
                    "completedAt",
                } or raw.get("target") != name:
                    raise ValueError
                input_sha, tool_sha = builder._identity(target)
                if (
                    raw.get("schema") != "dev.xenoid.artifact/v1"
                    or raw.get("inputSha256") != input_sha
                    or raw.get("toolSha256") != tool_sha
                    or not isinstance(raw.get("outputs"), list)
                ):
                    raise ValueError
                outputs: list[ArtifactOutput] = []
                sanitized_outputs: list[dict[str, Any]] = []
                for output in raw["outputs"]:
                    if not isinstance(output, Mapping):
                        raise ValueError
                    digest = output.get("sha256")
                    size = output.get("size")
                    mode_value = output.get("mode")
                    if (
                        not isinstance(digest, str)
                        or _SHA256_PATTERN.fullmatch(digest) is None
                        or not isinstance(size, int)
                        or isinstance(size, bool)
                        or not isinstance(mode_value, str)
                        or re.fullmatch(r"0[0-7]{3}", mode_value) is None
                    ):
                        raise ValueError
                    object_path = cache / "objects" / "sha256" / digest
                    object_info = object_path.lstat()
                    if (
                        not stat.S_ISREG(object_info.st_mode)
                        or stat.S_ISLNK(object_info.st_mode)
                        or object_info.st_uid != os.getuid()
                        or object_info.st_nlink != 1
                        or stat.S_IMODE(object_info.st_mode) != 0o600
                        or object_info.st_size != size
                        or hashlib.sha256(object_path.read_bytes()).hexdigest()
                        != digest
                    ):
                        raise OSError
                    artifact_output = ArtifactOutput(
                        str(output["path"]),
                        int(mode_value, 8),
                        size,
                        digest,
                    )
                    outputs.append(artifact_output)
                    sanitized_outputs.append(artifact_output.as_dict())
                record = ArtifactRecord(
                    name,
                    input_sha,
                    tool_sha,
                    tuple(outputs),
                    str(raw["completedAt"]),
                )
                records.append(record)
                public.append(
                    {
                        "schema": "dev.xenoid.artifact/v1",
                        "target": name,
                        "inputSha256": input_sha,
                        "toolSha256": tool_sha,
                        "outputs": sanitized_outputs,
                    }
                )
            except (KeyError, OSError, RuntimeError, TypeError, ValueError):
                stale.append(name)
        snapshot = (
            ArtifactSnapshot(
                tuple(record.target for record in records),
                tuple(records),
                hashlib.sha256(
                    json.dumps(
                        [
                            {
                                "target": record.target,
                                "inputSha256": record.input_sha256,
                                "toolSha256": record.tool_sha256,
                                "outputs": [
                                    output.as_dict()
                                    for output in record.outputs
                                ],
                            }
                            for record in records
                        ],
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("ascii")
                ).hexdigest(),
            )
            if not stale
            else None
        )
        return stale, public, snapshot

    def _observe_desired_runtime_image(
        self,
        snapshot: Optional[ArtifactSnapshot],
        *,
        selected_input_sha256: Optional[str] = None,
    ) -> tuple[Optional[dict[str, Any]], Optional[dict[str, Any]], Optional[str]]:
        if snapshot is None:
            return None, None, "artifact_record_unavailable"

        builder = object.__new__(RuntimeImageBuilder)
        builder.project_root = self.context.project_root.resolve()
        builder.docker_argv = tuple(self.docker_base_cmd())
        builder.docker_env = self.docker_env()
        builder.artifact_builder = ArtifactBuilder(self.context.project_root)
        builder._runner = self._run_runtime_image_command
        builder._engine_lock = self._runtime_image_engine_lock
        builder._cache_root = (
            self.context.project_root / ".xenoid" / "cache" / "runtime-images"
        )
        builder._local_lock_root = (
            self.context.project_root / ".xenoid" / "locks" / "runtime-images"
        )
        try:
            spec = self.google_runtime_spec(
                "convergence-observe",
                require_assets=False,
            )
            desired = builder.input_record(
                validate_image_reference(self.base_image_for_build()),
                configured_tag=validate_image_reference(
                    self.cfg.runtime_image_tag,
                    require_tag=True,
                    allow_digest=False,
                ),
                google_spec=spec,
            )
            selected = builder.lookup(
                selected_input_sha256 or str(desired["inputSha256"])
            )
            if selected is not None:
                image, inspected = self._inspect_docker_object(
                    "image",
                    str(selected["derivedTag"]),
                )
                if (
                    inspected.returncode != 0
                    or not isinstance(image, Mapping)
                    or image.get("Id") != selected.get("imageId")
                ):
                    selected = None
            return desired, selected, None
        except Exception as exc:
            return (
                None,
                None,
                str(getattr(exc, "code", "runtime_image_input_unavailable")),
            )

    def _observe_pending_operations(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "convergence": None,
            "regeneration": None,
        }
        for key, path in (
            ("convergence", self.context.state_root / "convergence-v1.json"),
            (
                "regeneration",
                RegenerationJournal(self.context).path,
            ),
        ):
            try:
                info = path.lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size > 256 * 1024
                ):
                    raise OSError
                raw = json.loads(path.read_text(encoding="ascii"))
                result[key] = {
                    "schema": raw.get("schema"),
                    "phase": raw.get("phase"),
                    "operationId": raw.get("operationId")
                    or raw.get("transactionId"),
                }
            except FileNotFoundError:
                pass
            except (OSError, UnicodeError, ValueError):
                result[key] = {"error": f"{key}_journal_invalid"}
        if result["regeneration"] is None:
            legacy_path = self.context.state_root / "device-regenerate.json"
            try:
                info = legacy_path.lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600
                ):
                    raise OSError
                raw = json.loads(legacy_path.read_text(encoding="ascii"))
                if (
                    not isinstance(raw, Mapping)
                    or set(raw) != {"schema", "instanceId", "startedAt"}
                    or raw.get("schema") != "dev.xenoid.device-regenerate/v1"
                    or raw.get("instanceId") != self.context.instance_id
                ):
                    raise ValueError
                result["regeneration"] = {
                    "schema": raw["schema"],
                    "phase": "legacy_pending",
                    "operationId": None,
                }
            except FileNotFoundError:
                pass
            except (OSError, UnicodeError, ValueError):
                result["regeneration"] = {
                    "error": "regeneration_journal_invalid"
                }
        return result

    def observe_convergence_inputs(self) -> dict[str, Any]:
        """Return only immutable source/artifact/image input identities."""
        self.ensure_instance_lease()
        artifact_targets, artifact_records, artifact_snapshot = (
            self._observe_artifact_records()
        )
        desired_image, _selected_image, _image_error = (
            self._observe_desired_runtime_image(artifact_snapshot)
        )
        return {
            "artifactTargets": artifact_targets,
            "artifactRecords": artifact_records,
            "desiredImageInputSha256": (
                desired_image.get("inputSha256")
                if isinstance(desired_image, Mapping)
                else None
            ),
            "desiredImageBootInputSha256": (
                desired_image.get("bootInputSha256")
                if isinstance(desired_image, Mapping)
                else None
            ),
        }


    def observe_convergence(self, skip_build: bool = False) -> dict[str, Any]:
        """Return the single read-only snapshot consumed by the planner."""
        self.ensure_instance_lease()
        artifact_targets, artifact_records, artifact_snapshot = (
            self._observe_artifact_records()
        )
        storage = self.storage_status()
        try:
            storage_state = StorageStateStore(self.context, self.lease).load()
        except StorageError:
            storage_state = None
        data_uuid, rootfs_uuid = self._committed_storage_uuids(storage_state)
        if data_uuid is None and isinstance(storage.get("filesystemUuid"), str):
            data_uuid = str(storage["filesystemUuid"])
        observed_rootfs = storage.get("rootfsImage")
        if (
            rootfs_uuid is None
            and isinstance(observed_rootfs, Mapping)
            and isinstance(observed_rootfs.get("filesystemUuid"), str)
        ):
            rootfs_uuid = str(observed_rootfs["filesystemUuid"])
        container, container_error = self._owned_container_record()
        ownership_valid = (
            container is not None
            or container_error == "instance container does not exist"
        )
        state = "absent"
        container_id: Optional[str] = None
        image_id: Optional[str] = None
        image_input: Optional[str] = None
        image_boot: Optional[str] = None
        create_spec: Optional[bool] = None
        integration_valid = True
        if container is not None:
            container_id = str(container.get("Id") or "") or None
            image_id = str(container.get("Image") or "") or None
            runtime_state = container.get("State")
            state = (
                "running"
                if isinstance(runtime_state, Mapping)
                and runtime_state.get("Running") is True
                else "stopped"
            )
            create_spec = self._container_matches_lease(
                container,
                image_identity={"ok": True},
            )
            config = container.get("Config")
            labels = config.get("Labels") if isinstance(config, Mapping) else None
            integration_valid = self._managed_container_labels_match(labels)
            current_image, _ = self._inspect_docker_object(
                "image",
                str(container.get("Image") or ""),
            )
            current_config = (
                current_image.get("Config")
                if isinstance(current_image, Mapping)
                else None
            )
            current_labels = (
                current_config.get("Labels")
                if isinstance(current_config, Mapping)
                else None
            )
            if isinstance(current_labels, Mapping):
                value = current_labels.get(_RUNTIME_INPUT_LABEL)
                image_input = value if isinstance(value, str) else None
                value = current_labels.get(_RUNTIME_BOOT_INPUT_LABEL)
                image_boot = value if isinstance(value, str) else None
        elif container_error != "instance container does not exist":
            ownership_valid = False
            integration_valid = False
        desired_image, selected_image, image_error = (
            self._observe_desired_runtime_image(
                artifact_snapshot,
                selected_input_sha256=image_input,
            )
        )
        network, _ = self._inspect_docker_object(
            "network",
            self.lease.network_name,
        )
        volume, _ = self._inspect_docker_object(
            "volume",
            self.lease.volume_name,
        )
        network_matches = (
            None if network is None else bool(network and self._network_matches_lease(network))
        )
        volume_matches = (
            None if volume is None else bool(volume and self._volume_matches_lease(volume))
        )
        identity = self.device_identity_status()
        identity_state = (
            "unknown"
            if identity.get("initialized") is not True
            else "pending"
            if identity.get("phase") not in {None, "applied"}
            else "matching"
        )
        try:
            from .location import (
                LocationStateStore,
                location_runtime_epoch,
                public_summary,
            )

            location_host = public_summary(
                LocationStateStore(self.context.state_root).load()
            )
            location_state = (
                "pending"
                if isinstance(location_host.get("pending"), Mapping)
                else "matching"
                if location_host.get("state") == "active"
                else "unknown"
            )
        except Exception:
            location_host = {"state": "invalid"}
            location_state = "incompatible"
        google = self.google_services_status(require_runtime=False)
        protection = self.observe_shared_protection()
        protection_error = protection.get("error")
        protection_state = (
            "matching"
            if protection.get("ok") is True
            else "incompatible"
            if protection_error
            in {
                "shared_protection_engine_unavailable",
                "shared_protection_ownership_ambiguous",
                "shared_protection_status_failed",
            }
            else "maintenance"
            if protection.get("maintenanceRequired") is True
            else "drift"
        )
        daemon_component: dict[str, Any] = {"state": "unknown"}
        deploy_components: dict[str, Any] = {
            name: {"state": "unknown"}
            for name in _CONVERGENCE_REMOTE_ARTIFACTS
        }
        bootstrap: Optional[dict[str, Any]] = None
        proxy_engine: Optional[dict[str, Any]] = None
        proxy_desired: Optional[dict[str, Any]] = None
        location_runtime_status: Optional[dict[str, Any]] = None
        adb_observation: dict[str, Any] = {"ok": False, "skipped": True}
        boot_observation: dict[str, Any] = {"ok": False, "skipped": True}
        sentinel: dict[str, Any] = {"ok": False, "skipped": True}
        if state == "running":
            adb_observation = (
                self.adb(["get-state"])
                if which("adb") is not None
                else {"ok": False, "error": "adb not found"}
            )
            boot_observation = self.docker_exec(
                ["getprop", "sys.boot_completed"],
                timeout=10,
            )
            desired_daemon = next(
                (
                    output["sha256"]
                    for record in artifact_records
                    if record.get("target") == "daemon"
                    for output in record.get("outputs", [])
                ),
                None,
            )
            installed_daemon = self._installed_daemon_apk_identity()
            daemon_component = {
                "state": (
                    "matching"
                    if desired_daemon is not None
                    and installed_daemon.get("sha256") == desired_daemon
                    else "drift"
                    if installed_daemon.get("state") in {"installed", "absent"}
                    else "unknown"
                ),
                "desiredSha256": desired_daemon,
                "installedSha256": installed_daemon.get("sha256"),
            }
            desired_by_target = {
                record["target"]: {
                    output["path"]: output
                    for output in record.get("outputs", [])
                }
                for record in artifact_records
            }
            for name, (output_path, remote_path, mode) in (
                _CONVERGENCE_REMOTE_ARTIFACTS.items()
            ):
                desired_output = desired_by_target.get(name, {}).get(output_path)
                observed = self._remote_file_identity(
                    remote_path,
                    require_arm64_elf=True,
                )
                deploy_components[name] = {
                    "state": (
                        "matching"
                        if isinstance(desired_output, Mapping)
                        and observed.get("sha256") == desired_output.get("sha256")
                        and observed.get("mode") == mode
                        and observed.get("architecture") == "arm64"
                        else "drift"
                        if isinstance(desired_output, Mapping)
                        else "unknown"
                    ),
                    "desiredSha256": (
                        desired_output.get("sha256")
                        if isinstance(desired_output, Mapping)
                        else None
                    ),
                    "installedSha256": observed.get("sha256"),
                }
            try:
                client = self.daemon_client(timeout=3.0)
                bootstrap = client.bootstrap_status(timeout=3.0)
                desired_status = client.proxy_status(timeout=3.0)
                if (
                    desired_status.get("ok") is True
                    and desired_status.get("stateReadable") is not False
                ):
                    proxy_desired = desired_status
                direct_location = client.location_status(timeout=3.0)
                if direct_location.get("ok") is True:
                    location_runtime_status = direct_location
                if bootstrap.get("state") in {"ready", "degraded", "failed"}:
                    sentinel = self.data_sentinel(create=False)
            except Exception:
                bootstrap = None
            try:
                proxy_engine = self._proxy_root_json("status")
            except Exception:
                proxy_engine = None
        components = (
            bootstrap.get("components")
            if isinstance(bootstrap, Mapping)
            and isinstance(bootstrap.get("components"), Mapping)
            else {}
        )
        if state == "running" and location_state == "matching":
            location_daemon = (
                components.get("location")
                if isinstance(components.get("location"), Mapping)
                else None
            )
            location_active = (
                location_host.get("active")
                if isinstance(location_host.get("active"), Mapping)
                else None
            )
            expected_location_epoch = (
                location_runtime_epoch(container_id)
                if isinstance(container_id, str)
                else None
            )
            if (
                not isinstance(location_daemon, Mapping)
                or not isinstance(location_runtime_status, Mapping)
                or not isinstance(location_active, Mapping)
                or location_daemon.get("ok") is not True
                or location_daemon.get("state") != "ready"
                or location_daemon.get("configured") is not True
                or location_runtime_status.get("state") != "active"
                or location_runtime_status.get("profileDigest")
                != location_active.get("profileDigest")
                or not isinstance(expected_location_epoch, str)
                or location_runtime_status.get("runtimeEpoch")
                != expected_location_epoch
                or location_active.get("lastValidatedRuntimeEpoch")
                != expected_location_epoch
            ):
                location_state = "drift"
        proxy_daemon = (
            components.get("proxy")
            if isinstance(components.get("proxy"), Mapping)
            else None
        )
        proxy_generation = (
            proxy_desired.get("generation")
            if isinstance(proxy_desired, Mapping)
            and isinstance(proxy_desired.get("generation"), int)
            and not isinstance(proxy_desired.get("generation"), bool)
            else proxy_daemon.get("generation")
            if isinstance(proxy_daemon, Mapping)
            and isinstance(proxy_daemon.get("generation"), int)
            else proxy_engine.get("generation")
            if isinstance(proxy_engine, Mapping)
            and isinstance(proxy_engine.get("generation"), int)
            else None
        )
        proxy_state = (
            "matching"
            if isinstance(proxy_engine, Mapping)
            and proxy_engine.get("ok") is True
            and (
                proxy_engine.get("dataPlaneVerified") is True
                or proxy_engine.get("phase") in {"off", "disabled"}
            )
            else "pending"
            if isinstance(proxy_daemon, Mapping)
            else "unknown"
        )
        pending = self._observe_pending_operations()
        return {
            "schema": "dev.xenoid.convergence-observation/v1",
            "instanceId": self.context.instance_id,
            "skipBuild": bool(skip_build),
            "artifactTargets": artifact_targets,
            "artifactRecords": artifact_records,
            "desiredImageInputSha256": (
                desired_image.get("inputSha256")
                if isinstance(desired_image, Mapping)
                else None
            ),
            "desiredImageBootInputSha256": (
                desired_image.get("bootInputSha256")
                if isinstance(desired_image, Mapping)
                else None
            ),
            "selectedImageRecord": selected_image,
            "imageError": image_error,
            "runtime": {
                "state": state,
                "containerId": container_id,
                "imageId": image_id,
                "ownershipValid": ownership_valid,
                "integrationIdentityValid": integration_valid,
                "storageValid": (
                    storage.get("ok") is True
                    or state == "absent"
                    and storage.get("error") == "storage_not_initialized"
                ),
                "storageMigrationRequired": storage.get("migrationRequired") is True,
                "createSpecMatches": create_spec,
                "networkMatches": network_matches,
                "volumeMatches": volume_matches,
                "imageInputSha256": image_input,
                "imageBootInputSha256": image_boot,
                "dataUuid": data_uuid,
                "rootfsUuid": rootfs_uuid,
                "bootSeedRequired": identity.get("initialized") is not True,
                "adb": adb_observation,
                "boot": boot_observation,
                "storageSentinel": sentinel,
            },
            "components": {
                "daemon": daemon_component,
                "deploy": deploy_components,
                "identity": {
                    "state": identity_state,
                    "containerEpoch": identity.get("containerEpoch"),
                    "phase": identity.get("phase"),
                    "status": identity,
                },
                "location": {
                    "state": location_state,
                    "host": location_host,
                    "daemon": components.get("location"),
                },
                "proxy": {
                    "state": proxy_state,
                    "generation": proxy_generation,
                    "enabled": (
                        proxy_desired.get("enabled")
                        if isinstance(proxy_desired, Mapping)
                        and isinstance(proxy_desired.get("enabled"), bool)
                        else None
                    ),
                    "quarantineRequired": (
                        False
                        if state == "absent"
                        else proxy_state != "matching"
                    ),
                    "daemon": proxy_daemon,
                    "engine": proxy_engine,
                },
                "keybox": {
                    "state": (
                        "matching"
                        if isinstance(components.get("keybox"), Mapping)
                        and components["keybox"].get("ok") is True
                        else "drift"
                        if isinstance(components.get("keybox"), Mapping)
                        else "unknown"
                    ),
                    "status": components.get("keybox"),
                },
                "camera": {
                    "state": (
                        "matching"
                        if isinstance(components.get("camera"), Mapping)
                        and components["camera"].get("ok") is True
                        else "drift"
                        if isinstance(components.get("camera"), Mapping)
                        else "unknown"
                    ),
                    "status": components.get("camera"),
                },
                "google": {
                    "state": "matching" if google.get("ready") is True else "drift",
                    "bindingReady": google.get("ready"),
                    "status": google,
                },
                "protection": {
                    "state": protection_state,
                    "expectedDigest": protection.get("expectedDigest"),
                    "currentDigest": protection.get("currentDigest"),
                    "replacementRequired": protection.get("replacementRequired"),
                    "maintenanceRequired": protection.get("maintenanceRequired"),
                    "siblingRuntimeActive": protection.get("siblingRuntimeActive"),
                    "error": protection_error,
                    "observed": protection,
                },
            },
            "acceptanceChecks": list(_CONVERGENCE_ACCEPTANCE_CHECKS),
            "pending": pending,
            "lease": {
                "state": self.lease.state,
                "transactionId": self.lease.transaction_id,
                "resourceTag": self.lease.resource_tag,
            },
            "storage": storage,
            "legacyTokenMigrationPending": self.legacy_token_migration_pending(),
        }

    def acceptance_context(self) -> dict[str, Any]:
        observation = self.observe_convergence(skip_build=True)
        runtime = observation["runtime"]
        proxy = observation["components"]["proxy"]
        protection = observation["components"]["protection"]
        return {
            "manager": self,
            "context": self.context,
            "observation": observation,
            "expected": {
                "containerId": runtime.get("containerId"),
                "imageId": runtime.get("imageId"),
                "dataUuid": runtime.get("dataUuid"),
                "rootfsUuid": runtime.get("rootfsUuid"),
                "imageInputSha256": runtime.get("imageInputSha256"),
                "imageBootInputSha256": runtime.get("imageBootInputSha256"),
                "proxyGeneration": proxy.get("generation"),
                "protectionDigest": protection.get("expectedDigest"),
            },
        }

    @staticmethod
    def _regeneration_digest(value: Mapping[str, Any]) -> str:
        payload = json.dumps(
            dict(value),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return hashlib.sha256(payload).hexdigest()

    def _offline_proxy_identity(self) -> tuple[bool, int]:
        volume, _ = self._inspect_docker_object("volume", self.lease.volume_name)
        mountpoint = volume.get("Mountpoint") if isinstance(volume, Mapping) else None
        if not isinstance(mountpoint, str) or not mountpoint.startswith("/"):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "offline proxy storage is unavailable",
            )
        image = f"{mountpoint.rstrip('/')}/{DATA_IMAGE_NAME}"
        def read_private(relative: str) -> Optional[tuple[dict[str, Any], bytes, int]]:
            request = relative.lstrip("/")
            metadata = self._engine_host_shell(
                "debugfs -R "
                + shlex.quote(f"stat {request}")
                + " "
                + shlex.quote(image)
                + " 2>/dev/null"
            )
            if metadata.returncode != 0:
                return None
            text = str(metadata.stdout or "")
            mode = re.search(r"Mode:\s*0*([0-7]{3,4})", text)
            links = re.search(r"Links:\s*(\d+)", text)
            owner = re.search(r"User:\s*(\d+)", text)
            size = re.search(r"Size:\s*(\d+)", text)
            if (
                "Type: regular" not in text
                or mode is None
                or int(mode.group(1), 8) != 0o600
                or links is None
                or int(links.group(1)) != 1
                or owner is None
                or int(owner.group(1)) < 10_000
                or size is None
                or not 0 < int(size.group(1)) <= 16 * 1024 * 1024
            ):
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "offline proxy v2 metadata is unsafe",
                )
            content = self._engine_host_shell(
                "debugfs -R "
                + shlex.quote(f"cat {request}")
                + " "
                + shlex.quote(image)
                + " 2>/dev/null"
            )
            raw = str(content.stdout or "").encode("utf-8")
            if content.returncode != 0 or len(raw) != int(size.group(1)):
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "offline proxy v2 object is unreadable",
                )
            try:
                document = json.loads(raw)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "offline proxy v2 object is invalid",
                ) from exc
            if not isinstance(document, dict):
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "offline proxy v2 object is invalid",
                )
            return document, raw, int(owner.group(1))

        for root in (
            "/user/0/dev.xenoid.daemon/no_backup/proxy-state/v2",
            "/data/dev.xenoid.daemon/no_backup/proxy-state/v2",
        ):
            active_record = read_private(f"{root}/active.json")
            if active_record is None:
                continue
            active, _, owner = active_record
            if set(active) != {"schemaVersion", "instanceId", "stateId", "keyId"}:
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "offline proxy v2 pointer is invalid",
                )
            state_id = active.get("stateId")
            key_id = active.get("keyId")
            if (
                active.get("schemaVersion") != 2
                or active.get("instanceId") != self.context.instance_id
            ):
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "offline proxy v2 pointer identity is invalid",
                )
            if (
                not isinstance(state_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", state_id) is None
                or not isinstance(key_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", key_id) is None
            ):
                raise IdentityError(
                    "proxy_legacy_live_proof_required",
                    "offline proxy v2 pointer requires authenticated recovery",
                )
            pending_check = self._engine_host_shell(
                "debugfs -R "
                + shlex.quote(f"stat {root.lstrip('/')}/pending.json")
                + " "
                + shlex.quote(image)
                + " 2>/dev/null"
            )
            if pending_check.returncode == 0:
                raise IdentityError(
                    "proxy_legacy_live_proof_required",
                    "offline proxy v2 transaction is pending",
                )
            key_request = f"{root.lstrip('/')}/keys/{key_id}.key"
            key_metadata = self._engine_host_shell(
                "debugfs -R "
                + shlex.quote(f"stat {key_request}")
                + " "
                + shlex.quote(image)
                + " 2>/dev/null"
            )
            key_text = str(key_metadata.stdout or "")
            if (
                key_metadata.returncode != 0
                or "Type: regular" not in key_text
                or re.search(r"Mode:\s*0*600", key_text) is None
                or re.search(r"Links:\s*1\b", key_text) is None
                or re.search(rf"User:\s*{owner}\b", key_text) is None
                or re.search(r"Size:\s*32\b", key_text) is None
            ):
                raise IdentityError(
                    "proxy_legacy_live_proof_required",
                    "offline proxy v2 key requires authenticated recovery",
                )
            key_probe = self._engine_host_shell(
                "set -eu; t=$(mktemp); trap 'rm -f \"$t\"' EXIT; "
                + "debugfs -R "
                + shlex.quote(f"dump {key_request} $t")
                + " "
                + shlex.quote(image)
                + " >/dev/null 2>&1; "
                + "printf '%s %s\\n' \"$(stat -c %s -- \"$t\")\" "
                + "\"$(sha256sum \"$t\" | cut -d' ' -f1)\""
            )
            key_fields = str(key_probe.stdout or "").strip().split()
            if (
                key_probe.returncode != 0
                or key_fields != ["32", key_id]
            ):
                raise IdentityError(
                    "proxy_legacy_live_proof_required",
                    "offline proxy v2 key requires authenticated recovery",
                )
            state_record = read_private(f"{root}/states/{state_id}.json")
            if state_record is None or state_record[2] != owner:
                raise IdentityError(
                    "proxy_legacy_live_proof_required",
                    "offline proxy v2 state requires authenticated recovery",
                )
            envelope, raw, _ = state_record
            generation = envelope.get("generation")
            enabled = envelope.get("enabled")
            if (
                envelope.get("schemaVersion") == 2
                and isinstance(envelope.get("instanceId"), str)
                and envelope.get("instanceId") != self.context.instance_id
            ):
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "offline proxy v2 state identity is invalid",
                )
            if (
                set(envelope) != {
                    "schemaVersion", "instanceId", "generation", "enabled",
                    "keyId", "sourceIv", "sourceCiphertext",
                }
                or envelope.get("schemaVersion") != 2
                or envelope.get("instanceId") != self.context.instance_id
                or envelope.get("keyId") != key_id
                or hashlib.sha256(raw).hexdigest() != state_id
                or isinstance(generation, bool)
                or not isinstance(generation, int)
                or generation < 0
                or not isinstance(enabled, bool)
            ):
                raise IdentityError(
                    "proxy_legacy_live_proof_required",
                    "offline proxy v2 state requires authenticated recovery",
                )
            if (
                envelope.get("sourceIv") is not None
                or envelope.get("sourceCiphertext") is not None
                or enabled is not False
            ):
                raise IdentityError(
                    "proxy_legacy_live_proof_required",
                    "offline configured proxy v2 requires authenticated decryption",
                )
            return enabled, generation
        candidates = (
            "/user/0/dev.xenoid.daemon/files/proxy-state/desired-v1.json",
            "/data/dev.xenoid.daemon/files/proxy-state/desired-v1.json",
        )
        for relative in candidates:
            request = relative.lstrip("/")
            metadata = self._engine_host_shell(
                "debugfs -R "
                + shlex.quote(f"stat {request}")
                + " "
                + shlex.quote(image)
                + " 2>/dev/null"
            )
            if metadata.returncode != 0:
                continue
            text = str(metadata.stdout or "")
            mode = re.search(r"Mode:\s*0*([0-7]{3,4})", text)
            links = re.search(r"Links:\s*(\d+)", text)
            owner = re.search(r"User:\s*(\d+)", text)
            size = re.search(r"Size:\s*(\d+)", text)
            if (
                "Type: regular" not in text
                or mode is None
                or int(mode.group(1), 8) != 0o600
                or links is None
                or int(links.group(1)) != 1
                or owner is None
                or int(owner.group(1)) < 10_000
                or size is None
                or not 0 < int(size.group(1)) <= 16 * 1024 * 1024
            ):
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "offline proxy state metadata is unsafe",
                )
            content = self._engine_host_shell(
                "debugfs -R "
                + shlex.quote(f"cat {request}")
                + " "
                + shlex.quote(image)
                + " 2>/dev/null"
            )
            raw = str(content.stdout or "")
            if (
                content.returncode != 0
                or len(raw.encode("utf-8")) != int(size.group(1))
            ):
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "offline proxy state is unreadable",
                )
            try:
                document = json.loads(raw)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "offline proxy state is invalid",
                ) from exc
            if not isinstance(document, Mapping) or set(document) != {
                "schemaVersion",
                "instanceId",
                "generation",
                "enabled",
                "sourceIv",
                "sourceCiphertext",
            }:
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "offline proxy state is invalid",
                )
            generation = document["generation"]
            enabled = document["enabled"]
            source_iv = document["sourceIv"]
            source_ciphertext = document["sourceCiphertext"]
            if (
                document["schemaVersion"] != 1
                or document["instanceId"] not in {
                    None,
                    self.context.instance_id,
                }
                or isinstance(generation, bool)
                or not isinstance(generation, int)
                or not 0 <= generation < (1 << 63)
                or not isinstance(enabled, bool)
                or enabled
                and (
                    not isinstance(source_iv, str)
                    or not isinstance(source_ciphertext, str)
                    or not source_iv
                    or not source_ciphertext
                )
                or not enabled
                and ((source_iv is None) != (source_ciphertext is None))
            ):
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "offline proxy state is invalid",
                )
            if source_iv is not None or source_ciphertext is not None:
                raise IdentityError(
                    "proxy_legacy_live_proof_required",
                    "configured legacy proxy requires live key readability proof",
                )
            return enabled, generation
        for root in (
            "/user/0/dev.xenoid.daemon/no_backup/proxy-state/v2",
            "/data/dev.xenoid.daemon/no_backup/proxy-state/v2",
        ):
            inspected = self._engine_host_shell(
                "debugfs -R "
                + shlex.quote(f"stat {root.lstrip('/')}")
                + " "
                + shlex.quote(image)
                + " 2>/dev/null"
            )
            if inspected.returncode == 0:
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "offline proxy v2 state requires exact pointer inspection",
                )
        try:
            host_state_exists = self._proxy_remote_exists(
                self._proxy_manifest_path
            )
        except Exception as exc:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "offline proxy host state is unreadable",
            ) from exc
        if host_state_exists:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "offline proxy host state exists without daemon state",
            )
        return False, 0


    def regeneration_snapshot(
        self,
        *,
        allow_absent: bool = False,
    ) -> dict[str, Any]:
        """Capture the complete immutable before-state for device regeneration."""
        self.ensure_instance_lease()
        container, error = self._owned_container_record()
        absent = container is None and error == "instance container does not exist"
        stopped = (
            isinstance(container, Mapping)
            and isinstance(container.get("State"), Mapping)
            and container["State"].get("Running") is False
        )
        offline = allow_absent and (absent or stopped)
        if offline:
            runtime_epoch = "0" * 64
            if stopped:
                if not self._container_has_lease_owner(dict(container)):
                    raise IdentityError(
                        "device_regeneration_state_invalid",
                        "stopped legacy runtime ownership is invalid",
                    )
                container_id = container.get("Id")
                image_id = container.get("Image")
            else:
                container_id = "0" * 64
                try:
                    image_id = str(self.selected_runtime_image()["imageId"])
                except Exception as exc:
                    raise IdentityError(
                        "device_regeneration_state_invalid",
                        "selected runtime image is unavailable for legacy recovery",
                    ) from exc
            if (
                not isinstance(container_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
                or not isinstance(image_id, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
            ):
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "offline legacy runtime identity is invalid",
                )
        else:
            if not isinstance(container, Mapping):
                raise IdentityError(
                    "device_runtime_not_running",
                    error or "owned runtime is unavailable",
                )
            runtime_state = container.get("State")
            container_id = container.get("Id")
            image_id = container.get("Image")
            if (
                not isinstance(runtime_state, Mapping)
                or runtime_state.get("Running") is not True
                or not isinstance(container_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
                or not isinstance(image_id, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
            ):
                raise IdentityError(
                    "device_runtime_not_running",
                    "device regeneration requires one running owned runtime",
                )
        identity = DeviceIdentityStore(self.context).load()
        storage = StorageStateStore(self.context, self.lease).load()
        data_before_uuid = (
            str(storage.get("filesystemUuid") or "")
            if isinstance(storage, Mapping)
            else ""
        )
        rootfs_before_uuid = (
            str(storage.get("rootfsFilesystemUuid") or "")
            if isinstance(storage, Mapping)
            else ""
        )
        legacy_pending = bool(
            allow_absent
            and isinstance(storage, Mapping)
            and storage.get("state") == "pending"
            and storage.get("temporaryImage") == ""
            and storage.get("rotationTargetUuid")
        )
        if (
            allow_absent
            and isinstance(storage, Mapping)
            and (
                storage.get("state") == "committed"
                and not rootfs_before_uuid
                or legacy_pending
            )
        ):
            volume, _ = self._inspect_docker_object(
                "volume",
                self.lease.volume_name,
            )
            observed_data = (
                self._inspect_volume_image(dict(volume))
                if isinstance(volume, Mapping)
                else {}
            )
            observed_rootfs = (
                self._inspect_volume_image(
                    dict(volume),
                    image_name=ROOTFS_IMAGE_NAME,
                )
                if isinstance(volume, Mapping)
                else {}
            )
            if (
                observed_data.get("ok") is not True
                or observed_rootfs.get("ok") is not True
                or legacy_pending
                and observed_data.get("filesystemUuid")
                not in {
                    storage.get("filesystemUuid"),
                    storage.get("rotationTargetUuid"),
                }
            ):
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "legacy storage transition is not an old-or-target state",
                )
            data_before_uuid = str(observed_data["filesystemUuid"])
            rootfs_before_uuid = str(observed_rootfs["filesystemUuid"])
        if (
            identity is None
            or storage is None
            or storage.get("state") != "committed"
            and not legacy_pending
            or not data_before_uuid
            or not rootfs_before_uuid
        ):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "identity and dual-image storage must be valid before regeneration",
            )
        from .location import LocationStateStore

        location = LocationStateStore(self.context.state_root).load()
        if location is None and allow_absent:
            location_sim_epoch = ""
            location_record: Mapping[str, Any] = {
                "profileDigest": "0" * 64,
            }
        else:
            active_location = (
                location.get("active")
                if isinstance(location, Mapping)
                else None
            )
            if not isinstance(location, Mapping) or not isinstance(
                active_location,
                Mapping,
            ):
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "location identity must be initialized before regeneration",
                )
            pending_location = location.get("pending")
            location_record = (
                pending_location
                if allow_absent and isinstance(pending_location, Mapping)
                else active_location
            )
            location_sim_epoch = str(location["simEpoch"])
        if offline:
            proxy_enabled, proxy_generation = self._offline_proxy_identity()
            proxy = {
                "enabled": proxy_enabled,
                "generation": proxy_generation,
            }
        else:
            try:
                client = self.daemon_client(timeout=15.0)
                bootstrap = client.bootstrap_status(timeout=15.0)
                proxy = client.proxy_status(timeout=15.0)
            except Exception as exc:
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "daemon component state is unavailable for regeneration",
                ) from exc
            runtime_epoch = bootstrap.get("runtimeEpoch")
            if (
                bootstrap.get("ok") is not True
                or not isinstance(runtime_epoch, str)
                or re.fullmatch(r"[0-9a-f]{64}", runtime_epoch) is None
                or proxy.get("ok") is not True
            ):
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "daemon component state is unavailable for regeneration",
                )
        if (
            not isinstance(proxy.get("enabled"), bool)
            or isinstance(proxy.get("generation"), bool)
            or not isinstance(proxy.get("generation"), int)
            or proxy["generation"] < 0
        ):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "proxy state is unavailable for regeneration",
            )
        try:
            binding = GoogleBindingStore(self.context, self.lease).load()
            if binding is None:
                spec = resolve_google_runtime_spec(
                    self.context,
                    self.cfg,
                    "status",
                    require_assets=False,
                )
                binding_identity: Mapping[str, Any] = expected_binding_identity(spec)
            else:
                binding_identity = {
                    key: binding[key]
                    for key in (
                        "provider",
                        "release",
                        "specSha256",
                        "dataCompatibilitySha256",
                    )
                }
        except GoogleServicesError as exc:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "Google binding state is unavailable for regeneration",
            ) from exc
        return {
            "containerId": container_id,
            "imageId": image_id,
            "runtimeEpoch": runtime_epoch,
            "stableDigest": stable_identity_digest(identity["stable"]),
            "networkEpoch": self.lease.network_epoch,
            "simEpoch": location_sim_epoch,
            "dataFilesystemUuid": data_before_uuid,
            "rootfsFilesystemUuid": rootfs_before_uuid,
            "locationDigest": str(location_record["profileDigest"]),
            "proxyEnabled": bool(proxy["enabled"]),
            "proxyGeneration": int(proxy["generation"]),
            "googleBindingDigest": self._regeneration_digest(binding_identity),
        }

    @staticmethod
    def _google_marker_path(package: str, root: str, transaction_id: str) -> str:
        base = "/data/user/0" if root == "ce" else "/data/user_de/0"
        return f"{base}/{package}/.xenoid-regenerate-{transaction_id}"

    def _require_google_wipe_capability(
        self,
        package: str,
        transaction_id: str,
        capability: Any,
    ) -> dict[str, Any]:
        if (
            package not in GOOGLE_CLEAR_PACKAGES
            or re.fullmatch(r"[0-9a-f]{32}", transaction_id) is None
        ):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "invalid Google wipe target",
            )
        state = RegenerationJournal(self.context).require_capability(capability)
        if state["transactionId"] != transaction_id:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "Google wipe transaction does not match regeneration",
            )
        return state

    def prepare_google_package_clear(
        self,
        package: str,
        transaction_id: str,
        capability: Any,
    ) -> dict[str, Any]:
        """Force-stop one allowlisted package and arm root-owned CE/DE markers."""
        try:
            self._require_google_wipe_capability(
                package,
                transaction_id,
                capability,
            )
        except IdentityError as exc:
            return exc.as_dict()
        stopped = self.adb(
            ["shell", "am", "force-stop", package],
            timeout=30,
        )
        if stopped.get("ok") is not True:
            return {"ok": False, "error": "google_package_force_stop_failed"}
        clauses: list[str] = ["set -eu"]
        for root in GOOGLE_MARKER_ROOTS:
            marker = self._google_marker_path(package, root, transaction_id)
            parent = marker.rsplit("/", 1)[0]
            clauses.append(
                "if [ -d "
                + shlex.quote(parent)
                + " ] && [ ! -L "
                + shlex.quote(parent)
                + " ]; then umask 077; : > "
                + shlex.quote(marker)
                + "; chown 0:0 "
                + shlex.quote(marker)
                + "; chmod 0600 "
                + shlex.quote(marker)
                + "; sync -f "
                + shlex.quote(marker)
                + "; sync -f "
                + shlex.quote(parent)
                + "; printf '%s\\n' "
                + shlex.quote(root)
                + "; fi"
            )
        try:
            result = self.daemon_client(timeout=30.0).root_exec("; ".join(clauses))
        except Exception:
            return {"ok": False, "error": "google_marker_prepare_failed"}
        roots = [
            line.strip()
            for line in str(result.get("stdout") or "").splitlines()
            if line.strip()
        ]
        if result.get("ok") is not True or roots != [
            root for root in GOOGLE_MARKER_ROOTS if root in roots
        ]:
            return {"ok": False, "error": "google_marker_prepare_failed"}
        return {"ok": True, "roots": roots}

    def google_package_markers(
        self,
        package: str,
        transaction_id: str,
        roots: list[str],
        capability: Any,
    ) -> dict[str, Any]:
        """Observe only the exact root-owned markers recorded in the journal."""
        try:
            self._require_google_wipe_capability(
                package,
                transaction_id,
                capability,
            )
        except IdentityError as exc:
            return exc.as_dict()
        if roots != [root for root in GOOGLE_MARKER_ROOTS if root in roots]:
            return {"ok": False, "error": "device_regeneration_state_invalid"}
        clauses: list[str] = ["set -eu"]
        for root in roots:
            marker = self._google_marker_path(package, root, transaction_id)
            clauses.append(
                "if [ -e "
                + shlex.quote(marker)
                + " ]; then [ -f "
                + shlex.quote(marker)
                + " ] && [ ! -L "
                + shlex.quote(marker)
                + " ] && [ \"$(stat -c '%u:%g:%a' -- "
                + shlex.quote(marker)
                + ")\" = 0:0:600 ]; printf '%s\\n' "
                + shlex.quote(root)
                + "; fi"
            )
        try:
            result = self.daemon_client(timeout=30.0).root_exec("; ".join(clauses))
        except Exception:
            return {"ok": False, "error": "google_marker_check_failed"}
        present = [
            line.strip()
            for line in str(result.get("stdout") or "").splitlines()
            if line.strip()
        ]
        if result.get("ok") is not True or present != [
            root for root in roots if root in present
        ]:
            return {"ok": False, "error": "google_marker_check_failed"}
        return {"ok": True, "present": present}

    def clear_google_package(
        self,
        package: str,
        transaction_id: str,
        capability: Any,
    ) -> dict[str, Any]:
        try:
            self._require_google_wipe_capability(
                package,
                transaction_id,
                capability,
            )
        except IdentityError as exc:
            return exc.as_dict()
        stopped = self.adb(["shell", "am", "force-stop", package], timeout=30)
        if stopped.get("ok") is not True:
            return {"ok": False, "error": "google_package_force_stop_failed"}
        cleared = self.adb(
            ["shell", "pm", "clear", "--user", "0", package],
            timeout=60,
        )
        if (
            cleared.get("ok") is not True
            or str(cleared.get("stdout") or "").strip() != "Success"
        ):
            return {"ok": False, "error": "google_package_clear_failed"}
        return {"ok": True}

    def status(self) -> dict[str, Any]:
        """Strictly observational status with one actionable recommendation."""
        self.ensure_instance_lease()
        selected = {
            **self.context.public_dict(),
            "container": self.lease.container_name,
            "volume": self.lease.volume_name,
            "adbTarget": self.adb_target,
            "daemonPort": self.lease.host_daemon_port,
        }
        if which("docker") is None:
            return {
                "ok": False,
                "error": "docker not found",
                "instance": selected,
                "recommendedAction": "resource-conflict",
                "driftReasons": ["engine_unavailable"],
            }
        observation = self.observe_convergence(skip_build=True)
        runtime = observation["runtime"]
        components = observation["components"]
        pending = observation["pending"]
        drift: list[str] = []
        recommended = "no-op"
        if isinstance(pending.get("regeneration"), Mapping):
            recommended = (
                "legacy-regeneration-recovery"
                if pending["regeneration"].get("schema")
                == "dev.xenoid.device-regenerate/v1"
                else "resume"
            )
            drift.append("device_regeneration_pending")
        elif isinstance(pending.get("convergence"), Mapping):
            recommended = "resume"
            drift.append("convergence_pending")
        elif observation.get("legacyTokenMigrationPending") is True:
            recommended = "resume"
            drift.append("legacy_token_migration_pending")
        elif runtime.get("ownershipValid") is not True and runtime.get("state") != "absent":
            recommended = "resource-conflict"
            drift.append("container_ownership_invalid")
        elif runtime.get("storageValid") is not True:
            recommended = "resource-conflict"
            drift.append("storage_invalid")
        elif observation.get("artifactTargets"):
            recommended = "image-required"
            drift.append("artifact_inputs_stale")
        elif observation.get("selectedImageRecord") is None:
            recommended = "image-required"
            drift.append("runtime_image_unavailable")
        elif runtime.get("state") == "absent":
            recommended = "create"
            drift.append("container_absent")
        elif runtime.get("createSpecMatches") is not True:
            recommended = "recreate"
            drift.append("create_spec_mismatch")
        elif runtime.get("imageBootInputSha256") != observation.get(
            "desiredImageBootInputSha256"
        ):
            recommended = "recreate"
            drift.append("boot_image_mismatch")
        elif runtime.get("state") == "stopped":
            recommended = "start"
            drift.append("container_stopped")
        elif components["daemon"].get("state") == "incompatible":
            recommended = "daemon-incompatible"
            drift.append("daemon_identity_incompatible")
        elif components["daemon"].get("state") == "drift":
            recommended = "daemon-only"
            drift.append("daemon_apk_drift")
        elif any(
            isinstance(value, Mapping) and value.get("state") == "drift"
            for value in components["deploy"].values()
        ):
            recommended = "helper-only"
            drift.append("helper_digest_drift")
        elif components["proxy"].get("state") in {"pending", "drift", "incompatible"}:
            recommended = "proxy-recovery"
            drift.append("proxy_not_converged")
        elif components["protection"].get("state") != "matching":
            recommended = "protection-maintenance"
            drift.append("shared_protection_drift")
        running = runtime.get("state") == "running"
        valid_stopped = bool(
            runtime.get("state") == "stopped"
            and runtime.get("ownershipValid") is True
            and runtime.get("storageValid") is True
            and runtime.get("createSpecMatches") is True
        )
        ok = bool(
            recommended
            not in {
                "resource-conflict",
                "daemon-incompatible",
                "legacy-regeneration-recovery",
            }
            and (
                running
                or valid_stopped
                or runtime.get("state") == "absent"
                and runtime.get("storageValid") is True
            )
        )
        return {
            "ok": ok,
            "running": running,
            "rows": [],
            "adb": runtime.get("adb"),
            "instance": selected,
            "runtimeIdentity": {
                "instanceId": self.context.instance_id,
                "containerId": runtime.get("containerId"),
                "imageId": runtime.get("imageId"),
                "dataUuid": runtime.get("dataUuid"),
                "rootfsUuid": runtime.get("rootfsUuid"),
                "runtimeEpoch": (
                    components["proxy"].get("daemon", {}).get("runtimeEpoch")
                    if isinstance(components["proxy"].get("daemon"), Mapping)
                    else None
                )
                or (
                    components["proxy"].get("engine", {}).get("runtimeEpoch")
                    if isinstance(components["proxy"].get("engine"), Mapping)
                    else None
                ),
                "protectionDigest": components["protection"].get("currentDigest"),
            },
            "storage": observation.get("storage"),
            "identity": components["identity"].get("status"),
            "googleServices": components["google"].get("status"),
            "runtimeImage": observation.get("selectedImageRecord"),
            "runtimeImageIdentity": {
                "containerImageSha256": runtime.get("imageId"),
                "containerInputSha256": runtime.get("imageInputSha256"),
                "containerBootInputSha256": runtime.get("imageBootInputSha256"),
                "desiredInputSha256": observation.get(
                    "desiredImageInputSha256"
                ),
                "desiredBootInputSha256": observation.get(
                    "desiredImageBootInputSha256"
                ),
            },
            "containerContractMatches": runtime.get("createSpecMatches"),
            "migrationPending": observation.get("legacyTokenMigrationPending") is True,
            "recommendedAction": recommended,
            "driftReasons": drift,
            "pendingJournalPhase": (
                pending["convergence"].get("phase")
                if isinstance(pending.get("convergence"), Mapping)
                else pending["regeneration"].get("phase")
                if isinstance(pending.get("regeneration"), Mapping)
                else None
            ),
            "pending": pending,
            "cache": {
                "artifactTargets": observation.get("artifactTargets"),
                "artifactRecords": observation.get("artifactRecords"),
                "selectedImageInputSha256": (
                    observation.get("selectedImageRecord") or {}
                ).get("inputSha256"),
            },
            "protection": components["protection"],
            "observationSchema": observation.get("schema"),
        }

    def adb(self, args: list[str], timeout: Optional[float] = None) -> dict[str, Any]:
        adb_bin = which("adb")
        if adb_bin is None:
            return {"ok": False, "error": "adb not found"}
        if args and args[0] == "kill-server":
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "global ADB server shutdown is not instance scoped",
            }
        global_command = bool(
            args
            and args[0] in {"--version", "version", "start-server"}
        )
        if not global_command:
            owned, error = self._owned_container()
            if not owned:
                return {"ok": False, "error": "resource_conflict", "message": error}
        if args and args[0] == "connect":
            cmd = [adb_bin, "connect", self.adb_target]
        elif global_command or (args and args[0] == "devices"):
            cmd = [adb_bin, *args]
        else:
            cmd = [adb_bin, "-s", self.adb_target, *args]
        try:
            proc = run(cmd, timeout=15 if timeout is None else timeout)
        except Exception as e:
            return {"ok": False, "error": str(e), "command": cmd}
        stdout = proc.stdout
        if args and args[0] == "devices":
            lines = [
                line
                for line in (proc.stdout or "").splitlines()
                if line.startswith("List of devices")
                or line.partition("\t")[0].strip() == self.adb_target
            ]
            stdout = "\n".join(lines) + ("\n" if lines else "")
        return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": stdout, "stderr": proc.stderr, "command": cmd}

    def adb_disconnect(self) -> dict[str, Any]:
        """Drop only this instance's transport before reconnecting a new container."""
        adb_bin = which("adb")
        if adb_bin is None:
            return {"ok": False, "error": "adb not found"}
        try:
            proc = run([adb_bin, "disconnect", self.adb_target], timeout=5)
        except Exception as error:
            return {"ok": False, "error": str(error)}
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "command": [adb_bin, "disconnect", self.adb_target],
        }

    def adb_connect(self) -> dict[str, Any]:
        adb_bin = which("adb")
        if adb_bin is None:
            return {"ok": False, "error": "adb not found"}
        try:
            state = run([adb_bin, "-s", self.adb_target, "get-state"], timeout=5)
            state_text = ((state.stdout or "") + (state.stderr or "")).lower()
            if "offline" in state_text:
                run([adb_bin, "disconnect", self.adb_target], timeout=5)
        except Exception:
            pass
        return self.adb(["connect"])

    def adb_wait(self, timeout_sec: int = 90) -> dict[str, Any]:
        if which("adb") is None:
            return {"ok": False, "error": "adb not found"}
        deadline = time.time() + timeout_sec
        last: dict[str, Any] = {}
        while time.time() < deadline:
            self.adb_connect()
            state = self.adb(["get-state"])
            last = state
            if state.get("ok") and "device" in state.get("stdout", ""):
                boot = self.adb(["shell", "getprop", "sys.boot_completed"])
                if "1" in boot.get("stdout", ""):
                    return {"ok": True, "state": state, "bootCompleted": boot}
            time.sleep(2)
        return {"ok": False, "error": "timeout waiting for Android boot", "last": last}

    def ensure_android_adb_port(self) -> dict[str, Any]:
        """Ensure adbd listens on the leased Android-internal port."""
        desired = str(self.lease.android_adb_port)
        cur = self.adb(["shell", "getprop", "service.adb.tcp.port"])
        current = str(cur.get("stdout", "")).strip()
        listener_current = self.adb(["shell", "ss -ltnp 2>/dev/null | grep -E '(^|[^0-9])" + desired + "([^0-9]|$)|:" + desired + "' || true"])
        if current == desired and desired in str(listener_current.get("stdout", "")):
            return {"ok": True, "already": True, "port": desired, "getprop": cur, "listener": listener_current}
        setp = self.adb(["shell", "setprop", "service.adb.tcp.port", desired])
        restart = self.adb(["shell", "setprop", "ctl.restart", "adbd"])
        time.sleep(3)
        reconnect = self.adb_connect()
        wait = self.adb_wait(timeout_sec=30)
        verify = self.adb(["shell", "getprop", "service.adb.tcp.port"])
        listener = self.adb(["shell", "ss -ltnp 2>/dev/null | grep -E '(^|[^0-9])" + desired + "([^0-9]|$)|:" + desired + "' || true"])
        ok = desired in str(listener.get("stdout", "")) and bool(wait.get("ok")) and str(verify.get("stdout", "")).strip() == desired
        return {"ok": ok, "from": current, "port": desired, "setprop": setp, "restart": restart, "reconnect": reconnect, "wait": wait, "verify": verify, "listener": listener}

    def enable_adb_root(self) -> dict[str, Any]:
        if which("adb") is None:
            return {"ok": False, "rooted": False, "error": "adb not found"}
        root = self.adb(["root"])
        root_output = f"{root.get('stdout', '')}\n{root.get('stderr', '')}".lower()
        production_build = "cannot run as root in production builds" in root_output
        if not production_build:
            time.sleep(3)
        reconnect = self.adb_connect()
        wait = self.adb_wait(timeout_sec=15 if production_build else 45)
        uid = self.adb(["shell", "id", "-u"]) if wait.get("ok") else {"ok": False}
        uid_value = str(uid.get("stdout", "")).strip()
        rooted = bool(root.get("ok")) and bool(wait.get("ok")) and uid_value == "0"
        skipped = production_build and bool(wait.get("ok")) and uid_value != "0"
        return {
            "ok": rooted or skipped,
            "rooted": rooted,
            "skipped": skipped,
            "reason": "production-build" if skipped else None,
            "root": root,
            "reconnect": reconnect,
            "wait": wait,
            "uid": uid,
            "uidValue": uid_value,
        }

    def forward_daemon_port(
        self,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        return self.adb([
            "forward",
            f"tcp:{self.lease.host_daemon_port}",
            f"tcp:{self.lease.android_daemon_port}",
        ], timeout=timeout)

    def _run_keybox_adb_stream(
        self,
        script: str,
        token: str,
        *,
        stream: Optional[BinaryIO] = None,
        expected_size: int = 0,
        timeout: float = 300,
    ) -> bool:
        """Run a fixed ADB receiver without placing private input in argv.

        Uses `adb shell -T` (shell v2 raw mode): binary stdin is preserved and
        the remote exit status propagates, unlike `exec-in` which always
        reports zero. The staging script self-verifies size/ownership/mode
        before disarming its cleanup trap, so a nonzero status here means the
        content never landed intact.
        """
        adb_bin = which("adb")
        if adb_bin is None:
            return False
        owned, _ = self._owned_container()
        if not owned:
            return False
        command = [
            adb_bin,
            "-s",
            self.adb_target,
            "shell",
            "-T",
            "sh -c '" + script.replace("'", "'\"'\"'") + "'",
        ]
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, ValueError):
            return False

        try:
            if process.stdin is None:
                raise OSError("ADB input pipe unavailable")
            if stream is not None:
                header = f"{token} {expected_size}\n"
            else:
                header = f"{token}\n"
            process.stdin.write(header.encode("ascii"))
            if stream is not None:
                stream.seek(0)
                remaining = expected_size
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise OSError("keybox input changed")
                    process.stdin.write(chunk)
                    remaining -= len(chunk)
                if stream.read(1):
                    raise OSError("keybox input changed")
            process.stdin.close()
            return process.wait(timeout=bounded_timeout(timeout)) == 0
        except (OSError, ValueError, subprocess.SubprocessError):
            if process.stdin is not None and not process.stdin.closed:
                try:
                    process.stdin.close()
                except OSError:
                    pass
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=bounded_timeout(5))
            except (OSError, subprocess.SubprocessError):
                pass
            return False

    def stage_keybox_source(
        self,
        stream: BinaryIO,
        size: int,
    ) -> dict[str, Any]:
        """Stream a validated keybox to a private, shell-owned Android file."""
        try:
            file_state = os.fstat(stream.fileno())
        except (AttributeError, OSError, ValueError):
            return {"ok": False, "error": "keybox_upload_failed"}
        permissions = stat.S_IMODE(file_state.st_mode)
        if (
            not stat.S_ISREG(file_state.st_mode)
            or file_state.st_uid != os.getuid()
            or permissions not in {0o400, 0o600}
            or isinstance(size, bool)
            or not 0 < size <= KEYBOX_MAX_SOURCE_BYTES
            or file_state.st_size != size
        ):
            return {"ok": False, "error": "keybox_upload_failed"}

        token = secrets.token_hex(16)
        staging_path = f"/data/local/tmp/.keybox-upload-{token}"
        staged = self._run_keybox_adb_stream(
            _KEYBOX_STAGE_SCRIPT,
            token,
            stream=stream,
            expected_size=size,
        )
        if not staged:
            self.cleanup_keybox_staging(staging_path)
            return {"ok": False, "error": "keybox_upload_failed"}
        return {"ok": True, "stagingPath": staging_path}

    def cleanup_keybox_staging(self, staging_path: str) -> dict[str, Any]:
        """Best-effort removal restricted to the generated keybox namespace."""
        match = _KEYBOX_STAGING_PATH.fullmatch(staging_path)
        if match is None:
            return {"ok": False, "error": "keybox_staging_invalid"}
        cleaned = self._run_keybox_adb_stream(
            _KEYBOX_CLEANUP_SCRIPT,
            match.group(1),
        )
        return {
            "ok": cleaned,
            **({} if cleaned else {"error": "keybox_cleanup_failed"}),
        }

    def stage_camera_source(self, local_path: str) -> dict[str, Any]:
        """Upload one immutable camera candidate for daemon-side validation."""
        try:
            source = Path(local_path).expanduser().resolve(strict=True)
            before = source.stat()
            if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
                return {"ok": False, "error": "camera source must be a nonempty regular file"}

            digest = hashlib.sha256()
            size = 0
            with source.open("rb") as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)

            after = source.stat()
            stable = (
                stat.S_ISREG(after.st_mode)
                and size == before.st_size == after.st_size
                and before.st_dev == after.st_dev
                and before.st_ino == after.st_ino
                and before.st_mtime_ns == after.st_mtime_ns
            )
            if not stable:
                return {"ok": False, "error": "camera source changed while reading"}
        except (OSError, RuntimeError):
            return {"ok": False, "error": "camera source must be a nonempty regular file"}

        staging_path = f"/data/local/tmp/.camera-upload-{secrets.token_hex(16)}"
        push = self.adb(
            ["push", str(source), staging_path],
            timeout=_camera_upload_timeout_seconds(size),
        )
        if not push.get("ok"):
            self.cleanup_camera_staging(staging_path)
            return {"ok": False, "error": "camera source upload failed"}
        chmod = self.adb(["shell", "chmod", "0600", staging_path], timeout=300)
        if not chmod.get("ok"):
            self.cleanup_camera_staging(staging_path)
            return {"ok": False, "error": "camera source upload failed"}
        owner = self.adb([
            "shell",
            f'if [ "$(id -u)" = 0 ]; then chown 2000:2000 {staging_path}; fi',
        ], timeout=300)
        if not owner.get("ok"):
            self.cleanup_camera_staging(staging_path)
            return {"ok": False, "error": "camera source upload failed"}
        return {
            "ok": True,
            "stagingPath": staging_path,
            "size": size,
            "sha256": digest.hexdigest(),
        }

    def cleanup_camera_staging(self, staging_path: str) -> dict[str, Any]:
        """Best-effort removal restricted to names generated above."""
        if re.fullmatch(r"/data/local/tmp/\.camera-upload-[0-9a-f]{32}", staging_path) is None:
            return {"ok": False, "error": "invalid camera staging reference"}
        result = self.adb(["shell", "rm", "-f", staging_path], timeout=300)
        return {"ok": bool(result.get("ok"))}

    def grant_daemon_camera_permission(self) -> dict[str, Any]:
        result = self.adb([
            "shell", "pm", "grant", "--user", "0",
            "dev.xenoid.daemon", "android.permission.CAMERA",
        ])
        return {
            "ok": bool(result.get("ok")),
            **({} if result.get("ok") else {"error": "camera permission grant failed"}),
        }

    def launch_daemon_activity_once(
        self,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        """Request the non-exported service through its exported Activity once."""
        launched = self.adb([
            "shell", "am", "start", "--user", "0", "-n",
            "dev.xenoid.daemon/.MainActivity", "--ez", "bootstrap", "true",
        ], timeout=timeout)
        return {
            "ok": bool(launched.get("ok")),
            **({} if launched.get("ok") else {"error": "daemon_activity_launch_failed"}),
        }

    def launch_camera_self_test(self, run_id: str) -> dict[str, Any]:
        if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", run_id) is None:
            return {"ok": False, "error": "invalid camera self-test run id"}
        result = self.adb([
            "shell", "am", "start", "--user", "0", "-n",
            "dev.xenoid.daemon/.MainActivity",
            "--es", "cameraSelfTestRunId", run_id,
        ])
        return {
            "ok": bool(result.get("ok")),
            **({} if result.get("ok") else {"error": "camera self-test launch failed"}),
        }

    def _rootd_output(
        self,
        args: list[str],
        *,
        timeout: float = 5,
        limit: int = 4096,
        deadline: Optional[float] = None,
    ) -> Optional[str]:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            timeout = min(timeout, remaining)
        result = self.docker_exec(args, timeout=timeout)
        if result.get("ok") is not True:
            return None
        output = str(result.get("stdout", ""))
        if len(output.encode("utf-8", "replace")) > limit:
            return None
        return output.strip()

    def _rootd_stat(
        self,
        path: str,
        *,
        follow: bool = False,
        deadline: Optional[float] = None,
    ) -> Optional[tuple[int, int, int, int, int, int]]:
        args = ["stat"]
        if follow:
            args.append("-L")
        args.extend(["-c", "%d:%i:%u:%f:%h:%s", path])
        output = self._rootd_output(args, limit=256, deadline=deadline)
        if output is None:
            return None
        fields = output.split(":")
        if len(fields) != 6:
            return None
        try:
            return (
                int(fields[0]),
                int(fields[1]),
                int(fields[2]),
                int(fields[3], 16),
                int(fields[4]),
                int(fields[5]),
            )
        except ValueError:
            return None

    @staticmethod
    def _proc_start_time(value: str) -> Optional[int]:
        close = value.rfind(")")
        if close < 0:
            return None
        fields = value[close + 1:].strip().split()
        if len(fields) <= 19:
            return None
        try:
            start_time = int(fields[19])
        except ValueError:
            return None
        return start_time if start_time > 0 else None

    def _rootd_remote_digest(
        self,
        path: str,
        *,
        deadline: Optional[float] = None,
    ) -> Optional[str]:
        output = self._rootd_output(
            ["sha256sum", path],
            limit=256,
            deadline=deadline,
        )
        if output is None:
            return None
        digest = output.partition(" ")[0]
        return digest if re.fullmatch(r"[0-9a-f]{64}", digest) else None

    def _rootd_port_inodes(
        self,
        *,
        deadline: Optional[float] = None,
    ) -> tuple[set[str], bool]:
        expected_port = format(self.lease.rootd_port, "04X")
        loopback = {
            "0100007F",
            "00000000000000000000000001000000",
        }
        inodes: set[str] = set()
        conflict = False
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            output = self._rootd_output(
                ["cat", path],
                limit=64 * 1024,
                deadline=deadline,
            )
            if output is None:
                continue
            for line in output.splitlines()[1:]:
                fields = line.split()
                if len(fields) < 10 or fields[3] != "0A":
                    continue
                address, separator, port = fields[1].rpartition(":")
                if not separator or port.upper() != expected_port:
                    continue
                if address.upper() not in loopback:
                    conflict = True
                    continue
                inode = fields[9]
                if inode.isdigit():
                    inodes.add(inode)
        if len(inodes) > 1:
            conflict = True
        return inodes, conflict

    def _rootd_process_identity(
        self,
        pid: int,
        *,
        allowed_paths: frozenset[str],
        deadline: Optional[float] = None,
    ) -> Optional[dict[str, Any]]:
        if pid <= 1:
            return None
        process_stat = self._rootd_output(
            ["cat", f"/proc/{pid}/stat"],
            limit=4096,
            deadline=deadline,
        )
        status = self._rootd_output(
            ["cat", f"/proc/{pid}/status"],
            limit=64 * 1024,
            deadline=deadline,
        )
        executable = self._rootd_output(
            ["readlink", f"/proc/{pid}/exe"],
            limit=512,
            deadline=deadline,
        )
        if process_stat is None or status is None or executable not in allowed_paths:
            return None
        start_time = self._proc_start_time(process_stat)
        uid_line = next(
            (line for line in status.splitlines() if line.startswith("Uid:")),
            "",
        )
        uid_fields = uid_line.partition(":")[2].split()
        if start_time is None or len(uid_fields) != 4 or any(
            field != "0" for field in uid_fields
        ):
            return None
        executable_stat = self._rootd_stat(
            f"/proc/{pid}/exe",
            follow=True,
            deadline=deadline,
        )
        deployed_stat = self._rootd_stat(
            executable,
            follow=True,
            deadline=deadline,
        )
        if (
            executable_stat is None
            or deployed_stat is None
            or executable_stat[:2] != deployed_stat[:2]
            or executable_stat[2] != 0
            or not stat.S_ISREG(executable_stat[3])
            or stat.S_IMODE(executable_stat[3]) != 0o755
        ):
            return None
        digest = self._rootd_remote_digest(
            f"/proc/{pid}/exe",
            deadline=deadline,
        )
        deployed_digest = self._rootd_remote_digest(
            executable,
            deadline=deadline,
        )
        if digest is None or digest != deployed_digest:
            return None
        inodes, conflict = self._rootd_port_inodes(deadline=deadline)
        descriptors = self._rootd_output(
            ["ls", "-l", f"/proc/{pid}/fd"],
            limit=64 * 1024,
            deadline=deadline,
        )
        if conflict or len(inodes) != 1 or descriptors is None:
            return None
        inode = next(iter(inodes))
        if f"socket:[{inode}]" not in descriptors:
            return None
        return {
            "pid": pid,
            "startTime": start_time,
            "digest": digest,
            "executable": executable,
        }

    def _rootd_owned_process(
        self,
        *,
        deadline: Optional[float] = None,
    ) -> tuple[Optional[dict[str, Any]], str]:
        exists = self._rootd_output(
            ["test", "-e", _ROOTD_PROCESS_RECORD],
            deadline=deadline,
        )
        if exists is None:
            return None, "absent"
        directory = self._rootd_stat(
            _ROOTD_RUN_DIRECTORY,
            deadline=deadline,
        )
        record = self._rootd_stat(
            _ROOTD_PROCESS_RECORD,
            deadline=deadline,
        )
        if (
            directory is None
            or record is None
            or directory[2] != 0
            or not stat.S_ISDIR(directory[3])
            or stat.S_IMODE(directory[3]) != 0o700
            or record[2] != 0
            or not stat.S_ISREG(record[3])
            or stat.S_IMODE(record[3]) != 0o600
            or record[4] != 1
            or not 1 <= record[5] <= 256
        ):
            return None, "invalid"
        raw = self._rootd_output(
            ["cat", _ROOTD_PROCESS_RECORD],
            limit=256,
            deadline=deadline,
        )
        try:
            document = json.loads(raw) if raw is not None else None
        except json.JSONDecodeError:
            document = None
        if (
            not isinstance(document, dict)
            or set(document) != {"schema", "pid", "startTime"}
            or document.get("schema") != _ROOTD_PROCESS_SCHEMA
            or not isinstance(document.get("pid"), int)
            or isinstance(document.get("pid"), bool)
            or not isinstance(document.get("startTime"), int)
            or isinstance(document.get("startTime"), bool)
            or document["pid"] <= 1
            or document["startTime"] <= 0
        ):
            return None, "invalid"
        current_stat = self._rootd_output(
            ["cat", f"/proc/{document['pid']}/stat"],
            limit=4096,
            deadline=deadline,
        )
        if current_stat is None:
            return None, "stale"
        identity = self._rootd_process_identity(
            document["pid"],
            allowed_paths=frozenset({_ROOTD_REMOTE_PATH}),
            deadline=deadline,
        )
        if (
            identity is None
            or identity["startTime"] != document["startTime"]
        ):
            return None, "invalid"
        return identity, "valid"

    def _rootd_authentication(
        self,
        client: DaemonClient,
        *,
        deadline: Optional[float] = None,
    ) -> str:
        timeout = (
            None
            if deadline is None
            else max(0.0, min(5.0, deadline - time.monotonic()))
        )
        if timeout == 0.0:
            return "rootd_unavailable"
        status = client.root_status(timeout=timeout)
        if (
            isinstance(status, dict)
            and status.get("ok") is True
            and (
                status.get("root") is True
                or status.get("uid") == 0
                or "uid=0" in str(status.get("stdout", ""))
            )
        ):
            return "ok"
        if isinstance(status, dict) and (
            status.get("httpStatus") == 401
            or status.get("error") in {"unauthorized", "rootd_unauthorized"}
            or status.get("errorCode") == "rootd_unauthorized"
        ):
            return "rootd_unauthorized"
        return "rootd_unavailable"

    def _terminate_rootd_process(
        self,
        identity: Mapping[str, Any],
        *,
        deadline: float,
    ) -> bool:
        pid = identity.get("pid")
        start_time = identity.get("startTime")
        if not isinstance(pid, int) or not isinstance(start_time, int):
            return False
        current = self._rootd_output(
            ["cat", f"/proc/{pid}/stat"],
            limit=4096,
            deadline=deadline,
        )
        if current is None or self._proc_start_time(current) != start_time:
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        self.docker_exec(["kill", "-TERM", str(pid)], timeout=remaining)
        term_deadline = min(deadline, time.monotonic() + 2.0)
        while time.monotonic() < term_deadline:
            current = self._rootd_output(
                ["cat", f"/proc/{pid}/stat"],
                limit=4096,
                deadline=term_deadline,
            )
            if current is None:
                return time.monotonic() < term_deadline
            if self._proc_start_time(current) != start_time:
                return False
            time.sleep(min(0.1, max(0.0, term_deadline - time.monotonic())))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        self.docker_exec(["kill", "-KILL", str(pid)], timeout=remaining)
        kill_deadline = min(deadline, time.monotonic() + 2.0)
        while time.monotonic() < kill_deadline:
            current = self._rootd_output(
                ["cat", f"/proc/{pid}/stat"],
                limit=4096,
                deadline=kill_deadline,
            )
            if current is None:
                return time.monotonic() < kill_deadline
            if self._proc_start_time(current) != start_time:
                return False
            time.sleep(min(0.1, max(0.0, kill_deadline - time.monotonic())))
        return False

    def _rootd_engine_env(self) -> dict[str, str]:
        environment = self.docker_env()
        for name in tuple(environment):
            normalized = name.upper()
            if (
                "TOKEN" in normalized
                or "AUTHORIZATION" in normalized
                or "COOKIE" in normalized
            ):
                environment.pop(name, None)
        return environment

    def _legacy_rootd_probe(self, token: str, *, deadline: float) -> bool:
        remaining = deadline - time.monotonic()
        container, _ = self._owned_container_record(
            timeout=max(0.0, remaining),
        )
        container_id = container.get("Id") if isinstance(container, dict) else None
        if (
            remaining <= 0
            or not isinstance(container_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        ):
            return False
        request = bytearray(
            (
                "GET /exec?cmd=id%20-u HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                f"X-Xenoid-Token: {token}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
        )
        process: Optional[subprocess.Popen[bytes]] = None
        probe_timeout = min(5.0, max(0.0, deadline - time.monotonic()))
        if probe_timeout <= 0:
            for index in range(len(request)):
                request[index] = 0
            return False
        try:
            process = subprocess.Popen(
                [
                    *self.docker_base_cmd(),
                    "exec",
                    "-i",
                    container_id,
                    "/system/bin/toybox",
                    "nc",
                    "127.0.0.1",
                    str(self.lease.rootd_port),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self._rootd_engine_env(),
                close_fds=True,
            )
            response, _ = process.communicate(
                input=request,
                timeout=bounded_timeout(probe_timeout),
            )
        except (OSError, subprocess.SubprocessError):
            if process is not None:
                try:
                    process.kill()
                    process.wait(timeout=1)
                except (OSError, subprocess.SubprocessError):
                    pass
            return False
        finally:
            for index in range(len(request)):
                request[index] = 0
        if process.returncode != 0 or len(response) > 64 * 1024:
            return False
        header, separator, body = response.partition(b"\r\n\r\n")
        if not separator or not header.startswith(b"HTTP/1.1 200 "):
            return False
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            return False
        stdout = parsed.get("stdout") if isinstance(parsed, dict) else None
        return (
            isinstance(parsed, dict)
            and parsed.get("ok") is True
            and isinstance(stdout, str)
            and stdout.strip() == "0"
        )

    def _adopt_legacy_rootd(
        self,
        token: str,
        *,
        deadline: float,
    ) -> tuple[bool, bool]:
        pids = self._rootd_output(
            ["pidof", ".netd-helper"],
            limit=256,
            deadline=deadline,
        )
        if pids is None:
            return False, False
        values = pids.split()
        if len(values) != 1 or not values[0].isdigit():
            return False, True
        identity = self._rootd_process_identity(
            int(values[0]),
            allowed_paths=frozenset({_ROOTD_REMOTE_PATH, _ROOTD_LEGACY_PATH}),
            deadline=deadline,
        )
        predeploy_digest = self._rootd_remote_digest(
            _ROOTD_REMOTE_PATH,
            deadline=deadline,
        )
        if (
            identity is None
            or predeploy_digest is None
            or identity["digest"] != predeploy_digest
            or not self._legacy_rootd_probe(token, deadline=deadline)
        ):
            return False, True
        return self._terminate_rootd_process(
            identity,
            deadline=deadline,
        ), True

    def _launch_rootd_with_token(
        self,
        container_id: str,
        token: str,
        timeout: float,
    ) -> bool:
        secret = bytearray(token.encode("ascii"))
        secret.append(0x0A)
        environment = self._rootd_engine_env()
        process: Optional[subprocess.Popen[bytes]] = None
        try:
            process = subprocess.Popen(
                [
                    *self.docker_base_cmd(),
                    "exec",
                    "-i",
                    container_id,
                    _ROOTD_REMOTE_PATH,
                    str(self.lease.rootd_port),
                    _ROOTD_RUN_DIRECTORY,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                close_fds=True,
            )
            if process.stdin is None:
                return False
            process.stdin.write(secret)
            process.stdin.flush()
            process.stdin.close()
            return process.wait(timeout=bounded_timeout(timeout)) == 0
        except (OSError, subprocess.SubprocessError):
            if process is not None:
                try:
                    process.kill()
                    process.wait(timeout=1)
                except (OSError, subprocess.SubprocessError):
                    pass
            return False
        finally:
            for index in range(len(secret)):
                secret[index] = 0

    def _remove_legacy_android_rootd_token(
        self,
        expected_container_id: str,
        *,
        deadline: float,
    ) -> bool:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        parent = self.docker_exec(
            [
                "sh",
                "-c",
                "test -d /data/local/tmp && "
                "test ! -L /data/local/tmp && "
                "stat -c '%u:%g:%a' /data/local/tmp",
            ],
            timeout=min(5.0, remaining),
        )
        parent_identity = str(
            parent.get("stdout") or ""
        ).strip()
        if (
            parent.get("ok") is not True
            or parent_identity not in {"0:0:700", "2000:2000:771"}
        ):
            return False
        remaining = deadline - time.monotonic()
        removed = self.docker_exec(
            ["rm", "-f", "--", "/data/local/tmp/.xenoid-rootd.token"],
            timeout=min(5.0, max(0.001, remaining)),
        )
        if removed.get("ok") is not True:
            return False
        remaining = deadline - time.monotonic()
        synced = self.docker_exec(
            ["sync"],
            timeout=min(5.0, max(0.001, remaining)),
        )
        if synced.get("ok") is not True:
            return False
        remaining = deadline - time.monotonic()
        container, _ = self._owned_container_record(
            timeout=max(0.001, min(5.0, remaining)),
        )
        return (
            isinstance(container, Mapping)
            and container.get("Id") == expected_container_id
        )

    def ensure_rootd_root(
        self,
        timeout: float = _ROOTD_PROVISION_TIMEOUT_SECONDS,
        client: Optional[DaemonClient] = None,
    ) -> dict[str, Any]:
        """Provision only an owned native rootd using the daemon's private token."""
        if which("docker") is None:
            return {"ok": False, "code": "rootd_unavailable", "error": "rootd_unavailable"}
        deadline = time.monotonic() + max(
            0.0,
            min(timeout, _ROOTD_PROVISION_TIMEOUT_SECONDS),
        )
        daemon_client = client or self.daemon_client(timeout=2.0)

        def remaining(cap: float = _ROOTD_PROVISION_TIMEOUT_SECONDS) -> float:
            return min(cap, max(0.0, deadline - time.monotonic()))

        def failure(code: str) -> dict[str, Any]:
            return {"ok": False, "code": code, "error": code}

        try:
            self.migrate_legacy_token_state()
        except InstanceError:
            return failure("legacy_token_state_invalid")
        container, _ = self._owned_container_record(timeout=remaining(5.0))
        container_id = (
            container.get("Id") if isinstance(container, Mapping) else None
        )
        if (
            not isinstance(container_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        ):
            return failure("rootd_resource_conflict")
        if not self._remove_legacy_android_rootd_token(
            container_id,
            deadline=deadline,
        ):
            return failure(
                "rootd_unavailable"
                if remaining() <= 0
                else "legacy_token_state_invalid"
            )

        token: Optional[str] = None
        while remaining() > 0:
            token = daemon_client.read_private_token(
                force=True,
                timeout=remaining(5.0),
            )
            if token is not None:
                break
            sleep_for = remaining(0.2)
            if sleep_for > 0:
                time.sleep(sleep_for)
        if token is None:
            return failure(
                "rootd_unavailable"
                if remaining() <= 0
                else "daemon_token_unavailable"
            )

        abi = self._rootd_output(
            ["getprop", "ro.product.cpu.abi"],
            limit=128,
            deadline=deadline,
        )
        if remaining() <= 0:
            return failure("rootd_unavailable")
        arch = "arm64" if abi and ("arm64" in abi or "aarch64" in abi) else "x86_64"
        try:
            candidate = self._artifact_output(
                "liveDeploy",
                f"native/xenoid-rootd/xenoid-rootd-{arch}",
            )
            candidate_state = candidate.stat()
            if not stat.S_ISREG(candidate_state.st_mode):
                raise OSError
            candidate_digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        except (InstanceError, OSError):
            return failure("rootd_deploy_failed")

        owned, record_state = self._rootd_owned_process(deadline=deadline)
        if remaining() <= 0:
            return failure("rootd_unavailable")
        legacy_adopted = False
        if owned is not None:
            authentication = self._rootd_authentication(
                daemon_client,
                deadline=deadline,
            )
            if authentication == "ok" and owned["digest"] == candidate_digest:
                return {
                    "ok": True,
                    "runsAsRoot": True,
                    "authenticated": True,
                    "reused": True,
                    "port": self.lease.rootd_port,
                }
            if authentication == "rootd_unauthorized":
                return failure("rootd_unauthorized")
            if not self._terminate_rootd_process(owned, deadline=deadline):
                return failure(
                    "rootd_unavailable"
                    if remaining() <= 0
                    else "rootd_resource_conflict"
                )
        elif record_state == "invalid":
            return failure("rootd_resource_conflict")
        elif record_state == "stale":
            remove_timeout = remaining()
            if remove_timeout <= 0:
                return failure("rootd_unavailable")
            removed = self.docker_exec(
                ["rm", "-f", _ROOTD_PROCESS_RECORD],
                timeout=remove_timeout,
            )
            if removed.get("ok") is not True:
                return failure(
                    "rootd_unavailable"
                    if remaining() <= 0
                    else "rootd_resource_conflict"
                )

        inodes, listener_conflict = self._rootd_port_inodes(deadline=deadline)
        if remaining() <= 0:
            return failure("rootd_unavailable")
        if inodes or listener_conflict:
            if record_state != "absent" or listener_conflict:
                return failure("rootd_resource_conflict")
            adopted, legacy_seen = self._adopt_legacy_rootd(
                token,
                deadline=deadline,
            )
            if not adopted:
                return failure(
                    "rootd_unavailable"
                    if remaining() <= 0
                    else "rootd_resource_conflict"
                )
            legacy_adopted = legacy_seen

        push_timeout = remaining(15.0)
        if push_timeout <= 0:
            return failure("rootd_unavailable")
        push = self.adb(
            ["push", str(candidate), _ROOTD_REMOTE_PATH],
            timeout=push_timeout,
        )
        if push.get("ok") is not True:
            return failure(
                "rootd_unavailable"
                if remaining() <= 0
                else "rootd_deploy_failed"
            )
        for command in (
            ["chown", "0:0", _ROOTD_REMOTE_PATH],
            ["chmod", "0755", _ROOTD_REMOTE_PATH],
        ):
            command_timeout = remaining()
            if command_timeout <= 0:
                return failure("rootd_unavailable")
            prepared = self.docker_exec(command, timeout=command_timeout)
            if prepared.get("ok") is not True:
                return failure(
                    "rootd_unavailable"
                    if remaining() <= 0
                    else "rootd_deploy_failed"
                )
        if self._rootd_remote_digest(
            _ROOTD_REMOTE_PATH,
            deadline=deadline,
        ) != candidate_digest:
            return failure(
                "rootd_unavailable"
                if remaining() <= 0
                else "rootd_deploy_failed"
            )
        cleanup_timeout = remaining()
        if cleanup_timeout <= 0:
            return failure("rootd_unavailable")
        self.docker_exec(
            ["rm", "-f", _ROOTD_LEGACY_PATH],
            timeout=cleanup_timeout,
        )

        ownership_timeout = remaining()
        if ownership_timeout <= 0:
            return failure("rootd_unavailable")
        container, _ = self._owned_container_record(timeout=ownership_timeout)
        container_id = container.get("Id") if isinstance(container, dict) else None
        if (
            not isinstance(container_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        ):
            return failure("rootd_resource_conflict")
        launch_timeout = remaining(10.0)
        if launch_timeout <= 0 or not self._launch_rootd_with_token(
            container_id,
            token,
            launch_timeout,
        ):
            return failure("rootd_unavailable")

        last_authentication = "rootd_unavailable"
        while remaining() > 0:
            process, state = self._rootd_owned_process(deadline=deadline)
            if (
                process is not None
                and state == "valid"
                and process["digest"] == candidate_digest
            ):
                last_authentication = self._rootd_authentication(
                    daemon_client,
                    deadline=deadline,
                )
                if last_authentication == "ok":
                    return {
                        "ok": True,
                        "runsAsRoot": True,
                        "authenticated": True,
                        "reused": False,
                        "legacyAdopted": legacy_adopted,
                        "port": self.lease.rootd_port,
                    }
                if last_authentication == "rootd_unauthorized":
                    break
            sleep_for = remaining(0.2)
            if sleep_for > 0:
                time.sleep(sleep_for)
        return failure(last_authentication)

    def daemon_client(self, timeout: float = 10.0) -> DaemonClient:
        return DaemonClient(
            context=self.context,
            lease=self.lease,
            docker_argv=self.docker_base_cmd(),
            timeout=timeout,
        )

    def wait_daemon_transport(
        self,
        timeout: float = _DAEMON_TRANSPORT_TIMEOUT_SECONDS,
        *,
        allow_activity_launch: bool = True,
    ) -> dict[str, Any]:
        """Bind and prove the listener without consulting aggregate health."""
        started = time.monotonic()
        deadline = started + max(0.0, min(timeout, _DAEMON_TRANSPORT_TIMEOUT_SECONDS))
        midpoint = started + (deadline - started) / 2.0
        client = self.daemon_client(timeout=2.0)
        attempts = 0
        launches = 0
        recovered = False

        def remaining(cap: float) -> float:
            return min(cap, max(0.0, deadline - time.monotonic()))

        initial_remaining = remaining(_DAEMON_TRANSPORT_TIMEOUT_SECONDS)
        if initial_remaining <= 0:
            return {
                "ok": False,
                "code": "daemon_transport_timeout",
                "error": "daemon_transport_timeout",
                "transportReady": False,
            }
        self.forward_daemon_port(timeout=initial_remaining)
        while True:
            transport_remaining = remaining(2.0)
            if transport_remaining <= 0:
                return {
                    "ok": False,
                    "code": "daemon_transport_timeout",
                    "error": "daemon_transport_timeout",
                    "transportReady": False,
                    "attempts": attempts,
                    "activityLaunches": launches,
                }
            attempts += 1
            transport = client.transport(timeout=transport_remaining)
            if transport.get("ok") is True:
                return {
                    "ok": True,
                    "transportReady": True,
                    "attempts": attempts,
                    "activityLaunches": launches,
                    "midpointRecovery": recovered,
                }
            now = time.monotonic()
            if launches == 0 and allow_activity_launch:
                launch_remaining = remaining(_DAEMON_TRANSPORT_TIMEOUT_SECONDS)
                if launch_remaining <= 0:
                    continue
                launch = self.launch_daemon_activity_once(timeout=launch_remaining)
                launches = 1
                if launch.get("ok") is not True:
                    return {
                        "ok": False,
                        "code": "daemon_activity_launch_failed",
                        "error": "daemon_activity_launch_failed",
                        "transportReady": False,
                    }
                forward_remaining = remaining(_DAEMON_TRANSPORT_TIMEOUT_SECONDS)
                if forward_remaining > 0:
                    self.forward_daemon_port(timeout=forward_remaining)
            elif not recovered and allow_activity_launch and now >= midpoint:
                force_stop_remaining = remaining(10.0)
                if force_stop_remaining <= 0:
                    continue
                self.adb(
                    ["shell", "am", "force-stop", "dev.xenoid.daemon"],
                    timeout=force_stop_remaining,
                )
                launch_remaining = remaining(_DAEMON_TRANSPORT_TIMEOUT_SECONDS)
                if launch_remaining <= 0:
                    continue
                launch = self.launch_daemon_activity_once(timeout=launch_remaining)
                launches += 1
                recovered = True
                if launch.get("ok") is not True:
                    return {
                        "ok": False,
                        "code": "daemon_activity_launch_failed",
                        "error": "daemon_activity_launch_failed",
                        "transportReady": False,
                    }
                forward_remaining = remaining(_DAEMON_TRANSPORT_TIMEOUT_SECONDS)
                if forward_remaining > 0:
                    self.forward_daemon_port(timeout=forward_remaining)
            sleep_remaining = remaining(0.25)
            if sleep_remaining > 0:
                time.sleep(sleep_remaining)

    def _daemon_runtime_epoch(
        self,
        *,
        deadline: Optional[float] = None,
    ) -> Optional[str]:
        def remaining(cap: float = 5.0) -> float:
            if deadline is None:
                return cap
            return min(cap, max(0.0, deadline - time.monotonic()))

        ownership_timeout = remaining()
        if ownership_timeout <= 0:
            return None
        container, _ = self._owned_container_record(timeout=ownership_timeout)
        container_id = container.get("Id") if isinstance(container, dict) else None
        if (
            not isinstance(container_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        ):
            return None

        def output(args: list[str], limit: int) -> Optional[str]:
            if remaining() <= 0:
                return None
            return self._rootd_output(args, limit=limit, deadline=deadline)

        pids = output(["pidof", "dev.xenoid.daemon"], 256)
        if pids is None:
            return None
        values = pids.split()
        if len(values) != 1 or not values[0].isdigit():
            return None
        pid = int(values[0])
        before = output(["cat", f"/proc/{pid}/stat"], 4096)
        status = output(["cat", f"/proc/{pid}/status"], 64 * 1024)
        app_uid = output(
            ["stat", "-c", "%u", "/data/data/dev.xenoid.daemon"],
            64,
        )
        boot_id = output(["cat", "/proc/sys/kernel/random/boot_id"], 128)
        after = output(["cat", f"/proc/{pid}/stat"], 4096)
        start_time = self._proc_start_time(before or "")
        uid_line = next(
            (line for line in (status or "").splitlines() if line.startswith("Uid:")),
            "",
        )
        uid_fields = uid_line.partition(":")[2].split()
        if (
            before is None
            or self._proc_start_time(after or "") != start_time
            or start_time is None
            or app_uid is None
            or len(uid_fields) != 4
            or any(field != app_uid for field in uid_fields)
            or boot_id is None
            or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                boot_id,
            ) is None
        ):
            return None
        material = (
            "dev.xenoid.daemon-runtime/v1\n"
            f"{container_id}\n{pid}\n{start_time}\n{boot_id}\n"
        ).encode("ascii")
        return hashlib.sha256(material).hexdigest()

    @staticmethod
    def _bootstrap_terminal_result(status: Mapping[str, Any]) -> dict[str, Any]:
        components = status.get("components")
        root = components.get("root") if isinstance(components, dict) else None
        control_ready = isinstance(root, dict) and root.get("ok") is True
        result: dict[str, Any] = {
            "ok": control_ready,
            "transportReady": True,
            "controlReady": control_ready,
            "ready": status.get("state") == "ready",
            "state": status.get("state"),
            "generation": status.get("generation"),
            "instanceId": status.get("instanceId"),
            "runtimeEpoch": status.get("runtimeEpoch"),
            "components": components if isinstance(components, dict) else {},
        }
        error_code = status.get("errorCode")
        if isinstance(error_code, str):
            result["errorCode"] = error_code
        if not control_ready:
            root_error = root.get("errorCode") if isinstance(root, dict) else None
            code = root_error if isinstance(root_error, str) else "rootd_unavailable"
            result["code"] = code
            result["error"] = code
        return result

    def reconcile_bootstrap(
        self,
        timeout: float = _BOOTSTRAP_SEQUENCE_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        """Run the sole listener -> rootd -> component-bootstrap sequence."""
        requested_timeout = max(0.0, min(timeout, _BOOTSTRAP_SEQUENCE_TIMEOUT_SECONDS))
        parent_timeout = bounded_timeout(requested_timeout)
        effective_timeout = requested_timeout if parent_timeout is None else parent_timeout
        if effective_timeout <= 0:
            return {
                "ok": False,
                "transportReady": False,
                "controlReady": False,
                "code": "bootstrap_timeout",
                "error": "bootstrap_timeout",
            }
        outer_deadline = time.monotonic() + effective_timeout
        transport = self.wait_daemon_transport(
            min(_DAEMON_TRANSPORT_TIMEOUT_SECONDS, outer_deadline - time.monotonic())
        )
        if transport.get("ok") is not True:
            return transport
        permissions = self.ensure_daemon_runtime_permissions()
        if permissions.get("ok") is not True:
            return {
                "ok": False,
                "transportReady": True,
                "controlReady": False,
                "code": "daemon_permission_grant_failed",
                "error": "daemon_permission_grant_failed",
            }
        client = self.daemon_client(timeout=5.0)
        root_deadline = min(
            outer_deadline,
            time.monotonic() + _ROOTD_PROVISION_TIMEOUT_SECONDS,
        )
        rootd = self.ensure_rootd_root(
            max(0.0, root_deadline - time.monotonic()),
            client,
        )
        reprovisioned = False
        root_remaining = root_deadline - time.monotonic()
        if (
            rootd.get("ok") is not True
            and rootd.get("code") == "rootd_unavailable"
            and root_remaining > 0.0
        ):
            reprovisioned = True
            rootd = self.ensure_rootd_root(root_remaining, client)
        if rootd.get("ok") is not True:
            return {
                "ok": False,
                "transportReady": True,
                "controlReady": False,
                "code": rootd.get("code", "rootd_unavailable"),
                "error": rootd.get("code", "rootd_unavailable"),
                "rootdReprovisioned": reprovisioned,
            }
        runtime_epoch = self._daemon_runtime_epoch(deadline=outer_deadline)
        remaining = outer_deadline - time.monotonic()
        if runtime_epoch is None or remaining < 1.0:
            return {
                "ok": False,
                "transportReady": True,
                "controlReady": True,
                "code": "daemon_runtime_identity_unavailable",
                "error": "daemon_runtime_identity_unavailable",
            }
        timeout_ms = min(
            BOOTSTRAP_WORKER_TIMEOUT_MS,
            max(1000, int(remaining * 1000)),
        )
        accepted = client.bootstrap_reconcile(
            self.context.instance_id,
            runtime_epoch,
            timeout_ms,
        )
        generation = accepted.get("generation")
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation <= 0
            or accepted.get("runtimeEpoch") != runtime_epoch
        ):
            code = accepted.get("code")
            safe_code = code if isinstance(code, str) else "bootstrap_reconcile_failed"
            return {
                "ok": False,
                "transportReady": True,
                "controlReady": True,
                "code": safe_code,
                "error": safe_code,
            }
        if accepted.get("state") in {"ready", "degraded", "failed"}:
            result = self._bootstrap_terminal_result(accepted)
            result["rootdReprovisioned"] = reprovisioned
            return result

        poll_deadline = min(
            outer_deadline,
            time.monotonic() + BOOTSTRAP_POLL_TIMEOUT_SECONDS,
        )
        try:
            while time.monotonic() < poll_deadline:
                remaining = poll_deadline - time.monotonic()
                status = client.bootstrap_status(timeout=min(5.0, remaining))
                if (
                    status.get("generation") == generation
                    and status.get("runtimeEpoch") == runtime_epoch
                    and status.get("state") in {"ready", "degraded", "failed"}
                ):
                    result = self._bootstrap_terminal_result(status)
                    result["rootdReprovisioned"] = reprovisioned
                    return result
                if status.get("generation") not in (None, generation):
                    return {
                        "ok": False,
                        "transportReady": True,
                        "controlReady": True,
                        "code": "bootstrap_generation_conflict",
                        "error": "bootstrap_generation_conflict",
                    }
                time.sleep(min(0.25, max(0.0, remaining)))
        except (KeyboardInterrupt, SystemExit):
            client.bootstrap_cancel(generation, timeout=2.0)
            raise
        client.bootstrap_cancel(generation, timeout=2.0)
        return {
            "ok": False,
            "transportReady": True,
            "controlReady": True,
            "code": "bootstrap_timeout",
            "error": "bootstrap_timeout",
            "generation": generation,
        }

    @staticmethod
    def _local_deploy_identity(
        path: Path,
        *,
        require_arm64_elf: bool,
    ) -> dict[str, Any]:
        try:
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_nlink != 1
            ):
                raise OSError("deploy artifact is not a private regular file")
            digest = hashlib.sha256()
            header = b""
            with path.open("rb") as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    if len(header) < 20:
                        header += chunk[: 20 - len(header)]
                    digest.update(chunk)
        except OSError:
            return {"ok": False, "error": "install_artifact_invalid"}
        machine: Optional[str] = None
        if len(header) >= 20 and header[:4] == b"\x7fELF":
            byte_order = "little" if header[5:6] == b"\x01" else "big"
            machine_number = int.from_bytes(header[18:20], byte_order)
            machine = "arm64" if machine_number == 183 else str(machine_number)
        if require_arm64_elf and (
            header[4:5] != b"\x02"
            or machine != "arm64"
        ):
            return {"ok": False, "error": "install_artifact_architecture_invalid"}
        return {
            "ok": True,
            "sha256": digest.hexdigest(),
            "size": info.st_size,
            "mode": stat.S_IMODE(info.st_mode),
            "architecture": machine,
        }

    def _remote_file_identity(
        self,
        remote_path: str,
        *,
        require_arm64_elf: bool,
    ) -> dict[str, Any]:
        if (
            not isinstance(remote_path, str)
            or not remote_path.startswith("/")
            or "\x00" in remote_path
        ):
            return {"ok": False, "error": "install_remote_path_invalid"}
        quoted = shlex.quote(remote_path)
        machine = (
            f"m=$(dd if={quoted} bs=1 skip=18 count=2 2>/dev/null "
            "| od -An -tu2 | tr -d ' '); "
            if require_arm64_elf
            else "m=0; "
        )
        command = (
            "set -eu; "
            f"test -f {quoted}; test ! -L {quoted}; "
            + machine
            + f"printf '%s %s %s %s\\n' \"$(sha256sum {quoted} | cut -d' ' -f1)\" "
            f"\"$(stat -c %a {quoted})\" \"$(stat -c %s {quoted})\" \"$m\""
        )
        observed = self.docker_exec(["sh", "-c", command], timeout=20)
        fields = str(observed.get("stdout") or "").strip().split()
        if (
            observed.get("ok") is not True
            or len(fields) != 4
            or _SHA256_PATTERN.fullmatch(fields[0]) is None
            or not fields[1].isdigit()
            or not fields[2].isdigit()
            or require_arm64_elf and fields[3] != "183"
        ):
            return {"ok": False, "error": "install_remote_identity_invalid"}
        return {
            "ok": True,
            "sha256": fields[0],
            "mode": int(fields[1], 8),
            "size": int(fields[2]),
            "architecture": "arm64" if fields[3] == "183" else None,
        }

    def _installed_daemon_apk_identity(self) -> dict[str, Any]:
        package = self.adb(
            ["shell", "pm", "path", "dev.xenoid.daemon"],
            timeout=15,
        )
        paths = [
            line.removeprefix("package:").strip()
            for line in str(package.get("stdout") or "").splitlines()
            if line.startswith("package:/")
        ]
        if package.get("ok") is not True or len(paths) != 1:
            return {"ok": False, "state": "absent"}
        quoted = shlex.quote(paths[0])
        identity = self.docker_exec(
            [
                "sh",
                "-c",
                "set -eu; "
                f"test -f {quoted}; test ! -L {quoted}; "
                f"printf '%s %s\\n' \"$(sha256sum {quoted} | cut -d' ' -f1)\" "
                f"\"$(stat -c %s {quoted})\"",
            ],
            timeout=20,
        )
        fields = str(identity.get("stdout") or "").strip().split()
        if (
            identity.get("ok") is not True
            or len(fields) != 2
            or _SHA256_PATTERN.fullmatch(fields[0]) is None
            or not fields[1].isdigit()
        ):
            return {"ok": False, "state": "unknown"}
        return {
            "ok": True,
            "state": "installed",
            "sha256": fields[0],
            "size": int(fields[1]),
        }

    def ensure_daemon_runtime_permissions(self) -> dict[str, Any]:
        granted: list[str] = []
        for permission in _DAEMON_RUNTIME_PERMISSIONS:
            result = self.adb(
                [
                    "shell",
                    "pm",
                    "grant",
                    "--user",
                    "0",
                    "dev.xenoid.daemon",
                    permission,
                ],
                timeout=15,
            )
            if result.get("ok") is not True:
                return {
                    "ok": False,
                    "error": "daemon_permission_grant_failed",
                    "permission": permission,
                }
            granted.append(permission)
        return {"ok": True, "granted": granted}

    def install_daemon(self, apk_path: str) -> dict[str, Any]:
        p = Path(apk_path).expanduser().resolve()
        local = self._local_deploy_identity(p, require_arm64_elf=False)
        if local.get("ok") is not True:
            return local
        installed = self._installed_daemon_apk_identity()
        if (
            installed.get("ok") is True
            and installed.get("sha256") == local["sha256"]
        ):
            permissions = self.ensure_daemon_runtime_permissions()
            if permissions.get("ok") is not True:
                return permissions
            return {
                "ok": True,
                "skipped": True,
                "reason": "digest_match",
                "sha256": local["sha256"],
                "installed": installed,
                "permission": permissions,
            }
        preserved = self._capture_proxy_desired_for_update()
        if preserved.get("ok") is not True:
            return preserved
        guarded = self.quarantine_proxy_for_lifecycle()
        if guarded.get("ok") is not True:
            self._discard_pending_proxy_restore()
            return guarded
        install = self.adb(["install", "-r", str(p)])
        if not install.get("ok"):
            self._discard_pending_proxy_restore()
            return install
        runtime_permissions = self.ensure_daemon_runtime_permissions()
        if runtime_permissions.get("ok") is not True:
            self._discard_pending_proxy_restore()
            return {
                "ok": False,
                "error": "daemon_permission_grant_failed",
                "install": install,
            }
        force_stop = self.adb(
            ["shell", "am", "force-stop", "dev.xenoid.daemon"],
            timeout=15,
        )
        if force_stop.get("ok") is not True:
            self._discard_pending_proxy_restore()
            return {
                "ok": False,
                "error": "daemon_restart_failed",
                "install": install,
            }
        verified = self._installed_daemon_apk_identity()
        if (
            verified.get("ok") is not True
            or verified.get("sha256") != local["sha256"]
        ):
            self._discard_pending_proxy_restore()
            return {
                "ok": False,
                "error": "daemon_apk_digest_mismatch",
                "install": install,
            }
        return {
            "ok": True,
            "changed": True,
            "sha256": local["sha256"],
            "install": install,
            "permission": runtime_permissions,
            "forceStop": force_stop,
            "proxyQuarantine": guarded,
        }



    def _instance_output_path(
        self,
        value: Optional[str],
        default_relative: str,
    ) -> Path:
        state_root = self.context.state_root.resolve()
        candidate = (
            state_root / default_relative
            if value is None
            else Path(value).expanduser()
        )
        if not candidate.is_absolute():
            candidate = state_root / candidate
        resolved = candidate.resolve()
        try:
            resolved.relative_to(state_root)
        except ValueError as exc:
            raise InstanceError(
                "resource_conflict",
                "mutable output path is outside instance state",
            ) from exc
        return resolved

    def fetch_frida(self, version: str = "latest", arch: str = "android-arm64", out_dir: Optional[str] = None) -> dict[str, Any]:
        out = self._instance_output_path(out_dir, "frida")
        out.mkdir(parents=True, exist_ok=True)
        requested = version
        if version == "latest":
            # Pin the server to the local frida CLI version: a minor mismatch
            # (e.g. server 17.2.x vs CLI 17.5.x) breaks app-process injection
            # with dlopen /proc/self/fd errors. Fall back to latest if the
            # CLI version cannot be determined or its tag has no matching asset.
            frida_bin = which("frida")
            if frida_bin:
                bounded = run_bounded(
                    [frida_bin, "--version"],
                    cwd=self.context.project_root,
                    deadline=time.monotonic() + 10.0,
                    project_root=self.context.project_root,
                )
                if bounded.ok:
                    cli_version = (bounded.stdout_tail or bounded.stderr_tail).strip().splitlines()[0].strip()
                    if re.fullmatch(r"\d+\.\d+\.\d+", cli_version):
                        requested = cli_version
        if requested != "latest":
            cached_asset = f"frida-server-{requested}-{arch}.xz"
            cached_xz = out / cached_asset
            if cached_xz.is_file():
                server_path = out / "frida-server"
                temporary_server = out / ".frida-server.tmp"
                try:
                    with lzma.open(cached_xz, "rb") as src, temporary_server.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
                    temporary_server.chmod(0o755)
                    temporary_server.replace(server_path)
                    return {
                        "ok": True,
                        "version": requested,
                        "requested": requested,
                        "asset": cached_asset,
                        "xz": str(cached_xz),
                        "path": str(server_path),
                        "cached": True,
                    }
                except (OSError, lzma.LZMAError):
                    temporary_server.unlink(missing_ok=True)
        api = "https://api.github.com/repos/frida/frida/releases/latest" if requested == "latest" else f"https://api.github.com/repos/frida/frida/releases/tags/{requested}"
        try:
            with urllib.request.urlopen(api, timeout=30) as resp:
                release = json.loads(resp.read().decode())
            assets = release.get("assets", [])
            selected = None
            for asset in assets:
                name = asset.get("name", "")
                if arch in name and name.endswith(".xz") and "frida-server" in name:
                    selected = asset
                    break
            if not selected:
                if requested != "latest":
                    return self.fetch_frida("latest", arch, out_dir)
                return {"ok": False, "error": f"no frida-server asset for {arch}", "release": release.get("tag_name"), "assetNames": [a.get("name") for a in assets]}
            xz_path = out / selected["name"]
            with urllib.request.urlopen(selected["browser_download_url"], timeout=120) as resp, xz_path.open("wb") as f:
                shutil.copyfileobj(resp, f)
            server_path = out / "frida-server"
            with lzma.open(xz_path, "rb") as src, server_path.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            server_path.chmod(0o755)
            return {"ok": True, "version": release.get("tag_name"), "requested": requested, "asset": selected.get("name"), "xz": str(xz_path), "path": str(server_path)}
        except Exception as e:
            return {"ok": False, "error": str(e), "api": api}

    def install_frida(
        self,
        version: str = "latest",
        arch: str = "android-arm64",
        out_dir: Optional[str] = None,
        remote_path: str = "/data/system/.core/svc.bin",
    ) -> dict[str, Any]:
        fetch = self.fetch_frida(version=version, arch=arch, out_dir=out_dir)
        result: dict[str, Any] = {
            "ok": False,
            "stage": "fetch",
            "fetch": fetch,
            "deploy": None,
            "remotePath": remote_path,
        }
        if not fetch.get("ok"):
            return result

        server_path = fetch.get("path")
        if not isinstance(server_path, str) or not server_path:
            result["fetch"] = {
                **fetch,
                "ok": False,
                "error": "frida-server download returned no install path",
            }
            return result

        deploy = self.deploy_frida(server_path, remote_path)
        result["deploy"] = deploy
        result["path"] = server_path
        result["ok"] = bool(deploy.get("ok"))
        result["stage"] = "complete" if result["ok"] else "deploy"
        return result

    def base_image_for_build(self) -> str:
        """Return the configured 64-bit Android 13 base image."""
        return self.cfg.image

    def make_runtime_context(
        self,
        image: Optional[str] = None,
        *,
        output: Optional[Path] = None,
        spec: Optional[ReleaseSpec] = None,
    ) -> dict[str, Any]:
        try:
            selected_spec = (
                self.google_runtime_spec("runtime-context", require_assets=True)
                if spec is None
                else spec
            )
            context = self._runtime_image_builder().materialize_context(
                image or self.base_image_for_build(),
                selected_spec,
                output,
            )
        except (GoogleServicesError, InstanceError, OSError, RuntimeError, ValueError) as exc:
            return {
                "ok": False,
                "error": getattr(exc, "code", "runtime_context_generation_failed"),
                "message": str(exc),
            }
        return {
            "ok": True,
            **context,
            "context": context["contextPath"],
            "googleServices": (
                selected_spec.public_dict()
                if selected_spec is not None
                else {"provider": PROVIDER_NONE, "release": PROVIDER_NONE}
            ),
        }


    def ensure_rootfs_images(self) -> dict[str, Any]:
        """Converge rootfs while preserving the committed instance data image."""
        return self.ensure_instance_storage()

    def make_ota_bundle(self, version: str = "0.1.0") -> dict[str, Any]:
        try:
            version = validate_release_version(version)
        except ValueError:
            return {
                "ok": False,
                "code": "release_version_invalid",
                "error": "release_version_invalid",
            }
        script = self.context.project_root / "scripts" / "make-ota-bundle.sh"
        output_root = self.context.state_root / "ota" / "bundles"
        env = self.docker_env()
        env["XENOID_STATE_ROOT"] = str(self.context.state_root)
        env["XENOID_OTA_OUTPUT_DIR"] = str(output_root)
        env["XENOID_ARTIFACT_ROOT"] = str(
            self._artifact_consumer_root(
                ("daemon", "input", "hide", "profile", "netctl")
            )
        )
        proc = run([str(script), version], env=env)
        bundle: Optional[str] = None
        error: Optional[str] = None
        if proc.returncode == 0 and proc.stdout.strip():
            source = Path(proc.stdout.strip().splitlines()[-1]).expanduser().resolve()
            try:
                if not source.is_file():
                    raise OSError("OTA builder returned no bundle")
                output_root.mkdir(parents=True, exist_ok=True)
                destination = output_root / source.name
                temporary = output_root / f".{source.name}.{secrets.token_hex(8)}.tmp"
                shutil.copy2(source, temporary)
                temporary.replace(destination)
                bundle = str(destination)
            except OSError:
                error = "failed to persist instance OTA bundle"
        ok = proc.returncode == 0 and bundle is not None
        return {
            "ok": ok,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "bundle": bundle,
            **({} if error is None else {"error": error}),
        }

    def apply_ota_bundle(self, bundle_path: str) -> dict[str, Any]:
        bundle = Path(bundle_path).expanduser().resolve()
        if not bundle.exists():
            return {"ok": False, "error": f"OTA bundle not found: {bundle}"}
        work = (self.context.state_root / "ota" / "staged").resolve()
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(bundle, "r:gz") as tf:
                import os
                for member in tf.getmembers():
                    target = (work / member.name).resolve()
                    if os.path.commonpath([str(work), str(target)]) != str(work):
                        return {"ok": False, "error": f"unsafe tar member: {member.name}"}
                tf.extractall(work)
            roots = [p for p in work.iterdir() if p.is_dir()]
            if not roots:
                return {"ok": False, "error": "bundle has no root directory"}
            root = roots[0]
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            payloads = manifest.get("payloads", {})
            results: dict[str, Any] = {"ok": True, "bundle": str(bundle), "manifest": manifest, "steps": {}}
            daemon_info = payloads.get("daemonApk")
            if daemon_info:
                apk = root / daemon_info["path"]
                results["steps"]["daemonInstall"] = self.install_daemon(str(apk))
                results["steps"]["daemonBootstrap"] = (
                    self.reconcile_bootstrap()
                    if results["steps"]["daemonInstall"].get("ok") is True
                    else {"ok": False, "error": "daemon_install_failed"}
                )
                results["steps"]["proxyConverged"] = (
                    self.reconcile_proxy_desired()
                    if results["steps"]["daemonBootstrap"].get("controlReady") is True
                    else {"ok": False, "error": "daemon_unreachable"}
                )
                if results["steps"]["proxyConverged"].get("ok") is not True:
                    self._discard_pending_proxy_restore()
            helper_info = payloads.get("inputHelper")
            if helper_info:
                helper = root / helper_info["path"]
                results["steps"]["inputDeploy"] = self.deploy_input_helper(str(helper), helper_info.get("remotePath", "/data/local/tmp/xenoid-input"))
            hide_info = payloads.get("hideHelper")
            if hide_info:
                helper = root / hide_info["path"]
                results["steps"]["hideDeploy"] = self.deploy_hide_helper(str(helper), hide_info.get("remotePath", "/data/local/tmp/xenoid-hide-helper"))
            profile_info = payloads.get("profileHelper")
            if profile_info:
                helper = root / profile_info["path"]
                results["steps"]["profileDeploy"] = self.deploy_profile_helper(str(helper), profile_info.get("remotePath", "/data/local/tmp/xenoid-profile-helper"))
            netctl_info = payloads.get("netctlHelper")
            if netctl_info:
                helper = root / netctl_info["path"]
                results["steps"]["netctlDeploy"] = self.deploy_netctl_helper(str(helper), netctl_info.get("remotePath", "/data/local/tmp/xenoid-netctl"))
            frida_scripts = payloads.get("fridaScripts")
            if frida_scripts:
                scripts = root / frida_scripts["path"]
                results["steps"]["fridaScriptsDeploy"] = self.deploy_frida_scripts(str(scripts), frida_scripts.get("remotePath", "/data/local/tmp/xenoid-frida"))
            results["ok"] = all(not isinstance(v, dict) or v.get("ok", True) for v in results["steps"].values())
            return results
        except Exception as e:
            return {"ok": False, "error": str(e), "bundle": str(bundle)}

    def deploy_frida(self, frida_server_path: str, remote_path: str = "/data/system/.core/svc.bin") -> dict[str, Any]:
        p = Path(frida_server_path).expanduser().resolve()
        if not p.exists():
            return {"ok": False, "error": f"frida-server not found: {p}"}
        staging = "/data/local/tmp/.svc.staging"
        push = self.adb(["push", str(p), staging])
        remote_q = shlex.quote(remote_path)
        remote_dir_q = shlex.quote(str(Path(remote_path).parent))
        move_cmd = f"mkdir -p {remote_dir_q} && chmod 700 {remote_dir_q} && mv -f {shlex.quote(staging)} {remote_q} && chmod 700 {remote_q}"
        move = self.docker_exec(["sh", "-c", move_cmd]) if push.get("ok") else {"ok": False, "skipped": True}
        cleanup = self.adb(["shell", "rm", "-f", staging]) if push.get("ok") else {"ok": False, "skipped": True}
        return {"ok": bool(push.get("ok") and move.get("ok")), "push": push, "move": move, "cleanup": cleanup, "remotePath": remote_path}

    def _deploy_verified_helper(
        self,
        helper_path: str,
        remote_path: str,
        *,
        mode: int = 0o755,
    ) -> dict[str, Any]:
        try:
            local_path = Path(helper_path).expanduser().resolve(strict=True)
        except OSError:
            return {"ok": False, "error": "install_artifact_invalid"}
        local = self._local_deploy_identity(
            local_path,
            require_arm64_elf=True,
        )
        if local.get("ok") is not True:
            return local
        remote = self._remote_file_identity(
            remote_path,
            require_arm64_elf=True,
        )
        if (
            remote.get("ok") is True
            and remote.get("sha256") == local["sha256"]
            and remote.get("size") == local["size"]
            and remote.get("mode") == mode
            and remote.get("architecture") == "arm64"
        ):
            return {
                "ok": True,
                "skipped": True,
                "reason": "digest_mode_architecture_match",
                "sha256": local["sha256"],
                "remotePath": remote_path,
            }
        token = secrets.token_hex(16)
        staging = f"/data/local/tmp/.xenoid-deploy-{token}"
        push = self.adb(["push", str(local_path), staging], timeout=120)
        if push.get("ok") is not True:
            return {
                "ok": False,
                "error": "helper_upload_failed",
                "push": push,
            }
        staged = self._remote_file_identity(
            staging,
            require_arm64_elf=True,
        )
        if (
            staged.get("ok") is not True
            or staged.get("sha256") != local["sha256"]
            or staged.get("size") != local["size"]
            or staged.get("architecture") != "arm64"
        ):
            self.adb(["shell", "rm", "-f", staging], timeout=15)
            return {"ok": False, "error": "helper_upload_digest_mismatch"}
        quoted_staging = shlex.quote(staging)
        quoted_remote = shlex.quote(remote_path)
        quoted_directory = shlex.quote(str(Path(remote_path).parent))
        installed = self.docker_exec(
            [
                "sh",
                "-c",
                "set -eu; "
                f"mkdir -p {quoted_directory}; "
                f"chown 0:0 {quoted_staging}; chmod 0{mode:o} {quoted_staging}; "
                f"mv -f {quoted_staging} {quoted_remote}; sync",
            ],
            timeout=30,
        )
        if installed.get("ok") is not True:
            self.adb(["shell", "rm", "-f", staging], timeout=15)
            return {"ok": False, "error": "helper_install_failed"}
        verified = self._remote_file_identity(
            remote_path,
            require_arm64_elf=True,
        )
        ok = bool(
            verified.get("ok") is True
            and verified.get("sha256") == local["sha256"]
            and verified.get("size") == local["size"]
            and verified.get("mode") == mode
            and verified.get("architecture") == "arm64"
        )
        return {
            "ok": ok,
            "changed": ok,
            "sha256": local["sha256"],
            "remotePath": remote_path,
            **({} if ok else {"error": "helper_install_verification_failed"}),
        }

    def deploy_input_helper(
        self,
        helper_path: str,
        remote_path: str = "/data/local/tmp/xenoid-input",
    ) -> dict[str, Any]:
        return self._deploy_verified_helper(helper_path, remote_path)

    def deploy_hide_helper(
        self,
        helper_path: str,
        remote_path: str = "/data/local/tmp/xenoid-hide-helper",
    ) -> dict[str, Any]:
        return self._deploy_verified_helper(helper_path, remote_path)

    def deploy_netctl_helper(
        self,
        helper_path: str,
        remote_path: str = "/data/local/tmp/xenoid-netctl",
    ) -> dict[str, Any]:
        return self._deploy_verified_helper(helper_path, remote_path)

    def netctl_status(self, ifname: str = "rmnet_data0") -> dict[str, Any]:
        safe_ifname = "".join(c for c in ifname if c.isalnum() or c in "_.:-") or "rmnet_data0"
        cmd = "test -x /data/local/tmp/xenoid-netctl && /data/local/tmp/xenoid-netctl status " + safe_ifname + " || echo '{\"ok\":false,\"error\":\"netctl-helper-missing\"}'"
        r = self.adb(["shell", cmd])
        out: dict[str, Any] = {"ok": bool(r.get("ok")), "adb": r}
        try:
            out["status"] = json.loads(str(r.get("stdout") or "{}"))
            out["ok"] = bool(out["status"].get("ok"))
        except Exception as e:
            out["ok"] = False; out["error"] = str(e)
        return out

    def netctl_set_mac(self, mac: str, ifname: str = "rmnet_data0") -> dict[str, Any]:
        safe_ifname = "".join(c for c in ifname if c.isalnum() or c in "_.:-") or "rmnet_data0"
        safe_mac = "".join(c for c in mac.lower() if c in "0123456789abcdef:")
        cmd = "test -x /data/local/tmp/xenoid-netctl && /data/local/tmp/xenoid-netctl set-mac " + safe_ifname + " " + safe_mac + " || echo '{\"ok\":false,\"error\":\"netctl-helper-missing\"}'"
        r = self.adb(["shell", cmd])
        out: dict[str, Any] = {"ok": bool(r.get("ok")), "adb": r}
        try:
            out["result"] = json.loads(str(r.get("stdout") or "{}"))
            out["ok"] = bool(out["result"].get("ok"))
        except Exception as e:
            out["ok"] = False; out["error"] = str(e)
        return out




    def overlay_status(self) -> dict[str, Any]:
        r = self.adb(["shell", "test -x /system/bin/xenoid-overlay-helper && /system/bin/xenoid-overlay-helper status-json || echo '{\"ok\":false,\"error\":\"overlay-helper-missing\"}'"])
        out = {"ok": bool(r.get("ok")), "adb": r}
        try:
            out["status"] = json.loads(str(r.get("stdout") or "{}"))
            out["ok"] = bool(out["status"].get("ok"))
        except Exception as e:
            out["ok"] = False; out["error"] = str(e)
        return out

    def overlay_cleanup(self) -> dict[str, Any]:
        cmd = "test -x /system/bin/xenoid-overlay-helper && (nohup /system/bin/xenoid-overlay-helper cleanup >/data/local/tmp/xenoid-overlay-cleanup.log 2>&1 & echo '{\"ok\":true,\"started\":true,\"log\":\"/data/local/tmp/xenoid-overlay-cleanup.log\"}') || echo '{\"ok\":false,\"error\":\"overlay-helper-missing\"}'"
        r = self.adb(["shell", cmd])
        out = {"ok": bool(r.get("ok")), "adb": r}
        try:
            out["result"] = json.loads(str(r.get("stdout") or "{}"))
            out["ok"] = bool(out["result"].get("ok"))
        except Exception as e:
            out["ok"] = False; out["error"] = str(e)
        return out

    def deploy_frida_scripts(self, scripts_dir: str = "frida/scripts", remote_dir: str = "/data/local/tmp/xenoid-frida") -> dict[str, Any]:
        src = Path(scripts_dir).expanduser().resolve()
        if not src.exists():
            return {"ok": False, "error": f"frida scripts dir not found: {src}"}
        # Image COPY leaves scripts root:root 644; adb push as shell cannot overwrite.
        # Prepare via rootd (preferred) or docker exec so push can replace files.
        prep_cmd = (
            f"mkdir -p {remote_dir} && chmod 777 {remote_dir} && "
            f"rm -f {remote_dir}/*.js && chown shell:shell {remote_dir} 2>/dev/null || true"
        )
        prep = self.docker_exec(["sh", "-c", prep_cmd])
        mkdir = self.adb(["shell", "mkdir", "-p", remote_dir])
        results = []
        for script in sorted(src.glob("*.js")):
            results.append({"script": str(script), "push": self.adb(["push", str(script), f"{remote_dir}/{script.name}"])})
        ok = bool(prep.get("ok")) and mkdir.get("ok") and all(r["push"].get("ok") for r in results)
        return {"ok": bool(ok), "remoteDir": remote_dir, "prep": prep, "mkdir": mkdir, "scripts": results}

    def load_frida_script(self, package: str, script_path: str, spawn: bool = False, oneshot: bool = False) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9_.]+", package or ""):
            return {"ok": False, "error": f"invalid package name: {package!r}"}
        owned, error = self._owned_container()
        if not owned:
            return {"ok": False, "error": "resource_conflict", "message": error}
        frida_bin = which("frida")
        if frida_bin is None:
            return {"ok": False, "error": "frida CLI not found; install frida-tools", "fix": "python3 -m pip install frida-tools"}
        script = Path(script_path).expanduser().resolve()
        if not script.exists():
            return {"ok": False, "error": f"script not found: {script}"}
        # -t 30: frida-tools quiet mode exits immediately after _ready when the
        # timeout is 0 (repl.py waits only when _quiet_timeout > 0); scripts with
        # delayed callbacks (self-tests, scan capture) need the linger window.
        cmd = [frida_bin, "-D", self.adb_target, "-q", "-t", "30", "--exit-on-error"]
        if spawn:
            # frida-tools 17 removed --no-pause; --spawn already keeps the
            # process paused until the script is loaded, no extra flag needed.
            cmd += ["-f", package]
        else:
            # Attach by PID: frida -n matches the app *label*, not the process
            # name, so name attach can miss. Resolve via pidof first; fall back
            # to exact ps NAME match (pkg or pkg:subproc) with strict input
            # validation — never substring-grep unsanitized input.
            pid_out = self.adb(["shell", f"pidof {package}"])
            pid = str(pid_out.get("stdout", "")).strip().split()
            if not (pid and pid[0].isdigit()) and re.fullmatch(r"[A-Za-z0-9_.]+", package):
                ps_out = self.adb(["shell", f"ps -A -o PID,NAME | awk '$2 == \"{package}\" || index($2, \"{package}:\") == 1 {{print $1; exit}}'"])
                pid = str(ps_out.get("stdout", "")).strip().split()
            if pid and pid[0].isdigit():
                cmd += ["-p", pid[0]]
            else:
                cmd += ["-n", package]
        cmd += ["-l", str(script)]
        if not oneshot:
            # Production default: keep the script resident after the CLI exits.
            # Without this the REPL unload on exit removes every hook.
            cmd += ["--eternalize"]
        try:
            # stdin=DEVNULL: frida REPL exits on EOF after script load (one-shot,
            # deterministic under TTY and non-TTY alike). Timeout must exceed -t.
            proc = run(cmd, timeout=45, stdin=subprocess.DEVNULL)
        except Exception as e:
            return {"ok": False, "error": str(e), "command": cmd}
        result = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "command": cmd, "eternalized": not oneshot}
        # Hook-hit evidence: the script's self-test invokes the hooked File.exists
        # and SystemProperties.get and logs whether the JS replacements fired.
        st = [line for line in (proc.stdout or "").splitlines() if "[xenoid-selftest]" in line]
        result["selfTest"] = st[-1].strip() if st else None
        result["hooksProven"] = any("fileHit=true" in line and "propHit=true" in line for line in st)
        return result

    def generate_profile_frida(self, profile_path: str, out: Optional[str] = None, keep_unique: bool = False) -> dict[str, Any]:
        script = self.context.project_root / "scripts" / "generate-profile-frida.py"
        output = self._instance_output_path(out, "frida/generated-profile.js")
        output.parent.mkdir(parents=True, exist_ok=True)
        cmd = [str(script), profile_path, "--out", str(output)]
        if keep_unique:
            cmd.append("--keep-unique")
        proc = run(cmd)
        data: dict[str, Any] = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip(), "command": cmd}
        try:
            data.update(json.loads(proc.stdout))
        except Exception:
            pass
        return data

    def automation_plan(self, script_path: str) -> dict[str, Any]:
        script = self.context.project_root / "scripts" / "automation-plan.py"
        proc = run([str(script), script_path])
        data: dict[str, Any] = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip()}
        try:
            data.update(json.loads(proc.stdout))
        except Exception:
            pass
        return data

    def automation_run_host(self, script_path: str, execute: bool = False, endpoint: Optional[str] = None) -> dict[str, Any]:
        node = which("node")
        runner = self.context.project_root / "scripts" / "xenoid-js-runner.mjs"
        if node is None:
            plan = self.automation_plan(script_path)
            plan["node"] = False
            plan["note"] = "node not found; returned static automation plan"
            return plan
        expected_endpoint = f"http://127.0.0.1:{self.lease.host_daemon_port}"
        if endpoint is not None and endpoint != expected_endpoint:
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "automation endpoint does not match instance daemon",
            }
        cmd = [node, str(runner), str(Path(script_path).resolve()), f"--endpoint={expected_endpoint}"]
        if execute:
            cmd.append("--execute")
        proc = run(cmd)
        data = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip(), "command": cmd, "node": node}
        try:
            data.update(json.loads(proc.stdout))
        except Exception:
            pass
        return data

    def deploy_profile_helper(
        self,
        helper_path: str,
        remote_path: str = "/data/local/tmp/xenoid-profile-helper",
    ) -> dict[str, Any]:
        return self._deploy_verified_helper(helper_path, remote_path)
    def _pinned_artifact_object(
        self,
        target: str,
        artifact_records: Any,
        *,
        output_path: Optional[str] = None,
    ) -> tuple[Optional[Path], Optional[dict[str, Any]], Optional[str]]:
        values = (
            list(artifact_records.values())
            if isinstance(artifact_records, Mapping)
            else list(artifact_records)
            if isinstance(artifact_records, (list, tuple))
            else []
        )
        record = next(
            (
                dict(value)
                for value in values
                if isinstance(value, Mapping) and value.get("target") == target
            ),
            None,
        )
        if record is None:
            return None, None, "journal_artifact_unavailable"
        outputs = record.get("outputs")
        if not isinstance(outputs, list):
            return None, None, "journal_artifact_unavailable"
        selected = next(
            (
                dict(output)
                for output in outputs
                if isinstance(output, Mapping)
                and (
                    output_path is None
                    or output.get("path") == output_path
                )
            ),
            None,
        )
        if selected is None:
            return None, None, "journal_artifact_unavailable"
        digest = selected.get("sha256")
        size = selected.get("size")
        if (
            not isinstance(digest, str)
            or _SHA256_PATTERN.fullmatch(digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            return None, None, "journal_artifact_unavailable"
        path = (
            self.context.project_root
            / ".xenoid"
            / "cache"
            / "artifacts"
            / "objects"
            / "sha256"
            / digest
        )
        try:
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != size
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest
            ):
                raise OSError
        except OSError:
            return None, None, "journal_artifact_unavailable"
        return path, selected, None

    def deploy_components(
        self,
        mapping: Mapping[str, Any],
        artifact_records: Any = None,
        expected_container_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Deploy only planner-selected, digest-pinned live components."""
        if not isinstance(mapping, Mapping):
            return {"ok": False, "error": "component_action_invalid"}
        container, error = self._owned_container_record()
        if container is None:
            return {
                "ok": False,
                "error": "convergence_state_conflict",
                "message": error,
            }
        container_id = str(container.get("Id") or "")
        if (
            expected_container_id is not None
            and container_id != expected_container_id
        ):
            return {
                "ok": False,
                "error": "convergence_state_conflict",
                "message": "component deployment runtime differs from the journal",
            }
        results: dict[str, Any] = {}
        for name, raw_action in mapping.items():
            if not isinstance(name, str):
                return {"ok": False, "error": "component_action_invalid"}
            action = (
                str(raw_action)
                if isinstance(raw_action, str)
                else str(raw_action.get("action") or "")
                if isinstance(raw_action, Mapping)
                else ""
            )
            if action in {"", "none", "reuse", "inspect"}:
                results[name] = {"ok": True, "skipped": True}
                continue
            details = dict(raw_action) if isinstance(raw_action, Mapping) else {}
            if name == "daemon":
                output_path = str(
                    details.get("outputPath")
                    or "daemon/app/build/outputs/apk/debug/app-debug.apk"
                )
                artifact, _, artifact_error = self._pinned_artifact_object(
                    "daemon",
                    artifact_records,
                    output_path=output_path,
                )
                if artifact_error is not None or artifact is None:
                    results[name] = {"ok": False, "error": artifact_error}
                else:
                    try:
                        with tempfile.TemporaryDirectory(
                            prefix="xenoid-daemon-install-"
                        ) as temporary:
                            staged_apk = Path(temporary) / "xenoid-daemon.apk"
                            shutil.copyfile(artifact, staged_apk)
                            staged_apk.chmod(0o600)
                            installed = self.install_daemon(str(staged_apk))
                    except OSError:
                        installed = {"ok": False}
                    results[name] = (
                        {"ok": True, "installed": True}
                        if installed.get("ok") is True
                        else {"ok": False, "error": "daemon_install_failed"}
                    )
                continue
            if name in {"rootd", "proxySandbox"}:
                # These owners deploy their pinned bytes while reconciling the
                # authenticated control plane/proxy host transaction.
                results[name] = {
                    "ok": True,
                    "deferred": True,
                    "owner": "control-plane" if name == "rootd" else "proxy",
                }
                continue
            defaults = _CONVERGENCE_REMOTE_ARTIFACTS.get(name)
            if defaults is None:
                results[name] = {
                    "ok": False,
                    "error": "component_action_unsupported",
                }
                continue
            default_output, default_remote, default_mode = defaults
            output_path = str(details.get("outputPath") or default_output)
            remote_path = str(details.get("remotePath") or default_remote)
            artifact, output, artifact_error = self._pinned_artifact_object(
                name,
                artifact_records,
                output_path=output_path,
            )
            if artifact_error is not None or artifact is None or output is None:
                results[name] = {"ok": False, "error": artifact_error}
                continue
            mode_value = output.get("mode")
            try:
                expected_mode = (
                    int(mode_value, 8)
                    if isinstance(mode_value, str)
                    else int(mode_value)
                )
            except (TypeError, ValueError):
                expected_mode = default_mode
            results[name] = self._deploy_verified_helper(
                str(artifact),
                remote_path,
                mode=expected_mode,
            )
        ok = all(
            isinstance(result, Mapping) and result.get("ok") is True
            for result in results.values()
        )
        if not ok:
            self._discard_pending_proxy_restore()
        return {
            "ok": ok,
            "containerId": container_id,
            "components": results,
            **({} if ok else {"error": "component_deploy_failed"}),
        }

    @staticmethod
    def _convergence_action_name(action: Any) -> str:
        if isinstance(action, str):
            return action
        if isinstance(action, Mapping):
            value = action.get("action") or action.get("state") or action.get("step")
            return str(value) if isinstance(value, str) else ""
        return ""

    def reconcile_control_plane(self) -> dict[str, Any]:
        """Run bounded bootstrap and restore the UUID-bound storage sentinel."""
        result = self.reconcile_bootstrap()
        if (
            result.get("transportReady") is not True
            or result.get("controlReady") is not True
        ):
            return result
        sentinel = self.data_sentinel(create=False)
        if sentinel.get("ok") is not True:
            sentinel = self.data_sentinel(create=True)
            if sentinel.get("ok") is not True:
                return {
                    **result,
                    "ok": False,
                    "error": "storage_sentinel_create_failed",
                }
            sentinel = self.data_sentinel(create=False)
        if sentinel.get("ok") is not True:
            return {
                **result,
                "ok": False,
                "error": "storage_sentinel_unverified",
            }
        return {
            **result,
            "storageSentinel": {"verified": True},
        }

    def reconcile_identity(
        self,
        action: Any,
        regeneration_capability: Any = None,
    ) -> dict[str, Any]:
        name = self._convergence_action_name(action)
        if name in {"none", "reuse", "inspect", "matching"}:
            status = self.device_identity_status()
            return {
                "ok": status.get("ok") is True,
                "skipped": True,
                "identity": status,
            }
        if regeneration_capability is not None and not isinstance(
            regeneration_capability,
            Mapping,
        ):
            return {"ok": False, "error": "device_regeneration_state_invalid"}
        details = dict(action) if isinstance(action, Mapping) else {}
        profile = details.get("profile")
        client = self.daemon_client()
        if not isinstance(profile, Mapping):
            dumped = client.profile_helper_dump()
            raw_profile = (
                dumped.get("stdout")
                if isinstance(dumped, Mapping)
                and dumped.get("ok") is True
                else None
            )
            if (
                isinstance(raw_profile, str)
                and 0 < len(raw_profile.encode("utf-8")) <= 256 * 1024
            ):
                try:
                    profile = json.loads(raw_profile)
                except (UnicodeError, json.JSONDecodeError):
                    profile = None
            if (
                not isinstance(profile, Mapping)
                or profile.get("schema") != "dev.xenoid.fingerprint/v1"
            ):
                canonical = (
                    self.context.project_root
                    / "examples"
                    / "fingerprints"
                    / "pixel-raven-android13.json"
                )
                try:
                    info = canonical.lstat()
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or not 0 < info.st_size <= 256 * 1024
                    ):
                        raise OSError("canonical device profile is unsafe")
                    profile = json.loads(canonical.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError):
                    profile = None
            if (
                not isinstance(profile, Mapping)
                or profile.get("schema") != "dev.xenoid.fingerprint/v1"
            ):
                return {
                    "ok": False,
                    "error": "device_profile_required",
                    "message": "identity convergence requires the canonical Raven profile",
                }
        try:
            from .device_identity import converge_instance_identity

            result = converge_instance_identity(
                self.context,
                self,
                client,
                profile,
                rotate_stable=False,
            )
        except (IdentityError, InstanceError) as exc:
            return {
                "ok": False,
                "error": getattr(exc, "code", "device_identity_apply_failed"),
            }
        if result.get("ok") is True:
            created_sentinel = self.data_sentinel(create=True)
            if created_sentinel.get("ok") is not True:
                return {
                    "ok": False,
                    "error": "storage_sentinel_create_failed",
                }
            verified_sentinel = self.data_sentinel(create=False)
            if verified_sentinel.get("ok") is not True:
                return {
                    "ok": False,
                    "error": "storage_sentinel_unverified",
                }
            result["storageSentinel"] = {
                "created": True,
                "verified": True,
            }
        return result

    def reconcile_location(
        self,
        action: Any,
        regeneration_capability: Any = None,
    ) -> dict[str, Any]:
        name = self._convergence_action_name(action)
        if name in {"none", "reuse", "inspect", "matching"}:
            return {"ok": True, "skipped": True}
        if regeneration_capability is not None and not isinstance(
            regeneration_capability,
            Mapping,
        ):
            return {"ok": False, "error": "device_regeneration_state_invalid"}
        try:
            from .cellular import encode_profile_v1
            from .location import (
                STAGE_SCHEMA,
                LocationError,
                LocationStateStore,
                convergence_action,
                location_runtime_epoch,
                masked_android_status,
                public_summary,
            )

            store = LocationStateStore(self.context.state_root)
            state = store.load()
            if state is None:
                return {"ok": False, "error": "location_state_missing"}
            if state.get("active") is None and state.get("pending") is None:
                state, _ = store.set_desired(str(state["desiredCountry"]))
            container_id = self.location_runtime_container_id()
            if container_id is None:
                return {"ok": False, "error": "location_runtime_invalid"}
            epoch = location_runtime_epoch(container_id)
            client = self.daemon_client()
            for _ in range(8):
                state = store.load()
                if state is None:
                    raise LocationError("location_state_missing")
                try:
                    android = client.location_status(timeout=10.0)
                except Exception:
                    android = None
                decision = convergence_action(state, android, epoch)
                step = str(decision.get("step") or "")
                if step == "noop":
                    return {
                        "ok": True,
                        "identity": public_summary(state),
                        "android": masked_android_status(android),
                    }
                if step == "resume":
                    store.mark_restarted(epoch)
                    continue
                if step == "stage":
                    profile = store.target_profile(state)
                    request = {
                        "schema": STAGE_SCHEMA,
                        "profile": profile,
                        "encodedProfile": base64.b64encode(
                            encode_profile_v1(profile)
                        ).decode("ascii"),
                        "profileDigest": profile["identityDigest"],
                        "locationKey": profile["locationKey"],
                        "runtimeEpoch": epoch,
                    }
                    staged = client.location_stage(request)
                    if staged.get("ok") is not True:
                        return {"ok": False, "error": "location_stage_failed"}
                    pending = state.get("pending")
                    if isinstance(pending, Mapping) and pending.get("phase") == "new":
                        store.mark_staged(epoch)
                    if decision.get("recreate") is True:
                        current = store.load()
                        pending = current.get("pending") if isinstance(current, Mapping) else None
                        if isinstance(pending, Mapping) and pending.get("phase") == "staged":
                            store.arm_restart()
                        return {
                            "ok": False,
                            "error": "convergence_live_resolution_conflict",
                            "message": "location still requires the planner-authorized runtime replacement",
                        }
                    continue
                if step == "verify":
                    if decision.get("restage"):
                        profile = store.target_profile(state)
                        staged = client.location_stage(
                            {
                                "schema": STAGE_SCHEMA,
                                "profile": profile,
                                "encodedProfile": base64.b64encode(
                                    encode_profile_v1(profile)
                                ).decode("ascii"),
                                "profileDigest": profile["identityDigest"],
                                "locationKey": profile["locationKey"],
                                "runtimeEpoch": epoch,
                            }
                        )
                        if staged.get("ok") is not True:
                            return {"ok": False, "error": "location_stage_failed"}
                    digest = store.target_profile(state)["identityDigest"]
                    verified = client.location_verify(digest, epoch)
                    if (
                        verified.get("ok") is not True
                        or verified.get("verified") is not True
                    ):
                        return {
                            "ok": False,
                            "error": "location_identity_unverified",
                        }
                    if decision.get("promote"):
                        store.promote(epoch)
                    else:
                        store.mark_validated(epoch)
                    continue
                if step in {"bootstrap", "recreate"}:
                    return {
                        "ok": False,
                        "error": "convergence_live_resolution_conflict",
                    }
                return {"ok": False, "error": "location_phase_invalid"}
            return {"ok": False, "error": "location_convergence_failed"}
        except (LocationError, InstanceError) as exc:
            return {
                "ok": False,
                "error": getattr(exc, "code", "location_convergence_failed"),
            }

    def reconcile_keybox(self, action: Any) -> dict[str, Any]:
        name = self._convergence_action_name(action)
        try:
            status = self.daemon_client().keybox_status(timeout=20.0)
        except Exception:
            return {"ok": False, "error": "keybox_daemon_unavailable"}
        if name in {"none", "reuse", "inspect", "matching"}:
            return {**status, "skipped": True}
        return status

    def reconcile_camera(self, action: Any) -> dict[str, Any]:
        name = self._convergence_action_name(action)
        try:
            client = self.daemon_client()
            if name in {"apply", "reconcile", "drift"}:
                applied = client.camera_apply()
                if applied.get("ok") is not True:
                    return applied
            else:
                applied = {"ok": True, "skipped": True}
            status = client.camera_status(timeout=20.0)
        except Exception:
            return {"ok": False, "error": "camera_daemon_unavailable"}
        return {
            **status,
            "apply": applied,
            "ok": status.get("ok") is True,
        }

    def reconcile_google(
        self,
        action: Any,
        fresh_bootstrap: bool = False,
    ) -> dict[str, Any]:
        name = self._convergence_action_name(action)
        try:
            spec = self.google_runtime_spec(
                "convergence-google",
                require_assets=True,
            )
            if name in {"none", "reuse", "inspect", "matching"}:
                status = self.google_services_status(require_runtime=True)
                return {**status, "skipped": True}
            try:
                preflight = self._google_binding_preflight(spec)
                binding = self._begin_google_binding(spec, preflight)
            except GoogleServicesError as exc:
                if (
                    not fresh_bootstrap
                    or spec is None
                    or exc.code != "google_services_new_instance_required"
                ):
                    raise
                binding_store = GoogleBindingStore(self.context, self.lease)
                storage = StorageStateStore(self.context, self.lease).load()
                if (
                    binding_store.load() is not None
                    or not isinstance(storage, Mapping)
                    or storage.get("state") != "committed"
                    or storage.get("source") != "fresh"
                ):
                    raise
                binding = binding_store.pending(spec, "fresh")
            gate = self.google_services_bootstrap_gate(spec)
            if gate.get("ok") is not True:
                return gate
            committed = self._commit_google_binding(binding)
            return {
                "ok": True,
                "binding": public_binding(committed),
                "runtime": gate,
            }
        except (GoogleServicesError, StorageError) as exc:
            return {
                "ok": False,
                "error": getattr(exc, "code", "google_services_runtime_not_ready"),
            }

    def observe_shared_protection(self) -> dict[str, Any]:
        return self.shared_protection_status()

    def maintain_shared_protection(
        self,
        expected_digest: Optional[str] = None,
    ) -> dict[str, Any]:
        return self.shared_protection_manager().ensure(expected_digest)

    def reconcile_protection(
        self,
        action: Any,
        expected_digest: Optional[str] = None,
    ) -> dict[str, Any]:
        name = self._convergence_action_name(action)
        if name in {"maintain", "maintenance", "drift", "reconcile"}:
            return self.maintain_shared_protection(expected_digest)
        observed = self.observe_shared_protection()
        if expected_digest is not None and (
            _SHA256_PATTERN.fullmatch(expected_digest) is None
            or observed.get("currentDigest") != expected_digest
        ):
            return {
                **observed,
                "ok": False,
                "error": "shared_protection_digest_mismatch",
                "expectedDigest": expected_digest,
            }
        return observed


    def generate_service_frida(self, profile_path: str, out: Optional[str] = None, keep_unique: bool = False) -> dict[str, Any]:
        script = self.context.project_root / "scripts" / "generate-service-frida.py"
        output = self._instance_output_path(out, "frida/generated-service-profile.js")
        output.parent.mkdir(parents=True, exist_ok=True)
        cmd = [str(script), profile_path, "--out", str(output)]
        if keep_unique:
            cmd.append("--keep-unique")
        proc = run(cmd)
        data: dict[str, Any] = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip(), "command": cmd}
        try:
            data.update(json.loads(proc.stdout))
        except Exception:
            pass
        return data


    def runtime_logs(self, out_dir: Optional[str] = None) -> dict[str, Any]:
        out = self._instance_output_path(out_dir, "logs")
        out.mkdir(parents=True, exist_ok=True)
        result: dict[str, Any] = {"ok": True, "outDir": str(out), "files": {}}
        if which("docker") is not None:
            container, error = self._owned_container_record()
            if container is None:
                return {"ok": False, "error": "resource_conflict", "message": error}
            logs = run(
                [*self.docker_base_cmd(), "logs", container["Id"]],
                env=self.docker_env(),
            )
            p = out / "docker.log"; p.write_text((logs.stdout or "") + (logs.stderr or "")); result["files"]["docker"] = str(p)
            inspect = run(
                [*self.docker_base_cmd(), "inspect", container["Id"]],
                env=self.docker_env(),
            )
            p = out / "docker-inspect.json"; p.write_text(inspect.stdout or inspect.stderr or ""); result["files"]["dockerInspect"] = str(p)
        else:
            result["docker"] = "not found"
        if which("adb") is not None:
            props = self.adb(["shell", "getprop"]); p = out / "getprop.txt"; p.write_text(props.get("stdout", "") + props.get("stderr", "")); result["files"]["getprop"] = str(p)
            logcat = self.adb(["logcat", "-d", "-t", "1000"]); p = out / "logcat.txt"; p.write_text(logcat.get("stdout", "") + logcat.get("stderr", "")); result["files"]["logcat"] = str(p)
        else:
            result["adb"] = "not found"
        return result

    def view(self) -> dict[str, Any]:
        scrcpy = which("scrcpy")
        if scrcpy is None:
            return {"ok": False, "error": "scrcpy not found", "fix": "brew install scrcpy"}
        owned, error = self._owned_container()
        if not owned:
            return {"ok": False, "error": "resource_conflict", "message": error}
        # redroid images commonly lack an Opus encoder; scrcpy 4.x enables audio by default.
        # Disable audio for the default Xenoid view path to avoid server startup failure.
        proc = run([scrcpy, "-s", self.adb_target, "--no-audio", "--video-codec=h264", "--max-size=1024"], capture=True)
        return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}

    @staticmethod
    def _proxy_failure(code: str) -> dict[str, Any]:
        if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code or "") is None:
            code = "engine_unavailable"
        return {"ok": False, "code": code, "error": code}

    @staticmethod
    def _proxy_json_document(text: str) -> Any:
        def exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = value
            return result

        return json.loads(text, object_pairs_hook=exact_object)

    @property
    def _proxy_manifest_path(self) -> str:
        return f"{self._proxy_runtime_path}/manifest.json"

    @property
    def _proxy_state_path(self) -> str:
        return f"/var/lib/xenoid/proxy/instances/{self.context.instance_id}"

    @property
    def _proxy_runtime_path(self) -> str:
        return f"/run/xenoid/proxy/{self.context.resource_tag}"

    @property
    def _proxy_installed_helper(self) -> str:
        return "/usr/libexec/xenoid-proxy-engine.py"


    def _proxy_transport_prefix(self) -> list[str]:
        endpoint = self.docker_endpoint_host()
        if (self.cfg.docker_context or "").strip() and not endpoint:
            raise InstanceError("resource_conflict", "Docker engine host transport is unavailable")
        if endpoint.startswith("tcp://"):
            raise InstanceError("resource_conflict", "proxy engine access requires a local or SSH Docker host")
        if endpoint.startswith("ssh://"):
            from urllib.parse import urlparse

            parsed = urlparse(endpoint)
            if (
                parsed.scheme != "ssh"
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
                or not parsed.hostname
                or re.fullmatch(r"[A-Za-z0-9_.:-]+", parsed.hostname) is None
                or (
                    parsed.username is not None
                    and re.fullmatch(r"[A-Za-z0-9_.-]+", parsed.username) is None
                )
            ):
                raise InstanceError("resource_conflict", "SSH Docker engine identity is invalid")
            ssh = which("ssh")
            if ssh is None:
                raise InstanceError("engine_unavailable", "SSH transport is unavailable")
            host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
            target = f"{parsed.username}@{host}" if parsed.username else host
            prefix = [ssh, "-T", "-o", "BatchMode=yes"]
            if parsed.port is not None:
                prefix.extend(["-p", str(parsed.port)])
            return [*prefix, target, "sudo", "-n", "--"]
        if self.should_use_colima():
            colima = which("colima")
            if colima is None:
                raise InstanceError("engine_unavailable", "Colima host transport is unavailable")
            return [colima, "ssh", "--", "sudo", "-n", "--"]
        if endpoint and not endpoint.startswith("unix://"):
            raise InstanceError("resource_conflict", "proxy engine access requires a local or SSH Docker host")
        if host_info().get("system") != "Linux":
            raise InstanceError("resource_conflict", "native proxy engine access requires Linux")
        sudo = which("sudo")
        if sudo is None:
            raise InstanceError("engine_unavailable", "root proxy engine transport is unavailable")
        return [sudo, "-n", "--"]

    def _proxy_process(
        self,
        argv: list[str],
        *,
        payload: Optional[bytes | bytearray] = None,
        stdin_file: Any = None,
        timeout: int = 120,
        output_limit: int = 8192,
    ) -> tuple[int, bytes]:
        if payload is not None and stdin_file is not None:
            raise InstanceError("internal_contract_error", "proxy transport received conflicting input")
        if (
            not argv
            or timeout <= 0
            or output_limit <= 0
            or any(
                not isinstance(argument, str)
                or not argument
                or any(character in argument for character in ("\0", "\n", "\r"))
                for argument in argv
            )
        ):
            raise InstanceError("internal_contract_error", "proxy transport command is invalid")
        proc: Optional[subprocess.Popen[bytes]] = None
        selector = selectors.DefaultSelector()
        stdout = bytearray()
        stderr_size = 0
        input_view = memoryview(payload) if payload is not None else None
        input_offset = 0
        effective_timeout = bounded_timeout(timeout)
        if effective_timeout is None:
            effective_timeout = float(timeout)
        deadline = time.monotonic() + effective_timeout
        try:
            proc = subprocess.Popen(
                argv,
                stdin=(
                    subprocess.PIPE
                    if input_view is not None
                    else stdin_file if stdin_file is not None else subprocess.DEVNULL
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            if proc.stdout is None or proc.stderr is None:
                raise OSError("proxy transport pipes unavailable")
            os.set_blocking(proc.stdout.fileno(), False)
            os.set_blocking(proc.stderr.fileno(), False)
            selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
            selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
            if input_view is not None:
                if proc.stdin is None:
                    raise OSError("proxy transport input unavailable")
                if len(input_view):
                    os.set_blocking(proc.stdin.fileno(), False)
                    selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
                else:
                    proc.stdin.close()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, effective_timeout)
                events = selector.select(remaining)
                if not events:
                    raise subprocess.TimeoutExpired(argv, effective_timeout)
                for key, _ in events:
                    stream = key.fileobj
                    if key.data == "stdin":
                        try:
                            written = os.write(
                                stream.fileno(),
                                input_view[input_offset : input_offset + 65536],
                            )
                        except BrokenPipeError:
                            written = 0
                            input_offset = len(input_view)
                        else:
                            input_offset += written
                        if input_offset == len(input_view):
                            selector.unregister(stream)
                            stream.close()
                        continue
                    try:
                        chunk = os.read(stream.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    if key.data == "stdout":
                        if len(stdout) + len(chunk) > output_limit:
                            raise InstanceError("engine_response_invalid", "proxy engine response exceeded its bound")
                        stdout.extend(chunk)
                    else:
                        stderr_size += len(chunk)
                        if stderr_size > output_limit:
                            raise InstanceError("engine_response_invalid", "proxy engine response exceeded its bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, effective_timeout)
            returncode = proc.wait(timeout=remaining)
        except InstanceError:
            raise
        except (OSError, subprocess.SubprocessError) as exc:
            raise InstanceError("engine_unavailable", "proxy engine transport failed") from exc
        finally:
            selector.close()
            if proc is not None:
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait()
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
            if input_view is not None:
                input_view.release()
        return returncode, bytes(stdout)

    def _proxy_root_process(
        self,
        arguments: list[str],
        *,
        payload: Optional[bytes | bytearray] = None,
        stdin_file: Any = None,
        timeout: int = 120,
        output_limit: int = 8192,
    ) -> tuple[int, bytes]:
        return self._proxy_process(
            [*self._proxy_transport_prefix(), *arguments],
            payload=payload,
            stdin_file=stdin_file,
            timeout=timeout,
            output_limit=output_limit,
        )

    def _proxy_root_json(
        self,
        action: str,
        *,
        helper: Optional[str] = None,
        timeout: int = 120,
    ) -> dict[str, Any]:
        returncode, output = self._proxy_root_process(
            [helper or self._proxy_installed_helper, action, "--manifest", self._proxy_manifest_path],
            timeout=timeout,
            output_limit=65536 if action == "status" else 8192,
        )
        try:
            text = output.decode("ascii", "strict")
            body = text[:-1]
            if (
                not text.endswith("\n")
                or text.count("\n") != 1
                or not body
                or body.strip() != body
                or "\r" in body
            ):
                raise ValueError
            response = self._proxy_json_document(body)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return self._proxy_failure("engine_response_invalid")
        if not isinstance(response, dict):
            return self._proxy_failure("engine_response_invalid")
        if returncode != 0:
            if (
                set(response) == {"ok", "error"}
                and response.get("ok") is False
                and isinstance(response.get("error"), str)
            ):
                return self._proxy_failure(response["error"])
            return self._proxy_failure("engine_unavailable")
        if response == {"ok": True}:
            return response
        if (
            action == "check-control"
            and set(response) == {"ok", "controlDigest"}
            and response.get("ok") is True
            and isinstance(response.get("controlDigest"), str)
            and re.fullmatch(r"[0-9a-f]{64}", response["controlDigest"]) is not None
        ):
            return response
        if action in {"quarantine", "cleanup"} and response == {"notPrepared": True, "ok": True}:
            return response
        if action == "status" and self._proxy_valid_status(response):
            return response
        return self._proxy_failure("engine_response_invalid")

    @staticmethod
    def _proxy_valid_status(response: dict[str, Any]) -> bool:
        capabilities = response.get("capabilities")
        counters = response.get("counters")
        counter_keys = {
            "ingress", "proxyUplink", "egress",
            "ingressBytes", "proxyUplinkBytes", "egressBytes",
        }
        counter_keys.update(
            f"v{family}{capability}{stage}"
            for family in ("4", "6")
            for capability in ("Dns", "Tcp", "Udp")
            for stage in ("Ingress", "Uplink", "Egress")
        )
        return (
            set(response)
            == {
                "ok", "instanceId", "resourceTag", "runtimeEpoch", "generation",
                "manifestDigest", "phase", "structuralApplied", "dataPlaneVerified",
                "capabilities", "counters", "selectedNode", "nodeCount",
            }
            and response.get("ok") is True
            and all(isinstance(response.get(name), str) for name in ("instanceId", "resourceTag", "runtimeEpoch"))
            and isinstance(response.get("generation"), int)
            and not isinstance(response.get("generation"), bool)
            and response["generation"] >= 0
            and isinstance(response.get("manifestDigest"), str)
            and re.fullmatch(r"[0-9a-f]{64}", response["manifestDigest"]) is not None
            and response.get("phase")
            in {"quarantined", "applying", "ready", "active", "error", "disabled", "off", "stopped"}
            and isinstance(response.get("structuralApplied"), bool)
            and isinstance(response.get("dataPlaneVerified"), bool)
            and isinstance(capabilities, dict)
            and set(capabilities)
            == {"v4DnsProxy", "v4TcpProxy", "v4UdpProxy", "v6DnsProxy", "v6TcpProxy", "v6UdpProxy"}
            and all(isinstance(value, bool) for value in capabilities.values())
            and isinstance(counters, dict)
            and set(counters) == counter_keys
            and all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in counters.values())
            and isinstance(response.get("selectedNode"), str)
            and all(
                not 0xD800 <= ord(character) <= 0xDFFF
                for character in response["selectedNode"]
            )
            and len(response["selectedNode"].encode("utf-8")) <= 128
            and isinstance(response.get("nodeCount"), int)
            and not isinstance(response.get("nodeCount"), bool)
            and 0 <= response["nodeCount"] <= 512
        )

    def _proxy_root_simple(
        self,
        arguments: list[str],
        *,
        payload: Optional[bytes | bytearray] = None,
        stdin_file: Any = None,
        timeout: int = 120,
    ) -> bool:
        returncode, output = self._proxy_root_process(
            arguments,
            payload=payload,
            stdin_file=stdin_file,
            timeout=timeout,
        )
        return returncode == 0 and output in {b"", b"\n"}

    def _proxy_remote_exists(self, path: str) -> bool:
        returncode, output = self._proxy_root_process(["test", "-e", path], timeout=15)
        if output not in {b"", b"\n"}:
            raise InstanceError("engine_response_invalid", "proxy host probe response is invalid")
        if returncode == 0:
            return True
        if returncode == 1:
            return False
        raise InstanceError("engine_unavailable", "proxy host probe failed")

    def _proxy_remote_directory_valid(self, path: str, mode: int) -> bool:
        link_returncode, link_output = self._proxy_root_process(
            ["test", "-L", path],
            timeout=15,
        )
        if link_output not in {b"", b"\n"} or link_returncode not in {0, 1}:
            raise InstanceError("engine_unavailable", "proxy host directory probe failed")
        if link_returncode == 0:
            return False
        directory_returncode, directory_output = self._proxy_root_process(
            ["test", "-d", path],
            timeout=15,
        )
        if directory_output not in {b"", b"\n"} or directory_returncode != 0:
            return False
        returncode, output = self._proxy_root_process(
            ["stat", "-c", "%u:%g:%a", path],
            timeout=15,
            output_limit=128,
        )
        if returncode != 0:
            return False
        try:
            metadata = output.decode("ascii", "strict").strip()
        except UnicodeDecodeError:
            return False
        return metadata == f"0:0:{mode:o}"

    def _proxy_remote_regular_valid(self, path: str, mode: int) -> bool:
        link_returncode, link_output = self._proxy_root_process(
            ["test", "-L", path],
            timeout=15,
        )
        if link_output not in {b"", b"\n"} or link_returncode not in {0, 1}:
            raise InstanceError("engine_unavailable", "proxy host file probe failed")
        if link_returncode == 0:
            return False
        file_returncode, file_output = self._proxy_root_process(
            ["test", "-f", path],
            timeout=15,
        )
        if file_output not in {b"", b"\n"} or file_returncode != 0:
            return False
        returncode, output = self._proxy_root_process(
            ["stat", "-c", "%u:%g:%a:%h", path],
            timeout=15,
            output_limit=128,
        )
        if returncode != 0:
            return False
        try:
            metadata = output.decode("ascii", "strict").strip()
        except UnicodeDecodeError:
            return False
        return metadata == f"0:0:{mode:o}:1"

    def _proxy_install_directory(self, path: str, mode: int) -> None:
        if self._proxy_remote_exists(path):
            if not self._proxy_remote_directory_valid(path, mode):
                raise InstanceError("ownership_mismatch", "proxy directory ownership is invalid")
            return
        created = self._proxy_root_simple(
            ["install", "-d", "-o", "root", "-g", "root", "-m", f"{mode:04o}", path],
            timeout=30,
        )
        if (
            not created
            and not self._proxy_remote_exists(path)
            or not self._proxy_remote_directory_valid(path, mode)
        ):
            raise InstanceError("install_artifact_invalid", "proxy directory staging failed")

    def _proxy_stage_stream(
        self,
        target: str,
        stream: Any,
        mode: int,
        *,
        timeout: int = 120,
    ) -> None:
        if not self._proxy_root_simple(
            ["install", "-o", "root", "-g", "root", "-m", f"{mode:04o}", "/dev/stdin", target],
            stdin_file=stream,
            timeout=timeout,
        ):
            raise InstanceError("install_artifact_invalid", "proxy artifact staging failed")

    def _proxy_stage_bytes(
        self,
        target: str,
        payload: bytes | bytearray,
        mode: int,
    ) -> None:
        if not isinstance(payload, (bytes, bytearray)) or len(payload) > 65536:
            raise InstanceError("internal_contract_error", "proxy payload exceeded its bound")
        if not self._proxy_root_simple(
            ["install", "-o", "root", "-g", "root", "-m", f"{mode:04o}", "/dev/stdin", target],
            payload=payload,
            timeout=30,
        ):
            raise InstanceError("install_artifact_invalid", "proxy payload staging failed")

    def _proxy_remote_sha256(self, path: str) -> str:
        returncode, output = self._proxy_root_process(["sha256sum", "--", path], timeout=30)
        if returncode != 0:
            raise InstanceError("install_artifact_invalid", "proxy artifact verification failed")
        try:
            text = output.decode("ascii", "strict").rstrip("\n")
        except UnicodeDecodeError as exc:
            raise InstanceError("install_artifact_invalid", "proxy artifact verification failed") from exc
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", text)
        if match is None or match.group(2) != path:
            raise InstanceError("install_artifact_invalid", "proxy artifact verification failed")
        return match.group(1)

    @staticmethod
    def _proxy_open_local_file(
        path: Path,
        *,
        limit: int,
        exact_mode: Optional[int] = None,
    ) -> tuple[Any, str]:
        absolute = Path(os.path.abspath(os.fspath(path)))
        try:
            before = absolute.lstat()
        except OSError as exc:
            raise InstanceError("install_artifact_invalid", "local proxy artifact is unavailable") from exc
        mode = stat.S_IMODE(before.st_mode)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > limit
            or (exact_mode is not None and mode != exact_mode)
            or (exact_mode is None and mode & 0o022)
        ):
            raise InstanceError("install_artifact_invalid", "local proxy artifact ownership or mode is invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        stream: Any = None
        try:
            descriptor = os.open(absolute, flags)
            stream = os.fdopen(descriptor, "rb", closefd=True)
            current = os.fstat(stream.fileno())
            if (
                (current.st_dev, current.st_ino, current.st_size)
                != (before.st_dev, before.st_ino, before.st_size)
                or not stat.S_ISREG(current.st_mode)
                or current.st_uid != os.getuid()
                or current.st_nlink != 1
            ):
                raise OSError("local proxy artifact changed")
            digest = hashlib.sha256()
            remaining = limit + 1
            while remaining:
                chunk = stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
            if stream.read(1) or stream.tell() != current.st_size:
                raise OSError("local proxy artifact exceeded its bound")
            stream.seek(0)
            return stream, digest.hexdigest()
        except OSError as exc:
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
            raise InstanceError("install_artifact_invalid", "local proxy artifact validation failed") from exc

    def _proxy_stage_control_bundle(self, expected_digest: str) -> dict[str, str]:
        root = self.context.project_root
        artifact_root = self._artifact_consumer_root("liveDeploy")
        staging = f"/var/lib/xenoid/proxy/control-{expected_digest}"
        ready = f"{staging}/READY"
        self._proxy_install_directory("/var/lib/xenoid", 0o755)
        self._proxy_install_directory("/var/lib/xenoid/proxy", 0o711)
        if self._proxy_remote_exists(staging):
            if not self._proxy_remote_directory_valid(staging, 0o700):
                raise InstanceError("ownership_mismatch", "proxy control staging ownership is invalid")
            creator = False
        else:
            creator = self._proxy_root_simple(
                ["mkdir", "-m", "0700", staging],
                timeout=30,
            )
            if not creator and not self._proxy_remote_directory_valid(staging, 0o700):
                raise InstanceError("install_artifact_invalid", "proxy control staging failed")
        if not self._proxy_remote_directory_valid(staging, 0o700):
            raise InstanceError("install_artifact_invalid", "proxy control staging ownership is invalid")
        populate = creator
        if not creator:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not self._proxy_remote_exists(ready):
                time.sleep(0.1)
            populate = not self._proxy_remote_exists(ready)
        if populate:
            self._proxy_install_directory(f"{staging}/xenoid", 0o755)
        elif not self._proxy_remote_directory_valid(f"{staging}/xenoid", 0o755):
            raise InstanceError("install_artifact_invalid", "proxy control staging is invalid")
        artifacts = (
            (root / "scripts" / "xenoid-proxy-engine.py", f"{staging}/xenoid-proxy-engine.py", 0o555),
            (root / "scripts" / "xenoid-proxy-agent.py", f"{staging}/xenoid-proxy-agent.py", 0o555),
            (root / "scripts" / "xenoid-proxy-compile-worker.py", f"{staging}/xenoid-proxy-compile-worker.py", 0o555),
            (root / "scripts" / "xenoid-proxy-fetch-worker.py", f"{staging}/xenoid-proxy-fetch-worker.py", 0o555),
            (root / "scripts" / "xenoid-proxy-agent@.service", f"{staging}/xenoid-proxy-agent@.service", 0o444),
            (
                artifact_root
                / "native"
                / "xenoid-proxy-sandbox"
                / "xenoid-proxy-sandbox",
                f"{staging}/xenoid-proxy-sandbox",
                0o555,
            ),
            (root / "src" / "xenoid" / "__init__.py", f"{staging}/xenoid/__init__.py", 0o444),
            (root / "src" / "xenoid" / "proxy_source.py", f"{staging}/xenoid/proxy_source.py", 0o444),
            (root / "src" / "xenoid" / "proxy_protocol.py", f"{staging}/xenoid/proxy_protocol.py", 0o444),
        )
        digests: dict[str, str] = {}
        total = 0
        for local, remote, target_mode in artifacts:
            stream, digest = self._proxy_open_local_file(local, limit=8 * 1024 * 1024)
            try:
                total += os.fstat(stream.fileno()).st_size
                if total > 32 * 1024 * 1024:
                    raise InstanceError("install_artifact_invalid", "proxy control bundle exceeded its bound")
                if populate:
                    self._proxy_stage_stream(remote, stream, target_mode)
            finally:
                stream.close()
            if (
                not self._proxy_remote_regular_valid(remote, target_mode)
                or self._proxy_remote_sha256(remote) != digest
            ):
                raise InstanceError("install_artifact_invalid", "proxy control bundle verification failed")
            digests[remote] = digest
        if self._proxy_expected_control_digest(digests, staging) != expected_digest:
            raise InstanceError("install_artifact_invalid", "proxy control bundle changed during staging")
        ready_payload = (expected_digest + "\n").encode("ascii")
        if populate:
            self._proxy_stage_bytes(ready, ready_payload, 0o444)
        returncode, ready_output = self._proxy_root_process(
            ["cat", "--", ready],
            timeout=15,
            output_limit=128,
        )
        if (
            returncode != 0
            or ready_output != ready_payload
            or not self._proxy_remote_regular_valid(ready, 0o444)
        ):
            raise InstanceError("install_artifact_invalid", "proxy control staging is incomplete")
        return digests

    def _proxy_expected_control_digest(
        self,
        staged: dict[str, str],
        base: str = "/var/lib/xenoid/proxy/control-v1",
    ) -> str:
        files = {
            "/usr/libexec/xenoid-proxy-engine.py": staged[f"{base}/xenoid-proxy-engine.py"],
            "/etc/systemd/system/xenoid-proxy-agent@.service": staged[f"{base}/xenoid-proxy-agent@.service"],
            "/usr/libexec/xenoid-proxy-sandbox": staged[f"{base}/xenoid-proxy-sandbox"],
            "/usr/libexec/xenoid-proxy-agent.py": staged[f"{base}/xenoid-proxy-agent.py"],
            "/usr/libexec/xenoid-proxy-compile-worker.py": staged[f"{base}/xenoid-proxy-compile-worker.py"],
            "/usr/libexec/xenoid-proxy-fetch-worker.py": staged[f"{base}/xenoid-proxy-fetch-worker.py"],
            "/usr/lib/xenoid-proxy/python/xenoid/__init__.py": staged[f"{base}/xenoid/__init__.py"],
            "/usr/lib/xenoid-proxy/python/xenoid/proxy_source.py": staged[f"{base}/xenoid/proxy_source.py"],
            "/usr/lib/xenoid-proxy/python/xenoid/proxy_protocol.py": staged[f"{base}/xenoid/proxy_protocol.py"],
        }
        return hashlib.sha256(
            json.dumps(files, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()

    def _proxy_live_identity(self, *, require_running: bool = True) -> tuple[str, str]:
        container, error = self._owned_container_record()
        if container is None:
            if require_running:
                raise InstanceError("resource_conflict", error)
            ensured = self.ensure_network()
            if ensured.get("ok") is not True:
                raise InstanceError(
                    "runtime_identity_mismatch",
                    "instance Docker network is unavailable",
                )
            network, _ = self._inspect_docker_object(
                "network",
                self.lease.network_name,
            )
            network_id = (
                network.get("Id") if isinstance(network, Mapping) else None
            )
            if (
                not isinstance(network, Mapping)
                or not self._network_matches_lease(dict(network))
                or not isinstance(network_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", network_id) is None
            ):
                raise InstanceError(
                    "runtime_identity_mismatch",
                    "instance Docker network identity is invalid",
                )
            return "0" * 64, network_id
        state = container.get("State")
        if (
            not isinstance(state, dict)
            or (require_running and state.get("Running") is not True)
        ):
            raise InstanceError("runtime_identity_mismatch", "instance container state is invalid")
        network, _ = self._inspect_docker_object("network", self.lease.network_name)
        if network is None or not network or not self._network_matches_lease(network):
            raise InstanceError("runtime_identity_mismatch", "instance Docker network identity is invalid")
        container_id = container.get("Id")
        network_id = network.get("Id")
        networks = container.get("NetworkSettings", {}).get("Networks", {})
        endpoint = networks.get(self.lease.network_name) if isinstance(networks, dict) else None
        if (
            not isinstance(container_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
            or not isinstance(network_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", network_id) is None
            or not isinstance(endpoint, dict)
            or (
                require_running
                and endpoint.get("NetworkID") != network_id
            )
            or (
                not require_running
                and endpoint.get("NetworkID") not in ("", network_id)
            )
        ):
            raise InstanceError("runtime_identity_mismatch", "instance runtime identity is invalid")
        return container_id, network_id

    def _proxy_manifest_document(
        self,
        runtime_epoch: str,
        generation: int,
        container_id: str,
        network_id: str,
    ) -> dict[str, Any]:
        if (
            not isinstance(runtime_epoch, str)
            or re.fullmatch(r"[A-Za-z0-9._-]{16,128}", runtime_epoch) is None
            or not isinstance(generation, int)
            or isinstance(generation, bool)
            or not 0 <= generation < (1 << 63)
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", network_id) is None
        ):
            raise InstanceError("manifest_invalid", "proxy runtime identity is invalid")
        instance_id = self.context.instance_id
        tag = self.context.resource_tag
        state = f"/var/lib/xenoid/proxy/instances/{instance_id}"
        manifest: dict[str, Any] = {
            "schema": "dev.xenoid.proxy-engine/v1",
            "manifestDigest": "",
            "instanceId": instance_id,
            "resourceTag": tag,
            "runtimeEpoch": runtime_epoch,
            "generation": generation,
            "containerId": container_id,
            "networkId": network_id,
            "bridgeName": self.lease.bridge_name,
            "proxyNamespace": f"xenoid-p-{tag}",
            "android": {
                "ipv4": self.lease.ipv4_address,
                "ipv6": self.lease.ipv6_address,
                "mac": self.lease.mac_address.lower(),
            },
            "users": {
                "proxy": f"xpm{tag}",
                "fetcher": f"xpf{tag}",
                "compiler": f"xpc{tag}",
                "agent": f"xpa{tag}",
            },
            "veth": {
                "host": self.lease.host_veth,
                "proxy": self.lease.proxy_veth,
                "hostIpv4": self.lease.transfer_ipv4_host,
                "proxyIpv4": self.lease.transfer_ipv4_proxy,
                "hostIpv6": self.lease.transfer_ipv6_host,
                "proxyIpv6": self.lease.transfer_ipv6_proxy,
            },
            "routing": {
                "mark": self.lease.mark_base,
                "mask": self.lease.mark_mask,
                "tables": list(self.lease.route_tables),
                "rulePriorities": list(self.lease.rule_priorities),
            },
            "engine": {
                "binaryPath": "/usr/lib/xenoid/proxy/mihomo-v1.19.29",
                "binarySha256": "8e02308f672e89c076bfc2fa1b03379bd54e58b0bafa81ffb01113fcf6da348d",
            },
            "paths": {
                "config": f"{state}/config.yaml",
                "state": state,
                "key": f"{state}/agent.key",
            },
            "daemon": {
                "ip": self.lease.ipv4_address,
                "port": self.lease.android_daemon_port,
                "adbPort": self.lease.android_adb_port,
            },
        }
        digest_source = dict(manifest)
        digest_source.pop("manifestDigest")
        manifest["manifestDigest"] = hashlib.sha256(
            json.dumps(
                digest_source,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
        return manifest

    def _proxy_validate_manifest(
        self,
        document: Any,
        *,
        require_live: bool,
        allow_stopped: bool = False,
    ) -> dict[str, Any]:
        if (
            not isinstance(document, dict)
            or set(document)
            != {
                "schema", "manifestDigest", "instanceId", "resourceTag", "runtimeEpoch",
                "generation", "containerId", "networkId", "bridgeName", "proxyNamespace",
                "android", "users", "veth", "routing", "engine", "paths", "daemon",
            }
        ):
            raise InstanceError("manifest_invalid", "proxy manifest is invalid")
        container_id = document.get("containerId")
        network_id = document.get("networkId")
        if require_live:
            expected_container, expected_network = self._proxy_live_identity(
                require_running=not allow_stopped
            )
            if (
                (container_id, network_id)
                != (expected_container, expected_network)
                and not (
                    container_id == "0" * 64
                    and network_id == expected_network
                    and isinstance(document.get("runtimeEpoch"), str)
                    and document["runtimeEpoch"].startswith("control-")
                )
            ):
                raise InstanceError(
                    "runtime_identity_mismatch",
                    "proxy manifest runtime identity is stale",
                )
        elif (
            not isinstance(container_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
            or not isinstance(network_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", network_id) is None
        ):
            raise InstanceError("manifest_invalid", "proxy manifest is invalid")
        expected = self._proxy_manifest_document(
            document.get("runtimeEpoch"),
            document.get("generation"),
            container_id,
            network_id,
        )
        if document != expected:
            raise InstanceError("ownership_mismatch", "proxy manifest does not match this instance")
        return document

    def _proxy_read_manifest(
        self,
        *,
        require_live: bool,
        allow_absent: bool,
        allow_stopped: bool = False,
    ) -> Optional[dict[str, Any]]:
        if not self._proxy_remote_exists(self._proxy_manifest_path):
            if allow_absent:
                return None
            raise InstanceError("engine_not_prepared", "proxy engine is not prepared")
        returncode, output = self._proxy_root_process(
            ["cat", "--", self._proxy_manifest_path],
            timeout=30,
            output_limit=65536,
        )
        if returncode != 0 or len(output) < 3 or len(output) > 65536:
            raise InstanceError("manifest_invalid", "proxy manifest could not be read")
        try:
            document = self._proxy_json_document(output.decode("ascii", "strict"))
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            raise InstanceError("manifest_invalid", "proxy manifest is invalid") from exc
        validated = self._proxy_validate_manifest(
            document,
            require_live=require_live,
            allow_stopped=allow_stopped,
        )
        canonical = (
            json.dumps(
                validated,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
        if output != canonical:
            raise InstanceError("manifest_invalid", "proxy manifest encoding is invalid")
        return validated

    def _proxy_restore_manifest_from_ownership(
        self,
        *,
        allow_stopped: bool,
    ) -> dict[str, Any]:
        """Restore volatile proxy manifest state after an engine-host reboot."""
        owner_path = f"{self._proxy_state_path}/engine-ownership.json"
        if not self._proxy_remote_regular_valid(owner_path, 0o600):
            raise InstanceError("ownership_mismatch", "proxy ownership state is invalid")
        returncode, output = self._proxy_root_process(
            ["cat", "--", owner_path],
            timeout=30,
            output_limit=65536,
        )
        if returncode != 0 or not 3 <= len(output) <= 65536:
            raise InstanceError("ownership_mismatch", "proxy ownership state could not be read")
        try:
            owner = self._proxy_json_document(output.decode("ascii", "strict"))
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            raise InstanceError("ownership_mismatch", "proxy ownership state is invalid") from exc
        if (
            not isinstance(owner, dict)
            or set(owner)
            != {
                "schema", "instanceId", "resourceTag", "runtimeEpoch",
                "manifestDigest", "leaseDigest", "manifestGeneration",
                "appliedGeneration", "phase", "activeCandidate", "candidate",
                "previous", "binarySha256", "pythonPath", "resources",
            }
            or owner.get("schema") != "dev.xenoid.proxy-engine.ownership/v1"
            or owner.get("instanceId") != self.context.instance_id
            or owner.get("resourceTag") != self.context.resource_tag
            or not isinstance(owner.get("runtimeEpoch"), str)
            or not isinstance(owner.get("manifestGeneration"), int)
            or isinstance(owner.get("manifestGeneration"), bool)
            or not isinstance(owner.get("manifestDigest"), str)
            or re.fullmatch(r"[0-9a-f]{64}", owner["manifestDigest"]) is None
        ):
            raise InstanceError("ownership_mismatch", "proxy ownership state is invalid")
        canonical = (
            json.dumps(
                owner,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
        if output != canonical:
            raise InstanceError("ownership_mismatch", "proxy ownership encoding is invalid")
        container_id, network_id = self._proxy_live_identity(
            require_running=not allow_stopped
        )
        manifest = self._proxy_manifest_document(
            owner["runtimeEpoch"],
            owner["manifestGeneration"],
            container_id,
            network_id,
        )
        if manifest["manifestDigest"] != owner["manifestDigest"]:
            raise InstanceError("ownership_mismatch", "proxy ownership runtime identity is stale")
        self._proxy_stage_manifest(manifest)
        return manifest

    def _proxy_stage_manifest(self, manifest: dict[str, Any]) -> None:
        self._proxy_install_directory("/run/xenoid", 0o755)
        self._proxy_install_directory("/run/xenoid/proxy", 0o755)
        self._proxy_install_directory(self._proxy_runtime_path, 0o711)
        payload = (
            json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
            + b"\n"
        )
        staged_path = f"{self._proxy_runtime_path}/.manifest.json.new"
        self._proxy_stage_bytes(staged_path, payload, 0o600)
        if (
            not self._proxy_remote_regular_valid(staged_path, 0o600)
            or self._proxy_remote_sha256(staged_path)
            != hashlib.sha256(payload).hexdigest()
            or not self._proxy_root_simple(
                ["mv", "-f", "--", staged_path, self._proxy_manifest_path],
                timeout=30,
            )
        ):
            raise InstanceError("manifest_invalid", "proxy manifest staging failed")
        if self._proxy_read_manifest(require_live=True, allow_absent=False) != manifest:
            raise InstanceError("manifest_invalid", "staged proxy manifest verification failed")

    def _proxy_feature_absent(self) -> bool:
        fixed_paths = (
            self._proxy_state_path,
            self._proxy_runtime_path,
            f"/run/netns/xenoid-p-{self.context.resource_tag}",
            f"/sys/class/net/{self.lease.host_veth}",
        )
        any_path_exists = any(
            self._proxy_remote_exists(path) for path in fixed_paths
        )
        unit_active = self._proxy_root_simple(
            ["systemctl", "is-active", "--quiet", self._proxy_systemd_unit()],
            timeout=15,
        )
        if not any_path_exists and not unit_active:
            return True
        if not self._proxy_remote_exists(self._proxy_manifest_path):
            raise InstanceError("cleanup_incomplete", "partial proxy engine state remains")
        return False

    def _proxy_agent_active(self, manifest: dict[str, Any]) -> bool:
        if not self._proxy_root_simple(
            ["systemctl", "is-active", "--quiet", self._proxy_systemd_unit()],
            timeout=15,
        ):
            return False
        pid_returncode, pid_output = self._proxy_root_process(
            ["systemctl", "show", "--property=MainPID", "--value", self._proxy_systemd_unit()],
            timeout=15,
            output_limit=64,
        )
        try:
            pid_text = pid_output.decode("ascii", "strict").strip()
        except UnicodeDecodeError:
            return False
        if pid_returncode != 0 or re.fullmatch(r"[1-9][0-9]{0,9}", pid_text) is None:
            return False
        command_returncode, command_output = self._proxy_root_process(
            ["cat", "--", f"/proc/{pid_text}/cmdline"],
            timeout=15,
            output_limit=4096,
        )
        command = command_output.rstrip(b"\0").split(b"\0")
        if (
            command_returncode != 0
            or len(command) < 4
            or command[-3:]
            != [
                b"/usr/libexec/xenoid-proxy-agent.py",
                b"--manifest",
                self._proxy_manifest_path.encode("ascii"),
            ]
        ):
            return False
        user_returncode, user_output = self._proxy_root_process(
            ["stat", "-c", "%U", f"/proc/{pid_text}"],
            timeout=15,
            output_limit=64,
        )
        if (
            user_returncode != 0
            or user_output.decode("ascii", "ignore").strip()
            != f"xpa{self.context.resource_tag}"
        ):
            return False
        returncode, output = self._proxy_root_process(
            ["cat", "--", f"{self._proxy_state_path}/agent-status.json"],
            timeout=15,
            output_limit=4096,
        )
        if returncode != 0 or not 3 <= len(output) <= 4096:
            return False
        try:
            status = self._proxy_json_document(output.decode("ascii", "strict"))
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return False
        return (
            isinstance(status, dict)
            and set(status)
            == {"schema", "instanceId", "resourceTag", "runtimeEpoch", "generation", "phase", "errorCode", "updatedAt"}
            and status.get("schema") == "dev.xenoid.proxy-agent.status/v1"
            and status.get("instanceId") == self.context.instance_id
            and status.get("resourceTag") == self.context.resource_tag
            and status.get("runtimeEpoch") == manifest["runtimeEpoch"]
            and isinstance(status.get("generation"), int)
            and not isinstance(status.get("generation"), bool)
            and status["generation"] >= manifest["generation"]
            and status.get("phase") in {"starting", "quarantined", "applying", "ready", "error", "disabled"}
            and isinstance(status.get("errorCode"), str)
            and isinstance(status.get("updatedAt"), int)
            and not isinstance(status.get("updatedAt"), bool)
            and abs(time.time() - status["updatedAt"]) <= 90
        )
    def _proxy_local_control_digest(self) -> str:
        root = self.context.project_root
        artifact_root = self._artifact_consumer_root("liveDeploy")
        base = "/var/lib/xenoid/proxy/control-v1"
        local_files = (
            (root / "scripts" / "xenoid-proxy-engine.py", f"{base}/xenoid-proxy-engine.py"),
            (root / "scripts" / "xenoid-proxy-agent.py", f"{base}/xenoid-proxy-agent.py"),
            (root / "scripts" / "xenoid-proxy-compile-worker.py", f"{base}/xenoid-proxy-compile-worker.py"),
            (root / "scripts" / "xenoid-proxy-fetch-worker.py", f"{base}/xenoid-proxy-fetch-worker.py"),
            (root / "scripts" / "xenoid-proxy-agent@.service", f"{base}/xenoid-proxy-agent@.service"),
            (artifact_root / "native" / "xenoid-proxy-sandbox" / "xenoid-proxy-sandbox", f"{base}/xenoid-proxy-sandbox"),
            (root / "src" / "xenoid" / "__init__.py", f"{base}/xenoid/__init__.py"),
            (root / "src" / "xenoid" / "proxy_source.py", f"{base}/xenoid/proxy_source.py"),
            (root / "src" / "xenoid" / "proxy_protocol.py", f"{base}/xenoid/proxy_protocol.py"),
        )
        digests: dict[str, str] = {}
        total = 0
        for local, staged in local_files:
            stream, digest = self._proxy_open_local_file(local, limit=8 * 1024 * 1024)
            try:
                total += os.fstat(stream.fileno()).st_size
            finally:
                stream.close()
            if total > 32 * 1024 * 1024:
                raise InstanceError("install_artifact_invalid", "proxy control bundle exceeded its bound")
            digests[staged] = digest
        return self._proxy_expected_control_digest(digests)

    def proxy_prerequisite(self, *, allow_stopped: bool = False) -> dict[str, Any]:
        self.ensure_instance_lease()
        container_id, network_id = self._proxy_live_identity(
            require_running=not allow_stopped
        )
        existing = self._proxy_read_manifest(
            require_live=False,
            allow_absent=True,
            allow_stopped=allow_stopped,
        )
        if (
            isinstance(existing, Mapping)
            and (existing.get("containerId"), existing.get("networkId"))
            != (container_id, network_id)
            and not (
                existing.get("containerId") == "0" * 64
                and container_id != "0" * 64
                and existing.get("networkId") == network_id
            )
        ):
            raise InstanceError(
                "runtime_identity_mismatch",
                "proxy manifest runtime identity is stale",
            )
        if existing is None:
            state_exists = self._proxy_remote_exists(self._proxy_state_path)
            runtime_exists = self._proxy_remote_exists(self._proxy_runtime_path)
            if state_exists:
                existing = self._proxy_restore_manifest_from_ownership(
                    allow_stopped=allow_stopped
                )
            elif runtime_exists:
                raise InstanceError("ownership_mismatch", "partial proxy instance state exists")
            else:
                existing = self._proxy_manifest_document(
                    f"control-{self.context.resource_tag}-{self.lease.transaction_id}",
                    0,
                    container_id,
                    network_id,
                )
                self._proxy_stage_manifest(existing)
        if (
            isinstance(existing, Mapping)
            and existing.get("containerId") == "0" * 64
            and container_id != "0" * 64
        ):
            existing = self._proxy_manifest_document(
                f"control-{self.context.resource_tag}-{secrets.token_hex(16)}",
                int(existing["generation"]),
                container_id,
                network_id,
            )
            self._proxy_stage_manifest(existing)
        expected_digest = self._proxy_local_control_digest()
        checked = self._proxy_root_json("check-control")
        if checked.get("ok") is True and checked.get("controlDigest") == expected_digest:
            return self._proxy_root_json("prepare-host", timeout=90)
        owns_engine_state = (
            self._proxy_remote_exists(f"{self._proxy_state_path}/engine-ownership.json")
            or self._proxy_remote_exists(f"{self._proxy_state_path}/mustBlock")
        )
        agent_service_active = self._proxy_root_simple(
            ["systemctl", "is-active", "--quiet", self._proxy_systemd_unit()],
            timeout=15,
        )
        staged: Optional[dict[str, str]] = None
        staging = f"/var/lib/xenoid/proxy/control-{expected_digest}"
        if owns_engine_state or agent_service_active:
            quarantined = self._proxy_root_json("quarantine")
            if (
                quarantined.get("ok") is not True
                and quarantined.get("code")
                in {
                    "runtime_identity_mismatch",
                    "ownership_mismatch",
                    "cleanup_incomplete",
                }
            ):
                # Repair an older installed control helper that rejected Docker's
                # valid stopped-container representation. Staging is inert; the
                # candidate still validates the existing signed manifest/owner.
                staged = self._proxy_stage_control_bundle(expected_digest)
                quarantined = self._proxy_root_json(
                    "quarantine",
                    helper=f"{staging}/xenoid-proxy-engine.py",
                    timeout=180,
                )
            if quarantined.get("ok") is not True:
                return quarantined
            if not self._proxy_stop_agent():
                return self._proxy_failure("agent_stop_failed")
        if staged is None:
            staged = self._proxy_stage_control_bundle(expected_digest)
        installed = self._proxy_root_json(
            "install-control",
            helper=f"{staging}/xenoid-proxy-engine.py",
            timeout=900,
        )
        if installed.get("ok") is not True:
            return installed
        if self._proxy_remote_sha256(self._proxy_installed_helper) != staged[f"{staging}/xenoid-proxy-engine.py"]:
            return self._proxy_failure("install_artifact_invalid")
        rechecked = self._proxy_root_json("check-control")
        if rechecked.get("ok") is not True or rechecked.get("controlDigest") != expected_digest:
            return self._proxy_failure("install_artifact_invalid")
        return {"ok": True}
    def proxy_bootstrap_quarantine(self) -> dict[str, Any]:
        """Install the host fail-closed guard before a stopped Android container starts."""
        deadline = time.monotonic() + 30.0
        while True:
            try:
                prerequisite = self.proxy_prerequisite(allow_stopped=True)
            except InstanceError as exc:
                if exc.code == "runtime_identity_mismatch" and time.monotonic() < deadline:
                    time.sleep(0.1)
                    continue
                raise
            if prerequisite.get("ok") is True:
                break
            if prerequisite.get("code") != "runtime_identity_mismatch" or time.monotonic() >= deadline:
                return prerequisite
            time.sleep(0.1)
        while True:
            guarded = self._proxy_root_json("quarantine")
            if guarded.get("ok") is True:
                return {"ok": True, "quarantined": True}
            if guarded.get("code") != "runtime_identity_mismatch" or time.monotonic() >= deadline:
                return guarded
            time.sleep(0.1)


    def proxy_prepare_asset(self, asset_path: Optional[Path]) -> dict[str, Any]:
        self.ensure_instance_lease()
        prerequisite = self.proxy_prerequisite()
        if prerequisite.get("ok") is not True:
            return prerequisite
        if asset_path is not None:
            stream, digest = self._proxy_open_local_file(
                Path(asset_path),
                limit=64 * 1024 * 1024,
                exact_mode=0o600,
            )
            try:
                if digest != "9a868b5e40ad91d9d71e1b41b0cfce78aaba44360c30df74a723f8e3926a86c":
                    return self._proxy_failure("binary_digest_mismatch")
                self._proxy_install_directory("/run/xenoid", 0o755)
                self._proxy_install_directory("/run/xenoid/proxy", 0o755)
                self._proxy_install_directory(self._proxy_runtime_path, 0o711)
                self._proxy_stage_stream(
                    f"{self._proxy_runtime_path}/mihomo-v1.19.29.gz",
                    stream,
                    0o600,
                    timeout=180,
                )
            finally:
                stream.close()
        result = self._proxy_root_json("install-asset", timeout=900)
        if result.get("ok") is not True:
            return result
        if self._proxy_remote_exists(f"{self._proxy_runtime_path}/mihomo-v1.19.29.gz"):
            return self._proxy_failure("cleanup_incomplete")
        return {"ok": True}

    @staticmethod
    def _proxy_validate_secret(value: str) -> bool:
        if not isinstance(value, str) or len(value) != 44 or value[-1:] != "=":
            return False
        decoded: Optional[bytearray] = None
        try:
            decoded = bytearray(base64.b64decode(value, validate=True))
            return (
                len(decoded) == 32
                and base64.b64encode(decoded).decode("ascii") == value
            )
        except (ValueError, TypeError):
            return False
        finally:
            if decoded is not None:
                for index in range(len(decoded)):
                    decoded[index] = 0

    def _proxy_systemd_unit(self) -> str:
        return f"xenoid-proxy-agent@{self.context.resource_tag}.service"

    def _proxy_stop_agent(self) -> bool:
        returncode, output = self._proxy_root_process(
            ["systemctl", "stop", self._proxy_systemd_unit()],
            timeout=45,
        )
        return returncode in {0, 5} and output in {b"", b"\n"}

    def _proxy_discard_agent_key(self) -> bool:
        try:
            discarded = self._proxy_root_json("discard-key")
            return (
                discarded.get("ok") is True
                and not self._proxy_remote_exists(
                    f"{self._proxy_state_path}/agent.key"
                )
            )
        except InstanceError:
            return False

    def proxy_start_agent(
        self,
        runtime_epoch: str,
        generation: int,
        master_key: str,
        agent_token: str,
        enabled: bool,
    ) -> dict[str, Any]:
        self.ensure_instance_lease()
        if (
            not isinstance(enabled, bool)
            or not self._proxy_validate_secret(master_key)
            or not self._proxy_validate_secret(agent_token)
        ):
            return self._proxy_failure("agent_bootstrap_failed")
        container_id, network_id = self._proxy_live_identity()
        manifest = self._proxy_manifest_document(
            runtime_epoch,
            generation,
            container_id,
            network_id,
        )
        prerequisite = self.proxy_prerequisite()
        if prerequisite.get("ok") is not True:
            return prerequisite
        if enabled:
            prepared_asset = self.proxy_prepare_asset(None)
            if prepared_asset.get("ok") is not True:
                return prepared_asset
        previous = self._proxy_read_manifest(require_live=True, allow_absent=False)
        if previous is not None and generation < previous["generation"]:
            return self._proxy_failure("generation_stale")
        quarantined = self._proxy_root_json("quarantine")
        if quarantined.get("ok") is not True:
            return quarantined
        if not self._proxy_stop_agent():
            return self._proxy_failure("agent_stop_failed")
        self._proxy_stage_manifest(manifest)
        transitioned = self._proxy_root_json("prepare" if enabled else "off", timeout=180)
        if transitioned.get("ok") is not True:
            return transitioned
        key_path = f"{self._proxy_state_path}/agent.key"
        key_payload = bytearray(b'{"agentToken":"')
        key_payload.extend(ord(character) for character in agent_token)
        key_payload.extend(b'","masterKey":"')
        key_payload.extend(ord(character) for character in master_key)
        key_payload.extend(b'"}\n')
        try:
            self._proxy_stage_bytes(key_path, key_payload, 0o400)
            if not self._proxy_remote_regular_valid(key_path, 0o400):
                raise InstanceError("agent_bootstrap_failed", "proxy key staging failed")
        except InstanceError as exc:
            key_removed = self._proxy_discard_agent_key()
            self._proxy_root_json("quarantine")
            if not key_removed:
                raise InstanceError(
                    "agent_key_cleanup_failed",
                    "proxy key cleanup failed",
                ) from exc
            raise
        finally:
            for index in range(len(key_payload)):
                key_payload[index] = 0
        self._proxy_root_process(
            ["systemctl", "reset-failed", self._proxy_systemd_unit()],
            timeout=30,
            output_limit=1024,
        )
        if not self._proxy_root_simple(
            ["systemctl", "start", self._proxy_systemd_unit()],
            timeout=60,
        ):
            key_removed = self._proxy_discard_agent_key()
            self._proxy_root_json("quarantine")
            return self._proxy_failure(
                "agent_start_failed" if key_removed else "agent_key_cleanup_failed"
            )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if (
                not self._proxy_remote_exists(key_path)
                and self._proxy_agent_active(manifest)
            ):
                break
            time.sleep(0.25)
        else:
            self._proxy_stop_agent()
            key_removed = self._proxy_discard_agent_key()
            self._proxy_root_json("quarantine")
            return self._proxy_failure(
                "agent_start_failed" if key_removed else "agent_key_cleanup_failed"
            )
        return {
            "ok": True,
            "instanceId": self.context.instance_id,
            "resourceTag": self.context.resource_tag,
            "runtimeEpoch": runtime_epoch,
            "generation": generation,
            "phase": "starting",
            "structuralApplied": False,
            "dataPlaneVerified": False,
        }

    def proxy_engine_status(self) -> dict[str, Any]:
        self.ensure_instance_lease()
        try:
            manifest = self._proxy_read_manifest(
                require_live=True,
                allow_absent=False,
            )
            if manifest is None:
                return self._proxy_failure("engine_not_prepared")
            agent_active = self._proxy_agent_active(manifest)
            result = self._proxy_root_json("status")
        except InstanceError as exc:
            return self._proxy_failure(exc.code)
        if result.get("ok") is not True:
            return result
        if (
            not agent_active
            and not (
                result.get("phase") == "off"
                and result.get("structuralApplied") is True
                and result.get("dataPlaneVerified") is True
            )
        ):
            return self._proxy_failure("agent_stale")
        if (
            result.get("instanceId") != self.context.instance_id
            or result.get("resourceTag") != self.context.resource_tag
            or result.get("runtimeEpoch") != manifest["runtimeEpoch"]
            or result.get("manifestDigest") != manifest["manifestDigest"]
            or result.get("generation") < manifest["generation"]
        ):
            return self._proxy_failure("runtime_identity_mismatch")
        return result

    def proxy_quarantine(self, generation: Optional[int] = None) -> dict[str, Any]:
        self.ensure_instance_lease()
        if (
            generation is not None
            and (
                not isinstance(generation, int)
                or isinstance(generation, bool)
                or not 0 <= generation < (1 << 63)
            )
        ):
            return self._proxy_failure("generation_stale")
        try:
            if self._proxy_feature_absent():
                return {"ok": True, "notPrepared": True}
            manifest = self._proxy_read_manifest(require_live=False, allow_absent=False)
            if manifest is None:
                return self._proxy_failure("engine_not_prepared")
        except InstanceError as exc:
            return self._proxy_failure(exc.code)
        return self._proxy_root_json("quarantine")

    def proxy_off(
        self,
        generation: int,
        *,
        runtime_epoch: Optional[str] = None,
    ) -> dict[str, Any]:
        self.ensure_instance_lease()
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or not 0 <= generation < (1 << 63)
            or runtime_epoch is not None
            and (
                not isinstance(runtime_epoch, str)
                or re.fullmatch(r"[A-Za-z0-9._-]{16,128}", runtime_epoch) is None
            )
        ):
            return self._proxy_failure("generation_stale")

        def fail_closed(code: str) -> dict[str, Any]:
            try:
                self._proxy_root_json("quarantine")
            except Exception:
                pass
            return self._proxy_failure(code)
        try:
            if self._proxy_feature_absent():
                if runtime_epoch is None:
                    return self._proxy_failure("engine_not_prepared")
                return {
                    "ok": True,
                    "phase": "off",
                    "generation": generation,
                    "runtimeEpoch": runtime_epoch,
                    "structuralApplied": True,
                    "dataPlaneVerified": True,
                    "agentAbsent": True,
                    "routingAbsent": True,
                }
            manifest = self._proxy_read_manifest(require_live=True, allow_absent=False)
            if manifest is None:
                return self._proxy_failure("engine_not_prepared")
            guarded = self._proxy_root_json("quarantine")
            if guarded.get("ok") is not True:
                return guarded
            if generation < manifest["generation"]:
                return self._proxy_failure("generation_stale")
            if not self._proxy_stop_agent():
                return fail_closed("agent_stop_failed")
            discarded = self._proxy_root_json("discard-key")
            if (
                discarded.get("ok") is not True
                or self._proxy_remote_exists(f"{self._proxy_state_path}/agent.key")
            ):
                return fail_closed("agent_key_cleanup_failed")
            target_epoch = runtime_epoch or manifest["runtimeEpoch"]
            if (
                generation != manifest["generation"]
                or target_epoch != manifest["runtimeEpoch"]
            ):
                manifest = self._proxy_manifest_document(
                    target_epoch,
                    generation,
                    manifest["containerId"],
                    manifest["networkId"],
                )
                self._proxy_stage_manifest(manifest)
            result = self._proxy_root_json("off", timeout=180)
            if result.get("ok") is not True:
                code = result.get("code")
                return fail_closed(code if isinstance(code, str) else "off_unverified")
            if self._proxy_root_simple(
                ["systemctl", "is-active", "--quiet", self._proxy_systemd_unit()],
                timeout=15,
            ):
                return fail_closed("agent_stop_failed")
            verified = self._proxy_root_json("status")
            if (
                verified.get("ok") is not True
                or verified.get("instanceId") != self.context.instance_id
                or verified.get("resourceTag") != self.context.resource_tag
                or verified.get("runtimeEpoch") != target_epoch
                or verified.get("generation") != generation
                or verified.get("phase") != "off"
                or verified.get("structuralApplied") is not True
                or verified.get("dataPlaneVerified") is not True
            ):
                return fail_closed("off_unverified")
        except InstanceError as exc:
            return fail_closed(exc.code)
        return {
            "ok": True,
            "phase": "off",
            "generation": generation,
            "runtimeEpoch": target_epoch,
            "structuralApplied": True,
            "dataPlaneVerified": True,
            "agentAbsent": True,
            "routingAbsent": True,
        }

    def proxy_cleanup(self) -> dict[str, Any]:
        self.ensure_instance_lease()
        try:
            if self._proxy_feature_absent():
                return {"ok": True, "notPrepared": True}
            self._proxy_read_manifest(require_live=False, allow_absent=False)
            if not self._proxy_stop_agent():
                return self._proxy_failure("agent_stop_failed")
            result = self._proxy_root_json("cleanup", timeout=180)
            if (
                result.get("ok") is not True
                and result.get("code") == "cleanup_incomplete"
            ):
                expected_digest = self._proxy_local_control_digest()
                self._proxy_stage_control_bundle(expected_digest)
                result = self._proxy_root_json(
                    "cleanup",
                    helper=(
                        f"/var/lib/xenoid/proxy/control-{expected_digest}"
                        "/xenoid-proxy-engine.py"
                    ),
                    timeout=180,
                )
        except InstanceError as exc:
            return self._proxy_failure(exc.code)
        if result.get("ok") is not True:
            return result
        try:
            if not self._proxy_feature_absent():
                return self._proxy_failure("cleanup_incomplete")
        except InstanceError as exc:
            return self._proxy_failure(exc.code)
        return result
