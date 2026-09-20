from __future__ import annotations

import concurrent.futures
import contextlib
import dataclasses
import datetime as _datetime
import errno
import fcntl
import glob as _glob
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import struct
import tempfile
import threading
import time
import urllib.parse
import zipfile
from collections.abc import Collection, Iterator, Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable
from .process import run_bounded


RESULT_SCHEMA = "dev.xenoid.artifacts/v1"
RECORD_SCHEMA = "dev.xenoid.artifact/v1"
SNAPSHOT_SCHEMA = "dev.xenoid.artifact-snapshot/v1"
_RECORD_FIELDS = frozenset({"schema", "target", "inputSha256", "toolSha256", "outputs", "completedAt"})
_OUTPUT_FIELDS = frozenset({"path", "mode", "size", "sha256"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_TARGET_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
_MODE_RE = re.compile(r"^0[0-7]{3}$")
_MAX_RECORD_BYTES = 1024 * 1024
_MAX_FAILED_TAIL_BYTES = 64 * 1024
_COPY_CHUNK = 1024 * 1024


def _validate_relative_name(value: str, code: str) -> None:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(code)
    path = Path(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(code)


def _validate_source_pattern(value: str) -> None:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("artifact_source_path_invalid")
    if value.startswith("/") or any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError("artifact_source_path_invalid")


def _normalize_elf_machine(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.upper().replace("-", "_")
    aliases = {
        "AARCH64": "EM_AARCH64",
        "ARM64": "EM_AARCH64",
        "EM_AARCH64": "EM_AARCH64",
        "X86_64": "EM_X86_64",
        "AMD64": "EM_X86_64",
        "EM_X86_64": "EM_X86_64",
    }
    if normalized not in aliases:
        raise ValueError("artifact_output_elf_machine_invalid")
    return aliases[normalized]


def _normalize_elf_type(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.upper().replace("-", "_")
    aliases = {
        "PIE": "ET_DYN",
        "DYN": "ET_DYN",
        "ET_DYN": "ET_DYN",
        "EXEC": "ET_EXEC",
        "ET_EXEC": "ET_EXEC",
    }
    if normalized not in aliases:
        raise ValueError("artifact_output_elf_type_invalid")
    return aliases[normalized]
class ArtifactError(RuntimeError):
    """A stable, safe artifact error suitable for returning to callers."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclasses.dataclass(frozen=True, slots=True)
class OutputSpec:
    path: str
    mode: int
    elf_machine: str | None = None
    elf_type: str | None = None
    elf_class: int | None = None
    interpreter: bool | None = None

    def __post_init__(self) -> None:
        _validate_relative_name(self.path, "artifact_output_path_invalid")
        if self.mode < 0 or self.mode > 0o7777:
            raise ValueError("artifact_output_mode_invalid")
        if self.elf_class not in (None, 32, 64):
            raise ValueError("artifact_output_elf_class_invalid")
        _normalize_elf_machine(self.elf_machine)
        _normalize_elf_type(self.elf_type)


@dataclasses.dataclass(frozen=True, slots=True)
class BuildTarget:
    name: str
    command: tuple[str, ...]
    sources: tuple[str, ...]
    outputs: tuple[OutputSpec, ...]
    output_directory: str
    dependencies: tuple[str, ...] = ()
    cpu_slots: int = 1
    tools: tuple[str, ...] = ()
    environment: tuple[str, ...] = ()
    force_command: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if not _SAFE_TARGET_RE.fullmatch(self.name):
            raise ValueError("artifact_target_name_invalid")
        if not self.command or any(not isinstance(part, str) or not part for part in self.command):
            raise ValueError("artifact_command_invalid")
        if self.force_command is not None and (
            not self.force_command or any(not isinstance(part, str) or not part for part in self.force_command)
        ):
            raise ValueError("artifact_force_command_invalid")
        if not self.sources:
            raise ValueError("artifact_source_closure_empty")
        for source in self.sources:
            _validate_source_pattern(source)
        if not self.outputs:
            raise ValueError("artifact_outputs_empty")
        _validate_relative_name(self.output_directory, "artifact_output_directory_invalid")
        if self.cpu_slots < 1:
            raise ValueError("artifact_cpu_slots_invalid")
        if len(set(self.dependencies)) != len(self.dependencies):
            raise ValueError("artifact_dependency_duplicate")
        if len(set(self.environment)) != len(self.environment):
            raise ValueError("artifact_environment_duplicate")


@dataclasses.dataclass(frozen=True, slots=True)
class ArtifactOutput:
    path: str
    mode: int
    size: int
    sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "mode": f"0{self.mode:03o}",
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class ArtifactRecord:
    target: str
    input_sha256: str
    tool_sha256: str
    outputs: tuple[ArtifactOutput, ...]
    completed_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": RECORD_SCHEMA,
            "target": self.target,
            "inputSha256": self.input_sha256,
            "toolSha256": self.tool_sha256,
            "outputs": [output.as_dict() for output in self.outputs],
            "completedAt": self.completed_at,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class ArtifactSnapshot:
    targets: tuple[str, ...]
    records: tuple[ArtifactRecord, ...]
    manifest_sha256: str

    @property
    def schema(self) -> str:
        return SNAPSHOT_SCHEMA

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SNAPSHOT_SCHEMA,
            "targets": list(self.targets),
            "records": [record.as_dict() for record in self.records],
            "manifestSha256": self.manifest_sha256,
        }


_ANDROID_ENV = (
    "ANDROID_HOME",
    "ANDROID_SDK_ROOT",
    "ANDROID_NDK_HOME",
    "ANDROID_NDK_ROOT",
    "ANDROID_API",
    "ANDROID_BUILD_TOOLS",
    "XENOID_ANDROID_API",
    "DEVELOPER_DIR",
    "SDKROOT",
)
_BASE_ENV = (
    "HOME",
    "PATH",
    "TMPDIR",
    "JAVA_HOME",
    "RUSTUP_HOME",
    "CARGO_HOME",
    *_ANDROID_ENV,
)
_DOCKER_ENV = ("DOCKER_HOST", "DOCKER_CONTEXT", "COLIMA_PROFILE")
_BUILD_OVERRIDE_NAMES = frozenset(
    {
        "CC",
        "CXX",
        "CPPFLAGS",
        "CFLAGS",
        "CXXFLAGS",
        "LDFLAGS",
        "RUSTFLAGS",
        "RUSTC",
        "RUSTC_WRAPPER",
        "CARGO_TARGET_DIR",
        "GRADLE_OPTS",
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "MAKEFLAGS",
        "XENOID_BUILD_JOBS",
        "XENOID_ARTIFACT_JOBS",
        "XENOID_FORCE_REBUILD",
    }
)


def _out(
    path: str,
    mode: int = 0o755,
    machine: str | None = "AArch64",
    elf_type: str | None = "DYN",
    *,
    interpreter: bool | None = None,
) -> OutputSpec:
    return OutputSpec(path, mode, machine, elf_type, 64 if machine else None, interpreter)


def _target(
    name: str,
    command: tuple[str, ...],
    sources: tuple[str, ...],
    outputs: tuple[OutputSpec, ...],
    output_directory: str,
    *,
    cpu_slots: int = 1,
    tools: tuple[str, ...] = ("android",),
    environment: tuple[str, ...] = _ANDROID_ENV,
    force_command: tuple[str, ...] | None = None,
) -> BuildTarget:
    return BuildTarget(
        name=name,
        command=command,
        sources=sources,
        outputs=outputs,
        output_directory=output_directory,
        cpu_slots=cpu_slots,
        tools=tools,
        environment=environment,
        force_command=force_command,
    )


_COMMON_ANDROID = ("scripts/android-sdk-root.sh",)
_GENERIC_ANDROID = ("scripts/android-sdk-root.sh", "scripts/build-native-for-arch.sh")

_TARGET_LIST = (
    _target(
        "daemon",
        ("scripts/build-daemon.sh",),
        (
            "scripts/build-daemon.sh",
            "scripts/build-daemon-standalone.sh",
            "scripts/android-sdk-root.sh",
            "daemon/settings.gradle",
            "daemon/build.gradle",
            "daemon/app/build.gradle",
            "daemon/app/src/main/AndroidManifest.xml",
            "daemon/app/src/main/java/**/*.java",
            "daemon/app/src/main/aidl/**/*.aidl",
            "daemon/app/src/main/res/**/*",
        ),
        (OutputSpec("daemon/app/build/outputs/apk/debug/app-debug.apk", 0o644),),
        "daemon/app/build",
        cpu_slots=2,
        tools=("jdk", "gradle", "android"),
        environment=(*_ANDROID_ENV, "XENOID_STANDALONE_APK"),
    ),
    _target(
        "keymint",
        ("scripts/build-keymint.sh", "--build"),
        (
            "scripts/build-keymint.sh",
            "scripts/fetch-keymint-deps.sh",
            "scripts/android-sdk-root.sh",
            "native/xenoid-keymint/CMakeLists.txt",
            "native/xenoid-keymint/src/**/*",
            "native/xenoid-keymint/rust/Cargo.toml",
            "native/xenoid-keymint/rust/Cargo.lock",
            "native/xenoid-keymint/rust/build.sh",
            "native/xenoid-keymint/rust/teesim-km/**/*",
            "native/xenoid-keymint/rust/patches/**/*",
            "native/xenoid-keymint/android.hardware.security.keymint.IKeyMintDevice.xml",
            "native/xenoid-keymint/.deps/keymint/**/*",
            "native/xenoid-keymint/.deps/interfaces/**/*",
            "native/xenoid-keymint/.deps/frameworks-native/**/*",
            "native/xenoid-keymint/.deps/boringssl/**/*",
        ),
        (
            _out("native/xenoid-keymint/xenoid-keymint"),
            OutputSpec("native/xenoid-keymint/android.hardware.security.keymint.IKeyMintDevice.xml", 0o644),
        ),
        "native/xenoid-keymint",
        cpu_slots=2,
        tools=("android", "rust", "cmake"),
        force_command=("scripts/build-keymint.sh", "--build"),
    ),
    _target(
        "input",
        ("scripts/build-native-input.sh",),
        (*_COMMON_ANDROID, "scripts/build-native-input.sh", "native/xenoid-input/xenoid_input.c", "native/xenoid-input/Makefile", "native/xenoid-input/README.md"),
        (_out("native/xenoid-input/xenoid-input"),),
        "native/xenoid-input",
    ),
    _target(
        "hide",
        ("scripts/build-native-hide.sh",),
        (*_COMMON_ANDROID, "scripts/build-native-hide.sh", "native/xenoid-hide/xenoid_hide.c", "native/xenoid-hide/Makefile"),
        (_out("native/xenoid-hide/xenoid-hide"),),
        "native/xenoid-hide",
    ),
    _target(
        "profile",
        ("scripts/build-native-profile.sh",),
        (*_COMMON_ANDROID, "scripts/build-native-profile.sh", "native/xenoid-profile/xenoid_profile.c", "native/xenoid-profile/Makefile"),
        (_out("native/xenoid-profile/xenoid-profile"),),
        "native/xenoid-profile",
    ),
    _target(
        "rootd",
        ("scripts/build-native-rootd.sh",),
        (*_COMMON_ANDROID, "scripts/build-native-rootd.sh", "native/xenoid-rootd/xenoid_rootd.c"),
        (
            _out("native/xenoid-rootd/xenoid-rootd-arm64"),
            _out("native/xenoid-rootd/xenoid-rootd-x86_64", machine="X86_64"),
        ),
        "native/xenoid-rootd",
    ),
    _target(
        "netctl",
        ("scripts/build-native-netctl.sh",),
        (*_GENERIC_ANDROID, "scripts/build-native-netctl.sh", "native/xenoid-netctl/xenoid_netctl.c", "native/xenoid-netctl/README.md"),
        (_out("native/xenoid-netctl/xenoid-netctl"),),
        "native/xenoid-netctl",
    ),
    _target(
        "overlay",
        ("scripts/build-native-overlay.sh", "arm64"),
        (
            *_COMMON_ANDROID,
            "scripts/build-native-overlay.sh",
            "native/xenoid-hide/xenoid_overlay.c",
            "native/xenoid-hide/xenoid_power_supply.c",
            "native/xenoid-hide/xenoid_power_supply.h",
        ),
        (_out("native/xenoid-hide/xenoid-overlay"),),
        "native/xenoid-hide",
    ),
    _target(
        "zygote",
        ("scripts/build-native-zygote.sh", "arm64"),
        (*_COMMON_ANDROID, "scripts/build-native-zygote.sh", "native/xenoid-zygote/xenoid_zygote.c", "native/xenoid-zygote/xenoid_drm.c", "native/xenoid-zygote/xenoid_drm_sret.S", "native/xenoid-shim/xenoid_shim.c"),
        (_out("native/xenoid-zygote/libxenoid_zygote.so"),),
        "native/xenoid-zygote",
    ),
    _target(
        "svcman",
        ("scripts/build-native-svcman.sh", "arm64"),
        (*_COMMON_ANDROID, "scripts/build-native-svcman.sh", "native/xenoid-svcman/xenoid_svcman.c"),
        (_out("native/xenoid-svcman/libxenoid_svcman.so"),),
        "native/xenoid-svcman",
    ),
    _target(
        "sensorsHal",
        ("scripts/build-sensors-hal.sh", "arm64"),
        (
            *_COMMON_ANDROID,
            "scripts/build-sensors-hal.sh",
            "scripts/sanitize-aidl-output.py",
            "native/xenoid-sensorshal/xenoid_sensors_hal.cpp",
            "native/xenoid-sensorshal/sensor_catalog.cpp",
            "native/xenoid-sensorshal/sensor_catalog.h",
            "native/xenoid-sensorshal/aidl/**/*.aidl",
            "native/xenoid-sensorshal/android.hardware.sensors.ISensors.xml",
            "native/xenoid-sensorshal/libbinder_ndk.so",
        ),
        (
            _out("native/xenoid-sensorshal/xenoid-sensorshal"),
            OutputSpec("native/xenoid-sensorshal/android.hardware.sensors.ISensors.xml", 0o644),
        ),
        "native/xenoid-sensorshal",
        cpu_slots=2,
    ),
    _target(
        "gralloc",
        ("scripts/build-gralloc.sh", "arm64"),
        (
            *_COMMON_ANDROID,
            "scripts/build-gralloc.sh",
            "native/xenoid-gralloc/gralloc.cpp",
            "native/xenoid-gralloc/mapper.cpp",
            "native/xenoid-gralloc/framebuffer.cpp",
            "native/xenoid-gralloc/gr.h",
            "native/xenoid-gralloc/gralloc_priv.h",
            "native/xenoid-gralloc/android_compat.h",
            "native/xenoid-gralloc/libcutils.so",
        ),
        (_out("native/xenoid-gralloc/gralloc.redroid.so"),),
        "native/xenoid-gralloc",
        cpu_slots=2,
    ),
    _target(
        "hwcomposer",
        ("scripts/build-hwcomposer.sh", "arm64"),
        (*_COMMON_ANDROID, "scripts/build-hwcomposer.sh", "native/xenoid-hwcomposer/hwcomposer_wrapper.c", "native/xenoid-gralloc/android_compat.h"),
        (_out("native/xenoid-hwcomposer/hwcomposer.raven.so"),),
        "native/xenoid-hwcomposer",
    ),
    _target(
        "cameraProvider",
        ("scripts/build-camera-hal.sh", "arm64"),
        (
            *_COMMON_ANDROID,
            "scripts/build-camera-hal.sh",
            "scripts/sanitize-aidl-output.py",
            "native/xenoid-camerahal/*.cpp",
            "native/xenoid-camerahal/*.h",
            "native/xenoid-camerahal/aidl/**/*.aidl",
            "native/xenoid-camerahal/framework-min.aidl",
            "native/xenoid-camerahal/android.hardware.camera.provider.ICameraProvider.xml",
            "native/xenoid-camerahal/media_profiles_V1_0.xml",
            "native/xenoid-camerahal/libbinder_ndk.so",
            "native/xenoid-camerahal/libcamera_metadata.so",
            "native/xenoid-camerahal/libcamera_device*.so",
            "native/xenoid-camerahal/libcamera_provider*.so",
            "native/xenoid-camerahal/libcamera_common*.so",
        ),
        (
            _out("native/xenoid-camerahal/android.hardware.camera.provider-service-aidl"),
            OutputSpec("native/xenoid-camerahal/android.hardware.camera.provider.ICameraProvider.xml", 0o644),
            OutputSpec("native/xenoid-camerahal/media_profiles_V1_0.xml", 0o644),
        ),
        "native/xenoid-camerahal",
        cpu_slots=2,
        tools=("android", "docker"),
        environment=(*_ANDROID_ENV, *_DOCKER_ENV, "XENOID_BASE_IMAGE"),
    ),
    _target(
        "ril",
        ("scripts/build-ril.sh", "arm64"),
        (
            *_COMMON_ANDROID,
            "scripts/build-ril.sh",
            "native/xenoid-ril/xenoid_ril.c",
            "native/xenoid-ril/include/**/*.h",
            "native/xenoid-ril/android.hardware.radio.IRadio.xml",
        ),
        (
            _out("native/xenoid-ril/libxenoid-ril.so"),
            _out("native/xenoid-ril/xenoid-ril-profile-test"),
            OutputSpec("native/xenoid-ril/android.hardware.radio.IRadio.xml", 0o644),
        ),
        "native/xenoid-ril",
    ),
    _target(
        "radioConfig",
        ("scripts/build-radio-config.sh", "arm64"),
        (
            *_COMMON_ANDROID,
            "scripts/build-radio-config.sh",
            "scripts/sanitize-aidl-output.py",
            "native/xenoid-radio-config/radio_config.cpp",
            "native/xenoid-radio-config/aidl/**/*.aidl",
            "native/xenoid-radio-config/framework-min.aidl",
            "native/xenoid-radio-config/android.hardware.radio.config.IRadioConfig.xml",
            "native/xenoid-radio-config/libbinder_ndk.so",
        ),
        (
            _out("native/xenoid-radio-config/android.hardware.radio.config-service.xenoid"),
            OutputSpec("native/xenoid-radio-config/android.hardware.radio.config.IRadioConfig.xml", 0o644),
        ),
        "native/xenoid-radio-config",
        cpu_slots=2,
        tools=("android", "docker"),
        environment=(*_ANDROID_ENV, *_DOCKER_ENV, "XENOID_BASE_IMAGE"),
    ),
    _target(
        "shimArm64",
        ("scripts/build-native-shim.sh", "arm64", "prop"),
        (*_COMMON_ANDROID, "scripts/build-native-shim.sh", "native/xenoid-shim/xenoid_shim.c"),
        (_out("native/xenoid-shim/libxenoid_shim-arm64.so"),),
        "native/xenoid-shim",
    ),
    _target(
        "pivot",
        ("scripts/build-native-for-arch.sh", "xenoid-pivot", "native/xenoid-pivot/xenoid_pivot.c", "native/xenoid-pivot/xenoid-pivot", "arm64", "static"),
        (*_GENERIC_ANDROID, "native/xenoid-pivot/xenoid_pivot.c"),
        (_out("native/xenoid-pivot/xenoid-pivot", elf_type="EXEC", interpreter=False),),
        "native/xenoid-pivot",
    ),
    _target(
        "propArea",
        ("scripts/build-native-for-arch.sh", "xenoid-prop-area", "native/xenoid-hide/xenoid_prop_area.c", "native/xenoid-hide/xenoid-prop-area", "arm64"),
        (*_GENERIC_ANDROID, "native/xenoid-hide/xenoid_prop_area.c"),
        (_out("native/xenoid-hide/xenoid-prop-area"),),
        "native/xenoid-hide",
    ),
    _target(
        "ssaid",
        ("scripts/build-native-for-arch.sh", "xenoid-ssaid", "native/xenoid-hide/xenoid_ssaid.c", "native/xenoid-hide/xenoid-ssaid", "arm64"),
        (*_GENERIC_ANDROID, "native/xenoid-hide/xenoid_ssaid.c"),
        (_out("native/xenoid-hide/xenoid-ssaid"),),
        "native/xenoid-hide",
    ),
    _target(
        "proxySandbox",
        ("scripts/build-proxy-sandbox.sh",),
        ("scripts/build-proxy-sandbox.sh", "native/xenoid-proxy-sandbox/xenoid_proxy_sandbox.c", "native/xenoid-proxy-sandbox/Makefile"),
        (_out("native/xenoid-proxy-sandbox/xenoid-proxy-sandbox", mode=0o555, elf_type="DYN", interpreter=False),),
        "native/xenoid-proxy-sandbox",
        tools=("proxyCompiler", "docker"),
        environment=(*_DOCKER_ENV, "XENOID_PROXY_CC"),
    ),
)

ALL_TARGETS = tuple(target.name for target in _TARGET_LIST)
TARGETS: Mapping[str, BuildTarget] = MappingProxyType({target.name: target for target in _TARGET_LIST})
CONSUMER_TARGETS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "runtimeContext": (
            "daemon",
            "keymint",
            "input",
            "hide",
            "profile",
            "netctl",
            "overlay",
            "propArea",
            "pivot",
            "zygote",
            "svcman",
            "sensorsHal",
            "gralloc",
            "hwcomposer",
            "cameraProvider",
            "ril",
            "radioConfig",
        ),
        "liveDeploy": ("daemon", "rootd", "shimArm64", "ssaid", "proxySandbox"),
        "release": ALL_TARGETS,
    }
)


@dataclasses.dataclass(slots=True)
class _RunResult:
    returncode: int
    stdout_tail: bytes
    stderr_tail: bytes


class _TailBuffer:
    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._data = bytearray()
        self._lock = threading.Lock()

    def append(self, data: bytes) -> None:
        if not data:
            return
        with self._lock:
            if len(data) >= self._limit:
                self._data[:] = data[-self._limit :]
                return
            excess = len(self._data) + len(data) - self._limit
            if excess > 0:
                del self._data[:excess]
            self._data.extend(data)

    def bytes(self) -> bytes:
        with self._lock:
            return bytes(self._data)


class _WeightedSlots:
    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self._available = capacity
        self._condition = threading.Condition()

    @contextlib.contextmanager
    def acquire(self, requested: int) -> Iterator[int]:
        count = min(max(1, requested), self.capacity)
        with self._condition:
            while self._available < count:
                self._condition.wait()
            self._available -= count
        try:
            yield count
        finally:
            with self._condition:
                self._available += count
                self._condition.notify_all()


class ArtifactBuilder:
    def __init__(
        self,
        project_root: str | os.PathLike[str],
        environment: Mapping[str, str] | None = None,
        *,
        catalog: Mapping[str, BuildTarget] | None = None,
        runner: Callable[..., Any] | None = None,
        max_workers: int = 4,
        cpu_slots: int | None = None,
    ) -> None:
        root = Path(project_root).expanduser()
        try:
            root = root.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError("artifact_project_root_invalid") from exc
        root_stat = root.stat()
        if not stat.S_ISDIR(root_stat.st_mode):
            raise ValueError("artifact_project_root_invalid")
        self.project_root = root
        self.catalog = MappingProxyType(dict(TARGETS if catalog is None else catalog))
        self._validate_catalog()
        supplied = {} if environment is None else {str(key): str(value) for key, value in environment.items()}
        declared_environment = set(_BASE_ENV)
        for target in self.catalog.values():
            declared_environment.update(target.environment)
        for key in supplied:
            if key in _BUILD_OVERRIDE_NAMES or key.startswith("ORG_GRADLE_PROJECT_"):
                if key not in declared_environment:
                    raise ValueError("artifact_environment_override_undeclared")
        self._requested_environment = dict(os.environ)
        self._requested_environment.update(supplied)
        self._runner = runner
        self.max_workers = min(4, max(1, int(max_workers)))
        default_slots = max(1, (os.cpu_count() or 1) - 2)
        self.cpu_slots = max(1, int(default_slots if cpu_slots is None else cpu_slots))
        self._slots = _WeightedSlots(self.cpu_slots)
        self._cache_root = self.project_root / ".xenoid" / "cache" / "artifacts"
        self._record_root = self._cache_root / "v1"
        self._object_root = self._cache_root / "objects" / "sha256"
        self._lock_root = self.project_root / ".xenoid" / "locks" / "artifacts"
        self._initialize_private_trees()
        self._deadline = time.monotonic() + 3600.0
        self._cancelled: threading.Event | Callable[[], bool] | None = None
        self._internal_cancel = threading.Event()
        self._file_digest_cache: dict[tuple[Any, ...], str] = {}
        self._version_digest_cache: dict[tuple[Any, ...], str] = {}
        self._tool_identity_cache: dict[
            tuple[Any, ...],
            Mapping[str, Any],
        ] = {}

    def ensure(
        self,
        targets: Collection[str],
        force: bool = False,
        *,
        deadline: float | None = None,
        cancelled: threading.Event | Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        self._deadline = deadline if deadline is not None else started + 3600.0
        self._cancelled = cancelled
        self._internal_cancel = threading.Event()
        try:
            ordered = self._expand_targets(targets)
        except ArtifactError as exc:
            requested = [targets] if isinstance(targets, str) else list(targets)
            return {
                "ok": False,
                "schema": RESULT_SCHEMA,
                "targets": {
                    str(name): {"status": "failed", "durationMs": 0, "code": exc.code}
                    for name in requested
                },
                "status": "failed",
                "manifestSha256": None,
                "durationMs": _duration_ms(started),
            }

        pending = set(ordered)
        results: dict[str, dict[str, Any]] = {}
        running: dict[concurrent.futures.Future[dict[str, Any]], str] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="xenoid-artifact") as executor:
            while pending or running:
                cancelled_now = self._cancel_requested()
                if cancelled_now and pending:
                    for name in pending:
                        results[name] = {
                            "status": "failed",
                            "durationMs": 0,
                            "code": "artifact_build_cancelled",
                        }
                    pending.clear()
                changed = True
                while changed:
                    changed = False
                    for name in ordered:
                        if name not in pending:
                            continue
                        dependencies = self.catalog[name].dependencies
                        failed_dependency = next(
                            (
                                dependency
                                for dependency in dependencies
                                if dependency in results and results[dependency]["status"] in ("failed", "blocked")
                            ),
                            None,
                        )
                        if failed_dependency is not None:
                            pending.remove(name)
                            results[name] = {
                                "status": "blocked",
                                "durationMs": 0,
                                "code": "artifact_dependency_failed",
                                "dependency": failed_dependency,
                            }
                            changed = True
                ready = [
                    name
                    for name in ordered
                    if name in pending and all(dependency in results and results[dependency]["status"] in ("reused", "built") for dependency in self.catalog[name].dependencies)
                ]
                while ready and len(running) < self.max_workers:
                    name = ready.pop(0)
                    pending.remove(name)
                    future = executor.submit(self._ensure_target, self.catalog[name], bool(force))
                    running[future] = name
                if not running:
                    if pending:
                        for name in ordered:
                            if name in pending:
                                results[name] = {
                                    "status": "blocked",
                                    "durationMs": 0,
                                    "code": "artifact_dependency_failed",
                                }
                        pending.clear()
                    break
                try:
                    done, _ = concurrent.futures.wait(
                        running,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                except BaseException:
                    self._internal_cancel.set()
                    for future in running:
                        future.cancel()
                    concurrent.futures.wait(running)
                    raise
                for future in done:
                    name = running.pop(future)
                    try:
                        results[name] = future.result()
                    except Exception:
                        results[name] = {
                            "status": "failed",
                            "durationMs": 0,
                            "code": "artifact_internal_error",
                        }

        tail_budget = _MAX_FAILED_TAIL_BYTES
        public_results: dict[str, dict[str, Any]] = {}
        for name in ordered:
            result = dict(results[name])
            raw_tail = result.pop("_tail", None)
            if raw_tail and result["status"] == "failed" and tail_budget > 0:
                safe_tail = self._sanitize_tail(raw_tail)
                encoded = safe_tail.encode("utf-8")
                if len(encoded) > tail_budget:
                    encoded = encoded[-tail_budget:]
                    safe_tail = encoded.decode("utf-8", "replace")
                result["tail"] = safe_tail
                tail_budget -= len(encoded)
            public_results[name] = result
        ok = all(result["status"] in ("reused", "built") for result in public_results.values())
        manifest: str | None = None
        if ok:
            try:
                manifest = self.snapshot(ordered).manifest_sha256
            except ArtifactError:
                ok = False
                for name in ordered:
                    if public_results[name]["status"] in ("reused", "built"):
                        public_results[name] = {
                            "status": "failed",
                            "durationMs": public_results[name]["durationMs"],
                            "code": "artifact_snapshot_invalid",
                        }
        return {
            "ok": ok,
            "schema": RESULT_SCHEMA,
            "targets": public_results,
            "status": "passed" if ok else "failed",
            "manifestSha256": manifest,
            "durationMs": _duration_ms(started),
        }

    def snapshot(self, targets_or_consumer: Collection[str] | str) -> ArtifactSnapshot:
        ordered = self._expand_targets(targets_or_consumer)
        records: list[ArtifactRecord] = []
        with self._manifest_lock():
            for name in ordered:
                record = self._load_record(name, validate_objects=True)
                if record is None:
                    raise ArtifactError("artifact_record_unavailable")
                records.append(record)
        digest = _manifest_digest(records)
        return ArtifactSnapshot(tuple(ordered), tuple(records), digest)

    def stage(self, snapshot: ArtifactSnapshot, destination: str | os.PathLike[str]) -> dict[str, Any]:
        if not isinstance(snapshot, ArtifactSnapshot):
            raise ArtifactError("artifact_snapshot_invalid")
        if snapshot.manifest_sha256 != _manifest_digest(snapshot.records):
            raise ArtifactError("artifact_snapshot_invalid")
        if tuple(record.target for record in snapshot.records) != snapshot.targets:
            raise ArtifactError("artifact_snapshot_invalid")
        destination_path = Path(destination).expanduser()
        if not destination_path.is_absolute():
            destination_path = self.project_root / destination_path
        self._ensure_stage_root(destination_path)
        staged: list[dict[str, Any]] = []
        for record in snapshot.records:
            current = self._load_record(record.target, validate_objects=True)
            if current != record:
                raise ArtifactError("artifact_snapshot_changed")
            target = self.catalog.get(record.target)
            if target is None:
                raise ArtifactError("artifact_snapshot_invalid")
            specs = {spec.path: spec for spec in target.outputs}
            for output in record.outputs:
                spec = specs.get(output.path)
                if spec is None:
                    raise ArtifactError("artifact_snapshot_invalid")
                target_path = destination_path / output.path
                self._materialize_output(output, spec, target_path, destination_path)
                staged.append(output.as_dict() | {"target": record.target})
        _fsync_directory(destination_path)
        return {
            "ok": True,
            "schema": SNAPSHOT_SCHEMA,
            "manifestSha256": snapshot.manifest_sha256,
            "outputs": staged,
        }

    def _validate_catalog(self) -> None:
        if not self.catalog:
            raise ValueError("artifact_catalog_empty")
        output_owners: dict[str, str] = {}
        for name, target in self.catalog.items():
            if name != target.name:
                raise ValueError("artifact_catalog_name_mismatch")
            for dependency in target.dependencies:
                if dependency not in self.catalog:
                    raise ValueError("artifact_dependency_unknown")
                if dependency == name:
                    raise ValueError("artifact_dependency_cycle")
            for output in target.outputs:
                owner = output_owners.setdefault(output.path, name)
                if owner != name:
                    raise ValueError("artifact_output_owner_duplicate")
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(name: str) -> None:
            if name in visiting:
                raise ValueError("artifact_dependency_cycle")
            if name in visited:
                return
            visiting.add(name)
            for dependency in self.catalog[name].dependencies:
                visit(dependency)
            visiting.remove(name)
            visited.add(name)

        for name in self.catalog:
            visit(name)

    def _expand_targets(self, requested: Collection[str] | str) -> list[str]:
        names = [requested] if isinstance(requested, str) else list(requested)
        if not names:
            raise ArtifactError("artifact_targets_empty")
        expanded_requests: list[str] = []
        for name in names:
            if not isinstance(name, str):
                raise ArtifactError("artifact_target_unknown")
            if name in CONSUMER_TARGETS:
                expanded_requests.extend(CONSUMER_TARGETS[name])
            elif name in self.catalog:
                expanded_requests.append(name)
            else:
                raise ArtifactError("artifact_target_unknown")
        ordered: list[str] = []
        seen: set[str] = set()

        def add(name: str) -> None:
            if name in seen:
                return
            if name not in self.catalog:
                raise ArtifactError("artifact_target_unknown")
            for dependency in self.catalog[name].dependencies:
                add(dependency)
            seen.add(name)
            ordered.append(name)

        for name in expanded_requests:
            add(name)
        return ordered

    def _ensure_target(self, target: BuildTarget, force: bool) -> dict[str, Any]:
        started = time.monotonic()
        with self._slots.acquire(target.cpu_slots) as allocation:
            try:
                input_sha256, tool_sha256 = self._identity(target)
            except ArtifactError as exc:
                return {"status": "failed", "durationMs": _duration_ms(started), "code": exc.code}
            try:
                with self._output_lock(target):
                    # Another process may have published while this caller waited.
                    current_input, current_tool = self._identity(target)
                    if (current_input, current_tool) != (input_sha256, tool_sha256):
                        return {
                            "status": "failed",
                            "durationMs": _duration_ms(started),
                            "code": "artifact_input_changed_before_build",
                        }
                    prior = self._load_record(target.name, validate_objects=True)
                    if not force and prior is not None and self._record_matches(prior, input_sha256, tool_sha256):
                        self._restore_directory(target.output_directory)
                        return {
                            "status": "reused",
                            "durationMs": _duration_ms(started),
                            "inputSha256": input_sha256,
                            "toolSha256": tool_sha256,
                        }
                    rollback_records = self._directory_records(target.output_directory)
                    command = target.force_command if force and target.force_command is not None else target.command
                    environment = self._execution_environment(target, allocation)
                    run_result = self._run(command, environment, target)
                    combined_tail = _combine_tails(run_result.stdout_tail, run_result.stderr_tail)
                    if run_result.returncode != 0:
                        rollback_ok = self._restore_records(rollback_records)
                        return {
                            "status": "failed",
                            "durationMs": _duration_ms(started),
                            "code": (
                                "artifact_build_timeout"
                                if run_result.returncode == 124
                                else "artifact_build_cancelled"
                                if run_result.returncode == 130
                                else "artifact_build_failed"
                            ) if rollback_ok else "artifact_rollback_failed",
                            "returncode": run_result.returncode,
                            "_tail": combined_tail,
                        }
                    try:
                        outputs = self._read_public_outputs(target)
                    except ArtifactError as exc:
                        rollback_ok = self._restore_records(rollback_records)
                        return {
                            "status": "failed",
                            "durationMs": _duration_ms(started),
                            "code": exc.code if rollback_ok else "artifact_rollback_failed",
                            "returncode": run_result.returncode,
                            "_tail": combined_tail,
                        }
                    post_input, post_tool = self._identity(target)
                    if (post_input, post_tool) != (input_sha256, tool_sha256):
                        rollback_ok = self._restore_records(rollback_records)
                        return {
                            "status": "failed",
                            "durationMs": _duration_ms(started),
                            "code": "artifact_input_changed_during_build" if rollback_ok else "artifact_rollback_failed",
                            "returncode": run_result.returncode,
                            "_tail": combined_tail,
                        }
                    if prior is not None and self._record_matches(prior, input_sha256, tool_sha256):
                        if prior.outputs != outputs:
                            rollback_ok = self._restore_records(rollback_records)
                            return {
                                "status": "failed",
                                "durationMs": _duration_ms(started),
                                "code": "artifact_nondeterministic" if rollback_ok else "artifact_rollback_failed",
                                "returncode": run_result.returncode,
                                "_tail": combined_tail,
                            }
                    try:
                        record = ArtifactRecord(
                            target=target.name,
                            input_sha256=input_sha256,
                            tool_sha256=tool_sha256,
                            outputs=outputs,
                            completed_at=_datetime.datetime.now(_datetime.timezone.utc).isoformat(timespec="seconds"),
                        )
                        with self._manifest_lock():
                            concurrent_record = self._load_record(target.name, validate_objects=True)
                            if concurrent_record is not None and self._record_matches(concurrent_record, input_sha256, tool_sha256):
                                if concurrent_record.outputs != outputs:
                                    raise ArtifactError("artifact_nondeterministic")
                                record = concurrent_record
                            else:
                                for output in outputs:
                                    self._import_object(output, self.project_root / output.path)
                                self._publish_record(record)
                        self._restore_directory(target.output_directory)
                    except ArtifactError as exc:
                        rollback_ok = self._restore_records(rollback_records)
                        return {
                            "status": "failed",
                            "durationMs": _duration_ms(started),
                            "code": exc.code if rollback_ok else "artifact_rollback_failed",
                            "returncode": run_result.returncode,
                            "_tail": combined_tail,
                        }
                    return {
                        "status": "built",
                        "durationMs": _duration_ms(started),
                        "inputSha256": input_sha256,
                        "toolSha256": tool_sha256,
                    }
            except ArtifactError as exc:
                return {"status": "failed", "durationMs": _duration_ms(started), "code": exc.code}

    def _identity(self, target: BuildTarget) -> tuple[str, str]:
        source_entries: list[dict[str, Any]] = []
        for relative_path in self._expand_source_closure(target.sources):
            path = self.project_root / relative_path
            try:
                info = path.lstat()
            except FileNotFoundError:
                source_entries.append({"path": relative_path, "missing": True})
                continue
            if stat.S_ISLNK(info.st_mode):
                link_target = os.readlink(path)
                if not link_target or len(link_target.encode("utf-8", "surrogateescape")) > 4096:
                    raise ArtifactError("artifact_source_unsafe")
                resolved = (path.parent / link_target).resolve(strict=False)
                try:
                    resolved.relative_to(self.project_root.resolve())
                except ValueError as exc:
                    raise ArtifactError("artifact_source_unsafe") from exc
                link_entry: dict[str, Any] = {
                    "path": relative_path,
                    "type": "symlink",
                    "target": link_target,
                }
                try:
                    target_info = resolved.lstat()
                except FileNotFoundError:
                    link_entry["targetMissing"] = True
                else:
                    if not stat.S_ISREG(target_info.st_mode):
                        raise ArtifactError("artifact_source_unsafe")
                    link_entry.update(
                        {
                            "targetMode": stat.S_IMODE(target_info.st_mode),
                            "targetSize": target_info.st_size,
                            "targetSha256": self._cached_file_digest(resolved),
                        }
                    )
                source_entries.append(link_entry)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ArtifactError("artifact_source_unsafe")
            source_entries.append(
                {
                    "path": relative_path,
                    "mode": stat.S_IMODE(info.st_mode),
                    "size": info.st_size,
                    "sha256": self._cached_file_digest(path),
                }
            )
        environment = {
            name: self._requested_environment.get(name, "")
            for name in sorted(set(_BASE_ENV).union(target.environment))
        }
        input_payload = {
            "schema": 1,
            "target": target.name,
            "command": list(target.command),
            "forceCommand": None if target.force_command is None else list(target.force_command),
            "sources": source_entries,
            "environment": environment,
            "outputs": [
                {
                    "path": output.path,
                    "mode": output.mode,
                    "elfMachine": _normalize_elf_machine(output.elf_machine),
                    "elfType": _normalize_elf_type(output.elf_type),
                    "elfClass": output.elf_class,
                    "interpreter": output.interpreter,
                }
                for output in target.outputs
            ],
            "outputDirectory": target.output_directory,
        }
        tool_payload = {
            "schema": 1,
            "target": target.name,
            "builderImplementationSha256": self._cached_file_digest(Path(__file__)),
            "tools": [self._tool_identity(tool) for tool in target.tools],
        }
        return _canonical_digest(input_payload), _canonical_digest(tool_payload)

    def _expand_source_closure(self, patterns: Sequence[str]) -> list[str]:
        expanded: set[str] = set()
        for pattern in patterns:
            absolute_pattern = str(self.project_root / pattern)
            matches = _glob.glob(absolute_pattern, recursive=True)
            file_matches = []
            for match in matches:
                path = Path(match)
                try:
                    relative = path.relative_to(self.project_root).as_posix()
                except ValueError as exc:
                    raise ArtifactError("artifact_source_path_invalid") from exc
                if path.is_dir():
                    continue
                file_matches.append(relative)
            if file_matches:
                expanded.update(file_matches)
            elif not _has_glob(pattern):
                expanded.add(pattern)
            else:
                expanded.add(f"{pattern}#missing")
        return sorted(expanded)

    @staticmethod
    def _file_fingerprint(path: Path) -> tuple[Any, ...]:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode):
            raise OSError(errno.EINVAL, "not regular")
        return (
            str(resolved),
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mode,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def _cached_file_digest(self, path: Path) -> str:
        fingerprint = self._file_fingerprint(path)
        cache = self._file_digest_cache
        digest = cache.get(fingerprint)
        if digest is None:
            digest = _hash_file(Path(fingerprint[0]))
            cache[fingerprint] = digest
        return digest


    def _tool_identity(self, tool: str) -> Mapping[str, Any]:
        candidates = self._tool_candidates(tool)
        prepared: list[
            tuple[
                str,
                Path | None,
                tuple[str, ...] | None,
                tuple[Any, ...] | None,
            ]
        ] = []
        signature: list[tuple[Any, ...]] = []
        for label, candidate, version_args in candidates:
            if candidate is None:
                prepared.append((label, None, version_args, None))
                signature.append((label, None, version_args))
                continue
            try:
                fingerprint = self._file_fingerprint(candidate)
            except OSError:
                prepared.append((label, None, version_args, None))
                signature.append((label, None, version_args))
                continue
            prepared.append(
                (label, candidate, version_args, fingerprint)
            )
            signature.append((label, fingerprint, version_args))
        cache_key = (tool, tuple(signature))
        cached = self._tool_identity_cache.get(cache_key)
        if cached is not None:
            return cached
        entries: list[dict[str, Any]] = []
        for label, candidate, version_args, fingerprint in prepared:
            if candidate is None or fingerprint is None:
                entries.append({"name": label, "missing": True})
                continue
            entry: dict[str, Any] = {
                "name": label,
                "size": fingerprint[3],
                "sha256": self._cached_file_digest(candidate),
            }
            if version_args is not None:
                entry["versionSha256"] = self._version_digest(
                    (str(candidate), *version_args)
                )
            entries.append(entry)
        result = {"name": tool, "entries": entries}
        self._tool_identity_cache[cache_key] = result
        return result

    def _tool_candidates(self, tool: str) -> list[tuple[str, Path | None, tuple[str, ...] | None]]:
        path_value = self._requested_environment.get("PATH", os.defpath)

        def executable(name: str) -> Path | None:
            found = shutil.which(name, path=path_value)
            return None if found is None else Path(found)

        if tool == "jdk":
            java_home = self._requested_environment.get("JAVA_HOME")
            java = Path(java_home) / "bin" / "java" if java_home else executable("java")
            release = Path(java_home) / "release" if java_home else None
            return [("java", java, ("-version",)), ("javaRelease", release, None)]
        if tool == "gradle":
            wrapper = self.project_root / "daemon" / "gradlew"
            gradle = wrapper if wrapper.is_file() else executable("gradle")
            return [("gradle", gradle, ("--version",))]
        if tool == "rust":
            return [
                ("rustup", executable("rustup"), ("--version",)),
                ("cargo", executable("cargo"), ("--version",)),
                ("rustc", executable("rustc"), ("--version",)),
            ]
        if tool == "cmake":
            return [("cmake", executable("cmake"), ("--version",)), ("ninja", executable("ninja"), ("--version",))]
        if tool == "docker":
            return [("docker", executable("docker"), ("version", "--format", "{{json .}}")), ("colima", executable("colima"), ("version",))]
        if tool == "proxyCompiler":
            explicit = self._requested_environment.get("XENOID_PROXY_CC")
            explicit_path = executable(explicit) if explicit else None
            return [
                ("explicit", explicit_path, ("--version",) if explicit_path else None),
                ("aarch64-linux-gnu-gcc", executable("aarch64-linux-gnu-gcc"), ("--version",)),
                ("zig", executable("zig"), ("version",)),
                ("hostCc", executable("cc"), ("--version",)),
            ]
        if tool == "android":
            return self._android_tool_candidates()
        if "/" in tool:
            try:
                _validate_relative_name(tool, "artifact_tool_path_invalid")
            except ValueError as exc:
                raise ArtifactError("artifact_tool_path_invalid") from exc
            return [(tool, self.project_root / tool, None)]
        return [(tool, executable(tool), ("--version",))]

    def _android_tool_candidates(self) -> list[tuple[str, Path | None, tuple[str, ...] | None]]:
        sdk_value = self._requested_environment.get("ANDROID_SDK_ROOT") or self._requested_environment.get("ANDROID_HOME")
        if sdk_value:
            sdk = Path(sdk_value).expanduser()
        else:
            sdk = Path(self._requested_environment.get("HOME", str(Path.home()))) / "Library" / "Android" / "sdk"
        candidates: list[tuple[str, Path | None, tuple[str, ...] | None]] = []
        ndk_files = sorted(sdk.glob("ndk/*/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android*-clang"))
        candidates.append(("ndkClang", ndk_files[-1] if ndk_files else None, ("--version",)))
        aidl_files = sorted(sdk.glob("build-tools/*/aidl"))
        candidates.append(("aidl", aidl_files[-1] if aidl_files else None, ("--version",)))
        ndk_properties = sorted(sdk.glob("ndk/*/source.properties"))
        candidates.append(("ndkProperties", ndk_properties[-1] if ndk_properties else None, None))
        strip_files = sorted(
            sdk.glob(
                "ndk/*/toolchains/llvm/prebuilt/*/bin/llvm-strip"
            )
        )
        candidates.append(
            (
                "llvmStrip",
                strip_files[-1] if strip_files else None,
                ("--version",),
            )
        )
        return candidates

    def _version_digest(self, command: tuple[str, ...]) -> str:
        environment = {
            "LC_ALL": "C",
            "TZ": "UTC",
            "PATH": self._requested_environment.get("PATH", os.defpath),
            "HOME": self._requested_environment.get("HOME", str(Path.home())),
        }
        try:
            executable = self._file_fingerprint(Path(command[0]))
        except OSError:
            executable = (command[0], "missing")
        cache_key = (
            command,
            executable,
            tuple(sorted(environment.items())),
        )
        cached = self._version_digest_cache.get(cache_key)
        if cached is not None:
            return cached
        result = run_bounded(
            command,
            cwd=self.project_root,
            env=environment,
            deadline=min(self._deadline, time.monotonic() + 8.0),
            project_root=self.project_root,
            cancelled=self._cancel_requested,
        )
        if result.returncode is None:
            payload = (result.error_code or "unavailable").encode()
        else:
            payload = (
                (result.stdout_tail + "\n" + result.stderr_tail)[-16384:]
                + f"\nrc={result.returncode}"
            ).encode("utf-8", "replace")
        digest = hashlib.sha256(payload).hexdigest()
        self._version_digest_cache[cache_key] = digest
        return digest

    def _execution_environment(self, target: BuildTarget, allocation: int) -> dict[str, str]:
        names = set(_BASE_ENV).union(target.environment)
        environment = {name: self._requested_environment[name] for name in names if name in self._requested_environment}
        environment.update(
            {
                "LC_ALL": "C",
                "LANG": "C",
                "TZ": "UTC",
                "SOURCE_DATE_EPOCH": "0",
                "PYTHONHASHSEED": "0",
                "ZERO_AR_DATE": "1",
                "XENOID_FORCE_REBUILD": "1",
                "XENOID_BUILD_JOBS": str(allocation),
                "XENOID_ARTIFACT_JOBS": str(allocation),
                "CARGO_BUILD_JOBS": str(allocation),
                "MAKEFLAGS": f"-j{allocation}",
                "GRADLE_OPTS": f"-Dorg.gradle.daemon=false -Dorg.gradle.workers.max={allocation}",
                "ORG_GRADLE_PROJECT_org.gradle.workers.max": str(allocation),
            }
        )
        return environment

    def _run(self, command: tuple[str, ...], environment: Mapping[str, str], target: BuildTarget) -> _RunResult:
        executable = Path(command[0])
        if not executable.is_absolute() and "/" in command[0]:
            executable = self.project_root / executable
        actual_command = (str(executable), *command[1:])
        if self._runner is not None:
            callable_runner = self._runner if callable(self._runner) else getattr(self._runner, "run")
            try:
                result = callable_runner(actual_command, cwd=self.project_root, env=dict(environment), target=target)
            except Exception as exc:
                return _RunResult(127, b"", str(exc).encode("utf-8", "replace")[-_MAX_FAILED_TAIL_BYTES:])
            return _coerce_run_result(result)
        result = run_bounded(
            actual_command,
            cwd=self.project_root,
            env=environment,
            deadline=self._deadline,
            project_root=self.project_root,
            cancelled=self._cancel_requested,
        )
        return _RunResult(
            124
            if result.state == "timed_out"
            else 130
            if result.state == "cancelled"
            else result.returncode
            if result.returncode is not None
            else (0 if result.ok else 1),
            result.stdout_tail.encode("utf-8", "replace"),
            result.stderr_tail.encode("utf-8", "replace"),
        )

    def _sanitize_public_output(self, path: Path) -> None:
        try:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(path, flags)
            try:
                is_elf = os.read(descriptor, 4) == b"\x7fELF"
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise ArtifactError(
                "artifact_output_sanitization_failed"
            ) from exc
        if not is_elf:
            return
        strip_tool = next(
            (
                candidate
                for name, candidate, _version in
                self._android_tool_candidates()
                if name == "llvmStrip"
            ),
            None,
        )
        if strip_tool is None:
            raise ArtifactError(
                "artifact_output_sanitization_failed"
            )
        result = run_bounded(
            [
                str(strip_tool),
                "--strip-debug",
                "--remove-section=.comment",
                str(path),
            ],
            cwd=self.project_root,
            deadline=self._deadline,
            env={
                "LC_ALL": "C",
                "LANG": "C",
                "TZ": "UTC",
                "PATH": self._requested_environment.get(
                    "PATH",
                    os.defpath,
                ),
            },
            project_root=self.project_root,
            cancelled=self._cancel_requested,
        )
        if not result.ok:
            raise ArtifactError(
                "artifact_output_sanitization_failed"
            )

    def _read_public_outputs(self, target: BuildTarget) -> tuple[ArtifactOutput, ...]:
        outputs: list[ArtifactOutput] = []
        try:
            for spec in sorted(target.outputs, key=lambda value: value.path):
                path = self.project_root / spec.path
                self._sanitize_public_output(path)
                info = _secure_regular_stat(path, spec.mode, require_owner=True)
                digest = _hash_file(path)
                _validate_content(path, spec)
                outputs.append(ArtifactOutput(spec.path, spec.mode, info.st_size, digest))
        except ArtifactError as exc:
            raise ArtifactError("artifact_output_invalid") from exc
        return tuple(outputs)

    def _record_matches(self, record: ArtifactRecord, input_sha256: str, tool_sha256: str) -> bool:
        return record.input_sha256 == input_sha256 and record.tool_sha256 == tool_sha256

    def _load_record(self, name: str, *, validate_objects: bool) -> ArtifactRecord | None:
        target = self.catalog.get(name)
        if target is None:
            return None
        path = self._record_root / f"{name}.json"
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_size > _MAX_RECORD_BYTES
        ):
            return None
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    return None
                raw = _read_fd_bounded(fd, _MAX_RECORD_BYTES)
            finally:
                os.close(fd)
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict) or set(data) != _RECORD_FIELDS:
                return None
            if data["schema"] != RECORD_SCHEMA or data["target"] != name:
                return None
            if not isinstance(data["inputSha256"], str) or not _SHA256_RE.fullmatch(data["inputSha256"]):
                return None
            if not isinstance(data["toolSha256"], str) or not _SHA256_RE.fullmatch(data["toolSha256"]):
                return None
            if not isinstance(data["completedAt"], str) or len(data["completedAt"]) > 64:
                return None
            raw_outputs = data["outputs"]
            if not isinstance(raw_outputs, list):
                return None
            specs = {spec.path: spec for spec in target.outputs}
            if len(raw_outputs) != len(specs):
                return None
            outputs: list[ArtifactOutput] = []
            seen: set[str] = set()
            for raw_output in raw_outputs:
                if not isinstance(raw_output, dict) or set(raw_output) != _OUTPUT_FIELDS:
                    return None
                relative = raw_output["path"]
                if not isinstance(relative, str) or relative in seen or relative not in specs:
                    return None
                mode_value = raw_output["mode"]
                if not isinstance(mode_value, str) or not _MODE_RE.fullmatch(mode_value):
                    return None
                mode = int(mode_value, 8)
                spec = specs[relative]
                if mode != spec.mode:
                    return None
                size = raw_output["size"]
                digest = raw_output["sha256"]
                if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                    return None
                if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
                    return None
                output = ArtifactOutput(relative, mode, size, digest)
                if validate_objects and not self._validate_object(output, spec):
                    return None
                outputs.append(output)
                seen.add(relative)
            if seen != set(specs):
                return None
            return ArtifactRecord(
                target=name,
                input_sha256=data["inputSha256"],
                tool_sha256=data["toolSha256"],
                outputs=tuple(sorted(outputs, key=lambda output: output.path)),
                completed_at=data["completedAt"],
            )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            return None

    def _validate_object(self, output: ArtifactOutput, spec: OutputSpec) -> bool:
        path = self._object_root / output.sha256
        try:
            info = _secure_regular_stat(path, 0o600, require_owner=True)
            if info.st_size != output.size or _hash_file(path) != output.sha256:
                return False
            _validate_content(path, spec)
            return True
        except ArtifactError:
            return False

    def _import_object(self, output: ArtifactOutput, source: Path) -> None:
        destination = self._object_root / output.sha256
        spec = self._spec_for_output(output.path)
        if self._validate_object(output, spec):
            return
        temporary = self._object_root / f".{output.sha256}.{secrets.token_hex(8)}.tmp"
        source_fd = destination_fd = None
        try:
            source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            source_info = os.fstat(source_fd)
            if not stat.S_ISREG(source_info.st_mode) or source_info.st_uid != os.geteuid() or source_info.st_nlink != 1:
                raise ArtifactError("artifact_output_unsafe")
            destination_fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            copied_hash = hashlib.sha256()
            copied = 0
            while True:
                chunk = os.read(source_fd, _COPY_CHUNK)
                if not chunk:
                    break
                copied_hash.update(chunk)
                copied += len(chunk)
                _write_all(destination_fd, chunk)
            if copied != output.size or copied_hash.hexdigest() != output.sha256:
                raise ArtifactError("artifact_output_changed")
            os.fchmod(destination_fd, 0o600)
            os.fsync(destination_fd)
            os.close(destination_fd)
            destination_fd = None
            os.replace(temporary, destination)
            _fsync_directory(self._object_root)
            if not self._validate_object(output, spec):
                raise ArtifactError("artifact_object_publication_failed")
        except OSError as exc:
            raise ArtifactError("artifact_object_publication_failed") from exc
        finally:
            if source_fd is not None:
                os.close(source_fd)
            if destination_fd is not None:
                os.close(destination_fd)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _publish_record(self, record: ArtifactRecord) -> None:
        path = self._record_root / f"{record.target}.json"
        payload = _canonical_json(record.as_dict()) + b"\n"
        _atomic_write(path, payload, 0o600)

    def _directory_records(self, output_directory: str) -> tuple[ArtifactRecord, ...]:
        records: list[ArtifactRecord] = []
        for name, target in self.catalog.items():
            if target.output_directory != output_directory:
                continue
            record = self._load_record(name, validate_objects=True)
            if record is not None:
                records.append(record)
        return tuple(records)

    def _restore_directory(self, output_directory: str) -> None:
        records = self._directory_records(output_directory)
        if not self._restore_records(records):
            raise ArtifactError("artifact_publication_failed")

    def _restore_records(self, records: Sequence[ArtifactRecord]) -> bool:
        try:
            for record in records:
                target = self.catalog[record.target]
                specs = {spec.path: spec for spec in target.outputs}
                for output in record.outputs:
                    self._materialize_output(output, specs[output.path], self.project_root / output.path, self.project_root)
            directories = {str((self.project_root / output.path).parent) for record in records for output in record.outputs}
            for directory in sorted(directories):
                _fsync_directory(Path(directory))
            return True
        except (ArtifactError, OSError):
            return False

    def _materialize_output(self, output: ArtifactOutput, spec: OutputSpec, destination: Path, allowed_root: Path) -> None:
        if not self._validate_object(output, spec):
            raise ArtifactError("artifact_object_invalid")
        self._ensure_public_parent(destination.parent, allowed_root)
        try:
            existing = destination.lstat()
            if (
                stat.S_ISREG(existing.st_mode)
                and not stat.S_ISLNK(existing.st_mode)
                and existing.st_uid == os.geteuid()
                and existing.st_nlink == 1
                and stat.S_IMODE(existing.st_mode) == spec.mode
                and existing.st_size == output.size
                and _hash_file(destination) == output.sha256
            ):
                _validate_content(destination, spec)
                return
        except (FileNotFoundError, ArtifactError):
            pass
        temporary = destination.parent / f".{destination.name}.{secrets.token_hex(8)}.tmp"
        object_path = self._object_root / output.sha256
        source_fd = destination_fd = None
        try:
            source_fd = os.open(object_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            object_info = os.fstat(source_fd)
            if (
                not stat.S_ISREG(object_info.st_mode)
                or object_info.st_uid != os.geteuid()
                or object_info.st_nlink != 1
                or stat.S_IMODE(object_info.st_mode) != 0o600
            ):
                raise ArtifactError("artifact_object_invalid")
            destination_fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                spec.mode,
            )
            copied_hash = hashlib.sha256()
            copied = 0
            while True:
                chunk = os.read(source_fd, _COPY_CHUNK)
                if not chunk:
                    break
                copied_hash.update(chunk)
                copied += len(chunk)
                _write_all(destination_fd, chunk)
            if copied != output.size or copied_hash.hexdigest() != output.sha256:
                raise ArtifactError("artifact_object_changed")
            os.fchmod(destination_fd, spec.mode)
            os.fsync(destination_fd)
            os.close(destination_fd)
            destination_fd = None
            os.replace(temporary, destination)
            _fsync_directory(destination.parent)
            public_info = _secure_regular_stat(destination, spec.mode, require_owner=True)
            if public_info.st_size != output.size or _hash_file(destination) != output.sha256:
                raise ArtifactError("artifact_publication_failed")
            _validate_content(destination, spec)
        except OSError as exc:
            raise ArtifactError("artifact_publication_failed") from exc
        finally:
            if source_fd is not None:
                os.close(source_fd)
            if destination_fd is not None:
                os.close(destination_fd)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _ensure_public_parent(self, parent: Path, allowed_root: Path) -> None:
        try:
            parent.relative_to(allowed_root)
        except ValueError as exc:
            raise ArtifactError("artifact_output_path_invalid") from exc
        relative_parts = parent.relative_to(allowed_root).parts
        current = allowed_root
        for part in relative_parts:
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                try:
                    current.mkdir(mode=0o755)
                except FileExistsError:
                    pass
                info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                raise ArtifactError("artifact_output_parent_unsafe")

    def _spec_for_output(self, relative: str) -> OutputSpec:
        for target in self.catalog.values():
            for spec in target.outputs:
                if spec.path == relative:
                    return spec
        raise ArtifactError("artifact_output_unknown")

    def _initialize_private_trees(self) -> None:
        self._ensure_owned_ancestor(self.project_root / ".xenoid")
        self._ensure_owned_ancestor(self.project_root / ".xenoid" / "cache")
        self._ensure_private_directory(self._cache_root)
        self._ensure_private_directory(self._record_root)
        self._ensure_private_directory(self._cache_root / "objects")
        self._ensure_private_directory(self._object_root)
        locks_parent = self.project_root / ".xenoid" / "locks"
        self._ensure_owned_ancestor(locks_parent)
        self._ensure_private_directory(self._lock_root)

    def _ensure_owned_ancestor(self, path: Path) -> None:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError("artifact_cache_parent_unsafe")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError("artifact_cache_parent_unsafe")

    def _ensure_private_directory(self, path: Path) -> None:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError("artifact_cache_directory_unsafe")

    def _ensure_stage_root(self, path: Path) -> None:
        try:
            path.mkdir(mode=0o700, parents=True)
        except FileExistsError:
            pass
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise ArtifactError("artifact_stage_directory_unsafe")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise ArtifactError("artifact_stage_directory_unsafe")

    @contextlib.contextmanager
    def _output_lock(self, target: BuildTarget) -> Iterator[None]:
        normalized = Path(target.output_directory).as_posix().encode("utf-8")
        name = hashlib.sha256(normalized).hexdigest() + ".lock"
        with self._file_lock(self._lock_root / name):
            yield

    @contextlib.contextmanager
    def _manifest_lock(self) -> Iterator[None]:
        with self._file_lock(self._lock_root / "manifest.lock"):
            yield

    @contextlib.contextmanager
    def _file_lock(self, path: Path) -> Iterator[None]:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags, 0o600)
        except OSError as exc:
            raise ArtifactError("artifact_lock_unsafe") from exc
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ArtifactError("artifact_lock_unsafe")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _sanitize_tail(self, tail: bytes) -> str:
        text = tail.decode("utf-8", "replace")
        replacements = {
            str(self.project_root): "$PROJECT",
            self._requested_environment.get("HOME", ""): "$HOME",
            tempfile.gettempdir(): "$TMP",
        }
        for raw, replacement in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
            if raw:
                text = text.replace(raw, replacement)
        for key, value in self._requested_environment.items():
            if value and len(value) >= 6 and re.search(r"TOKEN|PASSWORD|SECRET|COOKIE|AUTH", key, re.IGNORECASE):
                text = text.replace(value, "[REDACTED]")
        text = re.sub(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@", r"\1[REDACTED]@", text)
        text = re.sub(r"(?i)(https?://[^\s?#]+)\?[^\s#]*", r"\1?[REDACTED]", text)
        return "".join(character if character in "\n\t" or ord(character) >= 32 else "?" for character in text)




    def _cancel_requested(self) -> bool:
        if self._internal_cancel.is_set():
            return True
        if isinstance(self._cancelled, threading.Event):
            return self._cancelled.is_set()
        if callable(self._cancelled):
            try:
                return bool(self._cancelled())
            except Exception:
                return True
        return False


def _validate_content(path: Path, spec: OutputSpec) -> None:
    if spec.path.endswith(".apk"):
        try:
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                if not names or len(names) != len(set(names)) or "AndroidManifest.xml" not in names:
                    raise ArtifactError("artifact_output_format_invalid")
        except (OSError, zipfile.BadZipFile):
            raise ArtifactError("artifact_output_format_invalid")
    if spec.elf_machine is None and spec.elf_type is None and spec.elf_class is None and spec.interpreter is None:
        return
    try:
        with path.open("rb") as handle:
            header = handle.read(64)
            if len(header) < 64 or header[:4] != b"\x7fELF":
                raise ArtifactError("artifact_output_architecture_invalid")
            elf_class = {1: 32, 2: 64}.get(header[4])
            byte_order = {1: "<", 2: ">"}.get(header[5])
            if elf_class is None or byte_order is None:
                raise ArtifactError("artifact_output_architecture_invalid")
            elf_type = struct.unpack_from(byte_order + "H", header, 16)[0]
            machine = struct.unpack_from(byte_order + "H", header, 18)[0]
            if spec.elf_class is not None and elf_class != spec.elf_class:
                raise ArtifactError("artifact_output_architecture_invalid")
            expected_machine = {"EM_AARCH64": 183, "EM_X86_64": 62}.get(_normalize_elf_machine(spec.elf_machine))
            if expected_machine is not None and machine != expected_machine:
                raise ArtifactError("artifact_output_architecture_invalid")
            expected_type = {"ET_DYN": 3, "ET_EXEC": 2}.get(_normalize_elf_type(spec.elf_type))
            if expected_type is not None and elf_type != expected_type:
                raise ArtifactError("artifact_output_architecture_invalid")
            if spec.interpreter is not None:
                if elf_class == 64:
                    program_offset = struct.unpack_from(byte_order + "Q", header, 32)[0]
                    program_size = struct.unpack_from(byte_order + "H", header, 54)[0]
                    program_count = struct.unpack_from(byte_order + "H", header, 56)[0]
                else:
                    program_offset = struct.unpack_from(byte_order + "I", header, 28)[0]
                    program_size = struct.unpack_from(byte_order + "H", header, 42)[0]
                    program_count = struct.unpack_from(byte_order + "H", header, 44)[0]
                if program_size < 4 or program_count > 4096:
                    raise ArtifactError("artifact_output_architecture_invalid")
                has_interpreter = False
                for index in range(program_count):
                    handle.seek(program_offset + index * program_size)
                    raw_type = handle.read(4)
                    if len(raw_type) != 4:
                        raise ArtifactError("artifact_output_architecture_invalid")
                    if struct.unpack(byte_order + "I", raw_type)[0] == 3:
                        has_interpreter = True
                        break
                if has_interpreter != spec.interpreter:
                    raise ArtifactError("artifact_output_architecture_invalid")
    except OSError as exc:
        raise ArtifactError("artifact_output_architecture_invalid") from exc


def _secure_regular_stat(path: Path, expected_mode: int, *, require_owner: bool) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise ArtifactError("artifact_output_missing") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ArtifactError("artifact_output_unsafe")
    if require_owner and info.st_uid != os.geteuid():
        raise ArtifactError("artifact_output_unsafe")
    if stat.S_IMODE(info.st_mode) != expected_mode:
        raise ArtifactError("artifact_output_mode_invalid")
    return info


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ArtifactError("artifact_file_unreadable") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ArtifactError("artifact_file_unsafe")
        while True:
            chunk = os.read(fd, _COPY_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ArtifactError("artifact_file_changed")
    finally:
        os.close(fd)
    return digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _manifest_digest(records: Sequence[ArtifactRecord]) -> str:
    tuples = []
    for record in sorted(records, key=lambda item: item.target):
        tuples.append(
            {
                "target": record.target,
                "inputSha256": record.input_sha256,
                "toolSha256": record.tool_sha256,
                "outputs": [
                    {
                        "path": output.path,
                        "mode": output.mode,
                        "size": output.size,
                        "sha256": output.sha256,
                    }
                    for output in sorted(record.outputs, key=lambda item: item.path)
                ],
            }
        )
    return _canonical_digest(tuples)


def _atomic_write(path: Path, payload: bytes, mode: int) -> None:
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    fd = None
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        _write_all(fd, payload)
        os.fchmod(fd, mode)
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except OSError as exc:
        raise ArtifactError("artifact_record_publication_failed") from exc
    finally:
        if fd is not None:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _read_fd_bounded(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(65536, limit + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise ValueError("record too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _fsync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        raise ArtifactError("artifact_directory_sync_failed") from exc
    try:
        os.fsync(fd)
    except OSError as exc:
        raise ArtifactError("artifact_directory_sync_failed") from exc
    finally:
        os.close(fd)


def _coerce_run_result(result: Any) -> _RunResult:
    if isinstance(result, _RunResult):
        return result
    if isinstance(result, Mapping):
        returncode = result.get("returncode", 0)
        stdout = result.get("stdout", b"")
        stderr = result.get("stderr", b"")
    else:
        returncode = getattr(result, "returncode", 0)
        stdout = getattr(result, "stdout", b"")
        stderr = getattr(result, "stderr", b"")
    if isinstance(stdout, str):
        stdout = stdout.encode("utf-8", "replace")
    if isinstance(stderr, str):
        stderr = stderr.encode("utf-8", "replace")
    return _RunResult(int(returncode), bytes(stdout)[-_MAX_FAILED_TAIL_BYTES:], bytes(stderr)[-_MAX_FAILED_TAIL_BYTES:])


def _combine_tails(stdout: bytes, stderr: bytes) -> bytes:
    combined = b""
    if stdout:
        combined += b"stdout:\n" + stdout
    if stderr:
        if combined:
            combined += b"\n"
        combined += b"stderr:\n" + stderr
    return combined[-_MAX_FAILED_TAIL_BYTES:]


def _duration_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def _has_glob(value: str) -> bool:
    return any(character in value for character in "*?[")


__all__ = [
    "ALL_TARGETS",
    "CONSUMER_TARGETS",
    "TARGETS",
    "ArtifactBuilder",
    "ArtifactError",
    "ArtifactOutput",
    "ArtifactRecord",
    "ArtifactSnapshot",
    "BuildTarget",
    "OutputSpec",
]
