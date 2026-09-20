from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import sys
import signal
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Lock
from typing import Any

from .process import run_bounded

GATE_SCHEMA = "dev.xenoid.gates/v1"
VERIFY_SCHEMA = "dev.xenoid.verify/v1"
CI_SCHEMA = "dev.xenoid.ci/v1"
CACHE_SCHEMA = "dev.xenoid.gate-cache/v1"
GOOGLE_SMOKE_GATE_SCHEMA = "dev.xenoid.google-services-smoke/v2"
GOOGLE_REPRODUCIBILITY_SCHEMA = "dev.xenoid.google-reproducibility/v1"
GOOGLE_CUTOVER_SCHEMA = "dev.xenoid.google-provider-cutover/v1"
GOOGLE_ACCEPTANCE_NORMALIZED_SCHEMA = "dev.xenoid.google-release-acceptance-normalized/v1"
GOOGLE_ATTESTATION_SCHEMA = "dev.xenoid.google-release-attestation/v1"
GATE_DEPENDENCY_SNAPSHOT_SCHEMA = "dev.xenoid.gate-dependency-snapshot/v1"
_PROGRESS_SCHEMA = "dev.xenoid.progress/v1"
_SAFE_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_CACHE_FIELDS = {
    "schema",
    "name",
    "inputSha256",
    "commandSha256",
    "completedAt",
    "result",
}
_FAILURE_BUDGET = 64 * 1024
_ENVIRONMENT_KEYS = (
    "ANDROID_HOME",
    "ANDROID_SDK_ROOT",
    "ANDROID_NDK_HOME",
    "CC",
    "CXX",
    "JAVA_HOME",
)


_STDOUT_DOCUMENT_GATES: Mapping[str, tuple[str, str]] = {
    "google-runtime": ("result", GOOGLE_SMOKE_GATE_SCHEMA),
    "google-reproducibility": ("result", GOOGLE_REPRODUCIBILITY_SCHEMA),
    "google-provider-cutover-contract": ("result", GOOGLE_CUTOVER_SCHEMA),
    "google-release-acceptance": ("acceptance", GOOGLE_ACCEPTANCE_NORMALIZED_SCHEMA),
}


@dataclass(frozen=True)
class GateSpec:
    name: str
    command: tuple[str, ...] = ()
    inputs: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    timeout_seconds: int = 180
    cacheable: bool = True
    runtime_free: bool = True
    mutating: bool = False
    sensitive: bool = False
    required: bool = True
    tools: tuple[str, ...] = ("python3",)
    artifact_records: tuple[str, ...] = ()
    inventory: bool = False
    category: str = "static"
    network: bool = False
    privileged: bool = False
    outputs: tuple[str, ...] = ()

    @property
    def aggregate(self) -> bool:
        return not self.command


_COMMON_PYTHON = ("src/xenoid/**/*.py",)
_COMMON_CONTRACT = (
    "src/xenoid/**/*.py",
    "scripts/*.py",
    "scripts/*.sh",
    "daemon/app/src/**/*.java",
    "native/*/*.c",
    "native/*/*.cpp",
    "native/*/*.h",
    "native/*/*.S",
    "native/*/Makefile",
    "runtime/redroid/**/*",
    "data/**/*.json",
    "examples/**/*.json",
    "xenoid",
    "xenoid-mcp",
    "xenoid-service",
)
_RUNTIME_INPUTS = (
    "src/xenoid/**/*.py",
    "scripts/smoke-*.sh",
    "tests/**/*",
    "examples/**/*.json",
)


def _py(
    name: str,
    script: str,
    *,
    inputs: tuple[str, ...] = _COMMON_CONTRACT,
    timeout: int = 180,
    cacheable: bool = True,
    mutating: bool = False,
    category: str = "static",
    tools: tuple[str, ...] = ("python3",),
) -> GateSpec:
    return GateSpec(
        name=name,
        command=("{python}", script),
        inputs=inputs,
        timeout_seconds=timeout,
        cacheable=cacheable,
        mutating=mutating,
        tools=tools,
        category=category,
    )


def _smoke(name: str, script: str, *, mutating: bool = False) -> GateSpec:
    extra_tools: tuple[str, ...] = ()
    if script in {"smoke-rootd-auth.py", "smoke-power-supply-overlay.py", "smoke-native-shim.py"}:
        extra_tools = ("cc",)
    elif script == "smoke-hook-surfaces.py":
        extra_tools = ("c++",)
    elif script == "smoke-input-devices-overlay.py":
        extra_tools = ("strings",)
    extra_inputs = (
        ("frida/scripts/*.js",)
        if script == "smoke-hook-surfaces.py"
        else ()
    )
    return _py(
        name,
        f"scripts/{script}",
        inputs=(
            f"scripts/{script}",
            "scripts/*.py",
            "scripts/*.sh",
            "src/xenoid/**/*.py",
            "runtime/redroid/**/*",
            "examples/**/*.json",
            "data/**/*.json",
            "daemon/app/src/**/*.java",
            "native/*/*.c",
            "native/*/*.cpp",
            "native/*/*.h",
            "native/*/*.S",
            "native/*/Makefile",
            *extra_inputs,
        ),
        cacheable=not mutating,
        mutating=mutating,
        category="artifact" if mutating else "static",
        tools=("python3", *extra_tools),
    )


_CONTRACTS = (
    _py(
        "version-contract",
        "scripts/test-version-contract.py",
        inputs=(
            "scripts/test-version-contract.py",
            "src/xenoid/__init__.py",
            "src/xenoid/cli.py",
            "src/xenoid/mcp_server.py",
            "src/xenoid/gates.py",
            "src/xenoid/remote_service.py",
            "pyproject.toml",
            "setup.py",
            "daemon/app/build.gradle",
            "daemon/app/src/main/java/dev/xenoid/daemon/XenoidDaemonService.java",
            "CHANGELOG.md",
            "CHANGELOG_CN.md",
        ),
    ),
    _py("bootstrap-contract", "scripts/test-bootstrap-contract.py"),
    _py("proxy-instance-contract", "scripts/test-proxy.py"),
    _py(
        "proxy-state-contract",
        "scripts/test-proxy-state.py",
        inputs=(
            "scripts/test-proxy-state.py",
            "daemon/build.gradle",
            "daemon/settings.gradle",
            "daemon/app/build.gradle",
            "daemon/app/src/main/**/*.java",
            "daemon/app/src/test/**/*.java",
        ),
        tools=("python3", "gradle", "java", "javac"),
        timeout=600,
    ),
    _py("instance-storage-contract", "scripts/test-instance-storage.py", timeout=300),
    _py("cellular-profile-contract", "scripts/test-cellular-profile.py"),
    _py("ril-source-contract", "scripts/test-ril-source.py"),
    _py("google-services-contract", "scripts/test-google-services.py"),
    _py("proxy-control-contract", "scripts/test-proxy-control.py"),
    _py("proxy-compiler-contract", "scripts/test-proxy-compiler.py"),
    _py("remote-service-contract", "scripts/test-remote-service.py", timeout=300),
    _py("mcp-contract", "scripts/test-mcp-contract.py", timeout=300),
    _py("build-graph-contract", "scripts/test-build-contract.py", timeout=300),
    _py("runtime-image-contract", "scripts/test-runtime-image.py", timeout=300),
    _py("convergence-contract", "scripts/test-convergence.py", timeout=300),
    _py(
        "shared-protection-contract",
        "scripts/test-shared-protection.py",
        inputs=(
            "scripts/test-shared-protection.py",
            "src/xenoid/protection.py",
            "src/xenoid/backend.py",
            "scripts/build-ebpf.sh",
            "scripts/load-ebpf.sh",
            "scripts/build-kmod.sh",
            "scripts/smoke-ebpf.sh",
            "scripts/with-shared-protection-lock.py",
            "native/xenoid-ebpf/Makefile",
            "native/xenoid-ebpf/*.c",
            "native/xenoid-kmod/Makefile",
            "native/xenoid-kmod/xenoid_kmod.c",
        ),
        timeout=300,
    ),
    _py("gate-runner-contract", "scripts/test-gates.py"),
    _py("doctor-observation-contract", "scripts/test-doctor-contract.py"),
)

_SOURCE_SMOKES = (
    _smoke("prop-area-source", "smoke-prop-area-rules.py"),
    _smoke("profile-template-source", "smoke-profile-template.py"),
    _smoke("storage-surfaces-source", "smoke-storage-surfaces.py"),
    _smoke("netctl-source", "smoke-netctl-source.py"),
    _smoke("native-shim-source", "smoke-native-shim.py"),
    _smoke("rootd-auth-source", "smoke-rootd-auth.py"),
    _smoke("hook-surfaces-source", "smoke-hook-surfaces.py"),
    _smoke("frida-install-source", "smoke-frida-install.py"),
    _smoke("app-process-source", "smoke-app-process-needed.py"),
    _smoke("install-runtime-source", "smoke-install-runtime.py"),
    _smoke("idstore-helper-source", "smoke-idstore-helper.py"),
    _smoke("input-profile-source", "smoke-input-profile.py"),
    _smoke("rtc-overlay-source", "smoke-rtc-overlay.py"),
    _smoke("network-overlay-source", "smoke-network-overlay.py"),
    _smoke("mount-namespace-source", "smoke-mount-namespace-overlay.py"),
    _smoke("kernel-hardening-source", "smoke-kernel-hardening-overlay.py"),
    _smoke("cpu-proc-source", "smoke-cpu-proc-stats-overlay.py"),
    _smoke("cpu-sysfs-source", "smoke-cpu-sysfs-overlay.py"),
    _smoke("devicetree-source", "smoke-devicetree-overlay.py"),
    _smoke("framebuffer-source", "smoke-framebuffer-overlay.py"),
    _smoke("kallsyms-source", "smoke-kallsyms-tracing-overlay.py"),
    _smoke("kernel-device-source", "smoke-kernel-device-overlay.py"),
    _smoke("kernel-proc-source", "smoke-kernel-proc-overlay.py"),
    _smoke("memory-proc-source", "smoke-memory-proc-overlay.py"),
    _smoke("power-supply-source", "smoke-power-supply-overlay.py"),
    _smoke("proc-identity-source", "smoke-proc-identity-overlay.py"),
    _smoke("statfs-source", "smoke-statfs-coherence.py"),
    _smoke("random-sysctl-source", "smoke-random-sysctl-overlay.py"),
    _smoke("selinux-source", "smoke-selinux-overlay.py"),
    _smoke("input-devices-source", "smoke-input-devices-overlay.py"),
)

_STATIC_LEAF_NAMES = tuple(
    spec.name
    for spec in (
        *_CONTRACTS,
        *_SOURCE_SMOKES,
    )
    if not spec.mutating
)
_DOCTOR_SAFE_NAMES = tuple(
    spec.name
    for spec in (*_CONTRACTS, *_SOURCE_SMOKES)
    if not spec.mutating
)

GATE_CATALOG: tuple[GateSpec, ...] = (
    GateSpec(
        name="sensitive-data",
        command=("{python}", "scripts/audit-sensitive-data.py"),
        inputs=("scripts/audit-sensitive-data.py", "src/xenoid/google_services.py"),
        timeout_seconds=180,
        cacheable=False,
        sensitive=True,
        inventory=True,
        tools=("python3", "git"),
    ),
    GateSpec(
        name="python-compile",
        command=("{python}", "-m", "compileall", "-q", "src"),
        inputs=_COMMON_PYTHON,
        timeout_seconds=180,
        tools=("python3",),
    ),
    *_CONTRACTS,
    *_SOURCE_SMOKES,
    GateSpec(
        name="daemon-api-mock",
        command=("scripts/smoke-daemon-api.sh", "--mock"),
        inputs=("scripts/smoke-daemon-api.sh", "src/xenoid/**/*.py", "daemon/app/src/**/*.java"),
        timeout_seconds=300,
        tools=("bash", "python3"),
    ),
    GateSpec(
        name="dual-instance-report-contract",
        command=("scripts/smoke-dual-instance.sh", "--report-contract-test"),
        inputs=("scripts/smoke-dual-instance.sh", "src/xenoid/**/*.py"),
        timeout_seconds=180,
        tools=("bash", "python3"),
    ),
    GateSpec(
        name="runtime-convergence",
        command=("./xenoid", "up"),
        inputs=("src/xenoid/**/*.py", "scripts/*.py", "scripts/*.sh", "runtime/redroid/**/*", "daemon/app/src/**/*"),
        dependencies=("static",),
        timeout_seconds=1800,
        cacheable=False,
        runtime_free=False,
        mutating=True,
        tools=("python3", "docker", "adb"),
        category="live",
        network=True,
        privileged=True,
    ),
    GateSpec(
        name="filesystem-runtime",
        command=("scripts/smoke-filesystem-runtime.sh",),
        inputs=_RUNTIME_INPUTS,
        dependencies=("runtime-convergence",),
        timeout_seconds=900,
        cacheable=False,
        runtime_free=False,
        mutating=True,
        tools=("bash", "adb"),
        category="live",
    ),
    GateSpec(
        name="protection-runtime",
        command=("scripts/smoke-ebpf.sh", "--verify-loaded"),
        inputs=_RUNTIME_INPUTS + (
            "native/xenoid-ebpf/Makefile",
            "native/xenoid-ebpf/*.c",
            "native/xenoid-kmod/Makefile",
            "native/xenoid-kmod/xenoid_kmod.c",
        ),
        dependencies=("filesystem-runtime",),
        timeout_seconds=900,
        cacheable=False,
        runtime_free=False,
        mutating=True,
        tools=("bash", "docker"),
        category="live",
        privileged=True,
    ),
    GateSpec(
        name="persistence-runtime",
        command=("scripts/smoke-persistence-runtime.sh",),
        inputs=_RUNTIME_INPUTS,
        dependencies=("protection-runtime",),
        timeout_seconds=1200,
        cacheable=False,
        runtime_free=False,
        mutating=True,
        tools=("bash", "adb"),
        category="live",
        privileged=True,
    ),
    GateSpec(
        name="dual-instance-runtime",
        command=("scripts/smoke-dual-instance.sh",),
        inputs=_RUNTIME_INPUTS,
        dependencies=("persistence-runtime",),
        timeout_seconds=1200,
        cacheable=False,
        runtime_free=False,
        mutating=True,
        tools=("bash", "docker", "adb"),
        category="live",
        privileged=True,
    ),
    GateSpec(
        name="cellular-runtime",
        command=("scripts/smoke-cellular-runtime.sh",),
        inputs=_RUNTIME_INPUTS,
        dependencies=("dual-instance-runtime",),
        timeout_seconds=900,
        cacheable=False,
        runtime_free=False,
        mutating=True,
        tools=("bash", "adb"),
        category="live",
        privileged=True,
    ),
    GateSpec(
        name="camera-runtime",
        command=("scripts/smoke-camera-runtime.sh", "--full", "--loop-seconds", "10"),
        inputs=_RUNTIME_INPUTS,
        dependencies=("cellular-runtime",),
        timeout_seconds=1200,
        cacheable=False,
        runtime_free=False,
        mutating=True,
        tools=("bash", "adb"),
        category="live",
        privileged=True,
    ),
    GateSpec(
        name="drm-runtime",
        command=("scripts/smoke-drm-identity.sh",),
        inputs=_RUNTIME_INPUTS + (
            "native/xenoid-zygote/xenoid_zygote.c",
            "native/xenoid-zygote/xenoid_drm.c",
            "native/xenoid-zygote/xenoid_drm_sret.S",
            "native/xenoid-shim/xenoid_shim.c",
            "scripts/build-native-zygote.sh",
        ),
        dependencies=("camera-runtime",),
        timeout_seconds=900,
        cacheable=False,
        runtime_free=False,
        mutating=True,
        tools=("bash", "python3", "adb", "javac", "keytool", "zip"),
        category="live",
        privileged=True,
    ),
    GateSpec(
        name="google-runtime",
        command=("scripts/smoke-google-services-gate.sh",),
        inputs=_RUNTIME_INPUTS + ("data/google-services/*.json", "tests/google-services-runtime-probe/**/*", "runtime/redroid/microg-policy/**/*"),
        dependencies=("drm-runtime",),
        timeout_seconds=1200,
        cacheable=False,
        runtime_free=False,
        mutating=True,
        tools=("bash", "adb"),
        category="live",
        network=True,
        privileged=True,
    ),
    GateSpec(
        name="google-provider-cutover-contract",
        command=("{python}", "scripts/test-google-provider-cutover.py"),
        inputs=(
            "src/xenoid/**/*.py",
            "scripts/*.py",
            "scripts/*.sh",
            "data/google-services/*.json",
            "runtime/redroid/microg-policy/**/*",
            "tests/google-services-runtime-probe/**/*",
            "docs/*.md",
            "README.md",
            "README_CN.md",
            "examples/*.json",
            "skills/**/*.md",
        ),
        dependencies=("runtime-image-contract",),
        timeout_seconds=300,
        cacheable=False,
        tools=("python3",),
        category="static",
    ),
    GateSpec(
        name="google-reproducibility",
        command=("scripts/smoke-google-services-reproducibility.sh",),
        inputs=_RUNTIME_INPUTS + ("data/google-services/*.json", "runtime/redroid/microg-policy/**/*", "scripts/make-runtime-context.sh", "scripts/generate-microg-product-policy.py", "scripts/patch-services-runtime.py"),
        dependencies=("runtime-image-contract", "google-provider-cutover-contract"),
        timeout_seconds=7200,
        cacheable=False,
        runtime_free=False,
        mutating=True,
        tools=("bash", "docker"),
        category="release",
        network=True,
        privileged=True,
    ),
    GateSpec(
        name="google-release-acceptance",
        command=("{python}", "scripts/validate-google-services-release-acceptance.py"),
        inputs=("scripts/validate-google-services-release-acceptance.py", "data/google-services/*.json"),
        dependencies=("google-runtime", "google-reproducibility", "google-provider-cutover-contract"),
        timeout_seconds=1800,
        cacheable=False,
        sensitive=True,
        runtime_free=False,
        mutating=False,
        tools=("python3", "adb"),
        category="release",
        privileged=True,
    ),
    GateSpec(
        name="release-source-contract",
        command=("{python}", "scripts/verify-release.py", "--self-check"),
        inputs=("scripts/package-release.sh", "scripts/verify-release.py", "scripts/make-ota-bundle.sh", "scripts/canonical-tar.py", "scripts/run-bounded-command.py", "src/xenoid/process.py"),
        dependencies=("build-graph-contract", "runtime-image-contract"),
        timeout_seconds=180,
        cacheable=False,
        tools=("python3",),
        category="release",
    ),
    GateSpec(
        name="static",
        dependencies=("sensitive-data", "python-compile", *_STATIC_LEAF_NAMES, "daemon-api-mock", "dual-instance-report-contract"),
        cacheable=False,
    ),
    GateSpec(name="verify", dependencies=("static",), cacheable=False),
    GateSpec(name="ci-static", dependencies=("static",), cacheable=False),
    GateSpec(
        name="ci-runtime",
        dependencies=("ci-static", "filesystem-runtime", "protection-runtime", "persistence-runtime", "dual-instance-runtime"),
        cacheable=False,
        runtime_free=False,
        mutating=True,
        category="live",
        network=True,
        privileged=True,
    ),
    GateSpec(
        name="ci-full",
        dependencies=("ci-runtime", "cellular-runtime", "camera-runtime", "drm-runtime", "google-runtime", "release-source-contract"),
        cacheable=False,
        runtime_free=False,
        mutating=True,
        category="live",
        network=True,
        privileged=True,
    ),
    GateSpec(
        name="doctor-default",
        dependencies=("python-compile", "mcp-contract", "remote-service-contract", "convergence-contract"),
        cacheable=False,
        category="doctor",
    ),
    GateSpec(
        name="doctor-full",
        dependencies=("python-compile", *_DOCTOR_SAFE_NAMES, "dual-instance-report-contract"),
        cacheable=False,
        category="doctor",
    ),
    GateSpec(name="release", dependencies=("static", "release-source-contract", "google-provider-cutover-contract"), cacheable=False, category="release"),
    GateSpec(
        name="release-google",
        dependencies=("static", "release-source-contract", "google-provider-cutover-contract", "google-release-acceptance"),
        cacheable=False,
        category="release",
    ),
    GateSpec(name="audit", dependencies=("release",), cacheable=False, category="release"),
)

PROFILE_TARGETS: Mapping[str, str] = {
    "verify": "verify",
    "static": "ci-static",
    "runtime": "ci-runtime",
    "full": "ci-full",
    "doctor": "doctor-default",
    "doctor-full": "doctor-full",
    "release": "release",
    "release-google": "release-google",
    "audit": "audit",
}


def catalog() -> Mapping[str, GateSpec]:
    result = {spec.name: spec for spec in GATE_CATALOG}
    if len(result) != len(GATE_CATALOG):
        raise RuntimeError("gate_catalog_duplicate")
    for spec in GATE_CATALOG:
        if _SAFE_NAME.fullmatch(spec.name) is None:
            raise RuntimeError("gate_catalog_name_invalid")
        unknown = set(spec.dependencies) - set(result)
        if unknown:
            raise RuntimeError("gate_catalog_dependency_invalid")
        if spec.cacheable and (
            not spec.runtime_free
            or spec.mutating
            or spec.sensitive
            or spec.outputs
        ):
            raise RuntimeError("gate_catalog_cache_policy_invalid")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visiting:
            raise RuntimeError("gate_catalog_cycle")
        if name in visited:
            return
        visiting.add(name)
        for dependency in result[name].dependencies:
            visit(dependency)
        visiting.remove(name)
        visited.add(name)

    for name in result:
        visit(name)
    return result


class GateInputError(RuntimeError):
    pass


class GateRunner:
    def __init__(
        self,
        project_root: Path,
        *,
        specs: Mapping[str, GateSpec] | None = None,
        cache_root: Path | None = None,
        lock_root: Path | None = None,
        max_workers: int = 4,
    ) -> None:
        raw_project = Path(project_root).absolute()
        self.project_root = raw_project.resolve()
        self.specs = dict(catalog() if specs is None else specs)
        self._runtime_mutation_lock = Lock()
        selected_cache = cache_root or self.project_root / ".xenoid/cache/gates"
        selected_locks = lock_root or self.project_root / ".xenoid/locks/gates"

        def private_path(selected: Path) -> Path:
            candidate = (
                selected.absolute()
                if selected.is_absolute()
                else raw_project / selected
            )
            for base in (raw_project, self.project_root):
                try:
                    relative = candidate.relative_to(base)
                except ValueError:
                    continue
                return self.project_root / relative
            return candidate

        self.cache_root = private_path(selected_cache)
        self.lock_root = private_path(selected_locks)
        self.max_workers = max(1, min(4, max_workers))
        self._validate_specs()

    def _validate_specs(self) -> None:
        if not self.specs:
            raise ValueError("gate_catalog_empty")
        for key, spec in self.specs.items():
            if key != spec.name or _SAFE_NAME.fullmatch(key) is None:
                raise ValueError("gate_catalog_name_invalid")
            if any(dependency not in self.specs for dependency in spec.dependencies):
                raise ValueError("gate_catalog_dependency_invalid")
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(name: str) -> None:
            if name in visiting:
                raise ValueError("gate_catalog_cycle")
            if name in visited:
                return
            visiting.add(name)
            for dependency in self.specs[name].dependencies:
                visit(dependency)
            visiting.remove(name)
            visited.add(name)

        for name in self.specs:
            visit(name)

    def _validate_path_ancestry(self, path: Path) -> None:
        try:
            relative = path.relative_to(self.project_root)
        except ValueError as exc:
            raise GateInputError("gate_private_directory_invalid") from exc
        current = self.project_root
        for part in relative.parts:
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise GateInputError("gate_private_directory_invalid") from exc
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
            ):
                raise GateInputError("gate_private_directory_invalid")

    @staticmethod
    def _private_directory(path: Path) -> None:
        try:
            info = path.lstat()
        except FileNotFoundError:
            try:
                path.mkdir(mode=0o700, parents=True)
            except FileExistsError:
                pass
            except OSError as exc:
                raise GateInputError("gate_private_directory_invalid") from exc
            try:
                info = path.lstat()
            except OSError as exc:
                raise GateInputError("gate_private_directory_invalid") from exc
        except OSError as exc:
            raise GateInputError("gate_private_directory_invalid") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise GateInputError("gate_private_directory_invalid")

    def _prepare_private_trees(self) -> None:
        pycache_root = self.project_root / ".xenoid/cache/pycache"
        self._validate_path_ancestry(self.cache_root)
        self._validate_path_ancestry(self.lock_root)
        self._validate_path_ancestry(pycache_root)
        self._private_directory(self.cache_root)
        self._private_directory(self.cache_root / "v1")
        self._private_directory(self.lock_root)
        self._private_directory(pycache_root)
        self._validate_path_ancestry(self.cache_root / "v1")
        self._validate_path_ancestry(self.lock_root)
        self._validate_path_ancestry(pycache_root)

    def _expand_inputs(self, spec: GateSpec, deadline: float) -> list[tuple[str, bytes, int]]:
        paths: dict[str, Path | None] = {}
        for pattern in spec.inputs:
            matches = sorted(
                (path for path in self.project_root.glob(pattern) if path.is_file()),
                key=lambda path: path.relative_to(self.project_root).as_posix().encode(),
            )
            if not matches:
                raise GateInputError("gate_input_missing")
            for path in matches:
                relative = path.relative_to(self.project_root).as_posix()
                paths[relative] = path
        if spec.inventory:
            inventory = run_bounded(
                [sys.executable, "scripts/audit-sensitive-data.py", "--inventory-digest"],
                cwd=self.project_root,
                deadline=deadline,
                project_root=self.project_root,
            )
            if not inventory.ok:
                raise GateInputError("gate_inventory_unavailable")
            try:
                evidence = json.loads(inventory.stdout_tail)
                digest = evidence["sha256"]
                count = evidence["count"]
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise GateInputError("gate_inventory_invalid") from exc
            if (
                not isinstance(digest, str)
                or _HEX_64.fullmatch(digest) is None
                or not isinstance(count, int)
                or isinstance(count, bool)
                or count < 0
            ):
                raise GateInputError("gate_inventory_invalid")
            paths["@prospective-inventory"] = None
        result: list[tuple[str, bytes, int]] = []
        for relative in sorted(paths, key=lambda item: item.encode()):
            path = paths[relative]
            if path is None:
                result.append((relative, bytes.fromhex(digest), count))
                continue
            try:
                descriptor = os.open(
                    path,
                    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                )
                try:
                    before = os.fstat(descriptor)
                    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                        raise GateInputError("gate_input_unsafe")
                    chunks: list[bytes] = []
                    while True:
                        chunk = os.read(descriptor, 1024 * 1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    after = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
            except OSError as exc:
                raise GateInputError("gate_input_unreadable") from exc
            try:
                current = path.lstat()
            except OSError as exc:
                raise GateInputError("gate_input_changed") from exc
            identity = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
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
                raise GateInputError("gate_input_changed")
            data = b"".join(chunks)
            if len(data) != after.st_size:
                raise GateInputError("gate_input_changed")
            result.append((relative, data, stat.S_IMODE(after.st_mode)))
        return result

    def _tool_identity(self, spec: GateSpec) -> list[dict[str, str]]:
        identities: list[dict[str, str]] = []
        for tool in spec.tools:
            requested = (
                (
                    os.environ.get("CC")
                    or shutil.which("cc")
                    or shutil.which("clang")
                    or shutil.which("gcc")
                )
                if tool == "cc"
                else (
                    os.environ.get("CXX")
                    or shutil.which("c++")
                    or shutil.which("clang++")
                    or shutil.which("g++")
                )
                if tool == "c++"
                else sys.executable
                if tool == "python3"
                else tool
            )
            resolved = shutil.which(requested) if requested else None
            if resolved is None:
                identities.append({"name": tool, "identity": "missing"})
                continue
            path = Path(resolved)
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                digest = "unreadable"
            identities.append({"name": tool, "identity": digest})
        identities.append(
            {
                "name": "python-platform",
                "identity": hashlib.sha256(
                    json.dumps(
                        {
                            "version": sys.version,
                            "implementation": platform.python_implementation(),
                            "platform": platform.platform(),
                            "machine": platform.machine(),
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest(),
            }
        )
        return identities
    @staticmethod
    def _read_private_file(path: Path, *, maximum: int = 1024 * 1024) -> bytes:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > maximum
            ):
                raise GateInputError("gate_private_file_invalid")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) != info.st_size or len(data) > maximum:
                raise GateInputError("gate_private_file_invalid")
            return data
        finally:
            os.close(descriptor)

    def _artifact_record_bytes(self, spec: GateSpec) -> list[tuple[str, bytes]]:
        records: list[tuple[str, bytes]] = []
        for target in sorted(spec.artifact_records):
            path = self.project_root / ".xenoid/cache/artifacts/v1" / f"{target}.json"
            try:
                records.append((target, self._read_private_file(path)))
            except (OSError, GateInputError) as exc:
                raise GateInputError("gate_artifact_record_missing") from exc
        return records

    def _input_identity(self, spec: GateSpec, deadline: float) -> tuple[str, str]:
        command = tuple(sys.executable if item == "{python}" else item for item in spec.command)
        command_sha = hashlib.sha256(
            json.dumps(command, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        payload = {
            "name": spec.name,
            "command": command,
            "dependencies": spec.dependencies,
            "category": spec.category,
            "runtimeFree": spec.runtime_free,
            "mutating": spec.mutating,
            "required": spec.required,
            "network": spec.network,
            "privileged": spec.privileged,
            "environment": {
                key: hashlib.sha256(os.environ.get(key, "").encode("utf-8")).hexdigest()
                for key in _ENVIRONMENT_KEYS
            },
            "outputs": spec.outputs,
            "inputs": [
                {
                    "path": relative,
                    "mode": mode,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }
                for relative, data, mode in self._expand_inputs(spec, deadline)
            ],
            "tools": self._tool_identity(spec),
            "artifactRecords": [
                {"target": target, "sha256": hashlib.sha256(data).hexdigest()}
                for target, data in self._artifact_record_bytes(spec)
            ],
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
        return hashlib.sha256(encoded).hexdigest(), command_sha

    def _record_path(self, spec: GateSpec, input_sha: str) -> Path:
        return self.cache_root / "v1" / spec.name / f"{input_sha}.json"

    def _load_record(self, spec: GateSpec, input_sha: str, command_sha: str) -> bool:
        path = self._record_path(spec, input_sha)
        try:
            self._validate_path_ancestry(path.parent)
            self._private_directory_observed(path.parent)
        except GateInputError:
            return False
        try:
            raw = self._read_private_file(path, maximum=16 * 1024)
            data = json.loads(raw)
        except (OSError, GateInputError, ValueError, TypeError):
            return False
        return bool(
            isinstance(data, dict)
            and set(data) == _CACHE_FIELDS
            and data.get("schema") == CACHE_SCHEMA
            and data.get("name") == spec.name
            and data.get("inputSha256") == input_sha
            and data.get("commandSha256") == command_sha
            and isinstance(data.get("completedAt"), int)
            and data.get("result") == {"state": "passed"}
            and raw
            == (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        )

    def _publish_record(self, spec: GateSpec, input_sha: str, command_sha: str) -> None:
        path = self._record_path(spec, input_sha)
        self._validate_path_ancestry(path.parent)
        self._private_directory(path.parent)
        self._validate_path_ancestry(path.parent)
        data = {
            "schema": CACHE_SCHEMA,
            "name": spec.name,
            "inputSha256": input_sha,
            "commandSha256": command_sha,
            "completedAt": int(time.time()),
            "result": {"state": "passed"},
        }
        encoded = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        temporary = path.parent / f".{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _lock(
        self,
        spec: GateSpec,
        input_sha: str,
        *,
        deadline: float,
        progress: Callable[[Mapping[str, Any]], None] | None,
        cancelled: Event | None,
    ) -> tuple[int, Path]:
        directory = self.lock_root / spec.name
        self._validate_path_ancestry(directory)
        self._private_directory(directory)
        self._validate_path_ancestry(directory)
        path = directory / f"{input_sha}.lock"
        descriptor = os.open(
            path,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            os.close(descriptor)
            raise GateInputError("gate_lock_invalid")
        last_heartbeat = time.monotonic()
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return descriptor, path
            except BlockingIOError:
                now = time.monotonic()
                if cancelled is not None and cancelled.is_set():
                    os.close(descriptor)
                    raise GateInputError("gate_lock_cancelled")
                if now >= deadline:
                    os.close(descriptor)
                    raise GateInputError("gate_lock_timeout")
                if now - last_heartbeat >= 5.0:
                    try:
                        self._emit(progress, spec.name, "running", "waiting-lock")
                    except Exception as exc:
                        os.close(descriptor)
                        raise GateInputError("gate_lock_cancelled") from exc
                    last_heartbeat = now
                time.sleep(min(0.05, max(0.0, deadline - now)))

    def _run_one(
        self,
        spec: GateSpec,
        *,
        fresh: bool,
        deadline: float,
        progress: Callable[[Mapping[str, Any]], None] | None,
        cancelled: Event | None,
        dependency_results: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        runtime_mutating = False
        if spec.aggregate:
            return {
                "state": "passed",
                "cacheHit": False,
                "inputSha256": None,
                "durationMs": 0,
            }
        try:
            input_sha, command_sha = self._input_identity(spec, deadline)
            lock_fd, _ = self._lock(
                spec,
                input_sha,
                deadline=deadline,
                progress=progress,
                cancelled=cancelled,
            )
        except GateInputError as exc:
            code = str(exc)
            return {
                "state": "timed_out" if code == "gate_lock_timeout" else "failed",
                "cacheHit": False,
                "inputSha256": None,
                "durationMs": max(0, int((time.monotonic() - started) * 1000)),
                "errorCode": code,
            }
        try:
            # Recompute under the lock so cache records cannot be accepted from
            # the stale pre-lock view used to derive the lock key.
            locked_sha, locked_command_sha = self._input_identity(spec, deadline)
            if locked_sha != input_sha or locked_command_sha != command_sha:
                return {
                    "state": "failed",
                    "cacheHit": False,
                    "inputSha256": locked_sha,
                    "durationMs": max(0, int((time.monotonic() - started) * 1000)),
                    "errorCode": "gate_input_changed",
                }
            if spec.cacheable and not fresh and self._load_record(spec, input_sha, command_sha):
                return {
                    "state": "passed",
                    "cacheHit": True,
                    "inputSha256": input_sha,
                    "durationMs": max(0, int((time.monotonic() - started) * 1000)),
                }
            runtime_mutating = spec.mutating and not spec.runtime_free
            if runtime_mutating:
                # Gates that mutate the shared live runtime (restarts, image
                # rebuilds, container recreation) must not overlap; observers
                # and lighter live gates tolerate a stopped-observer window,
                # but two mutators racing one container corrupt both proofs.
                self._runtime_mutation_lock.acquire()
            command = [sys.executable if item == "{python}" else item for item in spec.command]
            child_env = {
                **os.environ,
                "LC_ALL": "C",
                "TZ": "UTC",
                "PYTHONHASHSEED": "0",
                "PYTHONPYCACHEPREFIX": str(self.project_root / ".xenoid/cache/pycache"),
                "XENOID_PROJECT": os.environ.get("XENOID_PROJECT", str(self.project_root)),
            }
            child_env.pop("PYTHONDONTWRITEBYTECODE", None)
            child_deadline = min(deadline, time.monotonic() + spec.timeout_seconds)
            document_rule = _STDOUT_DOCUMENT_GATES.get(spec.name)
            stdout_capture = bytearray() if document_rule is not None else None

            def _capture_stdout(chunk: bytes) -> None:
                if stdout_capture is None:
                    return
                if len(stdout_capture) + len(chunk) > 256 * 1024:
                    raise GateInputError("gate_result_document_too_large")
                stdout_capture.extend(chunk)

            stdin_payload: bytes | None = None
            if spec.name == "google-release-acceptance":
                snapshot: dict[str, Any] = {"schema": GATE_DEPENDENCY_SNAPSHOT_SCHEMA, "dependencies": {}}
                for dependency in ("google-runtime", "google-reproducibility", "google-provider-cutover-contract"):
                    observed = (dependency_results or {}).get(dependency)
                    if not isinstance(observed, Mapping):
                        return {
                            "state": "failed",
                            "cacheHit": False,
                            "inputSha256": input_sha,
                            "durationMs": max(0, int((time.monotonic() - started) * 1000)),
                            "errorCode": "gate_dependency_snapshot_unavailable",
                        }
                    snapshot["dependencies"][dependency] = {
                        "state": observed.get("state"),
                        "inputSha256": observed.get("inputSha256"),
                        "result": observed.get("result"),
                    }
                stdin_payload = (
                    json.dumps(snapshot, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode("ascii")
                if len(stdin_payload) > 256 * 1024:
                    return {
                        "state": "failed",
                        "cacheHit": False,
                        "inputSha256": input_sha,
                        "durationMs": max(0, int((time.monotonic() - started) * 1000)),
                        "errorCode": "gate_dependency_snapshot_too_large",
                    }
            result = run_bounded(
                command,
                cwd=self.project_root,
                deadline=child_deadline,
                env=child_env,
                project_root=self.project_root,
                cancelled=cancelled,
                input_bytes=stdin_payload,
                max_input_bytes=256 * 1024 if stdin_payload is not None else 4096,
                stdout_consumer=_capture_stdout if stdout_capture is not None else None,
                progress=(
                    (lambda stream, detail: self._emit(progress, spec.name, "running", stream))
                    if progress is not None
                    else None
                ),
            )
            gate_result: dict[str, Any] = {
                "state": result.state,
                "cacheHit": False,
                "inputSha256": input_sha,
                "durationMs": result.duration_ms,
            }
            if not result.ok:
                gate_result["errorCode"] = result.error_code or "gate_failed"
                if result.stdout_tail:
                    gate_result["stdoutTail"] = result.stdout_tail
                if result.stderr_tail:
                    gate_result["stderrTail"] = result.stderr_tail
                return gate_result
            if document_rule is not None:
                field, schema = document_rule
                raw_stdout = bytes(stdout_capture or b"")
                document: Any = None
                if raw_stdout.endswith(b"\n") and raw_stdout.count(b"\n") == 1:
                    try:
                        document = json.loads(raw_stdout[:-1])
                    except (ValueError, UnicodeError):
                        document = None
                if (
                    not isinstance(document, dict)
                    or document.get("schema") != schema
                    or (json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii") != raw_stdout
                ):
                    return {
                        **gate_result,
                        "state": "failed",
                        "errorCode": "gate_result_document_invalid",
                    }
                gate_result[field] = document
            after_sha, after_command_sha = self._input_identity(spec, deadline)
            if after_sha != input_sha or after_command_sha != command_sha:
                gate_result["state"] = "failed"
                gate_result["errorCode"] = "gate_input_changed"
                return gate_result
            if spec.cacheable:
                self._publish_record(spec, input_sha, command_sha)
            return gate_result
        except GateInputError as exc:
            return {
                "state": "failed",
                "cacheHit": False,
                "inputSha256": input_sha,
                "durationMs": max(0, int((time.monotonic() - started) * 1000)),
                "errorCode": str(exc),
            }
        finally:
            if runtime_mutating:
                self._runtime_mutation_lock.release()
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    @staticmethod
    def _emit(
        progress: Callable[[Mapping[str, Any]], None] | None,
        gate: str,
        state: str,
        detail: str,
    ) -> None:
        if progress is None:
            return
        progress(
            {
                "schema": _PROGRESS_SCHEMA,
                "command": "gates",
                "phase": gate,
                "state": state,
                "durationMs": 0,
                "detail": detail if _SAFE_NAME.fullmatch(detail) else "gate-output",
            }
        )

    def _closure(self, targets: Iterable[str]) -> set[str]:
        selected: set[str] = set()

        def add(name: str) -> None:
            if name not in self.specs:
                raise ValueError("gate_unknown")
            if name in selected:
                return
            selected.add(name)
            for dependency in self.specs[name].dependencies:
                add(dependency)

        for target in targets:
            add(target)
        return selected

    def run(
        self,
        targets: Sequence[str],
        *,
        fresh: bool = False,
        deadline: float | None = None,
        progress: Callable[[Mapping[str, Any]], None] | None = None,
        cancelled: Event | None = None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        absolute_deadline = deadline if deadline is not None else started + 3600.0
        try:
            self._prepare_private_trees()
            selected = self._closure(targets)
        except (GateInputError, ValueError) as exc:
            return {
                "schema": GATE_SCHEMA,
                "ok": False,
                "fresh": fresh,
                "gates": {},
                "failedGate": None,
                "errorCode": str(exc),
                "durationMs": max(0, int((time.monotonic() - started) * 1000)),
                "nextActions": ["repair-gate-catalog-or-private-cache"],
            }
        pending = set(selected)
        results: dict[str, dict[str, Any]] = {}
        running: dict[Future[dict[str, Any]], str] = {}
        last_heartbeat = started
        with ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="xenoid-gate") as pool:
            if cancelled is not None and cancelled.is_set():
                for name in sorted(pending):
                    results[name] = {"state": "cancelled", "cacheHit": False, "inputSha256": None, "durationMs": 0, "errorCode": "gate_cancelled"}
                pending.clear()
            while pending or running:
                if cancelled is not None and cancelled.is_set() and pending:
                    for name in sorted(pending):
                        results[name] = {"state": "cancelled", "cacheHit": False, "inputSha256": None, "durationMs": 0, "errorCode": "gate_cancelled"}
                    pending.clear()
                made_progress = True
                while made_progress:
                    made_progress = False
                    for name in sorted(tuple(pending)):
                        dependencies = self.specs[name].dependencies
                        if any(results.get(dep, {}).get("state") in {"failed", "blocked", "timed_out", "cancelled"} for dep in dependencies):
                            results[name] = {
                                "state": "blocked",
                                "cacheHit": False,
                                "inputSha256": None,
                                "durationMs": 0,
                                "errorCode": "gate_dependency_failed",
                            }
                            pending.remove(name)
                            self._emit(progress, name, "failed", "dependency-failed")
                            made_progress = True
                            continue
                        if not all(results.get(dep, {}).get("state") == "passed" for dep in dependencies):
                            continue
                        if len(running) >= self.max_workers:
                            break
                        pending.remove(name)
                        self._emit(progress, name, "started", "executing")
                        future = pool.submit(
                            self._run_one,
                            self.specs[name],
                            fresh=fresh,
                            deadline=absolute_deadline,
                            progress=progress,
                            cancelled=cancelled,
                            dependency_results={dep: results[dep] for dep in dependencies},
                        )
                        running[future] = name
                        made_progress = True
                if not running:
                    if pending:
                        for name in sorted(pending):
                            results[name] = {
                                "state": "blocked",
                                "cacheHit": False,
                                "inputSha256": None,
                                "durationMs": 0,
                                "errorCode": "gate_dependency_unresolved",
                            }
                        pending.clear()
                    break
                completed, _ = wait(
                    tuple(running),
                    timeout=max(0.0, min(0.25, absolute_deadline - time.monotonic())),
                    return_when=FIRST_COMPLETED,
                )
                for future in completed:
                    name = running.pop(future)
                    try:
                        result = future.result()
                    except Exception:
                        result = {
                            "state": "failed",
                            "cacheHit": False,
                            "inputSha256": None,
                            "durationMs": 0,
                            "errorCode": "gate_runner_failed",
                        }
                    results[name] = result
                    self._emit(
                        progress,
                        name,
                        "passed" if result.get("state") == "passed" else "failed",
                        "cache-hit" if result.get("cacheHit") else str(result.get("state")),
                    )
                now = time.monotonic()
                if now - last_heartbeat >= 5.0:
                    self._emit(progress, "gate-runner", "running", "running")
                    last_heartbeat = now
                if now >= absolute_deadline and pending:
                    for name in sorted(pending):
                        results[name] = {
                            "state": "timed_out",
                            "cacheHit": False,
                            "inputSha256": None,
                            "durationMs": 0,
                            "errorCode": "gate_deadline_exceeded",
                        }
                    pending.clear()
        ordered = {name: results[name] for name in sorted(results)}
        self._budget_failure_tails(ordered)
        failed = next(
            (
                name
                for name in sorted(selected)
                if ordered.get(name, {}).get("state") != "passed"
            ),
            None,
        )
        return {
            "schema": GATE_SCHEMA,
            "ok": failed is None,
            "fresh": fresh,
            "gates": ordered,
            "failedGate": failed,
            "durationMs": max(0, int((time.monotonic() - started) * 1000)),
            "nextActions": [] if failed is None else [f"rerun-gate:{failed}"],
        }

    @staticmethod
    def _budget_failure_tails(results: Mapping[str, dict[str, Any]]) -> None:
        remaining = _FAILURE_BUDGET
        for name in sorted(results):
            result = results[name]
            for field in ("stderrTail", "stdoutTail"):
                value = result.get(field)
                if not isinstance(value, str):
                    continue
                encoded = value.encode("utf-8")
                if remaining <= 0:
                    result.pop(field, None)
                    continue
                retained = encoded[-remaining:].decode("utf-8", "ignore")
                result[field] = retained
                remaining -= len(retained.encode("utf-8"))

    def observe_profile(self, profile: str) -> dict[str, Any]:
        """Read and validate successful gate records without executing a gate."""
        started = time.monotonic()
        target = PROFILE_TARGETS.get(profile)
        if target is None:
            return {
                "schema": GATE_SCHEMA,
                "ok": False,
                "complete": False,
                "profile": profile,
                "gates": {},
                "failedGate": None,
                "errorCode": "gate_profile_invalid",
                "durationMs": 0,
            }
        try:
            self._validate_path_ancestry(self.cache_root)
            self._private_directory_observed(self.cache_root)
            self._private_directory_observed(self.cache_root / "v1")
            selected = self._closure((target,))
        except (GateInputError, ValueError) as exc:
            return {
                "schema": GATE_SCHEMA,
                "ok": False,
                "complete": False,
                "profile": profile,
                "gates": {},
                "failedGate": None,
                "errorCode": str(exc),
                "durationMs": max(0, int((time.monotonic() - started) * 1000)),
            }
        results: dict[str, dict[str, Any]] = {}
        pending = set(selected)
        deadline = time.monotonic() + 300.0
        while pending:
            progressed = False
            for name in sorted(tuple(pending)):
                spec = self.specs[name]
                if not all(dependency in results for dependency in spec.dependencies):
                    continue
                if spec.aggregate:
                    complete = all(
                        results[dependency].get("state") == "passed"
                        for dependency in spec.dependencies
                    )
                    results[name] = {
                        "state": "passed" if complete else "incomplete",
                        "cacheHit": False,
                        "inputSha256": None,
                        "durationMs": 0,
                        **({} if complete else {"errorCode": "gate_record_incomplete"}),
                    }
                elif not spec.cacheable:
                    results[name] = {
                        "state": "unavailable",
                        "cacheHit": False,
                        "inputSha256": None,
                        "durationMs": 0,
                        "errorCode": "gate_record_not_cacheable",
                    }
                else:
                    input_sha: str | None = None
                    try:
                        input_sha, command_sha = self._input_identity(spec, deadline)
                        record_parent = self._record_path(spec, input_sha).parent
                        self._validate_path_ancestry(record_parent)
                        self._private_directory_observed(record_parent)
                        present = self._load_record(spec, input_sha, command_sha)
                    except GateInputError as exc:
                        present = False
                        error = str(exc)
                    else:
                        error = "gate_record_missing"
                    results[name] = {
                        "state": "passed" if present else "missing",
                        "cacheHit": present,
                        "inputSha256": input_sha,
                        "durationMs": 0,
                        **({} if present else {"errorCode": error}),
                    }
                pending.remove(name)
                progressed = True
            if not progressed:
                for name in pending:
                    results[name] = {
                        "state": "incomplete",
                        "cacheHit": False,
                        "inputSha256": None,
                        "durationMs": 0,
                        "errorCode": "gate_record_incomplete",
                    }
                break
        ordered = {name: results[name] for name in sorted(results)}
        failed = next(
            (name for name in sorted(selected) if ordered[name]["state"] != "passed"),
            None,
        )
        return {
            "schema": GATE_SCHEMA,
            "ok": failed is None,
            "complete": failed is None,
            "profile": profile,
            "gates": ordered,
            "failedGate": failed,
            "durationMs": max(0, int((time.monotonic() - started) * 1000)),
        }

    def publish_full_evidence(
        self,
        report: Mapping[str, Any],
        *,
        deadline: float,
        cancelled: Event | None,
    ) -> bool:
        required = (
            "protection-runtime",
            "persistence-runtime",
            "dual-instance-runtime",
            "cellular-runtime",
            "camera-runtime",
            "google-runtime",
        )
        gates = report.get("gates")
        if (
            report.get("ok") is not True
            or not isinstance(gates, Mapping)
            or set(gates).issuperset(required) is not True
        ):
            return False
        evidence_gates = {}
        for name in required:
            value = gates.get(name)
            input_sha = value.get("inputSha256") if isinstance(value, Mapping) else None
            if (
                not isinstance(value, Mapping)
                or value.get("state") != "passed"
                or not isinstance(input_sha, str)
                or _HEX_64.fullmatch(input_sha) is None
            ):
                return False
            evidence_gates[name] = {"state": "passed", "inputSha256": input_sha}
        try:
            from .backend import RuntimeManager
            from .config import resolve_instance
            from .live_observe import LiveAcceptance

            context, config, lease = resolve_instance(
                os.environ.get("XENOID_INSTANCE"),
                project_root=self.project_root,
                env=os.environ,
                migrate_legacy=False,
            )
            manager = RuntimeManager(context, config, lease)
            acceptance = LiveAcceptance(manager).observe(
                manager,
                {},
                "gate-full-evidence",
                min(deadline, time.monotonic() + 300.0),
                None,
            )
        except Exception:
            return False
        observation = acceptance.get("observation")
        if (
            acceptance.get("ok") is not True
            or acceptance.get("observationValid") is not True
            or not isinstance(observation, Mapping)
        ):
            return False
        identity = {
            "instanceId": context.instance_id,
            "containerId": observation.get("containerId"),
            "imageId": observation.get("imageId"),
            "dataUuid": observation.get("dataUuid"),
            "rootfsUuid": observation.get("rootfsUuid"),
            "runtimeEpoch": observation.get("runtimeEpoch"),
            "protectionDigest": observation.get("protectionDigest"),
            "runtimeInventoryDigest": observation.get("runtimeInventoryDigest"),
            "runtimeInventoryCount": observation.get("runtimeInventoryCount"),
        }
        string_identity = {
            key: value
            for key, value in identity.items()
            if key != "runtimeInventoryCount"
        }
        if any(
            not isinstance(value, str) or not value
            for value in string_identity.values()
        ) or not (
            isinstance(identity["runtimeInventoryCount"], int)
            and not isinstance(identity["runtimeInventoryCount"], bool)
            and identity["runtimeInventoryCount"] >= 2
        ):
            return False
        evidence_key = hashlib.sha256(identity["instanceId"].encode("utf-8")).hexdigest()
        path = self.cache_root / f"full-live-evidence-{evidence_key}.json"
        data = {
            "schema": "dev.xenoid.full-live-evidence/v1",
            "instance": context.instance_name,
            "completedAt": int(time.time()),
            "identity": identity,
            "gates": evidence_gates,
        }
        encoded = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        temporary = path.parent / f".{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            _fsync = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(_fsync)
            finally:
                os.close(_fsync)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return True

    def publish_google_release_attestation(
        self,
        report: Mapping[str, Any],
    ) -> Optional[dict[str, Any]]:
        gates = report.get("gates")
        if report.get("ok") is not True or not isinstance(gates, Mapping):
            return None
        acceptance_gate = gates.get("google-release-acceptance")
        runtime_gate = gates.get("google-runtime")
        if not isinstance(acceptance_gate, Mapping) or not isinstance(runtime_gate, Mapping):
            return None
        acceptance = acceptance_gate.get("acceptance")
        runtime_input = runtime_gate.get("inputSha256")
        if (
            acceptance_gate.get("state") != "passed"
            or runtime_gate.get("state") != "passed"
            or not isinstance(acceptance, Mapping)
            or acceptance.get("schema") != GOOGLE_ACCEPTANCE_NORMALIZED_SCHEMA
            or not isinstance(runtime_input, str)
            or _HEX_64.fullmatch(runtime_input) is None
        ):
            return None
        required_keys = {
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
        if set(acceptance) != required_keys:
            return None
        canonical_acceptance = (
            json.dumps(acceptance, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        attestation = {key: value for key, value in acceptance.items() if key != "privateEvidenceSha256"}
        attestation["schema"] = GOOGLE_ATTESTATION_SCHEMA
        attestation["gateInputsSha256"] = {
            "google-runtime": runtime_input,
            "google-release-acceptance": hashlib.sha256(canonical_acceptance).hexdigest(),
        }
        encoded = (
            json.dumps(attestation, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        evidence_key = hashlib.sha256(encoded).hexdigest()
        directory = self.cache_root / "google-release-attestations"
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        path = directory / f"{evidence_key}.json"
        temporary = path.parent / f".{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            os.chmod(path, 0o600)
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return {"attestation": attestation, "path": str(path), "sha256": evidence_key}

    def observe_full_evidence(
        self,
        instance_name: str,
        instance_id: str,
        current_identity: Mapping[str, Any],
    ) -> dict[str, Any]:
        required = {
            "protection-runtime",
            "persistence-runtime",
            "dual-instance-runtime",
            "cellular-runtime",
            "camera-runtime",
            "google-runtime",
        }
        evidence_key = hashlib.sha256(instance_id.encode("utf-8")).hexdigest()
        path = self.cache_root / f"full-live-evidence-{evidence_key}.json"
        try:
            self._validate_path_ancestry(path.parent)
            self._private_directory_observed(path.parent)
            raw = self._read_private_file(path, maximum=64 * 1024)
            data = json.loads(raw)
        except (OSError, GateInputError, ValueError):
            return {"ok": False, "errorCode": "full_live_evidence_missing"}
        now = int(time.time())
        completed = data.get("completedAt") if isinstance(data, dict) else None
        if (
            not isinstance(data, dict)
            or set(data) != {"schema", "instance", "completedAt", "identity", "gates"}
            or data.get("schema") != "dev.xenoid.full-live-evidence/v1"
            or data.get("instance") != instance_name
            or not isinstance(completed, int)
            or isinstance(completed, bool)
            or not 0 <= now - completed <= 900
            or not isinstance(data.get("identity"), dict)
            or not isinstance(data.get("gates"), dict)
            or set(data["gates"]) != required
            or raw != (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        ):
            return {"ok": False, "errorCode": "full_live_evidence_invalid"}
        expected_identity = {
            "instanceId": instance_id,
            "containerId": current_identity.get("containerId"),
            "imageId": current_identity.get("imageId"),
            "dataUuid": current_identity.get("dataUuid"),
            "runtimeInventoryDigest": current_identity.get("runtimeInventoryDigest"),
            "runtimeInventoryCount": current_identity.get("runtimeInventoryCount"),
            "rootfsUuid": current_identity.get("rootfsUuid"),
            "runtimeEpoch": current_identity.get("runtimeEpoch"),
            "protectionDigest": current_identity.get("protectionDigest"),
        }
        if data["identity"] != expected_identity:
            return {"ok": False, "errorCode": "full_live_evidence_identity_mismatch"}
        for name in required:
            value = data["gates"][name]
            spec = self.specs.get(name)
            if spec is None or not isinstance(value, dict):
                return {"ok": False, "errorCode": "full_live_evidence_invalid"}
            try:
                input_sha, _ = self._input_identity(spec, time.monotonic() + 300)
            except GateInputError:
                return {"ok": False, "errorCode": "full_live_evidence_stale"}
            if value != {"state": "passed", "inputSha256": input_sha}:
                return {"ok": False, "errorCode": "full_live_evidence_stale"}
        return {"ok": True, **data}


    @staticmethod
    def _private_directory_observed(path: Path) -> None:
        try:
            info = path.lstat()
        except OSError as exc:
            raise GateInputError("gate_cache_missing") from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise GateInputError("gate_private_directory_invalid")

    def run_profile(
        self,
        profile: str,
        *,
        fresh: bool = False,
        deadline: float | None = None,
        progress: Callable[[Mapping[str, Any]], None] | None = None,
        cancelled: Event | None = None,
    ) -> dict[str, Any]:
        target = PROFILE_TARGETS.get(profile)
        if target is None:
            return {
                "schema": GATE_SCHEMA,
                "ok": False,
                "profile": profile,
                "fresh": fresh,
                "gates": {},
                "failedGate": None,
                "errorCode": "gate_profile_invalid",
                "durationMs": 0,
                "nextActions": ["select-a-known-gate-profile"],
            }
        result = self.run(
            [target], fresh=fresh, deadline=deadline, progress=progress, cancelled=cancelled
        )
        return {**result, "profile": profile}


def _progress_writer(value: Mapping[str, Any]) -> None:
    sys.stderr.write(json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n")
    sys.stderr.flush()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the canonical Xenoid gate DAG")
    parser.add_argument(
        "profile",
        choices=tuple(PROFILE_TARGETS),
        nargs="?",
        default="verify",
    )
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--deadline-seconds", type=int)
    profile_budgets = {
        "verify": 3600,
        "static": 3600,
        "runtime": 7200,
        "full": 10800,
        "doctor": 300,
        "doctor-full": 300,
        "release": 7200,
        "release-google": 21600,
        "audit": 7200,
    }
    args = parser.parse_args(argv)
    requested_deadline = args.deadline_seconds or profile_budgets[args.profile]
    deadline_seconds = max(1, min(requested_deadline, 24 * 60 * 60))
    cancelled = Event()
    previous_handlers = {}
    for handled_signal in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[handled_signal] = signal.getsignal(handled_signal)
        signal.signal(handled_signal, lambda _signum, _frame: cancelled.set())
    runner = GateRunner(Path(__file__).resolve().parents[2])
    absolute_deadline = time.monotonic() + deadline_seconds
    try:
        report = runner.run_profile(
            args.profile,
            fresh=args.fresh,
            deadline=absolute_deadline,
            progress=_progress_writer,
            cancelled=cancelled,
        )
        if args.profile == "full" and args.fresh and report.get("ok") is True:
            if not runner.publish_full_evidence(
                report,
                deadline=absolute_deadline,
                cancelled=cancelled,
            ):
                report = {
                    **report,
                    "ok": False,
                    "failedGate": "full-live-evidence",
                    "errorCode": "full_live_evidence_unavailable",
                }
        if args.profile == "release-google" and args.fresh and report.get("ok") is True:
            published = runner.publish_google_release_attestation(report)
            if published is None:
                report = {
                    **report,
                    "ok": False,
                    "failedGate": "google-release-attestation",
                    "errorCode": "google_release_attestation_unavailable",
                }
            else:
                report = {
                    **report,
                    "googleReleaseAttestation": {
                        "path": published["path"],
                        "sha256": published["sha256"],
                    },
                }
    finally:
        for handled_signal, previous in previous_handlers.items():
            signal.signal(handled_signal, previous)
    schema = (
        VERIFY_SCHEMA
        if args.profile == "verify"
        else CI_SCHEMA
        if args.profile in {"static", "runtime", "full"}
        else GATE_SCHEMA
    )
    report = {**report, "schema": schema}
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
