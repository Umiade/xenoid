#!/usr/bin/env python3
"""Runtime-free contracts for the incremental artifact builder.

Every behavioral case uses a temporary catalog and synthetic output bytes.  No
repository build wrapper or compiler is invoked.
"""
from __future__ import annotations

import ast
import dataclasses
import json
import multiprocessing
import os
import stat
import struct
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid import artifacts  # noqa: E402

Case = Callable[[], None]
CASES: dict[str, Case] = {}
HEX_64 = set("0123456789abcdef")


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


def source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def result_entry(result: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    require(result.get("schema") == "dev.xenoid.artifacts/v1", "wrong result schema")
    entries = result.get("targets")
    require(isinstance(entries, Mapping), "result targets missing")
    entry = entries.get(name)
    require(isinstance(entry, Mapping), f"result missing target {name}")
    duration = entry.get("durationMs", entry.get("duration"))
    require(isinstance(duration, (int, float)) and duration >= 0,
            f"invalid duration for {name}")
    return entry


def expect_status(
    result: Mapping[str, Any], name: str, status: str, code: str | None = None
) -> Mapping[str, Any]:
    entry = result_entry(result, name)
    require(entry.get("status") == status,
            f"{name}: expected {status}, got {entry.get('status')}")
    if code is not None:
        require(entry.get("code") == code,
                f"{name}: expected {code}, got {entry.get('code')}")
    return entry


def assert_manifest(result: Mapping[str, Any]) -> str:
    digest = result.get("manifestSha256")
    require(isinstance(digest, str) and len(digest) == 64 and set(digest) <= HEX_64,
            "invalid aggregate manifest digest")
    return digest


def make_target(
    name: str,
    *,
    output_directory: str | None = None,
    outputs: tuple[artifacts.OutputSpec, ...] | None = None,
    dependencies: tuple[str, ...] = (),
    cpu_slots: int = 1,
    environment: tuple[str, ...] = (),
    sources: tuple[str, ...] | None = None,
    tools: tuple[str, ...] | None = None,
    command: tuple[str, ...] | None = None,
) -> artifacts.BuildTarget:
    directory = output_directory or f"out/{name}"
    return artifacts.BuildTarget(
        name=name,
        command=command if command is not None else ("contract-builder", name),
        sources=sources if sources is not None else (f"source/{name}.txt",),
        outputs=outputs if outputs is not None else (
            artifacts.OutputSpec(f"{directory}/{name}.bin", 0o755),
        ),
        output_directory=directory,
        dependencies=dependencies,
        cpu_slots=cpu_slots,
        tools=tools if tools is not None else (f"tool/{name}.tool",),
        environment=environment,
    )


def initialize_inputs(root: Path, catalog: Mapping[str, artifacts.BuildTarget]) -> None:
    for target in catalog.values():
        for relative in (*target.sources, *target.tools):
            path = Path(relative)
            if path.is_absolute():
                continue
            full = root / path
            full.parent.mkdir(parents=True, exist_ok=True)
            if not full.exists():
                full.write_bytes((relative + "\n").encode())


class FakeRunner:
    """In-memory command peer which only writes declared temporary outputs."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.environments: list[dict[str, str]] = []
        self.recipes: dict[str, Callable[[Path, artifacts.BuildTarget], Any]] = {}
        self.payloads: dict[str, dict[str, bytes]] = {}
        self._lock = threading.Lock()

    def __call__(
        self,
        command: tuple[str, ...],
        *,
        cwd: Path,
        env: dict[str, str],
        target: artifacts.BuildTarget,
    ) -> subprocess.CompletedProcess[str]:
        with self._lock:
            self.calls.append(target.name)
            self.environments.append(dict(env))
        recipe = self.recipes.get(target.name)
        if recipe is not None:
            value = recipe(cwd, target)
            if isinstance(value, subprocess.CompletedProcess):
                return value
            if isinstance(value, Mapping):
                return subprocess.CompletedProcess(
                    command,
                    int(value.get("returncode", 0)),
                    str(value.get("stdout", "")),
                    str(value.get("stderr", "")),
                )
        target_payloads = self.payloads.get(target.name, {})
        for output in target.outputs:
            path = cwd / output.path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(target_payloads.get(output.path, (target.name + "\n").encode()))
            path.chmod(output.mode)
        return subprocess.CompletedProcess(command, 0, "contract stdout", "")


@contextmanager
def temporary_builder(
    catalog: Mapping[str, artifacts.BuildTarget],
    *,
    runner: FakeRunner | Callable[..., Any] | None = None,
    environment: Mapping[str, str] | None = None,
    max_workers: int = 4,
    cpu_slots: int | None = None,
) -> Iterator[tuple[Path, artifacts.ArtifactBuilder, Any]]:
    with tempfile.TemporaryDirectory(prefix="xenoid-artifact-contract-") as directory:
        root = Path(directory)
        initialize_inputs(root, catalog)
        selected_runner = runner or FakeRunner()
        builder = artifacts.ArtifactBuilder(
            root,
            dict(environment or {}),
            catalog=catalog,
            runner=selected_runner,
            max_workers=max_workers,
            cpu_slots=cpu_slots,
        )
        yield root, builder, selected_runner


def cache_record(root: Path, target: str) -> Path:
    return root / ".xenoid/cache/artifacts/v1" / f"{target}.json"


def record_and_object(root: Path, target: str) -> tuple[Path, Path, dict[str, Any]]:
    record_path = cache_record(root, target)
    record = json.loads(record_path.read_text(encoding="utf-8"))
    digest = record["outputs"][0]["sha256"]
    return record_path, root / ".xenoid/cache/artifacts/objects/sha256" / digest, record


def elf(machine: int) -> bytes:
    """Small structurally valid ELF64 PIE header sufficient for contract validation."""
    value = bytearray(64)
    value[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHI", value, 16, 3, machine, 1)
    struct.pack_into("<HHH", value, 52, 64, 56, 0)
    return bytes(value)


def function_text(relative: str, name: str) -> str:
    text = source(relative)
    tree = ast.parse(text, filename=relative)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            lines = text.splitlines()
            return "\n".join(lines[node.lineno - 1:node.end_lineno])
    raise ContractFailure(f"missing function {name} in {relative}")


@contract_case("exactCatalogAndVirtualDag")
def exact_catalog_and_virtual_dag() -> None:
    expected = (
        "daemon", "keymint", "input", "hide", "profile", "rootd", "netctl",
        "overlay", "zygote", "svcman", "sensorsHal", "gralloc", "hwcomposer",
        "cameraProvider", "ril", "radioConfig", "shimArm64", "pivot",
        "propArea", "ssaid", "proxySandbox",
    )
    require(artifacts.ALL_TARGETS == expected, "the exact 21 target names/order changed")
    require(tuple(artifacts.TARGETS) == expected, "TARGETS does not match ALL_TARGETS")
    require(len(set(artifacts.ALL_TARGETS)) == 21, "duplicate target name")
    require(dataclasses.is_dataclass(artifacts.BuildTarget), "BuildTarget is not a record")
    require(artifacts.BuildTarget.__dataclass_params__.frozen, "BuildTarget is mutable")
    require(artifacts.OutputSpec.__dataclass_params__.frozen, "OutputSpec is mutable")

    consumers = artifacts.CONSUMER_TARGETS
    require(set(consumers) == {"runtimeContext", "liveDeploy", "release"},
            "virtual consumer set changed")
    require(consumers["runtimeContext"] == (
        "daemon", "keymint", "input", "hide", "profile", "netctl", "overlay",
        "propArea", "pivot", "zygote", "svcman", "sensorsHal", "gralloc", "hwcomposer",
        "cameraProvider", "ril", "radioConfig",
    ), "runtimeContext dependency closure changed")
    require(consumers["liveDeploy"] ==
            ("daemon", "rootd", "shimArm64", "ssaid", "proxySandbox"),
            "liveDeploy dependency closure changed")
    require(consumers["release"] == expected, "release is not the full closure")

    expected_outputs = {
        "daemon": ("daemon/app/build/outputs/apk/debug/app-debug.apk",),
        "keymint": (
            "native/xenoid-keymint/xenoid-keymint",
            "native/xenoid-keymint/android.hardware.security.keymint.IKeyMintDevice.xml",
        ),
        "input": ("native/xenoid-input/xenoid-input",),
        "hide": ("native/xenoid-hide/xenoid-hide",),
        "profile": ("native/xenoid-profile/xenoid-profile",),
        "rootd": ("native/xenoid-rootd/xenoid-rootd-arm64",
                  "native/xenoid-rootd/xenoid-rootd-x86_64"),
        "netctl": ("native/xenoid-netctl/xenoid-netctl",),
        "overlay": ("native/xenoid-hide/xenoid-overlay",),
        "zygote": ("native/xenoid-zygote/libxenoid_zygote.so",),
        "svcman": ("native/xenoid-svcman/libxenoid_svcman.so",),
        "sensorsHal": (
            "native/xenoid-sensorshal/xenoid-sensorshal",
            "native/xenoid-sensorshal/android.hardware.sensors.ISensors.xml",
        ),
        "gralloc": ("native/xenoid-gralloc/gralloc.redroid.so",),
        "hwcomposer": ("native/xenoid-hwcomposer/hwcomposer.raven.so",),
        "cameraProvider": (
            "native/xenoid-camerahal/android.hardware.camera.provider-service-aidl",
            "native/xenoid-camerahal/android.hardware.camera.provider.ICameraProvider.xml",
            "native/xenoid-camerahal/media_profiles_V1_0.xml",
        ),
        "ril": (
            "native/xenoid-ril/libxenoid-ril.so",
            "native/xenoid-ril/xenoid-ril-profile-test",
            "native/xenoid-ril/android.hardware.radio.IRadio.xml",
        ),
        "radioConfig": (
            "native/xenoid-radio-config/android.hardware.radio.config-service.xenoid",
            "native/xenoid-radio-config/android.hardware.radio.config.IRadioConfig.xml",
        ),
        "shimArm64": ("native/xenoid-shim/libxenoid_shim-arm64.so",),
        "pivot": ("native/xenoid-pivot/xenoid-pivot",),
        "propArea": ("native/xenoid-hide/xenoid-prop-area",),
        "ssaid": ("native/xenoid-hide/xenoid-ssaid",),
        "proxySandbox":
            ("native/xenoid-proxy-sandbox/xenoid-proxy-sandbox",),
    }
    owners: dict[str, str] = {}
    for name in expected:
        target = artifacts.TARGETS[name]
        require(target.name == name, f"record/key mismatch for {name}")
        require(target.dependencies == (), f"source leaf {name} has a dependency")
        require(target.command and target.sources and target.outputs,
                f"incomplete target declaration for {name}")
        require(tuple(item.path for item in target.outputs) == expected_outputs[name],
                f"artifact format/output set changed for {name}")
        require(target.cpu_slots >= 1, f"invalid CPU cost for {name}")
        require(target.output_directory and not Path(target.output_directory).is_absolute(),
                f"unsafe output lock key for {name}")
        for relative in (*target.sources, *(item.path for item in target.outputs)):
            path = Path(relative)
            require(not path.is_absolute() and ".." not in path.parts,
                    f"unsafe closure path for {name}: {relative}")
        for output in target.outputs:
            require(output.path not in owners,
                    f"public output owned by both {owners.get(output.path)} and {name}")
            owners[output.path] = name
            if output.elf_machine is None:
                require(
                    output.mode == 0o644
                    and output.elf_type is None
                    and output.elf_class is None,
                    f"data artifact format changed for {output.path}",
                )
            else:
                expected_mode = 0o555 if name == "proxySandbox" else 0o755
                expected_machine = (
                    ("X86_64", "EM_X86_64")
                    if output.path.endswith("x86_64")
                    else ("AArch64", "EM_AARCH64")
                )
                require(output.mode == expected_mode and
                        output.elf_machine in expected_machine and
                        output.elf_class == 64,
                        f"mode/ELF architecture changed for {output.path}")
                if name == "pivot":
                    require(output.elf_type in ("EXEC", "ET_EXEC") and
                            output.interpreter is False,
                            "pivot is no longer a static ARM64 executable")
                elif name == "proxySandbox":
                    require(output.elf_type in ("DYN", "PIE", "ET_DYN") and
                            output.interpreter is False,
                            "proxy sandbox is no longer static Linux ARM64 PIE")
                else:
                    require(output.elf_type in ("PIE", "DYN", "ET_DYN"),
                            f"non-PIE artifact declaration: {output.path}")
    shared_hide = {name for name, target in artifacts.TARGETS.items()
                   if target.output_directory == "native/xenoid-hide"}
    require(shared_hide == {"hide", "overlay", "propArea", "ssaid"},
            "shared xenoid-hide serialization set is incomplete")


@contract_case("sourceToolEnvironmentInvalidation")
def source_tool_environment_invalidation() -> None:
    target = make_target("unit", environment=("CONTRACT_FEATURE",))
    catalog = {target.name: target}
    runner = FakeRunner()
    with temporary_builder(
        catalog, runner=runner, environment={"CONTRACT_FEATURE": "one"}
    ) as (root, builder, _):
        first = builder.ensure(("unit",))
        expect_status(first, "unit", "built")
        first_manifest = assert_manifest(first)
        expect_status(builder.ensure(("unit",)), "unit", "reused")
        require(runner.calls == ["unit"], "warm reuse launched a child")

        (root / target.sources[0]).write_text("source changed\n", encoding="utf-8")
        source_result = builder.ensure(("unit",))
        expect_status(source_result, "unit", "built")
        require(assert_manifest(source_result) != first_manifest,
                "source bytes did not invalidate input identity")

        (root / target.tools[0]).write_text("tool changed\n", encoding="utf-8")
        tool_result = builder.ensure(("unit",))
        expect_status(tool_result, "unit", "built")
        tool_manifest = assert_manifest(tool_result)

        env_builder = artifacts.ArtifactBuilder(
            root, {"CONTRACT_FEATURE": "two"}, catalog=catalog, runner=runner,
            max_workers=4, cpu_slots=2,
        )
        env_result = env_builder.ensure(("unit",))
        expect_status(env_result, "unit", "built")
        require(assert_manifest(env_result) != tool_manifest,
                "allowlisted environment did not invalidate input identity")
        source_path = root / target.sources[0]
        link_target = source_path.parent / "unit-link-target.txt"
        link_target.write_text("linked source one\n", encoding="utf-8")
        source_path.unlink()
        source_path.symlink_to(link_target.name)
        linked_result = env_builder.ensure(("unit",))
        expect_status(linked_result, "unit", "built")
        linked_manifest = assert_manifest(linked_result)
        link_target.write_text("linked source two\n", encoding="utf-8")
        linked_target_result = env_builder.ensure(("unit",))
        expect_status(linked_target_result, "unit", "built")
        require(
            assert_manifest(linked_target_result) != linked_manifest,
            "in-project symlink target bytes did not invalidate identity",
        )
        require(runner.calls == ["unit"] * 6,
                "source/tool/environment/symlink invalidation did not rebuild exactly once")
        require(all(value.get("LC_ALL") == "C" and value.get("TZ") == "UTC" and
                    value.get("SOURCE_DATE_EPOCH") == "0" and
                    value.get("PYTHONHASHSEED") == "0" and
                    value.get("XENOID_BUILD_JOBS") == "1" and
                    value.get("XENOID_FORCE_REBUILD") == "1"
                    for value in runner.environments),
                "deterministic environment or nested rebuild allocation was not forced")


@contract_case("sharedLockParentCompatibility")
def shared_lock_parent_compatibility() -> None:
    target = make_target("unit")
    with tempfile.TemporaryDirectory(prefix="xenoid-artifact-lock-parent-") as directory:
        root = Path(directory)
        initialize_inputs(root, {"unit": target})
        gate_locks = root / ".xenoid" / "locks" / "gates"
        gate_locks.mkdir(mode=0o700, parents=True)
        gate_locks.chmod(0o700)
        shared_parent = gate_locks.parent
        shared_parent.chmod(0o755)

        artifacts.ArtifactBuilder(
            root,
            catalog={"unit": target},
            runner=FakeRunner(),
        )

        info = (shared_parent / "artifacts").lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            "artifact locks were not safely created below the shared lock parent",
        )


@contract_case("successfulReuseSnapshotAndRematerialization")
def successful_reuse_snapshot_and_rematerialization() -> None:
    target = make_target("unit")
    catalog = {"unit": target}
    runner = FakeRunner()
    payload = b"immutable artifact bytes\n"
    runner.payloads["unit"] = {target.outputs[0].path: payload}
    with temporary_builder(catalog, runner=runner) as (root, builder, _):
        first = builder.ensure(("unit",))
        expect_status(first, "unit", "built")
        manifest = assert_manifest(first)
        record_path, object_path, _record = record_and_object(root, "unit")
        private_directories = (
            root / ".xenoid/cache/artifacts",
            root / ".xenoid/cache/artifacts/v1",
            root / ".xenoid/cache/artifacts/objects",
            root / ".xenoid/cache/artifacts/objects/sha256",
            root / ".xenoid/locks/artifacts",
        )
        for directory in private_directories:
            info = directory.lstat()
            require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
                    info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    f"artifact private directory is unsafe: {directory.name}")
        for private_file in (record_path, object_path):
            info = private_file.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                    info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                    f"artifact private file is unsafe: {private_file.name}")
        output = root / target.outputs[0].path
        output.unlink()
        reused = builder.ensure(("unit",))
        expect_status(reused, "unit", "reused")
        require(assert_manifest(reused) == manifest, "reuse changed aggregate identity")
        require(output.read_bytes() == payload, "missing public output was not rematerialized")
        require(stat.S_IMODE(output.stat().st_mode) == 0o755,
                "rematerialized output mode is wrong")
        require(runner.calls == ["unit"], "rematerialization launched a build")

        snapshot = builder.snapshot(("unit",))
        require(dataclasses.is_dataclass(snapshot), "snapshot is not a validated record object")
        require(snapshot.__dataclass_params__.frozen, "snapshot is mutable")
        output.write_bytes(b"mutable public poison")
        stage_root = root / "staged"
        staged = builder.stage(snapshot, stage_root)
        require(staged.get("ok") is True, "snapshot stage failed")
        require(staged.get("manifestSha256") == manifest, "stage changed snapshot digest")
        require((stage_root / target.outputs[0].path).read_bytes() == payload,
                "stage read mutable public output instead of immutable object")

    other_runner = FakeRunner()
    other_runner.payloads["unit"] = {target.outputs[0].path: payload}
    with temporary_builder(catalog, runner=other_runner) as (_root, other_builder, _):
        other = other_builder.ensure(("unit",))
        expect_status(other, "unit", "built")
        require(assert_manifest(other) == manifest,
                "aggregate digest included absolute path, completion time, or logs")


class SchedulingRunner(FakeRunner):
    def __init__(self, release: threading.Event) -> None:
        super().__init__()
        self.release = release
        self.started: dict[str, threading.Event] = {}
        self.active_slots = 0
        self.peak_slots = 0
        self.active_count = 0
        self.peak_count = 0

    def event(self, name: str) -> threading.Event:
        return self.started.setdefault(name, threading.Event())

    def __call__(self, command: tuple[str, ...], *, cwd: Path,
                 env: dict[str, str], target: artifacts.BuildTarget
                 ) -> subprocess.CompletedProcess[str]:
        with self._lock:
            self.calls.append(target.name)
            self.environments.append(dict(env))
            self.active_slots += target.cpu_slots
            self.active_count += 1
            self.peak_slots = max(self.peak_slots, self.active_slots)
            self.peak_count = max(self.peak_count, self.active_count)
            self.event(target.name).set()
        require(self.release.wait(5), "scheduler probe was not released")
        try:
            for output in target.outputs:
                path = cwd / output.path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((target.name + "\n").encode())
                path.chmod(output.mode)
            return subprocess.CompletedProcess(command, 0, "", "")
        finally:
            with self._lock:
                self.active_slots -= target.cpu_slots
                self.active_count -= 1


def run_ensure_thread(
    builder: artifacts.ArtifactBuilder, targets: tuple[str, ...]
) -> tuple[threading.Thread, dict[str, Any]]:
    outcome: dict[str, Any] = {}

    def invoke() -> None:
        try:
            outcome["result"] = builder.ensure(targets)
        except BaseException as exc:  # surfaced by the controlling test thread
            outcome["error"] = exc

    thread = threading.Thread(target=invoke, name="artifact-contract-ensure", daemon=True)
    thread.start()
    return thread, outcome


def finish_ensure_thread(thread: threading.Thread, outcome: Mapping[str, Any]) -> Mapping[str, Any]:
    thread.join(10)
    require(not thread.is_alive(), "artifact ensure deadlocked")
    if "error" in outcome:
        raise outcome["error"]
    result = outcome.get("result")
    require(isinstance(result, Mapping), "ensure thread returned no result")
    return result


@contract_case("outputDirectorySerializationIndependentParallelismAndCpuCap")
def output_directory_serialization_independent_parallelism_and_cpu_cap() -> None:
    # Same output directory: the second runner may not enter before the first exits.
    shared_a = make_target("sharedA", output_directory="out/shared")
    shared_b = make_target("sharedB", output_directory="out/shared")
    shared_catalog = {target.name: target for target in (shared_a, shared_b)}
    release = threading.Event()
    shared_runner = SchedulingRunner(release)
    with temporary_builder(shared_catalog, runner=shared_runner, cpu_slots=4) as (_, builder, _):
        thread, outcome = run_ensure_thread(builder, ("sharedA", "sharedB"))
        started = shared_runner.event("sharedA")
        other = shared_runner.event("sharedB")
        if not started.wait(2):
            started, other = other, started
        require(started.is_set(), "no shared-directory target started")
        require(not other.wait(0.15), "shared output-directory commands overlapped")
        release.set()
        result = finish_ensure_thread(thread, outcome)
        expect_status(result, "sharedA", "built")
        expect_status(result, "sharedB", "built")
        require(shared_runner.peak_count == 1, "output lock admitted concurrent commands")

    # Disjoint directories overlap.
    independent = {name: make_target(name) for name in ("left", "right")}
    release = threading.Event()
    parallel_runner = SchedulingRunner(release)
    with temporary_builder(independent, runner=parallel_runner, cpu_slots=4) as (_, builder, _):
        thread, outcome = run_ensure_thread(builder, ("left", "right"))
        require(parallel_runner.event("left").wait(2), "left did not start")
        require(parallel_runner.event("right").wait(2), "independent target did not overlap")
        require(parallel_runner.peak_count == 2, "independent work was serialized")
        release.set()
        result = finish_ensure_thread(thread, outcome)
        expect_status(result, "left", "built")
        expect_status(result, "right", "built")

    # The worker pool remains bounded at four even when CPU capacity is larger.
    capped = {f"job{index}": make_target(f"job{index}") for index in range(5)}
    release = threading.Event()
    capped_runner = SchedulingRunner(release)
    with temporary_builder(
        capped, runner=capped_runner, max_workers=4, cpu_slots=8
    ) as (_, builder, _):
        thread, outcome = run_ensure_thread(builder, tuple(capped))
        for index in range(4):
            require(capped_runner.event(f"job{index}").wait(2),
                    f"worker slot {index} did not start")
        require(not capped_runner.event("job4").wait(0.15),
                "more than four build workers entered")
        require(capped_runner.peak_count == 4, "worker cap prevented safe parallelism")
        release.set()
        result = finish_ensure_thread(thread, outcome)
        for name in capped:
            expect_status(result, name, "built")

    # A three-slot budget admits one cost-2 and one cost-1 target, never both cost-2 jobs.
    budget_catalog = {
        "heavyA": make_target("heavyA", cpu_slots=2),
        "heavyB": make_target("heavyB", cpu_slots=2),
        "light": make_target("light", cpu_slots=1),
    }
    release = threading.Event()
    budget_runner = SchedulingRunner(release)
    with temporary_builder(
        budget_catalog, runner=budget_runner, max_workers=3, cpu_slots=3
    ) as (_, builder, _):
        thread, outcome = run_ensure_thread(builder, tuple(budget_catalog))
        require(budget_runner.event("light").wait(2), "light target did not use spare slot")
        require(budget_runner.event("heavyA").wait(0.1) or
                budget_runner.event("heavyB").wait(2), "no heavy target started")
        require(budget_runner.peak_slots <= 3, "CPU slot budget was exceeded")
        require(budget_runner.peak_count == 2, "CPU slots did not permit safe parallelism")
        started_heavy = sum(event.is_set() for name, event in budget_runner.started.items()
                            if name.startswith("heavy"))
        require(started_heavy == 1, "both cost-2 jobs entered a three-slot budget")
        release.set()
        result = finish_ensure_thread(thread, outcome)
        for name in budget_catalog:
            expect_status(result, name, "built")
        require(budget_runner.peak_slots <= 3, "CPU budget exceeded after release")
        allocations = {
            name: value.get("XENOID_BUILD_JOBS")
            for name, value in zip(budget_runner.calls, budget_runner.environments)
        }
        require(allocations == {"heavyA": "2", "heavyB": "2", "light": "1"},
                f"nested compiler allocations did not match CPU slots: {allocations}")


@contract_case("unsafeRecordsObjectsAndPublicOutputsAreRejected")
def unsafe_records_objects_and_public_outputs_are_rejected() -> None:
    poison_kinds = (
        "record-malformed", "record-symlink", "record-hardlink", "record-mode",
        "object-symlink", "object-hardlink", "object-mode",
    )
    for kind in poison_kinds:
        target = make_target("unit")
        catalog = {"unit": target}
        runner = FakeRunner()
        with temporary_builder(catalog, runner=runner) as (root, builder, _):
            expect_status(builder.ensure(("unit",)), "unit", "built")
            record_path, object_path, _record = record_and_object(root, "unit")
            if kind.startswith("record-"):
                victim = record_path
            else:
                victim = object_path
            if kind.endswith("malformed"):
                victim.write_text("{not-json", encoding="utf-8")
                victim.chmod(0o600)
            elif kind.endswith("symlink"):
                external = root / f"{kind}.external"
                external.write_bytes(victim.read_bytes())
                external.chmod(0o600)
                victim.unlink()
                victim.symlink_to(external)
            elif kind.endswith("hardlink"):
                external = root / f"{kind}.external"
                external.write_bytes(victim.read_bytes())
                external.chmod(0o600)
                victim.unlink()
                os.link(external, victim)
            elif kind.endswith("mode"):
                victim.chmod(0o644)
            result = builder.ensure(("unit",))
            expect_status(result, "unit", "built")
            require(runner.calls == ["unit", "unit"],
                    f"unsafe cache entry was reused: {kind}")
            rebuilt_record, rebuilt_object, _ = record_and_object(root, "unit")
            for rebuilt, mode in ((rebuilt_record, 0o600), (rebuilt_object, 0o600)):
                info = rebuilt.lstat()
                require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
                        info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode,
                        f"unsafe entry not replaced after {kind}")

    # Mutable public paths are not trusted, but a valid object can repair them without a build.
    for kind in ("symlink", "hardlink", "mode"):
        target = make_target("unit")
        catalog = {"unit": target}
        runner = FakeRunner()
        with temporary_builder(catalog, runner=runner) as (root, builder, _):
            expect_status(builder.ensure(("unit",)), "unit", "built")
            public = root / target.outputs[0].path
            expected = public.read_bytes()
            if kind == "symlink":
                external = root / "public.external"
                external.write_bytes(b"poison")
                public.unlink()
                public.symlink_to(external)
            elif kind == "hardlink":
                external = root / "public.external"
                external.write_bytes(expected)
                public.unlink()
                os.link(external, public)
            else:
                public.chmod(0o700)
            expect_status(builder.ensure(("unit",)), "unit", "reused")
            info = public.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                    stat.S_IMODE(info.st_mode) == 0o755 and public.read_bytes() == expected,
                    f"unsafe public {kind} was not atomically rematerialized")
            require(runner.calls == ["unit"], "public repair launched a compiler")

    # Architecture is checked both at build publication and on public rematerialization.
    output = artifacts.OutputSpec("out/elf/probe", 0o755,
                                  elf_machine="AArch64", elf_type="PIE", elf_class=64)
    target = make_target("elf", output_directory="out/elf", outputs=(output,))
    runner = FakeRunner()
    runner.payloads["elf"] = {output.path: elf(62)}  # EM_X86_64
    with temporary_builder({"elf": target}, runner=runner) as (root, builder, _):
        failed = builder.ensure(("elf",))
        expect_status(failed, "elf", "failed", "artifact_output_invalid")
        require(not cache_record(root, "elf").exists(), "wrong-arch output was published")

    runner = FakeRunner()
    runner.payloads["elf"] = {output.path: elf(183)}  # EM_AARCH64
    with temporary_builder({"elf": target}, runner=runner) as (root, builder, _):
        expect_status(builder.ensure(("elf",)), "elf", "built")
        public = root / output.path
        public.write_bytes(elf(62))
        public.chmod(0o755)
        expect_status(builder.ensure(("elf",)), "elf", "reused")
        require(struct.unpack_from("<H", public.read_bytes(), 18)[0] == 183,
                "wrong-arch public output was not rejected/rematerialized")
        require(runner.calls == ["elf"], "architecture repair launched a build")


@contract_case("forcedNondeterminismPreservesPriorPublication")
def forced_nondeterminism_preserves_prior_publication() -> None:
    target = make_target("unit")
    runner = FakeRunner()
    runner.payloads["unit"] = {target.outputs[0].path: b"first deterministic bytes"}
    with temporary_builder({"unit": target}, runner=runner) as (root, builder, _):
        first = builder.ensure(("unit",))
        expect_status(first, "unit", "built")
        manifest = assert_manifest(first)
        record_path, object_path, _ = record_and_object(root, "unit")
        record_bytes = record_path.read_bytes()
        object_bytes = object_path.read_bytes()
        runner.payloads["unit"] = {target.outputs[0].path: b"different bytes, same input"}
        forced = builder.ensure(("unit",), force=True)
        expect_status(forced, "unit", "failed", "artifact_nondeterministic")
        require(runner.environments[-1].get("XENOID_FORCE_REBUILD") == "1",
                "forced ensure did not select the wrapper's forced rebuild mode")
        require(record_path.read_bytes() == record_bytes,
                "nondeterministic build replaced the prior record")
        require(object_path.read_bytes() == object_bytes,
                "nondeterministic build replaced the prior object")
        require((root / target.outputs[0].path).read_bytes() == object_bytes,
                "nondeterministic build did not restore public last-known-good bytes")
        require(assert_manifest(builder.ensure(("unit",))) == manifest,
                "failed force changed the published aggregate identity")


@contract_case("inputDriftDuringBuildPublishesNothing")
def input_drift_during_build_publishes_nothing() -> None:
    target = make_target("unit")
    runner = FakeRunner()

    def drift(cwd: Path, record: artifacts.BuildTarget) -> Mapping[str, Any]:
        (cwd / record.sources[0]).write_text("changed while child ran\n", encoding="utf-8")
        output = cwd / record.outputs[0].path
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(b"unpublishable")
        output.chmod(record.outputs[0].mode)
        return {"returncode": 0, "stdout": "", "stderr": ""}

    runner.recipes["unit"] = drift
    with temporary_builder({"unit": target}, runner=runner) as (root, builder, _):
        result = builder.ensure(("unit",))
        expect_status(result, "unit", "failed", "artifact_input_changed_during_build")
        require(not cache_record(root, "unit").exists(), "drifted input published a record")
        object_root = root / ".xenoid/cache/artifacts/objects/sha256"
        require(not object_root.exists() or not any(object_root.iterdir()),
                "drifted input imported an immutable object")


@contract_case("partialCommandRollbackAndBlockedDependents")
def partial_command_rollback_and_blocked_dependents() -> None:
    outputs = (
        artifacts.OutputSpec("out/shared/a-one", 0o755),
        artifacts.OutputSpec("out/shared/a-two", 0o755),
    )
    target_a = make_target("a", output_directory="out/shared", outputs=outputs)
    target_b = make_target(
        "b", output_directory="out/shared",
        outputs=(artifacts.OutputSpec("out/shared/b", 0o755),),
    )
    runner = FakeRunner()
    with temporary_builder({"a": target_a, "b": target_b}, runner=runner) as (root, builder, _):
        initial = builder.ensure(("a", "b"))
        expect_status(initial, "a", "built")
        expect_status(initial, "b", "built")
        prior = {output.path: (root / output.path).read_bytes()
                 for target in (target_a, target_b) for output in target.outputs}

        def destructive_failure(cwd: Path, _target: artifacts.BuildTarget) -> Mapping[str, Any]:
            (cwd / outputs[0].path).write_bytes(b"partial replacement")
            (cwd / outputs[1].path).unlink()
            (cwd / target_b.outputs[0].path).unlink()
            return {"returncode": 9, "stdout": "partial", "stderr": "failed"}

        runner.recipes["a"] = destructive_failure
        failed = builder.ensure(("a",), force=True)
        expect_status(failed, "a", "failed", "artifact_build_failed")
        for relative, expected in prior.items():
            require((root / relative).read_bytes() == expected,
                    f"shared-directory rollback omitted {relative}")

    base = make_target("base")
    leaf = make_target("leaf", dependencies=("base",))
    independent = make_target("independent")
    runner = FakeRunner()
    runner.recipes["base"] = lambda _cwd, _target: {
        "returncode": 1, "stdout": "", "stderr": "base failed"
    }
    dependency_catalog = {
        "base": base, "leaf": leaf, "independent": independent,
    }
    with temporary_builder(dependency_catalog, runner=runner) as (_, builder, _):
        result = builder.ensure(("leaf", "independent"))
        expect_status(result, "base", "failed", "artifact_build_failed")
        expect_status(result, "leaf", "blocked", "artifact_dependency_failed")
        expect_status(result, "independent", "built")
        require("leaf" not in runner.calls and set(runner.calls) == {"base", "independent"},
                "dependency failure blocked independent work or launched its dependent")


def collect_tails(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(child, str) and any(word in str(key).lower()
                                               for word in ("tail", "stdout", "stderr", "log")):
                found.append((path, child))
            else:
                found.extend(collect_tails(child, path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            found.extend(collect_tails(child, f"{prefix}[{index}]"))
    return found


@contract_case("failedTailsShareDeterministic64KiBBudget")
def failed_tails_share_deterministic_64kib_budget() -> None:
    catalog = {name: make_target(name) for name in ("alpha", "beta", "gamma")}

    def capture() -> list[tuple[str, str]]:
        runner = FakeRunner()
        for index, name in enumerate(catalog):
            runner.recipes[name] = lambda _cwd, _target, index=index: {
                "returncode": 1,
                "stdout": chr(ord("A") + index) * 50000,
                "stderr": chr(ord("a") + index) * 50000,
            }
        with temporary_builder(catalog, runner=runner, max_workers=3, cpu_slots=3) as (
            _root, builder, _runner
        ):
            result = builder.ensure(tuple(catalog))
            for name in catalog:
                expect_status(result, name, "failed", "artifact_build_failed")
            tails = collect_tails(result.get("targets"))
            require(tails, "failed result retained no bounded diagnostic tail")
            require(sum(len(text.encode("utf-8")) for _path, text in tails) <= 64 * 1024,
                    "failure tails exceeded the aggregate 64-KiB budget")
            return tails

    require(capture() == capture(), "tail budgeting depends on worker completion order")


def _concurrent_ensure_worker(
    root_text: str,
    start: Any,
    results: Any,
) -> None:
    """Spawn-safe child for the cross-process publication contract."""
    try:
        root = Path(root_text)
        target = make_target(
            "concurrent",
            command=(sys.executable, "contract-build.py"),
            sources=("contract-build.py",),
            tools=(),
            output_directory="out/concurrent",
            outputs=(artifacts.OutputSpec("out/concurrent/artifact", 0o755),),
        )
        start.wait(5)
        result = artifacts.ArtifactBuilder(
            root, {}, catalog={"concurrent": target}, max_workers=1, cpu_slots=1
        ).ensure(("concurrent",))
        results.put({"ok": True, "result": result})
    except BaseException as exc:
        results.put({"ok": False, "error": type(exc).__name__, "detail": str(exc)})


@contract_case("concurrentBuildersPublishOnce")
def concurrent_builders_publish_once() -> None:
    with tempfile.TemporaryDirectory(prefix="xenoid-artifact-concurrent-") as directory:
        root = Path(directory)
        script = root / "contract-build.py"
        script.write_text(
            """import fcntl, os, pathlib, time
root = pathlib.Path.cwd()
count = root / 'child-count'
lock = root / 'child-count.lock'
with lock.open('a+b') as stream:
    fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
    try:
        current = int(count.read_text() or '0') if count.exists() else 0
        temporary = count.with_suffix('.tmp')
        temporary.write_text(str(current + 1))
        os.replace(temporary, count)
    finally:
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
time.sleep(0.2)
output = root / 'out/concurrent/artifact'
output.parent.mkdir(parents=True, exist_ok=True)
output.write_bytes(b'one publication\\n')
output.chmod(0o755)
""",
            encoding="utf-8",
        )
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        results = context.Queue()
        workers = [context.Process(
            target=_concurrent_ensure_worker,
            args=(str(root), start, results),
            name=f"artifact-contract-{index}",
        ) for index in range(2)]
        reports: list[dict[str, Any]] = []
        started_workers: list[Any] = []
        try:
            for worker in workers:
                worker.start()
                started_workers.append(worker)
            start.set()
            reports = [results.get(timeout=15) for _ in workers]
            for worker in started_workers:
                worker.join(15)
                require(worker.exitcode == 0,
                        f"concurrent child exited {worker.exitcode}")
        finally:
            for worker in started_workers:
                if worker.is_alive():
                    worker.terminate()
                worker.join(2)
            results.close()
            results.join_thread()
        require(all(report.get("ok") is True for report in reports),
                f"concurrent ensure failed: {reports}")
        statuses = sorted(
            report["result"]["targets"]["concurrent"]["status"] for report in reports
        )
        require(statuses == ["built", "reused"],
                f"concurrent builders did not coalesce: {statuses}")
        require((root / "child-count").read_text(encoding="utf-8") == "1",
                "concurrent builders launched the child more than once")
        record = json.loads(cache_record(root, "concurrent").read_text(encoding="utf-8"))
        require(record.get("schema") == "dev.xenoid.artifact/v1" and
                record.get("target") == "concurrent",
                "concurrent publication record is incomplete")


@contract_case("hiddenBuildCallsitesAreRemoved")
def hidden_build_callsites_are_removed() -> None:
    cli_build = function_text("src/xenoid/cli.py", "_run_artifact_build") + "\n" + \
        function_text("src/xenoid/cli.py", "cmd_build_all")
    require("ArtifactBuilder" in cli_build and ".ensure(" in cli_build,
            "build all does not use the sole ArtifactBuilder")
    require("subprocess" not in cli_build and "scripts/build-" not in cli_build,
            "build all retained a raw command loop")

    hidden_scripts = {
        "scripts/make-runtime-context.sh": (
            "build-daemon.sh", "build-keymint.sh", "build-native-input.sh",
            "build-native-hide.sh", "build-native-overlay.sh",
            "build-native-profile.sh", "build-native-netctl.sh",
            "build-native-for-arch.sh", "build-native-zygote.sh",
            "build-native-svcman.sh",
            "build-sensors-hal.sh", "build-gralloc.sh", "build-hwcomposer.sh",
            "build-camera-hal.sh", "build-ril.sh", "build-radio-config.sh",
        ),
        "scripts/make-ota-bundle.sh": (
            "build-daemon.sh", "build-native-input.sh", "build-native-hide.sh",
            "build-native-profile.sh", "build-native-netctl.sh",
        ),
    }
    for relative, forbidden in hidden_scripts.items():
        text = source(relative)
        for token in forbidden:
            require(token not in text, f"{relative} retained hidden builder {token}")

    for relative in (
        "scripts/build-native-input.sh",
        "scripts/build-native-hide.sh",
        "scripts/build-native-profile.sh",
    ):
        text = source(relative)
        require("clean all" not in text and " make clean" not in text,
                f"{relative} retained an unconditional clean rebuild")
        require("XENOID_BUILD_JOBS" in text and "XENOID_FORCE_REBUILD" in text,
                f"{relative} does not honor the builder allocation/force contract")
    daemon_wrapper = source("scripts/build-daemon.sh")
    require("--no-daemon" in daemon_wrapper and "--max-workers=" in daemon_wrapper,
            "Gradle wrapper ignores deterministic bounded execution")

    package = source("scripts/package-release.sh")
    require("build all" not in package and "build\", \"all" not in package,
            "release packaging recursively invokes build all")
    require(not (ROOT / "scripts/xenoid-up.sh").exists(),
            "the superseded shell convergence pipeline still exists")
    require(not (ROOT / "scripts/with-up-lock.py").exists(),
            "the superseded shell up lock wrapper still exists")
    up_handler = function_text("src/xenoid/cli.py", "cmd_up")
    require("ConvergenceExecutor" in up_handler and ".run(" in up_handler,
            "up does not call the in-process convergence executor")
    require("subprocess" not in up_handler and "xenoid-up.sh" not in up_handler,
            "up retained nested shell/CLI orchestration")
    proxy_install = function_text("scripts/xenoid-proxy-engine.py", "install_sandbox")
    for token in ('tool_opt("cc")', 'tool_opt("gcc")', "sandbox-build", "compiler,"):
        require(token not in proxy_install,
                f"proxy engine retained a second proxySandbox builder: {token}")


def main() -> int:
    selected = sys.argv[1:]
    unknown = [name for name in selected if name not in CASES]
    if unknown:
        print(json.dumps({"ok": False, "error": "unknown_case", "cases": unknown}))
        return 2
    ok, results = True, []
    for name in selected or list(CASES):
        try:
            CASES[name]()
            results.append({"name": name, "ok": True})
        except Exception as exc:
            ok = False
            results.append({
                "name": name,
                "ok": False,
                "error": type(exc).__name__,
                "detail": str(exc)[:300],
            })
    print(json.dumps({
        "schema": "dev.xenoid.build-contract/v1",
        "ok": ok,
        "cases": results,
    }, separators=(",", ":"), sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
