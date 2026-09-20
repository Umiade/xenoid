#!/usr/bin/env python3
"""Runtime-free contracts for the engine-host shared protection owner."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import Any, Mapping, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from xenoid.backend import RuntimeManager  # noqa: E402

from xenoid.protection import (  # noqa: E402
    BuildArtifacts,
    ProtectionInputs,
    RuntimeInventory,
    SCHEMA,
    SharedProtectionError,
    SharedProtectionManager,
)
from xenoid.convergence import _JOURNAL_KEYS  # noqa: E402

A = "a" * 64
B = "b" * 64
C = "c" * 64
D = "d" * 64
E = "e" * 64
F = "f" * 64


class FakeRuntime:
    def __init__(self, instance_id: str):
        self.context = SimpleNamespace(project_root=ROOT, instance_id=instance_id)
        self._shared_protection_capability: Optional[str] = None

    @contextmanager
    def _shared_protection_engine_lock(self):
        self._shared_protection_capability = A
        try:
            yield
        finally:
            self._shared_protection_capability = None

    def ensure_binder(self) -> dict[str, Any]:
        return {"ok": True, "skipped": True}


class Harness(SharedProtectionManager):
    def __init__(self, instance_id: str):
        super().__init__(FakeRuntime(instance_id))
        self.inventory = RuntimeInventory(0, False, A, 0)
        self.kmod: dict[str, Any] = {
            "ok": True,
            "loaded": True,
            "digest": D,
            "artifactSha256": F,
        }
        self.ebpf: dict[str, Any] = {
            "ok": True,
            "loaded": True,
            "digest": E,
            "artifactSha256": A,
            "attach": "lsm",
        }
        self.record: Optional[dict[str, Any]] = None
        self.record_valid = True
        self.built = False
        self.deployed = False
        self.legacy_unloaded = False

    def inputs(self) -> ProtectionInputs:
        return ProtectionInputs(A, B, D, E, C)

    def _runtime_inventory(self) -> RuntimeInventory:
        return self.inventory

    def _observe(self, inputs: ProtectionInputs):
        current = C if self.kmod.get("digest") == D and self.ebpf.get("digest") == E else None
        return dict(self.kmod), dict(self.ebpf), current

    def _read_record(self) -> Optional[dict[str, Any]]:
        return self.record

    def _record_valid_for(
        self,
        record: Optional[Mapping[str, Any]],
        inputs: ProtectionInputs,
        current_digest: Optional[str],
        attach_mode: Optional[str],
        kmod_artifact_sha256: Optional[str],
        ebpf_artifact_sha256: Optional[str],
        kmod_build_id: Optional[str],
        ebpf_program_tags: Optional[str],
    ) -> bool:
        return self.record_valid and current_digest == C

    def _build(self, inputs: ProtectionInputs) -> BuildArtifacts:
        self.built = True
        return BuildArtifacts("1" * 32, "2" * 40, F, A)

    def _publish_build(self, inputs, artifacts):
        return None

    def _install_kmod(self, inputs, artifacts, previous):
        self.deployed = True
        self.kmod = {
            "ok": True,
            "loaded": True,
            "digest": D,
            "artifactSha256": F,
            "buildId": "2" * 40,
        }
        return {"ok": True}

    def _ebpf_transition(self, desired_input, desired_artifact_sha256, **kwargs):
        self.deployed = True
        self.ebpf = {
            "ok": True,
            "loaded": True,
            "digest": E,
            "artifactSha256": A,
            "attach": "lsm",
            "programTags": "3" * 64,
        }
        return {"ok": True}

    def _unload_unbound_legacy_kmod(self):
        self.legacy_unloaded = True
        self.kmod = {
            "ok": False,
            "loaded": False,
            "digest": None,
            "artifactSha256": None,
        }
        return dict(self.kmod)

    def _write_record(self, inputs, artifacts, attach_mode, program_tags):
        self.record_valid = True
        self.record = valid_record()


class StatfsRuntime:
    def __init__(self, instance_id: str, pid: int, container_id: str, netns: str):
        self.context = SimpleNamespace(project_root=ROOT, instance_id=instance_id)
        self._shared_protection_capability: Optional[str] = None
        self.pid = pid
        self.container_id = container_id
        self.netns = netns
        self.running = True
        self.network_mode = f"xenoid-{instance_id[-12:]}"
        self.leaf: Optional[str] = None
        self.kernel = "0000000000000000"
        self.engine_returncode = 0
        self.engine_scripts: list[str] = []
        self.exec_calls: list[list[str]] = []
        self.exec_capabilities: list[Optional[str]] = []
        self.exact_exec_calls: list[tuple[str, list[str]]] = []
        self.lock_entries = 0

    @contextmanager
    def _shared_protection_engine_lock(self):
        self.lock_entries += 1
        self._shared_protection_capability = A
        try:
            yield
        finally:
            self._shared_protection_capability = None

    def _owned_container_record(self, *, timeout=None):
        return {
            "Id": self.container_id,
            "State": {"Running": self.running, "Pid": self.pid},
            "HostConfig": {"NetworkMode": self.network_mode},
        }, ""

    def docker_exec(self, args, timeout=10):
        self.exec_capabilities.append(self._shared_protection_capability)
        self.exec_calls.append(list(args))
        rendered = " ".join(args)
        if args[:2] == ["sh", "-c"] and "printf '%s\\n'" in rendered:
            match = __import__("re").search(r"printf '%s\\n' ([0-9a-f]{16})", rendered)
            if match:
                self.leaf = match.group(1)
                return {"ok": True, "stdout": ""}
        if args[:2] == ["sh", "-c"] and "cat " in rendered:
            return {"ok": True, "stdout": "" if self.leaf is None else self.leaf + "\n"}
        return {"ok": False, "stdout": ""}

    def _engine_host_shell(self, script, timeout=30):
        self.engine_scripts.append(script)
        if self.engine_returncode == 0:
            match = __import__("re").search(
                r"printf %s ([0-9a-f]{16}) > /sys/module/xenoid_kmod/parameters/statfs_fsid",
                script,
            )
            if match:
                self.kernel = match.group(1)
        return SimpleNamespace(returncode=self.engine_returncode, stdout="", stderr="")


class StatfsHarness(SharedProtectionManager):
    runtime: StatfsRuntime

    def __init__(self, instance_id: str, pid: int, container_id: str, netns: str):
        super().__init__(StatfsRuntime(instance_id, pid, container_id, netns))

    def _statfs_fsid_container_exec(self, container_id, args, *, timeout=10.0):
        self.runtime.exact_exec_calls.append((container_id, list(args)))
        if container_id != self.runtime.container_id:
            return {"ok": False, "stdout": ""}
        if args == ["readlink", "/proc/self/ns/net"]:
            return {"ok": True, "stdout": self.runtime.netns + "\n"}
        if args == ["cat", "/sys/module/xenoid_kmod/parameters/statfs_fsid"]:
            return {"ok": True, "stdout": self.runtime.kernel + "\n"}
        return {"ok": False, "stdout": ""}


def check_statfs_fsid_first_use_contracts() -> None:
    sources = {
        "shim": (ROOT / "native/xenoid-shim/xenoid_shim.c").read_text(encoding="utf-8"),
        "zygote": (ROOT / "native/xenoid-zygote/xenoid_zygote.c").read_text(encoding="utf-8"),
    }
    for source in sources.values():
        initializer = source.partition("static void initialize_statfs_fsid")[2].partition(
            "static uint64_t load_statfs_fsid"
        )[0]
        loader = source.partition("static uint64_t load_statfs_fsid")[2].partition(
            "#define XENOID_SHAPE_STATFS_FSID"
        )[0]
        shape = source.partition("#define XENOID_SHAPE_STATFS_FSID")[2].partition(
            "#define XENOID_SHAPE_DATA_STATFS"
        )[0]
        assert "#include <pthread.h>" in source
        assert "static pthread_once_t statfs_fsid_once = PTHREAD_ONCE_INIT;" in source
        assert "static uint64_t statfs_fsid_value;" in source
        assert "statfs_fsid_ready" not in source
        assert "statfs_fsid_vals" not in source
        assert source.count("statfs_fsid_value") == 3
        assert "text[half * 8 + i]" in initializer
        assert "(v[half] << 4)" in initializer
        assert initializer.index("text[half * 8 + i]") < initializer.index(
            "statfs_fsid_value = ((uint64_t)v[0] << 32) | (uint64_t)v[1];"
        )
        assert "pthread_once(&statfs_fsid_once, initialize_statfs_fsid);" in loader
        assert loader.index("pthread_once(") < loader.index("return statfs_fsid_value;")
        assert "uint64_t fsid = load_statfs_fsid();" in shape
        assert "__val[0] = (int)(uint32_t)(fsid >> 32);" in shape
        assert "__val[1] = (int)(uint32_t)fsid;" in shape

    assert "char text[18];" in sources["shim"]
    assert "size != 17 || text[16] != '\\n'" in sources["shim"]
    assert "char text[32];" in sources["zygote"]
    assert "size != 17 || text[16] != '\\n'" in sources["zygote"]
    assert "size != 16" not in sources["zygote"]

    stress = (ROOT / "scripts/smoke-statfs-coherence.py").read_text(encoding="utf-8")
    for token in (
        "os.mkfifo(fifo)",
        "#define THREAD_COUNT 64",
        "pthread_barrier_wait(context->barrier);",
        "usleep(250000);",
        "SYS_statfs",
        "SYS_fstatfs",
        "hooked_syscall(SYS_getpid",
        "hooked_fstatfs(data_fd, &buf)",
        "run_phase(0)",
        "run_phase(1)",
        "UINT32_C(0x01234567)",
        "UINT32_C(0x89abcdef)",
    ):
        assert token in stress


def check_statfs_fsid_contracts() -> None:
    first = StatfsHarness(
        "00000000-0000-4000-8000-000000000001", 101, "1" * 64, "net:[1001]"
    )
    second = StatfsHarness(
        "00000000-0000-4000-8000-000000000002", 202, "2" * 64, "net:[2002]"
    )
    assert first.set_statfs_fsid("0123456789abcdef") == {
        "ok": True,
        "fsid": "0123456789abcdef",
    }
    assert second.set_statfs_fsid("fedcba9876543210") == {
        "ok": True,
        "fsid": "fedcba9876543210",
    }
    assert first.runtime.leaf == first.runtime.kernel == "0123456789abcdef"
    assert second.runtime.leaf == second.runtime.kernel == "fedcba9876543210"
    assert first.runtime.kernel != second.runtime.kernel
    assert "/proc/101/ns/net" in first.runtime.engine_scripts[0]
    assert "/proc/202/ns/net" in second.runtime.engine_scripts[0]
    assert first.runtime.exec_capabilities[0] == A
    assert second.runtime.exec_capabilities[0] == A
    assert "net:[1001]" in first.runtime.engine_scripts[0]
    assert "net:[2002]" in second.runtime.engine_scripts[0]
    assert first.runtime.lock_entries == second.runtime.lock_entries == 1
    assert ("1" * 64, ["cat", "/sys/module/xenoid_kmod/parameters/statfs_fsid"]) in first.runtime.exact_exec_calls
    assert ("2" * 64, ["cat", "/sys/module/xenoid_kmod/parameters/statfs_fsid"]) in second.runtime.exact_exec_calls

    invalid = StatfsHarness(
        "00000000-0000-4000-8000-000000000003", 303, "3" * 64, "net:[3003]"
    )
    assert invalid.set_statfs_fsid("ABCDEF0123456789")["code"] == "statfs_fsid_invalid"
    assert invalid.set_statfs_fsid("0000000000000000")["code"] == "statfs_fsid_invalid"
    assert invalid.runtime.leaf is None and invalid.runtime.lock_entries == 0

    stopped = StatfsHarness(
        "00000000-0000-4000-8000-000000000004", 404, "4" * 64, "net:[4004]"
    )
    stopped.runtime.running = False
    assert stopped.set_statfs_fsid("1111111111111111")["code"] == "statfs_fsid_runtime_not_running"
    assert stopped.runtime.leaf == "1111111111111111"
    assert stopped.runtime.lock_entries == 1
    assert stopped.runtime.engine_scripts == []
    for bad_pid in (0, -1, True):
        bad = StatfsHarness(
            "00000000-0000-4000-8000-000000000005", bad_pid, "5" * 64, "net:[5005]"
        )
        assert bad.set_statfs_fsid("2222222222222222")["code"] == "statfs_fsid_runtime_not_running"
        assert bad.runtime.engine_scripts == []

    shared = StatfsHarness(
        "00000000-0000-4000-8000-000000000006", 606, "6" * 64, "net:[6006]"
    )
    shared.runtime.network_mode = "container:" + "1" * 64
    assert shared.set_statfs_fsid("3333333333333333")["code"] == "statfs_fsid_runtime_not_running"

    shared_runtime = StatfsHarness(
        "00000000-0000-4000-8000-000000000009", 909, "9" * 64, "net:[9009]"
    )
    shared_runtime.runtime.engine_returncode = 4
    assert shared_runtime.set_statfs_fsid("5555555555555555")["code"] == "statfs_fsid_namespace_shared"


    stale = StatfsHarness(
        "00000000-0000-4000-8000-000000000007", 707, "7" * 64, "net:[7007]"
    )
    stale.runtime.engine_returncode = 3
    assert stale.set_statfs_fsid("4444444444444444")["code"] == "statfs_fsid_ownership_lost"
    assert "statfs_fsid_reset" in stale.runtime.engine_scripts[0]

    empty = StatfsHarness(
        "00000000-0000-4000-8000-000000000008", 808, "8" * 64, "net:[8008]"
    )
    assert empty.republish_statfs_fsid() == {
        "ok": True,
        "published": False,
        "reason": "absent",
    }
    empty.runtime.leaf = "0000000000000000"
    assert empty.republish_statfs_fsid()["reason"] == "zero"
    empty.runtime.leaf = "not-a-valid-fsid"
    assert empty.republish_statfs_fsid()["code"] == "statfs_fsid_leaf_invalid"

    first.runtime.kernel = "0000000000000000"
    status = first.statfs_fsid_status()
    assert status["ok"] is True and status["diverged"] is True
    assert status["published"] is False
    assert first.republish_statfs_fsid()["published"] is True
    status = first.statfs_fsid_status()
    assert status["published"] is True and status["diverged"] is False


def valid_record() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "engineId": A,
        "kernelDigest": B,
        "expectedDigest": C,
        "currentDigest": C,
        "lastKnownGoodDigest": C,
        "inventory": {
            "modules": ["xenoid_kmod"],
            "links": ["path", "selinuxPermission", "unameEntry", "unameReturn"],
            "maps": ["denyCount", "policyIdentity"],
            "probes": [
                "security_socket_create",
                "security_netlink_send",
                "binder_transaction",
                "vfs_statfs",
                "linkInventory",
                "unprivilegedDeny",
            ],
        },
        "kmod": {
            "inputDigest": D,
            "artifactSha256": F,
            "buildId": "2" * 40,
        },
        "ebpf": {
            "inputDigest": E,
            "artifactSha256": A,
            "attachMode": "lsm",
            "programTags": "3" * 64,
        },
    }


def main() -> int:
    check_statfs_fsid_contracts()
    check_statfs_fsid_first_use_contracts()
    first = Harness("00000000-0000-4000-8000-000000000001")
    second = Harness("00000000-0000-4000-8000-000000000002")
    first.record = valid_record()
    second.record = valid_record()
    first_status = first.status()
    second_status = second.status()
    assert first_status["ok"] is True and second_status["ok"] is True
    assert first_status["engineId"] == second_status["engineId"] == A
    assert first_status["currentDigest"] == second_status["currentDigest"] == C
    for value in (first_status, second_status):
        rendered = repr(value)
        assert "instance" not in rendered.lower()
        assert "endpoint" not in rendered.lower()
        assert "token" not in rendered.lower()
        assert str(ROOT) not in rendered

    active = Harness("00000000-0000-4000-8000-000000000001")
    active.inventory = RuntimeInventory(2, True, A, 2)
    active.kmod["digest"] = A
    active.record = valid_record()
    active.record["kmod"]["inputDigest"] = A
    active.record_valid = False
    result = active.ensure(C)
    assert result["ok"] is False
    assert result["error"] == "shared_protection_reload_requires_maintenance"
    assert active.built is True
    assert active.deployed is False

    for script in ("scripts/build-kmod.sh", "scripts/build-ebpf.sh"):
        source = (ROOT / script).read_text(encoding="utf-8")
        assert 'expected="${2#0}"' in source
        assert '"0:0:$expected"' in source
        assert "setsid --wait sh -c" in source
    kmod_source = (ROOT / "scripts/build-kmod.sh").read_text(encoding="utf-8")
    assert 'BUILD="$BUILD_PARENT/$INPUT_DIGEST"' in kmod_source
    assert "cd '$BUILD'" in kmod_source
    assert "-fdebug-prefix-map=$BUILD=." in kmod_source
    assert "-ffile-prefix-map=$BUILD=." in kmod_source
    assert "-fmacro-prefix-map=$BUILD=." in kmod_source
    stopped = Harness("00000000-0000-4000-8000-000000000001")
    stopped.kmod = {

        "ok": False,
        "loaded": False,
        "digest": None,
        "artifactSha256": None,
    }
    stopped.record_valid = False
    stopped_status = stopped.status()
    assert stopped_status["maintenanceRequired"] is True

    legacy_active = Harness("00000000-0000-4000-8000-000000000001")
    legacy_active.kmod = {
        "ok": False,
        "loaded": True,
        "digest": None,
        "artifactSha256": None,
    }
    legacy_active.ebpf = {
        "ok": False,
        "loaded": False,
        "digest": None,
        "artifactSha256": None,
        "attach": None,
    }
    legacy_active.record_valid = False
    legacy_active.inventory = RuntimeInventory(1, False, A, 1)
    legacy_active_result = legacy_active.ensure(C)
    assert legacy_active_result["error"] == "shared_protection_reload_requires_maintenance"
    assert legacy_active.legacy_unloaded is False

    legacy_stopped = Harness("00000000-0000-4000-8000-000000000001")
    legacy_stopped.kmod = dict(legacy_active.kmod)
    legacy_stopped.ebpf = dict(legacy_active.ebpf)
    legacy_stopped.record_valid = False
    legacy_stopped_result = legacy_stopped.ensure(C)
    assert legacy_stopped_result["ok"] is True
    assert legacy_stopped.legacy_unloaded is True
    assert legacy_stopped.deployed is True

    ambiguous = Harness("00000000-0000-4000-8000-000000000001")
    ambiguous._runtime_inventory = lambda: (_ for _ in ()).throw(  # type: ignore[method-assign]
        SharedProtectionError("shared_protection_ownership_ambiguous")
    )
    result = ambiguous.status()
    assert result["ok"] is False
    assert result["error"] == "shared_protection_ownership_ambiguous"

    unsafe = valid_record()
    unsafe["hostPath"] = "/private/engine"
    try:
        SharedProtectionManager._validate_record(unsafe)
    except SharedProtectionError as exc:
        assert exc.code == "shared_protection_state_invalid"
    else:
        raise AssertionError("unsafe shared state accepted")
    assert {
        "protectionEngineId",
        "protectionExpectedDigest",
    }.issubset(_JOURNAL_KEYS)

    class DivergedProtection:
        @staticmethod
        def status() -> dict[str, Any]:
            return {"ok": True, "currentDigest": A, "expectedDigest": A}

        @staticmethod
        def statfs_fsid_status() -> dict[str, Any]:
            return {
                "ok": True,
                "running": True,
                "staged": "0123456789abcdef",
                "kernel": "0000000000000000",
                "published": False,
                "diverged": True,
            }

    runtime = object.__new__(RuntimeManager)
    runtime.shared_protection_manager = lambda: DivergedProtection()  # type: ignore[method-assign]
    diverged_status = runtime.shared_protection_status()
    assert diverged_status["ok"] is False
    assert diverged_status["error"] == "statfs_fsid_diverged"
    assert diverged_status["statfsFsid"]["diverged"] is True


    denied = Harness("00000000-0000-4000-8000-000000000001")
    assert denied.unload_ebpf(maintenance=False)["error"] == "shared_protection_maintenance_required"

    print("shared protection contracts: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
