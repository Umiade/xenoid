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

    denied = Harness("00000000-0000-4000-8000-000000000001")
    assert denied.unload_ebpf(maintenance=False)["error"] == "shared_protection_maintenance_required"

    print("shared protection contracts: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
