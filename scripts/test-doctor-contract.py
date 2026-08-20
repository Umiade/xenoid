#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import xenoid.doctor as doctor
from xenoid.gates import PROFILE_TARGETS, catalog


def require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


class FakeManager:
    running = False
    status_ok = True

    def __init__(self, context: object, config: object, lease: object) -> None:
        self.context = context

    def doctor(self) -> list[Check]:
        return [Check("host", True, "safe"), Check("scrcpy", False, "optional")]
    def docker_env(self) -> dict[str, str]:
        return {}

    def status(self) -> dict[str, object]:
        return {"ok": self.status_ok, "running": self.running}

    def storage_status(self) -> dict[str, object]:
        return {"ok": True, "state": "committed"}

    def __getattr__(self, name: str) -> object:
        if name.startswith(("ensure", "start", "repair", "build", "install", "reconcile")):
            raise AssertionError(f"doctor attempted mutator: {name}")
        raise AttributeError(name)


class FakeGateRunner:
    complete = True
    def __init__(self, root: Path) -> None:
        self.root = root

    def observe_profile(self, profile: str) -> dict[str, object]:
        return {
            "schema": "dev.xenoid.gates/v1",
            "ok": self.complete,
            "complete": self.complete,
            "profile": profile,
            "failedGate": None if self.complete else "cached",
            "durationMs": 1,
            "gates": {
                "cached": {
                    "state": "passed" if self.complete else "missing",
                    "cacheHit": self.complete,
                }
            },
        }
    def observe_full_evidence(
        self,
        instance_name: str,
        instance_id: str,
        current_identity: object,
    ) -> dict[str, object]:
        return {
            "ok": isinstance(current_identity, dict),
            "instance": instance_name,
            "instanceId": instance_id,
        }

    def run_profile(self, *args: object, **kwargs: object) -> dict[str, object]:
        raise AssertionError("doctor executed the gate suite")


class FakeAcceptance:
    calls = 0

    def __init__(self, manager: object) -> None:
        self.manager = manager

    def observe(self, *args: object) -> dict[str, object]:
        type(self).calls += 1
        return {
            "schema": "dev.xenoid.live-acceptance/v1",
            "ok": True,
            "observationValid": True,
            "checks": {
                name: {"ok": True}
                for name in (
                    "storageIdentity",
                    "cellular",
                    "camera",
                    "googleBinding",
                    "sharedProtection",
                    "persistence",
                    "dualInstance",
                )
            },
            "observation": {
                "containerId": "container",
                "imageId": "sha256:image",
                "dataUuid": "00000000-0000-4000-8000-000000000001",
                "rootfsUuid": "00000000-0000-4000-8000-000000000002",
                "runtimeEpoch": "a" * 64,
                "protectionDigest": "b" * 64,
            },
        }


def main() -> int:
    specs = catalog()
    for profile in ("doctor", "doctor-full"):
        selected: set[str] = set()

        def add(name: str) -> None:
            if name in selected:
                return
            selected.add(name)
            for dependency in specs[name].dependencies:
                add(dependency)

        add(PROFILE_TARGETS[profile])
        require(
            all(
                specs[name].runtime_free
                and not specs[name].mutating
                and (specs[name].aggregate or specs[name].cacheable)
                for name in selected
            ),
            f"{profile} contains an executable or uncacheable observation gate",
        )

    original_manager = doctor.RuntimeManager
    original_runner = doctor.GateRunner
    original_acceptance = doctor.LiveAcceptance
    original_preflight = doctor._preflight
    doctor.RuntimeManager = FakeManager
    doctor.GateRunner = FakeGateRunner
    doctor.LiveAcceptance = FakeAcceptance
    doctor._preflight = lambda *args, **kwargs: {"ok": True, "durationMs": 0}
    try:
        with tempfile.TemporaryDirectory(prefix="xenoid-doctor-contract-") as raw:
            context = SimpleNamespace(
                project_root=Path(raw),
                instance_name="contract",
                instance_id="00000000-0000-4000-8000-000000000000",
                public_dict=lambda: {"name": "contract", "id": "00000000-0000-4000-8000-000000000000"},
            )
            lease = SimpleNamespace(slot=1, state="active")
            FakeGateRunner.complete = False
            FakeManager.running = False
            absent = doctor.build_doctor_report(context, object(), lease)
            require(absent["ok"] is True, "runtime-absent doctor did not preserve host success")
            require(absent["complete"] is False, "cache-only doctor claimed complete")
            require(absent["sections"]["runtime"]["acceptance"]["fresh"] is True, "runtime skip was not explicitly fresh")
            require(FakeAcceptance.calls == 0, "runtime-absent doctor invoked live adapters")

            require(absent["sections"]["gates"]["skipped"] is True, "missing local records were not observationally reported")
            FakeGateRunner.complete = True
            FakeManager.running = True
            FakeManager.status_ok = False
            unhealthy = doctor.build_doctor_report(context, object(), lease)
            require(unhealthy["ok"] is False, "running unhealthy status was treated as absent")
            require(FakeAcceptance.calls == 1, "running unhealthy runtime skipped live observation")
            FakeManager.status_ok = True
            FakeManager.running = True
            online = doctor.build_doctor_report(context, object(), lease, full=True, require_runtime=True)
            require(online["ok"] is True and online["complete"] is True, "fresh live acceptance was not authoritative")
            require(FakeAcceptance.calls == 2, "doctor did not invoke exactly one fresh observer per running report")
            require(online["sections"]["runtime"]["acceptance"]["fresh"] is True, "live evidence was cacheable")
    finally:
        doctor.RuntimeManager = original_manager
        doctor.GateRunner = original_runner
        doctor.LiveAcceptance = original_acceptance
        doctor._preflight = original_preflight

    print(json.dumps({"schema": "dev.xenoid.doctor-contract/v1", "ok": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
