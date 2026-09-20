#!/usr/bin/env python3
"""Runtime-free contracts for the single resumable convergence owner.

The fakes model immutable engine/runtime observations and low-level idempotent
manager calls.  They never execute Docker, ADB, a build wrapper, a CLI, or a
network request.
"""
from __future__ import annotations

import contextlib
import copy
import dataclasses
import inspect
import json
import os
import stat
import tempfile
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "src"))

from xenoid import backend, cli, convergence, live_observe  # noqa: E402
from xenoid.google_services import capability_model  # noqa: E402
from xenoid.backend import RuntimeManager  # noqa: E402
from xenoid.google_services import GoogleServicesError  # noqa: E402


INSTANCE_ID = "10000000-0000-4000-8000-000000000001"
DATA_UUID = "20000000-0000-4000-8000-000000000001"
ROOTFS_UUID = "30000000-0000-4000-8000-000000000001"
TARGET_DATA_UUID = "40000000-0000-4000-8000-000000000001"
TARGET_ROOTFS_UUID = "50000000-0000-4000-8000-000000000001"
OLD_CONTAINER = "a" * 64
SEED_CONTAINER = "b" * 64
NEW_CONTAINER = "c" * 64
INPUT_DIGEST = "1" * 64
BOOT_DIGEST = "2" * 64
IMAGE_ID = "sha256:" + "3" * 64
OBSERVATION_DIGEST = "4" * 64
PROTECTION_DIGEST = "5" * 64
PROTECTION_ENGINE_ID = "7" * 64
ARTIFACT_DIGEST = "6" * 64
MICROG_PLAY_RELEASE = (
    "microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0"
)
GOOGLE_STATUS_KEYS = {
    "schema",
    "ok",
    "provider",
    "release",
    "configured",
    "state",
    "hostReady",
    "runtimeRequired",
    "runtimeChecked",
    "ready",
    "skipped",
    "implementation",
    "signatureModel",
    "storeImplementation",
    "specSha256",
    "dataCompatibilitySha256",
    "binding",
    "runtimeIdentity",
    "factoryComponents",
    "effectiveComponents",
    "live",
    "requiredCapabilities",
    "capabilities",
    "googleIdentityMode",
    "error",
    "nextActions",
}
GOOGLE_LIVE_CHECKS = {
    "components",
    "signaturePolicy",
    "productPolicy",
    "accountAuthenticator",
    "boundBroker",
    "fcmRegistrar",
    "fusedProvider",
    "playStoreLauncher",
    "processStability",
}
PLAN_KEYS = {
    "schema",
    "resolution",
    "artifactTargets",
    "artifactRecords",
    "imageAction",
    "desiredImageInputSha256",
    "desiredImageBootInputSha256",
    "selectedImageRecord",
    "runtimeAction",
    "bootSeedAction",
    "recreateReasons",
    "liveObservationRequired",
    "daemonAction",
    "deployComponents",
    "identityAction",
    "locationAction",
    "proxyAction",
    "keyboxAction",
    "cameraAction",
    "googleAction",
    "protectionAction",
    "acceptanceChecks",
    "planDigest",
}
JOURNAL_KEYS = {
    "schema",
    "instanceId",
    "operationId",
    "regenerationTransactionId",
    "plan",
    "planDigest",
    "phase",
    "selectedImageInputSha256",
    "selectedImageBootInputSha256",
    "protectionEngineId",
    "protectionExpectedDigest",
    "oldContainerId",
    "seedContainerId",
    "newContainerId",
    "observedDataUuid",
    "observedRootfsUuid",
    "bootSeedTarget",
    "proxyGeneration",
    "proxyEnabled",
    "proxyQuarantineRequired",
    "proxyQuarantined",
    "liveResolution",
    "completed",
    "createdAt",
    "updatedAt",
}
PHASES = (
    "planned",
    "quarantined",
    "image_ensured",
    "runtime_quiesced",
    "shared_protection_maintained",
    "seed_runtime_started",
    "seed_initialized",
    "container_removed",
    "storage_converged",
    "container_created",
    "runtime_started",
    "live_resolved",
    "components_deployed",
    "control_ready",
    "identity_converged",
    "location_converged",
    "keybox_converged",
    "camera_converged",
    "google_converged",
    "proxy_converged",
    "protection_converged",
    "accepted",
)

Case = Callable[[], None]
CASES: dict[str, Case] = {}


class ContractFailure(AssertionError):
    pass


def case(name: str) -> Callable[[Case], Case]:
    def register(function: Case) -> Case:
        if name in CASES:
            raise RuntimeError(f"duplicate case: {name}")
        CASES[name] = function
        return function
    return register


def require(value: bool, message: str) -> None:
    if not value:
        raise ContractFailure(message)


def microg_google_status() -> dict[str, Any]:
    digest = "9" * 64
    components = (
        (
            "gmsCore",
            "com.google.android.gms",
            "/system/product/priv-app/GmsCore/GmsCore.apk",
            250932030,
        ),
        (
            "gsfProxy",
            "com.google.android.gsf",
            "/system/product/priv-app/GsfProxy/GsfProxy.apk",
            8,
        ),
        (
            "playStoreSeed",
            "com.android.vending",
            "/system/product/priv-app/Phonesky/Phonesky.apk",
            83041710,
        ),
    )
    model = capability_model("microg", "ready")
    return {
        "schema": "dev.xenoid.google-services-status/v2",
        "ok": True,
        "provider": "microg",
        "release": MICROG_PLAY_RELEASE,
        "configured": True,
        "state": "ready",
        "hostReady": True,
        "runtimeRequired": True,
        "runtimeChecked": True,
        "ready": True,
        "skipped": False,
        "implementation": "microg",
        "signatureModel": "restricted-spoofing",
        "storeImplementation": "google-play",
        "specSha256": digest,
        "dataCompatibilitySha256": digest,
        "binding": {
            "provider": "microg",
            "release": MICROG_PLAY_RELEASE,
            "specSha256": digest,
            "dataCompatibilitySha256": digest,
            "state": "committed",
            "source": "fresh",
            "inferred": False,
        },
        "runtimeIdentity": {
            "desiredImageSha256": IMAGE_ID,
            "containerImageSha256": IMAGE_ID,
            "rootfsSourceImageSha256": IMAGE_ID,
            "desiredInputSha256": INPUT_DIGEST,
            "desiredBootInputSha256": BOOT_DIGEST,
            "containerInputSha256": INPUT_DIGEST,
            "containerBootInputSha256": BOOT_DIGEST,
            "imageMatch": "matching",
            "rootfsBootInputMatches": True,
            "labelsMatch": True,
            "commandMatch": True,
            "skipped": False,
        },
        "factoryComponents": {
            name: {
                "package": package,
                "path": path,
                "versionCode": version,
                "sha256": digest,
                "signingCertificateHistorySha256": [digest],
                "privileged": True,
            }
            for name, package, path, version in components
        },
        "effectiveComponents": {
            name: {
                "package": package,
                "codePath": path,
                "versionCode": version,
                "versionName": str(version),
                "signerSha256": digest,
                "enabled": True,
                "system": True,
                "privileged": True,
                "updatedSystemApp": False,
                "processState": (
                    "stable" if name == "gmsCore" else "dormant"
                ),
            }
            for name, package, path, version in components
        },
        "live": {
            "ok": True,
            "checks": {
                name: {"ok": True, "code": None}
                for name in GOOGLE_LIVE_CHECKS
            },
            "error": None,
        },
        **model,
        "googleIdentityMode": "provider-managed",
        "error": None,
        "nextActions": [],
    }


def selected_image() -> dict[str, Any]:
    return {
        "schema": "dev.xenoid.runtime-image/v1",
        "inputSha256": INPUT_DIGEST,
        "bootInputSha256": BOOT_DIGEST,
        "imageId": IMAGE_ID,
        "derivedTag": "xenoid/redroid:xenoid-" + INPUT_DIGEST[:32],
    }


def artifact_record(target: str = "daemon") -> dict[str, Any]:
    return {
        "schema": "dev.xenoid.artifact/v1",
        "target": target,
        "inputSha256": ARTIFACT_DIGEST,
        "toolSha256": "7" * 64,
        "outputs": [
            {
                "path": f"out/{target}",
                "mode": 0o755,
                "size": 4,
                "sha256": "8" * 64,
            }
        ],
    }


def healthy_snapshot() -> dict[str, Any]:
    return {
        "instanceId": INSTANCE_ID,
        "artifactTargets": [],
        "artifactRecords": [artifact_record()],
        "desiredImageInputSha256": INPUT_DIGEST,
        "desiredImageBootInputSha256": BOOT_DIGEST,
        "selectedImageRecord": selected_image(),
        "runtime": {
            "state": "running",
            "containerId": OLD_CONTAINER,
            "ownershipValid": True,
            "integrationIdentityValid": True,
            "storageValid": True,
            "createSpecMatches": True,
            "networkMatches": True,
            "volumeMatches": True,
            "imageInputSha256": INPUT_DIGEST,
            "imageBootInputSha256": BOOT_DIGEST,
            "dataUuid": DATA_UUID,
            "rootfsUuid": ROOTFS_UUID,
            "bootSeedRequired": False,
        },
        "components": {
            "daemon": {"state": "matching"},
            "deploy": {
                "input": "matching",
                "hide": "matching",
                "profile": "matching",
                "rootd": "matching",
                "netctl": "matching",
                "ssaid": "matching",
            },
            "identity": {"state": "matching"},
            "location": {"state": "matching"},
            "proxy": {
                "state": "matching",
                "generation": 7,
                "enabled": False,
                "quarantineRequired": False,
            },
            "keybox": {"state": "matching"},
            "camera": {"state": "matching"},
            "google": {
                "state": "matching",
                "status": microg_google_status(),
            },
            "protection": {
                "state": "matching",
                "expectedDigest": PROTECTION_DIGEST,
                "currentDigest": PROTECTION_DIGEST,
                "replacementRequired": False,
                "maintenanceRequired": False,
                "observed": {
                    "ok": True,
                    "engineId": PROTECTION_ENGINE_ID,
                    "expectedDigest": PROTECTION_DIGEST,
                    "currentDigest": PROTECTION_DIGEST,
                    "replacementRequired": False,
                    "maintenanceRequired": False,
                },
            },
        },
        "acceptanceChecks": [
            "container",
            "storage",
            "identity",
            "daemon",
            "rootd",
            "location",
            "keybox",
            "camera",
            "google",
            "proxy",
            "protection",
        ],
    }


class FakeManager:
    def __init__(self, root: Path, snapshot: Mapping[str, Any]) -> None:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root.chmod(0o700)
        self.context = SimpleNamespace(state_root=root, instance_id=INSTANCE_ID)
        self.snapshot = copy.deepcopy(dict(snapshot))
        self.calls: list[tuple[str, Any]] = []
        self.observe_count = 0
        self.fail_once: dict[str, str] = {}
        self.interrupt_once: set[str] = set()
        self.cancelled = 0
        self.convergence_deadline: float | None = None
        self._seed_container: str | None = None

    def observe_convergence(self, skip_build: bool = False) -> dict[str, Any]:
        self.observe_count += 1
        self.calls.append(("observe", skip_build))
        return copy.deepcopy(self.snapshot)

    @contextlib.contextmanager
    def instance_operation_lock(self) -> Iterator[None]:
        self.calls.append(("lock", "enter"))
        try:
            yield
        finally:
            self.calls.append(("lock", "exit"))

    def acceptance_context(self) -> Any:
        self.calls.append(("acceptance-context", {}))
        return {"manager": self}

    def cancel_convergence(self, reason: str = "convergence_cancelled") -> None:
        self.calls.append(("cancel", reason))
        self.cancelled += 1

    def _result(self, name: str, **values: Any) -> dict[str, Any]:
        self.calls.append((name, copy.deepcopy(values)))
        if name in self.interrupt_once:
            self.interrupt_once.remove(name)
            raise KeyboardInterrupt
        code = self.fail_once.pop(name, None)
        if code is not None:
            return {
                "ok": False,
                "error": code,
                "message": "/private/operator token=must-not-leak",
            }
        return {"ok": True, **values}

    def quarantine_proxy_for_lifecycle(
        self, expected_data_uuid: str | None, operation_id: str
    ) -> dict[str, Any]:
        return self._result(
            "quarantine",
            dataUuid=expected_data_uuid,
            quarantined=True,
            operationId=operation_id,
        )

    def ensure_runtime_image(
        self, expected_input_sha256: str, expected_boot_input_sha256: str
    ) -> dict[str, Any]:
        record = selected_image()
        self.snapshot["selectedImageRecord"] = record
        return self._result("image", selectedImageRecord=record)

    def quiesce_owned_container(
        self, expected_container_id: str | None
    ) -> dict[str, Any]:
        self.snapshot["runtime"]["state"] = "stopped"
        return self._result("quiesce", containerId=expected_container_id, preserved=True)

    def maintain_shared_protection(
        self, expected_digest: str | None
    ) -> dict[str, Any]:
        protection = self.snapshot["components"]["protection"]
        protection.update(
            {
                "state": "matching",
                "currentDigest": expected_digest,
                "replacementRequired": False,
                "maintenanceRequired": False,
            }
        )
        protection["observed"].update(
            {
                "ok": True,
                "currentDigest": expected_digest,
                "replacementRequired": False,
                "maintenanceRequired": False,
            }
        )
        return self._result(
            "maintain-protection",
            currentDigest=expected_digest,
        )

    def start_seed_runtime(
        self, image_record: Mapping[str, Any], boot_seed_target: Mapping[str, Any]
    ) -> dict[str, Any]:
        del image_record, boot_seed_target
        self._seed_container = SEED_CONTAINER
        self.snapshot["runtime"].update({"state": "running", "containerId": SEED_CONTAINER})
        return self._result("seed-start", containerId=SEED_CONTAINER)

    def initialize_seed_runtime(
        self, expected_container_id: str, boot_seed_target: Mapping[str, Any]
    ) -> dict[str, Any]:
        del boot_seed_target
        self.snapshot["runtime"]["bootSeedRequired"] = False
        return self._result("seed-initialize", containerId=expected_container_id)

    def remove_owned_container_for_recreate(
        self,
        expected_container_id: str | None = None,
        *,
        prepare_location: bool = False,
    ) -> dict[str, Any]:
        self.snapshot["runtime"].update({"state": "absent", "containerId": None})
        return self._result(
            "remove",
            oldContainerId=expected_container_id,
            removed=True,
            prepareLocation=prepare_location,
        )

    def remove_owned_container_for_regenerate(
        self, expected_container_id: str | None = None
    ) -> dict[str, Any]:
        return self.remove_owned_container_for_recreate(expected_container_id)

    def converge_storage(
        self,
        boot_seed_target: Mapping[str, Any] | None,
        regeneration_capability: Any,
    ) -> dict[str, Any]:
        del regeneration_capability
        data_uuid = (
            boot_seed_target.get("dataUuid")
            if isinstance(boot_seed_target, Mapping)
            else DATA_UUID
        ) or DATA_UUID
        rootfs_uuid = (
            boot_seed_target.get("rootfsUuid")
            if isinstance(boot_seed_target, Mapping)
            else ROOTFS_UUID
        ) or ROOTFS_UUID
        self.snapshot["runtime"].update(
            {"dataUuid": data_uuid, "rootfsUuid": rootfs_uuid, "storageValid": True}
        )
        return self._result("storage", dataUuid=data_uuid, rootfsUuid=rootfs_uuid)

    def create_owned_container(
        self,
        image_record: Mapping[str, Any],
        expected_data_uuid: str | None,
        expected_rootfs_uuid: str | None,
    ) -> dict[str, Any]:
        del image_record
        self.snapshot["runtime"].update(
            {
                "state": "stopped",
                "containerId": NEW_CONTAINER,
                "dataUuid": expected_data_uuid,
                "rootfsUuid": expected_rootfs_uuid,
                "imageInputSha256": INPUT_DIGEST,
                "imageBootInputSha256": BOOT_DIGEST,
                "createSpecMatches": True,
                "networkMatches": True,
                "volumeMatches": True,
            }
        )
        return self._result("create", containerId=NEW_CONTAINER)

    def start_owned_container(self, expected_container_id: str, wait: bool = True) -> dict[str, Any]:
        self.snapshot["runtime"].update(
            {"state": "running", "containerId": expected_container_id}
        )
        return self._result("start", containerId=expected_container_id, waited=wait)

    def deploy_components(
        self,
        mapping: Mapping[str, Any],
        artifact_records: Any,
        expected_container_id: str,
    ) -> dict[str, Any]:
        del artifact_records
        daemon = mapping.get("daemon")
        if daemon in {"install", "reconcile"}:
            self.snapshot["components"]["daemon"]["state"] = "matching"
        deploy = {name: action for name, action in mapping.items() if name != "daemon"}
        if isinstance(deploy, Mapping):
            for name, action in deploy.items():
                if action not in {None, "reuse", "inspect"}:
                    self.snapshot["components"]["deploy"][name] = "matching"
        return self._result(
            "deploy", actions=dict(mapping), containerId=expected_container_id
        )

    def reconcile_control_plane(self) -> dict[str, Any]:
        self.snapshot["components"]["daemon"]["state"] = "matching"
        return self._result("control", controlReady=True)

    def _component(self, name: str, action: Any) -> dict[str, Any]:
        self.snapshot["components"][name]["state"] = "matching"
        return self._result(name, action=action)

    def reconcile_identity(self, action: Any, regeneration_capability: Any) -> dict[str, Any]:
        del regeneration_capability
        return self._component("identity", action)

    def reconcile_location(self, action: Any, regeneration_capability: Any) -> dict[str, Any]:
        del regeneration_capability
        return self._component("location", action)

    def reconcile_keybox(self, action: Any) -> dict[str, Any]:
        return self._component("keybox", action)

    def reconcile_camera(self, action: Any) -> dict[str, Any]:
        return self._component("camera", action)

    def reconcile_google(
        self,
        action: Any,
        fresh_bootstrap: bool = False,
    ) -> dict[str, Any]:
        self.calls.append(
            (
                "google-bootstrap",
                {"freshBootstrap": fresh_bootstrap},
            )
        )
        return self._component("google", action)

    def reconcile_proxy_desired(self) -> dict[str, Any]:
        proxy = self.snapshot["components"]["proxy"]
        proxy["state"] = "matching"
        proxy["generation"] = 7
        enabled = proxy.get("enabled")
        return self._result(
            "proxy",
            generation=7,
            enabled=enabled if isinstance(enabled, bool) else False,
            dataPlaneVerified=True,
        )

    def reconcile_protection(self, action: Any, expected_digest: str | None) -> dict[str, Any]:
        self.snapshot["components"]["protection"]["state"] = "matching"
        return self._result("protection", action=action, currentDigest=expected_digest)

class FakeArtifacts:
    def __init__(self, manager: FakeManager, *, resolve: bool = True) -> None:
        self.manager = manager
        self.resolve = resolve
        self.calls: list[tuple[tuple[str, ...], bool]] = []

    def ensure(
        self,
        targets: Any,
        force: bool = False,
        *,
        deadline: float | None = None,
        cancelled: Any = None,
    ) -> dict[str, Any]:
        del deadline, cancelled
        names = tuple(targets)
        self.calls.append((names, force))
        if self.resolve:
            self.manager.snapshot["artifactTargets"] = []
            self.manager.snapshot["artifactRecords"] = [
                artifact_record(name) for name in names
            ]
        return {
            "ok": True,
            "schema": "dev.xenoid.artifacts/v1",
            "targets": {
                name: {"status": "reused", "durationMs": 0} for name in names
            },
        }


class FakeAcceptance:
    def __init__(self, manager: FakeManager) -> None:
        self.manager = manager
        self.calls: list[dict[str, Any]] = []
        self.fail_final = False
        self.drift_after: list[Callable[[], None]] = []

    def observe(
        self,
        context: Any,
        expected: Mapping[str, Any],
        mode: str,
        deadline: float | None,
        progress: Callable[[Mapping[str, Any]], None] | None,
    ) -> dict[str, Any]:
        del context, deadline
        self.calls.append({"mode": mode, "expected": dict(expected)})
        if progress is not None:
            progress(
                {
                    "schema": "dev.xenoid.progress/v1",
                    "command": "up",
                    "phase": "acceptance",
                    "state": "running",
                    "durationMs": 0,
                    "detail": "observing",
                }
            )
        if mode == "convergence-resolve":
            return {
                "ok": False,
                "observationValid": True,
                "observationSha256": OBSERVATION_DIGEST,
                "componentActions": {
                    "daemon": "install",
                    "deploy": {
                        name: "deploy"
                        for name in self.manager.snapshot["components"]["deploy"]
                    },
                    "identity": "converge",
                    "location": "converge",
                    "proxy": "reconcile",
                    "keybox": "reconcile",
                    "camera": "reconcile",
                    "google": "reconcile",
                    "protection": "reconcile",
                },
                "acceptanceChecks": list(self.manager.snapshot["acceptanceChecks"]),
                "errorCode": "components_not_converged",
            }
        if self.fail_final:
            return {
                "ok": False,
                "observationSha256": OBSERVATION_DIGEST,
                "errorCode": "acceptance_failed",
            }
        if self.drift_after:
            self.drift_after.pop(0)()
        return {
            "ok": True,
            "schema": "dev.xenoid.live-acceptance/v1",
            "observationSha256": OBSERVATION_DIGEST,
            "acceptanceChecks": list(self.manager.snapshot["acceptanceChecks"]),
        }


class FakeClock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def monotonic(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@contextlib.contextmanager
def manager_fixture(snapshot: Mapping[str, Any] | None = None) -> Iterator[FakeManager]:
    with tempfile.TemporaryDirectory(prefix="xenoid-convergence-contract-") as directory:
        root = Path(directory) / "state"
        yield FakeManager(root, snapshot or healthy_snapshot())


def planner_for(snapshot: Mapping[str, Any], *, skip_build: bool = False) -> convergence.ConvergencePlan:
    with manager_fixture(snapshot) as manager:
        return convergence.ConvergencePlanner(manager).inspect(skip_build=skip_build)


def expect_error(function: Callable[[], Any], code: str | None = None) -> Any:
    try:
        function()
    except convergence.ConvergenceError as exc:
        if code is not None:
            require(exc.code == code, f"expected {code}, got {exc.code}")
        return exc
    raise ContractFailure("expected ConvergenceError")

@case("regenerationPreflightRequiresNoOpPlan")
def regeneration_preflight_requires_no_op_plan() -> None:
    plan = planner_for(healthy_snapshot(), skip_build=True)
    require(
        cli._regeneration_plan_is_runtime_only(plan),
        "healthy no-op plan rejected by regeneration preflight",
    )
    mutations = {
        "image_action": "ensure-desired",
        "runtime_action": "recreate",
        "boot_seed_action": "initialize_replace",
        "daemon_action": "install",
        "deploy_components": {"rootd": "deploy"},
        "identity_action": "converge",
        "location_action": "converge",
        "proxy_action": "reconcile",
        "keybox_action": "reconcile",
        "camera_action": "reconcile",
        "google_action": "reconcile",
        "protection_action": "maintenance",
    }
    plan_fields = {
        field.name: getattr(plan, field.name)
        for field in dataclasses.fields(plan)
    }
    for field, value in mutations.items():
        require(
            not cli._regeneration_plan_is_runtime_only(
                SimpleNamespace(**{**plan_fields, field: value})
            ),
            f"regeneration preflight accepted mutating {field}",
        )
    state = {"transactionId": "a" * 32}
    direct = cli._regeneration_success_result(
        state,
        resumed=False,
        google_identity={"ok": True, "provider": "microg"},
    )
    recovered = cli._regeneration_success_result(
        state,
        resumed=True,
        cleaned=True,
    )
    canonical_keys = {
        "schema", "transactionId", "resumed", "phase", "runtimeOnly",
        "containerRecreated", "ok", "regeneration",
    }
    require(canonical_keys <= set(direct), "direct success envelope incomplete")
    require(canonical_keys <= set(recovered), "resumed success envelope incomplete")
    require(
        direct["schema"] == recovered["schema"]
        == "dev.xenoid.device-regenerate/v3"
        and direct["regeneration"]["schema"] == direct["schema"]
        and recovered["regeneration"]["schema"] == recovered["schema"],
        "success paths disagree on the canonical v3 schema",
    )

@case("pendingRegenerationDryRunShowsRemainingWork")
def pending_regeneration_dry_run_shows_remaining_work() -> None:
    state = {"phase": "radio_committed", "transactionId": "a" * 32}
    preview = cli._regeneration_dry_run_result(state)
    require(
        preview.get("schema") == "dev.xenoid.device-regenerate/v3"
        and preview.get("dryRun") is True
        and preview.get("resumed") is True
        and preview.get("runtimeOnly") is True
        and preview.get("containerRecreated") is False,
        "pending regeneration preview used the ordinary convergence contract",
    )
    start = cli.REGENERATION_PHASES.index("radio_committed") + 1
    require(
        preview.get("actions") == list(cli.REGENERATION_PHASES[start:]),
        "pending regeneration preview did not report remaining journal work",
    )


@case("regenerationRuntimePreflightIsOneDryRunOnly")
def regeneration_runtime_preflight_is_one_dry_run_only() -> None:
    plan = planner_for(healthy_snapshot(), skip_build=True)
    calls: list[dict[str, Any]] = []

    class Executor:
        def __init__(self, manager: Any) -> None:
            del manager

        def run(self, **kwargs: Any) -> dict[str, Any]:
            calls.append(dict(kwargs))
            return {
                "ok": True,
                "dryRun": True,
                "plan": plan.to_dict(),
                "initialPlanDigest": plan.plan_digest,
            }

    with mock.patch.object(cli, "ConvergenceExecutor", Executor):
        result = cli._regeneration_runtime_preflight(object())
    require(result["ok"] is True, "verified no-op dry-run plan was rejected")
    require(
        calls == [{"skip_build": True, "dry_run": True}],
        "regeneration preflight executed convergence or an auto follow-up",
    )


@case("regenerationPrejournalFailuresAreCanonical")
def regeneration_prejournal_failures_are_canonical() -> None:
    failed = cli._regeneration_preflight_failure("synthetic_preflight_failure")
    require(
        failed == {
            "schema": "dev.xenoid.device-regenerate/v3",
            "ok": False,
            "resumed": False,
            "phase": "preflight",
            "runtimeOnly": True,
            "containerRecreated": False,
            "error": "synthetic_preflight_failure",
        },
        "pre-journal failure pretended a prepared journal exists",
    )



@case("legacyRegenerationMarkersAreReadOnlyRecoveryStatus")
def legacy_regeneration_markers_are_read_only_recovery_status() -> None:
    shapes: list[tuple[str | None, bytes, str]] = [
        (None, b"", "no-op"),
        ("device-regenerate.json", b"{}\n", "legacy-regeneration-recovery"),
        ("device-regenerate-v2.json", b"{}\n", "legacy-regeneration-recovery"),
        ("device-regenerate-v1.evidence", b"{}\n", "legacy-regeneration-recovery"),
        ("device-regenerate-v1.corrupt", b"{not-json", "legacy-regeneration-recovery"),
        (
            "device-regenerate-v3.json",
            json.dumps(
                {
                    "schema": "dev.xenoid.device-regenerate/v3",
                    "phase": "prepared",
                    "transactionId": "a" * 32,
                },
                sort_keys=True,
            ).encode("ascii") + b"\n",
            "resource-conflict",
        ),
    ]
    for filename, payload, expected in shapes:
        with tempfile.TemporaryDirectory(prefix="xenoid-legacy-status-") as directory:
            root = Path(directory) / "state"
            root.mkdir(mode=0o700)
            if filename is not None:
                marker = root / filename
                marker.write_bytes(payload)
                marker.chmod(0o600)
            manager = object.__new__(RuntimeManager)
            manager.context = SimpleNamespace(
                state_root=root,
                instance_id=INSTANCE_ID,
                public_dict=lambda: {},
            )
            manager.lease = SimpleNamespace(
                container_name="xenoid-test",
                volume_name="xenoid-test-data",
                host_adb_port=5555,
                host_daemon_port=42871,
            )
            manager.ensure_instance_lease = lambda: None
            pending = manager._observe_pending_operations()
            observation = healthy_snapshot()
            observation.update(
                {"pending": pending, "storage": {}, "schema": "dev.xenoid.convergence-observation/v1"}
            )
            manager.observe_convergence = lambda skip_build=False: copy.deepcopy(observation)
            before = {
                path.name: path.read_bytes()
                for path in root.iterdir()
                if path.is_file()
            }
            with mock.patch.object(backend, "which", return_value="/usr/bin/docker"):
                status = manager.status()
            after = {
                path.name: path.read_bytes()
                for path in root.iterdir()
                if path.is_file()
            }
            require(
                status["recommendedAction"] == expected,
                f"{filename or 'clean'} recommended {status['recommendedAction']}",
            )
            if expected == "resource-conflict":
                require(status["ok"] is False, "invalid journal status reported healthy")
            require(before == after, f"status mutated state tree for {filename or 'clean'}")


@case("upDryRunDoesNotStartEngine")
def up_dry_run_does_not_start_engine() -> None:
    emitted: list[dict[str, Any]] = []
    manager = SimpleNamespace(
        engine_reachable=lambda: False,
        ensure_engine_started=lambda: (_ for _ in ()).throw(
            AssertionError("dry-run started the engine")
        ),
    )
    with mock.patch.object(cli, "runtime", return_value=manager), mock.patch.object(
        cli, "print_json", side_effect=emitted.append
    ):
        code = cli.cmd_up(SimpleNamespace(dry_run=True))
    require(code == 1, "unreachable engine dry-run should fail")
    require(emitted and emitted[-1].get("dryRun") is True, "dry-run marker missing")

@case("upResumesRegenerationBeforeGoogleAssetAcquisition")
def up_resumes_regeneration_before_google_asset_acquisition() -> None:
    args = SimpleNamespace(
        context=SimpleNamespace(instance_id=INSTANCE_ID),
        config=SimpleNamespace(google_services_provider="microg"),
        dry_run=False,
        skip_build=False,
    )
    pending = {"transactionId": "a" * 32, "phase": "google_reset"}
    expected = {"ok": True, "schema": "dev.xenoid.device-regenerate/v3"}
    manager = SimpleNamespace(ensure_engine_started=lambda: {"ok": True})
    with mock.patch.object(cli, "runtime", return_value=manager), \
         mock.patch.object(cli, "RegenerationJournal") as journal_type, \
         mock.patch.object(cli, "_execute_device_regeneration", return_value=expected) as resume, \
         mock.patch.object(
             cli,
             "_prepare_google_assets_for_up",
             side_effect=AssertionError("asset acquisition ran before resume"),
         ), \
         mock.patch.object(cli, "print_json"), \
         mock.patch.object(cli, "cli_operation_lock", return_value=contextlib.nullcontext()):
        journal_type.return_value.load.return_value = pending
        code = cli.cmd_up(args)
    require(code == 0 and resume.call_count == 1, "up did not resume pending v3 regeneration")


@case("corruptRegenerationJournalUsesCanonicalEnvelope")
def corrupt_regeneration_journal_uses_canonical_envelope() -> None:
    context = SimpleNamespace(instance_id=INSTANCE_ID)
    args = SimpleNamespace(
        context=context,
        config=SimpleNamespace(google_services_provider="microg"),
        dry_run=False,
        skip_build=False,
        _operation_lock_held=True,
    )
    manager = SimpleNamespace(
        ensure_engine_started=lambda: {"ok": True, "started": False},
    )
    invalid = cli.IdentityError(
        "device_regeneration_state_invalid",
        "invalid regeneration journal",
    )
    expected = {
        "schema": "dev.xenoid.device-regenerate/v3",
        "ok": False,
        "runtimeOnly": True,
        "containerRecreated": False,
        "error": "device_regeneration_state_invalid",
        "resumed": False,
        "phase": "preflight",
    }
    emitted: list[dict[str, Any]] = []
    with mock.patch.object(cli, "runtime", return_value=manager), \
         mock.patch.object(cli, "RegenerationJournal") as journal_type, \
         mock.patch.object(cli, "print_json", side_effect=emitted.append), \
         mock.patch.object(cli, "cli_operation_lock", return_value=contextlib.nullcontext()):
        journal_type.return_value.load.side_effect = invalid
        code = cli.cmd_up(args)
    require(code == 1 and emitted == [expected], "up corrupt journal envelope changed")

    emitted.clear()
    with mock.patch.object(cli, "RegenerationJournal") as journal_type, \
         mock.patch.object(cli, "print_json", side_effect=emitted.append):
        journal_type.return_value.load.side_effect = invalid
        code = cli.cmd_device_regenerate(
            SimpleNamespace(context=context, dry_run=True)
        )
    require(
        code == 1 and emitted == [expected],
        "device regenerate dry-run corrupt journal envelope changed",
    )


@case("googleRuntimePostconditionRequiresOfflineSeededMode")
def google_runtime_postcondition_requires_offline_seeded_mode() -> None:
    status = {"ok": True, "googleIdentityMode": "provider-managed"}
    manager = SimpleNamespace(
        cfg=SimpleNamespace(google_services_provider="microg"),
        reconcile_google=lambda action: dict(status),
    )
    rejected = cli._regeneration_google_runtime_postcondition(manager)
    require(
        rejected["ok"] is False
        and rejected["error"] == "google_identity_not_offline_seeded",
        "ready provider-managed Google runtime passed regeneration postcondition",
    )
    status["googleIdentityMode"] = "offline-seeded"
    require(
        cli._regeneration_google_runtime_postcondition(manager)["ok"] is True,
        "offline-seeded Google runtime failed regeneration postcondition",
    )

@case("googleStatusV2AndBindingAcceptance")
def google_status_v2_and_binding_acceptance() -> None:
    status = microg_google_status()
    require(set(status) == GOOGLE_STATUS_KEYS, "Google status v2 top-level keys drifted")
    require(
        status["schema"] == "dev.xenoid.google-services-status/v2"
        and status["provider"] == "microg"
        and status["release"] == MICROG_PLAY_RELEASE
        and status["implementation"] == "microg"
        and status["signatureModel"] == "restricted-spoofing"
        and status["storeImplementation"] == "google-play",
        "Google status v2 identity literals drifted",
    )
    require(
        set(status["runtimeIdentity"])
        == {
            "desiredImageSha256",
            "containerImageSha256",
            "rootfsSourceImageSha256",
            "desiredInputSha256",
            "desiredBootInputSha256",
            "containerInputSha256",
            "containerBootInputSha256",
            "imageMatch",
            "rootfsBootInputMatches",
            "labelsMatch",
            "commandMatch",
            "skipped",
        },
        "Google runtime identity field set drifted",
    )
    require(
        set(status["factoryComponents"])
        == {"gmsCore", "gsfProxy", "playStoreSeed"}
        and all(
            set(item)
            == {
                "package",
                "path",
                "versionCode",
                "sha256",
                "signingCertificateHistorySha256",
                "privileged",
            }
            for item in status["factoryComponents"].values()
        ),
        "Google factory component shape drifted",
    )
    require(
        set(status["effectiveComponents"])
        == {"gmsCore", "gsfProxy", "playStoreSeed"}
        and all(
            set(item)
            == {
                "package",
                "codePath",
                "versionCode",
                "versionName",
                "signerSha256",
                "enabled",
                "system",
                "privileged",
                "updatedSystemApp",
                "processState",
            }
            for item in status["effectiveComponents"].values()
        ),
        "Google effective component shape drifted",
    )
    require(
        set(status["live"]) == {"ok", "checks", "error"}
        and set(status["live"]["checks"]) == GOOGLE_LIVE_CHECKS
        and all(
            set(item) == {"ok", "code"}
            for item in status["live"]["checks"].values()
        ),
        "Google minimal-live shape drifted",
    )
    require(
        status["requiredCapabilities"]
        == [
            "googlePlayServices",
            "accountAuth",
            "cloudMessaging",
            "fusedLocation",
            "playStore",
        ]
        and all(
            set(item)
            == {"scope", "runtimeState", "releaseState", "evidence"}
            for item in status["capabilities"].values()
        ),
        "Google capability model shape drifted",
    )
    unsupported = {
        "scope": "application",
        "runtimeState": "unsupported",
        "releaseState": "unsupported",
        "evidence": "unsupported",
    }
    require(
        all(
            status["capabilities"][name] == unsupported
            for name in (
                "playIntegrity",
                "deviceCertification",
                "drm",
                "antiCheat",
            )
        ),
        "unsupported Google capabilities were promoted",
    )

    protection = healthy_snapshot()["components"]["protection"]
    checks = live_observe._Checks()
    live_observe.LiveAcceptance()._google_and_protection_checks(
        None,
        {
            "googleServices": status,
            "sharedProtection": protection,
        },
        {},
        live_observe._Budget(None),
        checks,
        {},
    )
    require(
        checks.values["googleBinding"] == {"ok": True, "code": "accepted"},
        "committed ready v2 Google status failed convergence acceptance",
    )
    pending = copy.deepcopy(status)
    pending["binding"]["state"] = "pending"
    pending_checks = live_observe._Checks()
    live_observe.LiveAcceptance()._google_and_protection_checks(
        None,
        {
            "googleServices": pending,
            "sharedProtection": protection,
        },
        {},
        live_observe._Budget(None),
        pending_checks,
        {},
    )
    require(
        pending_checks.values["googleBinding"]
        == {"ok": False, "code": "google_binding_not_ready"},
        "pending Google binding satisfied convergence acceptance",
    )

@case("googleBootstrapGateDispatch")
def google_bootstrap_gate_dispatch() -> None:
    manager = object.__new__(RuntimeManager)

    def absent_adb(
        _self: Any,
        arguments: list[str],
        timeout: int = 0,
    ) -> dict[str, Any]:
        del timeout
        if arguments[:3] == ["shell", "pm", "path"]:
            return {"ok": True, "stdout": ""}
        prop = arguments[-1]
        values = {
            "ro.build.version.release": "13\n",
            "ro.product.cpu.abilist": "arm64-v8a\n",
            "ro.build.product": "raven\n",
        }
        return {"ok": True, "stdout": values.get(prop, "")}

    with mock.patch.object(RuntimeManager, "adb", new=absent_adb):
        absent = manager.google_services_bootstrap_gate(None)
    require(
        set(absent) == {"ok", "provider", "packages", "platform"}
        and absent["ok"] is True
        and absent["provider"] == "none"
        and set(absent["packages"])
        == {
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.android.vending",
        }
        and all(
            set(item) == {"present", "expected", "path"}
            and item == {
                "present": False,
                "expected": False,
                "path": None,
            }
            for item in absent["packages"].values()
        )
        and absent["platform"]
        == {
            "release": "13",
            "product": "raven",
            "abilist": "arm64-v8a",
            "ok": True,
        },
        "none-provider bootstrap gate shape drifted",
    )

    status = microg_google_status()
    microg_result = {
        "ok": True,
        "checks": status["live"]["checks"],
        "error": None,
        "components": status["effectiveComponents"],
    }
    with mock.patch.object(
        RuntimeManager,
        "_google_services_gate_microg",
        return_value=microg_result,
    ) as microg_gate:
        dispatched = manager.google_services_bootstrap_gate(
            SimpleNamespace(provider="microg")
        )
    require(
        dispatched == microg_result
        and set(dispatched) == {"ok", "checks", "error", "components"},
        "microG bootstrap gate did not preserve the v2 live shape",
    )
    microg_gate.assert_called_once()

    try:
        manager.google_services_bootstrap_gate(
            SimpleNamespace(provider="mindthegapps")
        )
    except GoogleServicesError as exc:
        require(
            exc.code == "google_services_release_retired",
            "retired bootstrap dispatch returned an unstable error",
        )
    else:
        raise ContractFailure("retired provider reached a bootstrap gate")



@case("canonicalPlanAndDigest")
def canonical_plan_and_digest() -> None:
    snapshot = healthy_snapshot()
    plan = planner_for(snapshot)
    payload = plan.to_dict()
    require(set(payload) == PLAN_KEYS, "canonical plan field set drifted")
    require(payload["schema"] == "dev.xenoid.convergence-plan/v1", "plan schema")
    require(
        isinstance(payload["planDigest"], str)
        and len(payload["planDigest"]) == 64
        and set(payload["planDigest"]) <= set("0123456789abcdef"),
        "plan digest is not lowercase SHA-256",
    )
    require(convergence.ConvergencePlan.from_dict(payload) == plan, "plan round trip")
    noisy = copy.deepcopy(snapshot)
    noisy["observedAt"] = "secret timestamp"
    noisy["log"] = "/private/operator raw child output"
    require(planner_for(noisy).plan_digest == plan.plan_digest, "noise changed plan digest")
    changed = copy.deepcopy(snapshot)
    changed["components"]["proxy"]["state"] = "drift"
    require(planner_for(changed).plan_digest != plan.plan_digest, "action drift kept digest")
    try:
        plan.runtime_action = "recreate"  # type: ignore[misc]
    except (dataclasses.FrozenInstanceError, AttributeError):
        pass
    else:
        raise ContractFailure("ConvergencePlan is mutable")
    invalid = dict(payload)
    invalid["unknown"] = True
    expect_error(lambda: convergence.ConvergencePlan.from_dict(invalid))


@case("minimumActionMatrixAndPrecedence")
def minimum_action_matrix_and_precedence() -> None:
    observed: set[str] = set()

    healthy = planner_for(healthy_snapshot())
    observed.add(convergence.recommended_action(healthy))
    require(healthy.runtime_action == "reuse", "healthy runtime not reused")
    require(healthy.image_action == "reuse-selected", "healthy image not reused")

    stopped_snapshot = healthy_snapshot()
    stopped_snapshot["runtime"]["state"] = "stopped"
    stopped = planner_for(stopped_snapshot)
    require(stopped.runtime_action == "start", "stopped runtime not started")
    observed.add(convergence.recommended_action(stopped))

    absent_snapshot = healthy_snapshot()
    absent_snapshot["runtime"].update({"state": "absent", "containerId": None})
    absent = planner_for(absent_snapshot)
    require(absent.runtime_action == "create", "absent runtime not created")
    require(absent.image_action == "ensure-desired", "create did not ensure image")
    observed.add(convergence.recommended_action(absent))

    recreate_snapshot = healthy_snapshot()
    recreate_snapshot["runtime"]["createSpecMatches"] = False
    recreate = planner_for(recreate_snapshot)
    require(recreate.runtime_action == "recreate", "create-spec drift did not recreate")
    observed.add(convergence.recommended_action(recreate))

    image_required = dataclasses.replace(
        healthy,
        image_action="ensure-desired",
        selected_image_record=None,
        plan_digest="",
    )
    observed.add(convergence.recommended_action(image_required))

    daemon_snapshot = healthy_snapshot()
    daemon_snapshot["components"]["daemon"]["state"] = "drift"
    daemon = planner_for(daemon_snapshot)
    require(daemon.daemon_action == "install", "daemon drift not install-only")
    require(daemon.runtime_action == "reuse", "daemon drift recreated runtime")
    observed.add(convergence.recommended_action(daemon))

    helper_snapshot = healthy_snapshot()
    helper_snapshot["components"]["deploy"]["input"] = "drift"
    helper = planner_for(helper_snapshot)
    require(helper.runtime_action == "reuse", "helper drift recreated runtime")
    require(helper.deploy_components is not None, "helper drift not deployed")
    observed.add(convergence.recommended_action(helper))

    proxy_snapshot = healthy_snapshot()
    proxy_snapshot["components"]["proxy"]["state"] = "drift"
    proxy = planner_for(proxy_snapshot)
    require(proxy.runtime_action == "reuse", "proxy drift recreated runtime")
    observed.add(convergence.recommended_action(proxy))

    protection_snapshot = healthy_snapshot()
    protection_snapshot["components"]["protection"]["state"] = "maintenance"
    protection = planner_for(protection_snapshot)
    observed.add(convergence.recommended_action(protection))
    observed.add(convergence.recommended_action(healthy, resumed=True))

    for code in (
        "daemon_seed_contract_incompatible",
        "device_regeneration_legacy_pending",
        "resource_conflict",
    ):
        observed.add(convergence.ConvergenceError(code).recommended_action)

    require(
        observed
        == {
            "no-op",
            "resume",
            "start",
            "create",
            "recreate",
            "image-required",
            "daemon-only",
            "helper-only",
            "proxy-recovery",
            "protection-maintenance",
            "daemon-incompatible",
            "legacy-regeneration-recovery",
            "resource-conflict",
        },
        f"recommended action enum incomplete: {sorted(observed)}",
    )

    conflict = healthy_snapshot()
    conflict["runtime"]["ownershipValid"] = False
    conflict["runtime"]["integrationIdentityValid"] = False
    error = expect_error(lambda: planner_for(conflict))
    require(error.recommended_action == "resource-conflict", "ownership precedence weakened")

    incompatible = healthy_snapshot()
    incompatible["components"]["daemon"]["state"] = "incompatible"
    error = expect_error(lambda: planner_for(incompatible))
    require(error.recommended_action == "daemon-incompatible", "daemon identity not fail-closed")


@case("artifactResolutionOneReplanAndSkipBuild")
def artifact_resolution_one_replan_and_skip_build() -> None:
    unresolved = healthy_snapshot()
    unresolved["artifactTargets"] = ["daemon"]
    unresolved["artifactRecords"] = []
    with manager_fixture(unresolved) as manager:
        artifacts = FakeArtifacts(manager)
        acceptance = FakeAcceptance(manager)
        progress: list[Mapping[str, Any]] = []
        result = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=acceptance,
            artifact_builder=artifacts,
        ).run(progress=progress.append)
        require(result["ok"] is True, f"resolved convergence failed: {result.get('error')}")
        require(len(artifacts.calls) == 1, "artifact closure was not ensured exactly once")
        require(manager.observe_count >= 2, "artifact resolution did not re-inspect")
        require(result["resolvedPlanDigest"] is not None, "resolved plan digest missing")
        first_mutation = next(
            (index for index, call in enumerate(manager.calls) if call[0] not in {"observe", "lock", "acceptance-context"}),
            len(manager.calls),
        )
        last_observe = max(index for index, call in enumerate(manager.calls) if call[0] == "observe")
        require(last_observe < first_mutation, "runtime mutated before artifact replan")

    with manager_fixture(unresolved) as manager:
        artifacts = FakeArtifacts(manager, resolve=False)
        result = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=artifacts,
        ).run()
        require(result["ok"] is False, "still-unresolved artifact plan mutated")
        require(len(artifacts.calls) == 1, "executor retried artifact resolution")
        require(
            all(call[0] in {"observe", "lock"} for call in manager.calls),
            "unresolved artifact failure reached a runtime mutator",
        )
        require(not (manager.context.state_root / "convergence-v1.json").exists(), "unresolved plan created a journal")

    with manager_fixture(unresolved) as manager:
        artifacts = FakeArtifacts(manager)
        result = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=artifacts,
        ).run(skip_build=True)
        require(result["ok"] is False, "skip-build accepted missing records")
        require(artifacts.calls == [], "skip-build invoked the artifact builder")


@case("dryRunIsReadOnlyAndExplicit")
def dry_run_is_read_only_and_explicit() -> None:
    snapshot = healthy_snapshot()
    snapshot["artifactTargets"] = ["daemon"]
    snapshot["artifactRecords"] = []
    with manager_fixture(snapshot) as manager:
        artifacts = FakeArtifacts(manager)
        acceptance = FakeAcceptance(manager)
        progress: list[Mapping[str, Any]] = []
        result = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=acceptance,
            artifact_builder=artifacts,
        ).run(progress=progress.append, dry_run=True)
        require(result["schema"] == "dev.xenoid.convergence/v1", "dry-run schema")
        require(result["dryRun"] is True and result["ok"] is True, "dry-run result")
        require(result["plan"]["resolution"] == "requires-artifacts", "dry-run guessed artifacts")
        require(artifacts.calls == [], "dry-run built artifacts")
        require(acceptance.calls == [], "dry-run performed live acceptance")
        require(
            all(call[0] in {"lock", "observe"} for call in manager.calls),
            "dry-run mutated manager",
        )
        require(not (manager.context.state_root / "convergence-v1.json").exists(), "dry-run wrote journal")
        require(progress and progress[0]["phase"] == "inspecting", "pre-hash inspecting event missing")

    with manager_fixture(healthy_snapshot()) as manager:
        plan = convergence.ConvergencePlanner(manager).inspect(skip_build=True)
        journal = convergence.ConvergenceJournal.for_manager(manager)
        _create_journal(journal, plan)
        before = journal.path.read_bytes()
        result = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        ).run(dry_run=True, skip_build=True)
        require(result["ok"] is True, "dry-run could not inspect retained journal")
        require(
            journal.path.read_bytes() == before,
            "dry-run adopted, rewrote, or cleared the convergence journal",
        )



def _create_journal(journal: Any, plan: Any) -> dict[str, Any]:
    values = {
        "operation_id": "9" * 32,
        "regeneration_transaction_id": None,
        "selected_image_input_sha256": INPUT_DIGEST,
        "selected_image_boot_input_sha256": BOOT_DIGEST,
        "old_container_id": OLD_CONTAINER,
        "observed_data_uuid": DATA_UUID,
        "observed_rootfs_uuid": ROOTFS_UUID,
        "boot_seed_target": None,
        "proxy_generation": 7,
        "proxy_enabled": False,
        "proxy_quarantine_required": False,
        "observation": healthy_snapshot(),
    }
    parameters = inspect.signature(journal.create).parameters
    kwargs = {name: values[name] for name in parameters if name in values}
    created = journal.create(plan, **kwargs)
    return dict(created)


def _phase_updates(phase: str) -> dict[str, Any]:
    common = {
        "selectedImageInputSha256": INPUT_DIGEST,
        "selectedImageBootInputSha256": BOOT_DIGEST,
        "oldContainerId": OLD_CONTAINER,
        "seedContainerId": SEED_CONTAINER,
        "newContainerId": NEW_CONTAINER,
        "observedDataUuid": DATA_UUID,
        "observedRootfsUuid": ROOTFS_UUID,
        "proxyGeneration": 7,
        "proxyQuarantined": True,
        "liveResolution": {
            "observationSha256": OBSERVATION_DIGEST,
            "componentActions": {
                "daemon": "reuse",
                "deploy": {},
                "identity": "reuse",
                "location": "reuse",
                "proxy": "reuse",
                "keybox": "reuse",
                "camera": "reuse",
                "google": "reuse",
                "protection": "reuse",
            },
            "acceptanceChecks": ["container"],
        },
    }
    if phase == "planned":
        return {}
    return common


@case("journalStrictnessAndEveryCrashBoundary")
def journal_strictness_and_every_crash_boundary() -> None:
    with manager_fixture() as manager:
        plan = convergence.ConvergencePlanner(manager).inspect()
        journal = convergence.ConvergenceJournal(manager)
        record = _create_journal(journal, plan)
        path = manager.context.state_root / "convergence-v1.json"
        require(path.exists(), "journal not created")
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, "journal mode is not 0600")
        require(set(record) == JOURNAL_KEYS, "journal field set drifted")
        require(record["schema"] == "dev.xenoid.convergence-journal/v1", "journal schema")
        require(record["phase"] == "planned", "journal did not start planned")
        require(record["completed"] == ["planned"], "planned completion missing")
        require(len(path.read_bytes()) <= 256 * 1024, "journal exceeded 256 KiB")

        # Before and after every phase boundary must independently reload.  This
        # models process death on either side of each atomic rename.
        seen = ["planned"]
        before_after: list[tuple[str, bytes, bytes]] = []
        for phase in PHASES[1:]:
            before = path.read_bytes()
            journal.advance(phase, **_phase_updates(phase))
            after = path.read_bytes()
            before_after.append((phase, before, after))
            loaded = convergence.ConvergenceJournal(manager).load()
            seen.append(phase)
            require(loaded["phase"] == phase, f"{phase}: phase not durable")
            require(loaded["completed"] == seen, f"{phase}: completion order drifted")
        for phase, before, after in before_after:
            path.write_bytes(before)
            path.chmod(0o600)
            require(convergence.ConvergenceJournal(manager).load() is not None, f"{phase}: pre-crash did not resume")
            path.write_bytes(after)
            path.chmod(0o600)
            require(convergence.ConvergenceJournal(manager).load()["phase"] == phase, f"{phase}: post-crash did not resume")

        valid = path.read_bytes()
        valid_payload = json.loads(valid)
        corruptions = []
        malformed = dict(valid_payload)
        malformed["unknown"] = True
        corruptions.append(json.dumps(malformed).encode())
        malformed = dict(valid_payload)
        malformed["schema"] = "dev.xenoid.convergence/v2"
        corruptions.append(json.dumps(malformed).encode())
        malformed = dict(valid_payload)
        malformed["planDigest"] = "0" * 64
        corruptions.append(json.dumps(malformed).encode())
        malformed = dict(valid_payload)
        malformed["completed"] = ["accepted", "planned"]
        corruptions.append(json.dumps(malformed).encode())
        corruptions.append(b"{not-json")
        for payload in corruptions:
            path.write_bytes(payload)
            path.chmod(0o600)
            expect_error(lambda: convergence.ConvergenceJournal(manager).load())

        path.write_bytes(valid)
        path.chmod(0o644)
        expect_error(lambda: convergence.ConvergenceJournal(manager).load(), "convergence_state_invalid")
        path.unlink()
        target = manager.context.state_root / "journal-target"
        target.write_bytes(valid)
        target.chmod(0o600)
        path.symlink_to(target)
        expect_error(lambda: convergence.ConvergenceJournal(manager).load(), "convergence_state_invalid")


@case("legacyMissingRootfsUuidJournalsAsNull")
def legacy_missing_rootfs_uuid_journals_as_null() -> None:
    snapshot = healthy_snapshot()
    snapshot["runtime"]["rootfsUuid"] = ""
    with manager_fixture(snapshot) as manager:
        plan = convergence.ConvergencePlanner(manager).inspect()
        journal = convergence.ConvergenceJournal(manager)
        created = journal.create(
            plan,
            operation_id="8" * 32,
            observation=snapshot,
        )
        require(
            created["observedRootfsUuid"] is None,
            "missing legacy rootfs UUID was not normalized",
        )
        convergence.ConvergenceExecutor(manager)._validate_resume_state(
            created,
            snapshot,
        )


@case("storageOwnerCrashResumesBeforeStateRefresh")
def storage_owner_crash_resumes_before_state_refresh() -> None:
    snapshot = healthy_snapshot()
    snapshot["runtime"]["createSpecMatches"] = False
    with manager_fixture(snapshot) as manager:
        plan = convergence.ConvergencePlanner(manager).inspect()
        journal = convergence.ConvergenceJournal(manager)
        state = _create_journal(journal, plan)
        state = journal.advance("quarantined", proxyQuarantined=True)
        state = journal.advance("container_removed", oldContainerId=OLD_CONTAINER)
        interrupted = copy.deepcopy(snapshot)
        interrupted["runtime"].update(
            {
                "state": "absent",
                "containerId": None,
                "storageValid": False,
            }
        )
        convergence.ConvergenceExecutor(manager)._validate_resume_state(
            state,
            interrupted,
        )
        committed = journal.advance(
            "storage_converged",
            observedDataUuid=DATA_UUID,
            observedRootfsUuid=ROOTFS_UUID,
        )
        expect_error(
            lambda: convergence.ConvergenceExecutor(manager)._validate_resume_state(
                committed,
                interrupted,
            ),
            "convergence_state_conflict",
        )


@case("quarantineImageLiveResolutionAndReplacementLimits")
def quarantine_image_live_resolution_and_replacement_limits() -> None:
    snapshot = healthy_snapshot()
    snapshot["runtime"].update(
        {
            "state": "absent",
            "containerId": None,
            "dataUuid": TARGET_DATA_UUID,
            "rootfsUuid": TARGET_ROOTFS_UUID,
            "bootSeedRequired": True,
        }
    )
    snapshot["selectedImageRecord"] = None
    snapshot["components"]["proxy"].update(
        {"state": "unknown", "quarantineRequired": True}
    )
    for name in ("daemon", "identity", "location", "keybox", "camera", "google"):
        snapshot["components"][name]["state"] = "unknown"
    for name in snapshot["components"]["deploy"]:
        snapshot["components"]["deploy"][name] = "unknown"
    snapshot["components"]["protection"]["state"] = "unknown"
    with manager_fixture(snapshot) as manager:
        acceptance = FakeAcceptance(manager)
        result = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=acceptance,
            artifact_builder=FakeArtifacts(manager),
        ).run()
        require(result["ok"] is True, f"fresh convergence failed: {result.get('error')}")
        names = [name for name, _ in manager.calls]
        require(
            [
                value
                for name, value in manager.calls
                if name == "google-bootstrap"
            ]
            == [{"freshBootstrap": True}],
            "fresh Google binding capability was not pinned to boot seed",
        )
        require(names.index("quarantine") < names.index("image"), "image ensure preceded quarantine")
        require(names.index("image") < names.index("seed-start"), "seed boot preceded image ensure")
        require(names.index("start") < names.index("acceptance-context"), "live resolution preceded final runtime")
        require(names.index("deploy") < names.index("proxy"), "proxy released before component deployment")
        require(names.count("seed-start") == 1, "fresh seed runtime repeated")
        require(names.count("create") == 1, "final runtime replacement repeated")
        require(names.count("remove") <= 1, "plan performed more than one replacement")
        modes = [entry["mode"] for entry in acceptance.calls]
        require(modes[0] == "convergence-resolve", "live resolution observer missing")
        require(modes[-1] == "convergence-final", "fresh final observer missing")
        require(not (manager.context.state_root / "convergence-v1.json").exists(), "accepted journal retained")
        phases = [entry.get("phase") for entry in result["phases"]]
        require(phases.index("quarantined") < phases.index("image_ensured"), "result phase order")
        require(phases.index("live_resolved") < phases.index("components_deployed"), "live resolution not journaled first")

    replacement = healthy_snapshot()
    replacement["runtime"]["createSpecMatches"] = False
    for component in (
        "daemon",
        "identity",
        "keybox",
        "camera",
        "google",
        "protection",
    ):
        replacement["components"][component]["state"] = "unknown"
    replacement["components"]["proxy"]["state"] = "unknown"
    for component in replacement["components"]["deploy"]:
        replacement["components"]["deploy"][component] = "unknown"
    replacement["components"]["location"]["state"] = "pending"
    with manager_fixture(replacement) as manager:
        result = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        ).run()

        require(result["ok"] is True, "location-coalesced recreate failed")
        removals = [value for name, value in manager.calls if name == "remove"]
        require(len(removals) == 1, "location drift caused multiple replacements")
        require(
            removals[0].get("prepareLocation") is True,
            "pending Location state was not armed before replacement",
        )


@case("retainedCompatibilityJournalResumesBeforeSnapshot")
def retained_compatibility_journal_resumes_before_snapshot() -> None:
    snapshot = healthy_snapshot()
    snapshot["runtime"]["createSpecMatches"] = False
    for component in (
        "daemon",
        "identity",
        "location",
        "proxy",
        "keybox",
        "camera",
        "google",
        "protection",
    ):
        snapshot["components"][component]["state"] = "unknown"
    for component in snapshot["components"]["deploy"]:
        snapshot["components"]["deploy"][component] = "unknown"
    capability = {
        "transactionId": "ab" * 16,
        "legacyEvidenceSha256": "cd" * 32,
    }
    with manager_fixture(snapshot) as manager:
        executor = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        )
        first = executor.run(
            regeneration_capability=capability,
            retain_accepted_journal=True,
        )
        require(first["ok"] is True, "compatibility convergence failed")
        retained = executor.journal.load()
        require(retained is not None, "accepted compatibility journal cleared")
        require(retained["phase"] == "accepted", "compatibility journal not accepted")
        require(
            retained["operationId"] == capability["legacyEvidenceSha256"][:32],
            "compatibility journal not bound to v1 evidence",
        )
        calls_before = list(manager.calls)
        resumed = executor.run(
            regeneration_capability=capability,
            retain_accepted_journal=True,
        )
        require(resumed["ok"] is True, "accepted compatibility resume failed")
        new_mutations = [
            name
            for name, _ in manager.calls[len(calls_before):]
            if name in {"create", "remove", "seed-start"}
        ]
        require(not new_mutations, "accepted compatibility resume replayed mutation")
        executor.journal.clear()


@case("mutationCrashAfterEngineBoundaryResumes")
def mutation_crash_after_engine_boundary_resumes() -> None:
    def replacement_snapshot() -> dict[str, Any]:
        snapshot = healthy_snapshot()
        snapshot["runtime"]["createSpecMatches"] = False
        for component in (
            "daemon",
            "identity",
            "location",
            "proxy",
            "keybox",
            "camera",
            "google",
            "protection",
        ):
            snapshot["components"][component]["state"] = "unknown"
        for component in snapshot["components"]["deploy"]:
            snapshot["components"]["deploy"][component] = "unknown"
        return snapshot

    with manager_fixture(replacement_snapshot()) as manager:
        manager.interrupt_once.add("remove")
        first = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        ).run()
        require(
            first["ok"] is False
            and first["error"] == "convergence_cancelled"
            and manager.snapshot["runtime"]["state"] == "absent",
            "remove crash fixture did not reach the after-state",
        )
        resumed = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        ).run()
        require(resumed["ok"] is True, "remove after-state was not resumed")
        require(
            [name for name, _ in manager.calls].count("remove") == 2,
            "idempotent remove was not retried exactly once",
        )

    with manager_fixture(replacement_snapshot()) as manager:
        manager.interrupt_once.add("create")
        first = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        ).run()
        require(
            first["ok"] is False
            and first["error"] == "convergence_cancelled"
            and manager.snapshot["runtime"]["state"] == "stopped"
            and manager.snapshot["runtime"]["containerId"] == NEW_CONTAINER,
            "create crash fixture did not retain the stopped after-state",
        )
        calls_before_resume = len(manager.calls)
        resumed = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        ).run()
        require(resumed["ok"] is True, "stopped create after-state was not adopted")
        require(
            manager.snapshot["runtime"]["containerId"] == NEW_CONTAINER,
            "stopped create resume replaced the pinned container",
        )
        # Adoption means the pinned stopped container is never destroyed: the
        # resumed run may complete the interrupted create phase for the same
        # planned container, but a remove or seed-start would be a recreate
        # that discards the journaled after-state.
        replayed = [
            name
            for name, _ in manager.calls[calls_before_resume:]
            if name in {"remove", "seed-start"}
        ]
        require(not replayed, "stopped create resume replayed a mutation")
        require(
            not (manager.context.state_root / "convergence-v1.json").exists(),
            "accepted create resume retained its journal",
        )

    maintenance = healthy_snapshot()
    maintenance["runtime"]["createSpecMatches"] = False
    maintenance["components"]["protection"].update(
        {
            "state": "maintenance",
            "currentDigest": None,
            "replacementRequired": True,
            "maintenanceRequired": True,
        }
    )
    maintenance["components"]["protection"]["observed"].update(
        {
            "ok": False,
            "currentDigest": None,
            "replacementRequired": True,
            "maintenanceRequired": True,
        }
    )
    class MaintenanceResumeAcceptance(FakeAcceptance):
        def observe(
            self,
            context: Any,
            expected: Mapping[str, Any],
            mode: str,
            deadline: float | None,
            progress: Callable[[Mapping[str, Any]], None] | None,
        ) -> dict[str, Any]:
            result = super().observe(
                context,
                expected,
                mode,
                deadline,
                progress,
            )
            if mode == "convergence-resolve":
                result["componentActions"]["location"] = "reuse"
                result["componentActions"]["protection"] = "maintenance"
            return result

    with manager_fixture(maintenance) as manager:
        manager.fail_once["start"] = "adb_authorization_failed"
        first = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=MaintenanceResumeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        ).run()
        require(
            first["ok"] is False
            and first["error"] == "adb_authorization_failed"
            and manager.snapshot["runtime"]["state"] == "running",
            "post-start failure fixture did not retain its running state",
        )
        resumed = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=MaintenanceResumeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        ).run()
        require(
            resumed["ok"] is True,
            f"post-maintenance running resume failed: {resumed.get('error')}",
        )
        require(
            [name for name, _ in manager.calls].count("quiesce") == 1,
            "resume repeated an already-completed protection quiesce",
        )




@case("postGuestFailureResumesAtNextPhase")
def post_guest_failure_resumes_at_next_phase() -> None:
    snapshot = healthy_snapshot()
    snapshot["runtime"]["createSpecMatches"] = False
    for component in (
        "daemon",
        "identity",
        "location",
        "proxy",
        "keybox",
        "camera",
        "google",
        "protection",
    ):
        snapshot["components"][component]["state"] = "unknown"
    for component in snapshot["components"]["deploy"]:
        snapshot["components"]["deploy"][component] = "unknown"

    with manager_fixture(snapshot) as manager:
        manager.fail_once["proxy"] = "policy_route_failed"
        first = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        ).run()
        require(
            first["ok"] is False
            and first["error"] == "policy_route_failed",
            "post-guest failure fixture did not stop at proxy convergence",
        )
        retained = convergence.ConvergenceJournal(manager).load()
        require(
            retained is not None and retained["phase"] == "google_converged",
            "post-guest failure journal did not retain the last completed phase",
        )
        calls_before = {
            name: [entry for entry, _ in manager.calls].count(name)
            for name in ("deploy", "control", "identity", "location", "keybox", "camera", "google")
        }

        resumed = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        ).run()
        require(
            resumed["ok"] is True,
            f"post-guest phase resume failed: {resumed.get('error')}",
        )
        require(
            all(
                [entry for entry, _ in manager.calls].count(name) == count
                for name, count in calls_before.items()
            ),
            "resume replayed already-journaled guest mutations",
        )
        require(
            [name for name, _ in manager.calls].count("proxy") == 2,
            "resume did not retry exactly the failed proxy phase",
        )


@case("thirdStateResumeRefusesMutation")
def third_state_resume_refuses_mutation() -> None:
    with manager_fixture() as manager:
        plan = convergence.ConvergencePlanner(manager).inspect()
        journal = convergence.ConvergenceJournal(manager)
        _create_journal(journal, plan)
        journal.advance("quarantined", **_phase_updates("quarantined"))
        manager.snapshot["runtime"]["containerId"] = "d" * 64
        before = list(manager.calls)
        result = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        ).run()
        require(result["ok"] is False, "third runtime state was accepted")
        require(result["error"] == "convergence_state_conflict", "third-state error changed")
        new_calls = manager.calls[len(before):]
        require(
            all(name in {"observe", "lock"} for name, _ in new_calls),
            "third-state resume performed a mutation",
        )
        require((manager.context.state_root / "convergence-v1.json").exists(), "conflict deleted journal")


@case("componentOnlyUpdateAndLiveAcceptanceOnly")
def component_only_update_and_live_acceptance_only() -> None:
    snapshot = healthy_snapshot()
    snapshot["components"]["daemon"]["state"] = "drift"
    snapshot["components"]["deploy"]["input"] = "drift"
    snapshot["components"]["proxy"]["state"] = "drift"
    snapshot["components"]["proxy"]["generation"] = None
    with manager_fixture(snapshot) as manager:
        acceptance = FakeAcceptance(manager)
        result = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=acceptance,
            artifact_builder=FakeArtifacts(manager),
        ).run()
        require(result["ok"] is True, f"component convergence failed: {result.get('error')}")
        names = [name for name, _ in manager.calls]
        require("deploy" in names and "proxy" in names, "component updates missing")
        require(not ({"image", "remove", "create", "seed-start"} & set(names)), "component drift replaced runtime")
        require(acceptance.calls[-1]["mode"] == "convergence-final", "final acceptance owner bypassed")
        require(
            acceptance.calls[-1]["expected"].get("proxyGeneration") == 7,
            "final acceptance was not bound to reconciled proxy generation",
        )

    source = (ROOT / "src/xenoid/convergence.py").read_text(encoding="utf-8")
    forbidden = (
        "build_doctor_report",
        "GateRunner",
        "verify.sh",
        "ci.sh",
        "xenoid-up.sh",
        "subprocess.run",
        "subprocess.Popen",
    )
    for token in forbidden:
        require(token not in source, f"convergence retained forbidden acceptance path {token}")
    require(
        "self._acceptance_owner()" in source and "LiveAcceptance" in source,
        "accepted does not use LiveAcceptance",
    )


@case("inputDriftGetsOneFollowUpOnly")
def input_drift_gets_one_follow_up_only() -> None:
    with manager_fixture() as manager:
        acceptance = FakeAcceptance(manager)

        def drift_once() -> None:
            manager.snapshot["artifactRecords"][0]["inputSha256"] = "0" * 64
        acceptance.drift_after = [drift_once]
        result = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=acceptance,
            artifact_builder=FakeArtifacts(manager),
        ).run()
        require(result["ok"] is True, f"follow-up convergence failed: {result.get('error')}")
        require(result["followUpPlanDigest"] is not None, "input drift did not create follow-up")
        require([name for name, _ in manager.calls].count("deploy") <= 1, "follow-up repeated component deployment")

    with manager_fixture() as manager:
        acceptance = FakeAcceptance(manager)

        def drift_again() -> None:
            record = manager.snapshot["artifactRecords"][0]
            value = record["inputSha256"]
            record["inputSha256"] = "0" * 64 if value != "0" * 64 else "1" * 64

        acceptance.drift_after = [drift_again, drift_again]
        result = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=acceptance,
            artifact_builder=FakeArtifacts(manager),
        ).run()
        require(result["ok"] is False, "second input drift looped convergence")
        require(result["error"] == "convergence_inputs_changed", "second drift error changed")

@case("staleJournalInputsTriggerFreshReplan")
def stale_journal_inputs_trigger_fresh_replan() -> None:
    snapshot = healthy_snapshot()
    snapshot["runtime"]["createSpecMatches"] = False
    for component in (
        "daemon",
        "identity",
        "location",
        "proxy",
        "keybox",
        "camera",
        "google",
        "protection",
    ):
        snapshot["components"][component]["state"] = "unknown"
    for component in snapshot["components"]["deploy"]:
        snapshot["components"]["deploy"][component] = "unknown"
    with manager_fixture(snapshot) as manager:
        manager.interrupt_once.add("remove")
        first = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        ).run()
        require(first["ok"] is False, "interrupt fixture did not retain a journal")
        # Engine-host inputs drift after the journal was recorded: resume must
        # discard the obsolete journal and converge from a fresh plan.
        manager.snapshot["components"]["protection"]["expectedDigest"] = "6" * 64
        second = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        ).run()
        require(second["ok"] is True, f"fresh replan failed: {second.get('error')}")
        require(second.get("resumed") is False, "stale journal must not be resumed")


@case("deadlineCancellationProgressHeartbeatAndRedaction")
def deadline_cancellation_progress_heartbeat_and_redaction() -> None:
    with manager_fixture() as manager:
        clock = FakeClock()
        manager.convergence_deadline = clock.value
        progress: list[Mapping[str, Any]] = []
        with mock.patch.object(convergence.time, "monotonic", clock.monotonic):
            result = convergence.ConvergenceExecutor(
                manager,
                live_acceptance=FakeAcceptance(manager),
                artifact_builder=FakeArtifacts(manager),
            ).run(progress=progress.append)
        require(result["ok"] is False, "expired outer deadline succeeded")
        require(result["error"].endswith("_timeout"), "deadline error is not phase-specific")
        require(
            all(call[0] in {"observe", "lock", "cancel"} for call in manager.calls),
            "deadline mutated runtime",
        )
        require(any(event["state"] == "timed_out" for event in progress), "timed-out progress missing")

    snapshot = healthy_snapshot()
    snapshot["components"]["daemon"]["state"] = "drift"
    with manager_fixture(snapshot) as manager:
        manager.interrupt_once.add("deploy")
        progress = []
        result = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        ).run(progress=progress.append)
        require(result["ok"] is False and result["error"] == "convergence_cancelled", "SIGINT result changed")
        require(manager.cancelled == 1, "SIGINT did not cancel in-flight convergence")
        require((manager.context.state_root / "convergence-v1.json").exists(), "cancel deleted journal")

    with manager_fixture(snapshot) as manager:
        manager.fail_once["deploy"] = "component_deploy_failed"
        progress = []
        result = convergence.ConvergenceExecutor(
            manager,
            live_acceptance=FakeAcceptance(manager),
            artifact_builder=FakeArtifacts(manager),
        ).run(progress=progress.append)
        rendered = json.dumps({"result": result, "progress": progress})
        require("/private/operator" not in rendered, "private path leaked")
        require("must-not-leak" not in rendered, "token leaked")
        require(all(set(event) == {"schema", "command", "phase", "state", "durationMs", "detail"} for event in progress), "progress schema drifted")
        require(all(event["schema"] == "dev.xenoid.progress/v1" for event in progress), "progress version drifted")
        terminal = [
            event
            for event in progress
            if event["phase"] == "components_deployed"
            and event["state"] in {"failed", "timed_out"}
        ]
        require(len(terminal) == 1, "failed phase emitted duplicate terminal progress")
        result_terminal = [
            phase
            for phase in result["phases"]
            if phase["phase"] == "components_deployed"
            and phase["state"] in {"failed", "timed_out"}
        ]
        require(len(result_terminal) == 1, "failed phase duplicated in final result")

    source = (ROOT / "src/xenoid/convergence.py").read_text(encoding="utf-8")
    require("5.0" in source and "heartbeat" in source.lower(), "five-second heartbeat owner missing")
    require("thread" in source.lower(), "long operations cannot emit concurrent heartbeat")


@case("journaledStartPinsContainerAndImageDigests")
def journaled_start_pins_container_and_image_digests() -> None:
    labels = {
        backend._RUNTIME_SCHEMA_LABEL: "1",
        backend._RUNTIME_INPUT_LABEL: INPUT_DIGEST,
        backend._RUNTIME_BOOT_INPUT_LABEL: BOOT_DIGEST,
    }
    container = {
        "Id": NEW_CONTAINER,
        "Image": IMAGE_ID,
        "State": {"Running": True},
    }
    image = {"Config": {"Labels": labels}}
    manager = SimpleNamespace(
        ensure_instance_lease=lambda: None,
        _owned_container_record=lambda: (container, None),
        _container_matches_lease=lambda *_args, **_kwargs: True,
        _inspect_docker_object=lambda kind, name: (image, None),
        _republish_statfs_fsid_after_start=lambda _result: None,
    )
    started = RuntimeManager.start_owned_container(
        manager,
        expected_container_id=NEW_CONTAINER,
        expected_image_input_sha256=INPUT_DIGEST,
        expected_image_boot_input_sha256=BOOT_DIGEST,
        wait=False,
    )
    require(started.get("ok") is True, "journaled start rejected pinned image digests")

    labels[backend._RUNTIME_INPUT_LABEL] = "9" * 64
    rejected = RuntimeManager.start_owned_container(
        manager,
        expected_container_id=NEW_CONTAINER,
        expected_image_input_sha256=INPUT_DIGEST,
        expected_image_boot_input_sha256=BOOT_DIGEST,
        wait=False,
    )
    require(
        rejected.get("error") == "runtime_spec_mismatch",
        "journaled start accepted mismatched image labels",
    )


@case("directCallersAndRemovedShellAliases")
def direct_callers_and_removed_shell_aliases() -> None:
    require(not (ROOT / "scripts/xenoid-up.sh").exists(), "shell up pipeline still exists")
    require(not (ROOT / "scripts/with-up-lock.py").exists(), "shell up lock still exists")
    cli = (ROOT / "src/xenoid/cli.py").read_text(encoding="utf-8")
    mcp = (ROOT / "src/xenoid/mcp_server.py").read_text(encoding="utf-8")
    remote = (ROOT / "src/xenoid/remote_service.py").read_text(encoding="utf-8")
    for token in ("--reuse-runtime", "REUSE_RUNTIME", "XENOID_UP_LOCK"):
        require(token not in cli + mcp + remote, f"removed alias retained: {token}")
    require("ConvergenceExecutor" in cli and "ConvergenceExecutor" in mcp, "direct executor callers missing")
    require("_run_up_cli_process" not in mcp, "MCP still spawns CLI up")
    require("xenoid_up\": _remote_policy(\"control\", True, \"skipBuild\")" in remote, "remote up schema not clean")
    require("reuseRuntime" not in remote, "remote reuse alias retained")


def main() -> int:
    selected = sys.argv[1:]
    unknown = [name for name in selected if name not in CASES]
    if unknown:
        print(json.dumps({"ok": False, "error": "unknown_case", "cases": unknown}))
        return 2
    results: list[dict[str, Any]] = []
    ok = True
    for name in selected or list(CASES):
        try:
            CASES[name]()
            results.append({"name": name, "ok": True})
        except Exception as exc:
            ok = False
            results.append(
                {
                    "name": name,
                    "ok": False,
                    "error": type(exc).__name__,
                    "detail": str(exc)[:300],
                }
            )
    print(
        json.dumps(
            {
                "schema": "dev.xenoid.convergence-contract/v1",
                "ok": ok,
                "cases": results,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
