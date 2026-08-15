#!/usr/bin/env python3
"""Deterministic contracts for persistent instance storage and safe lifecycle."""
from __future__ import annotations

import json
import stat
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid import backend, config, device_identity, storage

ID_A = "10000000-0000-4000-8000-000000000001"
ID_B = "10000000-0000-4000-8000-000000000002"
TX_A = "20000000-0000-4000-8000-000000000001"
TX_B = "20000000-0000-4000-8000-000000000002"
FS_A = "11111111-1111-4111-8111-111111111111"
FS_B = "22222222-2222-4222-8222-222222222222"
SIZE = storage.CANONICAL_DATA_SIZE_BYTES
SMALL_SIZE = 8 * 1024 * 1024 * 1024


class ContractFailure(AssertionError):
    pass


Case = Callable[[], None]
CASES: dict[str, Case] = {}


def contract_case(name: str) -> Callable[[Case], Case]:
    def register(function: Case) -> Case:
        if name in CASES:
            raise RuntimeError("duplicate contract case")
        CASES[name] = function
        return function
    return register


def require(condition: bool) -> None:
    if not condition:
        raise ContractFailure


@contextmanager
def roots() -> Iterator[tuple[Path, Path]]:
    with tempfile.TemporaryDirectory(prefix="xenoid-storage-contract-") as directory:
        root = Path(directory)
        project = root / "project"
        state = root / "state"
        (project / "src" / "xenoid").mkdir(parents=True)
        with mock.patch.object(config, "_port_available", return_value=True):
            yield project, state


@contextmanager
def fixed_uuids(*values: str) -> Iterator[None]:
    sequence = [uuid.UUID(value) for value in values]
    with mock.patch.object(config.uuid, "uuid4", side_effect=sequence):
        yield


def initialize(project: Path, state: Path, name: str):
    return config.initialize_instance(
        name,
        project_root=project,
        state_home=state,
        env={},
    )


def volume_record(manager: backend.RuntimeManager, name: str) -> dict[str, Any]:
    labels = manager.lease.owner_labels if name == manager.lease.volume_name else {}
    return {
        "Name": name,
        "Driver": "local",
        "Labels": labels,
        "Mountpoint": f"/engine/volumes/{name}/_data",
    }

def image_record(
    filesystem_uuid: str,
    logical_size: int = SIZE,
    filesystem_size: int | None = None,
    payload: str = "",
) -> dict[str, Any]:
    filesystem_size = logical_size if filesystem_size is None else filesystem_size
    return {
        "filesystemUuid": filesystem_uuid,
        "logicalSizeBytes": logical_size,
        "filesystemSizeBytes": filesystem_size,
        "allocatedBytes": max(4096, logical_size // 32),
        "backingTotalBytes": 256 * 1024**3,
        "backingAvailableBytes": 96 * 1024**3,
        "backingPressure": False,
        "payload": payload,
    }


def owned_container_record(
    manager: backend.RuntimeManager,
    container_id: str = "container-id",
    *,
    running: bool = True,
) -> dict[str, Any]:
    return {
        "Id": container_id,
        "Name": f"/{manager.lease.container_name}",
        "Config": {"Labels": dict(manager.lease.owner_labels)},
        "State": {"Running": running},
    }


class FakeRuntime(backend.RuntimeManager):
    def __init__(self, context, cfg, lease):
        self.volumes: dict[str, dict[str, Any]] = {}
        self.images: dict[tuple[str, str], dict[str, Any]] = {}
        self.attachments: dict[str, list[tuple[str, str]]] = {}
        self.containers: dict[str, dict[str, Any]] = {}
        self.actions: list[str] = []
        self.initializations = 0
        self.proxy_captures = 0
        self.container_removals = 0
        super().__init__(context, cfg, lease)

    def _inspect_docker_object(self, object_type: str, name: str):
        if object_type == "volume":
            value = self.volumes.get(name)
        elif object_type == "container":
            value = self.containers.get(name)
        else:
            value = None
        return value, subprocess.CompletedProcess([], 0 if value is not None else 1, "", "")

    def ensure_volume(self) -> dict[str, Any]:
        existing = self.volumes.get(self.lease.volume_name)
        if existing is not None:
            return {"ok": True, "exists": True, "volume": existing}
        created = volume_record(self, self.lease.volume_name)
        self.volumes[self.lease.volume_name] = created
        return {"ok": True, "created": True, "volume": created}

    def _inspect_volume_image(self, volume: dict[str, Any], image_name: str = storage.DATA_IMAGE_NAME):
        value = self.images.get((str(volume["Name"]), image_name))
        if value is None:
            return {"ok": False, "error": "storage_image_invalid"}
        return {"ok": True, **value, "image": image_name}

    def _run_storage_image_action(
        self,
        action: str,
        *,
        expected_uuid: str = "",
        transaction_id: str = "",
        legacy_volume: str = "",
        backup_image: str = "",
        backup_uuid: str = "",
    ) -> dict[str, Any]:
        self.actions.append(action)
        target_key = (self.lease.volume_name, storage.DATA_IMAGE_NAME)
        if action == "initialize":
            if target_key not in self.images:
                self.initializations += 1
                self.images[target_key] = image_record(FS_A)
            else:
                current = self.images[target_key]
                self.images[target_key] = image_record(
                    current["filesystemUuid"],
                    payload=str(current.get("payload", "")),
                )
        elif action == "migrate":
            source = self.images.get((legacy_volume, storage.DATA_IMAGE_NAME))
            if source is None or source["filesystemUuid"] != expected_uuid:
                return {"ok": False, "error": "storage_image_invalid"}
            if source["logicalSizeBytes"] > SIZE:
                return {"ok": False, "error": "storage_size_unsafe"}
            target = self.images.get(target_key)
            if target is not None and target["filesystemUuid"] != source["filesystemUuid"]:
                if not backup_image or target["filesystemUuid"] != backup_uuid:
                    return {"ok": False, "error": "storage_identity_mismatch"}
                self.images[(self.lease.volume_name, backup_image)] = dict(target)
            self.images[target_key] = image_record(
                source["filesystemUuid"],
                payload=str(source.get("payload", "")),
            )
        elif action == "grow":
            current = self.images.get(target_key)
            if (
                current is None
                or current["filesystemUuid"] != expected_uuid
                or current["logicalSizeBytes"] > SIZE
                or current["filesystemSizeBytes"] > current["logicalSizeBytes"]
            ):
                return {"ok": False, "error": "storage_size_unsafe"}
            self.images[target_key] = image_record(
                expected_uuid,
                payload=str(current.get("payload", "")),
            )
        value = self.images.get(target_key)
        if (
            value is None
            or (
                expected_uuid
                and action == "preserve"
                and value["filesystemUuid"] != expected_uuid
            )
            or (
                action == "preserve"
                and (
                    value["logicalSizeBytes"] != SIZE
                    or value["filesystemSizeBytes"] != SIZE
                )
            )
        ):
            return {"ok": False, "error": "storage_image_invalid"}
        return {"ok": True, **value, "action": action}

    def _volume_attachments(self, volume_name: str):
        return list(self.attachments.get(volume_name, [])), {"ok": True}

    def _capture_proxy_desired_for_update(self) -> dict[str, Any]:
        self.proxy_captures += 1
        return {"ok": True, "captured": True, "configured": True}

    def _remove_owned_container(self, container: dict[str, Any]) -> dict[str, Any]:
        self.container_removals += 1
        self.attachments[self.lease.volume_name] = []
        self.containers.pop(str(container["Id"]), None)
        return {"ok": True}

    def _remove_legacy_container(self, container_id: str, expected_name: str, expected_volume: str):
        self.attachments[expected_volume] = []
        return {"ok": True}


def transfer_engine_state(source: FakeRuntime, target: FakeRuntime) -> None:
    target.volumes = source.volumes
    target.images = source.images
    target.attachments = source.attachments
    target.containers = source.containers


@contract_case("freshInitializesExactlyOnce")
def fresh_initializes_exactly_once() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        first = FakeRuntime(context, cfg, lease)
        result = first.ensure_instance_storage()
        require(result["ok"] is True)
        require(first.initializations == 1)
        second = FakeRuntime(context, cfg, lease)
        transfer_engine_state(first, second)
        result = second.ensure_instance_storage()
        require(result["ok"] is True)
        require(second.initializations == 0)
        require(second.actions == ["preserve"])
        persisted = storage.StorageStateStore(context, lease).load()
        require(persisted is not None and persisted["filesystemUuid"] == FS_A)
        require(stat.S_IMODE((context.state_root / storage.STATE_FILENAME).stat().st_mode) == 0o600)


@contract_case("pendingInitializationResumes")
def pending_initialization_resumes() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        store = storage.StorageStateStore(context, lease)
        pending = store.pending("fresh", transaction_id="3" * 32)
        runtime = FakeRuntime(context, cfg, lease)
        runtime.volumes[lease.volume_name] = volume_record(runtime, lease.volume_name)
        runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] = image_record(FS_A)
        result = runtime.ensure_instance_storage()
        require(result["ok"] is True)
        require(runtime.initializations == 0)
        committed = store.load()
        require(committed is not None and committed["state"] == "committed")
        require(committed["transactionId"] == pending["transactionId"])


@contract_case("taggedImageIsAdopted")
def tagged_image_is_adopted() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        runtime.volumes[lease.volume_name] = volume_record(runtime, lease.volume_name)
        runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] = image_record(FS_B)
        result = runtime.ensure_instance_storage()
        require(result["ok"] is True)
        require(runtime.initializations == 0)
        committed = storage.StorageStateStore(context, lease).load()
        require(committed is not None and committed["source"] == "adopted")
        require(committed["filesystemUuid"] == FS_B)


@contract_case("taggedSmallImageGrowsWithoutChangingUuidOrPayload")
def tagged_small_image_grows_without_changing_uuid_or_payload() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        runtime.volumes[lease.volume_name] = volume_record(runtime, lease.volume_name)
        runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] = image_record(
            FS_B,
            SMALL_SIZE,
            SMALL_SIZE,
            "sentinel",
        )
        runtime.containers["container-id"] = owned_container_record(runtime)
        runtime.attachments[lease.volume_name] = [("container-id", lease.container_name)]

        result = runtime.ensure_instance_storage()
        require(result["ok"] is True)
        require(runtime.actions == ["grow"])
        require(runtime.proxy_captures == 1)
        require(runtime.container_removals == 1)
        image = runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)]
        require(image["logicalSizeBytes"] == SIZE)
        require(image["filesystemSizeBytes"] == SIZE)
        require(image["filesystemUuid"] == FS_B)
        require(image["payload"] == "sentinel")
        committed = storage.StorageStateStore(context, lease).load()
        require(committed is not None and committed["source"] == "adopted")
        require(committed["state"] == "committed")
        require(committed["observedFilesystemSizeBytes"] == SIZE)


@contract_case("pendingGrowthRecoversIdempotently")
def pending_growth_recovers_idempotently() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        runtime.volumes[lease.volume_name] = volume_record(runtime, lease.volume_name)
        runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] = image_record(
            FS_B,
            SMALL_SIZE,
            SMALL_SIZE,
            "sentinel",
        )
        store = storage.StorageStateStore(context, lease)
        store.pending(
            "adopted",
            transaction_id=TX_A.replace("-", ""),
            filesystem_uuid=FS_B,
            observed_logical_size_bytes=SMALL_SIZE,
            observed_filesystem_size_bytes=SMALL_SIZE,
            host_allocated_bytes=SMALL_SIZE // 32,
            growth=True,
        )
        first = runtime.ensure_instance_storage()
        require(first["ok"] is True)
        require(runtime.actions == ["grow"])
        image = runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)]
        require(image["payload"] == "sentinel")
        require(image["filesystemUuid"] == FS_B)
        require(image["filesystemSizeBytes"] == SIZE)

        second = runtime.ensure_instance_storage()
        require(second["ok"] is True)
        require(runtime.actions == ["grow", "preserve"])
        require(runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)]["payload"] == "sentinel")


@contract_case("growthRejectsOversizedFilesystem")
def growth_rejects_oversized_filesystem() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        runtime.volumes[lease.volume_name] = volume_record(runtime, lease.volume_name)
        runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] = image_record(
            FS_B,
            SMALL_SIZE,
            SIZE + 4096,
            "sentinel",
        )
        result = runtime.ensure_instance_storage()
        require(result["ok"] is False)
        require(result["error"] == "storage_size_unsafe")
        require(runtime.actions == [])
        require(
            runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)]["payload"]
            == "sentinel"
        )


@contract_case("committedMissingImageFailsClosed")
def committed_missing_image_fails_closed() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        require(runtime.ensure_instance_storage()["ok"] is True)
        runtime.images.clear()
        result = runtime.ensure_instance_storage()
        require(result["ok"] is False)
        require(result["error"] == "storage_image_invalid")
        require(runtime.initializations == 1)


@contract_case("committedUuidMismatchFailsClosed")
def committed_uuid_mismatch_fails_closed() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        require(runtime.ensure_instance_storage()["ok"] is True)
        runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] = image_record(FS_B)
        result = runtime.ensure_instance_storage()
        require(result["ok"] is False)
        require(result["error"] == "storage_identity_mismatch")
        require(runtime.initializations == 1)


def write_legacy(context, volume: str = "xenoid-data", container: str = "xenoid-android") -> None:
    path = context.state_root / "legacy-engine.json"
    path.write_text(json.dumps({"android_data_volume": volume, "container_name": container}) + "\n")
    path.chmod(0o600)


@contract_case("legacyImageMigratesAndSourceRemains")
def legacy_image_migrates_and_source_remains() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        write_legacy(context)
        runtime = FakeRuntime(context, cfg, lease)
        runtime.volumes["xenoid-data"] = volume_record(runtime, "xenoid-data")
        runtime.images[("xenoid-data", storage.DATA_IMAGE_NAME)] = image_record(FS_B)
        result = runtime.ensure_instance_storage()
        require(result["ok"] is True)
        require(runtime.images[("xenoid-data", storage.DATA_IMAGE_NAME)] == image_record(FS_B))
        require(runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] == image_record(FS_B))
        committed = storage.StorageStateStore(context, lease).load()
        require(committed is not None and committed["source"] == "legacy")
        require(committed["legacyVolume"] == "xenoid-data")


@contract_case("legacyMigrationPreservesTaggedBackup")
def legacy_migration_preserves_tagged_backup() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        write_legacy(context)
        runtime = FakeRuntime(context, cfg, lease)
        runtime.volumes["xenoid-data"] = volume_record(runtime, "xenoid-data")
        runtime.images[("xenoid-data", storage.DATA_IMAGE_NAME)] = image_record(FS_B)
        runtime.volumes[lease.volume_name] = volume_record(runtime, lease.volume_name)
        runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] = image_record(FS_A)
        result = runtime.ensure_instance_storage()
        require(result["ok"] is True)
        committed = storage.StorageStateStore(context, lease).load()
        require(committed is not None and committed["backupFilesystemUuid"] == FS_A)
        backup_key = (lease.volume_name, committed["backupImage"])
        require(runtime.images[backup_key] == image_record(FS_A))
        require(runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] == image_record(FS_B))


@contract_case("legacyUnknownAttachmentIsRejected")
def legacy_unknown_attachment_is_rejected() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        write_legacy(context)
        runtime = FakeRuntime(context, cfg, lease)
        runtime.volumes["xenoid-data"] = volume_record(runtime, "xenoid-data")
        runtime.images[("xenoid-data", storage.DATA_IMAGE_NAME)] = image_record(FS_B)
        runtime.attachments["xenoid-data"] = [("foreign-id", "foreign-container")]
        result = runtime.ensure_instance_storage()
        require(result["ok"] is False)
        require(result["error"] == "storage_legacy_attached")
        require(lease.volume_name not in runtime.volumes)


@contract_case("safeRemovalOrdersSyncStopRemove")
def safe_removal_orders_sync_stop_remove() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        runtime.docker_base_cmd = lambda: ["docker"]  # type: ignore[method-assign]
        runtime.quarantine_proxy_for_lifecycle = lambda: {"ok": True}  # type: ignore[method-assign]
        runtime.proxy_cleanup = lambda: {"ok": True}  # type: ignore[method-assign]
        calls: list[str] = []

        def fake_run(command, **kwargs):
            operation = command[1]
            calls.append(operation)
            return subprocess.CompletedProcess(command, 0, "", "")

        container = {"Id": "container-id", "State": {"Running": True}}
        with mock.patch.object(backend, "run", side_effect=fake_run):
            result = runtime._remove_container_safely(container, ownership="lease")
        require(result["ok"] is True)
        require(calls == ["exec", "stop", "rm"])


@contract_case("safeRemovalStopsOnSyncFailure")
def safe_removal_stops_on_sync_failure() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        runtime.docker_base_cmd = lambda: ["docker"]  # type: ignore[method-assign]
        runtime.quarantine_proxy_for_lifecycle = lambda: {"ok": True}  # type: ignore[method-assign]
        calls: list[str] = []

        def fake_run(command, **kwargs):
            calls.append(command[1])
            return subprocess.CompletedProcess(command, 1, "", "sync failed")

        with mock.patch.object(backend, "run", side_effect=fake_run):
            result = runtime._remove_container_safely(
                {"Id": "container-id", "State": {"Running": True}},
                ownership="lease",
            )
        require(result["ok"] is False and result["error"] == "container_sync_failed")
        require(calls == ["exec"])


@contract_case("autoBuiltRuntimeImagesAreInstanceScoped")
def auto_built_runtime_images_are_instance_scoped() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A, ID_B, TX_B):
        context_a, cfg_a, lease_a = initialize(project, state, "phone-a")
        context_b, cfg_b, lease_b = initialize(project, state, "phone-b")
        cfg_a = replace(
            cfg_a,
            auto_build_runtime_image=True,
            runtime_image_tag="xenoid/redroid:test",
        )
        cfg_b = replace(
            cfg_b,
            auto_build_runtime_image=True,
            runtime_image_tag="xenoid/redroid:test",
        )
        image_a = backend.RuntimeManager(context_a, cfg_a, lease_a).effective_image()
        image_b = backend.RuntimeManager(context_b, cfg_b, lease_b).effective_image()
        require(image_a == f"xenoid/redroid:test-{context_a.resource_tag}")
        require(image_b == f"xenoid/redroid:test-{context_b.resource_tag}")
        require(image_a != image_b)


@contract_case("twoInstanceStorageIsIsolated")
def two_instance_storage_is_isolated() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A, ID_B, TX_B):
        context_a, cfg_a, lease_a = initialize(project, state, "phone-a")
        context_b, cfg_b, lease_b = initialize(project, state, "phone-b")
        runtime_a = FakeRuntime(context_a, cfg_a, lease_a)
        runtime_b = FakeRuntime(context_b, cfg_b, lease_b)
        require(runtime_a.ensure_instance_storage()["ok"] is True)
        runtime_b._run_storage_image_action = lambda action, **kwargs: {  # type: ignore[method-assign]
            "ok": True,
            **image_record(FS_B),
            "action": action,
        }
        require(runtime_b.ensure_instance_storage()["ok"] is True)
        state_a = storage.StorageStateStore(context_a, lease_a).load()
        state_b = storage.StorageStateStore(context_b, lease_b).load()
        require(state_a is not None and state_b is not None)
        require(lease_a.volume_name != lease_b.volume_name)
        require(state_a["filesystemUuid"] != state_b["filesystemUuid"])
        require((context_a.state_root / storage.STATE_FILENAME) != (context_b.state_root / storage.STATE_FILENAME))


class IdentityRuntimeStub:
    def __init__(self, container_id: str, candidates: dict[str, Any] | None = None):
        self.container_id = container_id
        self.candidates = dict(candidates or {})

    def location_runtime_container_id(self) -> str:
        return self.container_id

    def collect_persisted_device_identity(self) -> dict[str, Any]:
        return dict(self.candidates)


class FingerprintClientStub:
    def __init__(self, succeed: bool = True):
        self.succeed = succeed
        self.profiles: list[dict[str, Any]] = []

    def apply_fingerprint(self, profile: dict[str, Any], regenerate_unique: bool = True):
        self.profiles.append(profile)
        return {"ok": self.succeed, "regenerateUnique": regenerate_unique}


@contract_case("freshInstanceIdentitiesAreDistinct")
def fresh_instance_identities_are_distinct() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A, ID_B, TX_B):
        context_a, _, _ = initialize(project, state, "phone-a")
        context_b, _, _ = initialize(project, state, "phone-b")
        identity_a = device_identity.DeviceIdentityStore(context_a).load()
        identity_b = device_identity.DeviceIdentityStore(context_b).load()
        require(identity_a is not None and identity_b is not None)
        for key in ("androidId", "serial", "imei"):
            require(identity_a["stable"][key] != identity_b["stable"][key])
        require(identity_a["active"] is None and identity_a["pending"] is None)
        require(stat.S_IMODE((context_a.state_root / device_identity.STATE_FILENAME).stat().st_mode) == 0o600)


@contract_case("generatedImeiUsesRavenTac")
def generated_imei_uses_raven_tac() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, _, _ = initialize(project, state, "phone-a")
        identity = device_identity.DeviceIdentityStore(context).load()
        require(identity is not None)
        imei = identity["stable"]["imei"]
        require(imei.startswith(device_identity._IMEI_TAC))
        require(device_identity._valid_imei(imei))
        rotated = device_identity.DeviceIdentityStore(context).rotate_stable()
        require(rotated["stable"]["imei"].startswith(device_identity._IMEI_TAC))
        require(rotated["stable"]["imei"] != imei)


@contract_case("legacyIdentityAdoptsPersistedValues")
def legacy_identity_adopts_persisted_values() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, _, _ = initialize(project, state, "phone-a")
        (context.state_root / device_identity.STATE_FILENAME).unlink()
        candidates = {
            "androidId": "0123456789abcdef",
            "serial": "3A4940E5EDFA",
            "imei": "356938035643809",
            "imeisv": "01",
        }
        runtime = IdentityRuntimeStub("a" * 64, candidates)
        client = FingerprintClientStub()
        result = device_identity.converge_instance_identity(
            context,
            runtime,
            client,
            {"ids": {"android_id": "REGENERATE", "serial": "REGENERATE"}, "usb": {"serial": "REGENERATE"}},
        )
        require(result["ok"] is True and result["adopted"] is True)
        effective = client.profiles[0]
        require(effective["ids"]["android_id"] == candidates["androidId"])
        require(effective["ids"]["serial"] == candidates["serial"])
        require(effective["ids"]["imei"] == candidates["imei"])
        require(effective["usb"]["serial"] == candidates["serial"])
        require(effective["ids"]["boot_id"] != effective["ids"]["random_uuid"])


@contract_case("identityRetryReusesPendingEpoch")
def identity_retry_reuses_pending_epoch() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, _, _ = initialize(project, state, "phone-a")
        runtime = IdentityRuntimeStub("a" * 64)
        failed = FingerprintClientStub(succeed=False)
        first = device_identity.converge_instance_identity(context, runtime, failed, {})
        require(first["ok"] is False)
        pending = device_identity.DeviceIdentityStore(context).load()
        require(pending is not None and pending["pending"] is not None)
        succeeded = FingerprintClientStub()
        second = device_identity.converge_instance_identity(context, runtime, succeeded, {})
        require(second["ok"] is True)
        require(failed.profiles[0]["ids"] == succeeded.profiles[0]["ids"])


@contract_case("newContainerRotatesOnlyBootIdentity")
def new_container_rotates_only_boot_identity() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, _, _ = initialize(project, state, "phone-a")
        runtime = IdentityRuntimeStub("a" * 64)
        first_client = FingerprintClientStub()
        require(device_identity.converge_instance_identity(context, runtime, first_client, {})["ok"] is True)
        first = first_client.profiles[0]["ids"]
        runtime.container_id = "b" * 64
        second_client = FingerprintClientStub()
        require(device_identity.converge_instance_identity(context, runtime, second_client, {})["ok"] is True)
        second = second_client.profiles[0]["ids"]
        for key in ("android_id", "serial", "imei", "imeisv"):
            require(first[key] == second[key])
        require(first["boot_id"] != second["boot_id"])
        require(first["random_uuid"] != second["random_uuid"])


@contract_case("explicitRotationUpdatesStableOwner")
def explicit_rotation_updates_stable_owner() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, _, _ = initialize(project, state, "phone-a")
        runtime = IdentityRuntimeStub("a" * 64)
        first_client = FingerprintClientStub()
        require(device_identity.converge_instance_identity(context, runtime, first_client, {})["ok"] is True)
        second_client = FingerprintClientStub()
        require(device_identity.converge_instance_identity(
            context,
            runtime,
            second_client,
            {},
            rotate_stable=True,
        )["ok"] is True)
        for key in ("android_id", "serial", "imei"):
            require(first_client.profiles[0]["ids"][key] != second_client.profiles[0]["ids"][key])


@contract_case("seededBootBindsToNextEpoch")
def seeded_boot_binds_to_next_epoch() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, _, _ = initialize(project, state, "phone-a")
        store = device_identity.DeviceIdentityStore(context)
        seeded = store.seed_next_boot()
        runtime = IdentityRuntimeStub("a" * 64)
        client = FingerprintClientStub()
        result = device_identity.converge_instance_identity(context, runtime, client, {})
        require(result["ok"] is True)
        ids = client.profiles[0]["ids"]
        require(ids["boot_id"] == seeded["bootId"])
        require(ids["random_uuid"] == seeded["randomUuid"])
        final = store.load()
        require(final is not None and final["pending"] is None)
        require(final["active"] is not None)
        require(final["active"]["bootId"] == seeded["bootId"])
        require(final["active"]["containerEpoch"] != seeded["containerEpoch"])


@contract_case("liveSentinelBindsInstanceAndFilesystem")
def live_sentinel_binds_instance_and_filesystem() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        require(runtime.ensure_instance_storage()["ok"] is True)
        commands: list[str] = []

        class RootClient:
            def root_exec(self, command: str) -> dict[str, Any]:
                commands.append(command)
                return {"ok": True}

        runtime.daemon_client = lambda timeout=10.0: RootClient()  # type: ignore[method-assign]
        created = runtime.data_sentinel(create=True)
        verified = runtime.data_sentinel(create=False)
        require(created["ok"] is True and verified["ok"] is True)
        require(created["filesystemUuid"] == FS_A)
        require(len(commands) == 2)
        require("/data/local/tmp/runtime-state/storage-sentinel.v1" in commands[0])
        require(context.instance_id in commands[0] and FS_A in commands[0])
        require(".storage-sentinel.new" in commands[0])
        require(".storage-sentinel.new" not in commands[1])


def fake_identity_rotation(runtime: FakeRuntime):
    def _impl(
        expected_uuid: str,
        *,
        target_uuid: str,
        target_rootfs_uuid: str,
    ) -> dict[str, Any]:
        key = (runtime.lease.volume_name, storage.DATA_IMAGE_NAME)
        current = runtime.images[key]
        rotated = current["filesystemUuid"] == expected_uuid
        if rotated:
            runtime.images[key] = image_record(
                target_uuid,
                payload=str(current.get("payload", "")),
            )
        elif current["filesystemUuid"] != target_uuid:
            return {"ok": False, "error": "storage_identity_mismatch"}
        return {"ok": True, **runtime.images[key], "rotated": rotated}

    return _impl


@contract_case("storageRotationTargetIsDeterministic")
def storage_rotation_target_is_deterministic() -> None:
    first = storage.storage_rotation_target("4" * 32)
    require(first == storage.storage_rotation_target("4" * 32))
    require(first != storage.storage_rotation_target("4" * 32, rootfs=True))
    require(first != storage.storage_rotation_target("5" * 32))
    require(storage._UUID.fullmatch(first) is not None)


@contract_case("storageIdentityRotationCommitsNewUuid")
def storage_identity_rotation_commits_new_uuid() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        require(runtime.ensure_instance_storage()["ok"] is True)
        runtime._run_storage_identity_rotation = fake_identity_rotation(runtime)  # type: ignore[method-assign]
        result = runtime.rotate_storage_identity()
        require(result["ok"] is True)
        require(result["rotated"] is True)
        require(result["filesystemUuid"] != FS_A)
        require(result["previousFilesystemUuid"] == FS_A)
        committed = storage.StorageStateStore(context, lease).load()
        require(committed is not None and committed["state"] == "committed")
        require(committed["filesystemUuid"] == result["filesystemUuid"])
        require(committed["source"] == "fresh")
        followup = FakeRuntime(context, cfg, lease)
        transfer_engine_state(runtime, followup)
        require(followup.ensure_instance_storage()["ok"] is True)
        require(followup.actions == ["preserve"])


@contract_case("storageIdentityRotationRequiresStoppedContainer")
def storage_identity_rotation_requires_stopped_container() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        require(runtime.ensure_instance_storage()["ok"] is True)
        runtime.containers[lease.container_name] = owned_container_record(runtime)
        result = runtime.rotate_storage_identity()
        require(result["ok"] is False)
        require(result["error"] == "storage_rotation_requires_stop")
        committed = storage.StorageStateStore(context, lease).load()
        require(committed is not None and committed["state"] == "committed")
        require(committed["filesystemUuid"] == FS_A)


@contract_case("storageIdentityRotationResumesAfterCrash")
def storage_identity_rotation_resumes_after_crash() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        require(runtime.ensure_instance_storage()["ok"] is True)
        store = storage.StorageStateStore(context, lease)
        committed = store.load()
        require(committed is not None)
        target = storage.storage_rotation_target("4" * 32)
        pending = store.pending(
            "fresh",
            transaction_id="4" * 32,
            filesystem_uuid=FS_A,
            observed_logical_size_bytes=int(committed["observedLogicalSizeBytes"]),
            observed_filesystem_size_bytes=int(committed["observedFilesystemSizeBytes"]),
            host_allocated_bytes=int(committed["hostAllocatedBytes"]),
            growth=True,
            rotation_target_uuid=target,
        )
        runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] = image_record(target)
        runtime._run_storage_identity_rotation = fake_identity_rotation(runtime)  # type: ignore[method-assign]
        result = runtime.rotate_storage_identity()
        require(result["ok"] is True)
        require(result["rotated"] is False)
        require(result["filesystemUuid"] == target)
        require(result["previousFilesystemUuid"] == pending["filesystemUuid"])
        final = store.load()
        require(final is not None and final["state"] == "committed")
        require(final["filesystemUuid"] == target)
        require(final["rotationTargetUuid"] == "")


@contract_case("storageIdentityRotationRejectsReplacedImage")
def storage_identity_rotation_rejects_replaced_image() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        require(runtime.ensure_instance_storage()["ok"] is True)
        store = storage.StorageStateStore(context, lease)
        committed = store.load()
        require(committed is not None)
        store.pending(
            "fresh",
            transaction_id="4" * 32,
            filesystem_uuid=FS_A,
            observed_logical_size_bytes=int(committed["observedLogicalSizeBytes"]),
            observed_filesystem_size_bytes=int(committed["observedFilesystemSizeBytes"]),
            host_allocated_bytes=int(committed["hostAllocatedBytes"]),
            growth=True,
            rotation_target_uuid=storage.storage_rotation_target("4" * 32),
        )
        # The image is neither the pending expectation nor the rotation target:
        # a replaced/tampered image must fail closed instead of being adopted.
        runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] = image_record(FS_B)
        runtime._run_storage_identity_rotation = fake_identity_rotation(runtime)  # type: ignore[method-assign]
        result = runtime.rotate_storage_identity()
        require(result["ok"] is False)
        require(result["error"] == "storage_identity_mismatch")
        state = store.load()
        require(state is not None and state["state"] == "pending")
        require(state["transactionId"] == "4" * 32)
        require(state["filesystemUuid"] == FS_A)


@contract_case("upFailsClosedAcrossBothRotationWindows")
def up_fails_closed_across_both_rotation_windows() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        require(runtime.ensure_instance_storage()["ok"] is True)
        store = storage.StorageStateStore(context, lease)
        committed = store.load()
        require(committed is not None)
        target = storage.storage_rotation_target("4" * 32)
        store.pending(
            "fresh",
            transaction_id="4" * 32,
            filesystem_uuid=FS_A,
            observed_logical_size_bytes=int(committed["observedLogicalSizeBytes"]),
            observed_filesystem_size_bytes=int(committed["observedFilesystemSizeBytes"]),
            host_allocated_bytes=int(committed["hostAllocatedBytes"]),
            growth=True,
            rotation_target_uuid=target,
        )
        # Pre-mutation window: image still holds the old UUID.
        pre_mutation = FakeRuntime(context, cfg, lease)
        transfer_engine_state(runtime, pre_mutation)
        result = pre_mutation.ensure_instance_storage()
        require(result["ok"] is False)
        require(result["error"] == "storage_identity_mismatch")
        require("device regenerate" in str(result.get("message")))
        # Post-mutation window: image already carries the rotation target.
        post_mutation = FakeRuntime(context, cfg, lease)
        transfer_engine_state(runtime, post_mutation)
        post_mutation.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] = image_record(target)
        result = post_mutation.ensure_instance_storage()
        require(result["ok"] is False)
        require(result["error"] == "storage_identity_mismatch")
        require("device regenerate" in str(result.get("message")))
        # State is untouched in both windows; the rotation can still be resumed.
        pending = store.load()
        require(pending is not None and pending["state"] == "pending")
        require(pending["rotationTargetUuid"] == target)


@contract_case("plainGrowthPendingHasNoRotationMarker")
def plain_growth_pending_has_no_rotation_marker() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        require(runtime.ensure_instance_storage()["ok"] is True)
        store = storage.StorageStateStore(context, lease)
        committed = store.load()
        require(committed is not None)
        store.pending(
            "fresh",
            transaction_id="4" * 32,
            filesystem_uuid=FS_A,
            observed_logical_size_bytes=int(committed["observedLogicalSizeBytes"]),
            observed_filesystem_size_bytes=int(committed["observedFilesystemSizeBytes"]),
            host_allocated_bytes=int(committed["hostAllocatedBytes"]),
            growth=True,
        )
        pending_runtime = FakeRuntime(context, cfg, lease)
        transfer_engine_state(runtime, pending_runtime)
        require(pending_runtime.ensure_instance_storage()["ok"] is True)
        final = store.load()
        require(final is not None and final["state"] == "committed")
        require(final["rotationTargetUuid"] == "")


@contract_case("v2StorageStateMigratesWithoutMarker")
def v2_storage_state_migrates_without_marker() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        require(runtime.ensure_instance_storage()["ok"] is True)
        store = storage.StorageStateStore(context, lease)
        committed = store.load()
        require(committed is not None)
        v2 = {k: v for k, v in committed.items() if k != "rotationTargetUuid"}
        v2["schema"] = "dev.xenoid.instance-storage/v2"
        (context.state_root / storage.STATE_FILENAME).write_text(
            json.dumps(v2, sort_keys=True) + "\n"
        )
        migrated = store.load()
        require(migrated is not None and migrated["state"] == "committed")
        require(migrated["rotationTargetUuid"] == "")
        require(migrated["filesystemUuid"] == FS_A)


@contract_case("regenerateJournalLifecycle")
def regenerate_journal_lifecycle() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, _, _ = initialize(project, state, "phone-a")
        journal = device_identity.RegenerationJournal(context)
        require(journal.pending() is False)
        journal.clear()
        journal.mark()
        require(journal.pending() is True)
        require(stat.S_IMODE(journal.path.stat().st_mode) == 0o600)
        payload = json.loads(journal.path.read_text())
        require(payload["schema"] == "dev.xenoid.device-regenerate/v1")
        require(payload["instanceId"] == context.instance_id)
        journal.clear()
        require(journal.pending() is False)
        journal.clear()


@contract_case("regenerateJournalBlocksStart")
def regenerate_journal_blocks_start() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        journal = device_identity.RegenerationJournal(context)
        with mock.patch.object(backend, "which", return_value=None):
            unblocked = runtime.start()
            require(unblocked.get("error") == "docker not found")
            journal.mark()
            blocked = runtime.start()
            require(blocked.get("ok") is False)
            require(blocked.get("error") == "device_regeneration_pending")
            journal.clear()
            cleared = runtime.start()
            require(cleared.get("error") == "docker not found")


@contract_case("startSeedsBootIdentityBeforeCreate")
def start_seeds_boot_identity_before_create() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        captured: list[tuple[str, str]] = []

        def capture(boot_id: str, random_uuid: str) -> dict[str, Any]:
            captured.append((boot_id, random_uuid))
            return {"ok": True}

        runtime._run_boot_identity_seed = capture  # type: ignore[method-assign]
        result = runtime._seed_boot_identity_into_image()
        require(result["ok"] is True)
        require(len(captured) == 1)
        store = device_identity.DeviceIdentityStore(context)
        pending = store.load()["pending"]
        require(pending is not None)
        require(pending["bootId"] == captured[0][0])
        require(pending["randomUuid"] == captured[0][1])
        # The seeded values bind to the next container epoch verbatim.
        runtime_stub = IdentityRuntimeStub("c" * 64)
        client = FingerprintClientStub()
        require(device_identity.converge_instance_identity(context, runtime_stub, client, {})["ok"] is True)
        require(client.profiles[0]["ids"]["boot_id"] == captured[0][0])
        require(client.profiles[0]["ids"]["random_uuid"] == captured[0][1])


def main() -> int:
    failures: list[str] = []
    for name, case in CASES.items():
        try:
            case()
        except Exception as exc:
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
        else:
            print(f"ok {name}")
    if failures:
        for failure in failures:
            print(f"not ok {failure}", file=sys.stderr)
        return 1
    print(f"{len(CASES)} storage contracts passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
