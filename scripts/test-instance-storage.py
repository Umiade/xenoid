#!/usr/bin/env python3
"""Deterministic contracts for persistent instance storage and safe lifecycle."""
from __future__ import annotations

import hashlib
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

from xenoid import backend, config, device_identity, runtime_image, storage

ID_A = "10000000-0000-4000-8000-000000000001"
ID_B = "10000000-0000-4000-8000-000000000002"
TX_A = "20000000-0000-4000-8000-000000000001"
TX_B = "20000000-0000-4000-8000-000000000002"
FS_A = "11111111-1111-4111-8111-111111111111"
FS_B = "22222222-2222-4222-8222-222222222222"
ROOTFS_A = "33333333-3333-4333-8333-333333333333"
ROOTFS_B = "44444444-4444-4444-8444-444444444444"
ROOTFS_SOURCE = "ab" * 32
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
        self.networks: dict[str, dict[str, Any]] = {}
        self.actions: list[str] = []
        self.initializations = 0
        self.proxy_captures = 0
        self.container_removals = 0
        super().__init__(context, cfg, lease)

    def _inspect_docker_object(
        self, object_type: str, name: str, timeout: float | None = None
    ):
        del timeout
        if object_type == "volume":
            value = self.volumes.get(name)
        elif object_type == "container":
            value = self.containers.get(name)
        elif object_type == "network":
            value = self.networks.get(name)
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
        expected_rootfs_uuid: str = "",
    ) -> dict[str, Any]:
        self.actions.append(action)
        rootfs_key = (self.lease.volume_name, storage.ROOTFS_IMAGE_NAME)
        rootfs_uuid = expected_rootfs_uuid or ROOTFS_A
        current_rootfs = self.images.get(rootfs_key)
        if current_rootfs is None:
            self.images[rootfs_key] = image_record(
                rootfs_uuid,
                logical_size=3 * 1024 * 1024 * 1024,
            )
        elif expected_rootfs_uuid and current_rootfs["filesystemUuid"] != expected_rootfs_uuid:
            return {"ok": False, "error": "storage_identity_mismatch"}
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
        rootfs = self.images[rootfs_key]
        return {
            "ok": True,
            **value,
            "rootfsFilesystemUuid": rootfs["filesystemUuid"],
            "rootfsSourceSha256": ROOTFS_SOURCE,
            "rootfsSizeBytes": rootfs["logicalSizeBytes"],
            "action": action,
        }

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

    def _engine_host_shell(self, command: str, timeout: float | None = None):
        del timeout
        if "xenoid-rootfs.img.source.sha256" in command:
            return subprocess.CompletedProcess([], 0, ROOTFS_SOURCE, "")
        return subprocess.CompletedProcess([], 0, "", "")


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


@contract_case("publicStopPreservesOwnedContainer")
def public_stop_preserves_owned_container() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        runtime.docker_base_cmd = lambda: ["docker"]  # type: ignore[method-assign]
        runtime.docker_env = lambda: {}  # type: ignore[method-assign]
        runtime._owned_container_record = lambda: (  # type: ignore[method-assign]
            {"Id": "c" * 64, "State": {"Running": True}},
            "",
        )
        runtime._container_has_lease_owner = lambda _container: True  # type: ignore[method-assign]
        runtime.quarantine_proxy_for_lifecycle = (  # type: ignore[method-assign]
            lambda: {"ok": True, "proof": "quarantined"}
        )
        calls: list[str] = []

        def fake_run(command, **kwargs):
            del kwargs
            calls.append(command[1])
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch.object(backend, "which", return_value="/usr/bin/docker"), \
             mock.patch.object(backend, "run", side_effect=fake_run):
            result = runtime.stop()
        require(result["ok"] is True)
        require(calls == ["exec", "stop"])
        require(runtime.container_removals == 0)


@contract_case("safeRemovalOrdersSyncStopRemove")
def safe_removal_orders_sync_stop_remove() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        runtime.docker_base_cmd = lambda: ["docker"]  # type: ignore[method-assign]
        runtime.quarantine_proxy_for_lifecycle = lambda: {"ok": True}  # type: ignore[method-assign]
        runtime.proxy_cleanup = lambda: {"ok": True}  # type: ignore[method-assign]
        runtime._container_has_lease_owner = lambda _container: True  # type: ignore[method-assign]
        calls: list[str] = []

        def fake_run(command, **kwargs):
            operation = command[1]
            calls.append(operation)
            return subprocess.CompletedProcess(command, 0, "", "")

        container = {"Id": "c" * 64, "State": {"Running": True}}
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
        runtime._container_has_lease_owner = lambda _container: True  # type: ignore[method-assign]
        calls: list[str] = []

        def fake_run(command, **kwargs):
            calls.append(command[1])
            return subprocess.CompletedProcess(command, 1, "", "sync failed")

        with mock.patch.object(backend, "run", side_effect=fake_run):
            result = runtime._remove_container_safely(
                {"Id": "c" * 64, "State": {"Running": True}},
                ownership="lease",
            )
        require(result["ok"] is False and result["error"] == "container_sync_failed")
        require(calls == ["exec"])


@contract_case("contentAddressedRuntimeImagesAreSharedAcrossInstances")
def content_addressed_runtime_images_are_shared_across_instances() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A, ID_B, TX_B):
        context_a, cfg_a, lease_a = initialize(project, state, "phone-a")
        context_b, cfg_b, lease_b = initialize(project, state, "phone-b")
        configured_tag = "registry.example:5000/xenoid/redroid:operator"
        input_sha256 = "0123456789abcdef" * 4
        image_a = runtime_image.derive_tag(configured_tag, input_sha256)
        image_b = runtime_image.derive_tag(configured_tag, input_sha256)
        require(image_a == "registry.example:5000/xenoid/redroid:xenoid-0123456789abcdef0123456789abcdef")
        require(image_b == image_a)
        require(context_a.resource_tag not in image_a)
        require(context_b.resource_tag not in image_b)
        require(cfg_a.instance_id != cfg_b.instance_id)
        require(lease_a.container_name != lease_b.container_name)


@contract_case("twoInstanceStorageIsIsolated")
def two_instance_storage_is_isolated() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A, ID_B, TX_B):
        context_a, cfg_a, lease_a = initialize(project, state, "phone-a")
        context_b, cfg_b, lease_b = initialize(project, state, "phone-b")
        runtime_a = FakeRuntime(context_a, cfg_a, lease_a)
        runtime_b = FakeRuntime(context_b, cfg_b, lease_b)
        require(runtime_a.ensure_instance_storage()["ok"] is True)
        runtime_b.images[
            (lease_b.volume_name, storage.DATA_IMAGE_NAME)
        ] = image_record(FS_B)
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

    def ensure_drm_identity(self) -> dict[str, Any]:
        return {"ok": True, "seeded": False}


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
        require(rotated["stable"]["imeisv"] != identity["stable"]["imeisv"])


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
        for key in ("android_id", "serial", "imei", "imeisv"):
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
        require(set(seeded) == {"containerEpoch", "bootId", "phase", "createdAt"})
        final = store.load()
        require(final is not None and final["pending"] is None)
        require(final["active"] is not None)
        require(final["active"]["bootId"] == seeded["bootId"])
        require(final["active"]["containerEpoch"] != seeded["containerEpoch"])


def _debugfs_metadata(size: int, owner: int = 10001) -> str:
    return (
        f"Inode: 1 Type: regular Mode: 0600 Flags: 0\n"
        f"User: {owner} Group: {owner} Size: {size}\n"
        "Links: 1 Blockcount: 1\n"
    )


@contract_case("configuredLegacyProxyRequiresCompatibilityProof")
def configured_legacy_proxy_requires_compatibility_proof() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        require(runtime.ensure_instance_storage()["ok"] is True)
        runtime._proxy_remote_exists = lambda _path: False  # type: ignore[method-assign]
        document = {
            "schemaVersion": 1,
            "instanceId": context.instance_id,
            "generation": 7,
            "enabled": False,
            "sourceIv": "a" * 16,
            "sourceCiphertext": "b" * 32,
        }
        raw = json.dumps(document, sort_keys=True, separators=(",", ":"))

        def engine(command: str, timeout: float | None = None):
            del timeout
            if "desired-v1.json" in command and "stat " in command:
                return subprocess.CompletedProcess(
                    [], 0, _debugfs_metadata(len(raw)), ""
                )
            if "desired-v1.json" in command and "cat " in command:
                return subprocess.CompletedProcess([], 0, raw, "")
            return subprocess.CompletedProcess([], 1, "", "")

        runtime._engine_host_shell = engine  # type: ignore[method-assign]
        try:
            runtime._offline_proxy_identity()
        except device_identity.IdentityError as exc:
            require(exc.code == "proxy_legacy_live_proof_required")
        else:
            raise ContractFailure
        document.update(
            {
                "generation": 0,
                "sourceIv": None,
                "sourceCiphertext": None,
            }
        )
        raw = json.dumps(document, sort_keys=True, separators=(",", ":"))
        require(runtime._offline_proxy_identity() == (False, 0))


@contract_case("proxyV2PendingAndConfiguredStatesRequireCompatibilityProof")
def proxy_v2_pending_and_configured_states_require_compatibility_proof() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        require(runtime.ensure_instance_storage()["ok"] is True)
        runtime._proxy_remote_exists = lambda _path: False  # type: ignore[method-assign]
        key_id = "ab" * 32
        envelope = {
            "schemaVersion": 2,
            "instanceId": context.instance_id,
            "generation": 9,
            "enabled": False,
            "keyId": key_id,
            "sourceIv": None,
            "sourceCiphertext": None,
        }
        state_raw = json.dumps(
            envelope, sort_keys=True, separators=(",", ":")
        )
        state_id = hashlib.sha256(state_raw.encode()).hexdigest()
        active = {
            "schemaVersion": 2,
            "instanceId": context.instance_id,
            "stateId": state_id,
            "keyId": key_id,
        }
        active_raw = json.dumps(
            active, sort_keys=True, separators=(",", ":")
        )
        pending = {"present": True}

        def engine(command: str, timeout: float | None = None):
            del timeout
            if "stat user/0/dev.xenoid.daemon/no_backup/proxy-state/v2/active.json" in command:
                return subprocess.CompletedProcess(
                    [], 0, _debugfs_metadata(len(active_raw)), ""
                )
            if "cat user/0/dev.xenoid.daemon/no_backup/proxy-state/v2/active.json" in command:
                return subprocess.CompletedProcess([], 0, active_raw, "")
            if "pending.json" in command:
                return subprocess.CompletedProcess(
                    [], 0 if pending["present"] else 1, "", ""
                )
            if f"stat user/0/dev.xenoid.daemon/no_backup/proxy-state/v2/keys/{key_id}.key" in command:
                return subprocess.CompletedProcess(
                    [], 0, _debugfs_metadata(32), ""
                )
            if f"dump user/0/dev.xenoid.daemon/no_backup/proxy-state/v2/keys/{key_id}.key" in command:
                return subprocess.CompletedProcess([], 0, f"32 {key_id}\n", "")
            if f"stat user/0/dev.xenoid.daemon/no_backup/proxy-state/v2/states/{state_id}.json" in command:
                return subprocess.CompletedProcess(
                    [], 0, _debugfs_metadata(len(state_raw)), ""
                )
            if f"cat user/0/dev.xenoid.daemon/no_backup/proxy-state/v2/states/{state_id}.json" in command:
                return subprocess.CompletedProcess([], 0, state_raw, "")
            return subprocess.CompletedProcess([], 1, "", "")

        runtime._engine_host_shell = engine  # type: ignore[method-assign]
        try:
            runtime._offline_proxy_identity()
        except device_identity.IdentityError as exc:
            require(exc.code == "proxy_legacy_live_proof_required")
        else:
            raise ContractFailure
        pending["present"] = False
        require(runtime._offline_proxy_identity() == (False, 9))
        envelope["sourceIv"] = "iv"
        envelope["sourceCiphertext"] = "ciphertext"
        configured_raw = json.dumps(
            envelope, sort_keys=True, separators=(",", ":")
        )
        configured_id = hashlib.sha256(configured_raw.encode()).hexdigest()
        active["stateId"] = configured_id
        active_raw = json.dumps(
            active, sort_keys=True, separators=(",", ":")
        )
        state_raw = configured_raw
        state_id = configured_id
        try:
            runtime._offline_proxy_identity()
        except device_identity.IdentityError as exc:
            require(exc.code == "proxy_legacy_live_proof_required")
        else:
            raise ContractFailure


@contract_case("liveSentinelBindsInstanceAndFilesystem")
def live_sentinel_binds_instance_and_filesystem() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        require(runtime.ensure_instance_storage()["ok"] is True)
        commands: list[str] = []
        response: dict[str, Any] = {"ok": True}

        class RootClient:
            def root_exec(self, command: str) -> dict[str, Any]:
                commands.append(command)
                return dict(response)

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
        response.clear()
        response.update(ok=False, errorCode="rootd_command_timeout")
        unavailable = runtime.data_sentinel(create=False)
        require(unavailable.get("error") == "storage_sentinel_unavailable")
        response["errorCode"] = "rootd_command_failed"
        mismatch = runtime.data_sentinel(create=False)
        require(mismatch.get("error") == "storage_sentinel_mismatch")


@contract_case("v3StorageStateMigratesWithVerifiedRootfs")
def v3_storage_state_migrates_with_verified_rootfs() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        require(runtime.ensure_instance_storage()["ok"] is True)
        store = storage.StorageStateStore(context, lease)
        committed = store.load()
        require(committed is not None)
        v4_only = {
            "rootfsImage",
            "rootfsFilesystemUuid",
            "rootfsSourceSha256",
            "observedRootfsSizeBytes",
            "backupRootfsImage",
            "backupRootfsFilesystemUuid",
            "backupRootfsSizeBytes",
        }
        v3 = {key: value for key, value in committed.items() if key not in v4_only}
        v3["schema"] = "dev.xenoid.instance-storage/v3"
        path = context.state_root / storage.STATE_FILENAME
        path.write_text(json.dumps(v3, sort_keys=True) + "\n")
        path.chmod(0o600)
        migrated = store.load()
        require(migrated is not None and migrated["state"] == "committed")
        require(migrated["rootfsImage"] == "")
        rootfs_key = (lease.volume_name, storage.ROOTFS_IMAGE_NAME)
        original_rootfs = dict(runtime.images[rootfs_key])
        runtime.images[rootfs_key] = image_record(
            ROOTFS_B,
            logical_size=int(original_rootfs["logicalSizeBytes"]),
        )
        drifted = runtime.converge_storage(
            expected_data_uuid=FS_A,
            expected_rootfs_uuid=str(original_rootfs["filesystemUuid"]),
        )
        require(drifted["ok"] is False)
        require(drifted["error"] == "storage_identity_mismatch")
        require(store.load()["rootfsImage"] == "")
        runtime.images[rootfs_key] = original_rootfs
        require(runtime.ensure_instance_storage()["ok"] is True)
        migrated = store.load()
        require(migrated is not None)
        require(migrated["schema"] == storage.STORAGE_SCHEMA)
        require(migrated["rootfsFilesystemUuid"] != "")
        require(migrated["rootfsSourceSha256"] == ROOTFS_SOURCE)



@contract_case("v4PendingRotationEvidenceFailsClosedUntouched")
def v4_pending_rotation_evidence_fails_closed_untouched() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, _, lease = initialize(project, state, "phone-a")
        store = storage.StorageStateStore(context, lease)
        current = store.pending("fresh", transaction_id="1" * 32)
        data_target = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        rootfs_target = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        for already_mutated in (False, True):
            legacy = {
                **current,
                "schema": storage._V4_STORAGE_SCHEMA,
                "rotationTargetUuid": data_target,
                "rotationTargetRootfsUuid": rootfs_target,
            }
            if already_mutated:
                legacy["filesystemUuid"] = data_target
                legacy["rootfsFilesystemUuid"] = rootfs_target
            payload = (json.dumps(legacy, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            store.path.write_bytes(payload)
            store.path.chmod(0o600)
            before = store.path.read_bytes()
            try:
                store.load()
            except storage.StorageError as exc:
                require(exc.code == "storage_legacy_rotation_pending")
            else:
                raise ContractFailure
            require(store.path.read_bytes() == before)


@contract_case("ordinaryV4StorageMigratesToV5")
def ordinary_v4_storage_migrates_to_v5() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, _, lease = initialize(project, state, "phone-a")
        store = storage.StorageStateStore(context, lease)
        current = store.pending("fresh", transaction_id="1" * 32)
        legacy = {
            **current,
            "schema": storage._V4_STORAGE_SCHEMA,
            "rotationTargetUuid": "",
            "rotationTargetRootfsUuid": "",
        }
        store.path.write_text(json.dumps(legacy) + "\n", encoding="ascii")
        store.path.chmod(0o600)
        migrated = store.load()
        require(migrated is not None and migrated["schema"] == storage.STORAGE_SCHEMA)
        require("rotationTargetUuid" not in migrated)
        require("rotationTargetRootfsUuid" not in migrated)
def prepare_regeneration_journal(
    context: config.InstanceContext,
) -> tuple[
    device_identity.RegenerationJournal,
    device_identity.DeviceIdentityStore,
    dict[str, Any],
]:
    identity_store = device_identity.DeviceIdentityStore(context)
    identity = identity_store.initialize()
    transaction_id = "6" * 32
    stable_target = device_identity.generate_stable_target(identity["stable"])
    before = {
        "containerId": "c" * 64,
        "containerEpoch": device_identity.container_epoch("c" * 64),
        "imageId": "sha256:" + "d" * 64,
        "imageInputSha256": "e" * 64,
        "imageBootInputSha256": "f" * 64,
        "runtimeEpoch": "1" * 64,
        "stableDigest": device_identity.stable_identity_digest(identity["stable"]),
        "simEpoch": "a" * 32,
        "locationDigest": "3" * 64,
        "bootId": "11111111-2222-4233-8444-555555555555",
        "statfsFsid": "0123456789abcdef",
        "bluetoothAddress": "F4:F5:E8:00:00:01",
        "deviceName": "Pixel 6 Pro",
        "hostname": "localhost",
        "googleBindingDigest": "4" * 64,
        "drmDeviceUniqueId": "00" * 16,
        "advertisingIdDigest": "7" * 64,
        "gsfAndroidIdDigest": "8" * 64,
        "protectionEngineId": "AA:BB:CC:DD",
        "protectionExpectedDigest": "9" * 64,
    }
    target = {
        "stableDigest": device_identity.stable_identity_digest(stable_target),
        "stable": stable_target,
        "simEpoch": "b" * 32,
        "locationProfileDigest": "6" * 64,
        "bootId": "66666666-7777-4888-8999-aaaaaaaaaaaa",
        "statfsFsid": "fedcba9876543210",
        "bluetoothAddress": "F4:F5:E8:00:00:02",
        "deviceName": "Pixel 6 Pro ABC123",
        "hostname": "android-0123456789ab",
        "googleBindingDigest": "4" * 64,
        "drmDeviceUniqueId": "ff" * 16,
    }
    journal = device_identity.RegenerationJournal(context)
    state = journal.prepare(transaction_id, before, target)
    identity_store.prepare_regeneration_stable(transaction_id, stable_target)
    return journal, identity_store, state


def commit_regeneration_journal(
    journal: device_identity.RegenerationJournal,
) -> dict[str, Any]:
    state = journal.load()
    require(state is not None)
    for phase in device_identity.REGENERATION_PHASES[1:]:
        state = journal.advance(phase)
    return state


@contract_case("regenerateJournalLifecycle")
def regenerate_journal_lifecycle() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, _, _ = initialize(project, state, "phone-a")
        empty = device_identity.RegenerationJournal(context)
        require(empty.pending() is False)
        journal, identity_store, prepared = prepare_regeneration_journal(context)
        require(journal.pending() is True)
        require(prepared["phase"] == "prepared")
        require(stat.S_IMODE(journal.path.stat().st_mode) == 0o600)
        require(journal.path.name == "device-regenerate-v3.json")
        payload = json.loads(journal.path.read_text())
        require(set(payload) == device_identity._REGENERATION_KEYS)
        require(payload["schema"] == "dev.xenoid.device-regenerate/v3")
        require(payload["instanceId"] == context.instance_id)
        with mock.patch.object(
            device_identity,
            "_now",
            return_value=prepared["updatedAt"] - 60,
        ):
            same_phase = journal.advance("prepared")
        require(same_phase["updatedAt"] == prepared["updatedAt"])
        try:
            journal.advance("storage_committed")
        except device_identity.IdentityError as exc:
            require(exc.code == "device_regeneration_state_invalid")
        else:
            raise ContractFailure
        committed = commit_regeneration_journal(journal)
        identity_store.commit_regeneration_stable(committed["transactionId"])
        identity_store.clear_regeneration_stable(committed["transactionId"])
        journal.clear()
        require(journal.pending() is False)


@contract_case("regenerateTargetsExistBeforeIdentityMutation")
def regenerate_targets_exist_before_identity_mutation() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, _, _ = initialize(project, state, "phone-a")
        store = device_identity.DeviceIdentityStore(context)
        identity = store.initialize()
        # Seed one active epoch so journal-fixed boot staging can be replayed.
        seed = store.seed_next_boot()
        store.prepare_epoch("c" * 64)
        store.mark_applied(device_identity.container_epoch("c" * 64))
        # Simulate a deleted legacy v1/v2 journal whose pendingStable marker
        # survives. The new journal must exist before cleanup, and a crash
        # immediately after prepare must leave the old marker byte-identical.
        store.prepare_regeneration_stable("7" * 32)
        before_bytes = store.path.read_bytes()
        stable_target = device_identity.generate_stable_target(identity["stable"])
        before = {
            "containerId": "c" * 64,
            "containerEpoch": device_identity.container_epoch("c" * 64),
            "imageId": "sha256:" + "d" * 64,
            "imageInputSha256": "e" * 64,
            "imageBootInputSha256": "f" * 64,
            "runtimeEpoch": "1" * 64,
            "stableDigest": device_identity.stable_identity_digest(identity["stable"]),
            "simEpoch": "a" * 32,
            "locationDigest": "3" * 64,
            "bootId": seed["bootId"],
            "statfsFsid": "0123456789abcdef",
            "bluetoothAddress": "F4:F5:E8:00:00:01",
            "deviceName": "Pixel 6 Pro",
            "hostname": "localhost",
            "googleBindingDigest": "4" * 64,
            "drmDeviceUniqueId": "00" * 16,
            "advertisingIdDigest": "7" * 64,
            "gsfAndroidIdDigest": "8" * 64,
            "protectionEngineId": "AA:BB:CC:DD",
            "protectionExpectedDigest": "9" * 64,
        }
        target = {
            "stableDigest": device_identity.stable_identity_digest(stable_target),
            "stable": stable_target,
            "simEpoch": "b" * 32,
            "locationProfileDigest": "6" * 64,
            "bootId": "66666666-7777-4888-8999-aaaaaaaaaaaa",
            "statfsFsid": "fedcba9876543210",
            "bluetoothAddress": "F4:F5:E8:00:00:02",
            "deviceName": "Pixel 6 Pro ABC123",
            "hostname": "android-0123456789ab",
            "googleBindingDigest": "4" * 64,
            "drmDeviceUniqueId": "ff" * 16,
        }
        journal = device_identity.RegenerationJournal(context)
        prepared = journal.prepare("a" * 32, before, target)
        require(store.path.read_bytes() == before_bytes)
        require(prepared["target"]["stable"] == stable_target)
        require(
            device_identity.stable_identity_digest(store.load()["stable"])
            == prepared["before"]["stableDigest"]
        )
        require(store.recover_orphaned_regeneration_stable() is True)
        staged = store.prepare_regeneration_stable("a" * 32, prepared["target"]["stable"])
        first_boot = store.stage_regeneration_boot(prepared["target"]["bootId"])
        after_first_boot = store.path.read_bytes()
        second_boot = store.stage_regeneration_boot(prepared["target"]["bootId"])
        require(store.path.read_bytes() == after_first_boot)
        require(staged["pendingStable"]["digest"] == prepared["target"]["stableDigest"])
        require(first_boot["bootId"] == second_boot["bootId"] == prepared["target"]["bootId"])

@contract_case("regenerateGoogleIdentityJournalIsCrashResumable")
def regenerate_google_identity_journal_is_crash_resumable() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, _, _ = initialize(project, state, "phone-a")
        journal, identity_store, current = prepare_regeneration_journal(context)
        for phase in device_identity.REGENERATION_PHASES[1:8]:
            current = journal.advance(phase)
        require(current["phase"] == "google_reset")
        require(journal.load() == current)
        require(not any(key.startswith("googlePackage") for key in current))
        for phase in device_identity.REGENERATION_PHASES[8:]:
            current = journal.advance(phase)
        identity_store.commit_regeneration_stable(current["transactionId"])
        identity_store.clear_regeneration_stable(current["transactionId"])
        journal.clear()

@contract_case("orphanedStableTargetRecoversBeforeOrAfterCommit")
def orphaned_stable_target_recovers_before_or_after_commit() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, _, _ = initialize(project, state, "phone-a")
        store = device_identity.DeviceIdentityStore(context)
        prepared = store.prepare_regeneration_stable("7" * 32)
        require(prepared["pendingStable"] is not None)
        require(store.recover_orphaned_regeneration_stable() is True)
        store.prepare_regeneration_stable("8" * 32)
        committed = store.commit_regeneration_stable("8" * 32)
        committed_digest = device_identity.stable_identity_digest(committed["stable"])
        require(store.recover_orphaned_regeneration_stable() is True)
        recovered = store.load()
        require(recovered is not None and recovered["pendingStable"] is None)
        require(device_identity.stable_identity_digest(recovered["stable"]) == committed_digest)


@contract_case("regenerationTargetMustRotateEveryStableFactor")
def regeneration_target_must_rotate_every_stable_factor() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, _, _ = initialize(project, state, "phone-a")
        store = device_identity.DeviceIdentityStore(context)
        current = store.load()
        require(current is not None)
        target = dict(current["stable"])
        target["androidId"] = "0123456789abcdef"
        if target["androidId"] == current["stable"]["androidId"]:
            target["androidId"] = "fedcba9876543210"
        try:
            store.prepare_regeneration_stable("9" * 32, target)
        except device_identity.IdentityError as exc:
            require(exc.code == "device_regeneration_state_invalid")
        else:
            raise ContractFailure


@contract_case("regenerateJournalBlocksStart")
def regenerate_journal_blocks_start() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        with mock.patch.object(backend, "which", return_value=None):
            unblocked = runtime.start()
            require(unblocked.get("error") != "device_regeneration_pending")
            journal, identity_store, _ = prepare_regeneration_journal(context)
            blocked = runtime.start()
            require(blocked.get("ok") is False)
            require(blocked.get("error") == "device_regeneration_pending")
            committed = commit_regeneration_journal(journal)
            identity_store.commit_regeneration_stable(committed["transactionId"])
            identity_store.clear_regeneration_stable(committed["transactionId"])
            journal.clear()
            cleared = runtime.start()
            require(cleared.get("error") != "device_regeneration_pending")


@contract_case("startSeedsBootIdentityBeforeCreate")
def start_seeds_boot_identity_before_create() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = FakeRuntime(context, cfg, lease)
        captured: list[str] = []

        def capture(boot_id: str) -> dict[str, Any]:
            captured.append(boot_id)
            return {"ok": True}

        runtime._run_boot_identity_seed = capture  # type: ignore[method-assign]
        result = runtime._seed_boot_identity_into_image()
        require(result["ok"] is True)
        require(len(captured) == 1)
        store = device_identity.DeviceIdentityStore(context)
        pending = store.load()["pending"]
        require(pending is not None)
        require(set(pending) == {"containerEpoch", "bootId", "phase", "createdAt"})
        require(pending["bootId"] == captured[0])
        # The seeded values bind to the next container epoch verbatim.
        runtime_stub = IdentityRuntimeStub("c" * 64)
        client = FingerprintClientStub()
        require(device_identity.converge_instance_identity(context, runtime_stub, client, {})["ok"] is True)
        require(client.profiles[0]["ids"]["boot_id"] == captured[0])



def network_record(manager: backend.RuntimeManager) -> dict[str, Any]:
    return {
        "Name": manager.lease.network_name,
        "Driver": "bridge",
        "EnableIPv6": True,
        "Labels": dict(manager.lease.owner_labels),
        "IPAM": {
            "Config": [
                {"Subnet": manager.lease.ipv4_subnet, "Gateway": manager.lease.ipv4_gateway},
                {"Subnet": manager.lease.ipv6_subnet, "Gateway": manager.lease.ipv6_gateway},
            ]
        },
        "Options": {"com.docker.network.bridge.name": manager.lease.bridge_name},
    }


class DeleteRuntime(FakeRuntime):
    def __init__(self, context, cfg, lease):
        self.removed_containers: list[str] = []
        self.removed: list[list[str]] = []
        self.proxy_cleanups = 0
        super().__init__(context, cfg, lease)

    def _remove_container_safely(
        self,
        container: dict[str, Any],
        *,
        ownership: str,
        expected_container_id: str | None = None,
    ) -> dict[str, Any]:
        del expected_container_id
        self.removed_containers.append(f"{ownership}:{container['Id']}")
        self.containers.pop(self.lease.container_name, None)
        cleanup = self.proxy_cleanup()
        return {
            "ok": cleanup.get("ok") is True,
            "ownership": ownership,
            "containerId": container["Id"],
            "proxyCleanup": cleanup,
        }

    def proxy_cleanup(self) -> dict[str, Any]:
        self.proxy_cleanups += 1
        return {"ok": True, "notPrepared": True}


def delete_run(runtime: DeleteRuntime):
    def fake_run(cmd, *, check=False, capture=True, timeout=None, stdin=None, env=None):
        del check, capture, timeout, stdin, env
        runtime.removed.append(list(cmd))
        if "rm" in cmd and "volume" in cmd:
            runtime.volumes.pop(cmd[-1], None)
        elif "rm" in cmd and "network" in cmd:
            runtime.networks.pop(cmd[-1], None)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    return fake_run


@contract_case("deleteReleasesOwnedResourcesAndRecord")
def delete_releases_owned_resources_and_record() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A, ID_B, TX_B):
        context_a, cfg_a, lease_a = initialize(project, state, "phone-a")
        context_b, cfg_b, lease_b = initialize(project, state, "phone-b")
        runtime_a = DeleteRuntime(context_a, cfg_a, lease_a)
        require(runtime_a.ensure_instance_storage()["ok"] is True)
        container = owned_container_record(runtime_a, "a" * 64, running=True)
        runtime_a.containers[lease_a.container_name] = container
        runtime_a.networks[lease_a.network_name] = network_record(runtime_a)
        with mock.patch.object(backend, "which", return_value="/engine/docker"):
            plan = runtime_a.delete_owned_runtime(dry_run=True)
        require(plan["ok"] is True and plan["dryRun"] is True)
        require(plan["container"]["present"] is True)
        require(plan["volume"]["present"] is True)
        require(plan["network"]["present"] is True)
        require(plan["hostAllocatedBytes"] is not None)
        require(runtime_a.removed_containers == [] and runtime_a.removed == [])
        require(context_a.config_path.is_file() and context_a.state_root.is_dir())
        with mock.patch.object(backend, "which", return_value="/engine/docker"), mock.patch.object(
            backend, "run", delete_run(runtime_a)
        ):
            engine = runtime_a.delete_owned_runtime()
        require(engine["ok"] is True)
        require(runtime_a.removed_containers == [f"lease:{'a' * 64}"])
        require(runtime_a.proxy_cleanups == 1)
        require(runtime_a.containers == {} and runtime_a.volumes == {} and runtime_a.networks == {})
        record = config.delete_instance_record(context_a)
        require(record["ok"] is True and record["slot"] == lease_a.slot)
        require(not context_a.state_root.exists() and not context_a.config_path.parent.exists())
        try:
            config.resolve_instance("phone-a", project_root=project, state_home=state, env={})
        except config.InstanceError as exc:
            require(exc.code == "instance_not_initialized")
        else:
            raise ContractFailure
        registry = json.loads((state / "registry.json").read_text())
        require(ID_A not in registry["leases"] and ID_B in registry["leases"])
        sibling_context, _, sibling_lease = config.resolve_instance(
            "phone-b", project_root=project, state_home=state, env={}
        )
        require(sibling_context.instance_id == ID_B)
        require(sibling_lease.slot == lease_b.slot)


@contract_case("deleteWithoutEngineResourcesIsIdempotent")
def delete_without_engine_resources_is_idempotent() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = DeleteRuntime(context, cfg, lease)
        with mock.patch.object(backend, "which", return_value="/engine/docker"), mock.patch.object(
            backend, "run", delete_run(runtime)
        ):
            result = runtime.delete_owned_runtime()
        require(result["ok"] is True)
        require(result["container"]["present"] is False)
        require(result["volume"]["present"] is False)
        require(result["network"]["present"] is False)
        require(runtime.proxy_cleanups == 1)
        require(runtime.removed == [])
        record = config.delete_instance_record(context)
        require(record["ok"] is True)


@contract_case("deleteRefusesForeignEngineResources")
def delete_refuses_foreign_engine_resources() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        runtime = DeleteRuntime(context, cfg, lease)
        foreign = volume_record(runtime, lease.volume_name)
        foreign["Labels"] = {}
        runtime.volumes[lease.volume_name] = foreign
        with mock.patch.object(backend, "which", return_value="/engine/docker"):
            result = runtime.delete_owned_runtime()
        require(result["ok"] is False and result["error"] == "resource_conflict")
        require(runtime.removed_containers == [] and runtime.removed == [])
        require(context.config_path.is_file() and context.state_root.is_dir())
        registry = json.loads((state / "registry.json").read_text())
        require(ID_A in registry["leases"])
        runtime.volumes.pop(lease.volume_name)
        foreign_container = owned_container_record(runtime, "b" * 64)
        foreign_container["Config"]["Labels"] = {}
        runtime.containers[lease.container_name] = foreign_container
        with mock.patch.object(backend, "which", return_value="/engine/docker"):
            result = runtime.delete_owned_runtime()
        require(result["ok"] is False and result["error"] == "resource_conflict")
        require(context.config_path.is_file())

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
