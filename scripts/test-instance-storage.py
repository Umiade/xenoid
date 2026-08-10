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
SIZE = storage.DEFAULT_DATA_SIZE_BYTES


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


class FakeRuntime(backend.RuntimeManager):
    def __init__(self, context, cfg, lease):
        self.volumes: dict[str, dict[str, Any]] = {}
        self.images: dict[tuple[str, str], tuple[str, int]] = {}
        self.attachments: dict[str, list[tuple[str, str]]] = {}
        self.actions: list[str] = []
        self.initializations = 0
        super().__init__(context, cfg, lease)

    def _inspect_docker_object(self, object_type: str, name: str):
        if object_type == "volume":
            return self.volumes.get(name), subprocess.CompletedProcess([], 0, "", "")
        return None, subprocess.CompletedProcess([], 1, "", "missing")

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
        filesystem_uuid, size_bytes = value
        return {
            "ok": True,
            "filesystemUuid": filesystem_uuid,
            "sizeBytes": size_bytes,
            "image": image_name,
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
    ) -> dict[str, Any]:
        self.actions.append(action)
        target_key = (self.lease.volume_name, storage.DATA_IMAGE_NAME)
        if action == "initialize":
            if target_key not in self.images:
                self.initializations += 1
                self.images[target_key] = (FS_A, SIZE)
        elif action == "migrate":
            source = self.images.get((legacy_volume, storage.DATA_IMAGE_NAME))
            if source is None or source[0] != expected_uuid:
                return {"ok": False, "error": "storage_image_invalid"}
            target = self.images.get(target_key)
            if target is not None and target[0] != source[0]:
                if not backup_image or target[0] != backup_uuid:
                    return {"ok": False, "error": "storage_identity_mismatch"}
                self.images[(self.lease.volume_name, backup_image)] = target
            self.images[target_key] = source
        value = self.images.get(target_key)
        if value is None or (expected_uuid and action == "preserve" and value[0] != expected_uuid):
            return {"ok": False, "error": "storage_image_invalid"}
        return {
            "ok": True,
            "filesystemUuid": value[0],
            "sizeBytes": value[1],
            "action": action,
        }

    def _legacy_volume_attachments(self, volume_name: str):
        return list(self.attachments.get(volume_name, [])), {"ok": True}

    def _remove_legacy_container(self, container_id: str, expected_name: str, expected_volume: str):
        self.attachments[expected_volume] = []
        return {"ok": True}


def transfer_engine_state(source: FakeRuntime, target: FakeRuntime) -> None:
    target.volumes = source.volumes
    target.images = source.images
    target.attachments = source.attachments


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
        runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] = (FS_A, SIZE)
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
        runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] = (FS_B, SIZE)
        result = runtime.ensure_instance_storage()
        require(result["ok"] is True)
        require(runtime.initializations == 0)
        committed = storage.StorageStateStore(context, lease).load()
        require(committed is not None and committed["source"] == "adopted")
        require(committed["filesystemUuid"] == FS_B)


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
        runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] = (FS_B, SIZE)
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
        runtime.images[("xenoid-data", storage.DATA_IMAGE_NAME)] = (FS_B, SIZE)
        result = runtime.ensure_instance_storage()
        require(result["ok"] is True)
        require(runtime.images[("xenoid-data", storage.DATA_IMAGE_NAME)] == (FS_B, SIZE))
        require(runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] == (FS_B, SIZE))
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
        runtime.images[("xenoid-data", storage.DATA_IMAGE_NAME)] = (FS_B, SIZE)
        runtime.volumes[lease.volume_name] = volume_record(runtime, lease.volume_name)
        runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] = (FS_A, SIZE)
        result = runtime.ensure_instance_storage()
        require(result["ok"] is True)
        committed = storage.StorageStateStore(context, lease).load()
        require(committed is not None and committed["backupFilesystemUuid"] == FS_A)
        backup_key = (lease.volume_name, committed["backupImage"])
        require(runtime.images[backup_key] == (FS_A, SIZE))
        require(runtime.images[(lease.volume_name, storage.DATA_IMAGE_NAME)] == (FS_B, SIZE))


@contract_case("legacyUnknownAttachmentIsRejected")
def legacy_unknown_attachment_is_rejected() -> None:
    with roots() as (project, state), fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(project, state, "phone-a")
        write_legacy(context)
        runtime = FakeRuntime(context, cfg, lease)
        runtime.volumes["xenoid-data"] = volume_record(runtime, "xenoid-data")
        runtime.images[("xenoid-data", storage.DATA_IMAGE_NAME)] = (FS_B, SIZE)
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
            "filesystemUuid": FS_B,
            "sizeBytes": SIZE,
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
