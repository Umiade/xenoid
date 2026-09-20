"""Crash-safe ownership state for one instance's persistent Android /data image."""
from __future__ import annotations

import json
import os
import re
import secrets
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping, Optional

from .config import InstanceContext, InstanceLease

STORAGE_SCHEMA = "dev.xenoid.instance-storage/v5"
_V4_STORAGE_SCHEMA = "dev.xenoid.instance-storage/v4"
_V3_STORAGE_SCHEMA = "dev.xenoid.instance-storage/v3"
_V2_STORAGE_SCHEMA = "dev.xenoid.instance-storage/v2"
LEGACY_STORAGE_SCHEMA = "dev.xenoid.instance-storage/v1"
STATE_FILENAME = "storage.json"
DATA_IMAGE_NAME = "xenoid-data.img"
ROOTFS_IMAGE_NAME = "xenoid-rootfs.img"
CANONICAL_DATA_SIZE_BYTES = 128_000_000_000

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_TRANSACTION = re.compile(r"^[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TEMPORARY_IMAGE = re.compile(r"^\.xenoid-data\.img\.[0-9a-f]{32}\.new$")
_VOLUME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SOURCES = frozenset({"fresh", "adopted", "legacy"})
_STATES = frozenset({"pending", "committed"})
_KEYS = {
    "schema",
    "instanceId",
    "resourceTag",
    "volumeName",
    "dataImage",
    "filesystemUuid",
    "desiredLogicalSizeBytes",
    "rootfsImage",
    "rootfsFilesystemUuid",
    "rootfsSourceSha256",
    "observedRootfsSizeBytes",
    "observedLogicalSizeBytes",
    "observedFilesystemSizeBytes",
    "hostAllocatedBytes",
    "source",
    "state",
    "transactionId",
    "temporaryImage",
    "legacyVolume",
    "legacyFilesystemUuid",
    "backupImage",
    "backupFilesystemUuid",
    "backupSizeBytes",
    "backupRootfsImage",
    "backupRootfsFilesystemUuid",
    "backupRootfsSizeBytes",
}
_LEGACY_KEYS = {
    "schema",
    "instanceId",
    "resourceTag",
    "volumeName",
    "dataImage",
    "filesystemUuid",
    "sizeBytes",
    "source",
    "state",
    "transactionId",
    "temporaryImage",
    "legacyVolume",
    "legacyFilesystemUuid",
    "backupImage",
    "backupFilesystemUuid",
    "backupSizeBytes",
}


class StorageError(RuntimeError):
    """Stable, secret-free instance storage failure."""

    def __init__(self, code: str, message: str = ""):
        self.code = code
        super().__init__(message or code)

    def as_dict(self) -> dict[str, Any]:
        return {"ok": False, "error": self.code, "message": str(self)}


def _strict_text(value: Any, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or value != value.strip() or pattern.fullmatch(value) is None:
        raise StorageError(code, "invalid instance storage state")
    return value


def _optional_text(value: Any, pattern: re.Pattern[str], code: str) -> str:
    if value == "":
        return ""
    return _strict_text(value, pattern, code)


def _size(value: Any, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StorageError("storage_state_invalid", "invalid instance storage state")
    if value < 0 or (value == 0 and not allow_zero):
        raise StorageError("storage_state_invalid", "invalid instance storage state")
    return value

def _reject_pending_legacy_rotation(markers: Mapping[str, Any]) -> None:
    """Fail closed when a pre-v5 record still carries a pending rotation.

    A non-empty rotation target is crash-window evidence: the images may
    already carry the target UUIDs, so silently dropping the markers could
    wedge the instance into a permanent identity mismatch. Loading is
    read-only, so raising here keeps the original record byte-for-byte.
    """
    for value in markers.values():
        if _optional_text(value, _UUID, "storage_state_invalid"):
            raise StorageError(
                "storage_legacy_rotation_pending",
                "instance storage has a pending legacy offline rotation; "
                "the original state is preserved untouched for operator inspection",
            )


def storage_transaction_id() -> str:
    return secrets.token_hex(16)


def temporary_image_name(transaction_id: str) -> str:
    transaction = _strict_text(transaction_id, _TRANSACTION, "storage_state_invalid")
    return f".{DATA_IMAGE_NAME}.{transaction}.new"


def backup_image_name(transaction_id: str) -> str:
    transaction = _strict_text(transaction_id, _TRANSACTION, "storage_state_invalid")
    return f"{DATA_IMAGE_NAME}.pre-legacy-{transaction}"

def backup_rootfs_image_name(transaction_id: str) -> str:
    transaction = _strict_text(transaction_id, _TRANSACTION, "storage_state_invalid")
    return f"{ROOTFS_IMAGE_NAME}.pre-source-{transaction}"




class StorageStateStore:
    """Strict 0600 state store for a single lease's data-image transaction."""

    def __init__(self, context: InstanceContext, lease: InstanceLease):
        self.context = context
        self.lease = lease
        self.path = context.state_root / STATE_FILENAME

    def load(self) -> Optional[dict[str, Any]]:
        legacy_rootfs = False
        try:
            info = self.path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise StorageError("storage_state_permissions", "instance storage state permissions are unsafe")
            descriptor = os.open(
                self.path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    raw = json.load(stream)
            finally:
                os.close(descriptor)
        except FileNotFoundError:
            return None
        except StorageError:
            raise
        except (OSError, ValueError, UnicodeError) as exc:
            raise StorageError("storage_state_invalid", "invalid instance storage state") from exc
        if isinstance(raw, Mapping) and raw.get("schema") == LEGACY_STORAGE_SCHEMA:
            raw = self._migrate_v1(raw)
        if isinstance(raw, Mapping) and raw.get("schema") == _V2_STORAGE_SCHEMA:
            raw = {**raw, "schema": _V3_STORAGE_SCHEMA}
        if isinstance(raw, Mapping) and raw.get("schema") == _V3_STORAGE_SCHEMA:
            raw = self._migrate_v3(raw)
            legacy_rootfs = True
        if isinstance(raw, Mapping) and raw.get("schema") == _V4_STORAGE_SCHEMA:
            raw = self._migrate_v4(raw)
        return self.validate(raw, allow_legacy_rootfs=legacy_rootfs)

    def _migrate_v1(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        if set(raw) != _LEGACY_KEYS:
            raise StorageError("storage_state_invalid", "invalid legacy storage state")
        legacy_size = _size(raw.get("sizeBytes"))
        status = raw.get("state")
        observed_size = legacy_size if status == "committed" else 0
        return {
            "schema": _V3_STORAGE_SCHEMA,
            "instanceId": raw.get("instanceId"),
            "resourceTag": raw.get("resourceTag"),
            "volumeName": raw.get("volumeName"),
            "dataImage": raw.get("dataImage"),
            "filesystemUuid": raw.get("filesystemUuid"),
            "desiredLogicalSizeBytes": CANONICAL_DATA_SIZE_BYTES,
            "observedLogicalSizeBytes": observed_size,
            "observedFilesystemSizeBytes": observed_size,
            "hostAllocatedBytes": 0,
            "source": raw.get("source"),
            "state": status,
            "transactionId": raw.get("transactionId"),
            "temporaryImage": raw.get("temporaryImage"),
            "legacyVolume": raw.get("legacyVolume"),
            "legacyFilesystemUuid": raw.get("legacyFilesystemUuid"),
            "backupImage": raw.get("backupImage"),
            "backupFilesystemUuid": raw.get("backupFilesystemUuid"),
            "backupSizeBytes": raw.get("backupSizeBytes"),
        }

    def _migrate_v3(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        expected = _KEYS - {
            "rootfsImage",
            "rootfsFilesystemUuid",
            "rootfsSourceSha256",
            "observedRootfsSizeBytes",
            "backupRootfsImage",
            "backupRootfsFilesystemUuid",
            "backupRootfsSizeBytes",
        }
        if set(raw) - {"rotationTargetUuid"} != expected:
            raise StorageError("storage_state_invalid", "invalid v3 storage state")
        migrated = {
            **{key: value for key, value in raw.items() if key != "rotationTargetUuid"},
            "schema": STORAGE_SCHEMA,
            "rootfsImage": "",
            "rootfsFilesystemUuid": "",
            "rootfsSourceSha256": "",
            "observedRootfsSizeBytes": 0,
            "backupRootfsImage": "",
            "backupRootfsFilesystemUuid": "",
            "backupRootfsSizeBytes": 0,
        }
        self.validate(migrated, allow_legacy_rootfs=True)
        _reject_pending_legacy_rotation(
            {
                key: raw[key]
                for key in ("rotationTargetUuid",)
                if key in raw
            }
        )
        return migrated

    def _migrate_v4(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        expected = _KEYS | {"rotationTargetUuid", "rotationTargetRootfsUuid"}
        if set(raw) != expected:
            raise StorageError("storage_state_invalid", "invalid v4 storage state")
        _reject_pending_legacy_rotation(
            {
                key: raw[key]
                for key in ("rotationTargetUuid", "rotationTargetRootfsUuid")
            }
        )
        migrated = {
            **{
                key: value
                for key, value in raw.items()
                if key not in {"rotationTargetUuid", "rotationTargetRootfsUuid"}
            },
            "schema": STORAGE_SCHEMA,
        }
        self.validate(migrated)
        return migrated

    def save(self, state: Mapping[str, Any]) -> dict[str, Any]:
        clean = self.validate(state)
        self.context.state_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.context.state_root.chmod(0o700)
        payload = (
            json.dumps(clean, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("ascii")
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.context.state_root)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            self.path.chmod(0o600)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        return clean

    def pending(
        self,
        source: str,
        *,
        transaction_id: Optional[str] = None,
        filesystem_uuid: str = "",
        desired_logical_size_bytes: int = CANONICAL_DATA_SIZE_BYTES,
        observed_logical_size_bytes: int = 0,
        observed_filesystem_size_bytes: int = 0,
        host_allocated_bytes: int = 0,
        rootfs_image: str = "",
        rootfs_filesystem_uuid: str = "",
        rootfs_source_sha256: str = "",
        observed_rootfs_size_bytes: int = 0,
        legacy_volume: str = "",
        legacy_filesystem_uuid: str = "",
        backup_image: str = "",
        backup_filesystem_uuid: str = "",
        backup_size_bytes: int = 0,
        backup_rootfs_image: str = "",
        backup_rootfs_filesystem_uuid: str = "",
        backup_rootfs_size_bytes: int = 0,
        growth: bool = False,
    ) -> dict[str, Any]:
        transaction = transaction_id or storage_transaction_id()
        state = {
            "schema": STORAGE_SCHEMA,
            "instanceId": self.context.instance_id,
            "resourceTag": self.context.resource_tag,
            "volumeName": self.lease.volume_name,
            "dataImage": DATA_IMAGE_NAME,
            "filesystemUuid": filesystem_uuid,
            "desiredLogicalSizeBytes": desired_logical_size_bytes,
            "rootfsImage": rootfs_image,
            "rootfsFilesystemUuid": rootfs_filesystem_uuid,
            "rootfsSourceSha256": rootfs_source_sha256,
            "observedRootfsSizeBytes": observed_rootfs_size_bytes,
            "observedLogicalSizeBytes": observed_logical_size_bytes,
            "observedFilesystemSizeBytes": observed_filesystem_size_bytes,
            "hostAllocatedBytes": host_allocated_bytes,
            "source": source,
            "state": "pending",
            "transactionId": transaction,
            "temporaryImage": (
                "" if growth else temporary_image_name(transaction)
            ),
            "legacyVolume": legacy_volume,
            "legacyFilesystemUuid": legacy_filesystem_uuid,
            "backupImage": backup_image,
            "backupFilesystemUuid": backup_filesystem_uuid,
            "backupSizeBytes": backup_size_bytes,
            "backupRootfsImage": backup_rootfs_image,
            "backupRootfsFilesystemUuid": backup_rootfs_filesystem_uuid,
            "backupRootfsSizeBytes": backup_rootfs_size_bytes,
        }
        return self.save(state)

    def commit(
        self,
        pending: Mapping[str, Any],
        image: Mapping[str, Any],
    ) -> dict[str, Any]:
        state = self.validate(pending)
        if state["state"] != "pending":
            raise StorageError("storage_state_invalid", "storage transaction is not pending")
        image_data_uuid = str(image["filesystemUuid"]).lower()
        image_rootfs_uuid = str(image["rootfsFilesystemUuid"]).lower()
        image_rootfs_source = str(image["rootfsSourceSha256"]).lower()
        image_rootfs_size = int(image["rootfsSizeBytes"])
        expected_data_uuid = state["filesystemUuid"]
        expected_rootfs_uuid = state["rootfsFilesystemUuid"]
        if (
            expected_data_uuid
            and image_data_uuid != expected_data_uuid
            or expected_rootfs_uuid
            and image_rootfs_uuid != expected_rootfs_uuid
            or state["rootfsSourceSha256"]
            and image_rootfs_source != state["rootfsSourceSha256"]
            or state["observedRootfsSizeBytes"]
            and image_rootfs_size != state["observedRootfsSizeBytes"]
        ):
            raise StorageError(
                "storage_identity_mismatch",
                "storage commit observations differ from the pending target",
            )
        committed = {
            **state,
            "filesystemUuid": image_data_uuid,
            "observedLogicalSizeBytes": int(image["logicalSizeBytes"]),
            "observedFilesystemSizeBytes": int(image["filesystemSizeBytes"]),
            "hostAllocatedBytes": int(image["allocatedBytes"]),
            "rootfsImage": ROOTFS_IMAGE_NAME,
            "rootfsFilesystemUuid": image_rootfs_uuid,
            "rootfsSourceSha256": image_rootfs_source,
            "observedRootfsSizeBytes": image_rootfs_size,
            "backupRootfsImage": str(
                image.get("backupRootfsImage") or state["backupRootfsImage"]
            ),
            "backupRootfsFilesystemUuid": str(
                image.get("backupRootfsFilesystemUuid")
                or state["backupRootfsFilesystemUuid"]
            ).lower(),
            "backupRootfsSizeBytes": int(
                image.get("backupRootfsSizeBytes")
                or state["backupRootfsSizeBytes"]
            ),
            "state": "committed",
            "temporaryImage": "",
        }
        return self.save(committed)

    def refresh(
        self,
        committed: Mapping[str, Any],
        image: Mapping[str, Any],
    ) -> dict[str, Any]:
        state = self.validate(committed, allow_legacy_rootfs=not committed.get("rootfsImage"))
        if state["state"] != "committed":
            raise StorageError("storage_state_invalid", "storage transaction is not committed")
        filesystem_uuid = str(image["filesystemUuid"]).lower()
        logical_size = int(image["logicalSizeBytes"])
        filesystem_size = int(image["filesystemSizeBytes"])
        rootfs_uuid = str(image["rootfsFilesystemUuid"]).lower()
        rootfs_source = str(image["rootfsSourceSha256"]).lower()
        rootfs_size = int(image["rootfsSizeBytes"])
        if (
            filesystem_uuid != state["filesystemUuid"]
            or logical_size != state["desiredLogicalSizeBytes"]
            or filesystem_size != state["desiredLogicalSizeBytes"]
            or state["rootfsFilesystemUuid"]
            and rootfs_uuid != state["rootfsFilesystemUuid"]
        ):
            raise StorageError("storage_identity_mismatch", "instance image observations do not match")
        refreshed = {
            **state,
            "rootfsImage": ROOTFS_IMAGE_NAME,
            "rootfsFilesystemUuid": rootfs_uuid,
            "rootfsSourceSha256": rootfs_source,
            "observedRootfsSizeBytes": rootfs_size,
            "backupRootfsImage": str(
                image.get("backupRootfsImage") or state["backupRootfsImage"]
            ),
            "backupRootfsFilesystemUuid": str(
                image.get("backupRootfsFilesystemUuid")
                or state["backupRootfsFilesystemUuid"]
            ).lower(),
            "backupRootfsSizeBytes": int(
                image.get("backupRootfsSizeBytes")
                or state["backupRootfsSizeBytes"]
            ),
            "observedLogicalSizeBytes": logical_size,
            "observedFilesystemSizeBytes": filesystem_size,
            "hostAllocatedBytes": int(image["allocatedBytes"]),
        }
        return self.save(refreshed)

    def clear_rootfs_backup(self, committed: Mapping[str, Any]) -> dict[str, Any]:
        state = self.validate(committed)
        if state["state"] != "committed":
            raise StorageError(
                "storage_state_invalid",
                "rootfs backup cleanup requires committed storage",
            )
        return self.save(
            {
                **state,
                "backupRootfsImage": "",
                "backupRootfsFilesystemUuid": "",
                "backupRootfsSizeBytes": 0,
            }
        )

    def validate(
        self,
        raw: Mapping[str, Any],
        *,
        allow_legacy_rootfs: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(raw, Mapping) or set(raw) != _KEYS:
            raise StorageError("storage_state_invalid", "invalid instance storage state")
        state = dict(raw)
        if state["schema"] != STORAGE_SCHEMA:
            raise StorageError("storage_state_invalid", "unsupported instance storage schema")
        if state["instanceId"] != self.context.instance_id:
            raise StorageError("storage_identity_mismatch", "storage state belongs to another instance")
        if state["resourceTag"] != self.context.resource_tag:
            raise StorageError("storage_identity_mismatch", "storage resource tag mismatch")
        if state["volumeName"] != self.lease.volume_name:
            raise StorageError("storage_identity_mismatch", "storage volume lease mismatch")
        if state["dataImage"] != DATA_IMAGE_NAME:
            raise StorageError("storage_state_invalid", "invalid data image name")
        source = state["source"]
        status = state["state"]
        if source not in _SOURCES or status not in _STATES:
            raise StorageError("storage_state_invalid", "invalid instance storage transaction")
        transaction = _strict_text(state["transactionId"], _TRANSACTION, "storage_state_invalid")
        filesystem_uuid = _optional_text(state["filesystemUuid"], _UUID, "storage_state_invalid")
        temporary = _optional_text(state["temporaryImage"], _TEMPORARY_IMAGE, "storage_state_invalid")
        legacy_volume = _optional_text(state["legacyVolume"], _VOLUME, "storage_state_invalid")
        legacy_uuid = _optional_text(state["legacyFilesystemUuid"], _UUID, "storage_state_invalid")
        backup = _optional_text(state["backupImage"], _IMAGE, "storage_state_invalid")
        backup_uuid = _optional_text(state["backupFilesystemUuid"], _UUID, "storage_state_invalid")
        rootfs_image = _optional_text(state["rootfsImage"], _IMAGE, "storage_state_invalid")
        rootfs_uuid = _optional_text(state["rootfsFilesystemUuid"], _UUID, "storage_state_invalid")
        rootfs_source = _optional_text(state["rootfsSourceSha256"], _SHA256, "storage_state_invalid")
        backup_rootfs = _optional_text(state["backupRootfsImage"], _IMAGE, "storage_state_invalid")
        backup_rootfs_uuid = _optional_text(
            state["backupRootfsFilesystemUuid"],
            _UUID,
            "storage_state_invalid",
        )
        desired = _size(state["desiredLogicalSizeBytes"])
        observed = _size(state["observedLogicalSizeBytes"], allow_zero=True)
        filesystem_size = _size(state["observedFilesystemSizeBytes"], allow_zero=True)
        allocated = _size(state["hostAllocatedBytes"], allow_zero=True)
        backup_size = _size(state["backupSizeBytes"], allow_zero=True)
        rootfs_size = _size(state["observedRootfsSizeBytes"], allow_zero=True)
        backup_rootfs_size = _size(state["backupRootfsSizeBytes"], allow_zero=True)
        if desired != CANONICAL_DATA_SIZE_BYTES:
            raise StorageError("storage_size_unsafe", "non-canonical data image size")
        if observed > desired or filesystem_size > observed:
            raise StorageError("storage_size_unsafe", "data image geometry exceeds its desired size")
        if status == "pending":
            growth = temporary == ""
            if (
                growth
                and (not filesystem_uuid or observed == 0 or filesystem_size == 0)
                or not growth
                and temporary != temporary_image_name(transaction)
            ):
                raise StorageError("storage_state_invalid", "invalid pending storage transaction")
        elif not filesystem_uuid or temporary or observed == 0 or filesystem_size == 0:
            raise StorageError("storage_state_invalid", "invalid committed storage transaction")
        rootfs_fields = (
            bool(rootfs_image),
            bool(rootfs_uuid),
            bool(rootfs_source),
            rootfs_size > 0,
        )
        if len(set(rootfs_fields)) != 1:
            raise StorageError("storage_state_invalid", "rootfs storage identity is incomplete")
        if rootfs_image and rootfs_image != ROOTFS_IMAGE_NAME:
            raise StorageError("storage_state_invalid", "invalid rootfs image name")
        if not rootfs_image and status == "committed" and not allow_legacy_rootfs:
            raise StorageError("storage_state_invalid", "committed rootfs identity is missing")
        if source == "legacy":
            if not legacy_volume or not legacy_uuid:
                raise StorageError("storage_state_invalid", "legacy storage source is incomplete")
        elif legacy_volume or legacy_uuid:
            raise StorageError("storage_state_invalid", "unexpected legacy storage source")
        backup_fields = bool(backup), bool(backup_uuid), backup_size > 0
        if len(set(backup_fields)) != 1:
            raise StorageError("storage_state_invalid", "storage backup state is incomplete")
        if backup and source != "legacy":
            raise StorageError("storage_state_invalid", "unexpected storage backup")
        rootfs_backup_fields = (
            bool(backup_rootfs),
            bool(backup_rootfs_uuid),
            backup_rootfs_size > 0,
        )
        if len(set(rootfs_backup_fields)) != 1:
            raise StorageError("storage_state_invalid", "rootfs backup state is incomplete")
        if backup_rootfs and (
            backup_rootfs == ROOTFS_IMAGE_NAME
            or backup_rootfs != backup_rootfs_image_name(transaction)
        ):
            raise StorageError(
                "storage_state_invalid",
                "rootfs backup name is not transaction-owned",
            )
        state.update({
            "transactionId": transaction,
            "filesystemUuid": filesystem_uuid,
            "temporaryImage": temporary,
            "legacyVolume": legacy_volume,
            "legacyFilesystemUuid": legacy_uuid,
            "backupImage": backup,
            "backupFilesystemUuid": backup_uuid,
            "rootfsImage": rootfs_image,
            "rootfsFilesystemUuid": rootfs_uuid,
            "rootfsSourceSha256": rootfs_source,
            "backupRootfsImage": backup_rootfs,
            "backupRootfsFilesystemUuid": backup_rootfs_uuid,
            "desiredLogicalSizeBytes": desired,
            "observedLogicalSizeBytes": observed,
            "observedFilesystemSizeBytes": filesystem_size,
            "hostAllocatedBytes": allocated,
            "backupSizeBytes": backup_size,
            "observedRootfsSizeBytes": rootfs_size,
            "backupRootfsSizeBytes": backup_rootfs_size,
        })
        return state


def parse_storage_result(
    output: str,
    *,
    require_rootfs: bool = False,
) -> dict[str, Any]:
    """Parse bounded data and optional rootfs geometry from engine scripts."""
    values: dict[str, str] = {}
    for line in (output or "").splitlines():
        if (
            line.startswith("XENOID_DATA_")
            or line.startswith("XENOID_ROOTFS_")
        ) and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip()
    filesystem_uuid = _strict_text(
        values.get("XENOID_DATA_UUID", "").lower(),
        _UUID,
        "storage_image_invalid",
    )
    parsed: dict[str, int] = {}
    for output_key, result_key in (
        ("XENOID_DATA_LOGICAL_SIZE", "logicalSizeBytes"),
        ("XENOID_DATA_FILESYSTEM_SIZE", "filesystemSizeBytes"),
        ("XENOID_DATA_ALLOCATED_SIZE", "allocatedBytes"),
        ("XENOID_DATA_BACKING_TOTAL", "backingTotalBytes"),
        ("XENOID_DATA_BACKING_AVAILABLE", "backingAvailableBytes"),
    ):
        try:
            parsed[result_key] = int(values.get(output_key, ""), 10)
        except ValueError as exc:
            raise StorageError(
                "storage_image_invalid",
                f"{result_key} is unavailable",
            ) from exc
    if (
        parsed["logicalSizeBytes"] <= 0
        or parsed["filesystemSizeBytes"] <= 0
        or parsed["filesystemSizeBytes"] > parsed["logicalSizeBytes"]
        or parsed["allocatedBytes"] < 0
        or parsed["backingTotalBytes"] <= 0
        or parsed["backingAvailableBytes"] < 0
        or parsed["backingAvailableBytes"] > parsed["backingTotalBytes"]
    ):
        raise StorageError("storage_image_invalid", "data image geometry is invalid")
    result: dict[str, Any] = {"filesystemUuid": filesystem_uuid, **parsed}
    has_rootfs = any(key.startswith("XENOID_ROOTFS_") for key in values)
    if require_rootfs or has_rootfs:
        result["rootfsFilesystemUuid"] = _strict_text(
            values.get("XENOID_ROOTFS_UUID", "").lower(),
            _UUID,
            "storage_image_invalid",
        )
        result["rootfsSourceSha256"] = _strict_text(
            values.get("XENOID_ROOTFS_SOURCE_SHA256", "").lower(),
            _SHA256,
            "storage_image_invalid",
        )
        try:
            result["rootfsSizeBytes"] = int(
                values.get("XENOID_ROOTFS_LOGICAL_SIZE", ""),
                10,
            )
        except ValueError as exc:
            raise StorageError(
                "storage_image_invalid",
                "rootfsSizeBytes is unavailable",
            ) from exc
        if result["rootfsSizeBytes"] <= 0:
            raise StorageError(
                "storage_image_invalid",
                "rootfs image geometry is invalid",
            )
        backup_name = values.get("XENOID_ROOTFS_BACKUP_IMAGE", "")
        if backup_name:
            result["backupRootfsImage"] = _strict_text(
                backup_name,
                _IMAGE,
                "storage_image_invalid",
            )
            result["backupRootfsFilesystemUuid"] = _strict_text(
                values.get("XENOID_ROOTFS_BACKUP_UUID", "").lower(),
                _UUID,
                "storage_image_invalid",
            )
            try:
                result["backupRootfsSizeBytes"] = int(
                    values.get("XENOID_ROOTFS_BACKUP_SIZE", ""),
                    10,
                )
            except ValueError as exc:
                raise StorageError(
                    "storage_image_invalid",
                    "rootfs backup size is unavailable",
                ) from exc
            if result["backupRootfsSizeBytes"] <= 0:
                raise StorageError(
                    "storage_image_invalid",
                    "rootfs backup geometry is invalid",
                )
    return result


def public_storage_state(state: Optional[Mapping[str, Any]], *, healthy: bool, error: str = "") -> dict[str, Any]:
    if state is None:
        return {"initialized": False, "healthy": False, **({} if not error else {"error": error})}
    return {
        "initialized": state.get("state") == "committed",
        "healthy": healthy,
        "state": state.get("state"),
        "source": state.get("source"),
        "filesystemUuid": state.get("filesystemUuid") or None,
        "desiredLogicalSizeBytes": state.get("desiredLogicalSizeBytes"),
        "observedLogicalSizeBytes": state.get("observedLogicalSizeBytes"),
        "observedFilesystemSizeBytes": state.get("observedFilesystemSizeBytes"),
        "hostAllocatedBytes": state.get("hostAllocatedBytes"),
        "rootfsFilesystemUuid": state.get("rootfsFilesystemUuid") or None,
        "rootfsSourceSha256": state.get("rootfsSourceSha256") or None,
        "observedRootfsSizeBytes": state.get("observedRootfsSizeBytes"),
        "backup": (
            {
                "image": state.get("backupImage"),
                "filesystemUuid": state.get("backupFilesystemUuid"),
                "sizeBytes": state.get("backupSizeBytes"),
            }
            if state.get("backupImage")
            else None
        ),
        **({} if not error else {"error": error}),
    }
