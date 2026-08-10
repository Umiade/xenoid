"""Crash-safe ownership state for one instance's persistent Android /data image."""
from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
from pathlib import Path
from typing import Any, Mapping, Optional

from .config import InstanceContext, InstanceLease

STORAGE_SCHEMA = "dev.xenoid.instance-storage/v1"
STATE_FILENAME = "storage.json"
DATA_IMAGE_NAME = "xenoid-data.img"
DEFAULT_DATA_SIZE_BYTES = 8192 * 1024 * 1024

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_TRANSACTION = re.compile(r"^[0-9a-f]{32}$")
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


def storage_transaction_id() -> str:
    return secrets.token_hex(16)


def temporary_image_name(transaction_id: str) -> str:
    transaction = _strict_text(transaction_id, _TRANSACTION, "storage_state_invalid")
    return f".{DATA_IMAGE_NAME}.{transaction}.new"


def backup_image_name(transaction_id: str) -> str:
    transaction = _strict_text(transaction_id, _TRANSACTION, "storage_state_invalid")
    return f"{DATA_IMAGE_NAME}.pre-legacy-{transaction}"


class StorageStateStore:
    """Strict 0600 state store for a single lease's data-image transaction."""

    def __init__(self, context: InstanceContext, lease: InstanceLease):
        self.context = context
        self.lease = lease
        self.path = context.state_root / STATE_FILENAME

    def load(self) -> Optional[dict[str, Any]]:
        try:
            info = self.path.lstat()
            if not self.path.is_file() or info.st_mode & 0o077:
                raise StorageError("storage_state_permissions", "instance storage state permissions are unsafe")
            with self.path.open("rb") as stream:
                raw = json.load(stream)
        except FileNotFoundError:
            return None
        except StorageError:
            raise
        except (OSError, ValueError, UnicodeError) as exc:
            raise StorageError("storage_state_invalid", "invalid instance storage state") from exc
        return self.validate(raw)

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
        size_bytes: int = DEFAULT_DATA_SIZE_BYTES,
        legacy_volume: str = "",
        legacy_filesystem_uuid: str = "",
        backup_image: str = "",
        backup_filesystem_uuid: str = "",
        backup_size_bytes: int = 0,
    ) -> dict[str, Any]:
        transaction = transaction_id or storage_transaction_id()
        state = {
            "schema": STORAGE_SCHEMA,
            "instanceId": self.context.instance_id,
            "resourceTag": self.context.resource_tag,
            "volumeName": self.lease.volume_name,
            "dataImage": DATA_IMAGE_NAME,
            "filesystemUuid": "",
            "sizeBytes": size_bytes,
            "source": source,
            "state": "pending",
            "transactionId": transaction,
            "temporaryImage": temporary_image_name(transaction),
            "legacyVolume": legacy_volume,
            "legacyFilesystemUuid": legacy_filesystem_uuid,
            "backupImage": backup_image,
            "backupFilesystemUuid": backup_filesystem_uuid,
            "backupSizeBytes": backup_size_bytes,
        }
        return self.save(state)

    def commit(self, pending: Mapping[str, Any], filesystem_uuid: str, size_bytes: int) -> dict[str, Any]:
        state = self.validate(pending)
        if state["state"] != "pending":
            raise StorageError("storage_state_invalid", "storage transaction is not pending")
        committed = {
            **state,
            "filesystemUuid": filesystem_uuid.lower(),
            "sizeBytes": size_bytes,
            "state": "committed",
            "temporaryImage": "",
        }
        return self.save(committed)

    def validate(self, raw: Mapping[str, Any]) -> dict[str, Any]:
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
        size_bytes = _size(state["sizeBytes"])
        backup_size = _size(state["backupSizeBytes"], allow_zero=True)
        if status == "pending":
            if filesystem_uuid or temporary != temporary_image_name(transaction):
                raise StorageError("storage_state_invalid", "invalid pending storage transaction")
        elif not filesystem_uuid or temporary:
            raise StorageError("storage_state_invalid", "invalid committed storage transaction")
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
        state.update({
            "transactionId": transaction,
            "filesystemUuid": filesystem_uuid,
            "temporaryImage": temporary,
            "legacyVolume": legacy_volume,
            "legacyFilesystemUuid": legacy_uuid,
            "backupImage": backup,
            "backupFilesystemUuid": backup_uuid,
            "sizeBytes": size_bytes,
            "backupSizeBytes": backup_size,
        })
        return state


def parse_storage_result(output: str) -> tuple[str, int]:
    """Parse the bounded machine-readable trailer emitted by make-rootfs-image.sh."""
    values: dict[str, str] = {}
    for line in (output or "").splitlines():
        if line.startswith("XENOID_DATA_") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip()
    filesystem_uuid = _strict_text(
        values.get("XENOID_DATA_UUID", "").lower(),
        _UUID,
        "storage_image_invalid",
    )
    try:
        size_bytes = int(values.get("XENOID_DATA_SIZE", ""), 10)
    except ValueError as exc:
        raise StorageError("storage_image_invalid", "data image size is unavailable") from exc
    if size_bytes <= 0:
        raise StorageError("storage_image_invalid", "data image size is invalid")
    return filesystem_uuid, size_bytes


def public_storage_state(state: Optional[Mapping[str, Any]], *, healthy: bool, error: str = "") -> dict[str, Any]:
    if state is None:
        return {"initialized": False, "healthy": False, **({} if not error else {"error": error})}
    return {
        "initialized": state.get("state") == "committed",
        "healthy": healthy,
        "state": state.get("state"),
        "source": state.get("source"),
        "filesystemUuid": state.get("filesystemUuid") or None,
        "sizeBytes": state.get("sizeBytes"),
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
