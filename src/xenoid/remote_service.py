from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections import OrderedDict, deque
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Optional
from urllib.parse import urlsplit

from .backend import RuntimeManager
from .config import (
    INSTANCE_NAME_RE,
    InstanceContext,
    InstanceError,
    list_instances,
    resolve_instance,
    resolve_project_root,
    validate_instance_name,
)
from .daemon_client import DaemonClient
from .device_identity import IdentityError, RegenerationJournal
from .mcp_server import (
    MCPRuntime,
    _legacy_proxy_recovery_allowed,
    call_tool,
    tools as local_tools,
)
from .operation_lock import instance_operation_lock as shared_operation_lock
from .util import command_timeout


PROTOCOL_VERSION = "2026-07-28"
SERVER_INFO = {"name": "xenoid-service", "version": "0.1.0"}
ACCESS_SCHEMA_VERSION = 1
MAX_REQUEST_BYTES = 1024 * 1024
DEFAULT_REQUESTS_PER_MINUTE = 120
DEFAULT_MAX_CONCURRENCY = 8
TOKEN_PREFIX = "xnd_"

_TOKEN_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_HOST_RE = re.compile(r"^(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::[0-9]{1,5})?$")
_BASE64_SENTINEL_RE = re.compile(r"^=\?base64\?([A-Za-z0-9+/]*={0,2})\?=$")
_KNOWN_SCOPES = frozenset({"read", "control", "root", "inspect"})


@dataclass(frozen=True)
class RemoteToolPolicy:
    scope: str
    mutating: bool
    destructive: bool = False
    schema_properties: Optional[frozenset[str]] = None


def _remote_policy(
    scope: str,
    mutating: bool,
    *properties: str,
    destructive: bool = False,
) -> RemoteToolPolicy:
    return RemoteToolPolicy(
        scope,
        mutating,
        destructive=destructive,
        schema_properties=frozenset(properties),
    )


# Remote access deliberately excludes every tool that consumes an unrestricted
# host path, executes host JavaScript, deploys host artifacts, changes host
# protection, or builds/packages software. Those operations remain local CLI or
# fixed-instance stdio MCP workflows.
REMOTE_TOOL_POLICIES: dict[str, RemoteToolPolicy] = {
    "xenoid_status": _remote_policy("read", False),
    "xenoid_daemon_health": _remote_policy("read", False),
    "xenoid_google_services_status": _remote_policy("read", False, "requireRuntime"),
    "xenoid_proxy_status": _remote_policy("read", False),
    # A check records a fresh generation/runtime proof, so serialize it with
    # other instance mutations. A failed proof may quarantine the proxy, so it
    # belongs to control rather than read scope.
    "xenoid_proxy_check": _remote_policy("control", True),
    "xenoid_location_list": _remote_policy("read", False),
    "xenoid_location_status": _remote_policy("read", False, "check"),
    "xenoid_root_status": _remote_policy("read", False),
    "xenoid_frida_status": _remote_policy("read", False),
    "xenoid_device_collect": _remote_policy("read", False),
    "xenoid_profile_helper_status": _remote_policy("read", False),
    "xenoid_hide_status": _remote_policy("read", False),
    "xenoid_hide_overlay_status": _remote_policy("read", False),
    "xenoid_ota_check": _remote_policy("read", False),
    "xenoid_up": _remote_policy("control", True, "skipBuild"),
    "xenoid_stop": _remote_policy("control", True, destructive=True),
    "xenoid_google_services_enable": _remote_policy("control", True, "release"),
    "xenoid_google_services_disable": _remote_policy("control", True, destructive=True),
    "xenoid_proxy_on": _remote_policy("control", True),
    "xenoid_proxy_off": _remote_policy("control", True),
    "xenoid_proxy_clear": _remote_policy(
        "control",
        True,
        "discardUnreadableState",
        destructive=True,
    ),
    "xenoid_proxy_select": _remote_policy("control", True, "name"),
    "xenoid_location_set": _remote_policy("control", True, "countryCode"),
    "xenoid_input_tap": _remote_policy("control", True, "x", "y"),
    "xenoid_input_swipe": _remote_policy(
        "control", True, "x1", "y1", "x2", "y2", "durationMs"
    ),
    # xenoid_app_install accepts a path in the Android guest.  Keep all
    # free-form path parameters off the network surface so callers cannot
    # confuse guest and host path semantics through future implementation
    # changes.  Installation remains available through the local CLI/MCP.
    "xenoid_app_uninstall": _remote_policy("control", True, "package", destructive=True),
    "xenoid_app_launch": _remote_policy("control", True, "component"),
    "xenoid_device_set": _remote_policy("control", True, "field", "value"),
    # The remote form intentionally removes policyPath. It reapplies only the
    # daemon's already configured/default policy and cannot read a host file.
    "xenoid_hide_apply": _remote_policy("control", True),
    "xenoid_ota_apply": _remote_policy("control", True, "channel"),
    "xenoid_root_exec": _remote_policy("root", True, "command", destructive=True),
    "xenoid_frida_start": _remote_policy("inspect", True, "port"),
    "xenoid_frida_stop": _remote_policy("inspect", True),
}


class ServiceError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: Optional[str] = None,
        *,
        http_status: int = 400,
        rpc_code: int = -32602,
        data: Optional[dict[str, Any]] = None,
    ):
        self.code = code
        self.http_status = http_status
        self.rpc_code = rpc_code
        self.data = data
        super().__init__(message or code)


@dataclass(frozen=True)
class AccessGrant:
    name: str
    scopes: frozenset[str]
    instance_bindings: Mapping[str, str]
    created_at: str

    @property
    def effective_scopes(self) -> frozenset[str]:
        values = set(self.scopes)
        if values:
            values.add("read")
        return frozenset(values)

    def permits_scope(self, scope: str) -> bool:
        return scope in self.effective_scopes

    def permits_instance_name(self, instance_name: str) -> bool:
        return (
            self.instance_bindings.get("*") == "*"
            or instance_name in self.instance_bindings
        )

    def permits_instance(self, context: InstanceContext) -> bool:
        if self.instance_bindings.get("*") == "*":
            return True
        return hmac.compare_digest(
            self.instance_bindings.get(context.instance_name, ""),
            context.instance_id,
        )

    def public_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "scopes": sorted(self.scopes),
            "instances": sorted(self.instance_bindings),
            "createdAt": self.created_at,
        }


class AccessStore:
    """Private, project-scoped bearer-token digests and instance ACLs."""

    def __init__(
        self,
        project_root: Path,
        *,
        state_home: Optional[Path] = None,
    ):
        self.project_root = Path(project_root).resolve()
        self.state_home = Path(state_home).resolve() if state_home else None
        self.root = self.project_root / ".xenoid" / "service"
        self.path = self.root / "access.json"
        self.lock_path = self.root / "access.lock"

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            info = self.root.lstat()
        except OSError as exc:
            raise ServiceError("access_store_unavailable") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
        ):
            raise ServiceError("access_store_permissions_invalid")
        os.chmod(self.root, 0o700)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._ensure_root()
        flags = os.O_CREAT | os.O_RDWR
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.lock_path, flags, 0o600)
        except OSError as exc:
            raise ServiceError("access_store_unavailable") from exc
        try:
            os.fchmod(fd, 0o600)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise ServiceError("access_store_permissions_invalid")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    @staticmethod
    def _entry_to_grant(entry: Mapping[str, Any]) -> AccessGrant:
        name = entry.get("name")
        digest = entry.get("digest")
        scopes = entry.get("scopes")
        bindings = entry.get("instanceBindings")
        created_at = entry.get("createdAt")
        if (
            not isinstance(name, str)
            or not _TOKEN_NAME_RE.fullmatch(name)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not isinstance(scopes, list)
            or not scopes
            or any(not isinstance(value, str) or value not in _KNOWN_SCOPES for value in scopes)
            or len(set(scopes)) != len(scopes)
            or not isinstance(bindings, dict)
            or not bindings
            or not isinstance(created_at, str)
        ):
            raise ServiceError("access_store_invalid")
        if "*" in bindings:
            if bindings != {"*": "*"}:
                raise ServiceError("access_store_invalid")
        else:
            for instance, instance_id in bindings.items():
                if (
                    not isinstance(instance, str)
                    or not INSTANCE_NAME_RE.fullmatch(instance)
                    or not isinstance(instance_id, str)
                    or not re.fullmatch(
                        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                        instance_id,
                    )
                ):
                    raise ServiceError("access_store_invalid")
        return AccessGrant(
            name=name,
            scopes=frozenset(scopes),
            instance_bindings=dict(bindings),
            created_at=created_at,
        )

    def _read_unlocked(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(self.path, flags)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise ServiceError("access_store_permissions_invalid")
            stream = os.fdopen(descriptor, "r", encoding="utf-8")
            descriptor = -1
            with stream:
                document = json.load(stream)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ServiceError("access_store_invalid") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if (
            not isinstance(document, dict)
            or set(document) != {"schemaVersion", "tokens"}
            or document.get("schemaVersion") != ACCESS_SCHEMA_VERSION
            or not isinstance(document.get("tokens"), list)
        ):
            raise ServiceError("access_store_invalid")
        entries = document["tokens"]
        grants = [self._entry_to_grant(entry) for entry in entries if isinstance(entry, dict)]
        if len(grants) != len(entries) or len({grant.name for grant in grants}) != len(grants):
            raise ServiceError("access_store_invalid")
        return [dict(entry) for entry in entries]

    def _write_unlocked(self, entries: list[dict[str, Any]]) -> None:
        payload = json.dumps(
            {"schemaVersion": ACCESS_SCHEMA_VERSION, "tokens": entries},
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        ) + "\n"
        fd, raw_path = tempfile.mkstemp(prefix=".access.", dir=self.root)
        temporary = Path(raw_path)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            dir_fd = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def create(
        self,
        name: str,
        *,
        scopes: list[str],
        instances: Optional[list[str]] = None,
        all_instances: bool = False,
    ) -> tuple[AccessGrant, str]:
        if not _TOKEN_NAME_RE.fullmatch(name or ""):
            raise ServiceError("access_name_invalid")
        normalized_scopes = sorted(set(scopes))
        if (
            not normalized_scopes
            or len(normalized_scopes) != len(scopes)
            or any(scope not in _KNOWN_SCOPES for scope in normalized_scopes)
        ):
            raise ServiceError("access_scopes_invalid")
        selected = list(dict.fromkeys(instances or []))
        if all_instances == bool(selected):
            raise ServiceError("access_instances_invalid")
        if all_instances:
            bindings = {"*": "*"}
        else:
            bindings: dict[str, str] = {}
            for instance in selected:
                validate_instance_name(instance)
                context, _, _ = resolve_instance(
                    instance,
                    project_root=self.project_root,
                    state_home=self.state_home,
                )
                bindings[instance] = context.instance_id
        secret = TOKEN_PREFIX + secrets.token_urlsafe(32)
        digest = hashlib.sha256(secret.encode("ascii")).hexdigest()
        created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        entry = {
            "name": name,
            "digest": digest,
            "scopes": normalized_scopes,
            "instanceBindings": bindings,
            "createdAt": created_at,
        }
        with self._locked():
            entries = self._read_unlocked()
            if any(item.get("name") == name for item in entries):
                raise ServiceError("access_name_conflict")
            entries.append(entry)
            entries.sort(key=lambda item: str(item.get("name")))
            self._write_unlocked(entries)
        return self._entry_to_grant(entry), secret

    def revoke(self, name: str) -> bool:
        if not _TOKEN_NAME_RE.fullmatch(name or ""):
            raise ServiceError("access_name_invalid")
        with self._locked():
            entries = self._read_unlocked()
            kept = [entry for entry in entries if entry.get("name") != name]
            if len(kept) == len(entries):
                return False
            self._write_unlocked(kept)
        return True

    def list_public(self) -> list[dict[str, Any]]:
        with self._locked():
            return [
                self._entry_to_grant(entry).public_dict()
                for entry in self._read_unlocked()
            ]

    def authenticate(self, authorization: Optional[str]) -> Optional[AccessGrant]:
        if not isinstance(authorization, str):
            return None
        scheme, separator, secret = authorization.partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or not secret.startswith(TOKEN_PREFIX)
            or len(secret) > 256
            or any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in secret)
        ):
            return None
        candidate = hashlib.sha256(secret.encode("ascii")).hexdigest()
        with self._locked():
            entries = self._read_unlocked()
        matched: Optional[AccessGrant] = None
        for entry in entries:
            digest = entry.get("digest")
            equal = isinstance(digest, str) and hmac.compare_digest(candidate, digest)
            if equal:
                matched = self._entry_to_grant(entry)
        return matched


def _server_meta() -> dict[str, Any]:
    return {"io.modelcontextprotocol/serverInfo": dict(SERVER_INFO)}


def _complete_result(value: Any, *, is_error: bool = False) -> dict[str, Any]:
    return {
        "resultType": "complete",
        "content": [
            {
                "type": "text",
                "text": json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True),
            }
        ],
        "structuredContent": value,
        "isError": is_error,
        "_meta": _server_meta(),
    }


def _rpc_result(id_: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _rpc_error(
    id_: Any,
    code: int,
    message: str,
    data: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": id_, "error": error}


_PRIVATE_RESULT_KEYS = {
    "accesskey",
    "apikey",
    "archive",
    "authorization",
    "bundle",
    "certificate",
    "command",
    "context",
    "cookie",
    "credential",
    "credentials",
    "endpoint",
    "env",
    "headers",
    "key",
    "password",
    "privatekey",
    "script",
    "secret",
    "source",
    "stderr",
    "stdout",
    "token",
    "uri",
    "url",
}


_GUEST_PATH_PREFIXES = (
    "/system/",
    "/product/",
    "/system_ext/",
    "/vendor/",
    "/odm/",
    "/apex/",
    "/data/app/",
    "/data/user/",
    "/data/user_de/",
    "/data/misc/",
)


def _sanitize_value(value: Any, private_roots: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for raw_name, item in value.items():
            name = str(raw_name)
            normalized = "".join(ch for ch in name.lower() if ch.isalnum())
            if normalized in _PRIVATE_RESULT_KEYS:
                # Binding/storage lifecycle sources are fixed public enums.
                if normalized == "source" and isinstance(item, str) and item in {"fresh", "legacy"}:
                    clean[name] = item
                continue
            if (
                normalized.endswith("password")
                or normalized.endswith("secret")
                or normalized.endswith("token")
            ):
                continue
            if normalized.endswith("path"):
                # Android guest paths (e.g. Google services component codePath)
                # carry no host meaning; keep only exact guest-absolute values.
                if (
                    isinstance(item, str)
                    and item.startswith(_GUEST_PATH_PREFIXES)
                    and not any(root and root in item for root in private_roots)
                ):
                    clean[name] = item
                continue
            clean[name] = _sanitize_value(item, private_roots)
        return clean
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(item, private_roots) for item in value]
    if isinstance(value, str):
        if any(root and root in value for root in private_roots):
            return "[redacted]"
        lowered = value.lower()
        if re.search(
            r"(?:authorization|api[_-]?key|access[_-]?key|token|secret|password|credential)\s*[:=]",
            lowered,
        ):
            return "[redacted]"
        if "://" in value:
            return "[redacted]"
        if Path(value).is_absolute() or re.search(
            r"(?:^|[\s\"'=])/(?:[^/\s]+/)*[^/\s]*", value
        ):
            return "[redacted]"
        return value
    return value


def _tool_result_to_value(result: Any) -> tuple[Any, bool]:
    if not isinstance(result, dict):
        return {"ok": False, "error": "remote_operation_failed"}, True
    content = result.get("content")
    if not isinstance(content, list) or not content:
        return result, result.get("ok") is False
    first = content[0]
    if not isinstance(first, dict) or not isinstance(first.get("text"), str):
        return {"ok": False, "error": "remote_operation_failed"}, True
    try:
        value = json.loads(first["text"])
    except json.JSONDecodeError:
        return {"ok": False, "error": "remote_operation_failed"}, True
    is_error = isinstance(value, dict) and value.get("ok") is False
    return value, is_error


def _remote_tool_catalog() -> dict[str, dict[str, Any]]:
    catalog = {entry["name"]: entry for entry in local_tools()}
    missing = sorted(set(REMOTE_TOOL_POLICIES) - set(catalog))
    if missing:
        raise ServiceError("remote_tool_contract_invalid", ",".join(missing))
    return catalog


def _filtered_schema(
    base: dict[str, Any],
    policy: RemoteToolPolicy,
) -> dict[str, Any]:
    schema = base.get("inputSchema")
    if not isinstance(schema, dict):
        raise ServiceError("remote_tool_contract_invalid")
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        properties = {}
    allowed = policy.schema_properties
    copied: dict[str, Any] = {
        name: dict(definition) if isinstance(definition, dict) else {}
        for name, definition in properties.items()
        if allowed is None or name in allowed
    }
    copied["instance"] = {
        "type": "string",
        "pattern": r"^[a-z][a-z0-9-]{0,31}$",
        "description": "Initialized instance name in this Xenoid project",
        "x-mcp-header": "Instance",
    }
    required = [
        name
        for name in schema.get("required", [])
        if isinstance(name, str) and name in copied
    ]
    if "instance" not in required:
        required.append("instance")
    return {
        "type": "object",
        "properties": copied,
        "required": required,
        "additionalProperties": False,
    }


def _validate_arguments(schema: Mapping[str, Any], arguments: Any) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        raise ServiceError("invalid_tool_arguments")
    properties = schema.get("properties")
    required = schema.get("required")
    if not isinstance(properties, dict) or not isinstance(required, list):
        raise ServiceError("remote_tool_contract_invalid")
    unknown = set(arguments) - set(properties)
    missing = [name for name in required if name not in arguments]
    if unknown or missing:
        raise ServiceError("invalid_tool_arguments")
    for name, value in arguments.items():
        definition = properties[name]
        if not isinstance(definition, dict):
            continue
        expected = definition.get("type")
        valid = (
            expected is None
            or (expected == "string" and isinstance(value, str))
            or (expected == "boolean" and isinstance(value, bool))
            or (
                expected == "integer"
                and isinstance(value, int)
                and not isinstance(value, bool)
            )
            or (expected == "object" and isinstance(value, dict))
            or (expected == "array" and isinstance(value, list))
        )
        if not valid:
            raise ServiceError("invalid_tool_arguments")
        enum = definition.get("enum")
        if isinstance(enum, list) and value not in enum:
            raise ServiceError("invalid_tool_arguments")
        pattern = definition.get("pattern")
        if isinstance(pattern, str) and isinstance(value, str) and not re.fullmatch(pattern, value):
            raise ServiceError("invalid_tool_arguments")
    return dict(arguments)


@contextmanager
def _instance_operation_lock(context: InstanceContext) -> Iterator[None]:
    try:
        with shared_operation_lock(context.state_root, timeout_seconds=0):
            yield
    except InstanceError as exc:
        raise ServiceError(
            "instance_busy", http_status=503, rpc_code=-32000
        ) from exc


class ServiceApplication:
    def __init__(
        self,
        project_root: Path,
        *,
        state_home: Optional[Path] = None,
        tool_caller: Callable[[MCPRuntime, str, dict[str, Any]], Any] = call_tool,
    ):
        self.project_root = Path(project_root).resolve()
        self.state_home = Path(state_home).resolve() if state_home else None
        self.access = AccessStore(self.project_root, state_home=self.state_home)
        self._tool_caller = tool_caller
        self._thread_locks: dict[str, threading.RLock] = {}
        self._thread_locks_guard = threading.Lock()

    def _thread_lock(self, instance_id: str) -> threading.RLock:
        with self._thread_locks_guard:
            return self._thread_locks.setdefault(instance_id, threading.RLock())

    @contextmanager
    def _thread_operation_lock(self, instance_id: str) -> Iterator[None]:
        lock = self._thread_lock(instance_id)
        if not lock.acquire(blocking=False):
            raise ServiceError("instance_busy", http_status=503, rpc_code=-32000)
        try:
            yield
        finally:
            lock.release()

    def _resolve_runtime(self, instance: str) -> MCPRuntime:
        context, config, lease = resolve_instance(
            instance,
            project_root=self.project_root,
            state_home=self.state_home,
        )
        manager = RuntimeManager(context, config, lease)
        daemon = DaemonClient(context, lease, manager.docker_base_cmd())
        # Feature tools use MCPRuntime's shared bootstrap prerequisite; explicit
        # observational tools such as health/status remain non-converging.
        return MCPRuntime(
            context,
            config,
            lease,
            manager,
            daemon,
            operation_lock_timeout_seconds=0,
        )

    def authorized_instances(self, grant: AccessGrant) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for row in list_instances(
            project_root=self.project_root,
            state_home=self.state_home,
        ):
            name = row.get("instanceName")
            if not isinstance(name, str):
                continue
            try:
                context, _, lease = resolve_instance(
                    name,
                    project_root=self.project_root,
                    state_home=self.state_home,
                    migrate_legacy=False,
                )
            except InstanceError:
                continue
            if grant.permits_instance(context):
                rows.append(
                    {
                        **context.public_dict(),
                        "slot": lease.slot,
                        "state": lease.state,
                    }
                )
        return rows

    def remote_tools(self, grant: AccessGrant) -> list[dict[str, Any]]:
        catalog = _remote_tool_catalog()
        result = [
            {
                "name": "xenoid_instances_list",
                "description": "List initialized instances authorized for this caller in the fixed Xenoid project",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
                "annotations": {"readOnlyHint": True},
            }
        ] if grant.permits_scope("read") else []
        for name in sorted(REMOTE_TOOL_POLICIES):
            policy = REMOTE_TOOL_POLICIES[name]
            if not grant.permits_scope(policy.scope):
                continue
            base = catalog[name]
            result.append(
                {
                    "name": name,
                    "description": base.get("description", name)
                    + "; requires an explicit authorized instance",
                    "inputSchema": _filtered_schema(base, policy),
                    "annotations": {
                        "readOnlyHint": not policy.mutating,
                        # Network callers must treat every mutation as
                        # potentially destructive and non-idempotent unless a
                        # future policy proves a narrower contract.
                        "destructiveHint": policy.destructive or policy.mutating,
                        "idempotentHint": not policy.mutating,
                    },
                }
            )
        return result

    def discover(self) -> dict[str, Any]:
        return {
            "resultType": "complete",
            "supportedVersions": [PROTOCOL_VERSION],
            "capabilities": {"tools": {}},
            "instructions": (
                "Call xenoid_instances_list first. Every other tool requires an "
                "explicit instance selected from that authorized list. xenoid_up "
                "is the production convergence operation."
            ),
            "ttlMs": 30000,
            "cacheScope": "private",
            "_meta": _server_meta(),
        }

    def _execute_tool(
        self,
        grant: AccessGrant,
        name: str,
        arguments: Any,
    ) -> dict[str, Any]:
        if name == "xenoid_instances_list":
            if not grant.permits_scope("read"):
                raise ServiceError(
                    "insufficient_scope", http_status=403, rpc_code=-32001
                )
            schema = {
                "properties": {},
                "required": [],
            }
            _validate_arguments(schema, arguments)
            value = {"ok": True, "instances": self.authorized_instances(grant)}
            return _complete_result(value)

        policy = REMOTE_TOOL_POLICIES.get(name)
        if policy is None:
            raise ServiceError("unknown_tool", f"Unknown tool: {name}")
        if not grant.permits_scope(policy.scope):
            raise ServiceError(
                "insufficient_scope", http_status=403, rpc_code=-32001
            )
        base = _remote_tool_catalog()[name]
        schema = _filtered_schema(base, policy)
        validated = _validate_arguments(schema, arguments)
        instance = validated.pop("instance")
        if not grant.permits_instance_name(instance):
            value = {"ok": False, "error": "instance_not_available"}
            return _complete_result(value, is_error=True)
        try:
            initial = self._resolve_runtime(instance)
        except (InstanceError, OSError):
            value = {"ok": False, "error": "instance_not_available"}
            return _complete_result(value, is_error=True)
        if not grant.permits_instance(initial.context):
            value = {"ok": False, "error": "instance_not_available"}
            return _complete_result(value, is_error=True)

        def invoke(runtime: MCPRuntime) -> dict[str, Any]:
            try:
                execution_timeout = (
                    7200.0
                    if name == "xenoid_up"
                    else (900.0 if policy.mutating else 60.0)
                )
                with command_timeout(execution_timeout):
                    raw = self._tool_caller(runtime, name, validated)
                value, is_error = _tool_result_to_value(raw)
            except subprocess.TimeoutExpired:
                value, is_error = {
                    "ok": False,
                    "error": "remote_operation_timeout",
                }, True
            except InstanceError as exc:
                value, is_error = {"ok": False, "error": exc.code}, True
            except Exception:
                value, is_error = {
                    "ok": False,
                    "error": "remote_operation_failed",
                }, True
            private_roots = (
                str(runtime.context.project_root),
                str(runtime.context.state_root),
                str(Path.home()),
            )
            sanitized = _sanitize_value(value, private_roots)
            return _complete_result(sanitized, is_error=is_error)

        if not policy.mutating:
            return invoke(initial)

        with self._thread_operation_lock(initial.context.instance_id):
            with _instance_operation_lock(initial.context):
                try:
                    current = self._resolve_runtime(instance)
                except (InstanceError, OSError):
                    value = {"ok": False, "error": "instance_not_available"}
                    return _complete_result(value, is_error=True)
                if (
                    current.context.instance_id != initial.context.instance_id
                    or not grant.permits_instance(current.context)
                ):
                    value = {"ok": False, "error": "instance_not_available"}
                    return _complete_result(value, is_error=True)
                current = replace(current, operation_lock_held=True)
                current.manager.operation_lock_held = True
                if name != "xenoid_up":
                    try:
                        regeneration = RegenerationJournal(
                            current.context
                        ).load()
                    except IdentityError as exc:
                        if (
                            exc.code == "device_regeneration_legacy_pending"
                            and _legacy_proxy_recovery_allowed(
                                current,
                                name,
                                validated,
                            )
                        ):
                            regeneration = None
                        else:
                            value = {"ok": False, "error": exc.code}
                            return _complete_result(value, is_error=True)
                    if regeneration is not None:
                        value = {
                            "ok": False,
                            "error": "device_regeneration_pending",
                            "phase": regeneration["phase"],
                        }
                        return _complete_result(value, is_error=True)
                if not bool(validated.get("dryRun", False)):
                    current.manager.migrate_legacy_token_state()
                return invoke(current)

    def dispatch(
        self,
        grant: AccessGrant,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        if request.get("jsonrpc") != "2.0" or "id" not in request:
            raise ServiceError("invalid_request", rpc_code=-32600)
        id_ = request.get("id")
        if (
            isinstance(id_, bool)
            or id_ is None
            or not isinstance(id_, (str, int, float))
        ):
            raise ServiceError("invalid_request", rpc_code=-32600)
        method = request.get("method")
        params = request.get("params", {})
        if not isinstance(method, str) or not isinstance(params, dict):
            raise ServiceError("invalid_request", rpc_code=-32600)
        if method == "server/discover":
            return _rpc_result(id_, self.discover())
        if method == "tools/list":
            return _rpc_result(
                id_,
                {
                    "resultType": "complete",
                    "tools": self.remote_tools(grant),
                    "ttlMs": 30000,
                    "cacheScope": "private",
                    "_meta": _server_meta(),
                },
            )
        if method == "tools/call":
            name = params.get("name")
            if not isinstance(name, str) or not name:
                raise ServiceError("invalid_tool_name")
            return _rpc_result(
                id_,
                self._execute_tool(grant, name, params.get("arguments", {})),
            )
        raise ServiceError(
            "method_not_found",
            f"Method not found: {method}",
            http_status=404,
            rpc_code=-32601,
        )


class RateLimiter:
    def __init__(
        self,
        requests_per_minute: int,
        *,
        max_principals: int = 4096,
    ):
        self.limit = requests_per_minute
        self.max_principals = max(1, max_principals)
        self._events: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, principal: str) -> bool:
        now = time.monotonic()
        floor = now - 60.0
        with self._lock:
            events = self._events.pop(principal, None)
            if events is None:
                while len(self._events) >= self.max_principals:
                    self._events.popitem(last=False)
                events = deque()
            while events and events[0] <= floor:
                events.popleft()
            self._events[principal] = events
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True


@dataclass(frozen=True)
class HTTPSettings:
    allowed_origins: frozenset[str]
    allowed_hosts: frozenset[str]
    max_request_bytes: int = MAX_REQUEST_BYTES
    request_timeout_seconds: int = 30
    verbose: bool = False


class XenoidHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(
        self,
        address: tuple[str, int],
        application: ServiceApplication,
        settings: HTTPSettings,
        *,
        max_concurrency: int,
        requests_per_minute: int,
    ):
        self.application = application
        self.settings = settings
        self.capacity = threading.BoundedSemaphore(max_concurrency)
        self.rate_limiter = RateLimiter(requests_per_minute)
        self.auth_limiter = RateLimiter(requests_per_minute)
        self.inbound_limiter = RateLimiter(
            min(100000, requests_per_minute * max_concurrency),
            max_principals=1,
        )
        connection_limit = min(
            100000,
            requests_per_minute * max(2, max_concurrency),
        )
        self.connection_limiter = RateLimiter(
            connection_limit,
            max_principals=1,
        )
        self.connection_ip_limiter = RateLimiter(requests_per_minute)
        self.connection_loopback_limiter = RateLimiter(connection_limit)
        self.max_connections_per_principal = max(1, max_concurrency // 2)
        self.max_loopback_connections = max_concurrency
        self._active_connections: dict[str, int] = {}
        self._request_principals: dict[int, str] = {}
        self._active_connections_lock = threading.Lock()
        self.tls_context: Optional[ssl.SSLContext] = None
        self.address_family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        super().__init__(address, XenoidRequestHandler)

    def _prepare_accepted_socket(self, request: Any) -> Any:
        context = self.tls_context
        if context is None:
            return request
        try:
            return context.wrap_socket(
                request,
                server_side=True,
                do_handshake_on_connect=False,
            )
        except Exception:
            request.close()
            raise

    def get_request(self) -> tuple[Any, Any]:
        request, client_address = self.socket.accept()
        return self._prepare_accepted_socket(request), client_address

    @staticmethod
    def _connection_principal(client_address: Any) -> str:
        raw = str(client_address[0])
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            return raw
        if isinstance(address, ipaddress.IPv6Address):
            return str(ipaddress.ip_network(f"{address}/64", strict=False))
        return str(address)

    def _reserve_connection(self, client_address: Any) -> Optional[str]:
        principal = self._connection_principal(client_address)
        try:
            loopback = ipaddress.ip_address(str(client_address[0])).is_loopback
        except ValueError:
            loopback = False
        active_limit = (
            self.max_loopback_connections
            if loopback
            else self.max_connections_per_principal
        )
        with self._active_connections_lock:
            active = self._active_connections.get(principal, 0)
            if active >= active_limit:
                return None
            self._active_connections[principal] = active + 1
        # Local excess must not consume the global fairness budget. Reserve
        # per-principal concurrency first, then its rate share, then global.
        principal_limiter = (
            self.connection_loopback_limiter
            if loopback
            else self.connection_ip_limiter
        )
        if not principal_limiter.allow(principal):
            self._release_connection(principal)
            return None
        if not self.connection_limiter.allow("global"):
            self._release_connection(principal)
            return None
        return principal

    def _release_connection(self, principal: str) -> None:
        with self._active_connections_lock:
            active = self._active_connections.get(principal, 0)
            if active <= 1:
                self._active_connections.pop(principal, None)
            else:
                self._active_connections[principal] = active - 1

    def process_request(self, request: Any, client_address: Any) -> None:
        principal = self._reserve_connection(client_address)
        if principal is None:
            self.shutdown_request(request)
            return
        if not self.capacity.acquire(blocking=False):
            self._release_connection(principal)
            self.shutdown_request(request)
            return
        with self._active_connections_lock:
            self._request_principals[id(request)] = principal
        try:
            super().process_request(request, client_address)
        except Exception:
            self.capacity.release()
            with self._active_connections_lock:
                self._request_principals.pop(id(request), None)
            self._release_connection(principal)
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.capacity.release()
            with self._active_connections_lock:
                principal = self._request_principals.pop(id(request), None)
            if isinstance(principal, str):
                self._release_connection(principal)


def _normalize_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ServiceError("origin_invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ServiceError("origin_invalid")
    host = parsed.hostname
    if not host:
        raise ServiceError("origin_invalid")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ServiceError("origin_invalid") from exc
    port = f":{parsed_port}" if parsed_port is not None else ""
    rendered_host = f"[{host.lower()}]" if ":" in host else host.lower()
    return f"{parsed.scheme.lower()}://{rendered_host}{port}"


def _normalize_allowed_host(value: str) -> str:
    candidate = value.strip().lower()
    if not candidate or not _HOST_RE.fullmatch(candidate):
        raise ServiceError("host_invalid")
    port = ""
    if candidate.startswith("["):
        closing = candidate.find("]")
        port = candidate[closing + 1 :]
    elif candidate.count(":") == 1:
        _, port = candidate.rsplit(":", 1)
        port = f":{port}"
    if port:
        try:
            parsed_port = int(port[1:])
        except ValueError as exc:
            raise ServiceError("host_invalid") from exc
        if not 1 <= parsed_port <= 65535:
            raise ServiceError("host_invalid")
    return candidate


def _decode_header_value(value: str) -> str:
    match = _BASE64_SENTINEL_RE.fullmatch(value)
    if match is None:
        if (
            value != value.strip()
            or any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in value)
        ):
            raise ServiceError("header_mismatch", rpc_code=-32020)
        return value
    try:
        decoded = base64.b64decode(match.group(1), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ServiceError("header_mismatch", rpc_code=-32020) from exc
    return decoded


def _request_meta(request: Mapping[str, Any]) -> Mapping[str, Any]:
    params = request.get("params")
    if not isinstance(params, dict):
        raise ServiceError("invalid_request", rpc_code=-32600)
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        raise ServiceError("request_metadata_missing", rpc_code=-32600)
    version = meta.get("io.modelcontextprotocol/protocolVersion")
    capabilities = meta.get("io.modelcontextprotocol/clientCapabilities")
    client_info = meta.get("io.modelcontextprotocol/clientInfo")
    if version != PROTOCOL_VERSION or not isinstance(capabilities, dict):
        if isinstance(version, str) and version != PROTOCOL_VERSION:
            raise ServiceError(
                "unsupported_protocol_version",
                http_status=400,
                rpc_code=-32022,
                data={"supported": [PROTOCOL_VERSION], "requested": version},
            )
        raise ServiceError("request_metadata_invalid", rpc_code=-32600)
    if (
        not isinstance(client_info, dict)
        or not isinstance(client_info.get("name"), str)
        or not client_info.get("name")
        or not isinstance(client_info.get("version"), str)
        or not client_info.get("version")
    ):
        raise ServiceError("request_metadata_invalid", rpc_code=-32600)
    return meta


def _validate_protocol_headers(
    headers: Mapping[str, str],
    request: Mapping[str, Any],
) -> None:
    params = request.get("params")
    meta = params.get("_meta") if isinstance(params, dict) else None
    body_version = (
        meta.get("io.modelcontextprotocol/protocolVersion")
        if isinstance(meta, dict)
        else None
    )
    version = headers.get("MCP-Protocol-Version")
    if (
        isinstance(version, str)
        and isinstance(body_version, str)
        and version != body_version
    ):
        raise ServiceError("header_mismatch", rpc_code=-32020)
    _request_meta(request)
    if version != PROTOCOL_VERSION:
        if isinstance(version, str) and version != PROTOCOL_VERSION:
            raise ServiceError(
                "unsupported_protocol_version",
                http_status=400,
                rpc_code=-32022,
                data={"supported": [PROTOCOL_VERSION], "requested": version},
            )
        raise ServiceError("header_mismatch", rpc_code=-32020)
    method = request.get("method")
    if not isinstance(method, str) or headers.get("Mcp-Method") != method:
        raise ServiceError("header_mismatch", rpc_code=-32020)
    if not isinstance(params, dict):
        raise ServiceError("invalid_request", rpc_code=-32600)
    raw_name = headers.get("Mcp-Name")
    if method == "tools/call":
        body_name = params.get("name")
        if not isinstance(body_name, str) or raw_name is None:
            raise ServiceError("header_mismatch", rpc_code=-32020)
        if _decode_header_value(raw_name) != body_name:
            raise ServiceError("header_mismatch", rpc_code=-32020)
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            raise ServiceError("invalid_tool_arguments")
        instance_header = headers.get("Mcp-Param-Instance")
        if body_name == "xenoid_instances_list":
            if instance_header is not None:
                raise ServiceError("header_mismatch", rpc_code=-32020)
        elif body_name in REMOTE_TOOL_POLICIES:
            instance = arguments.get("instance")
            if not isinstance(instance, str) or instance_header is None:
                raise ServiceError("header_mismatch", rpc_code=-32020)
            if _decode_header_value(instance_header) != instance:
                raise ServiceError("header_mismatch", rpc_code=-32020)
    elif raw_name is not None:
        raise ServiceError("header_mismatch", rpc_code=-32020)


class XenoidRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "XenoidService/0.1"
    sys_version = ""

    @property
    def xserver(self) -> XenoidHTTPServer:
        return self.server  # type: ignore[return-value]

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(
            min(5, self.xserver.settings.request_timeout_seconds)
        )

    def handle_one_request(self) -> None:
        timer = threading.Timer(
            min(5, self.xserver.settings.request_timeout_seconds),
            self._expire_request_read,
        )
        timer.daemon = True
        self._request_read_timer = timer
        timer.start()
        try:
            super().handle_one_request()
        finally:
            timer.cancel()

    def _expire_request_read(self) -> None:
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _cancel_request_read_deadline(self) -> None:
        timer = getattr(self, "_request_read_timer", None)
        if timer is not None:
            timer.cancel()
        self.connection.settimeout(self.xserver.settings.request_timeout_seconds)

    def log_message(self, format_: str, *args: Any) -> None:
        if self.xserver.settings.verbose:
            path = urlsplit(self.path).path
            sys.stderr.write(f"xenoid-service {self.command} {path}\n")

    def _header_values(self, name: str) -> list[str]:
        return list(self.headers.get_all(name, []))

    def _single_header(self, name: str, *, required: bool = False) -> Optional[str]:
        values = self._header_values(name)
        if len(values) > 1 or (required and len(values) != 1):
            raise ServiceError(
                "request_headers_invalid", http_status=400, rpc_code=-32600
            )
        return values[0] if values else None

    def _origin_headers(self) -> dict[str, str]:
        origin = self.headers.get("Origin")
        if origin is None:
            return {}
        try:
            normalized = _normalize_origin(origin)
        except ServiceError:
            return {}
        if normalized not in self.xserver.settings.allowed_origins:
            return {}
        return {
            "Access-Control-Allow-Origin": normalized,
            "Vary": "Origin",
        }

    def _send_json(
        self,
        status_code: int,
        body: Any,
        *,
        headers: Optional[Mapping[str, str]] = None,
    ) -> None:
        payload = json.dumps(
            body, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        self.close_connection = True
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        for name, value in self._origin_headers().items():
            self.send_header(name, value)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _send_empty(
        self,
        status_code: int,
        *,
        headers: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.close_connection = True
        self.send_response(status_code)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        for name, value in self._origin_headers().items():
            self.send_header(name, value)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()

    def _validate_host_and_origin(self) -> None:
        try:
            host = self._single_header("Host", required=True)
        except ServiceError as exc:
            raise ServiceError(
                "host_invalid", http_status=400, rpc_code=-32600
            ) from exc
        assert host is not None
        try:
            normalized_host = _normalize_allowed_host(host)
        except ServiceError as exc:
            raise ServiceError(
                "host_invalid", http_status=400, rpc_code=-32600
            ) from exc
        host_only = normalized_host
        if normalized_host.startswith("["):
            closing = normalized_host.find("]")
            host_only = normalized_host[: closing + 1] if closing >= 0 else normalized_host
        elif normalized_host.count(":") == 1:
            host_only = normalized_host.rsplit(":", 1)[0]
        if (
            normalized_host not in self.xserver.settings.allowed_hosts
            and host_only not in self.xserver.settings.allowed_hosts
        ):
            raise ServiceError("host_invalid", http_status=400, rpc_code=-32600)
        origin = self._single_header("Origin")
        if origin is not None:
            try:
                normalized = _normalize_origin(origin)
            except ServiceError as exc:
                raise ServiceError(
                    "origin_forbidden", http_status=403, rpc_code=-32001
                ) from exc
            if normalized not in self.xserver.settings.allowed_origins:
                raise ServiceError(
                    "origin_forbidden", http_status=403, rpc_code=-32001
                )

    def _admit_request(self) -> None:
        if not self.xserver.inbound_limiter.allow("global"):
            raise ServiceError(
                "rate_limit_exceeded", http_status=429, rpc_code=-32001
            )
        if not self.xserver.auth_limiter.allow(f"ip:{self.client_address[0]}"):
            raise ServiceError(
                "rate_limit_exceeded", http_status=429, rpc_code=-32001
            )

    def _authenticate(self) -> AccessGrant:
        try:
            authorization = self._single_header("Authorization", required=True)
        except ServiceError:
            authorization = None
        grant = self.xserver.application.access.authenticate(authorization)
        if grant is None:
            raise ServiceError(
                "unauthorized", http_status=401, rpc_code=-32001
            )
        if not self.xserver.rate_limiter.allow(grant.name):
            raise ServiceError(
                "rate_limit_exceeded", http_status=429, rpc_code=-32001
            )
        return grant

    def _handle_error(self, exc: ServiceError, id_: Any = None) -> None:
        headers: dict[str, str] = {}
        if exc.http_status == 401:
            headers["WWW-Authenticate"] = 'Bearer realm="xenoid-service"'
        if exc.http_status in {429, 503}:
            headers["Retry-After"] = "1"
        self._send_json(
            exc.http_status,
            _rpc_error(id_, exc.rpc_code, exc.code, exc.data),
            headers=headers,
        )

    def do_OPTIONS(self) -> None:
        self._cancel_request_read_deadline()
        try:
            self._admit_request()
            self._validate_host_and_origin()
        except ServiceError as exc:
            self._handle_error(exc)
            return
        if urlsplit(self.path).path != "/mcp":
            self._send_empty(404)
            return
        self._send_empty(
            204,
            headers={
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": (
                    "Authorization, Content-Type, Accept, MCP-Protocol-Version, "
                    "Mcp-Method, Mcp-Name, Mcp-Param-Instance"
                ),
                "Access-Control-Max-Age": "600",
            },
        )

    def do_GET(self) -> None:
        self._cancel_request_read_deadline()
        try:
            self._admit_request()
            self._validate_host_and_origin()
            path = urlsplit(self.path)
            if path.query:
                raise ServiceError("query_not_allowed", http_status=400)
            if path.path == "/healthz":
                self._send_json(200, {"ok": True, "service": "xenoid"})
                return
            if path.path == "/mcp":
                self._send_empty(405, headers={"Allow": "POST, OPTIONS"})
                return
            if path.path != "/v1/instances":
                self._send_empty(404)
                return
            grant = self._authenticate()
            if not grant.permits_scope("read"):
                raise ServiceError(
                    "insufficient_scope", http_status=403, rpc_code=-32001
                )
            value = {
                "ok": True,
                "instances": self.xserver.application.authorized_instances(grant),
            }
            self._send_json(200, value)
        except ServiceError as exc:
            self._handle_error(exc)
        except Exception:
            self._handle_error(
                ServiceError(
                    "service_request_failed", http_status=500, rpc_code=-32603
                )
            )

    def do_POST(self) -> None:
        request_id: Any = None
        try:
            self._admit_request()
            self._validate_host_and_origin()
            path = urlsplit(self.path)
            if path.path != "/mcp" or path.query:
                raise ServiceError("endpoint_not_found", http_status=404, rpc_code=-32601)
            grant = self._authenticate()
            for name in (
                "MCP-Protocol-Version",
                "Mcp-Method",
                "Mcp-Name",
                "Mcp-Param-Instance",
                "Content-Length",
                "Content-Type",
            ):
                if len(self._header_values(name)) > 1:
                    raise ServiceError(
                        "request_headers_invalid", http_status=400, rpc_code=-32600
                    )
            if self._header_values("Transfer-Encoding"):
                raise ServiceError("request_framing_invalid", http_status=400, rpc_code=-32600)
            try:
                length = int(self._single_header("Content-Length", required=True) or "")
            except ValueError as exc:
                raise ServiceError("request_length_invalid", rpc_code=-32600) from exc
            if length <= 0 or length > self.xserver.settings.max_request_bytes:
                raise ServiceError(
                    "request_too_large" if length > 0 else "request_length_invalid",
                    http_status=413 if length > 0 else 400,
                    rpc_code=-32600,
                )
            content_type = (
                (self._single_header("Content-Type", required=True) or "")
                .split(";", 1)[0]
                .strip()
                .lower()
            )
            if content_type != "application/json":
                raise ServiceError("content_type_invalid", http_status=415, rpc_code=-32600)
            accept = {
                item.split(";", 1)[0].strip().lower()
                for item in ",".join(self._header_values("Accept")).split(",")
            }
            if not {"application/json", "text/event-stream"}.issubset(accept):
                raise ServiceError("accept_invalid", http_status=406, rpc_code=-32600)
            try:
                raw_request = self.rfile.read(length)
                self._cancel_request_read_deadline()
                if len(raw_request) != length:
                    raise ServiceError(
                        "request_body_incomplete",
                        http_status=400,
                        rpc_code=-32600,
                    )
                request = json.loads(raw_request.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ServiceError("parse_error", rpc_code=-32700) from exc
            if not isinstance(request, dict):
                raise ServiceError("invalid_request", rpc_code=-32600)
            request_id = request.get("id")
            _validate_protocol_headers(self.headers, request)
            if "id" not in request:
                if (
                    request.get("jsonrpc") != "2.0"
                    or not isinstance(request.get("method"), str)
                    or not request.get("method", "").startswith("notifications/")
                ):
                    raise ServiceError("invalid_request", rpc_code=-32600)
                self._send_empty(202)
                return
            response = self.xserver.application.dispatch(grant, request)
            self._send_json(200, response)
        except ServiceError as exc:
            self.close_connection = True
            self._handle_error(exc, request_id)
        except (OSError, socket.timeout):
            self.close_connection = True
        except Exception:
            self.close_connection = True
            self._handle_error(
                ServiceError(
                    "service_request_failed", http_status=500, rpc_code=-32603
                ),
                request_id,
            )

    def _unsupported_method(self) -> None:
        self._cancel_request_read_deadline()
        try:
            self._admit_request()
            self._validate_host_and_origin()
            self._send_empty(405, headers={"Allow": "GET, POST, OPTIONS"})
        except ServiceError as exc:
            self._handle_error(exc)

    do_CONNECT = _unsupported_method
    do_DELETE = _unsupported_method
    do_HEAD = _unsupported_method
    do_PATCH = _unsupported_method
    do_PUT = _unsupported_method
    do_TRACE = _unsupported_method

def create_server(
    application: ServiceApplication,
    *,
    bind: str,
    port: int,
    allowed_origins: list[str],
    allowed_hosts: list[str],
    max_request_bytes: int = MAX_REQUEST_BYTES,
    request_timeout_seconds: int = 30,
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
    requests_per_minute: int = DEFAULT_REQUESTS_PER_MINUTE,
    verbose: bool = False,
) -> XenoidHTTPServer:
    if not 1 <= port <= 65535 and port != 0:
        raise ServiceError("listen_port_invalid")
    if not 1024 <= max_request_bytes <= 16 * 1024 * 1024:
        raise ServiceError("request_limit_invalid")
    if not 1 <= request_timeout_seconds <= 300:
        raise ServiceError("request_timeout_invalid")
    if not 1 <= max_concurrency <= 128:
        raise ServiceError("concurrency_limit_invalid")
    if not 1 <= requests_per_minute <= 10000:
        raise ServiceError("rate_limit_invalid")
    origins = frozenset(_normalize_origin(value) for value in allowed_origins)
    hosts = frozenset(_normalize_allowed_host(value) for value in allowed_hosts)
    if not hosts:
        raise ServiceError("allowed_host_required")
    settings = HTTPSettings(
        allowed_origins=origins,
        allowed_hosts=hosts,
        max_request_bytes=max_request_bytes,
        request_timeout_seconds=request_timeout_seconds,
        verbose=verbose,
    )
    return XenoidHTTPServer(
        (bind, port),
        application,
        settings,
        max_concurrency=max_concurrency,
        requests_per_minute=requests_per_minute,
    )


def _is_loopback_bind(bind: str) -> bool:
    return bind in {"127.0.0.1", "::1", "localhost"}


def _private_tls_key(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ServiceError("tls_key_unavailable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise ServiceError("tls_key_permissions_invalid")


def _serve(args: argparse.Namespace, project_root: Path) -> int:
    tls_enabled = bool(args.tls_cert or args.tls_key)
    insecure_remote = bool(
        not _is_loopback_bind(args.bind)
        and not tls_enabled
        and args.allow_insecure_http
    )
    if tls_enabled and not (args.tls_cert and args.tls_key):
        raise ServiceError("tls_configuration_invalid")
    if not _is_loopback_bind(args.bind) and not tls_enabled and not insecure_remote:
        raise ServiceError("tls_required_for_remote_bind")
    if not args.allow_host:
        if not _is_loopback_bind(args.bind):
            raise ServiceError("allowed_host_required")
        args.allow_host = ["127.0.0.1", "localhost", "[::1]"]
    application = ServiceApplication(project_root)
    if not application.access.list_public():
        raise ServiceError("access_token_required")
    server = create_server(
        application,
        bind=args.bind,
        port=args.port,
        allowed_origins=args.allow_origin or [],
        allowed_hosts=args.allow_host,
        max_request_bytes=args.max_request_bytes,
        request_timeout_seconds=args.request_timeout,
        max_concurrency=args.max_concurrency,
        requests_per_minute=args.requests_per_minute,
        verbose=args.verbose,
    )
    scheme = "https" if tls_enabled else "http"
    if tls_enabled:
        key_path = Path(args.tls_key).expanduser().resolve()
        cert_path = Path(args.tls_cert).expanduser().resolve()
        _private_tls_key(key_path)
        if not cert_path.is_file():
            raise ServiceError("tls_certificate_unavailable")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        server.tls_context = context
    address = server.server_address
    startup = {
        "ok": True,
        "service": "xenoid",
        "listen": f"{scheme}://{address[0]}:{address[1]}/mcp",
        "protocolVersion": PROTOCOL_VERSION,
        "transportSecurity": (
            "tls" if tls_enabled else "insecure-http" if insecure_remote else "loopback"
        ),
    }
    if insecure_remote:
        startup["warning"] = (
            "Bearer tokens and MCP traffic are unencrypted; use only on an "
            "explicitly trusted temporary network"
        )
    sys.stderr.write(json.dumps(startup, sort_keys=True) + "\n")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xenoid-service",
        description="Authenticated multi-instance Xenoid MCP service",
    )
    parser.add_argument(
        "--project",
        help="fixed Xenoid project root (default: XENOID_PROJECT or installation root)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    token = commands.add_parser("token", help="manage project-scoped access tokens")
    token_commands = token.add_subparsers(dest="token_command", required=True)
    create = token_commands.add_parser("create", help="create and print a token once")
    create.add_argument("--name", required=True)
    target = create.add_mutually_exclusive_group(required=True)
    target.add_argument("--all-instances", action="store_true")
    target.add_argument("--instance", action="append", dest="instances")
    create.add_argument(
        "--scope",
        action="append",
        choices=sorted(_KNOWN_SCOPES),
        default=None,
        help="repeat to grant more scopes (default: read)",
    )
    token_commands.add_parser("list", help="list token metadata without secrets")
    revoke = token_commands.add_parser("revoke", help="revoke a token by name")
    revoke.add_argument("name")

    serve = commands.add_parser("serve", help="run the Streamable HTTP service")
    serve.add_argument("--bind", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--allow-host", action="append", default=None)
    serve.add_argument("--allow-origin", action="append", default=None)
    serve.add_argument("--tls-cert")
    serve.add_argument("--tls-key")
    serve.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help=(
            "allow explicit non-loopback cleartext HTTP for temporary trusted-"
            "network testing; bearer tokens and requests are not encrypted"
        ),
    )
    serve.add_argument("--max-request-bytes", type=int, default=MAX_REQUEST_BYTES)
    serve.add_argument("--request-timeout", type=int, default=30)
    serve.add_argument("--max-concurrency", type=int, default=DEFAULT_MAX_CONCURRENCY)
    serve.add_argument(
        "--requests-per-minute",
        type=int,
        default=DEFAULT_REQUESTS_PER_MINUTE,
    )
    serve.add_argument("--verbose", action="store_true")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        project_root = resolve_project_root(args.project)
        store = AccessStore(project_root)
        if args.command == "token":
            if args.token_command == "create":
                grant, secret = store.create(
                    args.name,
                    scopes=args.scope or ["read"],
                    instances=args.instances,
                    all_instances=bool(args.all_instances),
                )
                print(
                    json.dumps(
                        {
                            "ok": True,
                            "access": grant.public_dict(),
                            "token": secret,
                            "notice": "This token is shown once; store it securely.",
                        },
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    )
                )
                return 0
            if args.token_command == "list":
                print(
                    json.dumps(
                        {"ok": True, "access": store.list_public()},
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    )
                )
                return 0
            revoked = store.revoke(args.name)
            print(json.dumps({"ok": revoked, "name": args.name}, sort_keys=True))
            return 0 if revoked else 1
        return _serve(args, project_root)
    except (ServiceError, InstanceError) as exc:
        code = exc.code if isinstance(exc, (ServiceError, InstanceError)) else "service_failed"
        print(json.dumps({"ok": False, "error": code}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
