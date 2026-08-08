#!/usr/bin/python3
"""Per-instance Xenoid transparent proxy reconciliation agent."""
from __future__ import annotations

import array
import base64
import ctypes
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
import pwd
import re
import resource
import secrets
import selectors
import signal
import stat
import socket
import struct
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Mapping, Optional

try:
    from xenoid.proxy_protocol import ProxyProtocolError, derive_key, open_response, seal_request
except ModuleNotFoundError:
    module_root = Path("/usr/lib/xenoid-proxy/python")
    if not module_root.is_dir():
        module_root = Path(__file__).resolve().parents[1] / "src"
    if not module_root.is_dir():
        raise
    sys.path.insert(0, str(module_root))
    from xenoid.proxy_protocol import ProxyProtocolError, derive_key, open_response, seal_request

SCHEMA = "dev.xenoid.proxy-engine/v1"
IPC_SCHEMA = "dev.xenoid.proxy-engine.ipc/v1"
STATE_ROOT = Path("/var/lib/xenoid/proxy/instances")
RUNTIME_ROOT = Path("/run/xenoid/proxy")
ENGINE_BINARY = Path("/usr/lib/xenoid/proxy/mihomo-v1.19.29")
MAX_MANIFEST_BYTES = 64 * 1024
MAX_CHANNEL_BYTES = 10 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
MAX_WORKER_BYTES = 10 * 1024 * 1024
POLL_SECONDS = 3.0
REFRESH_SECONDS = 300.0
ROOT_TIMEOUT = 30.0
WORKER_TIMEOUT = 45.0
ANDROID_PROBE_TIMEOUT_MS = 45_000
CACHE_TTL_SECONDS = 24 * 60 * 60
CACHE_MAX_ENTRIES = 8
CACHE_MAX_BYTES = 8 * 1024 * 1024
CAPABILITY_KEYS = frozenset({
    "v4DnsProxy",
    "v4TcpProxy",
    "v4UdpProxy",
    "v6TcpProxy",
    "v6DnsProxy",
    "v6UdpProxy",
})
_SAFE_EPOCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_TAG = re.compile(r"^[0-9a-f]{12}$")
_USER = re.compile(r"^xp[afcm][0-9a-f]{12}$")
_STOP = False
_ENGINE: "EngineIPC | None" = None
_ACTIVE_WORKERS: set[str] = set()
_HEALTH_FD = -1
_CACHE_DIR_FD = -1


class AgentFailure(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class ChannelAuthenticationFailure(AgentFailure):
    pass

def _strict_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if not isinstance(key, str) or key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _loads(raw: bytes, code: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_strict_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise AgentFailure(code) from exc




def _signal_stop(_signum: int, _frame: Any) -> None:
    global _STOP
    _STOP = True


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AgentFailure("agent_schema_invalid") from exc


def _require_keys(value: Mapping[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise AgentFailure("agent_schema_invalid")


def _safe_absolute(path: str) -> Path:
    if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
        raise AgentFailure("manifest_invalid")
    candidate = Path(path)
    if any(part in {"", ".", ".."} for part in candidate.parts[1:]):
        raise AgentFailure("manifest_invalid")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise AgentFailure("manifest_invalid") from exc
    if resolved != candidate:
        raise AgentFailure("manifest_invalid")
    return candidate


def _open_private(path: Path, expected_mode: int, maximum: int) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AgentFailure("manifest_invalid") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != expected_mode
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > maximum
        ):
            raise AgentFailure("manifest_invalid")
        return descriptor, info
    except BaseException:
        os.close(descriptor)
        raise


def _read_exact_file(path: Path, expected_mode: int, maximum: int) -> bytes:
    descriptor, info = _open_private(path, expected_mode, maximum)
    try:
        data = bytearray()
        while len(data) < info.st_size:
            chunk = os.read(descriptor, info.st_size - len(data))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != info.st_size:
            raise AgentFailure("manifest_invalid")
        return bytes(data)
    finally:
        os.close(descriptor)


def _valid_uuid4(value: Any) -> str:
    if not isinstance(value, str):
        raise AgentFailure("manifest_invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise AgentFailure("manifest_invalid") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise AgentFailure("manifest_invalid")
    return value


def _valid_ip(value: Any, version: int, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if not isinstance(value, str):
        raise AgentFailure("manifest_invalid")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise AgentFailure("manifest_invalid") from exc
    if parsed.version != version or str(parsed) != value:
        raise AgentFailure("manifest_invalid")
    return value


def _validate_mac(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", value):
        raise AgentFailure("manifest_invalid")
    first = int(value[:2], 16)
    if first & 1 or not first & 2:
        raise AgentFailure("manifest_invalid")
    return value


def _validate_binary(path: Path, digest_value: str) -> None:
    try:
        resolved = path.resolve(strict=True)
        info = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise AgentFailure("engine_binary_invalid") from exc
    if (
        resolved != path
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o555
        or info.st_nlink != 1
    ):
        raise AgentFailure("engine_binary_invalid")
    digest = hashlib.sha256()
    try:
        with path.open("rb", buffering=0) as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise AgentFailure("engine_binary_invalid") from exc
    if digest.hexdigest() != digest_value:
        raise AgentFailure("engine_binary_invalid")


def _load_manifest(raw_path: str) -> tuple[dict[str, Any], Path]:
    path = _safe_absolute(raw_path)
    manifest = _loads(_read_exact_file(path, 0o600, MAX_MANIFEST_BYTES), "manifest_invalid")
    if not isinstance(manifest, dict):
        raise AgentFailure("manifest_invalid")
    _require_keys(manifest, {
        "schema", "manifestDigest", "instanceId", "resourceTag", "runtimeEpoch", "generation",
        "containerId", "networkId", "bridgeName", "proxyNamespace", "android", "users",
        "veth", "routing", "engine", "paths", "daemon",
    })
    if manifest["schema"] != SCHEMA:
        raise AgentFailure("manifest_invalid")
    instance_id = _valid_uuid4(manifest["instanceId"])
    tag = manifest["resourceTag"]
    expected_tag = hashlib.sha256(b"xenoid-instance/v1\0" + instance_id.encode("ascii")).hexdigest()[:12]
    if not isinstance(tag, str) or not _TAG.fullmatch(tag) or tag != expected_tag:
        raise AgentFailure("manifest_invalid")
    digest = manifest["manifestDigest"]
    if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
        raise AgentFailure("manifest_invalid")
    unsigned = dict(manifest)
    del unsigned["manifestDigest"]
    if hashlib.sha256(_canonical(unsigned)).hexdigest() != digest:
        raise AgentFailure("manifest_invalid")
    epoch = manifest["runtimeEpoch"]
    generation = manifest["generation"]
    if not isinstance(epoch, str) or not _SAFE_EPOCH.fullmatch(epoch):
        raise AgentFailure("manifest_invalid")
    if not isinstance(generation, int) or isinstance(generation, bool) or not 0 <= generation < 2**63:
        raise AgentFailure("manifest_invalid")
    if any(not isinstance(manifest[name], str) or not _HEX_64.fullmatch(manifest[name]) for name in ("containerId", "networkId")):
        raise AgentFailure("manifest_invalid")
    if manifest["bridgeName"] != "xbr" + tag or manifest["proxyNamespace"] != "xenoid-p-" + tag:
        raise AgentFailure("manifest_invalid")

    android = manifest["android"]
    if not isinstance(android, dict):
        raise AgentFailure("manifest_invalid")
    _require_keys(android, {"ipv4", "ipv6", "mac"})
    _valid_ip(android["ipv4"], 4)
    _valid_ip(android["ipv6"], 6, allow_empty=True)
    _validate_mac(android["mac"])

    users = manifest["users"]
    if not isinstance(users, dict):
        raise AgentFailure("manifest_invalid")
    _require_keys(users, {"proxy", "fetcher", "compiler", "agent"})
    expected_users = {"proxy": "xpm" + tag, "fetcher": "xpf" + tag, "compiler": "xpc" + tag, "agent": "xpa" + tag}
    if users != expected_users or any(not _USER.fullmatch(name) for name in users.values()):
        raise AgentFailure("manifest_invalid")
    user_ids: list[int] = []
    for name in users.values():
        try:
            record = pwd.getpwnam(name)
        except KeyError as exc:
            raise AgentFailure("manifest_live_mismatch") from exc
        if record.pw_uid == 0 or record.pw_gid == 0:
            raise AgentFailure("manifest_live_mismatch")
        user_ids.append(record.pw_uid)
    if len(set(user_ids)) != len(user_ids):
        raise AgentFailure("manifest_live_mismatch")

    veth = manifest["veth"]
    if not isinstance(veth, dict):
        raise AgentFailure("manifest_invalid")
    _require_keys(veth, {"host", "proxy", "hostIpv4", "proxyIpv4", "hostIpv6", "proxyIpv6"})
    if veth["host"] != "xph" + tag or veth["proxy"] != "xpp" + tag:
        raise AgentFailure("manifest_invalid")
    v4_host = ipaddress.ip_address(_valid_ip(veth["hostIpv4"], 4))
    v4_proxy = ipaddress.ip_address(_valid_ip(veth["proxyIpv4"], 4))
    v6_host = ipaddress.ip_address(_valid_ip(veth["hostIpv6"], 6))
    v6_proxy = ipaddress.ip_address(_valid_ip(veth["proxyIpv6"], 6))
    if not v4_host.is_link_local or not v4_proxy.is_link_local or int(v4_proxy) != int(v4_host) + 1:
        raise AgentFailure("manifest_invalid")
    if not v6_host.is_private or not v6_proxy.is_private or int(v6_proxy) != int(v6_host) + 1:
        raise AgentFailure("manifest_invalid")

    routing = manifest["routing"]
    if not isinstance(routing, dict):
        raise AgentFailure("manifest_invalid")
    _require_keys(routing, {"mark", "mask", "tables", "rulePriorities"})
    mark, mask = routing["mark"], routing["mask"]
    if not isinstance(mark, int) or isinstance(mark, bool) or mask != 0xFFFFFF00 or mark & mask != mark or mark & 0xF0000000 != 0xA0000000:
        raise AgentFailure("manifest_invalid")
    slot = (mark >> 8) & 0xFFF
    if slot > 999 or routing["tables"] != list(range(20000 + 4 * slot, 20004 + 4 * slot)) or routing["rulePriorities"] != list(range(30000 + 4 * slot, 30004 + 4 * slot)):
        raise AgentFailure("manifest_invalid")

    engine = manifest["engine"]
    if not isinstance(engine, dict):
        raise AgentFailure("manifest_invalid")
    _require_keys(engine, {"binaryPath", "binarySha256"})
    if engine["binaryPath"] != str(ENGINE_BINARY) or not isinstance(engine["binarySha256"], str) or not _HEX_64.fullmatch(engine["binarySha256"]):
        raise AgentFailure("manifest_invalid")

    paths = manifest["paths"]
    if not isinstance(paths, dict):
        raise AgentFailure("manifest_invalid")
    _require_keys(paths, {"config", "state", "key"})
    expected_state = STATE_ROOT / instance_id
    if paths != {"config": str(expected_state / "config.yaml"), "state": str(expected_state), "key": str(expected_state / "agent.key")}:
        raise AgentFailure("manifest_invalid")
    try:
        proxy_gid = pwd.getpwnam(manifest["users"]["proxy"]).pw_gid
        state_info = expected_state.stat(follow_symlinks=False)
        if (
            expected_state.resolve(strict=True) != expected_state
            or not stat.S_ISDIR(state_info.st_mode)
            or state_info.st_uid != 0
            or stat.S_IMODE(state_info.st_mode) != 0o700
        ):
            raise AgentFailure("manifest_invalid")
        config_path = expected_state / "config.yaml"
        if os.path.lexists(config_path):
            config_info = config_path.stat(follow_symlinks=False)
            if (
                config_path.resolve(strict=True) != config_path
                or not stat.S_ISREG(config_info.st_mode)
                or config_info.st_uid != 0
                or config_info.st_gid != proxy_gid
                or stat.S_IMODE(config_info.st_mode) != 0o640
                or config_info.st_nlink != 1
            ):
                raise AgentFailure("manifest_invalid")
    except (KeyError, OSError) as exc:
        raise AgentFailure("manifest_invalid") from exc
    if path not in {RUNTIME_ROOT / tag / "manifest.json", expected_state / "manifest.json"}:
        raise AgentFailure("manifest_invalid")

    daemon = manifest["daemon"]
    if not isinstance(daemon, dict):
        raise AgentFailure("manifest_invalid")
    _require_keys(daemon, {"ip", "port", "adbPort"})
    if daemon["ip"] != android["ipv4"] or daemon["port"] != 18765 or daemon["adbPort"] != 62111:
        raise AgentFailure("manifest_invalid")
    return manifest, path


class EngineIPC:
    def __init__(self, manifest: dict[str, Any], agent_gid: int):
        self._manifest = manifest
        self._agent_gid = agent_gid
        self._path = RUNTIME_ROOT / manifest["resourceTag"] / "engine.sock"
        self.generation = manifest["generation"]

    def _connect(self) -> socket.socket:
        try:
            info = self._path.stat(follow_symlinks=False)
        except OSError as exc:
            raise AgentFailure("engine_unavailable") from exc
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != self._agent_gid
            or stat.S_IMODE(info.st_mode) != 0o660
        ):
            raise AgentFailure("engine_unavailable")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        connection.settimeout(ROOT_TIMEOUT)
        try:
            connection.connect(str(self._path))
            credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _, peer_uid, _ = struct.unpack("3i", credentials)
            if peer_uid != 0:
                raise AgentFailure("engine_unavailable")
            return connection
        except BaseException:
            connection.close()
            raise

    def call(
        self,
        method: str,
        body: dict[str, Any],
        *,
        descriptor: int | None = None,
        receive_descriptors: int = 0,
    ) -> tuple[dict[str, Any], list[int]]:
        if method not in {
            "status", "writeConfig", "prepare", "apply", "off", "quarantine",
            "spawnCompiler", "spawnFetcher", "stopWorker",
        }:
            raise AgentFailure("agent_internal_error")
        request = {
            "schema": IPC_SCHEMA,
            "method": method,
            "instanceId": self._manifest["instanceId"],
            "resourceTag": self._manifest["resourceTag"],
            "runtimeEpoch": self._manifest["runtimeEpoch"],
            "manifestDigest": self._manifest["manifestDigest"],
            "generation": self.generation,
            "body": body,
        }
        ancillary: list[tuple[int, int, bytes]] = []
        if descriptor is not None:
            packed = array.array("i", [descriptor])
            ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, packed.tobytes()))
        connection = self._connect()
        received: list[int] = []
        try:
            connection.sendmsg([_canonical(request)], ancillary)
            payload, control, flags, _ = connection.recvmsg(
                MAX_CHANNEL_BYTES + 1,
                socket.CMSG_SPACE(max(1, receive_descriptors) * array.array("i").itemsize),
            )
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(payload) > MAX_CHANNEL_BYTES:
                raise AgentFailure("engine_unavailable")
            for level, kind, data in control:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    values = array.array("i")
                    values.frombytes(data[: len(data) - (len(data) % values.itemsize)])
                    received.extend(values.tolist())
        except (OSError, ValueError) as exc:
            for item in received:
                os.close(item)
            raise AgentFailure("engine_unavailable") from exc
        finally:
            connection.close()
        try:
            response = _loads(payload, "engine_unavailable")
        except AgentFailure:
            for item in received:
                os.close(item)
            raise
        if (
            isinstance(response, dict)
            and set(response) == {"schema", "ok", "error"}
            and response.get("schema") == IPC_SCHEMA
            and response.get("ok") is False
            and isinstance(response.get("error"), str)
            and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", response["error"])
        ):
            for item in received:
                os.close(item)
            raise AgentFailure(response["error"])
        if (
            not isinstance(response, dict)
            or set(response) != {"schema", "ok", "body"}
            or response.get("schema") != IPC_SCHEMA
            or response.get("ok") is not True
            or not isinstance(response.get("body"), dict)
            or len(received) != receive_descriptors
        ):
            for item in received:
                os.close(item)
            raise AgentFailure("engine_unavailable")
        return response["body"], received

    def write_config(self, value: dict[str, Any]) -> None:
        if not hasattr(os, "memfd_create"):
            raise AgentFailure("engine_unavailable")
        descriptor = os.memfd_create("xenoid-proxy-config", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            encoded = _canonical(value)
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise OSError
                offset += written
            os.lseek(descriptor, 0, os.SEEK_SET)
            seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
            fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
            self.call("writeConfig", {}, descriptor=descriptor)
        except OSError as exc:
            raise AgentFailure("engine_unavailable") from exc
        finally:
            os.close(descriptor)

    def spawn(self, role: str) -> tuple[str, int, int]:
        method = {"compiler": "spawnCompiler", "fetcher": "spawnFetcher"}.get(role)
        if method is None:
            raise AgentFailure("agent_internal_error")
        body, descriptors = self.call(method, {}, receive_descriptors=2)
        if set(body) != {"workerId"} or not isinstance(body["workerId"], str) or not re.fullmatch(r"[0-9a-f]{32}", body["workerId"]):
            for item in descriptors:
                os.close(item)
            raise AgentFailure("engine_unavailable")
        return body["workerId"], descriptors[0], descriptors[1]

    def stop_worker(self, worker_id: str) -> None:
        self.call("stopWorker", {"workerId": worker_id})


def _engine() -> EngineIPC:
    if _ENGINE is None:
        raise AgentFailure("engine_unavailable")
    return _ENGINE


def _run_root(action: str, _manifest_path: Path, payload: bytes | None = None) -> dict[str, Any]:
    client = _engine()
    if action == "status":
        body, _ = client.call("status", {})
        return body
    if action == "write-config":
        if payload is None:
            raise AgentFailure("agent_internal_error")
        value = _loads(payload, "agent_internal_error")
        if not isinstance(value, dict):
            raise AgentFailure("agent_internal_error")
        client.write_config(value)
        return {"ok": True}
    method = {"apply": "apply", "off": "off", "prepare": "prepare", "quarantine": "quarantine"}.get(action)
    if method is None or payload is not None:
        raise AgentFailure("agent_internal_error")
    client.call(method, {"target": "candidate", "commit": False} if method == "apply" else {})
    return {"ok": True}


def _rollback_previous() -> None:
    _engine().call("apply", {"target": "previous", "commit": True})


def _commit_candidate() -> None:
    _engine().call("apply", {"target": "candidate", "commit": True})


def _live_status(manifest: dict[str, Any], manifest_path: Path) -> dict[str, Any]:
    value = _run_root("status", manifest_path)
    required = {
        "ok", "instanceId", "resourceTag", "runtimeEpoch", "generation", "manifestDigest",
        "phase", "structuralApplied", "dataPlaneVerified", "capabilities", "counters",
        "selectedNode", "nodeCount",
    }
    if set(value) - (required | {"evidence"}) or not required.issubset(value):
        raise AgentFailure("manifest_live_mismatch")
    if value["ok"] is not True:
        raise AgentFailure("manifest_live_mismatch")
    for name in ("instanceId", "resourceTag", "runtimeEpoch", "manifestDigest"):
        if value[name] != manifest[name]:
            raise AgentFailure("manifest_live_mismatch")
    generation = value["generation"]
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < manifest["generation"]:
        raise AgentFailure("manifest_live_mismatch")
    if value["phase"] not in {
        "quarantined", "applying", "ready", "active", "error", "disabled", "off", "stopped"
    }:
        raise AgentFailure("manifest_live_mismatch")
    if not isinstance(value["structuralApplied"], bool) or not isinstance(value["dataPlaneVerified"], bool):
        raise AgentFailure("manifest_live_mismatch")
    if not isinstance(value["capabilities"], dict) or not isinstance(value["counters"], dict):
        raise AgentFailure("manifest_live_mismatch")
    if set(value["capabilities"]) != CAPABILITY_KEYS or any(
        not isinstance(item, bool) for item in value["capabilities"].values()
    ):
        raise AgentFailure("manifest_live_mismatch")
    if any(not isinstance(key, str) or not isinstance(item, int) or isinstance(item, bool) or item < 0 for key, item in value["counters"].items()):
        raise AgentFailure("manifest_live_mismatch")
    if not isinstance(value["selectedNode"], str) or len(value["selectedNode"]) > 128:
        raise AgentFailure("manifest_live_mismatch")
    if not isinstance(value["nodeCount"], int) or isinstance(value["nodeCount"], bool) or not 0 <= value["nodeCount"] <= 512:
        raise AgentFailure("manifest_live_mismatch")
    if "evidence" in value and not isinstance(value["evidence"], dict):
        raise AgentFailure("manifest_live_mismatch")
    return value


def _read_channel_secret(manifest: dict[str, Any]) -> tuple[bytearray, bytearray]:
    path = Path(manifest["paths"]["key"])
    data = bytearray(_read_exact_file(path, 0o400, 512))
    master = bytearray()
    token = bytearray()
    raw_token = bytearray()
    try:
        document = _loads(bytes(data), "agent_key_invalid")
        if not isinstance(document, dict) or set(document) != {"masterKey", "agentToken"}:
            raise AgentFailure("agent_key_invalid")
        encoded_master = document["masterKey"]
        encoded_token = document["agentToken"]
        if (
            not isinstance(encoded_master, str)
            or not isinstance(encoded_token, str)
            or len(encoded_master) != 44
            or len(encoded_token) != 44
            or any(character.isspace() for character in encoded_master + encoded_token)
        ):
            raise AgentFailure("agent_key_invalid")
        try:
            master = bytearray(base64.b64decode(encoded_master, validate=True))
            raw_token = bytearray(base64.b64decode(encoded_token, validate=True))
        except ValueError as exc:
            raise AgentFailure("agent_key_invalid") from exc
        if len(master) != 32 or len(raw_token) != 32:
            raise AgentFailure("agent_key_invalid")
        for index in range(len(raw_token)):
            raw_token[index] = 0
        token = bytearray(encoded_token.encode("ascii"))
        return master, token
    except BaseException:
        for value in (master, token, raw_token):
            for index in range(len(value)):
                value[index] = 0
        raise
    finally:
        for index in range(len(data)):
            data[index] = 0


def _prepare_health(manifest: dict[str, Any]) -> int:
    path = Path(manifest["paths"]["state"]) / "agent-status.json"
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise OSError
        return descriptor
    except OSError as exc:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise AgentFailure("agent_privilege_invalid") from exc

def _prepare_cache(manifest: dict[str, Any]) -> int:
    path = Path(manifest["paths"]["state"]) / "provider-cache"
    try:
        record = pwd.getpwnam(manifest["users"]["agent"])
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(descriptor)
        if (
            info.st_uid != record.pw_uid
            or info.st_gid != record.pw_gid
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise OSError
        return descriptor
    except (KeyError, OSError) as exc:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise AgentFailure("agent_privilege_invalid") from exc


def _write_health(manifest: dict[str, Any], phase: str, generation: int, code: str = "") -> None:
    if phase not in {"starting", "quarantined", "applying", "ready", "error", "disabled", "stopped"}:
        return
    encoded = _canonical({
        "schema": "dev.xenoid.proxy-agent.status/v1", "instanceId": manifest["instanceId"],
        "resourceTag": manifest["resourceTag"], "runtimeEpoch": manifest["runtimeEpoch"],
        "generation": generation, "phase": phase, "errorCode": code, "updatedAt": int(time.time()),
    }) + b"\n"
    if _HEALTH_FD < 0:
        return
    try:
        os.lseek(_HEALTH_FD, 0, os.SEEK_SET)
        os.ftruncate(_HEALTH_FD, 0)
        offset = 0
        while offset < len(encoded):
            written = os.write(_HEALTH_FD, encoded[offset:])
            if written <= 0:
                return
            offset += written
        os.fsync(_HEALTH_FD)
    except OSError:
        return


def _instance_lock(manifest: dict[str, Any]) -> int:
    path = Path(manifest["paths"]["state"]) / "agent.lock"
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise OSError
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except OSError as exc:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise AgentFailure("instance_busy") from exc


class DaemonChannel:
    def __init__(self, manifest: dict[str, Any], master_key: bytearray, agent_token: bytearray):
        self._manifest = manifest
        self._agent_token = bytearray(agent_token)
        self._session = os.urandom(16).hex()
        self._sequence = 0
        self._request_number = 0
        self._c2s_key = bytearray(derive_key(bytes(master_key), manifest["instanceId"], manifest["runtimeEpoch"], "c2s"))
        self._s2c_key = bytearray(derive_key(bytes(master_key), manifest["instanceId"], manifest["runtimeEpoch"], "s2c"))

    def close(self) -> None:
        for key in (self._c2s_key, self._s2c_key, self._agent_token):
            for index in range(len(key)):
                key[index] = 0

    def _once(self, operation: str, body: dict[str, Any]) -> dict[str, Any]:
        self._sequence += 1
        self._request_number += 1
        sequence = self._sequence
        request_id = f"{self._request_number:032x}"
        timestamp = int(time.time())
        try:
            envelope = seal_request(
                bytes(self._c2s_key), self._manifest["instanceId"], self._manifest["runtimeEpoch"],
                self._session, sequence, request_id, operation, timestamp, body,
            )
        except ProxyProtocolError as exc:
            raise ChannelAuthenticationFailure("agent_channel_auth_failed") from exc
        encoded = _canonical(envelope)
        # The Android probe endpoint runs ordinary-app capability probes with a
        # 45s budget through the fresh data path; keep channel headroom above it.
        timeout = 70.0 if operation == "probe" else 20.0
        connection = http.client.HTTPConnection(self._manifest["daemon"]["ip"], self._manifest["daemon"]["port"], timeout=timeout)
        try:
            connection.request("POST", "/proxy/agent", body=encoded, headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(encoded)),
                "Connection": "close",
                "X-Xenoid-Agent-Token": self._agent_token.decode("ascii"),
            })
            response = connection.getresponse()
            payload = response.read(MAX_CHANNEL_BYTES + 1)
            if response.status != 200 or len(payload) > MAX_CHANNEL_BYTES:
                raise ChannelAuthenticationFailure("agent_channel_auth_failed")
        except ChannelAuthenticationFailure:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise AgentFailure("agent_channel_unreachable") from exc
        finally:
            connection.close()
        try:
            outer = _loads(payload, "agent_channel_auth_failed")
        except AgentFailure as exc:
            raise ChannelAuthenticationFailure("agent_channel_auth_failed") from exc
        if not isinstance(outer, dict):
            raise ChannelAuthenticationFailure("agent_channel_auth_failed")
        try:
            opened = open_response(
                bytes(self._s2c_key), outer, self._manifest["instanceId"], self._manifest["runtimeEpoch"],
                self._session, sequence, request_id,
            )
        except ProxyProtocolError as exc:
            raise ChannelAuthenticationFailure("agent_channel_auth_failed") from exc
        if (
            not isinstance(opened, dict)
            or set(opened) != {"body", "ok", "status"}
            or opened.get("ok") is not True
            or opened.get("status") != 200
            or not isinstance(opened.get("body"), dict)
        ):
            raise ChannelAuthenticationFailure("agent_channel_auth_failed")
        return opened["body"]

    def call(self, operation: str, body: dict[str, Any]) -> dict[str, Any]:
        if operation not in {"desired", "report", "probe"}:
            raise AgentFailure("agent_internal_error")
        failure: AgentFailure | None = None
        for delay in (0.0, 1.0, 2.0):
            if _STOP:
                raise AgentFailure("agent_stopping")
            if delay:
                time.sleep(delay)
            try:
                return self._once(operation, body)
            except ChannelAuthenticationFailure:
                raise
            except AgentFailure as exc:
                failure = exc
        raise failure or AgentFailure("agent_channel_unreachable")


def _desired(channel: DaemonChannel, manifest: dict[str, Any], floor: int) -> dict[str, Any]:
    value = channel.call("desired", {})
    _require_keys(value, {"schemaVersion", "instanceId", "generation", "enabled", "checkId", "source"})
    if value["schemaVersion"] != 1 or value["instanceId"] != manifest["instanceId"]:
        raise ChannelAuthenticationFailure("runtime_epoch_mismatch")
    generation = value["generation"]
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < floor or generation >= 2**63:
        raise ChannelAuthenticationFailure("agent_stale")
    if not isinstance(value["enabled"], bool):
        raise AgentFailure("agent_schema_invalid")
    check_id = value["checkId"]
    if not isinstance(check_id, int) or isinstance(check_id, bool) or not 0 <= check_id < 2**63:
        raise AgentFailure("agent_schema_invalid")
    source = value["source"]
    if source is not None:
        if not isinstance(source, dict):
            raise AgentFailure("agent_schema_invalid")
        _require_keys(source, {"kind", "value", "selectedNode", "udpAllowed", "allowInsecureHttp"})
        if source["kind"] not in {"endpoint", "uri_list", "clash", "subscription"}:
            raise AgentFailure("source_invalid")
        if not isinstance(source["value"], str) or not source["value"] or len(source["value"].encode("utf-8")) > MAX_SOURCE_BYTES:
            raise AgentFailure("source_invalid")
        if not isinstance(source["selectedNode"], str) or len(source["selectedNode"]) > 128:
            raise AgentFailure("source_invalid")
        if not isinstance(source["udpAllowed"], bool) or not isinstance(source["allowInsecureHttp"], bool):
            raise AgentFailure("source_invalid")
    return value


def _write_worker(descriptor: int, value: dict[str, Any], deadline: float) -> None:
    payload = _canonical(value) + b"\n"
    offset = 0
    selector = selectors.DefaultSelector()
    try:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_WRITE)
        while offset < len(payload) and not _STOP:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AgentFailure("worker_unavailable")
            if not selector.select(min(0.5, remaining)):
                continue
            try:
                written = os.write(descriptor, payload[offset:])
            except BlockingIOError:
                continue
            if written <= 0:
                raise AgentFailure("worker_unavailable")
            offset += written
    except OSError as exc:
        raise AgentFailure("worker_unavailable") from exc
    finally:
        selector.close()
    if offset != len(payload):
        raise AgentFailure("worker_unavailable")


def _read_worker(descriptor: int, deadline: float) -> dict[str, Any]:
    selector = selectors.DefaultSelector()
    data = bytearray()
    try:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
        while not _STOP:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AgentFailure("worker_unavailable")
            if not selector.select(min(0.5, remaining)):
                continue
            try:
                chunk = os.read(descriptor, 64 * 1024)
            except BlockingIOError:
                continue
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_WORKER_BYTES or b"\n" in data:
                break
    except OSError as exc:
        raise AgentFailure("worker_unavailable") from exc
    finally:
        selector.close()
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise AgentFailure("worker_unavailable")
    value = _loads(bytes(data), "worker_unavailable")
    if not isinstance(value, dict):
        raise AgentFailure("worker_unavailable")
    return value


def _invoke_fetch(payload: dict[str, Any], deadline: float) -> dict[str, Any] | None:
    worker_id = ""
    input_fd = output_fd = -1
    try:
        worker_id, input_fd, output_fd = _engine().spawn("fetcher")
        _ACTIVE_WORKERS.add(worker_id)
        _write_worker(input_fd, payload, deadline)
        os.close(input_fd)
        input_fd = -1
        return _read_worker(output_fd, deadline)
    except AgentFailure:
        return None
    finally:
        for descriptor in (input_fd, output_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if worker_id:
            try:
                _engine().stop_worker(worker_id)
            except AgentFailure:
                pass
            _ACTIVE_WORKERS.discard(worker_id)


def _cache_key(url: str, headers: dict[str, str], allow_insecure_http: bool) -> str:
    return hashlib.sha256(_canonical({
        "url": url,
        "headers": headers,
        "allowInsecureHttp": allow_insecure_http,
    })).hexdigest()

def _cache_document(name: str) -> tuple[dict[str, Any], bytes]:
    if _CACHE_DIR_FD < 0 or not re.fullmatch(r"[0-9a-f]{64}\.json", name):
        raise AgentFailure("source_fetch_denied")
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=_CACHE_DIR_FD,
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_gid != os.getegid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > 2 * MAX_SOURCE_BYTES
        ):
            raise AgentFailure("source_fetch_denied")
        data = bytearray()
        while len(data) <= 2 * MAX_SOURCE_BYTES:
            chunk = os.read(descriptor, min(65536, 2 * MAX_SOURCE_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > 2 * MAX_SOURCE_BYTES:
            raise AgentFailure("source_fetch_denied")
        value = _loads(bytes(data), "source_fetch_denied")
    except OSError as exc:
        raise AgentFailure("source_fetch_denied") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict) or set(value) != {
        "schema", "bodyBase64", "etag", "lastModified", "fetchedAt",
    }:
        raise AgentFailure("source_fetch_denied")
    if value["schema"] != "dev.xenoid.proxy-provider-cache/v1":
        raise AgentFailure("source_fetch_denied")
    if (
        not isinstance(value["etag"], str)
        or len(value["etag"]) > 1024
        or not isinstance(value["lastModified"], str)
        or len(value["lastModified"]) > 1024
        or not isinstance(value["fetchedAt"], int)
        or isinstance(value["fetchedAt"], bool)
        or value["fetchedAt"] < 0
        or value["fetchedAt"] > int(time.time()) + 120
    ):
        raise AgentFailure("source_fetch_denied")
    try:
        body = base64.b64decode(value["bodyBase64"].encode("ascii"), validate=True)
    except (AttributeError, UnicodeEncodeError, ValueError) as exc:
        raise AgentFailure("source_fetch_denied") from exc
    if not body or len(body) > MAX_SOURCE_BYTES:
        raise AgentFailure("source_fetch_denied")
    return value, body


def _cache_entries() -> list[tuple[str, dict[str, Any], bytes]]:
    if _CACHE_DIR_FD < 0:
        raise AgentFailure("source_fetch_denied")
    try:
        names = os.listdir(_CACHE_DIR_FD)
    except OSError as exc:
        raise AgentFailure("source_fetch_denied") from exc
    entries: list[tuple[str, dict[str, Any], bytes]] = []
    for name in names:
        if name.startswith(".tmp-"):
            try:
                os.unlink(name, dir_fd=_CACHE_DIR_FD)
            except OSError:
                pass
            continue
        document, body = _cache_document(name)
        entries.append((name, document, body))
    if len(entries) > CACHE_MAX_ENTRIES or sum(len(entry[2]) for entry in entries) > CACHE_MAX_BYTES:
        raise AgentFailure("source_fetch_denied")
    return entries


def _cache_load(key: str) -> tuple[dict[str, Any], bytes] | None:
    name = key + ".json"
    entries = _cache_entries()
    for entry_name, document, body in entries:
        if entry_name == name:
            return document, body
    return None


def _cache_store(key: str, body: bytes, etag: str, last_modified: str) -> None:
    if not body or len(body) > MAX_SOURCE_BYTES:
        raise AgentFailure("source_fetch_denied")
    target = key + ".json"
    entries = [entry for entry in _cache_entries() if entry[0] != target]
    entries.sort(key=lambda entry: entry[1]["fetchedAt"])
    total = sum(len(entry[2]) for entry in entries)
    while entries and (len(entries) >= CACHE_MAX_ENTRIES or total + len(body) > CACHE_MAX_BYTES):
        name, _, old_body = entries.pop(0)
        try:
            os.unlink(name, dir_fd=_CACHE_DIR_FD)
        except OSError as exc:
            raise AgentFailure("source_fetch_denied") from exc
        total -= len(old_body)
    if len(entries) >= CACHE_MAX_ENTRIES or total + len(body) > CACHE_MAX_BYTES:
        raise AgentFailure("source_fetch_denied")
    document = {
        "schema": "dev.xenoid.proxy-provider-cache/v1",
        "bodyBase64": base64.b64encode(body).decode("ascii"),
        "etag": etag,
        "lastModified": last_modified,
        "fetchedAt": int(time.time()),
    }
    encoded = _canonical(document) + b"\n"
    temporary = f".tmp-{os.getpid()}-{secrets.token_hex(8)}"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=_CACHE_DIR_FD,
        )
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, target, src_dir_fd=_CACHE_DIR_FD, dst_dir_fd=_CACHE_DIR_FD)
        os.fsync(_CACHE_DIR_FD)
    except OSError as exc:
        raise AgentFailure("source_fetch_denied") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=_CACHE_DIR_FD)
        except OSError:
            pass


def _fetch_provider(
    _manifest: dict[str, Any],
    request: dict[str, Any],
    metadata: dict[str, tuple[str, str]],
    deadline: float,
) -> dict[str, Any]:
    failure = {"type": "fetchResult", "id": request.get("id"), "ok": False, "bodyBase64": ""}
    if set(request) != {"type", "id", "url", "headers", "allowInsecureHttp"} or request.get("type") != "fetch":
        return failure
    url, request_id, headers = request.get("url"), request.get("id"), request.get("headers")
    if (
        not isinstance(url, str)
        or not isinstance(request_id, int)
        or isinstance(request_id, bool)
        or not isinstance(headers, dict)
        or len(headers) > 16
        or not isinstance(request.get("allowInsecureHttp"), bool)
        or any(
            not isinstance(name, str)
            or not isinstance(value, str)
            or not name
            or len(name) > 128
            or len(value) > 4096
            or any(ord(character) < 32 or ord(character) == 127 for character in name + value)
            for name, value in headers.items()
        )
    ):
        return failure
    cache_key = _cache_key(url, headers, request.get("allowInsecureHttp") is True)
    cached = _cache_load(cache_key)
    if cached is None:
        etag, modified = metadata.get(cache_key, ("", ""))
    else:
        cached_document, _ = cached
        etag, modified = cached_document["etag"], cached_document["lastModified"]

    payload = {
        "op": "fetch",
        "url": url,
        "headers": headers,
        "etag": etag,
        "lastModified": modified,
        "allowInsecureHttp": request.get("allowInsecureHttp"),
    }
    fetched: dict[str, Any] | None = None
    for delay in (0.0, 1.0, 3.0):
        remaining = deadline - time.monotonic()
        if _STOP or remaining <= 0:
            break
        if delay:
            time.sleep(min(delay, remaining))
        if time.monotonic() >= deadline:
            break
        response = _invoke_fetch(payload, deadline)
        if isinstance(response, dict) and response.get("ok") is True:
            fetched = response
            break
    if (
        fetched is not None
        and set(fetched) == {"ok", "notModified", "bodyBase64", "etag", "lastModified"}
        and fetched.get("notModified") is True
        and cached is not None
        and isinstance(fetched.get("etag"), str)
        and isinstance(fetched.get("lastModified"), str)
    ):
        _, cached_body = cached
        _cache_store(cache_key, cached_body, fetched["etag"], fetched["lastModified"])
        metadata[cache_key] = (fetched["etag"], fetched["lastModified"])
        return {
            "type": "fetchResult",
            "id": request_id,
            "ok": True,
            "bodyBase64": base64.b64encode(cached_body).decode("ascii"),
        }
    if (
        fetched is not None
        and set(fetched) == {"ok", "notModified", "bodyBase64", "etag", "lastModified"}
        and fetched.get("notModified") is False
        and isinstance(fetched.get("bodyBase64"), str)
        and isinstance(fetched.get("etag"), str)
        and isinstance(fetched.get("lastModified"), str)
    ):
        try:
            body = base64.b64decode(fetched["bodyBase64"].encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError):
            body = b""
        if body and len(body) <= MAX_SOURCE_BYTES:
            _cache_store(cache_key, body, fetched["etag"], fetched["lastModified"])
            metadata[cache_key] = (fetched["etag"], fetched["lastModified"])
            return {
                "type": "fetchResult",
                "id": request_id,
                "ok": True,
                "bodyBase64": fetched["bodyBase64"],
            }
    if cached is not None:
        cached_document, cached_body = cached
        if int(time.time()) - cached_document["fetchedAt"] <= CACHE_TTL_SECONDS:
            return {
                "type": "fetchResult",
                "id": request_id,
                "ok": True,
                "bodyBase64": base64.b64encode(cached_body).decode("ascii"),
            }
    return failure


def _compile_source(manifest: dict[str, Any], source: dict[str, Any], metadata: dict[str, tuple[str, str]]) -> dict[str, Any]:
    deadline = time.monotonic() + WORKER_TIMEOUT
    worker_id = ""
    input_fd = output_fd = -1
    compile_source = source
    if source["kind"] == "subscription":
        fetched = _fetch_provider(manifest, {
            "type": "fetch",
            "id": 0,
            "url": source["value"],
            "headers": {},
            "allowInsecureHttp": source["allowInsecureHttp"],
        }, metadata, deadline)
        if fetched.get("ok") is not True:
            raise AgentFailure("source_fetch_denied")
        try:
            fetched_text = base64.b64decode(fetched["bodyBase64"], validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise AgentFailure("source_invalid") from exc
        compile_source = dict(source)
        compile_source["value"] = fetched_text
    request = {
        "op": "compile",
        "kind": compile_source["kind"],
        "valueBase64": base64.b64encode(compile_source["value"].encode("utf-8")).decode("ascii"),
        "selectedNode": compile_source["selectedNode"],
        "udpAllowed": compile_source["udpAllowed"],
        "allowInsecureHttp": compile_source["allowInsecureHttp"],
    }
    try:
        if time.monotonic() >= deadline:
            raise AgentFailure("compiler_unavailable")
        worker_id, input_fd, output_fd = _engine().spawn("compiler")
        _ACTIVE_WORKERS.add(worker_id)
        _write_worker(input_fd, request, deadline)
        while not _STOP and time.monotonic() < deadline:
            response = _read_worker(output_fd, deadline)
            if response.get("type") == "fetch":
                fetch_response = _fetch_provider(manifest, response, metadata, deadline)
                _write_worker(input_fd, fetch_response, deadline)
                continue
            if response.get("type") != "result":
                break
            if response.get("ok") is not True:
                code = response.get("error")
                if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code):
                    code = "source_invalid"
                raise AgentFailure(code)
            if set(response) != {"type", "ok", "config", "nodeNames", "sourceSha256"}:
                break
            if not isinstance(response["config"], dict) or not isinstance(response["nodeNames"], list):
                break
            if not isinstance(response["sourceSha256"], str) or not _HEX_64.fullmatch(response["sourceSha256"]):
                break
            return response
        raise AgentFailure("compiler_unavailable")
    finally:
        for descriptor in (input_fd, output_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if worker_id:
            try:
                _engine().stop_worker(worker_id)
            except AgentFailure:
                pass
            _ACTIVE_WORKERS.discard(worker_id)


def _stop_child() -> None:
    for worker_id in tuple(_ACTIVE_WORKERS):
        try:
            _engine().stop_worker(worker_id)
        except AgentFailure:
            pass
        _ACTIVE_WORKERS.discard(worker_id)


def _report_staging(channel: DaemonChannel, desired: dict[str, Any]) -> None:
    channel.call("report", {
        "generation": desired["generation"],
        "checkId": desired["checkId"],
        "structuralApplied": False,
        "dataPlaneVerified": False,
        "phase": "staging",
        "selectedNode": "",
        "nodeCount": 0,
        "nodes": [],
        "capabilities": {},
        "counters": {},
    })


def _report_failure(channel: DaemonChannel, desired: dict[str, Any], code: str, quarantined: bool) -> None:
    channel.call("report", {
        "generation": desired["generation"], "checkId": desired["checkId"],
        "structuralApplied": False, "dataPlaneVerified": False,
        "phase": "quarantined" if quarantined else "error", "selectedNode": "",
        "nodeCount": 0, "nodes": [], "capabilities": {}, "counters": {}, "errorCode": code,
    })


def _report_status(
    channel: DaemonChannel,
    desired: dict[str, Any],
    live: dict[str, Any],
    *,
    error_code: str = "",
) -> None:
    report = {
        "generation": desired["generation"],
        "structuralApplied": live["structuralApplied"], "dataPlaneVerified": live["dataPlaneVerified"],
        "phase": live["phase"], "selectedNode": live["selectedNode"], "nodeCount": live["nodeCount"],
        "nodes": live.get("nodes", []), "capabilities": live["capabilities"],
        "counters": live["counters"],
    }
    if live["phase"] != "off":
        report["checkId"] = desired["checkId"]
    if error_code:
        report["errorCode"] = error_code
    if len(_canonical(report)) > 60 * 1024:
        raise AgentFailure("source_invalid")
    channel.call("report", report)


def _probe_data_plane(
    channel: DaemonChannel,
    desired: dict[str, Any],
    manifest: dict[str, Any],
    manifest_path: Path,
    before: dict[str, Any],
    *,
    expected_generation: Optional[int] = None,
) -> dict[str, Any]:
    check_id = desired["checkId"]
    if check_id <= 0:
        raise AgentFailure("data_plane_unverified")
    result = channel.call("probe", {"checkId": check_id})
    if set(result) != {"checkId", "capabilities", "elapsedMs", "errorCode"}:
        raise ChannelAuthenticationFailure("agent_channel_auth_failed")
    capabilities = result["capabilities"]
    error_code = result["errorCode"]
    if (
        not isinstance(result["checkId"], int)
        or isinstance(result["checkId"], bool)
        or result["checkId"] != check_id
        or not isinstance(capabilities, dict)
        or set(capabilities) != CAPABILITY_KEYS
        or any(not isinstance(value, bool) for value in capabilities.values())
        or not isinstance(result["elapsedMs"], int)
        or isinstance(result["elapsedMs"], bool)
        or not 0 <= result["elapsedMs"] <= ANDROID_PROBE_TIMEOUT_MS
        or not isinstance(error_code, str)
        or (error_code != "" and not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", error_code))
    ):
        raise ChannelAuthenticationFailure("agent_channel_auth_failed")
    if error_code:
        raise AgentFailure(error_code)
    udp_allowed = desired["source"]["udpAllowed"]
    policy_matches = (
        capabilities["v4DnsProxy"]
        and capabilities["v4TcpProxy"]
        and capabilities["v6DnsProxy"]
        and capabilities["v4UdpProxy"] == udp_allowed
        and (udp_allowed or not capabilities["v6UdpProxy"])
    )
    if not policy_matches:
        raise AgentFailure("data_plane_unverified")

    after = _live_status(manifest, manifest_path)
    expected = desired["generation"] if expected_generation is None else expected_generation
    if after["generation"] != expected:
        raise AgentFailure("agent_stale")
    if not after["structuralApplied"]:
        code = {
            "active": "engine_process_failed",
            "applying": "apply_not_pending",
            "quarantined": "engine_quarantined",
            "off": "engine_unexpected_off",
        }.get(after["phase"], "engine_structure_mismatch")
        raise AgentFailure(code)
    for capability in CAPABILITY_KEYS:
        counter_prefix = capability[:-len("Proxy")]
        udp_blocked = "Udp" in capability and not udp_allowed
        for stage in ("Ingress", "Uplink", "Egress"):
            counter = counter_prefix + stage
            if counter not in before["counters"] or counter not in after["counters"]:
                raise AgentFailure("data_plane_unverified")
            if stage != "Egress" or capabilities[capability]:
                if after["counters"][counter] <= before["counters"][counter]:
                    raise AgentFailure("data_plane_unverified")
            elif udp_blocked:
                if after["counters"][counter] != before["counters"][counter]:
                    raise AgentFailure("data_plane_unverified")
            elif after["counters"][counter] < before["counters"][counter]:
                raise AgentFailure("data_plane_unverified")
    after["capabilities"] = dict(capabilities)
    after["dataPlaneVerified"] = True
    after["phase"] = "active"
    return after


def _quarantine(manifest_path: Path) -> None:
    try:
        _run_root("quarantine", manifest_path)
    except AgentFailure:
        pass


def _run(
    manifest: dict[str, Any],
    manifest_path: Path,
    master: bytearray,
    agent_token: bytearray,
    initial: dict[str, Any],
) -> int:
    channel = DaemonChannel(manifest, master, agent_token)
    metadata: dict[str, tuple[str, str]] = {}
    floor = max(manifest["generation"], initial["generation"])
    last_seen = floor
    active_generation = initial["generation"] if initial["structuralApplied"] else -1
    active_digest = ""
    active_nodes: list[str] = []
    active_selected = ""
    verified_old = False
    last_refresh = 0.0
    last_check = 0
    retry_generation = -1
    retry_count = 0
    retry_at = 0.0
    try:
        while not _STOP:
            desired = _desired(channel, manifest, floor)
            generation = desired["generation"]
            if verified_old:
                _write_health(manifest, "ready", active_generation)
            if generation < last_seen or desired["checkId"] < last_check:
                raise ChannelAuthenticationFailure("agent_stale")
            _engine().generation = generation
            now = time.monotonic()
            candidate_due = (
                generation != active_generation
                and (generation != retry_generation or now >= retry_at)
            )
            changed = generation != last_seen or candidate_due
            refresh_due = desired["enabled"] and now - last_refresh >= REFRESH_SECONDS
            check_due = desired["checkId"] > last_check
            last_seen = generation

            if not desired["enabled"]:
                live = _live_status(manifest, manifest_path)
                if live["phase"] != "off" or live["generation"] < generation:
                    _run_root("off", manifest_path)
                    live = _live_status(manifest, manifest_path)
                if (
                    live["phase"] != "off"
                    or live["generation"] < generation
                    or live["structuralApplied"] is not True
                    or live["dataPlaneVerified"] is not True
                ):
                    raise AgentFailure("off_unverified")
                live.update({"generation": generation, "selectedNode": "", "nodeCount": 0, "nodes": []})
                _report_status(channel, desired, live)
                _write_health(manifest, "disabled", generation)
                active_generation, active_digest, active_nodes, active_selected = generation, "", [], ""
                verified_old = False
                last_check = desired["checkId"]
                retry_generation, retry_count, retry_at = -1, 0, 0.0
                time.sleep(POLL_SECONDS)
                continue

            if desired["source"] is None:
                _quarantine(manifest_path)
                _report_failure(channel, desired, "source_invalid", True)
                _write_health(manifest, "quarantined", generation, "source_invalid")
                active_generation, active_digest, active_nodes, active_selected = -1, "", [], ""
                verified_old = False
                time.sleep(POLL_SECONDS)
                continue

            if changed or refresh_due:
                _write_health(manifest, "applying", generation)
                candidate_staged = False
                had_verified_old = verified_old
                try:
                    if _live_status(manifest, manifest_path)["phase"] == "off":
                        _run_root("prepare", manifest_path)
                    _validate_binary(ENGINE_BINARY, manifest["engine"]["binarySha256"])
                    compiled = _compile_source(manifest, desired["source"], metadata)
                    nodes = compiled["nodeNames"]
                    if (
                        len(nodes) > 512
                        or len(set(nodes)) != len(nodes)
                        or any(
                            not isinstance(name, str)
                            or not 1 <= len(name.encode("utf-8")) <= 128
                            or any(ord(character) < 32 or ord(character) == 127 for character in name)
                            for name in nodes
                        )
                    ):
                        raise AgentFailure("source_invalid")
                    selected = desired["source"]["selectedNode"]
                    if selected and selected not in nodes:
                        raise AgentFailure("selection_missing")
                    config_digest = hashlib.sha256(_canonical(compiled["config"])).hexdigest()
                    if generation != active_generation or config_digest != active_digest:
                        candidate = {
                            "instanceId": manifest["instanceId"], "runtimeEpoch": manifest["runtimeEpoch"],
                            "generation": generation, "config": compiled["config"],
                        }
                        _run_root("write-config", manifest_path, _canonical(candidate))
                        if retry_generation != generation:
                            _report_staging(channel, desired)
                        candidate_staged = True
                        _run_root("apply", manifest_path)
                    elif not check_due and verified_old:
                        last_refresh = time.monotonic()
                        _write_health(manifest, "ready", generation)
                        continue
                    before = _live_status(manifest, manifest_path)
                    if before["generation"] != generation or not before["structuralApplied"]:
                        raise AgentFailure("data_plane_unverified")
                    before.update({"selectedNode": selected, "nodeCount": len(nodes), "nodes": nodes})
                    if not (check_due or candidate_staged):
                        raise AgentFailure("data_plane_unverified")
                    live = _probe_data_plane(channel, desired, manifest, manifest_path, before)
                    if candidate_staged:
                        _commit_candidate()
                    live.update({"selectedNode": selected, "nodeCount": len(nodes), "nodes": nodes})
                    _report_status(channel, desired, live)
                    active_generation, active_digest = generation, config_digest
                    active_nodes, active_selected = list(nodes), selected
                    verified_old = True
                    last_refresh = time.monotonic()
                    last_check = desired["checkId"]
                    retry_generation, retry_count, retry_at = -1, 0, 0.0
                    _write_health(manifest, "ready", generation)
                except ChannelAuthenticationFailure:
                    raise
                except AgentFailure as exc:
                    restored_active = False
                    report_failure = retry_generation != generation
                    if had_verified_old:
                        try:
                            if candidate_staged:
                                _rollback_previous()
                            restored_before = _live_status(manifest, manifest_path)
                            if (
                                restored_before["generation"] != active_generation
                                or not restored_before["structuralApplied"]
                            ):
                                raise AgentFailure("data_plane_unverified")
                            restored_before.update({
                                "selectedNode": active_selected,
                                "nodeCount": len(active_nodes),
                                "nodes": active_nodes,
                            })
                            restored = _probe_data_plane(
                                channel,
                                desired,
                                manifest,
                                manifest_path,
                                restored_before,
                                expected_generation=active_generation,
                            )
                            restored.update({
                                "selectedNode": active_selected,
                                "nodeCount": len(active_nodes),
                                "nodes": active_nodes,
                            })
                            # Bind failure to the rejected desired generation while
                            # proving and releasing quarantine for the restored LKG.
                            if report_failure:
                                _report_status(
                                    channel, desired, restored, error_code=exc.code)
                            restored_active = True
                            verified_old = True
                            last_check = desired["checkId"]
                        except ChannelAuthenticationFailure:
                            raise
                        except AgentFailure:
                            _quarantine(manifest_path)
                    else:
                        try:
                            if candidate_staged:
                                _rollback_previous()
                            else:
                                _quarantine(manifest_path)
                        except AgentFailure:
                            _quarantine(manifest_path)
                        verified_old = False
                    if not verified_old:
                        active_generation, active_digest, active_nodes, active_selected = -1, "", [], ""
                    if not restored_active and report_failure:
                        _report_failure(
                            channel,
                            desired,
                            exc.code,
                            True,
                        )
                    _write_health(
                        manifest,
                        "error" if verified_old else "quarantined",
                        generation,
                        exc.code,
                    )
                    last_refresh = time.monotonic()
                    if retry_generation != generation:
                        retry_generation, retry_count = generation, 0
                    retry_count = min(retry_count + 1, 4)
                    retry_at = time.monotonic() + (5.0, 15.0, 60.0, 300.0)[retry_count - 1]
            elif check_due and verified_old and active_generation == generation:
                try:
                    before = _live_status(manifest, manifest_path)
                    if before["generation"] != generation:
                        raise AgentFailure("agent_stale")
                    if not before["structuralApplied"]:
                        code = {
                            "active": "engine_process_failed",
                            "applying": "apply_not_pending",
                            "quarantined": "engine_quarantined",
                            "off": "engine_unexpected_off",
                        }.get(before["phase"], "engine_structure_mismatch")
                        raise AgentFailure(code)
                    before.update({
                        "selectedNode": active_selected, "nodeCount": len(active_nodes), "nodes": active_nodes,
                    })
                    live = _probe_data_plane(channel, desired, manifest, manifest_path, before)
                    live.update({
                        "selectedNode": active_selected, "nodeCount": len(active_nodes), "nodes": active_nodes,
                    })
                    _report_status(channel, desired, live)
                    verified_old = True
                    last_check = desired["checkId"]
                    _write_health(manifest, "ready", generation)
                except ChannelAuthenticationFailure:
                    raise
                except AgentFailure as exc:
                    if not verified_old:
                        _quarantine(manifest_path)
                    _report_failure(channel, desired, exc.code, not verified_old)
                    _write_health(manifest, "error" if verified_old else "quarantined", generation, exc.code)
            time.sleep(POLL_SECONDS)
        return 0
    finally:
        channel.close()


def _harden_process() -> None:
    try:
        os.chdir("/")
        os.environ.clear()
        os.environ.update({
            "LANG": "C",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        })
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(4, 0, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl")
        for resource_id, ceiling in (
            (resource.RLIMIT_CORE, 0),
            (resource.RLIMIT_NOFILE, 256),
            (resource.RLIMIT_AS, 512 * 1024 * 1024),
            (resource.RLIMIT_NPROC, 0),
        ):
            _, hard = resource.getrlimit(resource_id)
            bounded = ceiling if hard == resource.RLIM_INFINITY else min(ceiling, hard)
            resource.setrlimit(resource_id, (bounded, bounded))
    except (OSError, ValueError) as exc:
        raise AgentFailure("agent_privilege_invalid") from exc


def _drop_to_agent(manifest: dict[str, Any]) -> tuple[int, int]:
    if os.geteuid() != 0:
        raise AgentFailure("agent_privilege_invalid")
    try:
        record = pwd.getpwnam(manifest["users"]["agent"])
    except KeyError as exc:
        raise AgentFailure("agent_privilege_invalid") from exc
    if record.pw_uid == 0 or record.pw_gid == 0:
        raise AgentFailure("agent_privilege_invalid")
    try:
        os.setgroups([])
        os.setgid(record.pw_gid)
        os.setuid(record.pw_uid)
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(38, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl")
    except OSError as exc:
        raise AgentFailure("agent_privilege_invalid") from exc
    if os.geteuid() != record.pw_uid or os.getegid() != record.pw_gid or os.getgroups():
        raise AgentFailure("agent_privilege_invalid")
    return record.pw_uid, record.pw_gid


def main(argv: list[str]) -> int:
    global _ENGINE, _HEALTH_FD, _CACHE_DIR_FD
    if len(argv) != 3 or argv[1] != "--manifest" or not argv[2].startswith("/"):
        return 64
    os.umask(0o077)
    lock_fd = -1
    master = bytearray()
    agent_token = bytearray()
    try:
        _harden_process()
        manifest, manifest_path = _load_manifest(argv[2])
        lock_fd = _instance_lock(manifest)
        _HEALTH_FD = _prepare_health(manifest)
        _CACHE_DIR_FD = _prepare_cache(manifest)
        master, agent_token = _read_channel_secret(manifest)
        _, agent_gid = _drop_to_agent(manifest)
        _ENGINE = EngineIPC(manifest, agent_gid)
    except AgentFailure:
        for secret in (master, agent_token):
            for index in range(len(secret)):
                secret[index] = 0
        if lock_fd >= 0:
            os.close(lock_fd)
        if _HEALTH_FD >= 0:
            os.close(_HEALTH_FD)
            _HEALTH_FD = -1
        if _CACHE_DIR_FD >= 0:
            os.close(_CACHE_DIR_FD)
            _CACHE_DIR_FD = -1
        return 65
    _write_health(manifest, "starting", manifest["generation"])
    live = {
        "generation": manifest["generation"],
        "phase": "quarantined",
        "structuralApplied": False,
        "dataPlaneVerified": False,
        "selectedNode": "",
        "nodeCount": 0,
        "nodes": [],
        "capabilities": {name: False for name in CAPABILITY_KEYS},
        "counters": {},
    }
    exit_code = 0
    exit_error = ""
    try:
        exit_code = _run(manifest, manifest_path, master, agent_token, live)
    except AgentFailure as exc:
        exit_error = exc.code
        _quarantine(manifest_path)
        _write_health(manifest, "quarantined", max(manifest["generation"], live["generation"]), exit_error)
        exit_code = 1
    finally:
        _stop_child()
        _quarantine(manifest_path)
        _write_health(manifest, "stopped", max(manifest["generation"], live["generation"]), exit_error)
        for secret in (master, agent_token):
            for index in range(len(secret)):
                secret[index] = 0
        os.close(lock_fd)
        os.close(_HEALTH_FD)
        _HEALTH_FD = -1
        os.close(_CACHE_DIR_FD)
        _CACHE_DIR_FD = -1
    return exit_code


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _signal_stop)
    signal.signal(signal.SIGINT, _signal_stop)
    signal.signal(signal.SIGHUP, _signal_stop)
    raise SystemExit(main(sys.argv))
