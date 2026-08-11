from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import stat
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional, Union


DEFAULT_IMAGE = "redroid/redroid:13.0.0_64only-latest"
_OBSOLETE_DEFAULT_IMAGES = frozenset({"redroid/redroid:13.0.0-latest"})
DEFAULT_ANDROID_ADB_PORT = 62111
DEFAULT_ANDROID_DAEMON_PORT = 18765
DEFAULT_ROOTD_PORT = 18767
DEFAULT_RUNTIME_TAG = "xenoid/redroid:local"
DEFAULT_GOOGLE_SERVICES_PROVIDER = "none"
DEFAULT_GOOGLE_SERVICES_RELEASE = "none"
MINDTHEGAPPS_RELEASE = "MindTheGapps-13.0.0-arm64-20231025_200931"
INSTANCE_SCHEMA_VERSION = 2
LEASE_SCHEMA_VERSION = 1
INSTANCE_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
RESOURCE_TAG_RE = re.compile(r"^[0-9a-f]{12}$")
_RESOURCE_TAG_DOMAIN = b"xenoid-instance/v1\0"
_LEASE_SLOTS = 1000
_ADB_PORT_BASE = 5555
_DAEMON_PORT_BASE = 18765
_INSTANCE_LABEL_PREFIX = "dev.xenoid"
_LEGACY_IDENTITY_FIELDS = {
    "container_name",
    "adb_port",
    "daemon_port",
    "data_dir",
    "android_data_volume",
    "network_enabled",
    "network_name",
    "network_subnet",
    "network_gateway",
    "network_ip",
    "network_mac",
}
_CONTROLLED_DOCKER_ARGS = {
    "--add-host",
    "--cgroupns",
    "--dns",
    "--dns-option",
    "--dns-search",
    "--entrypoint",
    "--hostname",
    "--ip",
    "--ip6",
    "--ipc",
    "--label",
    "--label-file",
    "--link",
    "--mac-address",
    "--mount",
    "--name",
    "--net",
    "--network",
    "--network-alias",
    "--platform",
    "--pid",
    "--privileged",
    "--publish",
    "--pull",
    "--publish-all",
    "--restart",
    "--rm",
    "--userns",
    "--uts",
    "--volume",
    "-P",
    "-l",
    "-p",
    "-v",
}


class InstanceError(RuntimeError):
    """Stable, redacted instance/config failure."""

    def __init__(self, code: str, message: Optional[str] = None):
        self.code = code
        super().__init__(message or code)

    def as_dict(self) -> dict[str, Any]:
        return {"ok": False, "error": self.code, "message": str(self)}


def _resource_tag(instance_id: str) -> str:
    return hashlib.sha256(_RESOURCE_TAG_DOMAIN + instance_id.encode("ascii")).hexdigest()[:12]


def _validated_uuid(value: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, AttributeError) as exc:
        raise InstanceError("instance_identity_mismatch", "invalid instance identity") from exc
    if parsed.version != 4 or str(parsed) != str(value).lower():
        raise InstanceError("instance_identity_mismatch", "instance identity must be canonical UUIDv4")
    return str(parsed)


def validate_instance_name(value: str) -> str:
    if not INSTANCE_NAME_RE.fullmatch(value or ""):
        raise InstanceError(
            "instance_identity_mismatch",
            "instance name must match [a-z][a-z0-9-]{0,31}",
        )
    return value


def select_instance_name(
    cli_value: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> str:
    values = os.environ if env is None else env
    return validate_instance_name(cli_value or values.get("XENOID_INSTANCE") or "default")


def _looks_like_project_root(path: Path) -> bool:
    return (
        (path / "src" / "xenoid").is_dir()
        or (path / "lib" / "xenoid").is_dir()
        or (path / "bin" / "xenoid").is_file()
    )


def resolve_project_root(
    value: Optional[Union[str, Path]] = None,
    env: Optional[Mapping[str, str]] = None,
) -> Path:
    values = os.environ if env is None else env
    raw: Union[str, Path]
    if value is not None:
        raw = value
    elif values.get("XENOID_PROJECT"):
        raw = values["XENOID_PROJECT"]
        if not Path(raw).expanduser().is_absolute():
            raise InstanceError("instance_identity_mismatch", "XENOID_PROJECT must be absolute")
    else:
        raw = Path(__file__).resolve().parents[2]
    root = Path(raw).expanduser().resolve()
    if not _looks_like_project_root(root):
        raise InstanceError("instance_identity_mismatch", "invalid Xenoid project root")
    return root


def default_state_home() -> Path:
    return (Path.home() / ".xenoid").resolve()


@dataclass(frozen=True)
class InstanceContext:
    instance_name: str
    instance_id: str
    project_root: Path
    config_path: Path
    state_root: Path
    resource_tag: str

    @property
    def short_id(self) -> str:
        return self.instance_id[:8]

    @property
    def registry_root(self) -> Path:
        return self.state_root.parent.parent

    def public_dict(self) -> dict[str, Any]:
        return {
            "instanceName": self.instance_name,
            "instanceId": self.short_id,
            "resourceTag": self.resource_tag,
        }


@dataclass(frozen=True)
class InstanceLease:
    schema_version: int
    instance_name: str
    instance_id: str
    resource_tag: str
    slot: int
    transaction_id: str
    state: str
    container_name: str
    network_name: str
    volume_name: str
    bridge_name: str
    host_veth: str
    proxy_veth: str
    host_adb_port: int
    host_daemon_port: int
    android_adb_port: int
    android_daemon_port: int
    rootd_port: int
    ipv4_subnet: str
    ipv4_gateway: str
    ipv4_address: str
    ipv6_subnet: str
    ipv6_gateway: str
    ipv6_address: str
    mac_address: str
    transfer_ipv4_subnet: str
    transfer_ipv4_host: str
    transfer_ipv4_proxy: str
    transfer_ipv6_subnet: str
    transfer_ipv6_host: str
    transfer_ipv6_proxy: str
    mark_base: int
    mark_mask: int
    route_tables: tuple[int, int, int, int]
    rule_priorities: tuple[int, int, int, int]

    @property
    def owner_labels(self) -> dict[str, str]:
        return {
            f"{_INSTANCE_LABEL_PREFIX}.owner": "xenoid",
            f"{_INSTANCE_LABEL_PREFIX}.schema": str(self.schema_version),
            f"{_INSTANCE_LABEL_PREFIX}.instance_id": self.instance_id,
            f"{_INSTANCE_LABEL_PREFIX}.instance_name": self.instance_name,
            f"{_INSTANCE_LABEL_PREFIX}.resource_tag": self.resource_tag,
        }

    @property
    def manifest_digest(self) -> str:
        payload = json.dumps(
            asdict(self),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(payload).hexdigest()

    @property
    def system_users(self) -> dict[str, str]:
        tag = self.resource_tag
        return {"fetcher": f"xpf{tag}", "compiler": f"xpc{tag}", "mihomo": f"xpm{tag}"}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "InstanceLease":
        values = dict(data)
        values["route_tables"] = tuple(int(x) for x in values.get("route_tables", ()))
        values["rule_priorities"] = tuple(int(x) for x in values.get("rule_priorities", ()))
        try:
            lease = cls(**values)
        except (TypeError, ValueError) as exc:
            raise InstanceError("resource_conflict", "invalid instance allocation") from exc
        _validate_lease(lease)
        return lease


@dataclass(frozen=True)
class XenoidConfig:
    instance_name: str
    instance_id: str
    schema_version: int = INSTANCE_SCHEMA_VERSION
    backend: str = "colima-docker"
    image: str = DEFAULT_IMAGE
    android_adb_port: int = DEFAULT_ANDROID_ADB_PORT
    extra_docker_args: list[str] = field(default_factory=list)
    runtime_image_tag: str = DEFAULT_RUNTIME_TAG
    auto_build_runtime_image: bool = False
    docker_context: str = ""
    google_services_provider: str = DEFAULT_GOOGLE_SERVICES_PROVIDER
    google_services_release: str = DEFAULT_GOOGLE_SERVICES_RELEASE
    network_dns_servers: list[str] = field(
        default_factory=lambda: ["1.1.1.1", "8.8.8.8"]
    )


def new_instance_config(
    instance_name: str,
    instance_id: str,
    overrides: Optional[Mapping[str, Any]] = None,
) -> XenoidConfig:
    values: dict[str, Any] = {
        "instance_name": validate_instance_name(instance_name),
        "instance_id": _validated_uuid(instance_id),
    }
    values.update({key: value for key, value in (overrides or {}).items() if value is not None})
    cfg = XenoidConfig(**values)
    _validate_config(cfg)
    return cfg


def _validate_config(cfg: XenoidConfig) -> None:
    validate_instance_name(cfg.instance_name)
    _validated_uuid(cfg.instance_id)
    if cfg.schema_version != INSTANCE_SCHEMA_VERSION:
        raise InstanceError("instance_identity_mismatch", "unsupported instance config schema")
    if cfg.backend not in {"colima-docker", "macos-colima", "linux-docker"}:
        raise InstanceError("resource_conflict", "unsupported backend")
    if not isinstance(cfg.google_services_provider, str) or not isinstance(cfg.google_services_release, str):
        raise InstanceError("google_services_spec_mismatch", "invalid Google services provider configuration")
    valid_google_pair = (
        cfg.google_services_provider == DEFAULT_GOOGLE_SERVICES_PROVIDER
        and cfg.google_services_release == DEFAULT_GOOGLE_SERVICES_RELEASE
    ) or (
        cfg.google_services_provider == "mindthegapps"
        and cfg.google_services_release == MINDTHEGAPPS_RELEASE
    )
    if not valid_google_pair:
        raise InstanceError("google_services_spec_mismatch", "unsupported Google services provider or release")
    if not isinstance(cfg.android_adb_port, int) or not 1024 <= cfg.android_adb_port <= 65535:
        raise InstanceError("resource_conflict", "invalid Android ADB port")
    if not isinstance(cfg.extra_docker_args, list) or not all(
        isinstance(value, str) for value in cfg.extra_docker_args
    ):
        raise InstanceError("resource_conflict", "extra_docker_args must be a string list")
    for argument in cfg.extra_docker_args:
        option = argument.split("=", 1)[0]
        attached_short = any(
            argument.startswith(short) and argument != short
            for short in ("-l", "-p", "-v")
        )
        if option in _CONTROLLED_DOCKER_ARGS or attached_short:
            raise InstanceError("resource_conflict", "extra_docker_args overrides managed identity")
    if not isinstance(cfg.network_dns_servers, list) or not cfg.network_dns_servers:
        raise InstanceError("resource_conflict", "network_dns_servers must not be empty")
    normalized: set[str] = set()
    for value in cfg.network_dns_servers:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise InstanceError("resource_conflict", "invalid network DNS address") from exc
        if (
            address.is_unspecified
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
        ):
            raise InstanceError("resource_conflict", "network DNS address is not routable")
        normalized.add(str(address))
    if len(normalized) != len(cfg.network_dns_servers):
        raise InstanceError("resource_conflict", "duplicate network DNS address")


def _validate_lease(lease: InstanceLease) -> None:
    validate_instance_name(lease.instance_name)
    instance_id = _validated_uuid(lease.instance_id)
    if lease.schema_version != LEASE_SCHEMA_VERSION:
        raise InstanceError("resource_conflict", "unsupported lease schema")
    if not RESOURCE_TAG_RE.fullmatch(lease.resource_tag) or lease.resource_tag != _resource_tag(instance_id):
        raise InstanceError("instance_tag_collision", "instance resource tag mismatch")
    if lease.slot < 0 or lease.slot >= _LEASE_SLOTS:
        raise InstanceError("resource_pool_exhausted", "invalid lease slot")
    expected = _lease_for_slot(lease.instance_name, instance_id, lease.slot, lease.transaction_id)
    for key, expected_value in asdict(expected).items():
        if key == "state":
            continue
        if asdict(lease).get(key) != expected_value:
            raise InstanceError("resource_conflict", "instance allocation does not match its slot")
    if lease.state not in {"pending", "committed"}:
        raise InstanceError("resource_conflict", "invalid lease state")


def _lease_for_slot(
    instance_name: str,
    instance_id: str,
    slot: int,
    transaction_id: Optional[str] = None,
    state: str = "committed",
) -> InstanceLease:
    tag = _resource_tag(instance_id)
    v4_base = int(ipaddress.ip_address("172.31.0.0")) + slot * 16
    v4_network = ipaddress.ip_network((v4_base, 28))
    transfer_base = int(ipaddress.ip_address("169.254.0.0")) + slot * 4
    transfer_network = ipaddress.ip_network((transfer_base, 30))
    ipv6_network = ipaddress.ip_network(f"fd78:656e:6f69:{slot:x}::/64")
    transfer_ipv6 = ipaddress.ip_network(f"fd78:7072:6f78:{slot:x}::/126")
    digest = bytearray(hashlib.sha256(instance_id.encode("ascii")).digest()[:6])
    digest[0] = (digest[0] & 0xFC) | 0x02
    mac = ":".join(f"{byte:02x}" for byte in digest)
    return InstanceLease(
        schema_version=LEASE_SCHEMA_VERSION,
        instance_name=instance_name,
        instance_id=instance_id,
        resource_tag=tag,
        slot=slot,
        transaction_id=transaction_id or uuid.uuid4().hex,
        state=state,
        container_name=f"xenoid-android-{tag}",
        network_name=f"xenoid-net-{tag}",
        volume_name=f"xenoid-data-{tag}",
        bridge_name=f"xbr{tag}",
        host_veth=f"xph{tag}",
        proxy_veth=f"xpp{tag}",
        host_adb_port=_ADB_PORT_BASE + slot,
        host_daemon_port=_DAEMON_PORT_BASE + slot,
        android_adb_port=DEFAULT_ANDROID_ADB_PORT,
        android_daemon_port=DEFAULT_ANDROID_DAEMON_PORT,
        rootd_port=DEFAULT_ROOTD_PORT,
        ipv4_subnet=str(v4_network),
        ipv4_gateway=str(v4_network.network_address + 1),
        ipv4_address=str(v4_network.network_address + 10),
        ipv6_subnet=str(ipv6_network),
        ipv6_gateway=str(ipv6_network.network_address + 1),
        ipv6_address=str(ipv6_network.network_address + 0x10),
        mac_address=mac,
        transfer_ipv4_subnet=str(transfer_network),
        transfer_ipv4_host=str(transfer_network.network_address + 1),
        transfer_ipv4_proxy=str(transfer_network.network_address + 2),
        transfer_ipv6_subnet=str(transfer_ipv6),
        transfer_ipv6_host=str(transfer_ipv6.network_address + 1),
        transfer_ipv6_proxy=str(transfer_ipv6.network_address + 2),
        mark_base=0xA0000000 | (slot << 8),
        mark_mask=0xFFFFFF00,
        route_tables=tuple(20000 + slot * 4 + offset for offset in range(4)),
        rule_priorities=tuple(30000 + slot * 4 + offset for offset in range(4)),
    )


def _context(
    project_root: Path,
    instance_name: str,
    instance_id: str,
    state_home: Optional[Union[str, Path]] = None,
) -> InstanceContext:
    root = Path(state_home).expanduser().resolve() if state_home else default_state_home()
    tag = _resource_tag(instance_id)
    return InstanceContext(
        instance_name=instance_name,
        instance_id=instance_id,
        project_root=project_root,
        config_path=project_root / ".xenoid" / "instances" / instance_name / "config.json",
        state_root=root / "instances" / instance_id,
        resource_tag=tag,
    )


def instance_config_path(
    project_root: Union[str, Path],
    instance_name: str,
) -> Path:
    return (
        Path(project_root).expanduser().resolve()
        / ".xenoid"
        / "instances"
        / validate_instance_name(instance_name)
        / "config.json"
    )


def _atomic_write(path: Path, payload: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(mode)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _atomic_json(path: Path, data: Mapping[str, Any], mode: int = 0o600) -> None:
    payload = json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ).encode() + b"\n"
    _atomic_write(path, payload, mode)


@contextmanager
def _registry_lock(registry_root: Path) -> Iterator[None]:
    registry_root.mkdir(parents=True, exist_ok=True)
    registry_root.chmod(0o700)
    path = registry_root / "registry.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _read_json_object(path: Path, error: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise InstanceError(error, "invalid instance state") from exc
    if not isinstance(data, dict):
        raise InstanceError(error, "instance state must be an object")
    return data


def _pending_lease(raw: Any) -> InstanceLease:
    if not isinstance(raw, dict) or set(raw) != {"lease", "configPath", "stateRoot"}:
        raise InstanceError("resource_conflict", "invalid pending instance transaction")
    return InstanceLease.from_dict(raw["lease"])


def _recover_pending_locked(registry_root: Path, registry: dict[str, Any]) -> None:
    changed = False
    for transaction_id, raw in list(registry["pending"].items()):
        lease = _pending_lease(raw)
        if lease.transaction_id != transaction_id or lease.state != "pending":
            raise InstanceError("resource_conflict", "invalid pending instance identity")
        expected_state = registry_root / "instances" / lease.instance_id
        state_root = Path(raw["stateRoot"])
        config_path = Path(raw["configPath"])
        if (
            not state_root.is_absolute()
            or state_root != expected_state
            or not config_path.is_absolute()
            or tuple(config_path.parts[-4:])
            != (".xenoid", "instances", lease.instance_name, "config.json")
        ):
            raise InstanceError("resource_conflict", "invalid pending instance path")
        allocation_path = state_root / "allocation.json"
        has_config = config_path.is_file()
        has_allocation = allocation_path.is_file()
        if not has_config and not has_allocation:
            registry["pending"].pop(transaction_id)
            changed = True
            continue
        if not has_config or not has_allocation:
            raise InstanceError("resource_conflict", "partial instance transaction requires repair")
        cfg = _config_from_dict(_read_json_object(config_path, "instance_identity_mismatch"))
        allocation = InstanceLease.from_dict(
            _read_json_object(allocation_path, "resource_conflict")
        )
        if (
            cfg.instance_name != lease.instance_name
            or cfg.instance_id != lease.instance_id
            or replace(allocation, state="pending") != lease
        ):
            raise InstanceError("resource_conflict", "pending instance transaction disagrees")
        committed = replace(lease, state="committed")
        existing = registry["leases"].get(lease.instance_id)
        if existing is not None and InstanceLease.from_dict(existing) != committed:
            raise InstanceError("resource_conflict", "pending instance lease conflicts")
        _atomic_json(allocation_path, asdict(committed))
        registry["leases"][lease.instance_id] = asdict(committed)
        registry["pending"].pop(transaction_id)
        changed = True
    if changed:
        _atomic_json(registry_root / "registry.json", registry)


def _read_registry(registry_root: Path) -> dict[str, Any]:
    path = registry_root / "registry.json"
    if not path.exists():
        return {"schemaVersion": 1, "leases": {}, "pending": {}}
    registry = _read_json_object(path, "resource_conflict")
    if (
        registry.get("schemaVersion") != 1
        or not isinstance(registry.get("leases"), dict)
        or not isinstance(registry.get("pending", {}), dict)
    ):
        raise InstanceError("resource_conflict", "unsupported client registry")
    registry.setdefault("pending", {})
    _recover_pending_locked(registry_root, registry)
    return registry


def _port_available(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        sock.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _slot_preference(legacy: Optional[Mapping[str, Any]]) -> Optional[int]:
    if not legacy:
        return None
    candidates: set[int] = set()
    for key, base in (("adb_port", _ADB_PORT_BASE), ("daemon_port", _DAEMON_PORT_BASE)):
        if key in legacy:
            value = legacy[key]
            if not isinstance(value, int):
                raise InstanceError("resource_conflict", "invalid legacy port preference")
            candidates.add(value - base)
    if not candidates:
        return None
    if len(candidates) != 1:
        raise InstanceError("resource_conflict", "legacy port preferences disagree")
    slot = candidates.pop()
    if slot < 0 or slot >= _LEASE_SLOTS:
        raise InstanceError("resource_conflict", "legacy port preference is outside the pool")
    return slot


def _allocate_lease_locked(
    registry: dict[str, Any],
    instance_name: str,
    instance_id: str,
    preferred_slot: Optional[int],
    allow_bound_preference: bool,
) -> InstanceLease:
    leases = registry["leases"]
    tag = _resource_tag(instance_id)
    for raw in leases.values():
        existing = InstanceLease.from_dict(raw)
        if existing.resource_tag == tag and existing.instance_id != instance_id:
            raise InstanceError("instance_tag_collision", "resource tag already belongs to another identity")
        if existing.instance_name == instance_name and existing.instance_id != instance_id:
            raise InstanceError("resource_conflict", "instance name already has another identity")
    if instance_id in leases:
        lease = InstanceLease.from_dict(leases[instance_id])
        if lease.instance_name != instance_name or lease.resource_tag != tag:
            raise InstanceError("instance_identity_mismatch", "registry identity mismatch")
        return lease
    used_slots = {
        InstanceLease.from_dict(raw).slot for raw in leases.values()
    } | {
        _pending_lease(raw).slot for raw in registry.get("pending", {}).values()
    }
    candidates = [preferred_slot] if preferred_slot is not None else []
    candidates.extend(slot for slot in range(_LEASE_SLOTS) if slot != preferred_slot)
    for slot in candidates:
        if slot is None or slot in used_slots:
            if preferred_slot == slot:
                raise InstanceError("resource_conflict", "preferred instance slot is occupied")
            continue
        candidate = _lease_for_slot(instance_name, instance_id, slot)
        ports_available = _port_available(candidate.host_adb_port) and _port_available(
            candidate.host_daemon_port
        )
        if not ports_available and not (allow_bound_preference and slot == preferred_slot):
            if preferred_slot == slot:
                raise InstanceError("resource_conflict", "preferred instance port is occupied")
            continue
        return candidate
    raise InstanceError("resource_pool_exhausted", "no free instance slot")


def _config_from_dict(data: Mapping[str, Any]) -> XenoidConfig:
    normalized = dict(data)
    if normalized.get("image") in _OBSOLETE_DEFAULT_IMAGES:
        normalized["image"] = DEFAULT_IMAGE
    allowed = set(XenoidConfig.__dataclass_fields__)
    unknown = set(normalized) - allowed
    if unknown:
        raise InstanceError("instance_identity_mismatch", "unknown instance config field")
    try:
        cfg = XenoidConfig(**normalized)
    except TypeError as exc:
        raise InstanceError("instance_identity_mismatch", "invalid instance config") from exc
    _validate_config(cfg)
    return cfg


def _write_instance_transaction(
    context: InstanceContext,
    cfg: XenoidConfig,
    lease: InstanceLease,
    registry: dict[str, Any],
    legacy: Optional[Mapping[str, Any]] = None,
    *,
    initialize_identity: bool = True,
) -> InstanceLease:
    context.state_root.mkdir(parents=True, exist_ok=True)
    context.state_root.chmod(0o700)
    allocation_path = context.state_root / "allocation.json"
    registry_path = context.registry_root / "registry.json"
    pending = replace(lease, state="pending")
    committed = replace(lease, state="committed")
    registry.setdefault("pending", {})[lease.transaction_id] = {
        "lease": asdict(pending),
        "configPath": str(context.config_path),
        "stateRoot": str(context.state_root),
    }
    _atomic_json(registry_path, registry)
    try:
        _atomic_json(allocation_path, asdict(pending))
        _atomic_json(context.config_path, asdict(cfg))
        if legacy:
            _atomic_json(
                context.state_root / "legacy-engine.json",
                {key: legacy[key] for key in sorted(_LEGACY_IDENTITY_FIELDS) if key in legacy},
            )
        if initialize_identity:
            from .device_identity import DeviceIdentityStore

            DeviceIdentityStore(context).initialize()
        registry["leases"][context.instance_id] = asdict(committed)
        registry["pending"].pop(lease.transaction_id, None)
        _atomic_json(allocation_path, asdict(committed))
        _atomic_json(registry_path, registry)
        return committed
    except Exception:
        registry["pending"].pop(lease.transaction_id, None)
        registry["leases"].pop(context.instance_id, None)
        _atomic_json(registry_path, registry)
        for path in (
            allocation_path,
            context.config_path,
            context.state_root / "device-identity.json",
        ):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise


def _config_template_overrides(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise InstanceError("instance_identity_mismatch", "instance config template must be an object")
    allowed = set(XenoidConfig.__dataclass_fields__) - {
        "instance_name",
        "instance_id",
        "schema_version",
        "android_adb_port",
    }
    unknown = set(raw) - allowed
    if unknown:
        raise InstanceError("instance_identity_mismatch", "unknown instance config template field")
    return {key: raw[key] for key in allowed & set(raw)}


def _clone_config_overrides(source: XenoidConfig) -> dict[str, Any]:
    values = asdict(source)
    excluded = {"instance_name", "instance_id", "schema_version", "android_adb_port"}
    return {key: values[key] for key in values if key not in excluded}


def initialize_instance(
    instance_name: Optional[str] = None,
    *,
    project_root: Optional[Union[str, Path]] = None,
    state_home: Optional[Union[str, Path]] = None,
    overrides: Optional[Mapping[str, Any]] = None,
    template_path: Optional[Union[str, Path]] = None,
    from_instance: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> tuple[InstanceContext, XenoidConfig, InstanceLease]:
    name = select_instance_name(instance_name, env)
    root = resolve_project_root(project_root, env)
    if name == "default" and (root / ".xenoid" / "config.json").is_file():
        return _migrate_legacy_default(root, state_home)
    if template_path is not None and from_instance is not None:
        raise InstanceError("resource_conflict", "init template and source instance are mutually exclusive")
    if overrides and from_instance is not None:
        raise InstanceError("resource_conflict", "init source and direct overrides are mutually exclusive")
    config_path = instance_config_path(root, name)
    registry_root = Path(state_home).expanduser().resolve() if state_home else default_state_home()
    with _registry_lock(registry_root):
        if config_path.exists():
            raise InstanceError("resource_conflict", "instance is already initialized")
        instance_id = str(uuid.uuid4())
        context = _context(root, name, instance_id, registry_root)
        resolved_overrides: dict[str, Any] = {}
        if template_path is not None:
            template = _read_json_object(
                Path(template_path).expanduser().resolve(),
                "instance_identity_mismatch",
            )
            resolved_overrides = _config_template_overrides(template)
            if overrides:
                unknown_override = set(overrides) - resolved_overrides
                if unknown_override:
                    raise InstanceError("resource_conflict", "init overrides are not allowed with a template")
                resolved_overrides.update(overrides)
        elif from_instance is not None:
            source_name = validate_instance_name(from_instance)
            if source_name == name:
                raise InstanceError("resource_conflict", "init source must be a different instance")
            source_config_path = instance_config_path(root, source_name)
            source_cfg = _config_from_dict(
                _read_json_object(source_config_path, "instance_identity_mismatch")
            )
            if source_cfg.instance_name != source_name:
                raise InstanceError("instance_identity_mismatch", "source instance config mismatch")
            resolved_overrides = _clone_config_overrides(source_cfg)
        elif overrides:
            resolved_overrides = dict(overrides)
        cfg = new_instance_config(name, instance_id, resolved_overrides)
        registry = _read_registry(registry_root)
        lease = _allocate_lease_locked(registry, name, instance_id, None, False)
        lease = _write_instance_transaction(context, cfg, lease, registry)
    return context, cfg, lease


def _legacy_policy_and_identity(data: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    policy_keys = set(XenoidConfig.__dataclass_fields__) - {
        "instance_name",
        "instance_id",
        "schema_version",
    }
    policy = {key: value for key, value in data.items() if key in policy_keys}
    identity = {key: value for key, value in data.items() if key in _LEGACY_IDENTITY_FIELDS}
    unknown = set(data) - policy_keys - _LEGACY_IDENTITY_FIELDS
    if unknown:
        raise InstanceError("instance_identity_mismatch", "unknown legacy config field")
    return policy, identity


def _copy_legacy_state(project_root: Path, context: InstanceContext) -> None:
    legacy_root = project_root / ".xenoid"
    sources = [legacy_root / name for name in ("daemon.token", "rootd.token", "logs", "ota", "frida")]
    for source in sources:
        if source.is_symlink():
            raise InstanceError("resource_conflict", "legacy state contains a symlink")
        if source.is_dir():
            for candidate in source.rglob("*"):
                if candidate.is_symlink():
                    raise InstanceError("resource_conflict", "legacy state contains a symlink")
    for name in ("daemon.token", "rootd.token"):
        source = legacy_root / name
        destination = context.state_root / name
        if source.is_file() and not destination.exists():
            _atomic_write(destination, source.read_bytes(), 0o600)
    for name in ("logs", "ota", "frida"):
        source = legacy_root / name
        destination = context.state_root / name
        if source.is_dir() and not destination.exists():
            shutil.copytree(source, destination, symlinks=False)


def _migrate_legacy_default(
    project_root: Path,
    state_home: Optional[Union[str, Path]],
) -> tuple[InstanceContext, XenoidConfig, InstanceLease]:
    legacy_path = project_root / ".xenoid" / "config.json"
    target = instance_config_path(project_root, "default")
    if not legacy_path.is_file() or target.exists():
        raise InstanceError("instance_not_initialized")
    legacy_data = _read_json_object(legacy_path, "instance_identity_mismatch")
    policy, identity = _legacy_policy_and_identity(legacy_data)
    registry_root = Path(state_home).expanduser().resolve() if state_home else default_state_home()
    with _registry_lock(registry_root):
        if target.exists():
            raise InstanceError("resource_conflict", "concurrent legacy migration conflict")
        instance_id = str(uuid.uuid4())
        context = _context(project_root, "default", instance_id, registry_root)
        cfg = new_instance_config("default", instance_id, policy)
        registry = _read_registry(registry_root)
        preference = _slot_preference(identity)
        lease = _allocate_lease_locked(registry, "default", instance_id, preference, True)
        if identity.get("network_enabled"):
            expected = _lease_for_slot("default", instance_id, lease.slot, lease.transaction_id)
            comparisons = {
                "network_subnet": expected.ipv4_subnet,
                "network_gateway": expected.ipv4_gateway,
                "network_ip": expected.ipv4_address,
                "network_mac": expected.mac_address,
            }
            if any(
                key in identity and str(identity[key]).lower() != value.lower()
                for key, value in comparisons.items()
            ):
                raise InstanceError("resource_conflict", "legacy network identity conflicts with managed lease")
        _copy_legacy_state(project_root, context)
        lease = _write_instance_transaction(
            context,
            cfg,
            lease,
            registry,
            identity,
            initialize_identity=False,
        )
        _atomic_json(
            context.state_root / "migration.json",
            {
                "schemaVersion": 1,
                "legacyConfigSha256": hashlib.sha256(legacy_path.read_bytes()).hexdigest(),
                "instanceId": instance_id,
            },
        )
    return context, cfg, lease


def resolve_instance(
    instance_name: Optional[str] = None,
    *,
    project_root: Optional[Union[str, Path]] = None,
    state_home: Optional[Union[str, Path]] = None,
    env: Optional[Mapping[str, str]] = None,
    migrate_legacy: bool = True,
) -> tuple[InstanceContext, XenoidConfig, InstanceLease]:
    name = select_instance_name(instance_name, env)
    root = resolve_project_root(project_root, env)
    path = instance_config_path(root, name)
    if not path.exists():
        if name == "default" and migrate_legacy and (root / ".xenoid" / "config.json").is_file():
            return _migrate_legacy_default(root, state_home)
        raise InstanceError("instance_not_initialized", f"instance {name} is not initialized")
    cfg = _config_from_dict(_read_json_object(path, "instance_identity_mismatch"))
    if cfg.instance_name != name:
        raise InstanceError("instance_identity_mismatch", "instance selector does not match config")
    instance_id = _validated_uuid(cfg.instance_id)
    context = _context(root, name, instance_id, state_home)
    if context.config_path != path or context.resource_tag != _resource_tag(instance_id):
        raise InstanceError("instance_identity_mismatch", "resolved instance identity mismatch")
    legacy_path = root / ".xenoid" / "config.json"
    if name == "default" and legacy_path.is_file():
        marker_path = context.state_root / "migration.json"
        marker = (
            _read_json_object(marker_path, "instance_identity_mismatch")
            if marker_path.is_file()
            else {}
        )
        if (
            marker.get("instanceId") != context.instance_id
            or marker.get("legacyConfigSha256")
            != hashlib.sha256(legacy_path.read_bytes()).hexdigest()
        ):
            raise InstanceError(
                "instance_identity_mismatch",
                "legacy and instance configs do not belong to one migration",
            )
    allocation_path = context.state_root / "allocation.json"
    with _registry_lock(context.registry_root):
        registry = _read_registry(context.registry_root)
        if not allocation_path.is_file():
            raise InstanceError("resource_conflict", "instance allocation is missing")
        lease = InstanceLease.from_dict(
            _read_json_object(allocation_path, "resource_conflict")
        )
        if (
            lease.instance_id != context.instance_id
            or lease.instance_name != context.instance_name
            or lease.resource_tag != context.resource_tag
        ):
            raise InstanceError("instance_identity_mismatch", "allocation belongs to another instance")
        raw = registry["leases"].get(context.instance_id)
        if raw is None:
            raise InstanceError("resource_conflict", "client registry lease is missing")
        registered = InstanceLease.from_dict(raw)
        if registered != lease:
            raise InstanceError("resource_conflict", "client registry and allocation disagree")
    from .device_identity import DeviceIdentityStore

    identity_store = DeviceIdentityStore(context)
    if (context.state_root / "migration.json").is_file():
        if identity_store.path.exists():
            identity_store.load()
    else:
        identity_store.initialize()
    return context, cfg, lease


def load_config(context: InstanceContext) -> XenoidConfig:
    cfg = _config_from_dict(_read_json_object(context.config_path, "instance_identity_mismatch"))
    if cfg.instance_name != context.instance_name or cfg.instance_id != context.instance_id:
        raise InstanceError("instance_identity_mismatch", "config belongs to another instance")
    return cfg


def save_config(context: InstanceContext, cfg: XenoidConfig) -> Path:
    _validate_config(cfg)
    if cfg.instance_name != context.instance_name or cfg.instance_id != context.instance_id:
        raise InstanceError("instance_identity_mismatch", "cannot change instance identity")
    _atomic_json(context.config_path, asdict(cfg))
    return context.config_path


def merge_config(
    context: InstanceContext,
    overrides: Mapping[str, Any],
) -> XenoidConfig:
    cfg = load_config(context)
    immutable = {"instance_name", "instance_id", "schema_version"}
    if any(key in immutable for key in overrides):
        raise InstanceError("instance_identity_mismatch", "instance identity is immutable")
    data = asdict(cfg)
    data.update({key: value for key, value in overrides.items() if value is not None})
    unknown = set(data) - set(XenoidConfig.__dataclass_fields__)
    if unknown:
        raise InstanceError("resource_conflict", "unknown config field")
    merged = XenoidConfig(**data)
    _validate_config(merged)
    return merged


def list_instances(
    *,
    project_root: Optional[Union[str, Path]] = None,
    state_home: Optional[Union[str, Path]] = None,
    env: Optional[Mapping[str, str]] = None,
) -> list[dict[str, Any]]:
    root = resolve_project_root(project_root, env)
    instances_root = root / ".xenoid" / "instances"
    if not instances_root.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for child in sorted(instances_root.iterdir(), key=lambda path: path.name):
        if not child.is_dir() or not INSTANCE_NAME_RE.fullmatch(child.name):
            continue
        try:
            context, _, lease = resolve_instance(
                child.name,
                project_root=root,
                state_home=state_home,
                env=env,
                migrate_legacy=False,
            )
            rows.append({**context.public_dict(), "slot": lease.slot, "state": lease.state})
        except InstanceError as exc:
            rows.append({"instanceName": child.name, "ok": False, "error": exc.code})
    return rows
