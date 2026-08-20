#!/usr/bin/env python3
"""Deterministic, runtime-free instance identity and lease contracts.

Later proxy contract cases should use ``contract_case`` and ``isolated_roots`` so
all mutable state remains inside a fresh temporary project and client state root.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import stat
import sys
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from xenoid import backend, cli, config, location


ID_A = "10000000-0000-4000-8000-000000000001"
ID_B = "10000000-0000-4000-8000-000000000002"
TX_A = "20000000-0000-4000-8000-000000000001"
TX_B = "20000000-0000-4000-8000-000000000002"


class ContractFailure(AssertionError):
    pass


@dataclass(frozen=True)
class Roots:
    project: Path
    state: Path


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


def require_error(code: str, action: Callable[[], Any]) -> None:
    try:
        action()
    except config.InstanceError as exc:
        require(exc.code == code)
    else:
        raise ContractFailure


@contextmanager
def isolated_roots() -> Iterator[Roots]:
    with tempfile.TemporaryDirectory(prefix="xenoid-contract-") as directory:
        base = Path(directory)
        project = base / "project"
        state = base / "state"
        (project / "src" / "xenoid").mkdir(parents=True)
        # Allocation must never inspect or bind real loopback ports in this suite.
        with mock.patch.object(config, "_port_available", return_value=True):
            yield Roots(project=project, state=state)


@contextmanager
def fixed_uuids(*values: str) -> Iterator[None]:
    sequence = [uuid.UUID(value) for value in values]
    with mock.patch.object(config.uuid, "uuid4", side_effect=sequence):
        yield


def initialize(
    roots: Roots,
    name: str,
    overrides: dict[str, Any] | None = None,
) -> tuple[config.InstanceContext, config.XenoidConfig, config.InstanceLease]:
    return config.initialize_instance(
        name,
        project_root=roots.project,
        state_home=roots.state,
        overrides=overrides,
        env={},
    )


def resolve(
    roots: Roots,
    name: str,
    *,
    migrate_legacy: bool = False,
) -> tuple[config.InstanceContext, config.XenoidConfig, config.InstanceLease]:
    return config.resolve_instance(
        name,
        project_root=roots.project,
        state_home=roots.state,
        env={},
        migrate_legacy=migrate_legacy,
    )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def expected_tag(instance_id: str) -> str:
    return hashlib.sha256(
        b"xenoid-instance/v1\0" + instance_id.encode("ascii")
    ).hexdigest()[:12]


def expected_mac(instance_id: str) -> str:
    digest = bytearray(hashlib.sha256(instance_id.encode("ascii")).digest()[:6])
    digest[0] = (digest[0] & 0xFC) | 0x02
    return ":".join(f"{byte:02x}" for byte in digest)


@contract_case("selectorPrecedenceAndRegex")
def selector_precedence_and_regex() -> None:
    require(
        config.select_instance_name("cli-name", {"XENOID_INSTANCE": "env-name"})
        == "cli-name"
    )
    require(config.select_instance_name(None, {"XENOID_INSTANCE": "env-name"}) == "env-name")
    require(config.select_instance_name(None, {}) == "default")
    require(config.validate_instance_name("a") == "a")
    require(config.validate_instance_name("a" + "0" * 31) == "a" + "0" * 31)
    for invalid in ("", "A", "0phone", "phone_a", "phone.a", "a" + "0" * 32):
        require_error("instance_identity_mismatch", lambda value=invalid: config.validate_instance_name(value))


@contract_case("contextConfigStateAndTag")
def context_config_state_and_tag() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(roots, "phone-a")
        tag = expected_tag(ID_A)
        require(context.instance_name == "phone-a")
        require(context.instance_id == ID_A)
        require(context.project_root == roots.project.resolve())
        require(
            context.config_path
            == roots.project.resolve() / ".xenoid" / "instances" / "phone-a" / "config.json"
        )
        require(context.state_root == roots.state.resolve() / "instances" / ID_A)
        require(context.registry_root == roots.state.resolve())
        require(context.resource_tag == tag == lease.resource_tag)
        require(cfg.instance_name == context.instance_name and cfg.instance_id == context.instance_id)
        require(config.load_config(context) == cfg)
        require((context.state_root / "allocation.json").is_file())
        location_state = location.LocationStateStore(context.state_root).load()
        require(location_state is not None)
        require(location_state["instanceId"] == ID_A)
        require(location_state["desiredCountry"] == location.DEFAULT_COUNTRY)
        require(location_state["active"] is None)
        require(
            isinstance(location_state["pending"], dict)
            and location_state["pending"]["country"] == location.DEFAULT_COUNTRY
            and location_state["pending"]["phase"] == "new"
        )
        require((roots.state / "registry.json").is_file())
        for directory in (context.config_path.parent, context.state_root, roots.state):
            require(stat.S_IMODE(directory.stat().st_mode) == 0o700)
        for private_file in (
            context.config_path,
            context.state_root / "allocation.json",
            context.state_root / location.STATE_FILENAME,
            roots.state / "registry.json",
        ):
            require(stat.S_IMODE(private_file.stat().st_mode) == 0o600)


@contract_case("networkEpochRotation")
def network_epoch_rotation() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A):
        context, _, lease = initialize(roots, "phone-a")
        require(lease.network_epoch == "")
        first_target = "11" * 16
        rotated = config.rotate_instance_network(
            context,
            target_epoch=first_target,
            expected_epoch="",
        )
        require(rotated.network_epoch == first_target)
        require(rotated.mac_address != lease.mac_address)
        require(
            (rotated.slot, rotated.ipv4_address, rotated.ipv6_address)
            == (lease.slot, lease.ipv4_address, lease.ipv6_address)
        )
        require(
            (rotated.host_adb_port, rotated.host_daemon_port, rotated.transaction_id)
            == (lease.host_adb_port, lease.host_daemon_port, lease.transaction_id)
        )
        first_octet = int(rotated.mac_address.split(":", 1)[0], 16)
        require(first_octet & 0x03 == 0x02)
        require(resolve(roots, "phone-a")[2] == rotated)
        retried = config.rotate_instance_network(
            context,
            target_epoch=first_target,
            expected_epoch="",
        )
        require(retried == rotated)
        second_target = "22" * 16
        again = config.rotate_instance_network(
            context,
            target_epoch=second_target,
            expected_epoch=first_target,
        )
        require(again.network_epoch == second_target)
        require(again.mac_address != rotated.mac_address)
        require(resolve(roots, "phone-a")[2] == again)
        require_error(
            "device_regeneration_state_invalid",
            lambda: config.rotate_instance_network(
                context,
                target_epoch=first_target,
                expected_epoch="",
            ),
        )


def _crash_rotation_at_write(target_write: int) -> Callable[[Any, Any, int], Any]:
    calls = {"count": 0}
    real_atomic = config._atomic_json

    def flaky(path: Any, data: Any, mode: int = 0o600) -> Any:
        calls["count"] += 1
        if calls["count"] == target_write:
            raise RuntimeError("simulated power loss")
        return real_atomic(path, data, mode)

    return flaky


def _require_rotation_recovered(
    roots: Roots,
    context: config.InstanceContext,
    original: config.InstanceLease,
) -> None:
    resolved = resolve(roots, "phone-a")[2]
    require(resolved.network_epoch != "")
    require(resolved.mac_address != original.mac_address)
    require(resolved.slot == original.slot)
    require(resolved.ipv4_address == original.ipv4_address)
    registry = json.loads((roots.state / "registry.json").read_text())
    require(registry["pending"] == {})
    require(
        config.InstanceLease.from_dict(registry["leases"][context.instance_id])
        == resolved
    )
    allocation = config.InstanceLease.from_dict(
        json.loads((context.state_root / "allocation.json").read_text())
    )
    require(allocation == resolved)


@contract_case("networkEpochRotationCrashBeforeAllocation")
def network_epoch_rotation_crash_before_allocation() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A):
        context, _, lease = initialize(roots, "phone-a")
        with mock.patch.object(
            config, "_atomic_json", side_effect=_crash_rotation_at_write(2)
        ):
            try:
                config.rotate_instance_network(
                    context,
                    target_epoch="33" * 16,
                    expected_epoch="",
                )
            except RuntimeError:
                pass
            else:
                raise ContractFailure
        _require_rotation_recovered(roots, context, lease)


@contract_case("networkEpochRotationCrashBeforeCommit")
def network_epoch_rotation_crash_before_commit() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A):
        context, _, lease = initialize(roots, "phone-a")
        with mock.patch.object(
            config, "_atomic_json", side_effect=_crash_rotation_at_write(3)
        ):
            try:
                config.rotate_instance_network(
                    context,
                    target_epoch="44" * 16,
                    expected_epoch="",
                )
            except RuntimeError:
                pass
            else:
                raise ContractFailure
        _require_rotation_recovered(roots, context, lease)


@contract_case("networkEpochRotationRejectsTamperedPending")
def network_epoch_rotation_rejects_tampered_pending() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A):
        context, _, lease = initialize(roots, "phone-a")
        config.rotate_instance_network(
            context,
            target_epoch="55" * 16,
            expected_epoch="",
        )
        registry_path = roots.state / "registry.json"
        registry = json.loads(registry_path.read_text())
        forged = config._lease_for_slot("phone-a", ID_A, 1, TX_A)
        registry["pending"][TX_A] = {
            "lease": asdict(replace(forged, state="pending")),
            "configPath": str(context.config_path),
            "stateRoot": str(context.state_root),
        }
        registry_path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n")
        require_error("resource_conflict", lambda: resolve(roots, "phone-a"))


@contract_case("independentStableLeases")
def independent_stable_leases() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A, ID_B, TX_B):
        context_a, _, lease_a = initialize(roots, "phone-a")
        context_b, _, lease_b = initialize(roots, "phone-b")
        require((lease_a.slot, lease_b.slot) == (0, 1))
        require((lease_a.host_adb_port, lease_b.host_adb_port) == (5555, 5556))
        require((lease_a.host_daemon_port, lease_b.host_daemon_port) == (18765, 18766))
        require(
            (lease_a.ipv4_subnet, lease_a.ipv4_gateway, lease_a.ipv4_address)
            == ("172.31.0.0/28", "172.31.0.1", "172.31.0.10")
        )
        require(
            (lease_b.ipv4_subnet, lease_b.ipv4_gateway, lease_b.ipv4_address)
            == ("172.31.0.16/28", "172.31.0.17", "172.31.0.26")
        )
        require(lease_a.ipv6_subnet == "fd78:656e:6f69::/64")
        require(lease_a.ipv6_gateway == "fd78:656e:6f69::1")
        require(lease_a.ipv6_address == "fd78:656e:6f69::10")
        require(lease_b.ipv6_subnet == "fd78:656e:6f69:1::/64")
        require(lease_b.ipv6_address == "fd78:656e:6f69:1::10")
        require(
            (lease_a.transfer_ipv4_subnet, lease_a.transfer_ipv4_host, lease_a.transfer_ipv4_proxy)
            == ("169.254.0.0/30", "169.254.0.1", "169.254.0.2")
        )
        require(
            (lease_b.transfer_ipv4_subnet, lease_b.transfer_ipv4_host, lease_b.transfer_ipv4_proxy)
            == ("169.254.0.4/30", "169.254.0.5", "169.254.0.6")
        )
        require(lease_a.mac_address == expected_mac(ID_A))
        require(lease_b.mac_address == expected_mac(ID_B))
        require(lease_a.mac_address != lease_b.mac_address)
        for lease in (lease_a, lease_b):
            first_octet = int(lease.mac_address.split(":", 1)[0], 16)
            require(first_octet & 0x03 == 0x02)
            tag = lease.resource_tag
            require(lease.container_name == f"xenoid-android-{tag}")
            require(lease.network_name == f"xenoid-net-{tag}")
            require(lease.volume_name == f"xenoid-data-{tag}")
            require(lease.bridge_name == f"xbr{tag}")
            require(lease.host_veth == f"xph{tag}")
            require(lease.proxy_veth == f"xpp{tag}")
            require(max(map(len, (lease.bridge_name, lease.host_veth, lease.proxy_veth))) <= 15)
        require((lease_a.mark_base, lease_b.mark_base) == (0xA0000000, 0xA0000100))
        require(lease_a.mark_mask == lease_b.mark_mask == 0xFFFFFF00)
        require(lease_a.route_tables == (20000, 20001, 20002, 20003))
        require(lease_b.route_tables == (20004, 20005, 20006, 20007))
        require(lease_a.rule_priorities == (30000, 30001, 30002, 30003))
        require(lease_b.rule_priorities == (30004, 30005, 30006, 30007))
        require(resolve(roots, "phone-a") == (context_a, config.load_config(context_a), lease_a))
        require(resolve(roots, "phone-b") == (context_b, config.load_config(context_b), lease_b))


@contract_case("immutableIdentityAndMismatch")
def immutable_identity_and_mismatch() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A):
        context, cfg, _ = initialize(roots, "phone-a")
        require_error(
            "instance_identity_mismatch",
            lambda: config.merge_config(context, {"instance_id": ID_B}),
        )
        require_error(
            "instance_identity_mismatch",
            lambda: config.merge_config(context, {"instance_name": "phone-b"}),
        )
        require_error(
            "instance_identity_mismatch",
            lambda: config.save_config(context, replace(cfg, instance_id=ID_B)),
        )
        write_json(context.config_path, asdict(replace(cfg, instance_name="phone-b")))
        require_error("instance_identity_mismatch", lambda: config.load_config(context))
        require_error("instance_identity_mismatch", lambda: resolve(roots, "phone-a"))


@contract_case("missingInstance")
def missing_instance() -> None:
    with isolated_roots() as roots:
        require_error("instance_not_initialized", lambda: resolve(roots, "phone-a"))
        require_error(
            "instance_not_initialized",
            lambda: config.resolve_instance(
                "default",
                project_root=roots.project,
                state_home=roots.state,
                env={},
                migrate_legacy=True,
            ),
        )


@contract_case("controlledDockerArgs")
def controlled_docker_args() -> None:
    rejected = (
        "--name=foreign",
        "--network=host",
        "--network-alias=foreign",
        "--ip=192.0.2.10",
        "--ip6=2001:db8::10",
        "--mac-address=02:00:00:00:00:01",
        "--publish=5000:5000",
        "-p",
        "--volume=/tmp:/data",
        "-v",
        "--restart=always",
        "--rm",
        "--label=owner=foreign",
    )
    for argument in rejected:
        require_error(
            "resource_conflict",
            lambda value=argument: config.new_instance_config(
                "phone-a", ID_A, {"extra_docker_args": [value]}
            ),
        )
    allowed = config.new_instance_config(
        "phone-a", ID_A, {"extra_docker_args": ["--cpus=2"]}
    )
    require(allowed.extra_docker_args == ["--cpus=2"])


@contract_case("legacyDefaultMigrationOnce")
def legacy_default_migration_once() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A):
        legacy_path = roots.project / ".xenoid" / "config.json"
        write_json(
            legacy_path,
            {
                "backend": "linux-docker",
                "image": "legacy-image",
                "adb_port": 5562,
                "daemon_port": 18772,
                "container_name": "legacy-container",
            },
        )
        first = resolve(roots, "default", migrate_legacy=True)
        second = resolve(roots, "default", migrate_legacy=True)
        context, cfg, lease = first
        require(second == first)
        require(context.instance_id == ID_A and cfg.instance_id == ID_A)
        require(cfg.instance_name == "default" and cfg.backend == "linux-docker")
        require(lease.slot == 7 and lease.host_adb_port == 5562)
        require(context.config_path.is_file())
        require((context.state_root / "migration.json").is_file())
        require((context.state_root / "legacy-engine.json").is_file())
        registry = json.loads((roots.state / "registry.json").read_text())
        require(list(registry["leases"]) == [ID_A])


@contract_case("legacyAndInstanceConflict")
def legacy_and_instance_conflict() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A):
        legacy_path = roots.project / ".xenoid" / "config.json"
        write_json(
            legacy_path,
            {
                "backend": "linux-docker",
                "adb_port": 5562,
                "daemon_port": 18772,
            },
        )
        resolve(roots, "default", migrate_legacy=True)
        write_json(
            legacy_path,
            {
                "backend": "colima-docker",
                "adb_port": 5562,
                "daemon_port": 18772,
            },
        )
        require_error(
            "instance_identity_mismatch",
            lambda: resolve(roots, "default", migrate_legacy=True),
        )


@contract_case("failedReservationRollsBack")
def failed_reservation_rolls_back() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A):
        original = config._atomic_json

        def fail_config_write(path: Path, value: Any, mode: int = 0o600) -> None:
            if path.name == "config.json":
                raise OSError
            original(path, value, mode)

        with mock.patch.object(config, "_atomic_json", side_effect=fail_config_write):
            try:
                initialize(roots, "phone-a")
            except OSError:
                pass
            else:
                raise ContractFailure
        registry = json.loads((roots.state / "registry.json").read_text())
        require(registry["leases"] == {} and registry["pending"] == {})
        require(not config.instance_config_path(roots.project, "phone-a").exists())


@contract_case("pendingReservationRecovers")
def pending_reservation_recovers() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(roots, "phone-a")
        pending = replace(lease, state="pending")
        write_json(context.state_root / "allocation.json", asdict(pending))
        registry_path = roots.state / "registry.json"
        registry = json.loads(registry_path.read_text())
        registry["leases"] = {}
        registry["pending"] = {
            pending.transaction_id: {
                "lease": asdict(pending),
                "configPath": str(context.config_path),
                "stateRoot": str(context.state_root),
            }
        }
        write_json(registry_path, registry)
        recovered = resolve(roots, "phone-a")
        require(recovered == (context, cfg, lease))
        recovered_registry = json.loads(registry_path.read_text())
        require(recovered_registry["pending"] == {})
        require(recovered_registry["leases"][ID_A]["state"] == "committed")


@contract_case("allocationRegistryDisagreement")
def allocation_registry_disagreement() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A):
        context, _, lease = initialize(roots, "phone-a")
        conflicting = config._lease_for_slot(
            lease.instance_name,
            lease.instance_id,
            1,
            lease.transaction_id,
        )
        write_json(context.state_root / "allocation.json", asdict(conflicting))
        require_error("resource_conflict", lambda: resolve(roots, "phone-a"))


@contract_case("corruptAllocation")
def corrupt_allocation() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A):
        context, _, _ = initialize(roots, "phone-a")
        (context.state_root / "allocation.json").write_text("not-json\n")
        require_error("resource_conflict", lambda: resolve(roots, "phone-a"))


@contract_case("registryConflict")
def registry_conflict() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A):
        _, _, lease = initialize(roots, "phone-a")
        registry_path = roots.state / "registry.json"
        registry = json.loads(registry_path.read_text())
        registry["leases"][ID_A] = asdict(replace(lease, instance_name="phone-b"))
        write_json(registry_path, registry)
        require_error("resource_conflict", lambda: resolve(roots, "phone-a"))


@contract_case("resourceTagCollision")
def resource_tag_collision() -> None:
    shared_tag = "a" * 12
    with mock.patch.object(config, "_resource_tag", return_value=shared_tag), mock.patch.object(
        config, "_port_available", return_value=True
    ):
        existing = config._lease_for_slot("phone-a", ID_A, 0, TX_A.replace("-", ""))
        registry = {"schemaVersion": 1, "leases": {ID_A: asdict(existing)}}
        require_error(
            "instance_tag_collision",
            lambda: config._allocate_lease_locked(registry, "phone-b", ID_B, None, False),
        )


@contract_case("resourceNameConflict")
def resource_name_conflict() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A, ID_B):
        context, _, _ = initialize(roots, "phone-a")
        context.config_path.unlink()
        require_error("resource_conflict", lambda: initialize(roots, "phone-a"))


@contract_case("resourceSlotConflict")
def resource_slot_conflict() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A, ID_B):
        initialize(roots, "phone-a")
        write_json(
            roots.project / ".xenoid" / "config.json",
            {"adb_port": 5555, "daemon_port": 18765},
        )
        require_error(
            "resource_conflict",
            lambda: resolve(roots, "default", migrate_legacy=True),
        )


@contract_case("resourcePoolFailure")
def resource_pool_failure() -> None:
    fixed = uuid.UUID(ID_A)
    with isolated_roots() as roots, mock.patch.object(
        config.uuid, "uuid4", return_value=fixed
    ), mock.patch.object(config, "_LEASE_SLOTS", 3), mock.patch.object(
        config, "_port_available", return_value=False
    ):
        require_error("resource_pool_exhausted", lambda: initialize(roots, "phone-a"))


@contract_case("daemonProxyDesiredSurvivesUpdate")
def daemon_proxy_desired_survives_update() -> None:
    with isolated_roots() as roots, fixed_uuids(ID_A, TX_A):
        context, cfg, lease = initialize(roots, "phone-a")
        manager = backend.RuntimeManager(context, cfg, lease)
        source_value = "socks5" + "://user:secret@proxy.example:1080"
        restored_calls: list[tuple[Any, ...]] = []

        class Client:
            @staticmethod
            def bootstrap_status(timeout: float = 2.0) -> dict[str, Any]:
                require(timeout == 2.0)
                return {
                    "ok": True,
                    "components": {"proxy": {"ok": True}},
                }
            @staticmethod
            def proxy_export() -> dict[str, Any]:
                return {
                    "ok": True,
                    "instanceId": ID_A,
                    "enabled": True,
                    "source": {
                        "kind": "endpoint",
                        "value": source_value,
                        "selectedNode": "",
                        "udpAllowed": True,
                        "allowInsecureHttp": False,
                    },
                }

        class Controller:
            @staticmethod
            def set_source(
                kind: str,
                value: str,
                enabled: bool,
                *,
                selected_node: str,
                udp_allowed: bool,
                allow_insecure_http: bool,
            ) -> dict[str, Any]:
                restored_calls.append(
                    (
                        kind,
                        value,
                        enabled,
                        selected_node,
                        udp_allowed,
                        allow_insecure_http,
                    )
                )
                return {"ok": True}

        client = Client()
        with mock.patch.object(manager, "daemon_client", return_value=client):
            captured = manager._capture_proxy_desired_for_update()
        require(captured == {"ok": True, "captured": True, "configured": True})
        require(source_value not in json.dumps(captured))
        restored = manager._restore_proxy_desired_after_update(Controller())
        require(restored == {"ok": True, "restored": True})
        require(
            restored_calls
            == [("endpoint", source_value, True, "", True, False)]
        )
        require(manager._pending_proxy_restore is None)

@contract_case("proxyAgentKeyIsOneShot")
def proxy_agent_key_is_one_shot() -> None:
    staged: list[bytearray] = []
    root_actions: list[str] = []

    class Runtime(backend.RuntimeManager):
        def __init__(self) -> None:
            self.context = SimpleNamespace(
                instance_id=ID_A,
                resource_tag="fixturetag",
            )

        def ensure_instance_lease(self) -> None:
            return None

        def _proxy_live_identity(self) -> tuple[str, str]:
            return ("container-id", "network-id")

        def _proxy_manifest_document(
            self,
            runtime_epoch: str,
            generation: int,
            _container_id: str,
            _network_id: str,
        ) -> dict[str, Any]:
            return {
                "runtimeEpoch": runtime_epoch,
                "generation": generation,
            }

        def proxy_prerequisite(self, **_kwargs: Any) -> dict[str, Any]:
            return {"ok": True}

        def proxy_prepare_asset(self, _asset: Any) -> dict[str, Any]:
            return {"ok": True}

        def _proxy_read_manifest(self, **_kwargs: Any) -> None:
            return None

        def _proxy_root_json(self, action: str, **_kwargs: Any) -> dict[str, Any]:
            root_actions.append(action)
            return {"ok": True}

        def _proxy_stop_agent(self) -> bool:
            return True

        def _proxy_stage_manifest(self, _manifest: dict[str, Any]) -> None:
            return None

        def _proxy_stage_bytes(
            self, _path: str, payload: bytearray, _mode: int
        ) -> None:
            staged.append(payload)

        def _proxy_remote_regular_valid(self, _path: str, _mode: int) -> bool:
            return True

        def _proxy_root_process(
            self, _command: list[str], **_kwargs: Any
        ) -> tuple[int, bytes]:
            return (0, b"")

        def _proxy_root_simple(self, _command: list[str], **_kwargs: Any) -> bool:
            return True

        def _proxy_remote_exists(self, path: str) -> bool:
            require(path.endswith("/agent.key"))
            return False

        def _proxy_agent_active(self, _manifest: dict[str, Any]) -> bool:
            return True

    encoded = base64.b64encode(b"k" * 32).decode("ascii")
    result = Runtime().proxy_start_agent(
        runtime_epoch="v1-fixturetag-" + "1" * 32,
        generation=7,
        master_key=encoded,
        agent_token=encoded,
        enabled=False,
    )
    require(result["ok"] is True and result["generation"] == 7)
    require(len(staged) == 1 and staged[0] and not any(staged[0]))
    require(root_actions == ["quarantine", "off"])
    require(encoded not in json.dumps(result, sort_keys=True))


@contract_case("proxyAgentConsumesKeyOnce")
def proxy_agent_consumes_key_once() -> None:
    module_path = ROOT / "scripts" / "xenoid-proxy-agent.py"
    spec = importlib.util.spec_from_file_location(
        "xenoid_proxy_agent_contract",
        module_path,
    )
    require(spec is not None and spec.loader is not None)
    agent = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = agent
    spec.loader.exec_module(agent)

    encoded = base64.b64encode(b"s" * 32).decode("ascii")
    payload = json.dumps(
        {"masterKey": encoded, "agentToken": encoded},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    with tempfile.TemporaryDirectory(prefix="xenoid-agent-key-") as directory:
        key_path = Path(directory) / "agent.key"
        key_path.write_bytes(payload)
        key_path.chmod(0o400)
        real_fstat = agent.os.fstat

        def root_owned_stat(descriptor: int) -> SimpleNamespace:
            info = real_fstat(descriptor)
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_uid=0,
                st_gid=0,
                st_nlink=info.st_nlink,
                st_size=info.st_size,
            )

        with mock.patch.object(agent.os, "fstat", side_effect=root_owned_stat):
            master, token = agent._read_channel_secret(
                {"paths": {"key": str(key_path)}}
            )
        try:
            require(bytes(master) == b"s" * 32)
            require(bytes(token) == encoded.encode("ascii"))
            require(not key_path.exists())
        finally:
            for value in (master, token):
                for index in range(len(value)):
                    value[index] = 0

@contract_case("proxyDiscardCliIsExplicit")
def proxy_discard_cli_is_explicit() -> None:
    ordinary = cli.build_parser().parse_args(["proxy", "clear"])
    recovery = cli.build_parser().parse_args(
        ["proxy", "clear", "--discard-unreadable-state"]
    )
    require(ordinary.discard_unreadable_state is False)
    require(recovery.discard_unreadable_state is True)


@contract_case("legacyRegenerationRestartCliIsExplicit")
def legacy_regeneration_restart_cli_is_explicit() -> None:
    ordinary = cli.build_parser().parse_args(["device", "regenerate"])
    require(ordinary.restart_legacy_transaction is False)
    recovery = cli.build_parser().parse_args(
        ["device", "regenerate", "--restart-legacy-transaction"]
    )
    require(recovery.restart_legacy_transaction is True)

@contract_case("legacyProxyRecoveryRequiresBoundCliJournal")
def legacy_proxy_recovery_requires_bound_cli_journal() -> None:
    digest = "ab" * 32
    bound = {
        "operationId": digest[:32],
        "regenerationTransactionId": "cd" * 16,
        "completed": ["planned", "quarantined"],
    }
    args = SimpleNamespace(
        context=SimpleNamespace(instance_id=ID_A),
        discard_unreadable_state=False,
    )
    with mock.patch.object(cli, "RegenerationJournal") as journal_type, \
         mock.patch.object(cli, "ConvergenceExecutor") as executor_type, \
         mock.patch.object(cli, "runtime", return_value=object()):
        journal_type.return_value.legacy_source_digest.return_value = digest
        executor_type.return_value.journal.load.return_value = bound
        require(cli._legacy_proxy_recovery_allowed(args, "cmd_proxy_set"))
        args.discard_unreadable_state = True
        require(cli._legacy_proxy_recovery_allowed(args, "cmd_proxy_clear"))
        args.discard_unreadable_state = False
        require(not cli._legacy_proxy_recovery_allowed(args, "cmd_proxy_clear"))
        executor_type.return_value.journal.load.return_value = {
            **bound,
            "operationId": "ef" * 16,
        }
        require(not cli._legacy_proxy_recovery_allowed(args, "cmd_proxy_set"))

    error = cli.IdentityError(
        "device_regeneration_legacy_pending",
        "legacy regeneration requires recovery",
    )
    with mock.patch.object(cli, "RegenerationJournal") as journal_type:
        journal_type.return_value.load.side_effect = error
        journal_type.return_value.legacy_source_digest.side_effect = error
        try:
            cli._reject_unrelated_regeneration_mutation(
                SimpleNamespace(
                    context=args.context,
                    func=SimpleNamespace(__name__="cmd_proxy_clear"),
                    discard_unreadable_state=False,
                )
            )
        except cli.IdentityError as exc:
            require(exc.code == "device_regeneration_legacy_pending")
        else:
            raise ContractFailure


def main() -> int:
    results: dict[str, bool] = {}
    for name, test in CASES.items():
        try:
            test()
        except Exception:
            results[name] = False
        else:
            results[name] = True
    payload = {"ok": all(results.values()), "cases": results}
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
