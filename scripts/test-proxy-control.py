#!/usr/bin/env python3
"""Runtime-free contracts for generation-bound proxy data-plane proof."""
from __future__ import annotations

import copy
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid import backend
from xenoid.daemon_client import DaemonClient, wait_for_proxy_check
from xenoid.operation_lock import instance_operation_lock, operation_lock_is_held
from xenoid.proxy_controller import ProxyController

INSTANCE = "123e4567-e89b-42d3-a456-426614174000"
EPOCH = "v1-abcdef012345-0123456789abcdef"


def require(value: bool) -> None:
    if not value:
        raise AssertionError


def capabilities() -> dict:
    return {
        "v4DnsProxy": True, "v4TcpProxy": True, "v4UdpProxy": True,
        "v6DnsProxy": True, "v6TcpProxy": True, "v6UdpProxy": True,
    }


def ready_status() -> dict:
    return {
        "ok": True, "enabled": True, "instanceId": INSTANCE,
        "runtimeEpoch": EPOCH, "generation": 7, "checkId": 9,
        "udpAllowed": True,
        "report": {
            "generation": 7, "checkId": 9, "phase": "active",
            "structuralApplied": True, "dataPlaneVerified": True,
            "capabilities": capabilities(), "errorCode": "",
        },
        "probe": {
            "checkId": 9, "elapsedMs": 50, "errorCode": "",
            "capabilities": capabilities(),
        },
    }


class FakeClient:
    def __init__(self, statuses: list[dict]):
        self.statuses = statuses
        self.index = 0

    def proxy_status(self) -> dict:
        value = self.statuses[min(self.index, len(self.statuses) - 1)]
        self.index += 1
        return copy.deepcopy(value)

    def proxy_check(self) -> dict:
        raise AssertionError("an exact in-flight check must not allocate a replacement")


def checked(status: dict) -> dict:
    return wait_for_proxy_check(
        FakeClient([status]), timeout=0, poll_interval=0.01,
        expected_check_id=9, expected_generation=7,
        expected_runtime_epoch=EPOCH,
    )


def test_accepts_one_exact_proof() -> None:
    result = checked(ready_status())
    require(result.get("ok") is True and result.get("checkCompleted") is True)


def test_rejects_stale_generation_and_epoch() -> None:
    stale = ready_status()
    stale["report"]["generation"] = 6
    require(checked(stale).get("error") == "proxy_check_timeout")
    stale = ready_status()
    stale["runtimeEpoch"] = "v1-other-0123456789abcdef"
    require(checked(stale).get("error") == "agent_stale")
    stale = ready_status()
    stale["checkId"] = 10
    require(checked(stale).get("error") == "agent_stale")


def test_rejects_region_shaped_probe_fields() -> None:
    # Removed region evidence must not resurrect: the readiness contract only
    # accepts the strict capability/phase keys and ignores nothing silently.
    mismatched = ready_status()
    mismatched["probe"]["egressRegion"] = {"regionKey": "HK/Asia/Hong_Kong"}
    mismatched["probe"]["capabilities"]["v4TcpProxy"] = False
    require(checked(mismatched).get("error") == "data_plane_unverified")
    replay = ready_status()
    replay["probe"]["checkId"] = 8
    replay["report"]["egressRegion"] = {"regionKey": "SG/Asia/Singapore"}
    require(checked(replay).get("error") == "proxy_check_timeout")


def test_preserves_fail_closed_error() -> None:
    failed = ready_status()
    failed["report"]["phase"] = "quarantined"
    failed["report"]["errorCode"] = "probe_failed"
    require(checked(failed).get("error") == "probe_failed")

def test_host_mutators_quarantine_before_daemon_commit() -> None:
    events: list[str] = []
    context = SimpleNamespace(
        instance_id=INSTANCE,
        resource_tag="fixturetag",
    )
    config = object()
    lease = SimpleNamespace(instance_id=INSTANCE, resource_tag="fixturetag")

    class Manager:
        def __init__(self) -> None:
            self.context = context
            self.cfg = config
            self.lease = lease

        @staticmethod
        def ensure_instance_lease() -> None:
            return None

        @staticmethod
        def proxy_prerequisite() -> dict:
            return {"ok": True}

        @staticmethod
        def proxy_quarantine(*_args: object, **_kwargs: object) -> dict:
            events.append("quarantine")
            return {"ok": True}

    class Daemon:
        @staticmethod
        def proxy_source(*_args: object, **_kwargs: object) -> dict:
            events.append("daemon.source")
            return {
                "ok": True, "generation": 1, "checkId": 1, "enabled": True,
                "configured": True, "quarantined": True,
            }

        @staticmethod
        def proxy_enabled(enabled: bool) -> dict:
            events.append("daemon.on" if enabled else "daemon.off")
            return {
                "ok": True, "generation": 1, "checkId": 1, "enabled": enabled,
                "configured": True, "quarantined": True,
            }

        @staticmethod
        def proxy_select(_name: str) -> dict:
            events.append("daemon.select")
            return {
                "ok": True, "generation": 1, "checkId": 1, "enabled": True,
                "configured": True, "quarantined": True,
            }

        @staticmethod
        def proxy_clear(discard_unreadable_state: bool = False) -> dict:
            require(discard_unreadable_state is True)
            events.append("daemon.clear")
            return {
                "ok": True, "generation": 1, "checkId": 1, "enabled": False,
                "configured": False, "quarantined": True,
            }

        @staticmethod
        def proxy_status() -> dict:
            return {"ok": True, "enabled": True, "generation": 1}

    manager = Manager()
    controller = ProxyController(context, config, lease, manager, Daemon())

    def proof(mutation: dict, *, fresh_check: bool) -> dict:
        require(mutation.get("generation") == 1)
        require(isinstance(fresh_check, bool))
        events.append("proof")
        return mutation

    controller._converge = proof  # type: ignore[method-assign]

    def direct_proof(mutation: dict, *, configured: bool) -> dict:
        require(mutation.get("generation") == 1)
        require(isinstance(configured, bool))
        events.append("proof")
        return mutation

    controller._release_direct = direct_proof  # type: ignore[method-assign]
    operations = (
        (
            "daemon.source",
            lambda: controller.set_source(
                "endpoint",
                "socks5://proxy.invalid:1080",
                True,
            ),
        ),
        ("daemon.on", lambda: controller.set_enabled(True)),
        ("daemon.off", lambda: controller.set_enabled(False)),
        ("daemon.select", lambda: controller.select("fixture-node")),
        (
            "daemon.clear",
            lambda: controller.clear(discard_unreadable_state=True),
        ),
    )
    with tempfile.TemporaryDirectory(prefix="xenoid-proxy-lock-") as directory:
        context.state_root = Path(directory) / INSTANCE
        with instance_operation_lock(context.state_root):
            for commit_event, operation in operations:
                events.clear()
                result = operation()
                require(result.get("ok") is True)
                require(events == ["quarantine", commit_event, "proof"])


def test_quarantine_failure_prevents_daemon_mutation() -> None:
    events: list[str] = []
    context = SimpleNamespace(instance_id=INSTANCE, resource_tag="fixturetag")
    config = object()
    lease = SimpleNamespace(instance_id=INSTANCE, resource_tag="fixturetag")

    class Manager:
        def __init__(self) -> None:
            self.context = context
            self.cfg = config
            self.lease = lease

        @staticmethod
        def ensure_instance_lease() -> None:
            return None

        @staticmethod
        def proxy_prerequisite() -> dict:
            return {"ok": True}

        @staticmethod
        def proxy_quarantine(*_args: object, **_kwargs: object) -> dict:
            events.append("quarantine")
            return {"ok": False, "code": "quarantine_failed"}

    class Daemon:
        @staticmethod
        def proxy_source(*_args: object, **_kwargs: object) -> dict:
            events.append("daemon")
            return {"ok": True, "generation": 1}

    controller = ProxyController(context, config, lease, Manager(), Daemon())
    with mock.patch(
        "xenoid.proxy_controller.operation_lock_is_held",
        return_value=True,
    ):
        result = controller.set_source(
            "endpoint",
            "socks5://proxy.invalid:1080",
            True,
        )
    require(result.get("ok") is False)
    require(events == ["quarantine"])

def test_daemon_clear_schema_is_explicit() -> None:
    client = object.__new__(DaemonClient)
    calls: list[tuple[str, str, dict]] = []

    def request(method: str, path: str, body: dict) -> dict:
        calls.append((method, path, body))
        return {
            "ok": True,
            "generation": 1,
            "checkId": 0,
            "enabled": False,
            "configured": False,
            "quarantined": True,
        }

    client._proxy_request = request  # type: ignore[method-assign]
    require(client.proxy_clear()["ok"] is True)
    require(client.proxy_clear(discard_unreadable_state=True)["ok"] is True)
    require(
        calls
        == [
            (
                "POST",
                "/proxy/clear",
                {"discardUnreadableState": False},
            ),
            (
                "POST",
                "/proxy/clear",
                {"discardUnreadableState": True},
            ),
        ]
    )

def test_status_v2_readable_and_unreadable_are_exact() -> None:
    client = object.__new__(DaemonClient)
    client._context = SimpleNamespace(instance_id=INSTANCE)
    readable = {
        "ok": True,
        "schemaVersion": 2,
        "stateReadable": True,
        "stateError": None,
        "instanceId": INSTANCE,
        "generation": 7,
        "enabled": True,
        "configured": True,
        "sourceKind": "endpoint",
        "selectedNode": "",
        "udpAllowed": True,
        "allowInsecureHttp": False,
        "quarantined": True,
        "checkId": 3,
        "runtimeEpoch": EPOCH,
        "report": None,
        "probe": None,
    }
    unreadable = {
        **readable,
        "ok": False,
        "stateReadable": False,
        "stateError": "proxy_state_key_mismatch",
        "instanceId": None,
        "generation": None,
        "enabled": None,
        "configured": None,
        "sourceKind": None,
        "selectedNode": None,
        "udpAllowed": None,
        "allowInsecureHttp": None,
        "quarantined": True,
        "runtimeEpoch": "",
    }
    responses = [readable, unreadable, {**readable, "schemaVersion": 1}]
    client._proxy_request = (  # type: ignore[method-assign]
        lambda _method, _path, **_kwargs: responses.pop(0)
    )
    require(client.proxy_status() == readable)
    require(client.proxy_status() == unreadable)
    require(client.proxy_status().get("error") == "daemon_response_invalid")


def test_terminal_failed_check_allocates_fresh_evidence() -> None:
    context = SimpleNamespace(instance_id=INSTANCE, resource_tag="fixturetag")
    config = object()
    lease = SimpleNamespace(instance_id=INSTANCE, resource_tag="fixturetag")
    failed = ready_status()
    failed["report"]["phase"] = "quarantined"
    failed["report"]["structuralApplied"] = False
    failed["report"]["dataPlaneVerified"] = False
    failed["report"]["errorCode"] = "proxy_outbound_unavailable"
    failed["probe"] = None

    class Manager:
        def __init__(self) -> None:
            self.context = context
            self.cfg = config
            self.lease = lease

        @staticmethod
        def ensure_instance_lease() -> None:
            return None

        @staticmethod
        def proxy_quarantine(*_args: object, **_kwargs: object) -> dict:
            return {"ok": True}

    class Daemon:
        @staticmethod
        def proxy_status() -> dict:
            return copy.deepcopy(failed)

    controller = ProxyController(context, config, lease, Manager(), Daemon())
    controller._ensure_agent = lambda _status: {"ok": True}  # type: ignore[method-assign]
    with mock.patch(
        "xenoid.proxy_controller.wait_for_proxy_check",
        return_value={"ok": True, "checkCompleted": True},
    ) as waiter:
        result = controller._converge({"ok": True, "generation": 7}, fresh_check=True)
    require(result.get("ok") is True)
    require(waiter.call_args.args == (controller._daemon,))
    require(waiter.call_args.kwargs == {})


def test_environment_cannot_forge_operation_lock() -> None:
    with tempfile.TemporaryDirectory(prefix="xenoid-operation-lock-") as directory:
        state_root = Path(directory) / INSTANCE
        with mock.patch.dict(
            os.environ,
            {"XENOID_OPERATION_LOCK_HELD": INSTANCE},
        ):
            require(not operation_lock_is_held(INSTANCE))
            with instance_operation_lock(state_root):
                require(operation_lock_is_held(INSTANCE))
            require(not operation_lock_is_held(INSTANCE))


def test_convergence_never_discards_unreadable_proxy_state() -> None:
    class Daemon:
        clear_calls = 0

        @staticmethod
        def proxy_status() -> dict:
            return {
                "ok": False,
                "stateReadable": False,
                "stateError": "proxy_state_invalid",
            }

        @classmethod
        def proxy_clear(cls, _discard: bool) -> dict:
            cls.clear_calls += 1
            return {"ok": True}

    class Manager(backend.RuntimeManager):
        def __init__(self, root: Path) -> None:
            self.context = SimpleNamespace(
                instance_id=INSTANCE,
                resource_tag="fixturetag",
                state_root=root,
            )
            self.cfg = object()
            self.lease = SimpleNamespace(
                instance_id=INSTANCE,
                resource_tag="fixturetag",
            )

        def ensure_instance_lease(self) -> object:
            return self.lease

        @staticmethod
        def daemon_client() -> Daemon:
            return Daemon()

    with tempfile.TemporaryDirectory(prefix="xenoid-proxy-unreadable-") as directory:
        result = Manager(Path(directory) / INSTANCE).reconcile_proxy_desired()
    require(result.get("error") == "proxy_state_invalid")
    require(Daemon.clear_calls == 0)




def main() -> int:
    tests = [


        test_accepts_one_exact_proof,
        test_rejects_stale_generation_and_epoch,
        test_rejects_region_shaped_probe_fields,
        test_preserves_fail_closed_error,
        test_host_mutators_quarantine_before_daemon_commit,
        test_quarantine_failure_prevents_daemon_mutation,
        test_daemon_clear_schema_is_explicit,
        test_status_v2_readable_and_unreadable_are_exact,
        test_convergence_never_discards_unreadable_proxy_state,
        test_terminal_failed_check_allocates_fresh_evidence,
        test_environment_cannot_forge_operation_lock,
    ]
    for test in tests:
        test()
    print("proxy control contracts ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
