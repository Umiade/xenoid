#!/usr/bin/env python3
"""Runtime-free contracts for the listener-first bootstrap control plane."""
from __future__ import annotations

import hashlib
import os
import json
import re
import stat
import sys
import time
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
import uuid
from types import SimpleNamespace
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from xenoid import backend, config, daemon_client  # noqa: E402

TRANSPORT_SCHEMA = "dev.xenoid.daemon-transport/v1"
BOOTSTRAP_SCHEMA = "dev.xenoid.daemon-bootstrap/v1"
INSTANCE_ID = "12345678-1234-4234-9234-123456789abc"
RUNTIME_EPOCH = "ab" * 32
TOKEN = "cd" * 16
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
Case = Callable[[], None]
CASES: dict[str, Case] = {}


class ContractFailure(AssertionError):
    pass


def contract_case(name: str) -> Callable[[Case], Case]:
    def register(function: Case) -> Case:
        if name in CASES:
            raise RuntimeError(f"duplicate case: {name}")
        CASES[name] = function
        return function
    return register


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractFailure(message)


def source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def ordered(text: str, *needles: str) -> None:
    positions = [text.find(item) for item in needles]
    require(all(value >= 0 for value in positions), f"missing anchors: {needles}")
    require(positions == sorted(positions), f"wrong order: {needles}")


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeResponse:
    def __init__(self, status: int, body: dict[str, Any]) -> None:
        self.status = status
        self.raw = json.dumps(body, separators=(",", ":")).encode()

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_: Any) -> None:
        return None

    def read(self, limit: int = -1) -> bytes:
        return self.raw if limit < 0 else self.raw[:limit]


class FakeDaemon:
    """Deterministic endpoint peer exercising the production DaemonClient."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.generation = 0
        self.started = 0.0
        self.state = "transport_ready"
        self.keybox_fails = True
        self.requests: list[dict[str, Any]] = []

    @staticmethod
    def transport_body() -> dict[str, Any]:
        return {"ok": True, "schema": TRANSPORT_SCHEMA,
                "service": "xenoid-daemon", "transportReady": True}

    def components(self) -> dict[str, Any]:
        terminal = self.state in {"ready", "degraded"}
        component_ok = self.state == "ready"
        pending = "reconciling" if self.state in {"accepted", "reconciling"} else "pending"
        keybox_ok = terminal and not self.keybox_fails
        return {
            "root": {"ok": terminal, "state": "ready" if terminal else pending},
            "keybox": {
                "ok": keybox_ok,
                "state": "ready" if keybox_ok else ("failed" if terminal else pending),
                "configured": True, "active": keybox_ok,
                "algorithms": {"rsa": keybox_ok, "ecdsa": keybox_ok,
                               "rsaChainCount": int(keybox_ok),
                               "ecdsaChainCount": int(keybox_ok)},
                **({"errorCode": "keybox_reconcile_failed"}
                   if terminal and not keybox_ok else {}),
            },
            "proxy": {"ok": component_ok, "state": "ready" if component_ok else (
                      "failed" if terminal else pending),
                      "configured": None if terminal and not component_ok else True,
                      "enabled": None if terminal and not component_ok else True,
                      "generation": None if terminal and not component_ok else 7,
                      "quarantined": True,
                      **({"errorCode": "proxy_state_invalid"}
                         if terminal and not component_ok else {})},
            "location": {"ok": terminal, "state": "ready" if terminal else pending,
                         "configured": True, "locationEpoch": "ef" * 32},
            "camera": {"ok": component_ok, "state": "ready" if component_ok else (
                       "failed" if terminal else pending),
                       "configured": True, "generation": 5, "active": component_ok,
                       "publicationReady": component_ok,
                       **({"errorCode": "camera_publication_failed"}
                          if terminal and not component_ok else {})},
        }

    def status(self) -> dict[str, Any]:
        if self.state in {"accepted", "reconciling"} and self.clock.now - self.started >= 1:
            self.state = "degraded" if self.keybox_fails else "ready"
        value: dict[str, Any] = {
            "ok": self.state == "ready", "schema": BOOTSTRAP_SCHEMA,
            "state": self.state, "generation": self.generation,
            "instanceId": INSTANCE_ID if self.generation else "",
            "runtimeEpoch": RUNTIME_EPOCH if self.generation else "",
            "components": self.components(),
        }
        if self.state == "degraded":
            value["errorCode"] = "bootstrap_component_degraded"
        return value

    def handle(self, request: Any, **_: Any) -> FakeResponse:
        method = request.get_method()
        path = request.full_url.split("127.0.0.1", 1)[-1]
        path = path[path.find("/"):]
        body = json.loads(request.data) if request.data else None
        token = request.headers.get("X-xenoid-token") or request.headers.get("X-Xenoid-Token")
        self.requests.append({"method": method, "path": path, "body": body, "token": token})
        if path == "/bootstrap/transport":
            require(token is None, "public transport leaked token")
            return FakeResponse(200, self.transport_body())
        require(token == TOKEN, f"missing bootstrap authentication: {path}")
        if path == "/bootstrap/reconcile":
            require(method == "POST", "reconcile is not POST")
            require(body == {"schema": BOOTSTRAP_SCHEMA, "instanceId": INSTANCE_ID,
                             "runtimeEpoch": RUNTIME_EPOCH, "timeoutMs": 230000},
                    "noncanonical reconcile body")
            if self.state not in {"accepted", "reconciling", "ready"}:
                self.generation += 1
                self.state = "accepted"
                self.started = self.clock.now
            elif self.state == "degraded":
                self.generation += 1
                self.state = "accepted"
                self.started = self.clock.now
            return FakeResponse(202 if self.state == "accepted" else 200, self.status())
        if path == "/bootstrap/status":
            require(method == "GET" and body is None, "status is not empty GET")
            return FakeResponse(200, self.status())
        if path == "/bootstrap/cancel":
            require(body == {"schema": BOOTSTRAP_SCHEMA, "generation": self.generation},
                    "cancel does not match generation")
            return FakeResponse(200, self.status())
        if path == "/health":
            return FakeResponse(200, {"ok": self.state == "ready",
                                      "service": "xenoid-daemon"})
        if path == "/root/status":
            return FakeResponse(200, {"ok": True, "root": True,
                                      "stdout": "uid=0(root)\n"})
        if path in {"/proxy/status", "/proxy/source"}:
            return FakeResponse(200, {"ok": False, "error": "proxy_state_invalid"})
        raise ContractFailure(f"unexpected request: {method} {path}")


@contextmanager
def client_fixture(fake: FakeDaemon) -> Iterator[tuple[Any, Path, list[str]]]:
    with tempfile.TemporaryDirectory(prefix="xenoid-bootstrap-contract-") as directory:
        root = Path(directory)
        project, state = root / "project", root / "state"
        (project / "src" / "xenoid").mkdir(parents=True)
        with mock.patch.object(config, "_port_available", return_value=True), \
             mock.patch.object(
                 config.uuid, "uuid4", return_value=uuid.UUID(INSTANCE_ID)
             ):
            context, _cfg, lease = config.initialize_instance(
                "bootstrap-contract", project_root=project, state_home=state, env={}
            )
        argv = ["docker", "--context", "contract"]
        client = daemon_client.DaemonClient(context, lease, argv, timeout=2)
        with mock.patch.object(
            daemon_client.DaemonClient, "read_private_token", return_value=TOKEN
        ), mock.patch.object(
            daemon_client.urllib.request, "urlopen", side_effect=fake.handle
        ):
            yield client, context.state_root, argv


@contract_case("listenerBeforeManagers")
def listener_before_managers() -> None:
    text = source("daemon/app/src/main/java/dev/xenoid/daemon/XenoidDaemonService.java")
    initialize = text[text.index("initializeServer"):]
    ordered(
        initialize,
        "loadOrCreateTokenStrict()",
        "RootHelper.setRootdToken",
        "new BootstrapCoordinator",
        "new ServerSocket",
        "server = listener",
        "acceptClients",
        "new KeyboxManager",
        "new ProxyManager",
        "new LocationIdentityManager",
        "CameraMediaManager.get",
        "installComponents",
    )
    require(
        'InetAddress.getByName("127.0.0.1")' in initialize
        or "InetAddress.getLoopbackAddress()" in initialize,
        "listener is not loopback",
    )
    require("0.0.0.0" not in initialize, "listener retained wildcard bind")
    require(
        '"/health".equals(path) || "/bootstrap/transport".equals(path)' in text,
        "transport is not the only public bootstrap route",
    )
    require(
        "new ArrayBlockingQueue<Runnable>(32)" in text
        and "new ThreadPoolExecutor.AbortPolicy()" in text,
        "daemon client queue is not bounded",
    )
    require(
        "new Thread(" in initialize
        and "acceptClients(activeListener, workers)" in initialize
        and "workers.execute(request)" in text,
        "accept loop still consumes a handler or bypasses bounded execution",
    )
    require(
        "clients.add(request)" in text
        and "request.close()" in text
        and "workers.shutdownNow()" in text,
        "queued or active sockets are not closed on rejection/shutdown",
    )
    for route in ("/bootstrap/reconcile", "/bootstrap/status", "/bootstrap/cancel"):
        require(route in text, f"daemon route missing: {route}")
    require("dev.xenoid.daemon-transport/v1" in text, "transport schema missing")
    tree = ET.parse(ROOT / "daemon/app/src/main/AndroidManifest.xml")
    app = tree.getroot().find("application")
    require(app is not None, "manifest application missing")
    activity, service_node = app.find("activity"), app.find("service")
    require(activity is not None and service_node is not None, "components missing")
    require(activity.get(ANDROID_NS + "launchMode") == "singleTop", "not singleTop")
    require(service_node.get(ANDROID_NS + "exported") == "false", "service exported")


@contract_case("boundedCoordinator")
def bounded_coordinator() -> None:
    text = source("daemon/app/src/main/java/dev/xenoid/daemon/BootstrapCoordinator.java")
    for item in ("230000", "root", "proxy", "keybox", "location", "camera",
                 "transport_ready", "accepted", "reconciling", "ready", "degraded",
                 "failed", "bootstrap_generation_conflict"):
        require(item in text, f"coordinator missing {item}")
    require("newSingleThreadExecutor" in text or "newFixedThreadPool(1" in text,
            "coordinator is not single-worker")
    require("shutdownNow" in text, "shutdown lacks cancellation")


@contract_case("clientGenerationComponentsAndAggregateHealth")
def client_generation_components_and_aggregate_health() -> None:
    clock, fake = FakeClock(), FakeDaemon(FakeClock())
    fake.clock = clock
    with client_fixture(fake) as (client, state_root, argv):
        transport = client.transport()
        require(transport == fake.transport_body(), "transport body not exact")
        first = client.bootstrap_reconcile(INSTANCE_ID, RUNTIME_EPOCH, 230000)
        joined = client.bootstrap_reconcile(INSTANCE_ID, RUNTIME_EPOCH, 230000)
        require(first["generation"] == joined["generation"] == 1, "active call did not join")
        clock.advance(1)
        cancelled = client.bootstrap_cancel(1)
        require(cancelled["generation"] == 1, "cancel did not target active generation")
        degraded = client.bootstrap_status()
        require(not degraded["ok"] and degraded["state"] == "degraded", "degrade hidden")
        require(degraded["components"]["root"]["ok"], "healthy root collapsed")
        require(not degraded["components"]["keybox"]["ok"], "Keybox failure hidden")
        require(not degraded["components"]["proxy"]["ok"], "proxy degradation hidden")
        require(not degraded["components"]["camera"]["ok"], "camera degradation hidden")
        require(client.health()["ok"] is False, "aggregate health accepted degradation")
        require(client.root_status()["ok"], "aggregate health blocked root")
        host_snapshot = backend.RuntimeManager._bootstrap_terminal_result(degraded)
        require(
            host_snapshot.get("ok") is True
            and host_snapshot.get("controlReady") is True
            and host_snapshot.get("ready") is False,
            "host collapsed component degradation into control-plane failure",
        )
        proxy_status = client.proxy_status()
        require(proxy_status.get("error") == "proxy_state_invalid", "proxy recovery hidden")
        recovery = client.proxy_source("endpoint", "https://127.0.0.1:443", True)
        require(recovery.get("error") == "proxy_state_invalid", "proxy import blocked")
        fake.keybox_fails = False
        retry = client.bootstrap_reconcile(INSTANCE_ID, RUNTIME_EPOCH, 230000)
        require(retry["generation"] == 2, "degraded same-input did not retry")
        clock.advance(1)
        ready = client.bootstrap_status()
        require(ready["ok"] and ready["state"] == "ready", "retry did not converge")
        rendered = json.dumps({"transport": transport, "degraded": degraded,
                               "proxy": proxy_status, "recovery": recovery,
                               "ready": ready, "progress": [{"state": "passed"}]})
        require(TOKEN not in rendered, "token leaked to result/progress")
        require(all(TOKEN not in part for part in argv), "token leaked to argv")
        require(not (state_root / "daemon.token").exists(), "host daemon token created")
        require(not (state_root / "rootd.token").exists(), "host rootd token created")




@contract_case("delayedTransportLaunchesActivityOnce")
def delayed_transport_launches_activity_once() -> None:
    class TransportClient:
        def __init__(self, clock: FakeClock) -> None:
            self.clock = clock

        def transport(self, timeout: float) -> dict[str, Any]:
            del timeout
            return (
                FakeDaemon.transport_body()
                if self.clock.now >= 3.0
                else {"ok": False, "code": "daemon_transport_unavailable"}
            )

    class TransportProbe(backend.RuntimeManager):
        def __init__(self, clock: FakeClock) -> None:
            self.clock = clock
            self.launches = 0
            self.force_stops = 0
            self.forwards = 0
            self.client = TransportClient(clock)

        def daemon_client(self, timeout: float = 10.0) -> TransportClient:
            del timeout
            return self.client

        def forward_daemon_port(self, timeout: float | None = None) -> dict[str, Any]:
            require(timeout is not None and timeout <= 30, "forward escaped transport deadline")
            self.forwards += 1
            return {"ok": True}

        def launch_daemon_activity_once(
            self, timeout: float | None = None
        ) -> dict[str, Any]:
            require(timeout is not None and timeout <= 30, "Activity escaped transport deadline")
            self.launches += 1
            return {"ok": True}

        def adb(self, args: list[str], timeout: float = 0) -> dict[str, Any]:
            del args, timeout
            self.force_stops += 1
            return {"ok": True}

    clock = FakeClock()
    probe = TransportProbe(clock)
    with mock.patch.object(backend.time, "monotonic", side_effect=lambda: clock.now), \
         mock.patch.object(backend.time, "sleep", side_effect=clock.advance):
        result = probe.wait_daemon_transport(timeout=30)
    require(result.get("transportReady") is True, "delayed listener was rejected")
    require(clock.now >= 3.0, "test did not exceed the obsolete two-second wait")
    require(probe.launches == 1, "polling launched Activity more than once")
    require(probe.force_stops == 0, "bound-before-midpoint daemon was force-stopped")


@contract_case("staleRootdRecordSurvivesPidReuseSafely")
def stale_rootd_record_survives_pid_reuse_safely() -> None:
    recorded_pid = 3668
    record = json.dumps({
        "schema": backend._ROOTD_PROCESS_SCHEMA,
        "pid": recorded_pid,
        "startTime": 12345,
    })

    class Probe(backend.RuntimeManager):
        def _rootd_output(
            self,
            args: list[str],
            limit: int = 0,
            deadline: float | None = None,
        ) -> str | None:
            del limit, deadline
            if args == ["test", "-e", backend._ROOTD_PROCESS_RECORD]:
                return ""
            if args == ["cat", backend._ROOTD_PROCESS_RECORD]:
                return record
            if args == ["cat", f"/proc/{recorded_pid}/stat"]:
                return f"{recorded_pid} (unrelated) S " + "0 " * 40
            return None

        def _rootd_stat(
            self,
            path: str,
            *,
            follow: bool = False,
            deadline: float | None = None,
        ) -> tuple[int, int, int, int, int, int] | None:
            del follow, deadline
            if path == backend._ROOTD_RUN_DIRECTORY:
                return (1, 2, 0, stat.S_IFDIR | 0o700, 1, 64)
            if path == backend._ROOTD_PROCESS_RECORD:
                return (1, 3, 0, stat.S_IFREG | 0o600, 1, len(record))
            return None

        def _rootd_process_identity(self, *args: Any, **kwargs: Any) -> None:
            del args, kwargs
            return None

    owned, state = Probe._rootd_owned_process(object.__new__(Probe))
    require(owned is None and state == "stale", "PID reuse was treated as an owned conflict")


@contract_case("delayedPrivateTokenAndRootdFailureClasses")
def delayed_private_token_and_rootd_failure_classes() -> None:
    class TokenClient:
        def __init__(self, clock: FakeClock, available_at: float) -> None:
            self.clock = clock
            self.available_at = available_at
            self.reads = 0

        def read_private_token(
            self, force: bool = False, timeout: float = 5.0
        ) -> str | None:
            require(force, "token wait reused stale cache")
            require(0 < timeout <= 5, "token read escaped rootd deadline")
            self.reads += 1
            return TOKEN if self.clock.now >= self.available_at else None

    class RootdProbe(backend.RuntimeManager):
        def __init__(self, project: Path, digest: str) -> None:
            self.context = SimpleNamespace(project_root=project)
            self.lease = SimpleNamespace(rootd_port=18767)
            self.digest = digest
            self.authentication = "ok"
            self.container_id = "1" * 64

        def _rootd_output(
            self,
            args: list[str],
            limit: int = 0,
            deadline: float | None = None,
        ) -> str | None:
            del limit
            require(deadline is not None, "rootd command lacks phase deadline")
            return "arm64-v8a" if args == ["getprop", "ro.product.cpu.abi"] else None

        def _rootd_owned_process(
            self, *, deadline: float | None = None
        ) -> tuple[dict[str, Any], str]:
            require(deadline is not None, "rootd ownership lacks phase deadline")
            return {"digest": self.digest}, "valid"

        def _rootd_authentication(
            self, client: Any, *, deadline: float | None = None
        ) -> str:
            del client
            require(deadline is not None, "rootd auth lacks phase deadline")
            return self.authentication

        def _artifact_output(self, consumer: str, relative: str) -> Path:
            require(consumer == "liveDeploy", "rootd used wrong artifact consumer")
            return self.context.project_root / relative

        def docker_base_cmd(self) -> list[str]:
            return ["docker", "--context", "contract"]

        def docker_env(self) -> dict[str, str]:
            return {"SAFE": "1", "XENOID_ROOTD_TOKEN": TOKEN}

        @staticmethod
        def migrate_legacy_token_state() -> dict[str, Any]:
            return {"ok": True, "removed": 0}

        def _owned_container_record(
            self, timeout: float | None = None
        ) -> tuple[dict[str, Any], None]:
            require(timeout is not None and timeout > 0, "ownership deadline missing")
            return {"Id": self.container_id}, None

        def _remove_legacy_android_rootd_token(
            self,
            expected_container_id: str,
            *,
            deadline: float,
        ) -> bool:
            require(expected_container_id == self.container_id, "wrong token cleanup runtime")
            require(deadline > 0, "token cleanup deadline missing")
            return True

    with tempfile.TemporaryDirectory(prefix="xenoid-rootd-contract-") as directory:
        project = Path(directory)
        candidate = project / "native/xenoid-rootd/xenoid-rootd-arm64"
        candidate.parent.mkdir(parents=True)
        candidate.write_bytes(b"contract-rootd")
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        clock = FakeClock()
        client = TokenClient(clock, available_at=3.0)
        probe = RootdProbe(project, digest)
        with mock.patch.object(backend, "which", return_value="/usr/bin/docker"), \
             mock.patch.object(backend.time, "monotonic", side_effect=lambda: clock.now), \
             mock.patch.object(backend.time, "sleep", side_effect=clock.advance):
            result = probe.ensure_rootd_root(timeout=30, client=client)
        require(result.get("ok") is True and result.get("reused") is True, "delayed token failed")
        require(clock.now >= 3.0 and client.reads > 10, "token wait retained old short polling")
        require(TOKEN not in json.dumps(result), "rootd result leaked token")

        class SecretSink:
            def __init__(self) -> None:
                self.data = bytearray()

            def write(self, value: bytes | bytearray) -> int:
                self.data.extend(value)
                return len(value)

            def flush(self) -> None:
                return None

            def close(self) -> None:
                return None

        class LaunchProcess:
            def __init__(self) -> None:
                self.stdin = SecretSink()

            def wait(self, timeout: float) -> int:
                require(timeout <= 10, "rootd launch timeout is unbounded")
                return 0

        launched = LaunchProcess()
        with mock.patch.object(backend.subprocess, "Popen", return_value=launched) as popen:
            require(
                probe._launch_rootd_with_token("1" * 64, TOKEN, 10),
                "direct rootd launch failed",
            )
        launch_argv = popen.call_args.args[0]
        launch_env = popen.call_args.kwargs["env"]
        require(launched.stdin.data == (TOKEN + "\n").encode(), "stdin token framing changed")
        require(TOKEN not in json.dumps(launch_argv), "token leaked into rootd argv")
        require(TOKEN not in json.dumps(launch_env), "token leaked into rootd environment")
        require("XENOID_ROOTD_TOKEN" not in launch_env, "legacy token environment survived")

        probe.authentication = "rootd_unauthorized"
        immediate = TokenClient(clock, available_at=0)
        with mock.patch.object(backend, "which", return_value="/usr/bin/docker"):
            unauthorized = probe.ensure_rootd_root(timeout=30, client=immediate)
        require(unauthorized.get("code") == "rootd_unauthorized", "401 collapsed into unavailable")

        class UnownedRootdProbe(RootdProbe):
            def _rootd_owned_process(
                self, *, deadline: float | None = None
            ) -> tuple[None, str]:
                require(deadline is not None, "unowned proof lacks phase deadline")
                return None, "absent"

            def _rootd_port_inodes(
                self, *, deadline: float | None = None
            ) -> tuple[set[str], bool]:
                require(deadline is not None, "listener proof lacks phase deadline")
                return {"unowned-inode"}, True

        conflict_probe = UnownedRootdProbe(project, digest)
        with mock.patch.object(backend, "which", return_value="/usr/bin/docker"):
            conflict = conflict_probe.ensure_rootd_root(timeout=30, client=immediate)
        require(conflict.get("code") == "rootd_resource_conflict", "unowned port was adopted")

    class FlowProbe(backend.RuntimeManager):
        def __init__(self, responses: list[str]) -> None:
            self.context = SimpleNamespace(instance_id=INSTANCE_ID)
            self.responses = responses
            self.root_calls = 0

        def wait_daemon_transport(self, timeout: float) -> dict[str, Any]:
            del timeout
            return {"ok": True, "transportReady": True}

        def daemon_client(self, timeout: float = 10.0) -> object:
            del timeout
            return object()
        def ensure_daemon_runtime_permissions(self) -> dict[str, Any]:
            return {"ok": True, "granted": 4}


        def ensure_rootd_root(self, timeout: float, client: object) -> dict[str, Any]:
            del timeout, client
            code = self.responses[min(self.root_calls, len(self.responses) - 1)]
            self.root_calls += 1
            return {"ok": False, "code": code, "error": code}

    unavailable_probe = FlowProbe(["rootd_unavailable"])
    unavailable = unavailable_probe.reconcile_bootstrap()
    require(unavailable.get("code") == "rootd_unavailable", "unavailable class changed")
    require(unavailable_probe.root_calls == 2, "unavailable was not retried exactly once")
    unauthorized_probe = FlowProbe(["rootd_unauthorized"])
    unauthorized = unauthorized_probe.reconcile_bootstrap()
    require(unauthorized.get("code") == "rootd_unauthorized", "unauthorized class changed")
    require(unauthorized_probe.root_calls == 1, "401 incorrectly triggered reprovision")


@contract_case("strictLegacyRootdAdoption")
def strict_legacy_rootd_adoption() -> None:
    class LegacyProbe(backend.RuntimeManager):
        def __init__(self) -> None:
            self.pids = "41"
            self.identity: dict[str, Any] | None = {
                "pid": 41, "startTime": 9001, "digest": "a" * 64,
                "executable": "/data/local/tmp/.netd-helper",
            }
            self.remote_digest: str | None = "a" * 64
            self.authenticated = True
            self.terminated = False

        def _rootd_output(
            self,
            args: list[str],
            limit: int = 0,
            deadline: float | None = None,
        ) -> str | None:
            del limit
            require(deadline is not None, "legacy command lacks phase deadline")
            return self.pids if args == ["pidof", ".netd-helper"] else None

        def _rootd_process_identity(
            self,
            pid: int,
            *,
            allowed_paths: frozenset[str],
            deadline: float | None = None,
        ) -> dict[str, Any] | None:
            require(pid == 41 and bool(allowed_paths), "legacy identity proof bypassed")
            require(deadline is not None, "legacy identity lacks phase deadline")
            return self.identity

        def _rootd_remote_digest(
            self, path: str, *, deadline: float | None = None
        ) -> str | None:
            require(path, "legacy digest path missing")
            require(deadline is not None, "legacy digest lacks phase deadline")
            return self.remote_digest

        def _legacy_rootd_probe(self, token: str, *, deadline: float) -> bool:
            require(token == TOKEN, "legacy proof used another token")
            require(deadline > 0, "legacy auth lacks phase deadline")
            return self.authenticated

        def _terminate_rootd_process(
            self, identity: dict[str, Any], *, deadline: float
        ) -> bool:
            require(identity == self.identity, "termination was not identity-bound")
            require(deadline > 0, "legacy termination lacks phase deadline")
            self.terminated = True
            return True

    probe = LegacyProbe()
    require(
        probe._adopt_legacy_rootd(TOKEN, deadline=time.monotonic() + 30) == (True, True),
        "strict legacy adoption failed",
    )
    require(probe.terminated, "adopted process was not identity-bound terminated")
    for mutation in ("multiple", "digest", "auth", "identity"):
        candidate = LegacyProbe()
        if mutation == "multiple":
            candidate.pids = "41 42"
        elif mutation == "digest":
            candidate.remote_digest = "b" * 64
        elif mutation == "auth":
            candidate.authenticated = False
        else:
            candidate.identity = None
        adopted, seen = candidate._adopt_legacy_rootd(
            TOKEN, deadline=time.monotonic() + 30
        )
        require(not adopted and seen, f"unsafe legacy {mutation} state was adopted")
        require(not candidate.terminated, f"unsafe legacy {mutation} process was killed")


@contract_case("legacyTokenMigrationNoFollow")
def legacy_token_migration_no_follow() -> None:
    with tempfile.TemporaryDirectory(prefix="xenoid-token-migration-") as directory:
        registry = Path(directory).resolve() / "registry"
        instances = registry / "instances"
        state_root = instances / INSTANCE_ID
        state_root.mkdir(parents=True, mode=0o700)
        registry.chmod(0o700)
        instances.chmod(0o700)
        state_root.chmod(0o700)
        external = Path(directory) / "external-token"
        external.write_text(TOKEN, encoding="ascii")
        (state_root / "daemon.token").symlink_to(external)
        (state_root / "rootd.token").write_text(TOKEN, encoding="ascii")
        manager = object.__new__(backend.RuntimeManager)
        manager.context = SimpleNamespace(state_root=state_root)

        require(manager.legacy_token_migration_pending(), "legacy tokens not observed")
        require((state_root / "daemon.token").is_symlink(), "observation mutated token")
        migrated = manager.migrate_legacy_token_state()
        require(migrated == {"ok": True, "removed": 2}, "migration result changed")
        require(not manager.legacy_token_migration_pending(), "migration remained pending")
        require(external.read_text(encoding="ascii") == TOKEN, "symlink target was followed")

        (state_root / "daemon.token").write_text(TOKEN, encoding="ascii")
        instances.chmod(0o777)
        try:
            manager.migrate_legacy_token_state()
        except Exception as exc:
            require(
                getattr(exc, "code", None) == "legacy_token_state_invalid",
                "unsafe parent returned the wrong error",
            )
        else:
            raise ContractFailure("unsafe parent accepted token migration")
        require((state_root / "daemon.token").exists(), "unsafe migration deleted evidence")

    class AndroidTokenProbe(backend.RuntimeManager):
        def __init__(self) -> None:
            self.commands: list[list[str]] = []

        def docker_exec(
            self, args: list[str], timeout: float = 0
        ) -> dict[str, Any]:
            require(timeout > 0, "Android token cleanup escaped its deadline")
            self.commands.append(list(args))
            if args[:2] == ["sh", "-c"]:
                return {"ok": True, "stdout": "2000:2000:771\n"}
            return {"ok": True, "stdout": ""}

        def _owned_container_record(
            self, timeout: float | None = None
        ) -> tuple[dict[str, Any], None]:
            require(timeout is not None and timeout > 0, "cleanup recheck unbounded")
            return {"Id": "1" * 64}, None

    android = AndroidTokenProbe()
    require(
        android._remove_legacy_android_rootd_token(
            "1" * 64,
            deadline=time.monotonic() + 30,
        ),
        "Android legacy token cleanup failed",
    )
    require(
        android.commands
        == [
            [
                "sh",
                "-c",
                "test -d /data/local/tmp && "
                "test ! -L /data/local/tmp && "
                "stat -c '%u:%g:%a' /data/local/tmp",
            ],
            ["rm", "-f", "--", "/data/local/tmp/.xenoid-rootd.token"],

            ["sync"],
        ],
        "Android token cleanup read/followed the obsolete entry",
    )
@contract_case("adbKeyPayloadUsesBoundedStdin")
def adb_key_payload_uses_bounded_stdin() -> None:
    with tempfile.TemporaryDirectory(
        prefix="xenoid-adb-stream-"
    ) as directory:
        root = Path(directory)
        public_key = "fixture-public-key host"
        public_key_path = root / "adbkey.pub"
        public_key_path.write_text(public_key + "\n", encoding="ascii")
        payload = (public_key + "\n").encode("ascii")
        expected_sha = hashlib.sha256(payload).hexdigest()
        manager = object.__new__(backend.RuntimeManager)
        manager.context = SimpleNamespace(
            project_root=ROOT,
            state_root=root,
        )
        manager.cancellation_event = None
        manager.adb = lambda _args: {"ok": True}
        manager.docker_base_cmd = lambda: ["docker"]
        manager.docker_env = lambda: {}
        manager._owned_container_record = lambda: (
            {"Id": "1" * 64},
            None,
        )

        def docker_exec(
            args: list[str],
            timeout: float = 0,
        ) -> dict[str, Any]:
            del timeout
            if "sha256sum" in " ".join(args):
                return {"ok": True, "stdout": expected_sha + "\n"}
            return {"ok": True, "stdout": ""}

        manager.docker_exec = docker_exec
        calls: list[tuple[list[str], dict[str, Any]]] = []

        def bounded(
            command: list[str],
            **kwargs: Any,
        ) -> SimpleNamespace:
            calls.append((list(command), dict(kwargs)))
            return SimpleNamespace(
                ok=True,
                returncode=0,
                state="passed",
                error_code=None,
                stderr_tail="",
            )

        with mock.patch.dict(
            os.environ,
            {"ADB_VENDOR_KEYS": str(public_key_path)},
        ), mock.patch.object(
            backend,
            "run_bounded",
            side_effect=bounded,
        ):
            result = manager.ensure_adb_authorized_key()
        require(result["ok"] is True, "bounded ADB key stream failed")
        require(len(calls) == 1, "ADB key stream launched extra children")
        command, kwargs = calls[0]
        require(
            command[1:4] == ["exec", "-i", "1" * 64],
            "ADB key stream did not use interactive docker exec",
        )
        require(
            kwargs.get("input_bytes") == payload
            and kwargs.get("max_input_bytes") == 64 * 1024,
            "ADB key stream lost its explicit payload bound",
        )
        require(
            public_key not in " ".join(command),
            "ADB public key leaked into argv",
        )



@contract_case("runtimeEpochBindsDaemonProcess")
def runtime_epoch_binds_daemon_process() -> None:
    class EpochProbe(backend.RuntimeManager):
        def __init__(self) -> None:
            self.pid = 401
            self.started = 9001
            self.stat_reads = 0

        def _owned_container_record(
            self, timeout: float | None = None
        ) -> tuple[dict[str, Any], None]:
            del timeout
            return {"Id": "1" * 64}, None

        def _rootd_output(
            self,
            args: list[str],
            limit: int = 0,
            deadline: float | None = None,
        ) -> str | None:
            del limit, deadline
            if args == ["pidof", "dev.xenoid.daemon"]:
                return str(self.pid)
            if args == ["cat", f"/proc/{self.pid}/stat"]:
                self.stat_reads += 1
                fields = ["0"] * 18
                fields[10] = str(self.stat_reads)
                return f"{self.pid} (daemon) S " + " ".join(
                    fields + [str(self.started)]
                )
            if args == ["cat", f"/proc/{self.pid}/status"]:
                return "Uid:\t10123\t10123\t10123\t10123\n"
            if args == ["stat", "-c", "%u", "/data/data/dev.xenoid.daemon"]:
                return "10123"
            if args == ["cat", "/proc/sys/kernel/random/boot_id"]:
                return "12345678-1234-4234-9234-123456789abc"
            return None

    probe = EpochProbe()
    first = probe._daemon_runtime_epoch()
    same = probe._daemon_runtime_epoch()
    probe.pid, probe.started = 402, 9017
    restarted = probe._daemon_runtime_epoch()
    require(isinstance(first, str), "production epoch unavailable")
    require(re.fullmatch(r"[0-9a-f]{64}", first) is not None, "epoch format")
    require(first == same and first != restarted, "epoch not bound to process identity")


@contract_case("outerDeadlineAndLocationRetry")
def outer_deadline_and_location_retry() -> None:
    class DeadlineProbe(backend.RuntimeManager):
        def __init__(self) -> None:
            self.observed_timeout: float | None = None

        def wait_daemon_transport(self, timeout: float) -> dict[str, Any]:
            self.observed_timeout = timeout
            return {
                "ok": False,
                "code": "daemon_transport_timeout",
                "error": "daemon_transport_timeout",
            }

    probe = DeadlineProbe()
    with mock.patch.object(backend, "bounded_timeout", return_value=4.0):
        result = probe.reconcile_bootstrap(timeout=300)
    require(result.get("code") == "daemon_transport_timeout", "deadline probe result")
    require(
        probe.observed_timeout is not None and 0 < probe.observed_timeout <= 4.0,
        "parent deadline did not cap transport",
    )

    location = source(
        "daemon/app/src/main/java/dev/xenoid/daemon/LocationIdentityManager.java"
    )
    require(
        'if ("location_state_invalid".equals(bootstrapError))' in location,
        "Location structural failure is not fail-closed",
    )
    require(
        "if (bootstrapError != null)" not in location,
        "transient Location failure prevents retry",
    )


@contract_case("rootdProtocolAndHostClassification")
def rootd_protocol_and_host_classification() -> None:
    native = source("native/xenoid-rootd/xenoid_rootd.c")
    for item in ("XENOID_ROOTD_TOKEN", "/data/local/tmp/.xenoid-rootd.token",
                 "getenv(", "popen(", "query_param(", "/exec?"):
        require(item not in native, f"legacy rootd transport: {item}")
    for item in ("POST", "/exec", "X-Xenoid-Request-Id", "X-Xenoid-Timeout-Ms",
                 "Content-Length", "text/plain", "/system/bin/sh", "PR_SET_DUMPABLE",
                 "dev.xenoid.rootd-exec/v1", "MAX_OUTPUT_BYTES", "4096", "MAX_HANDLERS"):
        require(item.lower() in native.lower(), f"rootd missing {item}")
    require("INADDR_LOOPBACK" in native, "rootd is not loopback")
    require("kill(-" in native or "killpg(" in native, "no process-group cancel")
    helper = source("daemon/app/src/main/java/dev/xenoid/daemon/RootHelper.java")
    require(all(item in helper for item in ("POST /exec", "X-Xenoid-Request-Id",
                                             "X-Xenoid-Timeout-Ms")), "RootHelper protocol")
    require("cancel" in helper.lower(), "RootHelper not cancellable")
    require("su -c" not in helper and "which su" not in helper, "RootHelper exposes su")
    host = source("src/xenoid/backend.py")
    client = source("src/xenoid/daemon_client.py")
    combined = host + client
    for item in ('state_root / "daemon.token"', 'state_root / "rootd.token"',
                 '"tokenSource"', '"host-cache"'):
        require(item not in combined, f"secret fallback retained: {item}")
    for item in ("daemon_token_unavailable", "rootd_unauthorized",
                 "rootd_resource_conflict", "read_private_token", "stdin"):
        require(item in combined, f"rootd classification missing {item}")
    for item in ("start_time", "executable", "digest", "uid", "listener"):
        require(item in host.lower(), f"legacy adoption omits {item}")


@contract_case("singleHostCliMcpBootstrapPath")
def single_host_cli_mcp_bootstrap_path() -> None:
    host, cli = source("src/xenoid/backend.py"), source("src/xenoid/cli.py")
    mcp = source("src/xenoid/mcp_server.py")
    require("def reconcile_bootstrap(" in host, "host owner missing")
    for item in ("def ensure_daemon(", "def repair_control_plane(",
                 "def launch_daemon_bootstrap("):
        require(item not in host, f"old path remains: {item}")
    require("def launch_daemon_activity_once(" in host, "one-shot launcher missing")
    require("def wait_daemon_transport(" in host, "transport wait missing")
    for text, label in ((cli, "CLI"), (mcp, "MCP")):
        require(".ensure_daemon(" not in text and ".repair_control_plane(" not in text,
                f"{label} retained old readiness")
        require(".reconcile_bootstrap(" in text, f"{label} bypasses bootstrap owner")
        for match in re.finditer("CAMERA_MUTATION_TIMEOUT_SECONDS", text):
            window = text[max(0, match.start() - 180):match.end() + 180]
            require("reconcile_bootstrap" not in window, f"{label} camera timeout readiness")
    require("def daemon_ensured(" not in cli, "CLI health-first helper remains")

@contract_case("regenerationRestartReceiptPrecedesReboot")
def regeneration_restart_receipt_precedes_reboot() -> None:
    probe = object.__new__(backend.RuntimeManager)
    probe.lease = SimpleNamespace(rootd_port=42870)
    client = SimpleNamespace(
        read_private_token=lambda force, timeout: TOKEN,
        health=lambda timeout: {"ok": True},
    )
    probe.daemon_client = lambda timeout: client
    probe.ensure_rootd_root = lambda timeout, daemon: {"ok": True}
    commands: list[str] = []

    def rootd_exec(command: str, token: str, **kwargs: Any) -> dict[str, Any]:
        commands.append(command)
        return {"ok": True, "exitCode": 0}

    probe._rootd_exec = rootd_exec
    probe._rootd_output = lambda args, **kwargs: (
        "running" if args[-1] == "init.svc.keystore2" else "1"
    )
    probe.reconcile_bootstrap = lambda timeout: {"controlReady": True}
    probe.reconcile_proxy_desired = lambda: {"ok": True}
    receipt = "a" * 32
    result = probe.soft_reboot(
        timeout=10,
        require_health=False,
        reset_ssaid=True,
        restart_receipt=receipt,
    )
    require(result.get("ok") is True, "soft reboot probe failed")
    reboot = commands[0]
    ssaid_delete = reboot.index("settings_ssaid.xml")
    receipt_write = reboot.index("printf '%s\\n'")
    ril_restart = reboot.index("ctl.restart vendor.ril-daemon")
    zygote_restart = reboot.index("ctl.restart zygote")
    require(
        ssaid_delete < receipt_write < ril_restart < zygote_restart,
        "receipt is not durably ordered before the restart",
    )



def main() -> int:
    selected = sys.argv[1:]
    unknown = [name for name in selected if name not in CASES]
    if unknown:
        print(json.dumps({"ok": False, "error": "unknown_case", "cases": unknown}))
        return 2
    ok, results = True, []
    for name in selected or list(CASES):
        try:
            CASES[name]()
            results.append({"name": name, "ok": True})
        except Exception as exc:
            ok = False
            results.append({"name": name, "ok": False,
                            "error": type(exc).__name__, "detail": str(exc)[:240]})
    print(json.dumps({"schema": "dev.xenoid.bootstrap-contract/v1",
                      "ok": ok, "cases": results}, separators=(",", ":"), sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
