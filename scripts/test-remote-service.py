#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import http.client
import io
import json
import os
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid.config import initialize_instance  # noqa: E402
from xenoid.operation_lock import (  # noqa: E402
    EXPECTED_INSTANCE_ID_ENV,
    OPERATION_LOCK_TIMEOUT_ENV,
)
from xenoid.remote_service import (  # noqa: E402
    DEFAULT_REQUESTS_PER_MINUTE,
    PROTOCOL_VERSION,
    REMOTE_TOOL_POLICIES,
    AccessStore,
    RateLimiter,
    ServiceApplication,
    ServiceError,
    XenoidHTTPServer,
    XenoidRequestHandler,
    _normalize_allowed_host,
    _normalize_origin,
    _serve,
    create_server,
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def meta() -> dict[str, Any]:
    return {
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {
            "name": "xenoid-service-contract",
            "version": "1.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def mcp_request(
    method: str,
    *,
    id_: Optional[int] = 1,
    name: Optional[str] = None,
    arguments: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    params: dict[str, Any] = {"_meta": meta()}
    if name is not None:
        params["name"] = name
        params["arguments"] = arguments or {}
    result: dict[str, Any] = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    }
    if id_ is not None:
        result["id"] = id_
    return result


class Fixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="xenoid-service-test.")
        root = Path(self.temporary.name)
        self.project = root / "project"
        self.home = root / "home"
        (self.project / "src" / "xenoid").mkdir(parents=True)
        self.home.mkdir()
        # Lease allocation probes host ports in production.  Contract tests may
        # run in sandboxes where bind probes are denied, so keep the allocator
        # deterministic while preserving its normal slot/overlap logic.
        with mock.patch("xenoid.config._port_available", return_value=True):
            initialize_instance(
                "phone-a", project_root=self.project, state_home=self.home
            )
            initialize_instance(
                "phone-b", project_root=self.project, state_home=self.home
            )
        self.store = AccessStore(self.project, state_home=self.home)

    def close(self) -> None:
        self.temporary.cleanup()


def access_store_contract(fixture: Fixture) -> tuple[str, str]:
    reader, reader_secret = fixture.store.create(
        "reader",
        scopes=["read"],
        instances=["phone-a"],
    )
    operator, operator_secret = fixture.store.create(
        "operator",
        scopes=["read", "control"],
        all_instances=True,
    )
    require(reader.public_dict()["instances"] == ["phone-a"], "reader ACL")
    require(operator.public_dict()["instances"] == ["*"], "wildcard ACL")
    raw = fixture.store.path.read_text()
    require(reader_secret not in raw and operator_secret not in raw, "plaintext token stored")
    require("digest" in raw, "token digest missing")
    require(stat.S_IMODE(fixture.store.path.stat().st_mode) == 0o600, "access mode")
    require(stat.S_IMODE(fixture.store.root.stat().st_mode) == 0o700, "service dir mode")
    require(
        fixture.store.authenticate(f"Bearer {reader_secret}") is not None,
        "reader authentication",
    )
    require(fixture.store.authenticate("Bearer xnd_invalid") is None, "invalid token")
    metadata = fixture.store.list_public()
    require(all("digest" not in item and "token" not in item for item in metadata), "secret metadata")

    fixture.store.create(
        "revoked",
        scopes=["read"],
        instances=["phone-a"],
    )
    require(fixture.store.revoke("revoked"), "token revoke")
    require(not fixture.store.revoke("revoked"), "repeat revoke")
    return reader_secret, operator_secret


def catalog_and_routing_contract(
    fixture: Fixture,
    reader_secret: str,
    operator_secret: str,
) -> ServiceApplication:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    def fake_call(runtime: Any, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        require(not hasattr(runtime, "auto_ensure_daemon"), "remote retained daemon bypass")
        calls.append((runtime.context.instance_name, name, dict(arguments)))
        value = {
            "ok": True,
            "instance": runtime.context.instance_name,
            "operation": name,
            "token": "must-not-leak",
            "hostPath": str(fixture.project / "private"),
            "authorization": "Bearer must-not-leak",
            "apiKey": "must-not-leak",
            "endpoint": "https" + "://service.example/path?to" + "ken=must-not-leak",
            "externalError": "failed at /srv/operator/private-state",
        }
        return {"content": [{"type": "text", "text": json.dumps(value)}]}

    app = ServiceApplication(
        fixture.project,
        state_home=fixture.home,
        tool_caller=fake_call,
    )
    reader = fixture.store.authenticate(f"Bearer {reader_secret}")
    operator = fixture.store.authenticate(f"Bearer {operator_secret}")
    require(reader is not None and operator is not None, "fixture authentication")
    reader_names = {tool["name"] for tool in app.remote_tools(reader)}
    operator_tools = {tool["name"]: tool for tool in app.remote_tools(operator)}
    require(
        all("keybox" not in name.lower() for name in reader_names | set(operator_tools)),
        "trusted-local keybox operation leaked to remote catalog",
    )
    require(
        all("keybox" not in name.lower() for name in REMOTE_TOOL_POLICIES),
        "trusted-local keybox operation leaked to remote policy",
    )
    require("xenoid_instances_list" in reader_names, "instance list missing")
    require("xenoid_status" in reader_names, "read tool missing")
    require("xenoid_proxy_check" not in reader_names, "stateful check leaked to read")
    require("xenoid_up" not in reader_names, "control tool leaked to reader")
    require("xenoid_root_exec" not in operator_tools, "root leaked to control scope")
    require("xenoid_up" in operator_tools, "production up missing")
    require(
        all(policy.schema_properties is not None for policy in REMOTE_TOOL_POLICIES.values()),
        "remote schema policy is fail-open",
    )
    up_schema = operator_tools["xenoid_up"]["inputSchema"]
    require("instance" in up_schema["required"], "instance not required")
    require(
        up_schema["properties"]["instance"].get("x-mcp-header") == "Instance",
        "instance routing header annotation missing",
    )
    require(up_schema.get("additionalProperties") is False, "schema not closed")
    require(
        set(up_schema["properties"]) == {"instance", "skipBuild"},
        "up schema differs from the clean cutover",
    )
    clear_schema = operator_tools["xenoid_proxy_clear"]["inputSchema"]
    require(
        set(clear_schema["properties"])
        == {"instance", "discardUnreadableState"},
        "proxy clear recovery boolean missing from remote schema",
    )
    require(
        clear_schema["properties"]["discardUnreadableState"]
        == {"type": "boolean"},
        "proxy clear recovery type is not exact",
    )
    require(
        "discardUnreadableState"
        in REMOTE_TOOL_POLICIES["xenoid_proxy_clear"].schema_properties,
        "remote proxy recovery boolean is not allowlisted",
    )
    tap_annotations = operator_tools["xenoid_input_tap"]["annotations"]
    require(
        tap_annotations["destructiveHint"] is True
        and tap_annotations["idempotentHint"] is False,
        "mutation annotations are unsafe",
    )
    for tool in operator_tools.values():
        properties = tool["inputSchema"].get("properties", {})
        forbidden = {
            "archive",
            "bundle",
            "outDir",
            "path",
            "policyPath",
            "profilePath",
            "remotePath",
            "scriptPath",
        }
        require(not (forbidden & set(properties)), f"host path exposed by {tool['name']}")

    listed = app.dispatch(
        reader,
        mcp_request(
            "tools/call", name="xenoid_instances_list", arguments={}
        ),
    )
    rows = listed["result"]["structuredContent"]["instances"]
    require([row["instanceName"] for row in rows] == ["phone-a"], "ACL list filter")
    status = app.dispatch(
        reader,
        mcp_request(
            "tools/call",
            name="xenoid_status",
            arguments={"instance": "phone-a"},
        ),
    )
    structured = status["result"]["structuredContent"]
    require(structured["instance"] == "phone-a", "instance routing")
    require(
        not ({"token", "hostPath", "authorization", "apiKey", "endpoint"} & set(structured)),
        "result key leak",
    )
    require(structured["externalError"] == "[redacted]", "absolute path leak")
    require(calls[-1][:2] == ("phone-a", "xenoid_status"), "wrong runtime selected")

    denied = app.dispatch(
        reader,
        mcp_request(
            "tools/call",
            name="xenoid_status",
            arguments={"instance": "phone-b"},
        ),
    )
    denied_result = denied["result"]
    require(
        denied_result["isError"] is True
        and denied_result["structuredContent"]["error"] == "instance_not_available",
        "instance ACL bypass or enumeration leak",
    )

    invalid = False
    try:
        app.dispatch(
            operator,
            mcp_request(
                "tools/call",
                name="xenoid_up",
                arguments={"instance": "phone-a", "skipBuild": "false"},
            ),
        )
    except ServiceError as exc:
        invalid = exc.code == "invalid_tool_arguments"
    require(invalid, "tool input types not enforced")

    initial_runtime = app._resolve_runtime("phone-a")
    rebound_runtime = replace(
        initial_runtime,
        context=replace(
            initial_runtime.context,
            instance_id="00000000-0000-4000-8000-000000000001",
        ),
    )
    call_count = len(calls)
    with mock.patch.object(
        app,
        "_resolve_runtime",
        side_effect=[initial_runtime, rebound_runtime],
    ):
        rebound = app.dispatch(
            operator,
            mcp_request(
                "tools/call",
                name="xenoid_up",
                arguments={"instance": "phone-a", "skipBuild": True},
            ),
        )
    require(
        rebound["result"]["isError"] is True
        and rebound["result"]["structuredContent"]["error"]
        == "instance_not_available",
        "instance UUID changed inside lock",
    )
    require(len(calls) == call_count, "tool ran after instance UUID changed")
    return app


def direct_up_lock_contract(fixture: Fixture, operator_secret: str) -> None:
    captured: list[Any] = []

    def capture(runtime: Any, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        captured.append((runtime, name, dict(arguments)))
        return {
            "content": [
                {"type": "text", "text": json.dumps({"ok": True})}
            ]
        }

    app = ServiceApplication(
        fixture.project,
        state_home=fixture.home,
        tool_caller=capture,
    )
    grant = fixture.store.authenticate(f"Bearer {operator_secret}")
    require(grant is not None, "operator authentication")
    legacy_token = app._resolve_runtime("phone-a").context.state_root / "daemon.token"
    legacy_token.write_text("legacy", encoding="ascii")
    legacy_token.chmod(0o600)
    app.dispatch(
        grant,
        mcp_request(
            "tools/call",
            name="xenoid_up",
            arguments={"instance": "phone-a", "skipBuild": True},
        ),
    )
    runtime, name, arguments = captured[-1]
    require(
        not legacy_token.exists(),
        "remote mutator did not migrate legacy token state under the lock",
    )
    require(name == "xenoid_up" and arguments == {"skipBuild": True}, "up dispatch")
    require(
        runtime.operation_lock_held is True,
        "remote up did not retain the service operation lock",
    )
    require(
        runtime.operation_lock_timeout_seconds == 0,
        "remote up lock timeout was not bounded",
    )
    environment = runtime.subprocess_env
    require(
        environment.get(EXPECTED_INSTANCE_ID_ENV) == runtime.context.instance_id,
        "expected instance UUID missing from direct up environment",
    )
    require(
        "XENOID_OPERATION_LOCK_HELD" not in environment,
        "direct up exported a forgeable operation-lock marker",
    )
    require(
        environment.get(OPERATION_LOCK_TIMEOUT_ENV) == "0",
        "direct up lock timeout missing",
    )

    for name, arguments in (
        ("xenoid_google_services_enable", {}),
        ("xenoid_google_services_disable", {}),
        ("xenoid_location_set", {"countryCode": "US"}),
    ):
        app.dispatch(
            grant,
            mcp_request(
                "tools/call",
                name=name,
                arguments={"instance": "phone-a", **arguments},
            ),
        )
        direct_runtime, direct_name, _ = captured[-1]
        require(direct_name == name, f"{name} dispatch")
        require(
            direct_runtime.operation_lock_held is True,
            f"service did not retain the {name} operation lock",
        )
        require(
            direct_runtime.operation_lock_timeout_seconds == 0,
            f"{name} operation lock timeout",
        )
        require(
            "XENOID_OPERATION_LOCK_HELD" not in direct_runtime.subprocess_env,
            f"service exported a forgeable {name} lock marker",
        )

def concurrency_contract(fixture: Fixture, operator_secret: str) -> None:
    guard = threading.Lock()
    active_by_instance: dict[str, int] = {"phone-a": 0, "phone-b": 0}
    max_by_instance: dict[str, int] = {"phone-a": 0, "phone-b": 0}
    global_active = 0
    global_max = 0
    busy = 0

    def slow_call(runtime: Any, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        nonlocal global_active, global_max
        instance = runtime.context.instance_name
        with guard:
            active_by_instance[instance] += 1
            max_by_instance[instance] = max(
                max_by_instance[instance], active_by_instance[instance]
            )
            global_active += 1
            global_max = max(global_max, global_active)
        time.sleep(0.12)
        with guard:
            active_by_instance[instance] -= 1
            global_active -= 1
        return {
            "content": [
                {"type": "text", "text": json.dumps({"ok": True})}
            ]
        }

    app = ServiceApplication(
        fixture.project,
        state_home=fixture.home,
        tool_caller=slow_call,
    )
    grant = fixture.store.authenticate(f"Bearer {operator_secret}")
    require(grant is not None, "operator authentication")

    def invoke(instance: str) -> None:
        nonlocal busy
        try:
            app.dispatch(
                grant,
                mcp_request(
                    "tools/call",
                    name="xenoid_stop",
                    arguments={"instance": instance},
                ),
            )
        except ServiceError as exc:
            require(exc.code == "instance_busy", "unexpected concurrency error")
            with guard:
                busy += 1

    same = [threading.Thread(target=invoke, args=("phone-a",)) for _ in range(2)]
    for thread in same:
        thread.start()
    for thread in same:
        thread.join()
    require(max_by_instance["phone-a"] == 1, "same-instance mutation overlapped")
    require(busy == 1, "same-instance contention did not fail fast")

    global_max = 0
    parallel = [
        threading.Thread(target=invoke, args=("phone-a",)),
        threading.Thread(target=invoke, args=("phone-b",)),
    ]
    for thread in parallel:
        thread.start()
    for thread in parallel:
        thread.join()
    require(global_max >= 2, "different instances were globally serialized")
    for instance in ("phone-a", "phone-b"):
        context = app._resolve_runtime(instance).context
        lock = context.state_root / "operation.lock"
        require(lock.is_file() and stat.S_IMODE(lock.stat().st_mode) == 0o600, "lock mode")

    alpha_root = app._resolve_runtime("phone-a").context.state_root
    beta_root = app._resolve_runtime("phone-b").context.state_root
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    holder_code = (
        "import pathlib,sys,time; "
        "from xenoid.operation_lock import instance_operation_lock; "
        "cm=instance_operation_lock(pathlib.Path(sys.argv[1])); cm.__enter__(); "
        "print('locked', flush=True); time.sleep(0.5); cm.__exit__(None,None,None)"
    )
    holder = subprocess.Popen(
        [sys.executable, "-c", holder_code, str(alpha_root)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    require(holder.stdout is not None and holder.stdout.readline().strip() == "locked", "holder")
    contender_code = (
        "import pathlib,sys; from xenoid.config import InstanceError; "
        "from xenoid.operation_lock import instance_operation_lock; "
        "\ntry:\n with instance_operation_lock(pathlib.Path(sys.argv[1]), timeout_seconds=0): pass"
        "\nexcept InstanceError as exc:\n raise SystemExit(0 if exc.code == 'instance_busy' else 2)"
        "\nraise SystemExit(1)"
    )
    contender = subprocess.run(
        [sys.executable, "-c", contender_code, str(alpha_root)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=5,
    )
    require(contender.returncode == 0, "cross-process same-instance lock bypass")
    other_code = (
        "import pathlib,sys; from xenoid.operation_lock import instance_operation_lock; "
        "cm=instance_operation_lock(pathlib.Path(sys.argv[1]), timeout_seconds=0); "
        "cm.__enter__(); cm.__exit__(None,None,None)"
    )
    other = subprocess.run(
        [sys.executable, "-c", other_code, str(beta_root)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=5,
    )
    require(other.returncode == 0, "different instance blocked across processes")
    require(holder.wait(timeout=5) == 0, "lock holder failed")


class HTTPFixture:
    def __init__(
        self,
        app: ServiceApplication,
        *,
        max_concurrency: int = 8,
        requests_per_minute: int = 1000,
    ):
        self.server = create_server(
            app,
            bind="127.0.0.1",
            port=0,
            allowed_origins=["https://client.example"],
            allowed_hosts=["127.0.0.1", "localhost"],
            max_request_bytes=4096,
            max_concurrency=max_concurrency,
            requests_per_minute=requests_per_minute,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(
        self,
        method: str,
        path: str,
        *,
        token: Optional[str] = None,
        body: Optional[Any] = None,
        origin: Optional[str] = None,
        header_overrides: Optional[dict[str, str]] = None,
    ) -> tuple[int, dict[str, str], Any]:
        connection = http.client.HTTPConnection(
            self.host,
            self.port,
            timeout=5,
        )
        headers: dict[str, str] = {}
        encoded: Optional[bytes] = None
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if origin is not None:
            headers["Origin"] = origin
        if body is not None:
            if isinstance(body, bytes):
                encoded = body
            else:
                encoded = json.dumps(body).encode()
            headers.update(
                {
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                }
            )
            if isinstance(body, dict):
                headers["MCP-Protocol-Version"] = PROTOCOL_VERSION
                headers["Mcp-Method"] = str(body.get("method", ""))
                params = body.get("params")
                if isinstance(params, dict) and body.get("method") == "tools/call":
                    name = params.get("name")
                    if isinstance(name, str):
                        headers["Mcp-Name"] = name
                    arguments = params.get("arguments")
                    if isinstance(arguments, dict) and isinstance(arguments.get("instance"), str):
                        headers["Mcp-Param-Instance"] = arguments["instance"]
        headers.update(header_overrides or {})
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        response_headers = {name.lower(): value for name, value in response.getheaders()}
        require(
            response_headers.get("connection", "").lower() == "close",
            f"{method} {path} response kept the connection alive",
        )
        connection.close()
        parsed: Any = None
        if payload:
            parsed = json.loads(payload)
        return response.status, response_headers, parsed


def http_contract(
    app: ServiceApplication,
    reader_secret: str,
    operator_secret: str,
) -> None:
    server = HTTPFixture(app)
    try:
        status, headers, body = server.request("GET", "/healthz")
        require(status == 200 and body["ok"], "health endpoint")
        require(headers.get("connection") == "close", "health connection policy")
        status, headers, body = server.request(
            "OPTIONS",
            "/mcp",
            origin="https://client.example",
        )
        require(status == 204 and body is None, "OPTIONS endpoint")
        require(headers.get("connection") == "close", "OPTIONS connection policy")
        status, _, body = server.request("DELETE", "/mcp")
        require(status == 405 and body is None, "DELETE MCP must be disabled")
        status, headers, _ = server.request(
            "POST",
            "/mcp",
            body=mcp_request("server/discover"),
        )
        require(status == 401 and "www-authenticate" in headers, "missing auth")

        status, headers, body = server.request(
            "POST",
            "/mcp",
            token=reader_secret,
            origin="https://client.example",
            body=mcp_request("server/discover"),
        )
        require(status == 200, "server/discover status")
        require(body["result"]["supportedVersions"] == [PROTOCOL_VERSION], "discover version")
        require(headers.get("access-control-allow-origin") == "https://client.example", "CORS")

        status, _, body = server.request(
            "POST", "/mcp", token=reader_secret, body=mcp_request("tools/list")
        )
        names = {tool["name"] for tool in body["result"]["tools"]}
        require(status == 200 and "xenoid_up" not in names, "scoped tools/list")
        require(body["result"]["resultType"] == "complete", "modern list result")

        status, _, body = server.request(
            "POST",
            "/mcp",
            token=reader_secret,
            body=mcp_request(
                "tools/call", name="xenoid_instances_list", arguments={}
            ),
        )
        require(status == 200, "instance list tool")
        instances = body["result"]["structuredContent"]["instances"]
        require([item["instanceName"] for item in instances] == ["phone-a"], "HTTP ACL")

        status, _, body = server.request(
            "POST",
            "/mcp",
            token=reader_secret,
            body=mcp_request(
                "tools/call",
                name="xenoid_status",
                arguments={"instance": "phone-a"},
            ),
        )
        require(status == 200 and body["result"]["resultType"] == "complete", "tool call")

        status, _, body = server.request(
            "POST",
            "/mcp",
            token=reader_secret,
            body=mcp_request(
                "tools/call",
                name="xenoid_status",
                arguments={"instance": "phone-a"},
            ),
            header_overrides={"Mcp-Param-Instance": "phone-b"},
        )
        require(status == 400 and body["error"]["code"] == -32020, "header mismatch")

        status, _, body = server.request(
            "POST",
            "/mcp",
            token=reader_secret,
            body=mcp_request("tools/list"),
            header_overrides={"MCP-Protocol-Version": "2025-11-25"},
        )
        require(
            status == 400 and body["error"]["code"] == -32020,
            "protocol header/body mismatch code",
        )

        unsupported = mcp_request("tools/list")
        unsupported["params"]["_meta"][
            "io.modelcontextprotocol/protocolVersion"
        ] = "2025-11-25"
        status, _, body = server.request(
            "POST",
            "/mcp",
            token=reader_secret,
            body=unsupported,
            header_overrides={"MCP-Protocol-Version": "2025-11-25"},
        )
        require(
            status == 400 and body["error"]["code"] == -32022,
            "unsupported protocol code",
        )

        status, _, _ = server.request(
            "POST",
            "/mcp",
            token=reader_secret,
            origin="https://evil.example",
            body=mcp_request("tools/list"),
        )
        require(status == 403, "Origin validation")

        status, _, _ = server.request("GET", "/mcp", token=reader_secret)
        require(status == 405, "GET MCP must be disabled")
        status, _, body = server.request("GET", "/v1/instances", token=reader_secret)
        require(status == 200 and len(body["instances"]) == 1, "HTTP instance inventory")

        notification = mcp_request("notifications/cancelled", id_=None)
        status, _, body = server.request(
            "POST", "/mcp", token=reader_secret, body=notification
        )
        require(status == 202 and body is None, "notification response")

        invalid_notification = mcp_request("notifications/cancelled", id_=None)
        invalid_notification["jsonrpc"] = "1.0"
        status, _, body = server.request(
            "POST", "/mcp", token=reader_secret, body=invalid_notification
        )
        require(
            status == 400 and body["error"]["code"] == -32600,
            "invalid notification accepted",
        )

        status, _, body = server.request(
            "POST", "/mcp", token=reader_secret, body=mcp_request("ping")
        )
        require(status == 404 and body["error"]["code"] == -32601, "legacy ping")

        status, _, body = server.request(
            "POST",
            "/mcp",
            token=operator_secret,
            body=mcp_request("unknown/method"),
        )
        require(status == 404 and body["error"]["code"] == -32601, "unknown method")

        status, _, _ = server.request(
            "POST",
            "/mcp",
            token=operator_secret,
            body=b"{" + b"x" * 5000,
            header_overrides={
                "MCP-Protocol-Version": PROTOCOL_VERSION,
                "Mcp-Method": "tools/list",
            },
        )
        require(status == 413, "request size limit")

        status, _, _ = server.request(
            "GET",
            "/healthz",
            header_overrides={"Host": "127.0.0.1:99999"},
        )
        require(status == 400, "invalid inbound Host port accepted")

        connection = http.client.HTTPConnection(server.host, server.port, timeout=5)
        connection.putrequest("GET", "/healthz", skip_host=True)
        connection.putheader("Host", "127.0.0.1")
        connection.putheader("Host", "evil.example")
        connection.endheaders()
        response = connection.getresponse()
        response.read()
        require(response.status == 400, "duplicate Host accepted")
        response_headers = {
            name.lower(): value for name, value in response.getheaders()
        }
        require(
            response_headers.get("connection", "").lower() == "close",
            "duplicate Host response kept the connection alive",
        )
        connection.close()

    finally:
        server.close()


def incomplete_body_contract(fixture: Fixture, reader_secret: str) -> None:
    tool_caller = mock.Mock(
        return_value={
            "content": [
                {"type": "text", "text": json.dumps({"ok": True})}
            ]
        }
    )
    app = ServiceApplication(
        fixture.project,
        state_home=fixture.home,
        tool_caller=tool_caller,
    )
    server = HTTPFixture(app)
    client: Optional[socket.socket] = None
    try:
        body = json.dumps(
            mcp_request(
                "tools/call",
                name="xenoid_status",
                arguments={"instance": "phone-a"},
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        declared_length = len(body) + 64
        request = (
            f"POST /mcp HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{server.port}\r\n"
            f"Authorization: Bearer {reader_secret}\r\n"
            "Content-Type: application/json\r\n"
            "Accept: application/json, text/event-stream\r\n"
            f"MCP-Protocol-Version: {PROTOCOL_VERSION}\r\n"
            "Mcp-Method: tools/call\r\n"
            "Mcp-Name: xenoid_status\r\n"
            "Mcp-Param-Instance: phone-a\r\n"
            f"Content-Length: {declared_length}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii") + body
        with mock.patch.object(app, "dispatch", wraps=app.dispatch) as dispatch:
            client = socket.create_connection((server.host, server.port), timeout=5)
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            response = http.client.HTTPResponse(client)
            response.begin()
            payload = response.read()
            require(response.status == 400, "short request body status")
            require(
                response.getheader("Connection", "").lower() == "close",
                "short request body connection policy",
            )
            parsed = json.loads(payload)
            require(
                parsed["error"]["message"] == "request_body_incomplete",
                "short request body error",
            )
            dispatch.assert_not_called()
        tool_caller.assert_not_called()
    finally:
        if client is not None:
            client.close()
        server.close()


def rate_limiter_contract() -> None:
    limiter = RateLimiter(10000, max_principals=4)
    for index in range(128):
        limiter.allow(f"rotating-source-{index}")
    require(
        len(limiter._events) <= 4,
        "rate limiter principal table grew past its hard limit",
    )


def connection_fairness_contract(app: ServiceApplication) -> None:
    loopback_server = create_server(
        app,
        bind="127.0.0.1",
        port=0,
        allowed_origins=[],
        allowed_hosts=["127.0.0.1"],
    )
    try:
        for port in range(20000, 20020):
            principal = loopback_server._reserve_connection(
                ("127.0.0.1", port)
            )
            require(principal is not None, "default loopback connection quota")
            loopback_server._release_connection(principal)
        require(
            not loopback_server._active_connections,
            "loopback connection reservation leak",
        )
        for port in range(21000, 21000 + DEFAULT_REQUESTS_PER_MINUTE):
            principal = loopback_server._reserve_connection(
                ("192.0.2.44", port)
            )
            require(principal is not None, "direct TLS connection quota")
            loopback_server._release_connection(principal)
        require(
            loopback_server._reserve_connection(("192.0.2.44", 22001)) is None,
            "direct source quota was not enforced",
        )
        other = loopback_server._reserve_connection(("198.51.100.44", 22002))
        require(other is not None, "one direct source exhausted global quota")
        loopback_server._release_connection(other)
    finally:
        loopback_server.server_close()

    server = object.__new__(XenoidHTTPServer)
    server.max_connections_per_principal = 1
    server._active_connections_lock = threading.Lock()

    def exercise(
        first_address: str,
        excess_address: str,
        other_address: str,
    ) -> None:
        server._active_connections = {}
        server.connection_ip_limiter = RateLimiter(1000, max_principals=8)
        server.connection_limiter = RateLimiter(2, max_principals=1)
        first = server._reserve_connection((first_address, 10001))
        require(first is not None, "initial connection reservation")
        for port in range(10002, 10034):
            require(
                server._reserve_connection((excess_address, port)) is None,
                "same-principal active connection cap bypass",
            )
        other = server._reserve_connection((other_address, 20001))
        require(other is not None, "local excess exhausted global fairness")
        require(
            len(server.connection_limiter._events["global"]) == 2,
            "rejected local excess consumed global reservations",
        )
        server._release_connection(first)
        server._release_connection(other)
        require(not server._active_connections, "connection reservation leak")

    exercise("192.0.2.1", "192.0.2.1", "198.51.100.1")
    exercise("2001:db8:1::1", "2001:db8:1::ffff", "2001:db8:2::1")


def pre_header_deadline_contract() -> None:
    handler = object.__new__(XenoidRequestHandler)
    handler.server = SimpleNamespace(
        settings=SimpleNamespace(request_timeout_seconds=30)
    )
    handler.connection = mock.Mock(name="pre-header-connection")
    with mock.patch.object(
        socketserver.StreamRequestHandler,
        "setup",
        return_value=None,
    ):
        XenoidRequestHandler.setup(handler)
    setup_timeout = handler.connection.settimeout.call_args.args[0]
    require(0 < setup_timeout <= 5, "setup pre-header timeout exceeded five seconds")

    timer = mock.Mock(name="pre-header-timer")
    with contextlib.ExitStack() as stack:
        timer_factory = stack.enter_context(
            mock.patch(
                "xenoid.remote_service.threading.Timer",
                return_value=timer,
            )
        )
        stack.enter_context(
            mock.patch(
                "xenoid.remote_service.BaseHTTPRequestHandler.handle_one_request"
            )
        )
        XenoidRequestHandler.handle_one_request(handler)
    handle_timeout = timer_factory.call_args.args[0]
    require(0 < handle_timeout <= 5, "header read deadline exceeded five seconds")
    timer.start.assert_called_once_with()
    timer.cancel.assert_called_once_with()


def inbound_rate_limit_contract(app: ServiceApplication) -> None:
    limiter_server = SimpleNamespace(
        inbound_limiter=RateLimiter(1, max_principals=1),
        auth_limiter=RateLimiter(1000, max_principals=2),
    )
    first = object.__new__(XenoidRequestHandler)
    first.server = limiter_server
    first.client_address = ("192.0.2.1", 10001)
    first._admit_request()
    second = object.__new__(XenoidRequestHandler)
    second.server = limiter_server
    second.client_address = ("198.51.100.1", 10002)
    try:
        second._admit_request()
    except ServiceError as exc:
        require(exc.code == "rate_limit_exceeded", "unstable global limiter error")
    else:
        raise AssertionError("rotating source bypassed the global inbound limiter")
    require(
        list(limiter_server.auth_limiter._events) == ["ip:192.0.2.1"],
        "rotating source reached the per-IP limiter after global rejection",
    )

    cases = (
        ("GET", "/healthz", {}, 200),
        ("OPTIONS", "/mcp", {"origin": "https://client.example"}, 204),
        ("POST", "/mcp", {"body": mcp_request("server/discover")}, 401),
        ("DELETE", "/mcp", {}, 405),
    )
    for method, path, request_options, first_status in cases:
        server = HTTPFixture(app, requests_per_minute=1)
        server.server.inbound_limiter = RateLimiter(1, max_principals=1)
        try:
            status, _, _ = server.request(
                method,
                path,
                **request_options,
            )
            require(status == first_status, f"{method} inbound limiter baseline")
            status, headers, body = server.request(
                method,
                path,
                **request_options,
            )
            require(status == 429, f"{method} bypassed the global inbound limiter")
            require(
                body["error"]["message"] == "rate_limit_exceeded",
                f"{method} inbound limiter error",
            )
            require(headers.get("retry-after") == "1", f"{method} retry header")
        finally:
            server.close()


def admission_limit_contract(app: ServiceApplication) -> None:
    server = HTTPFixture(app, max_concurrency=1)
    require(server.server.capacity.acquire(blocking=False), "capacity fixture")
    try:
        rejected = False
        try:
            server.request("GET", "/healthz")
        except (OSError, http.client.HTTPException):
            rejected = True
        require(rejected, "connection admission limit bypass")
    finally:
        server.server.capacity.release()
        server.close()


def tls_accept_contract(fixture: Fixture) -> None:
    tls_root = fixture.project.parent / "tls"
    tls_root.mkdir()
    certificate = tls_root / "service.crt"
    private_key = tls_root / "service.key"
    certificate.write_text("test certificate\n")
    private_key.write_text("test private key\n")
    private_key.chmod(0o600)

    listener = mock.Mock(name="listener")
    fake_server = SimpleNamespace(
        socket=listener,
        server_address=("0.0.0.0", 8765),
        tls_context=None,
        serve_forever=mock.Mock(),
        server_close=mock.Mock(),
    )
    tls_context = mock.Mock(name="tls-context")
    args = SimpleNamespace(
        tls_cert=str(certificate),
        tls_key=str(private_key),
        allow_insecure_http=False,
        bind="0.0.0.0",
        allow_host=["service.example"],
        allow_origin=[],
        port=8765,
        max_request_bytes=4096,
        request_timeout=30,
        max_concurrency=2,
        requests_per_minute=60,
        verbose=False,
    )
    with contextlib.ExitStack() as stack:
        stack.enter_context(
            mock.patch(
                "xenoid.remote_service.create_server",
                return_value=fake_server,
            )
        )
        stack.enter_context(
            mock.patch(
                "xenoid.remote_service.ssl.SSLContext",
                return_value=tls_context,
            )
        )
        stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        require(_serve(args, fixture.project) == 0, "TLS service setup")
    require(fake_server.socket is listener, "TLS setup replaced the listening socket")
    require(
        fake_server.tls_context is tls_context,
        "TLS context was not attached to the HTTP server",
    )
    tls_context.wrap_socket.assert_not_called()
    tls_context.load_cert_chain.assert_called_once_with(
        certfile=str(certificate.resolve()),
        keyfile=str(private_key.resolve()),
    )

    accepted = mock.Mock(name="accepted-socket")
    wrapped = mock.Mock(name="wrapped-socket")
    client_address = ("127.0.0.1", 54321)
    tls_context.reset_mock()
    tls_context.wrap_socket.return_value = wrapped
    http_server = object.__new__(XenoidHTTPServer)
    http_server.tls_context = tls_context
    http_server.socket = mock.Mock(name="listening-socket")
    http_server.socket.accept.return_value = (accepted, client_address)
    request, address = XenoidHTTPServer.get_request(http_server)
    http_server.socket.accept.assert_called_once_with()
    require(request is wrapped and address == client_address, "TLS accepted socket")
    tls_context.wrap_socket.assert_called_once_with(
        accepted,
        server_side=True,
        do_handshake_on_connect=False,
    )


def deployment_guard_contract(fixture: Fixture) -> None:
    for invalid in ("https://client.example:99999", "https://[::1"):
        try:
            _normalize_origin(invalid)
        except ServiceError as exc:
            require(exc.code == "origin_invalid", "unstable Origin error")
        else:
            raise AssertionError("invalid Origin accepted")
    try:
        _normalize_allowed_host("service.example:99999")
    except ServiceError as exc:
        require(exc.code == "host_invalid", "unstable Host error")
    else:
        raise AssertionError("invalid Host accepted")

    args = SimpleNamespace(
        tls_cert=None,
        tls_key=None,
        allow_insecure_http=False,
        bind="0.0.0.0",
        allow_host=["service.example"],
        allow_origin=[],
        port=8765,
        max_request_bytes=4096,
        request_timeout=30,
        max_concurrency=2,
        requests_per_minute=60,
        verbose=False,
    )
    try:
        _serve(args, fixture.project)
    except ServiceError as exc:
        require(exc.code == "tls_required_for_remote_bind", "remote TLS guard")
    else:
        raise AssertionError("cleartext remote bind accepted")

    args.allow_insecure_http = True
    fake_server = SimpleNamespace(
        server_address=("0.0.0.0", 8765),
        tls_context=None,
        serve_forever=mock.Mock(),
        server_close=mock.Mock(),
    )
    stderr = io.StringIO()
    with mock.patch(
        "xenoid.remote_service.create_server", return_value=fake_server
    ), contextlib.redirect_stderr(stderr):
        require(_serve(args, fixture.project) == 0, "explicit insecure HTTP setup")
    startup = json.loads(stderr.getvalue())
    require(
        startup.get("transportSecurity") == "insecure-http",
        "insecure HTTP startup was not visibly marked",
    )
    require("warning" in startup, "insecure HTTP startup omitted warning")
    fake_server.serve_forever.assert_called_once_with(poll_interval=0.5)


def main() -> int:
    fixture = Fixture()
    try:
        reader_secret, operator_secret = access_store_contract(fixture)
        app = catalog_and_routing_contract(
            fixture, reader_secret, operator_secret
        )
        direct_up_lock_contract(fixture, operator_secret)
        concurrency_contract(fixture, operator_secret)
        http_contract(app, reader_secret, operator_secret)
        incomplete_body_contract(fixture, reader_secret)
        rate_limiter_contract()
        connection_fairness_contract(app)
        pre_header_deadline_contract()
        inbound_rate_limit_contract(app)
        admission_limit_contract(app)
        tls_accept_contract(fixture)
        deployment_guard_contract(fixture)
    finally:
        fixture.close()
    print(
        json.dumps(
            {
                "ok": True,
                "protocolVersion": PROTOCOL_VERSION,
                "checks": [
                    "access-store",
                    "scoped-catalog",
                    "instance-routing",
                    "direct-up-operation-lock",
                    "operation-locking",
                    "streamable-http",
                    "incomplete-request-body",
                    "bounded-rate-limiting",
                    "connection-fairness",
                    "pre-header-deadline",
                    "deferred-tls-handshake",
                    "deployment-guards",
                    "explicit-insecure-http-opt-in",
                ],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
