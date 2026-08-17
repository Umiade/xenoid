#!/usr/bin/env python3
from __future__ import annotations

import ast
import contextlib
import io
import json
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid import cli, mcp_server  # noqa: E402
from xenoid.backend import RuntimeManager  # noqa: E402
from xenoid.util import command_timeout, run, validate_release_version  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def decoded(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


class FakeContext:
    project_root = ROOT
    instance_name = "phone-a"
    instance_id = "12345678"
    state_root = ROOT / ".xenoid" / "test-state"

    @staticmethod
    def public_dict() -> dict:
        return {
            "instanceName": "phone-a",
            "instanceId": "12345678",
            "resourceTag": "abcdef012345",
        }


class FakeManager:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def deploy_netctl_helper(self, path: str, remote_path: str) -> dict:
        self.calls.append(("deploy", path, remote_path))
        return {"ok": True, "operation": "deploy"}

    def netctl_status(self, ifname: str) -> dict:
        self.calls.append(("status", ifname))
        return {"ok": True, "operation": "status"}

    def netctl_set_mac(self, mac: str, ifname: str) -> dict:
        self.calls.append(("set-mac", mac, ifname))
        return {"ok": True, "operation": "set-mac"}


class FakeRuntime:
    def __init__(self) -> None:
        self.context = FakeContext()
        self.config = object()
        self.lease = object()
        self.manager = FakeManager()
        self.daemon = object()

    @property
    def subprocess_env(self) -> dict[str, str]:
        return {
            "XENOID_PROJECT": str(ROOT),
            "XENOID_INSTANCE": self.context.instance_name,
        }


def registered_tools_have_handlers() -> None:
    source = (ROOT / "src" / "xenoid" / "mcp_server.py").read_text()
    tree = ast.parse(source)
    handled: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Name)
            and node.left.id == "name"
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.Eq)
            and len(node.comparators) == 1
            and isinstance(node.comparators[0], ast.Constant)
            and isinstance(node.comparators[0].value, str)
        ):
            handled.add(node.comparators[0].value)
    registered = {entry["name"] for entry in mcp_server.tools()}
    require(registered == handled, f"tool/handler mismatch: {sorted(registered ^ handled)}")


def netctl_dispatches_to_runtime_manager() -> None:
    runtime = FakeRuntime()
    result = decoded(mcp_server.call_tool(
        runtime,
        "xenoid_netctl_deploy",
        {"path": "/tmp/netctl", "remotePath": "/data/local/tmp/netctl-test"},
    ))
    require(result == {"ok": True, "operation": "deploy"}, "netctl deploy result")
    result = decoded(mcp_server.call_tool(runtime, "xenoid_netctl_status", {}))
    require(result == {"ok": True, "operation": "status"}, "netctl status result")
    result = decoded(mcp_server.call_tool(
        runtime,
        "xenoid_netctl_set_mac",
        {"mac": "02:00:00:00:00:01", "ifname": "rmnet_test0"},
    ))
    require(result == {"ok": True, "operation": "set-mac"}, "netctl set result")
    require(runtime.manager.calls == [
        ("deploy", "/tmp/netctl", "/data/local/tmp/netctl-test"),
        ("status", "rmnet_data0"),
        ("set-mac", "02:00:00:00:00:01", "rmnet_test0"),
    ], "netctl arguments were not propagated")


def up_tool_uses_complete_cli_path() -> None:
    runtime = FakeRuntime()
    completed = subprocess.CompletedProcess([], 0, stdout="private output", stderr="")
    with mock.patch.object(mcp_server, "_run_up_cli_process", return_value=completed) as run_mock:
        result = decoded(mcp_server.call_tool(
            runtime,
            "xenoid_up",
            {"skipBuild": True, "reuseRuntime": True},
        ))
    command = run_mock.call_args.args[0]
    require(command == [
        str(ROOT / "xenoid"),
        "--instance",
        "phone-a",
        "up",
        "--skip-build",
        "--reuse-runtime",
    ], "xenoid_up did not invoke the complete CLI up path")
    require(run_mock.call_args.kwargs["cwd"] == ROOT, "xenoid_up cwd mismatch")
    require(result["ok"] is True and result["returncode"] == 0, "xenoid_up success result")
    require("private output" not in json.dumps(result), "xenoid_up leaked subprocess output")

    failed = subprocess.CompletedProcess(
        [],
        17,
        stdout="/private/operator/path",
        stderr="sensitive exception text",
    )
    with mock.patch.object(mcp_server, "_run_up_cli_process", return_value=failed):
        result = decoded(mcp_server.call_tool(runtime, "xenoid_up", {}))
    rendered = json.dumps(result)
    require(result.get("code") == "xenoid_up_failed", "xenoid_up failure code")
    require("private/operator" not in rendered and "sensitive" not in rendered, "xenoid_up leaked failure output")

    with mock.patch.object(
        mcp_server,
        "_run_up_cli_process",
        side_effect=OSError("/private/operator/executable"),
    ):
        result = decoded(mcp_server.call_tool(runtime, "xenoid_up", {}))
    require(result.get("code") == "xenoid_up_unavailable", "xenoid_up OSError code")
    require("private/operator" not in json.dumps(result), "xenoid_up leaked exception text")

    with mock.patch.object(
        mcp_server,
        "_run_up_cli_process",
        side_effect=RuntimeError("sensitive internal failure"),
    ):
        result = decoded(mcp_server.call_tool(runtime, "xenoid_up", {}))
    require(result.get("code") == "xenoid_up_unavailable", "xenoid_up exception code")
    require("sensitive" not in json.dumps(result), "xenoid_up leaked unexpected exception text")

    with mock.patch.object(mcp_server, "_run_up_cli_process") as run_mock:
        result = decoded(mcp_server.call_tool(
            runtime,
            "xenoid_up",
            {"skipBuild": "false"},
        ))
    require(result.get("code") == "invalid_request_schema", "xenoid_up type validation")
    run_mock.assert_not_called()


def generated_mcp_config_is_checkout_runnable() -> None:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        rc = cli.cmd_mcp_config(SimpleNamespace(context=FakeContext()))
    require(rc == 0, "mcp-config return code")
    server = json.loads(output.getvalue())["mcpServers"]["xenoid"]
    require(server["command"] == str(ROOT / "xenoid-mcp"), "wrapper not selected")
    require(server["args"] == [], "wrapper received module arguments")
    require(server["env"] == {
        "XENOID_PROJECT": str(ROOT),
        "XENOID_INSTANCE": "phone-a",
    }, "mcp-config instance binding")


def up_timeout_terminates_and_waits_for_process_group() -> None:
    class FakeProcess:
        pid = 4321
        returncode = None

        def __init__(self) -> None:
            self.communicate_calls = 0

        def communicate(self, timeout: object = None) -> tuple[str, str]:
            self.communicate_calls += 1
            if self.communicate_calls == 1:
                raise subprocess.TimeoutExpired(["xenoid"], 1)
            self.returncode = -15
            return "", ""

    process = FakeProcess()
    with mock.patch.object(mcp_server.subprocess, "Popen", return_value=process) as popen_mock, \
         mock.patch.object(mcp_server.os, "killpg") as kill_mock:
        try:
            mcp_server._run_up_cli_process(
                ["xenoid", "up"], cwd=ROOT, env={}
            )
        except subprocess.TimeoutExpired:
            pass
        else:
            raise AssertionError("up timeout was swallowed")
    require(popen_mock.call_args.kwargs["start_new_session"] is True, "no process group")
    kill_mock.assert_called_once_with(4321, mcp_server.signal.SIGTERM)
    require(process.communicate_calls == 2, "process group was not waited")


def stdio_mutations_use_shared_instance_lock() -> None:
    runtime = mcp_server.MCPRuntime(
        FakeContext(),
        object(),
        object(),
        FakeManager(),
        object(),
    )
    locked: list[Path] = []

    @contextlib.contextmanager
    def fake_lock(path: Path):
        locked.append(path)
        yield

    with mock.patch.object(
        mcp_server,
        "_refresh_stdio_runtime",
        side_effect=[runtime, runtime],
    ), mock.patch.object(
        mcp_server,
        "instance_operation_lock",
        side_effect=fake_lock,
    ), mock.patch.object(
        mcp_server,
        "call_tool",
        return_value={"ok": True},
    ) as call_mock:
        result = mcp_server._call_stdio_tool(
            runtime,
            "xenoid_input_tap",
            {"x": 1, "y": 2},
        )
    require(result == {"ok": True}, "stdio mutation result")
    require(locked == [FakeContext.state_root], "stdio mutation lock missing")
    locked_runtime = call_mock.call_args.args[0]
    require(locked_runtime.operation_lock_held is True, "nested lock marker missing")

    with mock.patch.object(
        mcp_server,
        "_refresh_stdio_runtime",
        return_value=runtime,
    ), mock.patch.object(
        mcp_server,
        "instance_operation_lock",
    ) as lock_mock, mock.patch.object(
        mcp_server,
        "call_tool",
        return_value={"ok": True},
    ):
        mcp_server._call_stdio_tool(runtime, "xenoid_status", {})
    lock_mock.assert_not_called()

    for child_name in mcp_server.CHILD_LOCK_TOOL_NAMES:
        with mock.patch.object(
            mcp_server,
            "_refresh_stdio_runtime",
            return_value=runtime,
        ), mock.patch.object(
            mcp_server,
            "instance_operation_lock",
        ) as lock_mock, mock.patch.object(
            mcp_server,
            "call_tool",
            return_value={"ok": True},
        ):
            mcp_server._call_stdio_tool(runtime, child_name, {})
        lock_mock.assert_not_called()

    rebound_context = SimpleNamespace(
        project_root=ROOT,
        instance_name="phone-a",
        instance_id="87654321",
        state_root=FakeContext.state_root,
    )
    rebound = replace(runtime, context=rebound_context)
    with mock.patch.object(
        mcp_server,
        "_refresh_stdio_runtime",
        side_effect=[runtime, rebound],
    ), mock.patch.object(
        mcp_server,
        "instance_operation_lock",
        side_effect=fake_lock,
    ), mock.patch.object(mcp_server, "call_tool") as call_mock:
        try:
            mcp_server._call_stdio_tool(runtime, "xenoid_stop", {})
        except Exception as exc:
            require(
                getattr(exc, "code", None) == "instance_identity_mismatch",
                "stdio UUID rebind error",
            )
        else:
            raise AssertionError("stdio mutation accepted rebound instance")
    call_mock.assert_not_called()


def remote_command_deadline_bounds_unset_subprocesses() -> None:
    started = time.monotonic()
    try:
        with command_timeout(0.05):
            run([sys.executable, "-c", "import time; time.sleep(5)"])
    except subprocess.TimeoutExpired:
        pass
    else:
        raise AssertionError("request command deadline was not enforced")
    require(time.monotonic() - started < 1.0, "command deadline did not fail fast")

    manager = object.__new__(RuntimeManager)
    started = time.monotonic()
    try:
        with command_timeout(0.05):
            manager._proxy_process(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                timeout=120,
            )
    except Exception as exc:
        require(
            getattr(exc, "code", None) == "engine_unavailable",
            "proxy process deadline error",
        )
    else:
        raise AssertionError("proxy process ignored request command deadline")
    require(time.monotonic() - started < 1.0, "proxy process deadline did not fail fast")


def versions_are_path_safe_before_side_effects() -> None:
    valid = ("dev", "0.1.0", "release_1-rc.2", "A" * 64)
    invalid = (
        "",
        ".",
        "..",
        "../outside",
        "a/../../../../outside",
        "a\\outside",
        " leading",
        "trailing ",
        "line\nbreak",
        "\u7248\u672c1",
        "A" * 65,
        None,
        1,
    )
    for value in valid:
        require(validate_release_version(value) == value, f"valid version rejected: {value!r}")
    for value in invalid:
        try:
            validate_release_version(value)
        except ValueError as exc:
            require(str(exc) == "release_version_invalid", "unstable version error")
        else:
            raise AssertionError(f"invalid version accepted: {value!r}")

    with mock.patch.object(cli.subprocess, "run") as run_mock:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = cli.cmd_package_release(SimpleNamespace(version="a/../../outside"))
    require(rc == 2, "CLI invalid version return code")
    require(json.loads(output.getvalue())["code"] == "release_version_invalid", "CLI invalid version result")
    run_mock.assert_not_called()

    ota = RuntimeManager.make_ota_bundle(object(), "a/../../outside")
    require(ota.get("code") == "release_version_invalid", "OTA Python validation")

    runtime = FakeRuntime()
    with mock.patch.object(mcp_server.subprocess, "run") as run_mock:
        result = decoded(mcp_server.call_tool(
            runtime,
            "xenoid_package_release",
            {"version": "a/../../outside"},
        ))
    require(result.get("code") == "release_version_invalid", "MCP release validation")
    run_mock.assert_not_called()

    for relative in ("scripts/package-release.sh", "scripts/make-ota-bundle.sh"):
        proc = subprocess.run(
            [str(ROOT / relative), "a/../../../../outside"],
            text=True,
            capture_output=True,
            cwd=ROOT,
        )
        require(proc.returncode == 64, f"{relative} invalid version return code")
        require(proc.stderr.strip() == "release_version_invalid", f"{relative} unstable error")


def main() -> int:
    cases = (
        registered_tools_have_handlers,
        netctl_dispatches_to_runtime_manager,
        up_tool_uses_complete_cli_path,
        generated_mcp_config_is_checkout_runnable,
        up_timeout_terminates_and_waits_for_process_group,
        stdio_mutations_use_shared_instance_lock,
        remote_command_deadline_bounds_unset_subprocesses,
        versions_are_path_safe_before_side_effects,
    )
    completed = []
    for case in cases:
        case()
        completed.append(case.__name__)
    print(json.dumps({"ok": True, "checks": completed}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
