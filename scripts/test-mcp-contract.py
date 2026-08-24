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
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid import cli, mcp_server  # noqa: E402
from xenoid.backend import RuntimeManager  # noqa: E402
from xenoid.util import command_timeout, run, validate_release_version  # noqa: E402

MICROG_PLAY_RELEASE = (
    "microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0"
)


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
        self.operation_lock_held = False

    def migrate_legacy_token_state(self) -> dict:
        self.calls.append(("legacy-token-migration",))
        return {"ok": True, "removed": 0}

    def deploy_netctl_helper(self, path: str, remote_path: str) -> dict:
        self.calls.append(("deploy", path, remote_path))
        return {"ok": True, "operation": "deploy"}

    def netctl_status(self, ifname: str) -> dict:
        self.calls.append(("status", ifname))
        return {"ok": True, "operation": "status"}

    def netctl_set_mac(self, mac: str, ifname: str) -> dict:
        self.calls.append(("set-mac", mac, ifname))
        return {"ok": True, "operation": "set-mac"}

    def runtime_image_input_record(self, base_image: str | None = None) -> dict:
        self.calls.append(("image-input", base_image))
        return {
            "schema": "dev.xenoid.runtime-image-input/v1",
            "inputSha256": "1" * 64,
            "bootInputSha256": "2" * 64,
            "derivedTag": "xenoid/redroid:xenoid-" + "1" * 32,
        }

    def ensure_runtime_image(self, base_image: str | None = None) -> dict:
        self.calls.append(("image-ensure", base_image))
        return {
            "ok": True,
            "schema": "dev.xenoid.runtime-image/v1",
            "inputSha256": "1" * 64,
            "bootInputSha256": "2" * 64,
            "derivedTag": "xenoid/redroid:xenoid-" + "1" * 32,
            "imageId": "sha256:" + "3" * 64,
            "reused": True,
        }


class FakeRuntime:
    def __init__(self) -> None:
        self.context = FakeContext()
        self.config = object()
        self.lease = object()
        self.manager = FakeManager()
        self.daemon = object()
        self.operation_lock_held = True

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


def keybox_is_trusted_local_cli_only() -> None:
    catalog = mcp_server.tools()
    serialized = json.dumps(catalog, sort_keys=True).lower()
    require("keybox" not in serialized, "keybox operation leaked into MCP catalog")
    runtime = SimpleNamespace(
        context=FakeContext(), config={}, manager=object(), daemon=object()
    )
    try:
        mcp_server.call_tool(runtime, "xenoid_keybox_status", {})
    except ValueError as exc:
        require(str(exc) == "unknown tool: xenoid_keybox_status", "unstable MCP denial")
    else:
        raise AssertionError("unregistered keybox MCP operation was callable")

def google_services_enable_defaults_to_microg_release() -> None:
    catalog = {entry["name"]: entry for entry in mcp_server.tools()}
    enable = catalog["xenoid_google_services_enable"]
    require(
        "microG production Google services release" in enable["description"],
        "MCP enable description does not identify the production microG provider",
    )
    require(
        "MindTheGapps" not in enable["description"],
        "MCP enable description still advertises the retired source",
    )
    require(
        enable["inputSchema"]
        == {
            "type": "object",
            "properties": {"release": {"type": "string"}},
        },
        "MCP Google enable schema drifted",
    )

    observed: list[str] = []

    def capture(arguments: Any) -> dict[str, Any]:
        observed.append(arguments.release)
        return {"ok": True, "release": arguments.release}

    runtime = FakeRuntime()
    with mock.patch.object(
        mcp_server,
        "_google_services_enable_result",
        side_effect=capture,
    ):
        defaulted = decoded(
            mcp_server.call_tool(
                runtime,
                "xenoid_google_services_enable",
                {},
            )
        )
        explicit = decoded(
            mcp_server.call_tool(
                runtime,
                "xenoid_google_services_enable",
                {"release": "operator-selected"},
            )
        )
    require(
        observed == [MICROG_PLAY_RELEASE, "operator-selected"],
        "MCP enable default or explicit release dispatch drifted",
    )
    require(
        defaulted.get("release") == MICROG_PLAY_RELEASE
        and explicit.get("release") == "operator-selected",
        "MCP enable result did not preserve the selected release",
    )


def proxy_unreadable_discard_is_explicit() -> None:
    catalog = {entry["name"]: entry for entry in mcp_server.tools()}
    clear_schema = catalog["xenoid_proxy_clear"]["inputSchema"]
    require(
        clear_schema.get("properties")
        == {"discardUnreadableState": {"type": "boolean"}},
        "proxy clear recovery boolean missing from MCP schema",
    )
    require(
        "required" not in clear_schema,
        "ordinary proxy clear must remain an explicit false default",
    )

    calls: list[bool] = []

    class Manager:
        @staticmethod
        def reconcile_bootstrap() -> dict:
            return {"ok": True, "transportReady": True, "controlReady": True}

    class Controller:
        def __init__(self, *_args: object) -> None:
            pass

        def clear(self, *, discard_unreadable_state: bool = False) -> dict:
            calls.append(discard_unreadable_state)
            return {"ok": True}

    runtime = mcp_server.MCPRuntime(
        FakeContext(),
        object(),
        object(),
        Manager(),
        object(),
    )
    with mock.patch.object(mcp_server, "ProxyController", Controller):
        require(
            decoded(mcp_server.call_tool(runtime, "xenoid_proxy_clear", {}))["ok"]
            is True,
            "ordinary MCP proxy clear failed",
        )
        require(
            decoded(
                mcp_server.call_tool(
                    runtime,
                    "xenoid_proxy_clear",
                    {"discardUnreadableState": True},
                )
            )["ok"]
            is True,
            "explicit MCP proxy recovery failed",
        )
    require(calls == [False, True], "MCP proxy clear recovery flag was not exact")


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


def up_tools_use_in_process_convergence() -> None:
    runtime = FakeRuntime()
    calls: list[tuple[str, Any]] = []
    result_payload = {
        "schema": "dev.xenoid.convergence/v1",
        "ok": True,
        "resumed": False,
        "dryRun": False,
        "plan": {"schema": "dev.xenoid.convergence-plan/v1", "planDigest": "1" * 64},
        "initialPlanDigest": "1" * 64,
        "resolvedPlanDigest": None,
        "followUpPlanDigest": None,
        "phases": [],
        "before": {},
        "after": {},
        "nextActions": [],
    }

    class FakeExecutor:
        def __init__(self, manager: object, **_kwargs: object) -> None:
            calls.append(("executor", manager))

        def run(self, **kwargs: object) -> dict[str, Any]:
            calls.append(("run", dict(kwargs)))
            return dict(result_payload)

    class FakePlan:
        def to_dict(self) -> dict[str, Any]:
            return {
                "schema": "dev.xenoid.convergence-plan/v1",
                "resolution": "complete",
                "planDigest": "2" * 64,
            }

    class FakePlanner:
        def __init__(self, manager: object, **_kwargs: object) -> None:
            calls.append(("planner", manager))

        def inspect(self, **kwargs: object) -> FakePlan:
            calls.append(("inspect", dict(kwargs)))
            return FakePlan()

    with mock.patch.object(mcp_server, "ConvergenceExecutor", FakeExecutor), \
         mock.patch.object(mcp_server, "ConvergencePlanner", FakePlanner):
        result = decoded(
            mcp_server.call_tool(runtime, "xenoid_up", {"skipBuild": True})
        )
        dry_plan = decoded(
            mcp_server.call_tool(runtime, "xenoid_up_plan", {})
        )

    require(result == result_payload, "xenoid_up changed the executor result")
    require(
        calls[0] == ("executor", runtime.manager)
        and calls[1][0] == "run"
        and calls[1][1].get("skip_build") is True,
        "xenoid_up did not call the shared executor directly",
    )
    require(
        calls[2] == ("planner", runtime.manager)
        and calls[3] == ("inspect", {"skip_build": False}),
        "xenoid_up_plan did not inspect through the shared planner",
    )
    require(
        dry_plan.get("schema") == "dev.xenoid.convergence-plan/v1"
        and dry_plan.get("planDigest") == "2" * 64,
        "xenoid_up_plan result is not the canonical plan",
    )

    regeneration_payload = {
        "schema": "dev.xenoid.convergence/v1",
        "ok": True,
        "regeneration": {
            "schema": "dev.xenoid.device-regenerate/v2",
            "transactionId": "3" * 32,
            "phase": "committed",
        },
    }
    with mock.patch.object(mcp_server, "RegenerationJournal") as journal_type, \
         mock.patch.object(
             mcp_server,
             "_execute_device_regeneration",
             return_value=regeneration_payload,
         ) as resume, \
         mock.patch.object(
             mcp_server,
             "ConvergenceExecutor",
             side_effect=AssertionError("regeneration bypassed shared resume"),
         ):
        journal_type.return_value.load.return_value = {
            "schema": "dev.xenoid.device-regenerate/v2",
            "transactionId": "3" * 32,
        }
        regenerated = decoded(
            mcp_server.call_tool(runtime, "xenoid_up", {"skipBuild": True})
        )
    require(
        regenerated == regeneration_payload,
        "xenoid_up changed regeneration resume result",
    )
    resume_args = resume.call_args.args[0]
    require(
        resume_args.context is runtime.context
        and resume_args.skip_build is True
        and resume_args._operation_lock_held is True,
        "xenoid_up did not pass the locked runtime into regeneration resume",
    )

    failed_payload = {
        **result_payload,
        "ok": False,
        "error": "convergence_state_conflict",
        "nextActions": ["resume"],
    }

    class FailingExecutor(FakeExecutor):
        def run(self, **kwargs: object) -> dict[str, Any]:
            calls.append(("failed-run", dict(kwargs)))
            return dict(failed_payload)

    with mock.patch.object(mcp_server, "ConvergenceExecutor", FailingExecutor):
        failed = decoded(mcp_server.call_tool(runtime, "xenoid_up", {}))
    require(failed == failed_payload, "xenoid_up hid the convergence failure")
    require("private/operator" not in json.dumps(failed), "xenoid_up leaked private output")

    with mock.patch.object(mcp_server, "ConvergenceExecutor", FakeExecutor):
        before = len(calls)
        invalid_type = decoded(
            mcp_server.call_tool(runtime, "xenoid_up", {"skipBuild": "false"})
        )
        removed_alias = decoded(
            mcp_server.call_tool(runtime, "xenoid_up", {"reuseRuntime": True})
        )
    require(
        invalid_type.get("code") == "invalid_request_schema",
        "xenoid_up skipBuild type validation",
    )
    require(
        removed_alias.get("code") == "invalid_request_schema",
        "removed reuseRuntime accepted",
    )
    require(len(calls) == before, "invalid xenoid_up request reached the executor")


def generated_mcp_config_is_checkout_runnable() -> None:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        rc = cli.cmd_mcp_config(SimpleNamespace(context=FakeContext()))
    require(rc == 0, "mcp-config return code")
    server = json.loads(output.getvalue())["mcpServers"]["xenoid"]
    require(server["command"] == "xenoid-mcp", "path-independent wrapper not selected")
    require(server["args"] == [], "wrapper received module arguments")
    require(
        server["env"] == {"XENOID_INSTANCE": "phone-a"},
        "mcp-config instance binding",
    )
    require(str(ROOT) not in json.dumps(server), "mcp-config leaked checkout path")


def up_source_has_no_nested_process() -> None:
    mcp_source = (ROOT / "src/xenoid/mcp_server.py").read_text(encoding="utf-8")
    require("_run_up_cli_process" not in mcp_source, "MCP retained the up child runner")
    require("_up_cli_result" not in mcp_source, "MCP retained the up CLI adapter")
    require("xenoid-up.sh" not in mcp_source, "MCP retained the shell up planner")
    require(
        "CHILD_LOCK_TOOL_NAMES" not in mcp_source,
        "MCP retained child-owned mutation lock exceptions",
    )
    require(
        "_location_cli_result" not in mcp_source
        and "_google_services_cli_result" not in mcp_source,
        "MCP retained nested feature CLI adapters",
    )
    require(
        'project_root / "xenoid"' not in mcp_source,
        "MCP retained a nested xenoid command path",
    )
    cli_source = (ROOT / "src/xenoid/cli.py").read_text(encoding="utf-8")
    tree = ast.parse(cli_source)
    handler = next(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "cmd_up"
    )
    rendered = ast.get_source_segment(cli_source, handler) or ""
    require(
        "ConvergenceExecutor" in rendered and ".run(" in rendered,
        "CLI up bypasses the shared executor",
    )
    require(
        "subprocess" not in rendered and "xenoid-up.sh" not in rendered,
        "CLI up retained nested process orchestration",
    )
    require(
        "--reuse-runtime" not in cli_source and "reuse_runtime" not in rendered,
        "CLI retained the removed reuse runtime alias",
    )


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
    require(
        ("legacy-token-migration",) in runtime.manager.calls,
        "stdio mutator did not migrate legacy token state under the lock",
    )
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
        "RegenerationJournal",
    ) as journal_type, mock.patch.object(
        mcp_server,
        "call_tool",
        return_value={"ok": True},
    ) as blocked_call:
        journal_type.return_value.load.return_value = {
            "phase": "storage_pending",
            "transactionId": "4" * 32,
        }
        blocked = decoded(
            mcp_server._call_stdio_tool(
                runtime,
                "xenoid_proxy_off",
                {},
            )
        )
    require(
        blocked.get("error") == "device_regeneration_pending",
        "stdio mutator bypassed regeneration guard",
    )
    blocked_call.assert_not_called()

    for direct_name, direct_arguments in (
        ("xenoid_up", {"skipBuild": True}),
        ("xenoid_google_services_enable", {}),
        ("xenoid_google_services_disable", {}),
        ("xenoid_location_set", {"countryCode": "US"}),
    ):
        locked.clear()
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
        ) as direct_call:
            mcp_server._call_stdio_tool(
                runtime,
                direct_name,
                direct_arguments,
            )
        require(
            locked == [FakeContext.state_root],
            f"stdio {direct_name} operation lock missing",
        )
        require(
            direct_call.call_args.args[0].operation_lock_held is True,
            f"stdio {direct_name} did not retain the shared operation lock",
        )

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
    with command_timeout(0.05):
        bounded = run([sys.executable, "-c", "import time; time.sleep(5)"])
    require(bounded.returncode != 0, "request command deadline was not enforced")
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

    with mock.patch.object(cli, "run_bounded") as run_mock:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = cli.cmd_package_release(SimpleNamespace(version="a/../../outside"))
    require(rc == 2, "CLI invalid version return code")
    require(json.loads(output.getvalue())["code"] == "release_version_invalid", "CLI invalid version result")
    run_mock.assert_not_called()

    ota = RuntimeManager.make_ota_bundle(object(), "a/../../outside")
    require(ota.get("code") == "release_version_invalid", "OTA Python validation")

    runtime = FakeRuntime()
    with mock.patch.object(mcp_server, "run_bounded") as run_mock:
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


def runtime_image_tool_uses_content_addressed_builder() -> None:
    source = (ROOT / "src" / "xenoid" / "mcp_server.py").read_text(encoding="utf-8")
    marker = '    if name == "xenoid_runtime_build_image":'
    require(source.count(marker) == 1, "runtime image MCP handler missing")
    branch = source.split(marker, 1)[1].split("\n    if name == ", 1)[0]
    require("ensure_runtime_image" in branch, "runtime image MCP bypasses shared builder")
    require("runtime_image_input_record" in branch, "runtime image dry-run lacks pure input record")
    require("subprocess.run" not in branch, "runtime image MCP invokes a raw build child")
    require("make_runtime_context" not in branch, "runtime image MCP creates an unowned context")
    require('"build"' not in branch, "runtime image MCP exposes the legacy Docker builder")

    cli_source = (ROOT / "src" / "xenoid" / "cli.py").read_text(encoding="utf-8")
    tree = ast.parse(cli_source)
    handler = next(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "cmd_runtime_build_image"
    )
    rendered = ast.get_source_segment(cli_source, handler) or ""
    require("ensure_runtime_image" in rendered, "runtime image CLI bypasses shared builder")
    require("runtime_image_input_record" in rendered, "runtime image CLI dry-run lacks pure record")
    require("subprocess.run" not in rendered, "runtime image CLI invokes a raw build child")
    require("make_runtime_context" not in rendered, "runtime image CLI creates an unowned context")

    runtime = FakeRuntime()
    dry_run = decoded(
        mcp_server.call_tool(
            runtime,
            "xenoid_runtime_build_image",
            {"image": "example/base:observed", "dryRun": True},
        )
    )
    ensured = decoded(
        mcp_server.call_tool(
            runtime,
            "xenoid_runtime_build_image",
            {"image": "example/base:observed", "dryRun": False},
        )
    )
    require(dry_run["dryRun"] is True, "runtime image MCP dry-run schema")
    require(dry_run["schema"] == "dev.xenoid.runtime-image-input/v1", "runtime input schema")
    require(ensured["schema"] == "dev.xenoid.runtime-image/v1", "runtime ensure schema")
    require(runtime.manager.calls == [
        ("image-input", "example/base:observed"),
        ("image-ensure", "example/base:observed"),
    ], "runtime image MCP did not dispatch to shared builder APIs")


def legacy_proxy_recovery_requires_bound_quarantine() -> None:
    runtime = FakeRuntime()
    digest = "ab" * 32
    bound_state = {
        "operationId": digest[:32],
        "regenerationTransactionId": "cd" * 16,
        "completed": ["planned", "quarantined"],
    }
    with mock.patch.object(
        mcp_server,
        "RegenerationJournal",
    ) as journal_type, mock.patch.object(
        mcp_server,
        "ConvergenceExecutor",
    ) as executor_type:
        journal_type.return_value.legacy_source_digest.return_value = digest
        executor_type.return_value.journal.load.return_value = bound_state
        require(
            mcp_server._legacy_proxy_recovery_allowed(
                runtime,
                "xenoid_proxy_set",
                {},
            ),
            "bound proxy import recovery was rejected",
        )
        require(
            mcp_server._legacy_proxy_recovery_allowed(
                runtime,
                "xenoid_proxy_clear",
                {"discardUnreadableState": True},
            ),
            "bound explicit proxy discard recovery was rejected",
        )
        require(
            not mcp_server._legacy_proxy_recovery_allowed(
                runtime,
                "xenoid_proxy_clear",
                {"discardUnreadableState": False},
            ),
            "ordinary clear bypassed regeneration guard",
        )
        forged = dict(bound_state, operationId="ef" * 16)
        executor_type.return_value.journal.load.return_value = forged
        require(
            not mcp_server._legacy_proxy_recovery_allowed(
                runtime,
                "xenoid_proxy_set",
                {},
            ),
            "forged compatibility journal authorized proxy recovery",
        )


def main() -> int:
    cases = (
        registered_tools_have_handlers,
        keybox_is_trusted_local_cli_only,
        google_services_enable_defaults_to_microg_release,
        proxy_unreadable_discard_is_explicit,
        netctl_dispatches_to_runtime_manager,
        up_tools_use_in_process_convergence,
        generated_mcp_config_is_checkout_runnable,
        up_source_has_no_nested_process,
        stdio_mutations_use_shared_instance_lock,
        legacy_proxy_recovery_requires_bound_quarantine,
        remote_command_deadline_bounds_unset_subprocesses,
        versions_are_path_safe_before_side_effects,
        runtime_image_tool_uses_content_addressed_builder,
    )
    completed = []
    for case in cases:
        case()
        completed.append(case.__name__)
    print(json.dumps({"ok": True, "checks": completed}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
