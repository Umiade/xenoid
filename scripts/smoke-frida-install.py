#!/usr/bin/env python3
"""Runtime-free contract smoke for the combined Frida installer."""
from __future__ import annotations

import json
import lzma
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid.backend import RuntimeManager
from xenoid.config import XenoidConfig


def manager() -> RuntimeManager:
    return RuntimeManager(XenoidConfig())


def success_case() -> dict[str, Any]:
    runtime = manager()
    calls: dict[str, Any] = {}

    def fetch(**kwargs: str) -> dict[str, Any]:
        calls["fetch"] = kwargs
        return {"ok": True, "path": "/cache/frida-server", "version": "17.2.1"}

    def deploy(path: str, remote_path: str) -> dict[str, Any]:
        calls["deploy"] = [path, remote_path]
        return {"ok": True, "remotePath": remote_path}

    runtime.fetch_frida = fetch  # type: ignore[method-assign]
    runtime.deploy_frida = deploy  # type: ignore[method-assign]
    result = runtime.install_frida("17.2.1", "android-arm64", "/cache", "/device/frida")
    expected_calls = {
        "fetch": {"version": "17.2.1", "arch": "android-arm64", "out_dir": "/cache"},
        "deploy": ["/cache/frida-server", "/device/frida"],
    }
    return {
        "ok": result.get("ok") is True
        and result.get("stage") == "complete"
        and result.get("path") == "/cache/frida-server"
        and calls == expected_calls,
        "result": result,
        "calls": calls,
    }


def fetch_failure_case() -> dict[str, Any]:
    runtime = manager()
    deploy_called = False

    def fetch(**_kwargs: str) -> dict[str, Any]:
        return {"ok": False, "error": "download failed"}

    def deploy(_path: str, _remote_path: str) -> dict[str, Any]:
        nonlocal deploy_called
        deploy_called = True
        return {"ok": True}

    runtime.fetch_frida = fetch  # type: ignore[method-assign]
    runtime.deploy_frida = deploy  # type: ignore[method-assign]
    result = runtime.install_frida()
    return {
        "ok": result.get("ok") is False
        and result.get("stage") == "fetch"
        and result.get("deploy") is None
        and not deploy_called,
        "result": result,
    }


def missing_path_case() -> dict[str, Any]:
    runtime = manager()
    deploy_called = False

    def fetch(**_kwargs: str) -> dict[str, Any]:
        return {"ok": True, "version": "17.2.1"}

    def deploy(_path: str, _remote_path: str) -> dict[str, Any]:
        nonlocal deploy_called
        deploy_called = True
        return {"ok": True}

    runtime.fetch_frida = fetch  # type: ignore[method-assign]
    runtime.deploy_frida = deploy  # type: ignore[method-assign]
    result = runtime.install_frida()
    return {
        "ok": result.get("ok") is False
        and result.get("stage") == "fetch"
        and "no install path" in str(result.get("fetch", {}).get("error"))
        and not deploy_called,
        "result": result,
    }


def deploy_failure_case() -> dict[str, Any]:
    runtime = manager()
    runtime.fetch_frida = lambda **_kwargs: {"ok": True, "path": "/cache/frida-server"}  # type: ignore[method-assign]
    runtime.deploy_frida = lambda _path, _remote: {"ok": False, "error": "adb unavailable"}  # type: ignore[method-assign]
    result = runtime.install_frida()
    return {
        "ok": result.get("ok") is False
        and result.get("stage") == "deploy"
        and result.get("deploy", {}).get("error") == "adb unavailable",
        "result": result,
    }

def cached_fetch_case() -> dict[str, Any]:
    payload = b"cached-frida-server"
    with tempfile.TemporaryDirectory() as directory:
        cache = Path(directory)
        asset = cache / "frida-server-17.2.1-android-arm64.xz"
        asset.write_bytes(lzma.compress(payload))
        result = manager().fetch_frida("17.2.1", "android-arm64", directory)
        server = cache / "frida-server"
        return {
            "ok": result.get("ok") is True
            and result.get("cached") is True
            and result.get("path") == str(server.resolve())
            and server.read_bytes() == payload
            and bool(server.stat().st_mode & 0o100),
            "result": result,
        }



def main() -> int:
    cases = {
        "success": success_case(),
        "fetchFailure": fetch_failure_case(),
        "missingPath": missing_path_case(),
        "deployFailure": deploy_failure_case(),
        "cachedFetch": cached_fetch_case(),
    }
    result = {"ok": all(case["ok"] for case in cases.values()), "cases": cases}
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
