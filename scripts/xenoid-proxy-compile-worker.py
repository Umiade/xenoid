#!/usr/bin/python3
"""Networkless bounded compiler worker for Xenoid proxy sources."""
from __future__ import annotations

import base64
import encodings.idna  # Preload the IDNA codec before the no-file audit boundary.
import json
import os
import resource
import sys
from pathlib import Path
from typing import Any
try:
    import yaml as _yaml  # Preload before the no-file audit boundary.
except ImportError:
    _yaml = None

try:
    from xenoid.proxy_source import (
        ProxySourceError,
        compile_fetched_subscription,
        compile_source,
    )
except ModuleNotFoundError:
    module_root = Path("/usr/lib/xenoid-proxy/python")
    if not module_root.is_dir():
        module_root = Path(__file__).resolve().parents[1] / "src"
    if not module_root.is_dir():
        raise
    sys.path.insert(0, str(module_root))
    from xenoid.proxy_source import (
        ProxySourceError,
        compile_fetched_subscription,
        compile_source,
    )

MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_BYTES = 10 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024


class WorkerFailure(Exception):
    def __init__(self, code: str = "source_invalid"):
        self.code = code
        super().__init__(code)


def _restrict_process() -> None:
    for name, value in (
        (resource.RLIMIT_CORE, (0, 0)),
        (resource.RLIMIT_CPU, (20, 20)),
        (resource.RLIMIT_FSIZE, (0, 0)),
        (resource.RLIMIT_NOFILE, (32, 32)),
    ):
        try:
            resource.setrlimit(name, value)
        except (OSError, ValueError):
            raise WorkerFailure("compiler_sandbox_failed")
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        finite = [item for item in (soft, hard, 512 * 1024 * 1024) if item != resource.RLIM_INFINITY]
        target = min(finite) if finite else 512 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (target, target))
    except (OSError, ValueError):
        raise WorkerFailure("compiler_sandbox_failed")

    def audit(event: str, _args: tuple[Any, ...]) -> None:
        if event.startswith("socket.") or event in {
            "open",
            "os.system",
            "os.posix_spawn",
            "subprocess.Popen",
        }:
            raise PermissionError("compiler_sandbox_failed")

    sys.addaudithook(audit)


def _read_json_line() -> dict[str, Any]:
    raw = sys.stdin.buffer.readline(MAX_LINE_BYTES + 1)
    if not raw or len(raw) > MAX_LINE_BYTES or not raw.endswith(b"\n"):
        raise WorkerFailure
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerFailure from exc
    if not isinstance(value, dict):
        raise WorkerFailure
    return value


def _write_json_line(value: dict[str, Any]) -> None:
    encoded = json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise WorkerFailure
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()


def _decode_source(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2 * MAX_SOURCE_BYTES:
        raise WorkerFailure
    try:
        raw = base64.b64decode(value, validate=True)
        text = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise WorkerFailure from exc
    if not raw or len(raw) > MAX_SOURCE_BYTES or "\x00" in text:
        raise WorkerFailure
    return text


class _ProviderFetcher:
    def __init__(self) -> None:
        self._request_id = 0

    def __call__(self, url: str, *args: Any, **kwargs: Any) -> bytes:
        if args or not isinstance(url, str) or not url:
            raise ProxySourceError("source_fetch_denied")
        headers = kwargs.get("headers", {})
        allow_insecure = kwargs.get("allow_insecure_http", False)
        if set(kwargs) - {"headers", "allow_insecure_http"}:
            raise ProxySourceError("source_fetch_denied")
        if not isinstance(headers, dict) or not isinstance(allow_insecure, bool):
            raise ProxySourceError("source_fetch_denied")
        self._request_id += 1
        request_id = self._request_id
        _write_json_line(
            {
                "type": "fetch",
                "id": request_id,
                "url": url,
                "headers": headers,
                "allowInsecureHttp": allow_insecure,
            }
        )
        try:
            response = _read_json_line()
        except WorkerFailure as exc:
            raise ProxySourceError("source_fetch_denied") from exc
        if set(response) != {"type", "id", "ok", "bodyBase64"}:
            raise ProxySourceError("source_fetch_denied")
        if response.get("type") != "fetchResult" or response.get("id") != request_id or response.get("ok") is not True:
            raise ProxySourceError("source_fetch_denied")
        encoded = response.get("bodyBase64")
        if not isinstance(encoded, str) or len(encoded) > 2 * MAX_SOURCE_BYTES:
            raise ProxySourceError("source_fetch_denied")
        try:
            body = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise ProxySourceError("source_fetch_denied") from exc
        if len(body) > MAX_SOURCE_BYTES:
            raise ProxySourceError("source_fetch_denied")
        return body


def _compile(request: dict[str, Any]) -> dict[str, Any]:
    if set(request) != {
        "op",
        "kind",
        "valueBase64",
        "selectedNode",
        "udpAllowed",
        "allowInsecureHttp",
    } or request.get("op") != "compile":
        raise WorkerFailure
    kind = request.get("kind")
    selected_node = request.get("selectedNode")
    udp_allowed = request.get("udpAllowed")
    allow_insecure = request.get("allowInsecureHttp")
    if kind not in {"endpoint", "uri_list", "clash", "subscription"}:
        raise WorkerFailure
    if not isinstance(selected_node, str) or len(selected_node) > 128:
        raise WorkerFailure
    if not isinstance(udp_allowed, bool) or not isinstance(allow_insecure, bool):
        raise WorkerFailure
    source = _decode_source(request.get("valueBase64"))
    fetcher = _ProviderFetcher()
    if kind == "subscription":
        compiled = compile_fetched_subscription(
            source,
            selected_node=selected_node,
            udp_allowed=udp_allowed,
            allow_insecure_http=allow_insecure,
            fetcher=fetcher,
        )
    else:
        compiled = compile_source(
            kind,
            source,
            selected_node=selected_node,
            udp_allowed=udp_allowed,
            allow_insecure_http=allow_insecure,
            fetcher=fetcher,
        )
    config = compiled.config
    node_names = list(compiled.node_names)
    if not isinstance(config, dict) or not all(isinstance(name, str) for name in node_names):
        raise WorkerFailure
    json.dumps(config, ensure_ascii=True, allow_nan=False)
    return {
        "type": "result",
        "ok": True,
        "config": config,
        "nodeNames": node_names,
        "sourceSha256": compiled.source_sha256,
    }


def main() -> int:
    try:
        _restrict_process()
        request = _read_json_line()
        _write_json_line(_compile(request))
        return 0
    except ProxySourceError as exc:
        _write_json_line({"type": "result", "ok": False, "error": exc.code})
        return 1
    except WorkerFailure as exc:
        _write_json_line({"type": "result", "ok": False, "error": exc.code})
        return 1
    except BaseException:
        _write_json_line({"type": "result", "ok": False, "error": "source_invalid"})
        return 1


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
