#!/usr/bin/python3
"""One-shot unprivileged pinned fetch worker for Xenoid proxy sources."""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path
from typing import Any

try:
    from xenoid.proxy_source import PinnedHTTPSFetcher, ProxySourceError
except ModuleNotFoundError:
    module_root = Path("/usr/lib/xenoid-proxy/python")
    if not module_root.is_dir():
        module_root = Path(__file__).resolve().parents[1] / "src"
    if not module_root.is_dir():
        raise
    sys.path.insert(0, str(module_root))
    from xenoid.proxy_source import PinnedHTTPSFetcher, ProxySourceError

MAX_REQUEST_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 1024 * 1024


class WorkerFailure(Exception):
    pass


def _read_request() -> dict[str, Any]:
    raw = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
    if not raw or len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
        raise WorkerFailure
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerFailure from exc
    if not isinstance(value, dict):
        raise WorkerFailure
    return value


def _write(value: dict[str, Any]) -> None:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()


def _fetch(request: dict[str, Any]) -> dict[str, Any]:
    if set(request) != {
        "op", "url", "headers", "etag", "lastModified", "allowInsecureHttp"
    } or request.get("op") != "fetch":
        raise WorkerFailure
    url = request.get("url")
    headers = request.get("headers")
    etag = request.get("etag")
    modified = request.get("lastModified")
    insecure = request.get("allowInsecureHttp")
    if (
        not isinstance(url, str)
        or not isinstance(headers, dict)
        or not isinstance(etag, str)
        or not isinstance(modified, str)
        or not isinstance(insecure, bool)
        or len(url.encode("utf-8")) > 4096
        or len(etag) > 1024
        or len(modified) > 128
    ):
        raise WorkerFailure
    result = PinnedHTTPSFetcher()(
        url,
        headers=headers,
        etag=etag,
        last_modified=modified,
        allow_insecure_http=insecure,
    )
    if result.status == 304:
        return {
            "ok": True,
            "notModified": True,
            "bodyBase64": "",
            "etag": result.etag or etag,
            "lastModified": result.last_modified or modified,
        }
    if result.status != 200 or not result.body or len(result.body) > MAX_SOURCE_BYTES:
        raise WorkerFailure
    return {
        "ok": True,
        "notModified": False,
        "bodyBase64": base64.b64encode(result.body).decode("ascii"),
        "etag": result.etag,
        "lastModified": result.last_modified,
    }


def main() -> int:
    try:
        _write(_fetch(_read_request()))
        return 0
    except (ProxySourceError, WorkerFailure):
        _write({"ok": False, "error": "source_fetch_denied"})
        return 1
    except BaseException:
        _write({"ok": False, "error": "source_fetch_denied"})
        return 1


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
