from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional, Union

# A source import can spend up to five sequential 600-second rootd phases on
# copy, publication, rollback/cleanup, and staging cleanup. Keep the host
# socket alive beyond that daemon-side bound so callers never clean staging
# while the daemon can still be consuming it.
CAMERA_MUTATION_TIMEOUT_SECONDS = 3605.0


class DaemonClient:
    def __init__(self, port: int = 18765, host: str = "127.0.0.1", timeout: float = 10.0):
        self.base = f"http://{host}:{port}"
        self.timeout = timeout
        self._token: Optional[str] = None

    def _get_token(self, force: bool = False) -> Optional[str]:
        """Read the daemon token from its private device file and cache it mode 0600."""
        if self._token is not None and not force:
            return self._token
        cache = Path(".xenoid/daemon.token")
        if not force:
            try:
                if cache.exists():
                    self._token = cache.read_text().strip() or None
                    if self._token:
                        cache.chmod(0o600)
                        return self._token
            except OSError:
                pass
        try:
            from xenoid.backend import RuntimeManager
            from xenoid.config import load_config
            cfg = load_config()
            base = RuntimeManager(cfg).docker_base_cmd()
            result = subprocess.run(
                [*base, "exec", cfg.container_name, "cat", "/data/data/dev.xenoid.daemon/files/daemon.token"],
                text=True,
                capture_output=True,
                timeout=10,
            )
            token = result.stdout.strip()
            if result.returncode == 0 and token:
                self._token = token
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(token + "\n")
                cache.chmod(0o600)
                return self._token
        except (OSError, subprocess.SubprocessError):
            pass
        self._token = None
        return None

    def request(self, method: str, path: str, body: Optional[Any] = None, timeout: Optional[float] = None) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode()
        for attempt in range(2):
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            token = self._get_token(force=attempt > 0)
            if token:
                headers["X-Xenoid-Token"] = token
            req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                    raw = resp.read().decode()
                    result = json.loads(raw) if raw else {"ok": True}
                    if resp.status == 401 and attempt == 0:
                        self._token = None
                        continue
                    return result
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode(errors="replace")
                if exc.code == 401 and attempt == 0:
                    self._token = None
                    continue
                try:
                    result = json.loads(raw) if raw else {"ok": False}
                except json.JSONDecodeError:
                    result = {"ok": False, "error": raw or str(exc)}
                result["httpStatus"] = exc.code
                return result
            except urllib.error.URLError as exc:
                return {"ok": False, "error": str(exc), "url": self.base + path}
        return {"ok": False, "error": "unauthorized after token refresh", "url": self.base + path}

    def health(self) -> dict[str, Any]:
        return self.request("GET", "/health")

    def camera_status(self) -> dict[str, Any]:
        return self.request(
            "GET",
            "/camera/status",
            timeout=CAMERA_MUTATION_TIMEOUT_SECONDS,
        )

    def camera_source(self, kind: str, staging_path: str, size: int, sha256: str) -> dict[str, Any]:
        return self.request(
            "POST",
            "/camera/source",
            {
                "kind": kind,
                "stagingPath": staging_path,
                "size": size,
                "sha256": sha256,
            },
            timeout=CAMERA_MUTATION_TIMEOUT_SECONDS,
        )

    def camera_settings(self, mode: str) -> dict[str, Any]:
        return self.request(
            "POST",
            "/camera/settings",
            {"mode": mode},
            timeout=CAMERA_MUTATION_TIMEOUT_SECONDS,
        )

    def camera_clear(self, kind: str) -> dict[str, Any]:
        return self.request(
            "POST",
            "/camera/clear",
            {"kind": kind},
            timeout=CAMERA_MUTATION_TIMEOUT_SECONDS,
        )

    def camera_apply(self) -> dict[str, Any]:
        return self.request(
            "POST",
            "/camera/apply",
            {},
            timeout=CAMERA_MUTATION_TIMEOUT_SECONDS,
        )

    def camera_self_test_start(self, run_id: str) -> dict[str, Any]:
        return self.request("POST", "/camera/self-test/start", {"runId": run_id})

    def camera_self_test_status(self, timeout: Optional[float] = None) -> dict[str, Any]:
        return self.request("GET", "/camera/self-test/status", timeout=timeout)

    def root_status(self) -> dict[str, Any]:
        return self.request("GET", "/root/status")

    def root_exec(self, command: str) -> dict[str, Any]:
        return self.request("POST", "/root/exec", {"command": command})

    def frida_start(self, port: int = 27042) -> dict[str, Any]:
        return self.request("POST", "/frida/start", {"port": port}, timeout=90)

    def frida_stop(self) -> dict[str, Any]:
        return self.request("POST", "/frida/stop", timeout=30)

    def frida_status(self) -> dict[str, Any]:
        return self.request("GET", "/frida/status")

    def profile_helper_status(self) -> dict[str, Any]:
        return self.request("GET", "/profile/helper/status")

    def profile_helper_env(self) -> dict[str, Any]:
        return self.request("GET", "/profile/helper/env")

    def profile_helper_dump(self) -> dict[str, Any]:
        return self.request("GET", "/profile/helper/dump")

    def collect_fingerprint(self) -> dict[str, Any]:
        return self.request("GET", "/fingerprint/collect")

    def apply_fingerprint(self, profile: dict[str, Any], regenerate_unique: bool = True) -> dict[str, Any]:
        # Full apply fans out to dozens of rootd exec calls (props, overlay re-mount,
        # ssaid, netctl) — far beyond the 10s default. Give it the same headroom as ota_apply.
        return self.request("POST", "/fingerprint/apply", {"profile": profile, "regenerateUnique": regenerate_unique}, timeout=120)

    def set_fingerprint_field(self, field: str, value: Any) -> dict[str, Any]:
        return self.request("POST", "/fingerprint/set", {"field": field, "value": value}, timeout=30)

    def run_automation(self, script_path: Union[str, Path]) -> dict[str, Any]:
        script = Path(script_path).read_text()
        return self.request("POST", "/automation/run", {"language": "js", "script": script, "name": Path(script_path).name})

    def tap(self, x: int, y: int) -> dict[str, Any]:
        return self.request("POST", "/input/tap", {"x": x, "y": y})

    def swipe(self, x1: int, y1: int, x2: int, y2: int, duration_ms: int = 300) -> dict[str, Any]:
        return self.request("POST", "/input/swipe", {"x1": x1, "y1": y1, "x2": x2, "y2": y2, "durationMs": duration_ms})

    def app_install(self, path: str) -> dict[str, Any]:
        return self.request("POST", "/app/install", {"path": path}, timeout=120)

    def app_uninstall(self, package: str) -> dict[str, Any]:
        return self.request("POST", "/app/uninstall", {"package": package})

    def app_launch(self, component: str) -> dict[str, Any]:
        return self.request("POST", "/app/launch", {"component": component})

    def hide_status(self) -> dict[str, Any]:
        return self.request("GET", "/hide/status")

    def hide_apply(self, policy: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        # hide apply re-runs the overlay helper + prop-area as root; allow for slow mounts.
        return self.request("POST", "/hide/apply", {"policy": policy or {}}, timeout=90)

    def ota_check(self) -> dict[str, Any]:
        return self.request("GET", "/ota/check")

    def ota_apply(self, channel: str = "stable") -> dict[str, Any]:
        return self.request("POST", "/ota/apply", {"channel": channel}, timeout=120)
