from __future__ import annotations

import base64
import hashlib
import os
import secrets
import signal
import shlex
import subprocess
import json
import lzma
import re
import shutil
import stat
import tarfile
import selectors
import time
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

from .config import (
    InstanceContext,
    InstanceError,
    InstanceLease,
    XenoidConfig,
)
from .daemon_client import CAMERA_MUTATION_TIMEOUT_SECONDS, PROXY_MAX_SOURCE_BYTES, DaemonClient
from .device_identity import (
    DeviceIdentityStore,
    IdentityError,
    public_identity_state,
)
from .google_services import (
    GOOGLE_LABEL_DATA_COMPAT,
    GOOGLE_LABEL_PROVIDER,
    GOOGLE_LABEL_RELEASE,
    GOOGLE_LABEL_SPEC,
    PROVIDER_MINDTHEGAPPS,
    PROVIDER_NONE,
    GoogleBindingStore,
    GoogleServicesError,
    ReleaseSpec,
    base_status,
    binding_matches,
    capability_model,
    cleanup_runtime_context,
    create_runtime_context_handle,
    disabled_runtime_spec_fingerprint,
    effective_google_image,
    expected_binding_identity,
    load_release_spec,
    public_binding,
    quick_validate_assets,
    resolve_google_runtime_spec,
    staged_google_payload,
    transition_decision,
    verify_context_copy,
)
from .storage import (
    DEFAULT_DATA_SIZE_BYTES,
    StorageError,
    StorageStateStore,
    backup_image_name,
    parse_storage_result,
    public_storage_state,
)
from .util import host_info, run, which


_CAMERA_UPLOAD_MIN_BYTES_PER_SECOND = 512 * 1024
_CAMERA_UPLOAD_TIMEOUT_FLOOR_SECONDS = 600
_CAMERA_UPLOAD_TIMEOUT_CAP_SECONDS = 7200
_CAMERA_UPLOAD_SETUP_SECONDS = 300


def _camera_upload_timeout_seconds(size: int) -> int:
    transfer_seconds = (
        size + _CAMERA_UPLOAD_MIN_BYTES_PER_SECOND - 1
    ) // _CAMERA_UPLOAD_MIN_BYTES_PER_SECOND
    return min(
        _CAMERA_UPLOAD_TIMEOUT_CAP_SECONDS,
        max(
            _CAMERA_UPLOAD_TIMEOUT_FLOOR_SECONDS,
            _CAMERA_UPLOAD_SETUP_SECONDS + transfer_seconds,
        ),
    )


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    fix: Optional[str] = None


class RuntimeManager:
    def __init__(
        self,
        context: InstanceContext,
        cfg: XenoidConfig,
        lease: InstanceLease,
    ):
        self.context = context
        self.cfg = cfg
        self.lease = lease
        self._pending_proxy_restore: Optional[
            tuple[str, str, bool, str, bool, bool]
        ] = None
        self.ensure_instance_lease()

    def ensure_instance_lease(self) -> InstanceLease:
        validated_lease = InstanceLease.from_dict(asdict(self.lease))
        if validated_lease != self.lease:
            raise InstanceError("resource_conflict", "instance lease validation failed")
        if (
            self.context.instance_name != self.cfg.instance_name
            or self.context.instance_id != self.cfg.instance_id
            or self.context.instance_name != self.lease.instance_name
            or self.context.instance_id != self.lease.instance_id
        ):
            raise InstanceError(
                "instance_identity_mismatch",
                "runtime inputs belong to different instances",
            )
        if self.context.resource_tag != self.lease.resource_tag:
            raise InstanceError(
                "instance_tag_collision",
                "runtime resource tag does not match instance identity",
            )
        if self.lease.state != "committed":
            raise InstanceError("resource_conflict", "instance lease is not committed")
        if self.cfg.android_adb_port != self.lease.android_adb_port:
            raise InstanceError(
                "resource_conflict",
                "Android ADB port does not match instance lease",
            )
        expected_config_path = (
            self.context.project_root
            / ".xenoid"
            / "instances"
            / self.context.instance_name
            / "config.json"
        )
        if self.context.config_path != expected_config_path:
            raise InstanceError(
                "instance_identity_mismatch",
                "runtime config path does not match instance identity",
            )
        if (
            self.context.state_root.name != self.context.instance_id
            or self.context.state_root.parent.name != "instances"
        ):
            raise InstanceError(
                "instance_identity_mismatch",
                "runtime state path does not match instance identity",
            )
        return self.lease

    @property
    def adb_target(self) -> str:
        return f"127.0.0.1:{self.lease.host_adb_port}"

    def doctor(self) -> list[Check]:
        info = host_info()
        checks = [
            Check("host", True, f"{info['system']} {info['machine']} / Python {info['python']}"),
            Check("docker", which("docker") is not None, which("docker") or "not found", "brew install docker" if info["system"] == "Darwin" else "install docker/podman compatible Docker CLI"),
            Check("adb", which("adb") is not None, which("adb") or "not found", "brew install android-platform-tools" if info["system"] == "Darwin" else "install android-tools-adb"),
            Check("scrcpy", which("scrcpy") is not None, which("scrcpy") or "not found", "brew install scrcpy" if info["system"] == "Darwin" else "install scrcpy"),
        ]
        if info["system"] == "Darwin":
            checks.insert(2, Check("colima", which("colima") is not None, which("colima") or "not found", "brew install colima"))
            if info["machine"] not in {"arm64", "aarch64"}:
                checks.append(Check("apple-silicon", False, f"machine={info['machine']}", "Use an Apple Silicon Mac"))
        elif info["system"] == "Linux" and info["machine"] not in {"arm64", "aarch64"}:
            checks.append(Check("linux-arm", False, f"machine={info['machine']}", "Use a Linux ARM host"))
        checks.append(Check("backend", True, self.cfg.backend))
        if self.cfg.google_services_provider == PROVIDER_MINDTHEGAPPS:
            for command in ("keytool", "jarsigner", "aapt2", "apksigner"):
                resolved = which(command)
                checks.append(
                    Check(
                        f"google-{command}",
                        resolved is not None,
                        resolved or "not found",
                        "run ./xenoid install-runtime",
                    )
                )
        return checks

    def colima_start_command(self) -> list[str]:
        return ["colima", "start", "--arch", "aarch64", "--vm-type", "vz", "--memory", "8", "--cpu", "8"]

    def google_runtime_spec(
        self,
        purpose: str,
        *,
        require_assets: bool = True,
    ) -> Optional[ReleaseSpec]:
        return resolve_google_runtime_spec(
            self.context,
            self.cfg,
            purpose,
            require_assets=require_assets,
        )

    def effective_image(self) -> str:
        base = (
            f"{self.cfg.runtime_image_tag}-{self.context.resource_tag}"
            if self.cfg.auto_build_runtime_image
            else self.cfg.image
        )
        spec = self.google_runtime_spec("effective-image", require_assets=False)
        return effective_google_image(base, spec)

    def docker_endpoint_host(self) -> str:
        """Return the Docker engine Host endpoint for cfg.docker_context, if any."""
        ctx = (self.cfg.docker_context or "").strip()
        if not ctx:
            return ""
        docker = which("docker") or "docker"
        proc = run([docker, "context", "inspect", ctx, "--format", "{{.Endpoints.docker.Host}}"])
        if proc.returncode != 0:
            return ""
        return (proc.stdout or "").strip()

    def _docker_host_is_remote(self) -> bool:
        host = self.docker_endpoint_host()
        return host.startswith("ssh://") or host.startswith("tcp://")

    def remote_docker_ssh_cmd(self) -> Optional[list[str]]:
        """SSH argv prefix to the docker engine host when context uses ssh://."""
        host = self.docker_endpoint_host()
        if not host.startswith("ssh://"):
            return None
        from urllib.parse import urlparse

        parsed = urlparse(host)
        target = parsed.hostname or ""
        if not target:
            return None
        if parsed.username:
            target = f"{parsed.username}@{target}"
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
        if parsed.port:
            cmd.extend(["-p", str(parsed.port)])
        cmd.append(target)
        return cmd

    def _binder_probe_command(self) -> Optional[list[str]]:
        """Command that prints binderfs|legacy|none on the docker engine host."""
        probe = (
            "test -e /dev/binderfs/binder-control && echo binderfs || "
            "(test -e /dev/binder && echo legacy) || echo none"
        )
        if self.should_use_colima():
            return ["colima", "ssh", "--", "sh", "-c", probe]
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            return [*ssh_cmd, "sh", "-c", probe]
        return None

    def binder_volume_args(self) -> list[str]:
        """Host-side binder device mounts for the redroid container.

        Prefer binderfs (verified path on Ubuntu kernels ≥5.x via
        linux-modules-extra). Fall back to legacy nodes when a kernel exposes
        /dev/binder directly (older devbox path). Probe the Docker engine host
        (local Colima VM or remote context SSH), not the macOS client filesystem.
        """
        probe_cmd = self._binder_probe_command()
        if probe_cmd is not None:
            probe = run(probe_cmd, env=self.docker_env())
            out = (probe.stdout or "").strip()
            if "binderfs" in out:
                return ["-v", "/dev/binderfs:/dev/binderfs"]
            if "legacy" in out:
                return ["-v", "/dev/binder:/dev/binder", "-v", "/dev/hwbinder:/dev/hwbinder", "-v", "/dev/vndbinder:/dev/vndbinder"]
            return []
        if Path("/dev/binderfs/binder-control").exists():
            return ["-v", "/dev/binderfs:/dev/binderfs"]
        if Path("/dev/binder").exists():
            return ["-v", "/dev/binder:/dev/binder", "-v", "/dev/hwbinder:/dev/hwbinder", "-v", "/dev/vndbinder:/dev/vndbinder"]
        return []

    def _binder_setup_shell(self) -> str:
        return (
            "set -e; "
            "if ! sudo modprobe binder_linux 2>/dev/null; then "
            "sudo apt-get update -qq && sudo apt-get install -y -qq linux-modules-extra-$(uname -r) && sudo modprobe binder_linux; "
            "fi; "
            "sudo mkdir -p /dev/binderfs; "
            "mountpoint -q /dev/binderfs || sudo mount -t binder binder /dev/binderfs; "
            "test -e /dev/binderfs/binder-control && echo BINDER_READY"
        )

    def ensure_binder(self) -> dict[str, Any]:
        """Idempotently ensure binder support on the docker engine host.

        Local Colima: modprobe/mount via `colima ssh`. Remote docker context
        (ssh://): same setup over SSH to the engine host. Native Linux: delegate
        to scripts/setup-linux-binderfs.sh.
        """
        script = self._binder_setup_shell()
        if self.should_use_colima():
            if which("colima") is None:
                return {"ok": False, "error": "colima not found"}
            proc = run(["colima", "ssh", "--", "sh", "-c", script], timeout=600, env=self.docker_env())
            ok = proc.returncode == 0 and "BINDER_READY" in (proc.stdout or "")
            return {"ok": ok, "backend": "colima", "returncode": proc.returncode, "stdout": proc.stdout.strip()[-800:], "stderr": proc.stderr.strip()[-800:]}
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            proc = run([*ssh_cmd, "sh", "-c", script], timeout=600, env=self.docker_env())
            ok = proc.returncode == 0 and "BINDER_READY" in (proc.stdout or "")
            return {"ok": ok, "backend": "remote-ssh", "ssh": ssh_cmd[-1], "returncode": proc.returncode, "stdout": proc.stdout.strip()[-800:], "stderr": proc.stderr.strip()[-800:]}
        if host_info()["system"] == "Linux":
            script_path = self.context.project_root / "scripts" / "setup-linux-binderfs.sh"
            proc = run(["bash", str(script_path)], timeout=600, env=self.docker_env())
            return {"ok": proc.returncode == 0, "backend": "linux", "returncode": proc.returncode, "stdout": proc.stdout.strip()[-800:], "stderr": proc.stderr.strip()[-800:]}
        return {"ok": True, "skipped": True, "reason": "no binder action for this backend"}

    def should_use_colima(self) -> bool:
        """True only for local Colima (colima-docker / default macOS local).

        Never when backend=linux-docker, or when docker_context points at a
        remote engine (ssh:// or tcp://).
        """
        if self.cfg.backend == "linux-docker":
            return False
        if self._docker_host_is_remote():
            return False
        if self.cfg.backend in {"colima-docker", "macos-colima"}:
            return True
        # Default macOS local path when no remote docker_context is configured.
        return host_info()["system"] == "Darwin" and not (self.cfg.docker_context or "").strip()

    def build_ebpf_command(self) -> list[str]:
        script = self.context.project_root / "scripts" / "build-ebpf.sh"
        cmd = [str(script)]
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            target = ssh_cmd[-1]
            cmd.extend(["--ssh", target])
            if "-p" in ssh_cmd:
                port = ssh_cmd[ssh_cmd.index("-p") + 1]
                cmd.extend(["--ssh-port", port])
            return cmd
        if self.should_use_colima():
            cmd.append("--colima")
            return cmd
        cmd.append("--local")
        return cmd

    def ebpf_action_command(self, action: str) -> list[str]:
        script = self.context.project_root / "scripts" / "load-ebpf.sh"
        cmd = [str(script)]
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            target = ssh_cmd[-1]
            cmd.extend(["--ssh", target])
            if "-p" in ssh_cmd:
                port = ssh_cmd[ssh_cmd.index("-p") + 1]
                cmd.extend(["--ssh-port", port])
        elif self.should_use_colima():
            cmd.append("--colima")
        else:
            cmd.append("--local")
        cmd.append(action)
        return cmd

    def build_kmod_command(self) -> list[str]:
        script = self.context.project_root / "scripts" / "build-kmod.sh"
        cmd = [str(script)]
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            # Pass user@host and optional -p port as ENGINE_SSH / ENGINE_SSH_PORT via flags.
            target = ssh_cmd[-1]
            cmd.extend(["--ssh", target])
            if "-p" in ssh_cmd:
                port = ssh_cmd[ssh_cmd.index("-p") + 1]
                cmd.extend(["--ssh-port", port])
            return cmd
        if self.should_use_colima():
            cmd.append("--colima")
            return cmd
        cmd.append("--local")
        return cmd

    def kernel_module_status(self) -> dict[str, Any]:
        path = "/sys/module/xenoid_kmod"
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            cmd = [*ssh_cmd, "test", "-d", path]
        elif self.should_use_colima():
            cmd = ["colima", "ssh", "--", "test", "-d", path]
        else:
            cmd = [which("test") or "test", "-d", path]
        try:
            proc = run(cmd, timeout=20, env=self.docker_env())
        except Exception as exc:
            return {"ok": False, "loaded": False, "command": cmd, "error": str(exc)}
        loaded = proc.returncode == 0
        return {
            "ok": loaded,
            "loaded": loaded,
            "command": cmd,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip()[-300:],
            "stderr": proc.stderr.strip()[-300:],
        }

    def ebpf_status(self) -> dict[str, Any]:
        cmd = self.ebpf_action_command("status")
        try:
            proc = run(cmd, timeout=60, env=self.docker_env())
        except Exception as exc:
            return {"ok": False, "loaded": False, "command": cmd, "error": str(exc)}
        data: dict[str, Any] = {}
        for line in reversed((proc.stdout or "").splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    parsed = json.loads(line)
                    if isinstance(parsed, dict):
                        data = parsed
                except json.JSONDecodeError:
                    pass
                break
        loaded = proc.returncode == 0 and data.get("loaded") is True
        return {
            "ok": loaded,
            "loaded": loaded,
            "command": cmd,
            "returncode": proc.returncode,
            "data": data,
            "stdout": proc.stdout.strip()[-300:],
            "stderr": proc.stderr.strip()[-300:],
        }

    def image_protection_status(self) -> dict[str, Any]:
        command = (
            "test -x /system/bin/xenoid-prop-area && "
            "test -x /system/bin/xenoid-overlay-helper && "
            "test -x /system/bin/xenoid-sensorshal && "
            "test -x /system/bin/hw/android.hardware.camera.provider-service-aidl && "
            "test ! -e /system/bin/xenoid-camerahal && "
            "test ! -e /system/bin/hw/xenoid-camerahal && "
            "test ! -e /system/etc/init/xenoid-camerahal.rc && "
            "test ! -e /system/etc/init/hw/xenoid-camerahal.rc && "
            "test -r /system/etc/init/android.hardware.camera.provider-service-aidl.rc && "
            "grep -q '^service vendor.camera-provider-aidl ' "
            "/system/etc/init/android.hardware.camera.provider-service-aidl.rc && "
            "test -r /system/lib64/libpiex_shim.so && "
            "test -r /system/lib64/libxenoid_core.so && "
            "grep -q '/system/lib64/libpiex_shim.so:/system/lib64/libxenoid_core.so' "
            "/system/etc/init/hw/init.zygote64.rc && "
            "test \"$(getprop init.svc.xenoid-sensorshal)\" = running && "
            "test \"$(getprop init.svc.vendor.camera-provider-aidl)\" = running && "
            "test \"$(getprop ro.hardware)\" = tensor && "
            "test \"$(getprop ro.product.device)\" = raven && "
            "zygote_pid=$(pidof zygote64 | cut -d' ' -f1) && "
            "test -n \"$zygote_pid\" && "
            "grep -q ' /proc/cpuinfo ' /proc/$zygote_pid/mountinfo && "
            "grep -q ' /proc/version ' /proc/$zygote_pid/mountinfo && "
            "grep -q ' /proc/meminfo ' /proc/$zygote_pid/mountinfo"
        )
        result = self.docker_exec(["sh", "-c", command], timeout=30)
        result["components"] = [
            "property-area",
            "overlay",
            "zygote-preload",
            "sensor-hal",
            "camera-provider",
        ]
        return result


    def effective_docker_context(self) -> str:
        configured = (self.cfg.docker_context or "").strip()
        if configured:
            return configured
        return "colima" if self.should_use_colima() else "default"

    def docker_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env.pop("DOCKER_CONTEXT", None)
        env.pop("DOCKER_HOST", None)
        env["DOCKER_CONTEXT"] = self.effective_docker_context()
        env["XENOID_PROJECT"] = str(self.context.project_root)
        env["XENOID_INSTANCE"] = self.context.instance_name
        return env

    def docker_base_cmd(self) -> list[str]:
        docker = which("docker") or "docker"
        return [docker, "--context", self.effective_docker_context()]

    def _owner_label_args(self) -> list[str]:
        return [
            argument
            for key, value in sorted(self.lease.owner_labels.items())
            for argument in ("--label", f"{key}={value}")
        ]

    def _google_label_values(self) -> dict[str, str]:
        spec = self.google_runtime_spec("container-labels", require_assets=False)
        identity = expected_binding_identity(spec)
        return {
            GOOGLE_LABEL_PROVIDER: identity["provider"],
            GOOGLE_LABEL_RELEASE: identity["release"],
            GOOGLE_LABEL_SPEC: identity["specSha256"],
            GOOGLE_LABEL_DATA_COMPAT: identity["dataCompatibilitySha256"],
        }

    def _google_label_args(self) -> list[str]:
        return [
            argument
            for key, value in sorted(self._google_label_values().items())
            for argument in ("--label", f"{key}={value}")
        ]
    def _managed_container_labels_match(self, labels: Any) -> bool:
        if not isinstance(labels, dict):
            return False
        expected = {
            **self.lease.owner_labels,
            **self._google_label_values(),
        }
        return all(labels.get(key) == value for key, value in expected.items()) and not any(
            key.startswith("dev.xenoid.google_") and key not in expected
            for key in labels
        )


    def _inspect_docker_object(
        self,
        object_type: str,
        name: str,
    ) -> tuple[Optional[dict[str, Any]], Any]:
        proc = run(
            [*self.docker_base_cmd(), object_type, "inspect", name],
            env=self.docker_env(),
        )
        if proc.returncode != 0:
            return None, proc
        try:
            payload = json.loads(proc.stdout)
        except (TypeError, json.JSONDecodeError):
            return {}, proc
        if (
            not isinstance(payload, list)
            or len(payload) != 1
            or not isinstance(payload[0], dict)
        ):
            return {}, proc
        return payload[0], proc

    def _container_effective_image_identity(
        self,
        container: Mapping[str, Any],
    ) -> dict[str, Any]:
        image, inspect = self._inspect_docker_object(
            "image",
            self.effective_image(),
        )
        desired_id = (
            str(image.get("Id") or "")
            if isinstance(image, dict)
            else ""
        )
        container_id = str(container.get("Image") or "")
        return {
            "ok": bool(desired_id) and container_id == desired_id,
            "containerImageSha256": container_id or None,
            "desiredImageSha256": desired_id or None,
            "returncode": inspect.returncode,
        }

    def docker_network_command(self) -> list[str]:
        return [
            *self.docker_base_cmd(),
            "network",
            "create",
            "--driver",
            "bridge",
            "--opt",
            f"com.docker.network.bridge.name={self.lease.bridge_name}",
            *self._owner_label_args(),
            "--subnet",
            self.lease.ipv4_subnet,
            "--gateway",
            self.lease.ipv4_gateway,
            "--ipv6",
            "--subnet",
            self.lease.ipv6_subnet,
            "--gateway",
            self.lease.ipv6_gateway,
            self.lease.network_name,
        ]

    def _network_matches_lease(self, network: dict[str, Any]) -> bool:
        ipam = network.get("IPAM")
        configs = ipam.get("Config") if isinstance(ipam, dict) else None
        if not isinstance(configs, list):
            return False
        allocations = {
            (entry.get("Subnet"), entry.get("Gateway"))
            for entry in configs
            if isinstance(entry, dict)
        }
        expected_allocations = {
            (self.lease.ipv4_subnet, self.lease.ipv4_gateway),
            (self.lease.ipv6_subnet, self.lease.ipv6_gateway),
        }
        options = network.get("Options")
        return (
            network.get("Name") == self.lease.network_name
            and network.get("Driver") == "bridge"
            and network.get("EnableIPv6") is True
            and network.get("Labels") == self.lease.owner_labels
            and allocations == expected_allocations
            and isinstance(options, dict)
            and options.get("com.docker.network.bridge.name") == self.lease.bridge_name
        )

    def ensure_network(self) -> dict[str, Any]:
        network, _ = self._inspect_docker_object(
            "network",
            self.lease.network_name,
        )
        if network is not None:
            if network and self._network_matches_lease(network):
                return {"ok": True, "exists": True}
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "Docker network is not owned by this instance",
            }
        command = self.docker_network_command()
        proc = run(command, env=self.docker_env())
        if proc.returncode != 0:
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "Docker network creation failed",
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "command": command,
            }
        created, _ = self._inspect_docker_object("network", self.lease.network_name)
        verified = bool(created and self._network_matches_lease(created))
        return {
            "ok": verified,
            "created": True,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "command": command,
            **(
                {}
                if verified
                else {
                    "error": "resource_conflict",
                    "message": "created Docker network identity is invalid",
                }
            ),
        }

    def docker_volume_command(self) -> list[str]:
        return [
            *self.docker_base_cmd(),
            "volume",
            "create",
            *self._owner_label_args(),
            self.lease.volume_name,
        ]

    def _volume_matches_lease(self, volume: dict[str, Any]) -> bool:
        return (
            volume.get("Name") == self.lease.volume_name
            and volume.get("Driver") == "local"
            and volume.get("Labels") == self.lease.owner_labels
            and isinstance(volume.get("Mountpoint"), str)
            and str(volume.get("Mountpoint")).startswith("/")
        )

    def ensure_volume(self) -> dict[str, Any]:
        volume, _ = self._inspect_docker_object("volume", self.lease.volume_name)
        if volume is not None:
            if volume and self._volume_matches_lease(volume):
                return {"ok": True, "exists": True, "volume": volume}
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "Docker volume is not owned by this instance",
            }
        command = self.docker_volume_command()
        proc = run(command, env=self.docker_env())
        if proc.returncode != 0:
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "Docker volume creation failed",
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "command": command,
            }
        created, _ = self._inspect_docker_object("volume", self.lease.volume_name)
        verified = bool(created and self._volume_matches_lease(created))
        return {
            "ok": verified,
            "created": True,
            "volume": created,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "command": command,
            **(
                {}
                if verified
                else {
                    "error": "resource_conflict",
                    "message": "created Docker volume identity is invalid",
                }
            ),
        }

    def _engine_host_shell(self, script: str, *, timeout: int = 120) -> Any:
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            command = [*ssh_cmd, "sudo", "-n", "sh", "-c", script]
        elif self.should_use_colima():
            command = ["colima", "ssh", "--", "sudo", "-n", "sh", "-c", script]
        else:
            command = ["sudo", "-n", "sh", "-c", script]
        return run(command, timeout=timeout, env=self.docker_env())

    def _inspect_volume_image(
        self,
        volume: dict[str, Any],
        image_name: str = "xenoid-data.img",
    ) -> dict[str, Any]:
        mountpoint = volume.get("Mountpoint")
        if (
            volume.get("Driver") != "local"
            or not isinstance(mountpoint, str)
            or not mountpoint.startswith("/")
            or "\n" in mountpoint
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", image_name) is None
        ):
            return {
                "ok": False,
                "error": "storage_image_invalid",
                "message": "Docker volume mountpoint is invalid",
            }
        path = f"{mountpoint.rstrip('/')}/{image_name}"
        quoted = shlex.quote(path)
        command = (
            f"set -eu; p={quoted}; "
            "[ -f \"$p\" ] && [ ! -L \"$p\" ] && [ -s \"$p\" ]; "
            "[ \"$(blkid -p -s TYPE -o value -- \"$p\" 2>/dev/null)\" = ext4 ]; "
            "printf 'XENOID_DATA_UUID=%s\\n' \"$(blkid -p -s UUID -o value -- \"$p\" | tr A-F a-f)\"; "
            "printf 'XENOID_DATA_SIZE=%s\\n' \"$(stat -c %s -- \"$p\")\""
        )
        proc = self._engine_host_shell(command)
        if proc.returncode != 0:
            return {
                "ok": False,
                "error": "storage_image_invalid",
                "message": "persistent data image is missing or invalid",
                "returncode": proc.returncode,
                "stderr": proc.stderr.strip()[-500:],
            }
        try:
            filesystem_uuid, size_bytes = parse_storage_result(proc.stdout)
        except StorageError as exc:
            return exc.as_dict()
        return {
            "ok": True,
            "filesystemUuid": filesystem_uuid,
            "sizeBytes": size_bytes,
            "image": image_name,
        }

    def _run_storage_image_action(
        self,
        action: str,
        *,
        expected_uuid: str = "",
        transaction_id: str = "",
        legacy_volume: str = "",
        backup_image: str = "",
        backup_uuid: str = "",
    ) -> dict[str, Any]:
        script = self.context.project_root / "scripts" / "make-rootfs-image.sh"
        command = [
            str(script),
            self.effective_image(),
            self.lease.volume_name,
            "3072",
            str(DEFAULT_DATA_SIZE_BYTES // (1024 * 1024)),
            action,
            expected_uuid or "-",
            transaction_id or "-",
            legacy_volume or "-",
            backup_image or "-",
            backup_uuid or "-",
            self.cfg.google_services_provider,
        ]
        env = self.docker_env()
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            env["XENOID_ENGINE_SSH"] = ssh_cmd[-1]
            if "-p" in ssh_cmd:
                env["XENOID_ENGINE_SSH_PORT"] = ssh_cmd[ssh_cmd.index("-p") + 1]
        proc = run(command, timeout=1800, env=env)
        result: dict[str, Any] = {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "command": command,
            "stdout": proc.stdout.strip()[-2000:],
            "stderr": proc.stderr.strip()[-2000:],
        }
        if proc.returncode != 0:
            storage_failure = 41 <= proc.returncode <= 56
            capacity_failure = proc.returncode == 61
            result.update({
                "error": (
                    "storage_image_invalid"
                    if storage_failure
                    else (
                        "rootfs_capacity_insufficient"
                        if capacity_failure
                        else "rootfs_image_build_failed"
                    )
                ),
                "message": (
                    "persistent data image operation failed"
                    if storage_failure
                    else (
                        "generated rootfs capacity is insufficient"
                        if capacity_failure
                        else "rootfs image preparation failed"
                    )
                ),
            })
            return result
        try:
            filesystem_uuid, size_bytes = parse_storage_result(proc.stdout)
        except StorageError as exc:
            return {**result, **exc.as_dict(), "ok": False}
        result.update({
            "filesystemUuid": filesystem_uuid,
            "sizeBytes": size_bytes,
            "action": action,
        })
        return result

    def _legacy_engine_record(self) -> Optional[dict[str, str]]:
        path = self.context.state_root / "legacy-engine.json"
        try:
            info = path.lstat()
            if not path.is_file() or info.st_mode & 0o077:
                raise StorageError(
                    "storage_legacy_invalid",
                    "legacy engine state permissions are unsafe",
                )
            raw = json.loads(path.read_text())
        except FileNotFoundError:
            return None
        except StorageError:
            raise
        except (OSError, ValueError, UnicodeError) as exc:
            raise StorageError(
                "storage_legacy_invalid",
                "legacy engine state is invalid",
            ) from exc
        if not isinstance(raw, dict):
            raise StorageError("storage_legacy_invalid", "legacy engine state is invalid")
        volume_name = raw.get("android_data_volume")
        container_name = raw.get("container_name", "")
        pattern = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"
        if (
            not isinstance(volume_name, str)
            or re.fullmatch(pattern, volume_name) is None
            or not isinstance(container_name, str)
            or (container_name and re.fullmatch(pattern, container_name) is None)
        ):
            raise StorageError("storage_legacy_invalid", "legacy engine identity is invalid")
        if volume_name == self.lease.volume_name:
            return None
        return {"volumeName": volume_name, "containerName": container_name}

    def _legacy_volume_attachments(
        self,
        volume_name: str,
    ) -> tuple[Optional[list[tuple[str, str]]], dict[str, Any]]:
        proc = run(
            [
                *self.docker_base_cmd(),
                "ps",
                "-a",
                "--filter",
                f"volume={volume_name}",
                "--format",
                "{{.ID}}\t{{.Names}}",
            ],
            env=self.docker_env(),
        )
        if proc.returncode != 0:
            return None, {
                "ok": False,
                "error": "engine_unavailable",
                "message": "cannot inspect legacy volume attachments",
            }
        rows: list[tuple[str, str]] = []
        for line in proc.stdout.splitlines():
            parts = line.split("\t", 1)
            if len(parts) != 2 or not parts[0] or not parts[1]:
                return None, {
                    "ok": False,
                    "error": "storage_legacy_invalid",
                    "message": "legacy volume attachment identity is invalid",
                }
            rows.append((parts[0], parts[1]))
        return rows, {"ok": True}

    def _storage_error(self, code: str, message: str, **details: Any) -> dict[str, Any]:
        return {"ok": False, "error": code, "message": message, **details}

    def ensure_instance_storage(self) -> dict[str, Any]:
        """Converge rootfs plus the one persistent, never-silently-replaced data image."""
        self.ensure_instance_lease()
        store = StorageStateStore(self.context, self.lease)
        try:
            state = store.load()
            legacy = self._legacy_engine_record()
        except StorageError as exc:
            return exc.as_dict()

        volume, _ = self._inspect_docker_object("volume", self.lease.volume_name)
        if volume == {}:
            return self._storage_error(
                "resource_conflict",
                "Docker volume inspection returned invalid identity",
            )
        if volume is not None and not self._volume_matches_lease(volume):
            return self._storage_error(
                "resource_conflict",
                "Docker volume is not owned by this instance",
            )

        if state is not None and state["state"] == "committed":
            if volume is None:
                return self._storage_error(
                    "storage_volume_missing",
                    "committed instance data volume is missing",
                    storage=public_storage_state(state, healthy=False, error="storage_volume_missing"),
                )
            image = self._inspect_volume_image(volume)
            if not image.get("ok"):
                return self._storage_error(
                    "storage_image_invalid",
                    "committed instance data image is missing or invalid",
                    storage=public_storage_state(state, healthy=False, error="storage_image_invalid"),
                    image=image,
                )
            if (
                image["filesystemUuid"] != state["filesystemUuid"]
                or image["sizeBytes"] != state["sizeBytes"]
            ):
                return self._storage_error(
                    "storage_identity_mismatch",
                    "committed data image identity changed",
                    storage=public_storage_state(state, healthy=False, error="storage_identity_mismatch"),
                    image=image,
                )
            action = self._run_storage_image_action(
                "preserve",
                expected_uuid=state["filesystemUuid"],
                transaction_id=state["transactionId"],
            )
            if not action.get("ok"):
                code = str(action.get("error") or "storage_image_invalid")
                rootfs_failed = code == "rootfs_image_build_failed"
                return self._storage_error(
                    code,
                    str(action.get("message") or "instance image preparation failed"),
                    storage=public_storage_state(
                        state,
                        healthy=rootfs_failed,
                        error="" if rootfs_failed else code,
                    ),
                    imageAction=action,
                )
            if action.get("sizeBytes") != state["sizeBytes"]:
                return self._storage_error(
                    "storage_identity_mismatch",
                    "persistent data image validation failed",
                    storage=public_storage_state(state, healthy=False, error="storage_identity_mismatch"),
                    imageAction=action,
                )
            return {
                "ok": True,
                "volume": {"ok": True, "exists": True},
                "imageAction": action,
                "storage": public_storage_state(state, healthy=True),
            }

        if state is None and legacy is not None:
            legacy_volume, _ = self._inspect_docker_object("volume", legacy["volumeName"])
            if (
                legacy_volume is None
                or not legacy_volume
                or legacy_volume.get("Driver") != "local"
            ):
                return self._storage_error(
                    "storage_legacy_invalid",
                    "recorded legacy data volume is missing or not local",
                )
            attachments, attachment_status = self._legacy_volume_attachments(legacy["volumeName"])
            if attachments is None:
                return attachment_status
            unexpected = [
                {"id": container_id, "name": name}
                for container_id, name in attachments
                if not legacy["containerName"] or name != legacy["containerName"]
            ]
            if unexpected:
                return self._storage_error(
                    "storage_legacy_attached",
                    "legacy data volume has an unknown container attachment",
                    attachments=unexpected,
                )
            if attachments:
                removed = self._remove_legacy_container(
                    attachments[0][0],
                    legacy["containerName"],
                    legacy["volumeName"],
                )
                if not removed.get("ok"):
                    return self._storage_error(
                        "storage_legacy_attached",
                        "legacy data container could not be stopped safely",
                        removal=removed,
                    )
            source = self._inspect_volume_image(legacy_volume)
            if not source.get("ok"):
                return self._storage_error(
                    "storage_legacy_invalid",
                    "legacy data image is missing or invalid",
                    source=source,
                )
            backup_image = ""
            backup_uuid = ""
            backup_size = 0
            if volume is not None:
                target = self._inspect_volume_image(volume)
                if not target.get("ok"):
                    return self._storage_error(
                        "storage_image_invalid",
                        "tagged data volume exists without a valid data image",
                        target=target,
                    )
                if target["filesystemUuid"] != source["filesystemUuid"]:
                    transaction = secrets.token_hex(16)
                    backup_image = backup_image_name(transaction)
                    backup_uuid = target["filesystemUuid"]
                    backup_size = target["sizeBytes"]
                    state = store.pending(
                        "legacy",
                        transaction_id=transaction,
                        size_bytes=source["sizeBytes"],
                        legacy_volume=legacy["volumeName"],
                        legacy_filesystem_uuid=source["filesystemUuid"],
                        backup_image=backup_image,
                        backup_filesystem_uuid=backup_uuid,
                        backup_size_bytes=backup_size,
                    )
            if state is None:
                state = store.pending(
                    "legacy",
                    size_bytes=source["sizeBytes"],
                    legacy_volume=legacy["volumeName"],
                    legacy_filesystem_uuid=source["filesystemUuid"],
                )

        if state is None:
            if volume is None:
                state = store.pending("fresh")
            else:
                adopted = self._inspect_volume_image(volume)
                if not adopted.get("ok"):
                    return self._storage_error(
                        "storage_uninitialized_volume",
                        "existing instance volume has no valid data image",
                        image=adopted,
                    )
                state = store.pending("adopted", size_bytes=adopted["sizeBytes"])

        if state["source"] == "legacy":
            source_volume, _ = self._inspect_docker_object(
                "volume",
                state["legacyVolume"],
            )
            if (
                source_volume is None
                or not source_volume
                or source_volume.get("Driver") != "local"
            ):
                return self._storage_error(
                    "storage_legacy_invalid",
                    "pending legacy data volume is missing or not local",
                )
            attachments, attachment_status = self._legacy_volume_attachments(
                state["legacyVolume"],
            )
            if attachments is None:
                return attachment_status
            expected_container = (
                legacy["containerName"]
                if legacy is not None
                and legacy["volumeName"] == state["legacyVolume"]
                else ""
            )
            if attachments:
                if (
                    not expected_container
                    or len(attachments) != 1
                    or attachments[0][1] != expected_container
                ):
                    return self._storage_error(
                        "storage_legacy_attached",
                        "pending legacy volume has an unknown container attachment",
                    )
                removed = self._remove_legacy_container(
                    attachments[0][0],
                    expected_container,
                    state["legacyVolume"],
                )
                if not removed.get("ok"):
                    return self._storage_error(
                        "storage_legacy_attached",
                        "pending legacy container could not be stopped safely",
                        removal=removed,
                    )
            source_image = self._inspect_volume_image(source_volume)
            if (
                not source_image.get("ok")
                or source_image.get("filesystemUuid")
                != state["legacyFilesystemUuid"]
                or source_image.get("sizeBytes") != state["sizeBytes"]
            ):
                return self._storage_error(
                    "storage_legacy_invalid",
                    "pending legacy data image identity changed",
                    source=source_image,
                )

        if volume is None:
            created = self.ensure_volume()
            if not created.get("ok"):
                return self._storage_error(
                    "resource_conflict",
                    "instance data volume creation failed",
                    volume=created,
                )
            volume = created.get("volume")
            if not isinstance(volume, dict) or not self._volume_matches_lease(volume):
                return self._storage_error(
                    "resource_conflict",
                    "created instance data volume identity is invalid",
                )

        if state["source"] == "fresh":
            action = self._run_storage_image_action(
                "initialize",
                transaction_id=state["transactionId"],
            )
        elif state["source"] == "adopted":
            action = self._run_storage_image_action(
                "preserve",
                transaction_id=state["transactionId"],
            )
        else:
            action = self._run_storage_image_action(
                "migrate",
                expected_uuid=state["legacyFilesystemUuid"],
                transaction_id=state["transactionId"],
                legacy_volume=state["legacyVolume"],
                backup_image=state["backupImage"],
                backup_uuid=state["backupFilesystemUuid"],
            )
        if not action.get("ok"):
            code = str(action.get("error") or "storage_image_invalid")
            return self._storage_error(
                code,
                str(action.get("message") or "instance image preparation failed"),
                storage=public_storage_state(state, healthy=False, error=code),
                imageAction=action,
            )
        if action.get("sizeBytes") != state["sizeBytes"]:
            return self._storage_error(
                "storage_identity_mismatch",
                "instance data image size changed during transaction",
                storage=public_storage_state(state, healthy=False, error="storage_identity_mismatch"),
                imageAction=action,
            )
        if state["source"] == "legacy" and action.get("filesystemUuid") != state["legacyFilesystemUuid"]:
            return self._storage_error(
                "storage_identity_mismatch",
                "legacy data image UUID changed during migration",
                imageAction=action,
            )
        try:
            committed = store.commit(
                state,
                str(action["filesystemUuid"]),
                int(action["sizeBytes"]),
            )
        except (StorageError, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, StorageError):
                return exc.as_dict()
            return self._storage_error(
                "storage_state_invalid",
                "cannot commit instance storage transaction",
            )
        return {
            "ok": True,
            "volume": {"ok": True, "exists": True},
            "imageAction": action,
            "storage": public_storage_state(committed, healthy=True),
        }

    def _android_boot_command(self) -> list[str]:
        return [
            "androidboot.redroid_width=1080",
            "androidboot.redroid_height=1920",
            "androidboot.redroid_dpi=480",
            f"service.adb.tcp.port={self.lease.android_adb_port}",
            "androidboot.use_memfd=true",
            "androidboot.mode=normal",
        ]

    def docker_create_command(self) -> list[str]:
        dns_args = [
            argument
            for address in self.cfg.network_dns_servers
            for argument in ("--dns", address)
        ]
        return [
            *self.docker_base_cmd(),
            "create",
            "--privileged",
            "--restart=no",
            "--name",
            self.lease.container_name,
            *self._owner_label_args(),
            *self._google_label_args(),
            "-p",
            f"127.0.0.1:{self.lease.host_adb_port}:{self.lease.android_adb_port}",
            "-v",
            f"{self.lease.volume_name}:/data",
            "--network",
            self.lease.network_name,
            "--ip",
            self.lease.ipv4_address,
            "--ip6",
            self.lease.ipv6_address,
            "--mac-address",
            self.lease.mac_address,
            *dns_args,
            *self.cfg.extra_docker_args,
            *self.binder_volume_args(),
            self.effective_image(),
            *self._android_boot_command(),
        ]

    def docker_exec(self, args: list[str], timeout: int = 15) -> dict[str, Any]:
        if which("docker") is None:
            return {"ok": False, "error": "docker not found"}
        container, error = self._owned_container_record()
        if container is None:
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": error,
            }
        cmd = [*self.docker_base_cmd(), "exec", container["Id"], *args]
        try:
            proc = run(cmd, timeout=timeout, env=self.docker_env())
        except Exception as e:
            return {"ok": False, "error": str(e), "command": cmd}
        return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "command": cmd}

    def docker_wait_boot(self, timeout_sec: int = 120) -> dict[str, Any]:
        """Wait for Android boot via docker exec; independent of adb state."""
        deadline = time.time() + timeout_sec
        last: dict[str, Any] = {}
        while time.time() < deadline:
            r = self.docker_exec(["getprop", "sys.boot_completed"], timeout=10)
            last = r
            if r.get("ok") and r.get("stdout", "").strip() == "1":
                return {"ok": True}
            time.sleep(2)
        return {"ok": False, "error": "timeout waiting for Android boot via docker exec", "last": last}
    def ensure_adb_authorized_key(self) -> dict[str, Any]:
        """Authorize the current host ADB identity before the first TCP connection."""
        # Starting the local server also generates ~/.android/adbkey{,.pub} when
        # this is the host's first ADB use.
        self.adb(["start-server"])
        candidates: list[tuple[str, Path]] = []
        vendor_keys = os.environ.get("ADB_VENDOR_KEYS", "")
        for raw in vendor_keys.split(os.pathsep):
            if not raw:
                continue
            candidate = Path(raw).expanduser()
            if candidate.is_dir():
                candidate = candidate / "adbkey.pub"
            elif candidate.suffix != ".pub":
                candidate = Path(f"{candidate}.pub")
            candidates.append(("ADB_VENDOR_KEYS", candidate))
        candidates.append(("default", Path.home() / ".android" / "adbkey.pub"))

        label = ""
        public_key = ""
        for candidate_label, candidate in candidates:
            try:
                value = candidate.read_text().strip()
            except OSError:
                continue
            if value:
                label = candidate_label
                public_key = value
                break
        if not public_key:
            return {"ok": False, "error": "host ADB public key not found"}

        existing = self.docker_exec(
            ["sh", "-c", "cat /data/misc/adb/adb_keys 2>/dev/null || true"]
        ).get("stdout", "")
        keys = [line.strip() for line in str(existing).splitlines() if line.strip()]
        if public_key not in keys:
            keys.append(public_key)
        payload = "\n".join(keys) + "\n"
        container, ownership_error = self._owned_container_record()
        if container is None:
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": ownership_error,
            }
        cmd = [
            *self.docker_base_cmd(),
            "exec",
            "-i",
            container["Id"],
            "sh",
            "-c",
            "umask 027; mkdir -p /data/misc/adb && "
            "cat > /data/misc/adb/adb_keys && "
            "chown 1000:2000 /data/misc/adb/adb_keys && "
            "chmod 640 /data/misc/adb/adb_keys && "
            "(restorecon /data/misc/adb /data/misc/adb/adb_keys >/dev/null 2>&1 || true)",
        ]
        try:
            proc = subprocess.run(
                cmd,
                input=payload,
                text=True,
                capture_output=True,
                timeout=20,
                env=self.docker_env(),
            )
        except Exception as e:
            return {"ok": False, "error": str(e), "source": label}
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stderr": proc.stderr,
            "source": label,
            "keyCount": len(keys),
        }

    def switch_adbd_port_via_docker(self) -> dict[str, Any]:
        """Move adbd to the leased Android ADB port via docker exec."""
        desired = str(self.lease.android_adb_port)
        if desired == "5555":
            return {"ok": True, "skipped": True}
        setp = self.docker_exec(["sh", "-c", "setprop service.adb.tcp.port " + desired])
        restart = self.docker_exec(["sh", "-c", "setprop ctl.restart adbd"])
        deadline = time.time() + 30
        listen: dict[str, Any] = {}
        while time.time() < deadline:
            listen = self.docker_exec(["sh", "-c", "ss -ltn 2>/dev/null | grep ':" + desired + "' || true"], timeout=10)
            if desired in str(listen.get("stdout", "")):
                break
            time.sleep(1)
        ok = desired in str(listen.get("stdout", ""))
        return {"ok": ok, "port": desired, "setprop": setp, "restart": restart, "listener": listen}

    def runtime_preflight(self) -> dict[str, Any]:
        script = self.context.project_root / "scripts" / "redroid-preflight.sh"
        proc = run([str(script)], env=self.docker_env())
        try:
            data = json.loads(proc.stdout)
        except Exception:
            data = {"ok": proc.returncode == 0, "stdout": proc.stdout, "stderr": proc.stderr}
        data["returncode"] = proc.returncode
        return data

    def _container_has_lease_owner(self, container: dict[str, Any]) -> bool:
        config = container.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        return (
            isinstance(container.get("Id"), str)
            and bool(container["Id"])
            and str(container.get("Name", "")).removeprefix("/")
            == self.lease.container_name
            and isinstance(labels, dict)
            and all(
                labels.get(key) == value
                for key, value in self.lease.owner_labels.items()
            )
        )

    def _container_matches_lease(self, container: dict[str, Any]) -> bool:
        config = container.get("Config")
        host_config = container.get("HostConfig")
        network_settings = container.get("NetworkSettings")
        if (
            not isinstance(config, dict)
            or not isinstance(host_config, dict)
            or not isinstance(network_settings, dict)
        ):
            return False
        restart_policy = host_config.get("RestartPolicy")
        port_bindings = host_config.get("PortBindings")
        adb_bindings = (
            port_bindings.get(f"{self.lease.android_adb_port}/tcp")
            if isinstance(port_bindings, dict)
            else None
        )
        expected_adb_binding = {
            "HostIp": "127.0.0.1",
            "HostPort": str(self.lease.host_adb_port),
        }
        mounts = container.get("Mounts")
        owns_data_mount = (
            isinstance(mounts, list)
            and any(
                isinstance(mount, dict)
                and mount.get("Type") == "volume"
                and mount.get("Name") == self.lease.volume_name
                and mount.get("Destination") == "/data"
                for mount in mounts
            )
        )
        networks = network_settings.get("Networks")
        endpoint = (
            networks.get(self.lease.network_name)
            if isinstance(networks, dict)
            else None
        )
        ipam_config = endpoint.get("IPAMConfig") if isinstance(endpoint, dict) else None
        ipv4_matches = (
            endpoint.get("IPAddress") == self.lease.ipv4_address
            or (
                not endpoint.get("IPAddress")
                and isinstance(ipam_config, dict)
                and ipam_config.get("IPv4Address") == self.lease.ipv4_address
            )
        ) if isinstance(endpoint, dict) else False
        ipv6_matches = (
            endpoint.get("GlobalIPv6Address") == self.lease.ipv6_address
            or (
                not endpoint.get("GlobalIPv6Address")
                and isinstance(ipam_config, dict)
                and ipam_config.get("IPv6Address") == self.lease.ipv6_address
            )
        ) if isinstance(endpoint, dict) else False
        labels = config.get("Labels")
        return (
            self._container_has_lease_owner(container)
            and config.get("Image") == self.effective_image()
            and self._managed_container_labels_match(labels)
            and config.get("Cmd") == self._android_boot_command()
            and host_config.get("AutoRemove") is False
            and host_config.get("Privileged") is True
            and isinstance(restart_policy, dict)
            and restart_policy.get("Name") == "no"
            and host_config.get("NetworkMode") == self.lease.network_name
            and host_config.get("Dns") == self.cfg.network_dns_servers
            and isinstance(adb_bindings, list)
            and expected_adb_binding in adb_bindings
            and owns_data_mount
            and isinstance(networks, dict)
            and set(networks) == {self.lease.network_name}
            and isinstance(endpoint, dict)
            and ipv4_matches
            and ipv6_matches
            and str(endpoint.get("MacAddress", "")).lower()
            == self.lease.mac_address.lower()
        )

    def _owned_container_record(
        self,
    ) -> tuple[Optional[dict[str, Any]], str]:
        container, _ = self._inspect_docker_object(
            "container",
            self.lease.container_name,
        )
        if container is None:
            return None, "instance container does not exist"
        if not container or not self._container_has_lease_owner(container):
            return None, "Docker container is not owned by this instance"
        return container, ""

    def _owned_container(self) -> tuple[bool, str]:
        container, error = self._owned_container_record()
        return container is not None, error

    def collect_persisted_device_identity(self) -> dict[str, Any]:
        """Read legacy stable identifiers from persistent Android state."""
        command = (
            "set +e; "
            "printf 'androidId=%s\\n' \"$(settings --user 0 get secure android_id 2>/dev/null)\"; "
            "serial=$(cat /data/local/tmp/xenoid-profile/serial 2>/dev/null); "
            "[ -n \"$serial\" ] || serial=$(getprop ro.serialno); "
            "printf 'serial=%s\\n' \"$serial\"; "
            "printf 'imei=%s\\n' \"$(getprop persist.xenoid.radio.imei)\"; "
            "printf 'imeisv=%s\\n' \"$(getprop persist.xenoid.radio.imeisv)\""
        )
        result = self.docker_exec(["sh", "-c", command], timeout=15)
        if not result.get("ok"):
            return {}
        allowed = {"androidId", "serial", "imei", "imeisv"}
        values: dict[str, str] = {}
        for line in str(result.get("stdout", "")).splitlines():
            key, separator, value = line.partition("=")
            normalized = value.strip()
            if (
                separator
                and key in allowed
                and normalized
                and normalized.lower() != "null"
                and len(normalized) <= 64
            ):
                values[key] = normalized
        return values

    def location_runtime_container_id(self) -> Optional[str]:
        """Owned running container ID used to derive the location runtime epoch."""
        try:
            container, _ = self._owned_container_record()
        except Exception:
            return None
        if container is None:
            return None
        state = container.get("State")
        if not isinstance(state, dict) or state.get("Running") is not True:
            return None
        container_id = container.get("Id")
        if not isinstance(container_id, str) or re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
            return None
        return container_id

    def _capture_proxy_desired_for_update(self) -> dict[str, Any]:
        """Keep credential-bearing desired state only in memory across an APK update."""
        if self._pending_proxy_restore is not None:
            return {"ok": True, "captured": True, "configured": True}
        try:
            client = self.daemon_client(timeout=2.0)
            health = client.health()
        except Exception:
            return {"ok": True, "captured": False, "configured": False}
        if not isinstance(health, dict) or health.get("ok") is not True:
            return {"ok": True, "captured": False, "configured": False}
        try:
            exported = client.proxy_export()
        except Exception:
            exported = {"ok": False}
        if not isinstance(exported, dict) or exported.get("ok") is not True:
            if isinstance(exported, dict) and exported.get("httpStatus") == 404:
                return {"ok": True, "captured": False, "configured": False}
            return self._proxy_failure("proxy_state_backup_failed")
        instance_id = exported.get("instanceId")
        source = exported.get("source")
        enabled = exported.get("enabled")
        if instance_id not in ("", self.context.instance_id) or not isinstance(enabled, bool):
            return self._proxy_failure("proxy_state_backup_failed")
        if source is None:
            return {"ok": True, "captured": True, "configured": False}
        if not isinstance(source, dict):
            return self._proxy_failure("proxy_state_backup_failed")
        kind = source.get("kind")
        value = source.get("value")
        selected_node = source.get("selectedNode")
        udp_allowed = source.get("udpAllowed")
        allow_insecure_http = source.get("allowInsecureHttp")
        if (
            kind not in {"endpoint", "uri_list", "clash", "subscription"}
            or not isinstance(value, str)
            or not isinstance(selected_node, str)
            or not isinstance(udp_allowed, bool)
            or not isinstance(allow_insecure_http, bool)
        ):
            return self._proxy_failure("proxy_state_backup_failed")
        try:
            if len(value.encode("utf-8")) > PROXY_MAX_SOURCE_BYTES:
                return self._proxy_failure("proxy_state_backup_failed")
        except UnicodeError:
            return self._proxy_failure("proxy_state_backup_failed")
        self._pending_proxy_restore = (
            kind,
            value,
            enabled,
            selected_node,
            udp_allowed,
            allow_insecure_http,
        )
        return {"ok": True, "captured": True, "configured": True}

    def _restore_proxy_desired_after_update(self, client: DaemonClient) -> dict[str, Any]:
        pending = self._pending_proxy_restore
        if pending is None:
            return {"ok": True, "restored": False}
        kind, value, enabled, selected_node, udp_allowed, allow_insecure_http = pending
        restored = client.proxy_source(
            kind,
            value,
            enabled,
            selected_node,
            udp_allowed,
            allow_insecure_http,
        )
        if not isinstance(restored, dict) or restored.get("ok") is not True:
            return self._proxy_failure("proxy_state_restore_failed")
        self._pending_proxy_restore = None
        return {"ok": True, "restored": True}

    def reconcile_proxy_desired(self) -> dict[str, Any]:
        """Converge this instance's daemon desired state before runtime acceptance."""
        try:
            from .proxy_controller import ProxyController

            client = self.daemon_client()
            restored = self._restore_proxy_desired_after_update(client)
            if restored.get("ok") is not True:
                return restored
            return ProxyController(
                self.context,
                self.cfg,
                self.lease,
                self,
                client,
            ).reconcile_desired()
        except InstanceError as exc:
            return {"ok": False, "code": exc.code, "error": exc.code}
        except Exception:
            return {
                "ok": False,
                "code": "proxy_reconcile_failed",
                "error": "proxy_reconcile_failed",
            }

    def quarantine_proxy_for_lifecycle(self) -> dict[str, Any]:
        """Install this instance's fail-closed guard before container removal."""
        try:
            prerequisite = self.proxy_prerequisite(allow_stopped=True)
            if prerequisite.get("ok") is not True:
                return prerequisite
            result = self.proxy_quarantine()
        except InstanceError as exc:
            return {"ok": False, "code": exc.code, "error": exc.code}
        except Exception:
            return {
                "ok": False,
                "code": "engine_unavailable",
                "error": "engine_unavailable",
            }
        if not isinstance(result, dict):
            return {
                "ok": False,
                "code": "engine_response_invalid",
                "error": "engine_response_invalid",
            }
        if result.get("ok") is True:
            return result
        code = result.get("code") or result.get("error")
        if not isinstance(code, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) is None:
            code = "engine_unavailable"
        return {"ok": False, "code": code, "error": code}

    def _remove_container_safely(
        self,
        container: dict[str, Any],
        *,
        ownership: str,
    ) -> dict[str, Any]:
        container_id = container.get("Id")
        if not isinstance(container_id, str) or not container_id:
            return self._storage_error(
                "resource_conflict",
                "container identity is invalid",
            )
        result: dict[str, Any] = {"ok": False, "ownership": ownership}
        quarantine = self.quarantine_proxy_for_lifecycle()
        result["proxyQuarantine"] = quarantine
        if quarantine.get("ok") is not True:
            result["error"] = quarantine.get("code", "engine_unavailable")
            return result
        state = container.get("State")
        running = isinstance(state, dict) and state.get("Running") is True
        if running:
            synced = run(
                [*self.docker_base_cmd(), "exec", container_id, "sync"],
                timeout=30,
                env=self.docker_env(),
            )
            result["sync"] = {
                "ok": synced.returncode == 0,
                "returncode": synced.returncode,
                "stderr": synced.stderr.strip()[-500:],
            }
            if synced.returncode != 0:
                result["error"] = "container_sync_failed"
                return result
            stopped = run(
                [
                    *self.docker_base_cmd(),
                    "stop",
                    "--time",
                    "30",
                    container_id,
                ],
                timeout=45,
                env=self.docker_env(),
            )
            result["stop"] = {
                "ok": stopped.returncode == 0,
                "returncode": stopped.returncode,
                "stderr": stopped.stderr.strip()[-500:],
            }
            if stopped.returncode != 0:
                result["error"] = "container_stop_failed"
                return result
        removed = run(
            [*self.docker_base_cmd(), "rm", container_id],
            timeout=30,
            env=self.docker_env(),
        )
        result["remove"] = {
            "ok": removed.returncode == 0,
            "returncode": removed.returncode,
            "stderr": removed.stderr.strip()[-500:],
        }
        if removed.returncode != 0:
            result["error"] = "container_remove_failed"
            return result
        try:
            cleanup = self.proxy_cleanup()
        except InstanceError as exc:
            cleanup = {"ok": False, "code": exc.code, "error": exc.code}
        except Exception:
            cleanup = {
                "ok": False,
                "code": "engine_unavailable",
                "error": "engine_unavailable",
            }
        result["proxyCleanup"] = cleanup
        result["ok"] = isinstance(cleanup, dict) and cleanup.get("ok") is True
        if not result["ok"]:
            result["error"] = "proxy_cleanup_failed"
        return result

    def _remove_owned_container(self, container: dict[str, Any]) -> dict[str, Any]:
        if not self._container_has_lease_owner(container):
            return self._storage_error(
                "resource_conflict",
                "Docker container is not owned by this instance",
            )
        return self._remove_container_safely(container, ownership="lease")

    def _remove_legacy_container(
        self,
        container_id: str,
        expected_name: str,
        expected_volume: str,
    ) -> dict[str, Any]:
        container, _ = self._inspect_docker_object("container", container_id)
        if not container:
            return self._storage_error(
                "storage_legacy_attached",
                "legacy container inspection failed",
            )
        config = container.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        mounts = container.get("Mounts")
        name = str(container.get("Name", "")).removeprefix("/")
        has_expected_mount = isinstance(mounts, list) and any(
            isinstance(mount, dict)
            and mount.get("Type") == "volume"
            and mount.get("Name") == expected_volume
            and mount.get("Destination") == "/data"
            for mount in mounts
        )
        foreign_owner = (
            isinstance(labels, dict)
            and labels.get("dev.xenoid.owner") == "xenoid"
            and labels.get("dev.xenoid.instance_id")
            not in (None, self.context.instance_id)
        )
        if (
            not expected_name
            or name != expected_name
            or not has_expected_mount
            or foreign_owner
        ):
            return self._storage_error(
                "storage_legacy_attached",
                "legacy container ownership cannot be proven",
            )
        return self._remove_container_safely(container, ownership="legacy-record")

    def _google_binding_preflight(
        self,
        spec: Optional[ReleaseSpec],
    ) -> dict[str, Any]:
        binding_store = GoogleBindingStore(self.context, self.lease)
        binding = binding_store.load()
        storage = StorageStateStore(self.context, self.lease).load()
        legacy = self._legacy_engine_record()
        volume, inspected = self._inspect_docker_object(
            "volume",
            self.lease.volume_name,
        )
        if volume == {}:
            raise GoogleServicesError(
                "google_services_freshness_unknown",
                "cannot inspect the instance data volume identity",
            )
        missing = "no such volume" in str(inspected.stderr or "").lower()
        freshness_known = volume is not None or missing
        fresh = (
            freshness_known
            and volume is None
            and storage is None
            and legacy is None
        )
        legacy_actual_none = (
            spec is None
            and not fresh
            and (volume is not None or storage is not None or legacy is not None)
        )
        decision = transition_decision(
            spec,
            binding,
            freshness_known=freshness_known,
            fresh=fresh,
            legacy_actual_none=legacy_actual_none,
        )
        return {
            **decision,
            "binding": binding,
            "storagePresent": storage is not None,
            "volumePresent": volume is not None,
            "legacyPresent": legacy is not None,
        }

    def google_services_configuration_mutable(self) -> dict[str, Any]:
        current = GoogleBindingStore(self.context, self.lease).load()
        storage = StorageStateStore(self.context, self.lease).load()
        legacy = self._legacy_engine_record()
        volume, inspected = self._inspect_docker_object(
            "volume",
            self.lease.volume_name,
        )
        missing = "no such volume" in str(inspected.stderr or "").lower()
        known = volume is not None or missing
        mutable = (
            current is None
            and storage is None
            and legacy is None
            and known
            and volume is None
        )
        return {
            "ok": mutable,
            "mutable": mutable,
            "binding": public_binding(current),
            "storagePresent": storage is not None,
            "volumePresent": volume is not None,
            "legacyPresent": legacy is not None,
            **(
                {}
                if mutable
                else {
                    "error": (
                        "google_services_new_instance_required"
                        if known
                        else "google_services_freshness_unknown"
                    ),
                    "message": (
                        "Google services configuration is immutable after Android data exists"
                        if known
                        else "cannot prove that this instance has no Android data"
                    ),
                }
            ),
        }

    def _begin_google_binding(
        self,
        spec: Optional[ReleaseSpec],
        preflight: dict[str, Any],
    ) -> dict[str, Any]:
        store = GoogleBindingStore(self.context, self.lease)
        existing = preflight.get("binding")
        if isinstance(existing, dict):
            return existing
        source = (
            "legacy"
            if preflight.get("transition") == "legacy-none"
            else "fresh"
        )
        pending = store.pending(spec, source)
        if preflight.get("transition") == "legacy-none":
            return store.commit(pending)
        return pending

    def _commit_google_binding(
        self,
        binding: Mapping[str, Any],
    ) -> dict[str, Any]:
        return GoogleBindingStore(self.context, self.lease).commit(binding)

    def google_services_bootstrap_gate(
        self,
        spec: Optional[ReleaseSpec],
    ) -> dict[str, Any]:
        packages: dict[str, Any] = {}
        package_ok = True
        for package in (
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.android.vending",
        ):
            path = self.adb(["shell", "pm", "path", package], timeout=20)
            output = str(path.get("stdout") or "").strip()
            present = path.get("ok") is True and "package:" in output
            expected = spec is not None
            packages[package] = {
                "present": present,
                "expected": expected,
                "path": output if present else None,
            }
            package_ok = package_ok and present is expected
        release = self.adb(["shell", "getprop", "ro.build.version.release"])
        abilist = self.adb(["shell", "getprop", "ro.product.cpu.abilist"])
        product = self.adb(["shell", "getprop", "ro.build.product"])
        platform_ok = (
            str(release.get("stdout") or "").strip() == "13"
            and str(product.get("stdout") or "").strip() == "raven"
            and str(abilist.get("stdout") or "").strip() == "arm64-v8a"
        )
        launcher: dict[str, Any] = {"ok": spec is None, "skipped": spec is None}
        system_flags: dict[str, Any] = {
            "ok": spec is None,
            "skipped": spec is None,
        }
        provision: dict[str, Any] = {
            "ok": True,
            "skipped": spec is None,
            "present": False,
        }
        if spec is not None:
            resolved = self.adb(
                [
                    "shell",
                    "cmd",
                    "package",
                    "resolve-activity",
                    "--brief",
                    "-a",
                    "android.intent.action.MAIN",
                    "-c",
                    "android.intent.category.LAUNCHER",
                    "com.android.vending",
                ],
                timeout=20,
            )
            resolved_lines = [
                line.strip()
                for line in str(resolved.get("stdout") or "").splitlines()
                if line.strip()
            ]
            resolved_text = resolved_lines[-1] if resolved_lines else ""
            launcher = {
                "ok": resolved.get("ok") is True
                and resolved_text.startswith("com.android.vending/"),
                "component": resolved_text,
            }
            flags = self.adb(
                [
                    "shell",
                    "dumpsys",
                    "package",
                    "com.google.android.gms",
                ],
                timeout=30,
            )
            flags_text = str(flags.get("stdout") or "")
            system_flags = {
                "ok": flags.get("ok") is True
                and (
                    "SYSTEM" in flags_text
                    or "system_ext/priv-app/GmsCore" in flags_text
                    or "product/priv-app/GmsCore" in flags_text
                ),
                "updatedSystemApp": "UPDATED_SYSTEM_APP" in flags_text,
            }
            provision_path = self.adb(
                ["shell", "pm", "path", "com.android.provision"],
                timeout=20,
            )
            provision_present = (
                "package:" in str(provision_path.get("stdout") or "")
            )
            provision_absence_checked = (
                provision_path.get("ok") is True
                or (
                    provision_path.get("returncode") == 1
                    and not str(provision_path.get("stderr") or "").strip()
                )
            )
            provision = {
                "ok": provision_absence_checked and not provision_present,
                "present": provision_present,
            }
        ok = bool(
            package_ok
            and platform_ok
            and launcher.get("ok")
            and system_flags.get("ok")
            and provision.get("ok")
        )
        return {
            "ok": ok,
            "provider": spec.provider if spec is not None else PROVIDER_NONE,
            "packages": packages,
            "launcher": launcher,
            "systemPackage": system_flags,
            "provisionConflict": provision,
            "platform": {
                "release": str(release.get("stdout") or "").strip(),
                "product": str(product.get("stdout") or "").strip(),
                "abilist": str(abilist.get("stdout") or "").strip(),
                "ok": platform_ok,
            },
            **(
                {}
                if ok
                else {
                    "error": "google_services_runtime_not_ready",
                    "message": "Android PackageManager Google services bootstrap gate failed",
                }
            ),
        }

    def start(self, dry_run: bool = False, wait: bool = True, install_daemon_apk: Optional[str] = None, start_colima: bool = False, adb_root: bool = True, skip_preflight: bool = False, recreate: bool = False, defer_proxy: bool = False) -> dict[str, Any]:
        self.ensure_instance_lease()
        plan: dict[str, Any] = {
            "backend": self.cfg.backend,
            "colimaCommand": self.colima_start_command(),
            "effectiveImage": self.effective_image(),
            "adbTarget": self.adb_target,
            "daemonPort": self.lease.host_daemon_port,
            "recreate": recreate,
            "proxyDesiredConvergence": not defer_proxy,
        }
        if dry_run:
            plan["dockerCommand"] = self.docker_create_command()
            preflight = None if skip_preflight else self.runtime_preflight()
            if preflight is not None:
                plan["preflight"] = preflight
            return {"dry_run": True, "plan": plan}
        if which("docker") is None:
            return {"ok": False, "error": "docker not found", "plan": plan}
        endpoint = self.docker_endpoint_host()
        if endpoint.startswith("tcp://"):
            return {
                "ok": False,
                "error": "remote Docker contexts must use ssh:// so host protection and rootfs setup can run",
                "plan": plan,
            }
        if start_colima and self.should_use_colima():
            if which("colima") is None:
                return {"ok": False, "error": "colima not found", "plan": plan}
            colima = run(self.colima_start_command())
            plan["colima"] = {
                "ok": colima.returncode == 0,
                "returncode": colima.returncode,
                "stdout": colima.stdout.strip(),
                "stderr": colima.stderr.strip(),
            }
            if colima.returncode != 0:
                return {"ok": False, "error": "colima start failed", "plan": plan}
        preflight = None if skip_preflight else self.runtime_preflight()
        if preflight is not None:
            plan["preflight"] = preflight
            if not preflight.get("ok"):
                return {"ok": False, "error": "runtime preflight failed", "plan": plan}
        try:
            google_spec = self.google_runtime_spec(
                "start",
                require_assets=True,
            )
            google_transition = self._google_binding_preflight(google_spec)
        except (GoogleServicesError, StorageError) as exc:
            code = getattr(exc, "code", "google_services_spec_mismatch")
            return {
                "ok": False,
                "error": code,
                "message": str(exc),
                "plan": plan,
            }
        plan["googleServicesPreflight"] = {
            "ok": True,
            "provider": (
                google_spec.provider
                if google_spec is not None
                else PROVIDER_NONE
            ),
            "release": (
                google_spec.release
                if google_spec is not None
                else PROVIDER_NONE
            ),
            "specSha256": (
                google_spec.fingerprint
                if google_spec is not None
                else disabled_runtime_spec_fingerprint()
            ),
            "transition": google_transition["transition"],
        }
        if self.cfg.auto_build_runtime_image:
            image_build = self._build_effective_runtime_image(google_spec)
            plan["runtimeImageBuild"] = image_build
            if image_build.get("ok") is not True:
                return {
                    "ok": False,
                    "error": image_build.get(
                        "error",
                        "runtime_image_build_failed",
                    ),
                    "message": image_build.get(
                        "message",
                        "runtime image build failed",
                    ),
                    "plan": plan,
                }
        preexisting_container, _ = self._inspect_docker_object(
            "container",
            self.lease.container_name,
        )
        if (
            isinstance(preexisting_container, dict)
            and preexisting_container
            and self._container_has_lease_owner(preexisting_container)
        ):
            image_identity = self._container_effective_image_identity(
                preexisting_container,
            )
            plan["containerImageIdentity"] = image_identity
            if image_identity.get("ok") is not True and not recreate:
                return {
                    "ok": False,
                    "error": "runtime_spec_mismatch",
                    "message": "owned container requires explicit recreation for the effective image",
                    "plan": plan,
                }



        plan["network"] = self.ensure_network()
        if not plan["network"].get("ok"):
            return {"ok": False, "error": "docker network setup failed", "plan": plan}

        try:
            google_binding = self._begin_google_binding(
                google_spec,
                google_transition,
            )
        except GoogleServicesError as exc:
            return {
                "ok": False,
                "error": exc.code,
                "message": str(exc),
                "plan": plan,
            }
        plan["googleServicesBinding"] = public_binding(google_binding)

        rootfs_images = self.ensure_rootfs_images()
        plan["rootfsImages"] = rootfs_images
        if not rootfs_images.get("ok"):
            return {
                "ok": False,
                "error": rootfs_images.get(
                    "error",
                    "rootfs_image_build_failed",
                ),
                "message": rootfs_images.get(
                    "message",
                    "rootfs/data image build failed",
                ),
                "plan": plan,
            }

        binder = self.ensure_binder()
        plan["binder"] = binder
        if not binder.get("ok"):
            return {"ok": False, "error": "binder setup failed on docker host", "plan": plan}

        docker_cmd = self.docker_create_command()
        plan["dockerCommand"] = docker_cmd
        if not any("/dev/binder" in arg for arg in docker_cmd):
            return {"ok": False, "error": "binder device mounts unavailable after binder setup", "plan": plan}

        loaded_kmod = self.kernel_module_status()
        if loaded_kmod.get("ok"):
            plan["kmod"] = {
                "ok": True,
                "reused": True,
                "reason": "engine-host kernel protection is already loaded",
            }
        else:
            kmod_cmd = self.build_kmod_command()
            kmod = run(kmod_cmd, timeout=900, env=self.docker_env())
            plan["kmod"] = {
                "ok": kmod.returncode == 0,
                "command": kmod_cmd,
                "returncode": kmod.returncode,
                "stdout": kmod.stdout.strip()[-300:],
                "stderr": kmod.stderr.strip()[-300:],
            }
            if kmod.returncode != 0:
                return {"ok": False, "error": "kernel protection build/load failed", "plan": plan}
        plan["kernelModuleStatus"] = self.kernel_module_status()
        if not plan["kernelModuleStatus"].get("ok"):
            return {"ok": False, "error": "kernel protection failed post-load verification", "plan": plan}
        existing_container, existing_inspect = self._inspect_docker_object(
            "container",
            self.lease.container_name,
        )
        plan["containerLookup"] = {
            "ok": existing_container is None or bool(existing_container),
            "returncode": existing_inspect.returncode,
            "stderr": existing_inspect.stderr.strip()[-300:],
        }
        if existing_container == {}:
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "container inspection returned invalid identity",
                "plan": plan,
            }
        existing_present = existing_container is not None
        if existing_present and not self._container_has_lease_owner(existing_container):
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "Docker container is not owned by this instance",
                "plan": plan,
            }
        if (
            existing_present
            and not recreate
            and not self._container_matches_lease(existing_container)
        ):
            return {
                "ok": False,
                "error": "runtime_spec_mismatch",
                "message": "owned container requires explicit recreation",
                "plan": plan,
            }
        if existing_present and recreate:
            preserved = self._capture_proxy_desired_for_update()
            plan["proxyDesiredBeforeRecreate"] = preserved
            if preserved.get("ok") is not True:
                return {
                    "ok": False,
                    "error": preserved.get("code", "proxy_state_backup_failed"),
                    "plan": plan,
                }
        if existing_present and recreate:
            removal = self._remove_owned_container(existing_container)
            plan["containerRecreate"] = removal
            if removal.get("ok") is not True:
                return {
                    "ok": False,
                    "error": removal.get("error", "existing_container_removal_failed"),
                    "plan": plan,
                }
            existing_present = False

        created_new = False
        if not existing_present:
            # Recover proxy ownership left by an externally removed container
            # before assigning a new Docker identity to this instance.
            cleanup = self.proxy_cleanup()
            plan["proxyCleanupBeforeCreate"] = cleanup
            if cleanup.get("ok") is not True:
                return {"ok": False, "error": "proxy_cleanup_failed", "plan": plan}
            proc = run(docker_cmd, env=self.docker_env())
            result: dict[str, Any] = {
                "ok": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip(),
                "plan": plan,
            }
            if proc.returncode != 0:
                return result
            existing_container, _ = self._owned_container_record()
            if existing_container is None:
                result["ok"] = False
                result["error"] = "resource_conflict"
                result["message"] = "created container is not owned by this instance"
                return result
            created_new = True
        else:
            result = {
                "ok": True,
                "container": self.lease.container_name,
                "plan": plan,
            }

        state = existing_container.get("State") if isinstance(existing_container, dict) else None
        already_running = isinstance(state, dict) and state.get("Running") is True
        if already_running:
            result["alreadyRunning"] = True
        else:
            try:
                guarded = self.proxy_bootstrap_quarantine()
            except InstanceError as exc:
                guarded = self._proxy_failure(exc.code)
            except Exception:
                guarded = self._proxy_failure("engine_unavailable")
            result["proxyQuarantineBeforeStart"] = guarded
            if guarded.get("ok") is not True:
                result["ok"] = False
                result["error"] = guarded.get("code", "engine_unavailable")
                return result
            started = run(
                [*self.docker_base_cmd(), "start", existing_container["Id"]],
                env=self.docker_env(),
            )
            result["containerStart"] = {
                "ok": started.returncode == 0,
                "returncode": started.returncode,
                "stdout": started.stdout.strip(),
                "stderr": started.stderr.strip(),
            }
            if started.returncode != 0:
                result["ok"] = False
                result["error"] = "container_start_failed"
                return result
            result["created"] = created_new

        required: list[dict[str, Any]] = []
        if wait:
            result["dockerBootWait"] = self.docker_wait_boot()
            result["adbAuthorization"] = self.ensure_adb_authorized_key()
            required.extend([result["dockerBootWait"], result["adbAuthorization"]])
            if self.lease.android_adb_port != 5555:
                result["dockerAdbPortSwitch"] = self.switch_adbd_port_via_docker()
                required.append(result["dockerAdbPortSwitch"])
            result["adbConnect"] = self.adb_connect()
            result["adbWait"] = self.adb_wait(timeout_sec=90)
            if self.lease.android_adb_port != 5555 and not result["adbWait"].get("ok"):
                result["dockerAdbPortRetry"] = self.switch_adbd_port_via_docker()
                result["adbConnectRetry"] = self.adb_connect()
                result["adbWait"] = self.adb_wait(timeout_sec=60)
            required.append(result["adbWait"])
            if self.lease.android_adb_port != 5555:
                result["androidAdbPort"] = self.ensure_android_adb_port()
                required.append(result["androidAdbPort"])
            if adb_root:
                result["adbRoot"] = self.enable_adb_root()
                required.append(result["adbRoot"])
                if self.lease.android_adb_port != 5555 and result["adbRoot"].get("rooted"):
                    result["dockerAdbPortPostRoot"] = self.switch_adbd_port_via_docker()
                    result["adbConnectPostRoot"] = self.adb_connect()
                    result["adbWaitPostRoot"] = self.adb_wait(timeout_sec=60)
                    required.extend([result["dockerAdbPortPostRoot"], result["adbWaitPostRoot"]])
            result["daemonForward"] = self.forward_daemon_port()
            required.append(result["daemonForward"])

        if not wait:
            result["googleServicesBootstrap"] = {
                "ok": True,
                "skipped": True,
                "pending": True,
                "reason": "Android boot wait was disabled",
            }
        elif result.get("adbWait", {}).get("ok") is True:
            result["googleServicesBootstrap"] = (
                self.google_services_bootstrap_gate(google_spec)
            )
        else:
            result["googleServicesBootstrap"] = {
                "ok": False,
                "skipped": True,
                "error": "google_services_runtime_not_ready",
                "message": "Android boot is required before the Google services bootstrap gate",
            }
        required.append(result["googleServicesBootstrap"])
        if wait and result["googleServicesBootstrap"].get("ok") is True:
            try:
                google_binding = self._commit_google_binding(google_binding)
                result["googleServicesBinding"] = public_binding(google_binding)
            except GoogleServicesError as exc:
                result["googleServicesBinding"] = exc.as_dict()
                required.append(result["googleServicesBinding"])

        daemon_package = self.adb(
            ["shell", "pm", "path", "dev.xenoid.daemon"],
            timeout=15,
        )
        daemon_installed = bool(
            daemon_package.get("ok")
            and "package:" in str(daemon_package.get("stdout", ""))
        )
        daemon_apk = install_daemon_apk
        if daemon_apk is None and not daemon_installed:
            for candidate in (
                self.context.project_root / "artifacts" / "xenoid-daemon.apk",
                self.context.project_root / "daemon" / "app" / "build"
                / "outputs" / "apk" / "debug" / "app-debug.apk",
            ):
                if candidate.is_file():
                    daemon_apk = str(candidate)
                    break
        result["daemonPackage"] = daemon_package
        if daemon_apk is not None:
            result["daemonInstall"] = self.install_daemon(daemon_apk)
        elif daemon_installed:
            result["daemonInstall"] = {"ok": True, "skipped": True}
        else:
            result["daemonInstall"] = {
                "ok": False,
                "error": "daemon APK is not installed and no local artifact is available",
            }
        result["daemonStart"] = (
            self.start_daemon_service()
            if result["daemonInstall"].get("ok")
            else {"ok": False, "skipped": True}
        )
        result["daemonForward"] = (
            self.forward_daemon_port()
            if result["daemonStart"].get("ok")
            else {"ok": False, "skipped": True}
        )
        required.extend([
            result["daemonInstall"],
            result["daemonStart"],
            result["daemonForward"],
        ])

        # Start rootd after the daemon so both processes use the daemon's private
        # control token. This avoids a world-readable token under /data/local/tmp.
        result["rootdRoot"] = self.ensure_rootd_root()
        required.append(result["rootdRoot"])
        result["daemonReady"] = (
            self.ensure_daemon(
                readiness_timeout=CAMERA_MUTATION_TIMEOUT_SECONDS
            )
            if result["rootdRoot"].get("ok")
            and result["daemonForward"].get("ok")
            else {"ok": False, "skipped": True}
        )
        required.append(result["daemonReady"])
        result["dataSentinel"] = (
            self.data_sentinel(create=True)
            if result["daemonReady"].get("ok")
            else {"ok": False, "skipped": True}
        )
        required.append(result["dataSentinel"])
        if defer_proxy:
            # Internal location-refresh path: proxy desired state is reconciled by
            # the caller after the location identity converges, so a broken proxy
            # never blocks location staging or the one-time recreate.
            result["proxyConverged"] = {"ok": True, "skipped": True, "deferred": True}
        else:
            result["proxyConverged"] = (
                self.reconcile_proxy_desired()
                if result["daemonReady"].get("ok")
                else {
                    "ok": False,
                    "code": "daemon_unreachable",
                    "error": "daemon_unreachable",
                }
            )
        required.append(result["proxyConverged"])
        result["imageProtectionStatus"] = self.image_protection_status()
        required.append(result["imageProtectionStatus"])
        result["ok"] = all(bool(step.get("ok")) for step in required)
        result["ready"] = bool(result["ok"] and result["proxyConverged"].get("ok"))
        if not result["ok"]:
            result["error"] = "one or more required runtime startup steps failed"
        return result

    def stop(self) -> dict[str, Any]:
        self.ensure_instance_lease()
        if which("docker") is None:
            return {"ok": False, "error": "docker not found"}
        container, error = self._owned_container_record()
        if container is None:
            if error != "instance container does not exist":
                return {"ok": False, "error": "resource_conflict", "message": error}
            try:
                cleanup = self.proxy_cleanup()
            except InstanceError as exc:
                cleanup = {"ok": False, "code": exc.code, "error": exc.code}
            except Exception:
                cleanup = {
                    "ok": False,
                    "code": "engine_unavailable",
                    "error": "engine_unavailable",
                }
            return {
                "ok": cleanup.get("ok") is True,
                "alreadyStopped": True,
                "proxyCleanup": cleanup,
                **(
                    {}
                    if cleanup.get("ok") is True
                    else {"error": "proxy_cleanup_failed"}
                ),
            }
        return self._remove_owned_container(container)

    def data_sentinel(self, *, create: bool = False) -> dict[str, Any]:
        try:
            state = StorageStateStore(self.context, self.lease).load()
        except StorageError as exc:

            return exc.as_dict()
        if state is None or state.get("state") != "committed":
            return self._storage_error(
                "storage_not_initialized",
                "instance storage is not committed",
            )
        expected = f"{self.context.instance_id} {state['filesystemUuid']}"
        directory = "/data/local/tmp/runtime-state"
        path = f"{directory}/storage-sentinel.v1"
        quoted_expected = shlex.quote(expected)
        expected_digest = hashlib.sha256(f"{expected}\n".encode("ascii")).hexdigest()
        command = (
            "set -eu; "
            f"d={shlex.quote(directory)}; f={shlex.quote(path)}; "
            + (
                "if [ ! -e ${f} ]; then "
                "umask 077; mkdir -p ${d}; chown 0:0 ${d}; chmod 700 ${d}; "
                f"echo {quoted_expected} > ${{d}}/.storage-sentinel.new; "
                "chown 0:0 ${d}/.storage-sentinel.new; "
                "chmod 600 ${d}/.storage-sentinel.new; "
                "sync; "
                "mv -f ${d}/.storage-sentinel.new ${f}; sync; fi; "
                if create
                else ""
            )
            + "[ -d ${d} ] && [ ! -L ${d} ]; "
            "[ $(stat -c %u:%g:%a ${d}) = 0:0:700 ]; "
            "[ -f ${f} ] && [ ! -L ${f} ]; "
            "actual=$(sha256sum ${f}); actual=${actual%% *}; "
            f"[ ${{actual}} = {expected_digest} ]; "
            "[ $(stat -c %u:%g:%a ${f}) = 0:0:600 ]"
        )
        try:
            result = self.daemon_client(timeout=10.0).root_exec(command)
        except Exception:
            return self._storage_error(
                "storage_sentinel_unavailable",
                "live data sentinel is unavailable",
            )
        if not isinstance(result, dict) or result.get("ok") is not True:
            return self._storage_error(
                "storage_sentinel_mismatch",
                "live data sentinel does not match this instance",
            )
        return {
            "ok": True,
            "path": path,
            "instanceId": self.context.short_id,
            "filesystemUuid": state["filesystemUuid"],
            "createdIfMissing": create,
        }

    def device_identity_status(self) -> dict[str, Any]:
        try:
            state = DeviceIdentityStore(self.context).load()
        except IdentityError as exc:
            return exc.as_dict()
        if state is None:
            return {"ok": False, "initialized": False}
        return {"ok": True, **public_identity_state(state)}

    def storage_status(self) -> dict[str, Any]:
        store = StorageStateStore(self.context, self.lease)
        try:
            state = store.load()
        except StorageError as exc:
            return exc.as_dict()
        if state is None:
            return {
                "ok": False,
                "volume": self.lease.volume_name,
                **public_storage_state(
                    None,
                    healthy=False,
                    error="storage_not_initialized",
                ),
            }
        if state["state"] != "committed":
            return {
                "ok": False,
                "volume": self.lease.volume_name,
                **public_storage_state(
                    state,
                    healthy=False,
                    error="storage_transaction_pending",
                ),
            }
        volume, _ = self._inspect_docker_object("volume", self.lease.volume_name)
        if volume is None:
            return {
                "ok": False,
                "volume": self.lease.volume_name,
                **public_storage_state(
                    state,
                    healthy=False,
                    error="storage_volume_missing",
                ),
            }
        if not volume or not self._volume_matches_lease(volume):
            return {
                "ok": False,
                "volume": self.lease.volume_name,
                **public_storage_state(
                    state,
                    healthy=False,
                    error="resource_conflict",
                ),
            }
        image = self._inspect_volume_image(volume)
        if (
            not image.get("ok")
            or image.get("filesystemUuid") != state["filesystemUuid"]
            or image.get("sizeBytes") != state["sizeBytes"]
        ):
            return {
                "ok": False,
                "volume": self.lease.volume_name,
                "image": image,
                **public_storage_state(
                    state,
                    healthy=False,
                    error="storage_identity_mismatch",
                ),
            }
        backup_status: Optional[dict[str, Any]] = None
        if state["backupImage"]:
            backup_status = self._inspect_volume_image(volume, state["backupImage"])
            if (
                not backup_status.get("ok")
                or backup_status.get("filesystemUuid")
                != state["backupFilesystemUuid"]
                or backup_status.get("sizeBytes") != state["backupSizeBytes"]
            ):
                return {
                    "ok": False,
                    "volume": self.lease.volume_name,
                    "image": image,
                    "backupImage": backup_status,
                    **public_storage_state(
                        state,
                        healthy=False,
                        error="storage_backup_mismatch",
                    ),
                }
        return {
            "ok": True,
            "volume": self.lease.volume_name,
            "image": image,
            "backupImage": backup_status,
            **public_storage_state(state, healthy=True),
        }

    def google_services_status(
        self,
        *,
        require_runtime: bool = False,
    ) -> dict[str, Any]:
        provider = self.cfg.google_services_provider
        release = self.cfg.google_services_release
        spec: Optional[ReleaseSpec] = None
        host_ready = provider == PROVIDER_NONE
        error: Optional[str] = None
        try:
            spec = self.google_runtime_spec("status", require_assets=False)
            if spec is not None:
                quick_validate_assets(self.context.project_root, spec)
                host_ready = True
        except GoogleServicesError as exc:
            error = exc.code

        status = base_status(provider, release, spec)
        binding: Optional[dict[str, Any]] = None
        try:
            binding = GoogleBindingStore(self.context, self.lease).load()
        except GoogleServicesError as exc:
            error = error or exc.code
        binding_ok = (
            binding is not None
            and spec is not None
            and binding_matches(binding, spec)
            and binding.get("state") == "committed"
        ) if provider == PROVIDER_MINDTHEGAPPS else (
            binding is None
            or (
                binding_matches(binding, None)
                and binding.get("state") == "committed"
            )
        )

        image, _ = self._inspect_docker_object(
            "image",
            self.effective_image(),
        )
        desired_image_id = (
            str(image.get("Id") or "")
            if isinstance(image, dict)
            else ""
        )
        image_config = (
            image.get("Config")
            if isinstance(image, dict)
            else None
        )
        image_labels = (
            image_config.get("Labels")
            if isinstance(image_config, dict)
            else None
        )
        image_labels = image_labels if isinstance(image_labels, dict) else {}
        if spec is not None:
            image_labels_match: Optional[bool] = bool(
                desired_image_id
                and all(
                    image_labels.get(key) == value
                    for key, value in spec.labels.items()
                )
            )
        elif desired_image_id:
            image_labels_match = not any(
                key in image_labels for key in self._google_label_values()
            )
        else:
            image_labels_match = None

        container, _ = self._inspect_docker_object(
            "container",
            self.lease.container_name,
        )
        owned_container = bool(
            isinstance(container, dict)
            and container
            and self._container_has_lease_owner(container)
        )
        container_state = (
            container.get("State")
            if owned_container and isinstance(container, dict)
            else None
        )
        running = bool(
            isinstance(container_state, dict)
            and container_state.get("Running") is True
        )
        container_config = (
            container.get("Config")
            if owned_container and isinstance(container, dict)
            else None
        )
        container_labels = (
            container_config.get("Labels")
            if isinstance(container_config, dict)
            else None
        )
        container_labels_match = (
            self._managed_container_labels_match(container_labels)
            if owned_container
            else None
        )
        command_match = (
            container_config.get("Cmd") == self._android_boot_command()
            if isinstance(container_config, dict)
            else None
        )
        container_image_id = (
            str(container.get("Image") or "")
            if owned_container and isinstance(container, dict)
            else ""
        )

        rootfs_source_id = ""
        volume, _ = self._inspect_docker_object(
            "volume",
            self.lease.volume_name,
        )
        if isinstance(volume, dict) and self._volume_matches_lease(volume):
            mountpoint = str(volume["Mountpoint"])
            marker = self._engine_host_shell(
                "cat "
                + shlex.quote(
                    f"{mountpoint}/xenoid-rootfs.img.sha256"
                )
                + " 2>/dev/null",
                timeout=30,
            )
            if marker.returncode == 0:
                rootfs_source_id = str(marker.stdout or "").strip()

        identity_ready = bool(
            desired_image_id
            and owned_container
            and desired_image_id == container_image_id
            and desired_image_id == rootfs_source_id
            and image_labels_match is True
            and container_labels_match is True
            and command_match is True
        )
        live: dict[str, Any] = {
            "ok": False,
            "skipped": True,
            "reason": "Android runtime is not running",
        }
        if running:
            live = self.google_services_bootstrap_gate(spec)

        configured = provider == PROVIDER_MINDTHEGAPPS
        ready = bool(
            configured
            and host_ready
            and binding_ok
            and identity_ready
            and running
            and live.get("ok") is True
        )
        if configured:
            runtime_state = "ready" if ready else (
                "failed" if running or error else "configured"
            )
            state = runtime_state
            ok = ready
            if not ready and error is None:
                error = "google_services_runtime_not_ready"
        else:
            clean = bool(
                not running
                or (
                    live.get("ok") is True
                    and (
                        not desired_image_id
                        or image_labels_match is True
                    )
                )
            )
            state = "running-clean" if running and clean else "disabled"
            ready = clean
            ok = clean
            runtime_state = "absent" if clean else "failed"
            if not clean:
                error = error or "unexpected_google_payload"
        if require_runtime and configured and not ready:
            ok = False

        model = capability_model(provider, runtime_state)
        selected = f"./xenoid --instance {self.context.instance_name}"
        next_actions: list[str] = []
        if configured and not host_ready:
            next_actions.append(
                f"{selected} google-services import-mindthegapps "
                f"<{release}.zip> <release.x509.pem>"
            )
        if configured and not running:
            next_actions.append(f"{selected} up")
        elif configured and not ready:
            next_actions.append(
                f"{selected} doctor --require-runtime"
            )
        return {
            **status,
            "ok": ok,
            "state": state,
            "hostReady": host_ready,
            "runtimeRequired": configured,
            "runtimeChecked": running,
            "ready": ready,
            "skipped": not running,
            "binding": public_binding(binding),
            "runtimeIdentity": {
                "desiredImageSha256": desired_image_id or None,
                "containerImageSha256": container_image_id or None,
                "rootfsSourceImageSha256": rootfs_source_id or None,
                "labelsMatch": (
                    image_labels_match is True
                    and container_labels_match is True
                    if owned_container and desired_image_id
                    else None
                ),
                "commandMatch": command_match,
                "skipped": not owned_container,
            },
            "live": live,
            **model,
            "error": error,
            "nextActions": next_actions,
        }

    def status(self) -> dict[str, Any]:
        self.ensure_instance_lease()
        selected = {
            **self.context.public_dict(),
            "container": self.lease.container_name,
            "volume": self.lease.volume_name,
            "adbTarget": self.adb_target,
            "daemonPort": self.lease.host_daemon_port,
        }
        if which("docker") is None:
            return {
                "ok": False,
                "error": "docker not found",
                "instance": selected,
            }
        storage = self.storage_status()
        identity = self.device_identity_status()
        google_services = self.google_services_status()
        container, _ = self._inspect_docker_object(
            "container",
            self.lease.container_name,
        )
        adb_stopped = {"ok": False, "error": "container not running"}
        if container is None:
            return {
                "ok": storage.get("ok") is True,
                "running": False,
                "rows": [],
                "adb": adb_stopped,
                "instance": selected,
                "storage": storage,
                "identity": identity,
                "googleServices": google_services,
            }
        if not container or not self._container_has_lease_owner(container):
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "Docker container is not owned by this instance",
                "instance": selected,
                "storage": storage,
                "identity": identity,
                "googleServices": google_services,
            }
        state = container.get("State")
        running = isinstance(state, dict) and state.get("Running") is True
        proc = run(
            [
                *self.docker_base_cmd(),
                "ps",
                "--filter",
                f"id={container['Id']}",
                "--format",
                "{{json .}}",
            ],
            env=self.docker_env(),
        )
        rows = [line for line in proc.stdout.splitlines() if line.strip()]
        adb_state: dict[str, Any] = adb_stopped
        if running and which("adb") is not None:
            adb_state = self.adb(["get-state"])
        spec_matches = self._container_matches_lease(container)
        return {
            "ok": proc.returncode == 0 and storage.get("ok") is True,
            "running": running,
            "runtimeSpecMatches": spec_matches,
            "rows": rows,
            "adb": adb_state,
            "instance": selected,
            "storage": storage,
            "identity": identity,
            "googleServices": google_services,
        }

    def adb(self, args: list[str], timeout: Optional[float] = None) -> dict[str, Any]:
        adb_bin = which("adb")
        if adb_bin is None:
            return {"ok": False, "error": "adb not found"}
        if args and args[0] == "kill-server":
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "global ADB server shutdown is not instance scoped",
            }
        global_command = bool(
            args
            and args[0] in {"--version", "version", "start-server"}
        )
        if not global_command:
            owned, error = self._owned_container()
            if not owned:
                return {"ok": False, "error": "resource_conflict", "message": error}
        if args and args[0] == "connect":
            cmd = [adb_bin, "connect", self.adb_target]
        elif global_command or (args and args[0] == "devices"):
            cmd = [adb_bin, *args]
        else:
            cmd = [adb_bin, "-s", self.adb_target, *args]
        try:
            proc = run(cmd, timeout=15 if timeout is None else timeout)
        except Exception as e:
            return {"ok": False, "error": str(e), "command": cmd}
        stdout = proc.stdout
        if args and args[0] == "devices":
            lines = [
                line
                for line in (proc.stdout or "").splitlines()
                if line.startswith("List of devices")
                or line.partition("\t")[0].strip() == self.adb_target
            ]
            stdout = "\n".join(lines) + ("\n" if lines else "")
        return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": stdout, "stderr": proc.stderr, "command": cmd}

    def adb_connect(self) -> dict[str, Any]:
        adb_bin = which("adb")
        if adb_bin is None:
            return {"ok": False, "error": "adb not found"}
        try:
            state = run([adb_bin, "-s", self.adb_target, "get-state"], timeout=5)
            state_text = ((state.stdout or "") + (state.stderr or "")).lower()
            if "offline" in state_text:
                run([adb_bin, "disconnect", self.adb_target], timeout=5)
        except Exception:
            pass
        return self.adb(["connect"])

    def adb_wait(self, timeout_sec: int = 90) -> dict[str, Any]:
        if which("adb") is None:
            return {"ok": False, "error": "adb not found"}
        deadline = time.time() + timeout_sec
        last: dict[str, Any] = {}
        while time.time() < deadline:
            self.adb_connect()
            state = self.adb(["get-state"])
            last = state
            if state.get("ok") and "device" in state.get("stdout", ""):
                boot = self.adb(["shell", "getprop", "sys.boot_completed"])
                if "1" in boot.get("stdout", ""):
                    return {"ok": True, "state": state, "bootCompleted": boot}
            time.sleep(2)
        return {"ok": False, "error": "timeout waiting for Android boot", "last": last}

    def ensure_android_adb_port(self) -> dict[str, Any]:
        """Ensure adbd listens on the leased Android-internal port."""
        desired = str(self.lease.android_adb_port)
        cur = self.adb(["shell", "getprop", "service.adb.tcp.port"])
        current = str(cur.get("stdout", "")).strip()
        listener_current = self.adb(["shell", "ss -ltnp 2>/dev/null | grep -E '(^|[^0-9])" + desired + "([^0-9]|$)|:" + desired + "' || true"])
        if current == desired and desired in str(listener_current.get("stdout", "")):
            return {"ok": True, "already": True, "port": desired, "getprop": cur, "listener": listener_current}
        setp = self.adb(["shell", "setprop", "service.adb.tcp.port", desired])
        restart = self.adb(["shell", "setprop", "ctl.restart", "adbd"])
        time.sleep(3)
        reconnect = self.adb_connect()
        wait = self.adb_wait(timeout_sec=30)
        verify = self.adb(["shell", "getprop", "service.adb.tcp.port"])
        listener = self.adb(["shell", "ss -ltnp 2>/dev/null | grep -E '(^|[^0-9])" + desired + "([^0-9]|$)|:" + desired + "' || true"])
        ok = desired in str(listener.get("stdout", "")) and bool(wait.get("ok")) and str(verify.get("stdout", "")).strip() == desired
        return {"ok": ok, "from": current, "port": desired, "setprop": setp, "restart": restart, "reconnect": reconnect, "wait": wait, "verify": verify, "listener": listener}

    def enable_adb_root(self) -> dict[str, Any]:
        if which("adb") is None:
            return {"ok": False, "rooted": False, "error": "adb not found"}
        root = self.adb(["root"])
        root_output = f"{root.get('stdout', '')}\n{root.get('stderr', '')}".lower()
        production_build = "cannot run as root in production builds" in root_output
        if not production_build:
            time.sleep(3)
        reconnect = self.adb_connect()
        wait = self.adb_wait(timeout_sec=15 if production_build else 45)
        uid = self.adb(["shell", "id", "-u"]) if wait.get("ok") else {"ok": False}
        uid_value = str(uid.get("stdout", "")).strip()
        rooted = bool(root.get("ok")) and bool(wait.get("ok")) and uid_value == "0"
        skipped = production_build and bool(wait.get("ok")) and uid_value != "0"
        return {
            "ok": rooted or skipped,
            "rooted": rooted,
            "skipped": skipped,
            "reason": "production-build" if skipped else None,
            "root": root,
            "reconnect": reconnect,
            "wait": wait,
            "uid": uid,
            "uidValue": uid_value,
        }

    def forward_daemon_port(self) -> dict[str, Any]:
        return self.adb([
            "forward",
            f"tcp:{self.lease.host_daemon_port}",
            f"tcp:{self.lease.android_daemon_port}",
        ])

    def stage_camera_source(self, local_path: str) -> dict[str, Any]:
        """Upload one immutable camera candidate for daemon-side validation."""
        try:
            source = Path(local_path).expanduser().resolve(strict=True)
            before = source.stat()
            if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
                return {"ok": False, "error": "camera source must be a nonempty regular file"}

            digest = hashlib.sha256()
            size = 0
            with source.open("rb") as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)

            after = source.stat()
            stable = (
                stat.S_ISREG(after.st_mode)
                and size == before.st_size == after.st_size
                and before.st_dev == after.st_dev
                and before.st_ino == after.st_ino
                and before.st_mtime_ns == after.st_mtime_ns
            )
            if not stable:
                return {"ok": False, "error": "camera source changed while reading"}
        except (OSError, RuntimeError):
            return {"ok": False, "error": "camera source must be a nonempty regular file"}

        staging_path = f"/data/local/tmp/.camera-upload-{secrets.token_hex(16)}"
        push = self.adb(
            ["push", str(source), staging_path],
            timeout=_camera_upload_timeout_seconds(size),
        )
        if not push.get("ok"):
            self.cleanup_camera_staging(staging_path)
            return {"ok": False, "error": "camera source upload failed"}
        chmod = self.adb(["shell", "chmod", "0600", staging_path], timeout=300)
        if not chmod.get("ok"):
            self.cleanup_camera_staging(staging_path)
            return {"ok": False, "error": "camera source upload failed"}
        owner = self.adb([
            "shell",
            f'if [ "$(id -u)" = 0 ]; then chown 2000:2000 {staging_path}; fi',
        ], timeout=300)
        if not owner.get("ok"):
            self.cleanup_camera_staging(staging_path)
            return {"ok": False, "error": "camera source upload failed"}
        return {
            "ok": True,
            "stagingPath": staging_path,
            "size": size,
            "sha256": digest.hexdigest(),
        }

    def cleanup_camera_staging(self, staging_path: str) -> dict[str, Any]:
        """Best-effort removal restricted to names generated above."""
        if re.fullmatch(r"/data/local/tmp/\.camera-upload-[0-9a-f]{32}", staging_path) is None:
            return {"ok": False, "error": "invalid camera staging reference"}
        result = self.adb(["shell", "rm", "-f", staging_path], timeout=300)
        return {"ok": bool(result.get("ok"))}

    def grant_daemon_camera_permission(self) -> dict[str, Any]:
        result = self.adb([
            "shell", "pm", "grant", "--user", "0",
            "dev.xenoid.daemon", "android.permission.CAMERA",
        ])
        return {
            "ok": bool(result.get("ok")),
            **({} if result.get("ok") else {"error": "camera permission grant failed"}),
        }

    def launch_daemon_bootstrap(self) -> dict[str, Any]:
        return self.adb([
            "shell", "am", "start", "--user", "0", "-n",
            "dev.xenoid.daemon/.MainActivity", "--ez", "bootstrap", "true",
        ])

    def launch_camera_self_test(self, run_id: str) -> dict[str, Any]:
        if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", run_id) is None:
            return {"ok": False, "error": "invalid camera self-test run id"}
        result = self.adb([
            "shell", "am", "start", "--user", "0", "-n",
            "dev.xenoid.daemon/.MainActivity",
            "--es", "cameraSelfTestRunId", run_id,
        ])
        return {
            "ok": bool(result.get("ok")),
            **({} if result.get("ok") else {"error": "camera self-test launch failed"}),
        }

    def ensure_rootd_root(self) -> dict[str, Any]:
        """Start xenoid-rootd as uid=0 with this instance's control token."""
        if which("docker") is None:
            return {"ok": False, "skipped": True, "error": "docker not found"}
        port = self.lease.rootd_port
        abi = self.docker_exec(["getprop", "ro.product.cpu.abi"])
        abi_s = str(abi.get("stdout", ""))
        arch = "arm64" if ("arm64" in abi_s or "aarch64" in abi_s) else "x86_64"
        root = self.context.project_root
        candidate = root / "native" / "xenoid-rootd" / f"xenoid-rootd-{arch}"
        if not candidate.exists():
            alternate = root / "native" / "xenoid-rootd" / "xenoid-rootd-x86_64"
            candidate = alternate if alternate.exists() else candidate
        if not candidate.exists():
            return {"ok": False, "skipped": True, "error": f"rootd binary not found for arch {arch}"}

        token = ""
        token_source = ""
        daemon_token_path = "/data/data/dev.xenoid.daemon/files/daemon.token"
        for _ in range(10):
            live = self.docker_exec(["cat", daemon_token_path])
            token = str(live.get("stdout", "")).strip() if live.get("ok") else ""
            if token:
                token_source = "daemon-private-file"
                break
            time.sleep(0.2)
        host_token = self.context.state_root / "daemon.token"
        if not token:
            try:
                token = host_token.read_text().strip() if host_token.exists() else ""
            except OSError:
                token = ""
            token_source = "host-cache" if token else ""
        if not token:
            token = secrets.token_hex(16)
            token_source = "generated"
        try:
            host_token.parent.mkdir(parents=True, exist_ok=True)
            host_token.write_text(token + "\n")
            host_token.chmod(0o600)
            rootd_cache = self.context.state_root / "rootd.token"
            rootd_cache.write_text(token + "\n")
            rootd_cache.chmod(0o600)
        except OSError as exc:
            return {"ok": False, "error": f"cannot persist rootd token: {exc}"}

        push = self.adb(["push", str(candidate), "/data/local/tmp/xenoid-rootd"])
        if not push.get("ok"):
            return {
                "ok": False,
                "error": "ADB rootd deployment failed",
                "stderr": push.get("stderr", ""),
            }
        prep = self.docker_exec([
            "sh", "-c",
            "chmod 755 /data/local/tmp/xenoid-rootd; "
            "ln -sf /data/local/tmp/xenoid-rootd /data/local/tmp/.netd-helper; "
            "rm -f /data/local/tmp/.xenoid-rootd.token; "
            "pkill -x .netd-helper 2>/dev/null; true",
        ], timeout=15)
        container, ownership_error = self._owned_container_record()
        if container is None:
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": ownership_error,
            }
        launch = run([
            *self.docker_base_cmd(), "exec", "-d", "-e", f"XENOID_ROOTD_TOKEN={token}",
            container["Id"], "sh", "-c",
            f"exec /data/local/tmp/.netd-helper {port} >/data/local/tmp/.netd-helper.log 2>&1",
        ], env=self.docker_env())
        time.sleep(1)
        hexport = format(port, "04X")
        listen = self.docker_exec(["sh", "-c", f"cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep -i ':{hexport}' || true"])
        uid = self.docker_exec(["sh", "-c", "for p in $(pidof .netd-helper 2>/dev/null); do grep '^Uid:' /proc/$p/status 2>/dev/null; done; true"])
        listening = hexport.lower() in str(listen.get("stdout", "")).lower()
        uid_s = str(uid.get("stdout", ""))
        runs_root = "Uid:\t0\t" in uid_s or "Uid: 0 " in uid_s
        ok = bool(prep.get("ok") and launch.returncode == 0 and listening and runs_root)
        return {
            "ok": ok,
            "arch": arch,
            "port": port,
            "listening": listening,
            "runsAsRoot": runs_root,
            "tokenProvisioned": True,
            "tokenSource": token_source,
            "prep": prep,
            "launchRc": launch.returncode,
            "listen": str(listen.get("stdout", "")).strip()[:120],
            "uid": uid_s.strip()[:80],
        }

    def daemon_client(self, timeout: float = 10.0) -> Any:
        from .daemon_client import DaemonClient

        return DaemonClient(
            context=self.context,
            lease=self.lease,
            docker_argv=self.docker_base_cmd(),
            timeout=timeout,
        )

    def repair_control_plane(self) -> dict[str, Any]:
        """Re-establish the adb lease, daemon, and rootd after a recreate.

        A freshly recreated container can lose the leased adb port switch or
        the docker-exec'd rootd in the first minute after boot; convergence
        callers use this bounded repair instead of failing on the transient.
        """
        result: dict[str, Any] = {}
        if self.lease.android_adb_port != 5555:
            result["adbPort"] = self.switch_adbd_port_via_docker()
        result["adbConnect"] = self.adb_connect()
        result["adbWait"] = self.adb_wait(timeout_sec=60)
        result["rootd"] = (
            self.ensure_rootd_root() if result["adbWait"].get("ok") else {"ok": False, "skipped": True}
        )
        result["daemon"] = (
            self.ensure_daemon(readiness_timeout=120.0)
            if result["rootd"].get("ok")
            else {"ok": False, "skipped": True}
        )
        result["ok"] = bool(
            result["adbWait"].get("ok")
            and result["rootd"].get("ok")
            and result["daemon"].get("ok")
        )
        return result

    def ensure_daemon(self, readiness_timeout: float = 30.0) -> dict[str, Any]:
        steps: dict[str, Any] = {}
        steps["forward"] = self.forward_daemon_port()
        try:
            client = self.daemon_client(timeout=2.0)
            health1 = client.health()
        except Exception as error:
            client = None
            health1 = {"ok": False, "error": str(error)}
        steps["healthBefore"] = health1
        if isinstance(health1, dict) and health1.get("ok"):
            return {"ok": True, "already": True, "steps": steps}

        steps["startActivity"] = self.launch_daemon_bootstrap()
        steps["forwardAfter"] = self.forward_daemon_port()
        deadline = time.monotonic() + max(0.0, readiness_timeout)
        health_attempts: list[dict[str, Any]] = []
        health_after: dict[str, Any] = {
            "ok": False,
            "error": "daemon health readiness timed out",
        }
        while True:
            try:
                if client is None:
                    client = self.daemon_client(timeout=2.0)
                health_after = client.health()
            except Exception as error:
                health_after = {"ok": False, "error": str(error)}
                client = None
            health_attempts.append(health_after)
            if health_after.get("ok"):
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.5, remaining))

        steps["healthAfter"] = health_after
        steps["healthAttempts"] = len(health_attempts)
        return {"ok": bool(health_after.get("ok")), "steps": steps}

    def install_daemon(self, apk_path: str) -> dict[str, Any]:
        p = Path(apk_path).expanduser().resolve()
        if not p.exists():
            return {"ok": False, "error": f"daemon apk not found: {p}"}
        preserved = self._capture_proxy_desired_for_update()
        if preserved.get("ok") is not True:
            return preserved
        install = self.adb(["install", "-r", str(p)])
        if not install.get("ok"):
            return install
        notification_grant = self.adb([
            "shell",
            'sdk="$(getprop ro.build.version.sdk)"; '
            'case "$sdk" in ""|*[!0-9]*) exit 1;; esac; '
            'if [ "$sdk" -ge 33 ]; then '
            'pm grant --user 0 dev.xenoid.daemon android.permission.POST_NOTIFICATIONS; '
            'fi',
        ])
        if notification_grant.get("ok"):
            return install
        failed = dict(install)
        failed["ok"] = False
        failed["error"] = "daemon notification permission grant failed"
        return failed

    def start_daemon_service(self) -> dict[str, Any]:
        # The service remains non-exported. Its exported launcher activity
        # enters the app UID and starts the service in explicit bootstrap mode.
        result = self.launch_daemon_bootstrap()
        result["method"] = "self-start-activity"
        return result


    def _instance_output_path(
        self,
        value: Optional[str],
        default_relative: str,
    ) -> Path:
        state_root = self.context.state_root.resolve()
        candidate = (
            state_root / default_relative
            if value is None
            else Path(value).expanduser()
        )
        if not candidate.is_absolute():
            candidate = state_root / candidate
        resolved = candidate.resolve()
        try:
            resolved.relative_to(state_root)
        except ValueError as exc:
            raise InstanceError(
                "resource_conflict",
                "mutable output path is outside instance state",
            ) from exc
        return resolved

    def fetch_frida(self, version: str = "latest", arch: str = "android-arm64", out_dir: Optional[str] = None) -> dict[str, Any]:
        out = self._instance_output_path(out_dir, "frida")
        out.mkdir(parents=True, exist_ok=True)
        requested = version
        if version == "latest":
            # Pin the server to the local frida CLI version: a minor mismatch
            # (e.g. server 17.2.x vs CLI 17.5.x) breaks app-process injection
            # with dlopen /proc/self/fd errors. Fall back to latest if the
            # CLI version cannot be determined or its tag has no matching asset.
            frida_bin = which("frida")
            if frida_bin:
                try:
                    v = subprocess.run([frida_bin, "--version"], text=True, capture_output=True, timeout=10)
                    cli_version = (v.stdout or v.stderr).strip().splitlines()[0].strip()
                    if re.fullmatch(r"\d+\.\d+\.\d+", cli_version):
                        requested = cli_version
                except Exception:
                    pass
        if requested != "latest":
            cached_asset = f"frida-server-{requested}-{arch}.xz"
            cached_xz = out / cached_asset
            if cached_xz.is_file():
                server_path = out / "frida-server"
                temporary_server = out / ".frida-server.tmp"
                try:
                    with lzma.open(cached_xz, "rb") as src, temporary_server.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
                    temporary_server.chmod(0o755)
                    temporary_server.replace(server_path)
                    return {
                        "ok": True,
                        "version": requested,
                        "requested": requested,
                        "asset": cached_asset,
                        "xz": str(cached_xz),
                        "path": str(server_path),
                        "cached": True,
                    }
                except (OSError, lzma.LZMAError):
                    temporary_server.unlink(missing_ok=True)
        api = "https://api.github.com/repos/frida/frida/releases/latest" if requested == "latest" else f"https://api.github.com/repos/frida/frida/releases/tags/{requested}"
        try:
            with urllib.request.urlopen(api, timeout=30) as resp:
                release = json.loads(resp.read().decode())
            assets = release.get("assets", [])
            selected = None
            for asset in assets:
                name = asset.get("name", "")
                if arch in name and name.endswith(".xz") and "frida-server" in name:
                    selected = asset
                    break
            if not selected:
                if requested != "latest":
                    return self.fetch_frida("latest", arch, out_dir)
                return {"ok": False, "error": f"no frida-server asset for {arch}", "release": release.get("tag_name"), "assetNames": [a.get("name") for a in assets]}
            xz_path = out / selected["name"]
            with urllib.request.urlopen(selected["browser_download_url"], timeout=120) as resp, xz_path.open("wb") as f:
                shutil.copyfileobj(resp, f)
            server_path = out / "frida-server"
            with lzma.open(xz_path, "rb") as src, server_path.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            server_path.chmod(0o755)
            return {"ok": True, "version": release.get("tag_name"), "requested": requested, "asset": selected.get("name"), "xz": str(xz_path), "path": str(server_path)}
        except Exception as e:
            return {"ok": False, "error": str(e), "api": api}

    def install_frida(
        self,
        version: str = "latest",
        arch: str = "android-arm64",
        out_dir: Optional[str] = None,
        remote_path: str = "/data/system/.core/svc.bin",
    ) -> dict[str, Any]:
        fetch = self.fetch_frida(version=version, arch=arch, out_dir=out_dir)
        result: dict[str, Any] = {
            "ok": False,
            "stage": "fetch",
            "fetch": fetch,
            "deploy": None,
            "remotePath": remote_path,
        }
        if not fetch.get("ok"):
            return result

        server_path = fetch.get("path")
        if not isinstance(server_path, str) or not server_path:
            result["fetch"] = {
                **fetch,
                "ok": False,
                "error": "frida-server download returned no install path",
            }
            return result

        deploy = self.deploy_frida(server_path, remote_path)
        result["deploy"] = deploy
        result["path"] = server_path
        result["ok"] = bool(deploy.get("ok"))
        result["stage"] = "complete" if result["ok"] else "deploy"
        return result

    def base_image_for_build(self) -> str:
        """Return the configured 64-bit Android 13 base image."""
        return self.cfg.image

    def make_runtime_context(
        self,
        image: Optional[str] = None,
        *,
        output: Optional[Path] = None,
        spec: Optional[ReleaseSpec] = None,
    ) -> dict[str, Any]:
        script = self.context.project_root / "scripts" / "make-runtime-context.sh"
        selected_spec = (
            self.google_runtime_spec("runtime-context", require_assets=True)
            if spec is None
            else spec
        )
        destination = output or (
            self.context.state_root
            / "runtime-context"
            / f"{self.lease.transaction_id}-{secrets.token_hex(8)}"
        )
        env = self.docker_env()
        env["XENOID_EXPECT_BUILD_PRODUCT"] = (
            str(selected_spec.android["targetProduct"])
            if selected_spec is not None
            else "raven"
        )

        def generate() -> tuple[Any, Optional[dict[str, Any]]]:
            proc = run(
                [
                    str(script),
                    image or self.base_image_for_build(),
                    str(destination),
                ],
                env=env,
            )
            verification: Optional[dict[str, Any]] = None
            if proc.returncode == 0 and selected_spec is not None:
                verification = verify_context_copy(destination, selected_spec, stage)
            return proc, verification

        if selected_spec is None:
            proc, verification = generate()
        else:
            with staged_google_payload(self.context, selected_spec) as stage:
                env.update(
                    {
                        "XENOID_GOOGLE_PAYLOAD": str(stage.tree),
                        "XENOID_GOOGLE_PROVIDER": selected_spec.provider,
                        "XENOID_GOOGLE_RELEASE": selected_spec.release,
                        "XENOID_GOOGLE_SPEC_SHA256": selected_spec.fingerprint,
                        "XENOID_GOOGLE_DATA_COMPAT_SHA256": selected_spec.data_compatibility_fingerprint,
                    }
                )
                proc, verification = generate()
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "context": (
                proc.stdout.strip().splitlines()[-1]
                if proc.stdout.strip()
                else None
            ),
            "googleServices": (
                selected_spec.public_dict()
                if selected_spec is not None
                else {"provider": PROVIDER_NONE, "release": PROVIDER_NONE}
            ),
            "verification": verification,
        }

    def _verify_effective_image(
        self,
        spec: Optional[ReleaseSpec],
    ) -> dict[str, Any]:
        image, inspect = self._inspect_docker_object("image", self.effective_image())
        if image is None:
            return {
                "ok": False,
                "error": "google_services_runtime_not_ready",
                "message": "effective runtime image does not exist",
                "returncode": inspect.returncode,
            }
        if not image:
            return {
                "ok": False,
                "error": "google_services_spec_mismatch",
                "message": "effective runtime image identity is invalid",
            }
        config = image.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        labels = labels if isinstance(labels, dict) else {}
        expected = spec.labels if spec is not None else {}
        labels_match = (
            all(labels.get(key) == value for key, value in expected.items())
            and (
                spec is not None
                or not any(key in labels for key in self._google_label_values())
            )
        )
        architecture = str(image.get("Architecture") or "")
        image_id = str(image.get("Id") or "")
        ok = (
            bool(image_id)
            and architecture in {"arm64", "aarch64"}
            and labels_match
        )
        return {
            "ok": ok,
            "image": self.effective_image(),
            "imageSha256": image_id,
            "architecture": architecture,
            "labelsMatch": labels_match,
            **(
                {}
                if ok
                else {
                    "error": "google_services_spec_mismatch",
                    "message": "effective runtime image does not match the Google services specification",
                }
            ),
        }

    def _build_effective_runtime_image(
        self,
        spec: Optional[ReleaseSpec],
    ) -> dict[str, Any]:
        handle = create_runtime_context_handle()
        result: dict[str, Any] = {"ok": False}
        try:
            context = self.make_runtime_context(
                self.base_image_for_build(),
                output=handle.output,
                spec=spec,
            )
            result["runtimeContext"] = context
            if not context.get("ok") or context.get("context") != str(handle.output):
                result.update(
                    {
                        "error": "google_services_asset_invalid",
                        "message": "runtime context generation failed",
                    }
                )
                return result
            build = run(
                [
                    *self.docker_base_cmd(),
                    "build",
                    "-t",
                    self.effective_image(),
                    str(handle.output),
                ],
                env=self.docker_env(),
            )
            result["build"] = {
                "ok": build.returncode == 0,
                "returncode": build.returncode,
                "stdout": build.stdout[-4000:],
                "stderr": build.stderr[-4000:],
            }
            if build.returncode != 0:
                result.update(
                    {
                        "error": "runtime_image_build_failed",
                        "message": "runtime image build failed",
                    }
                )
                return result
            verified = self._verify_effective_image(spec)
            result["image"] = verified
            result["ok"] = verified.get("ok") is True
            if not result["ok"]:
                result["error"] = verified.get(
                    "error",
                    "google_services_spec_mismatch",
                )
            return result
        finally:
            try:
                result["cleanup"] = cleanup_runtime_context(handle)
            except GoogleServicesError as exc:
                result["ok"] = False
                result["error"] = exc.code
                result["message"] = str(exc)


    def ensure_rootfs_images(self) -> dict[str, Any]:
        """Converge rootfs while preserving the committed instance data image."""
        return self.ensure_instance_storage()

    def make_ota_bundle(self, version: str = "0.1.0") -> dict[str, Any]:
        script = self.context.project_root / "scripts" / "make-ota-bundle.sh"
        output_root = self.context.state_root / "ota" / "bundles"
        env = self.docker_env()
        env["XENOID_STATE_ROOT"] = str(self.context.state_root)
        env["XENOID_OTA_OUTPUT_DIR"] = str(output_root)
        proc = run([str(script), version], env=env)
        bundle: Optional[str] = None
        error: Optional[str] = None
        if proc.returncode == 0 and proc.stdout.strip():
            source = Path(proc.stdout.strip().splitlines()[-1]).expanduser().resolve()
            try:
                if not source.is_file():
                    raise OSError("OTA builder returned no bundle")
                output_root.mkdir(parents=True, exist_ok=True)
                destination = output_root / source.name
                temporary = output_root / f".{source.name}.{secrets.token_hex(8)}.tmp"
                shutil.copy2(source, temporary)
                temporary.replace(destination)
                bundle = str(destination)
            except OSError:
                error = "failed to persist instance OTA bundle"
        ok = proc.returncode == 0 and bundle is not None
        return {
            "ok": ok,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "bundle": bundle,
            **({} if error is None else {"error": error}),
        }

    def apply_ota_bundle(self, bundle_path: str) -> dict[str, Any]:
        bundle = Path(bundle_path).expanduser().resolve()
        if not bundle.exists():
            return {"ok": False, "error": f"OTA bundle not found: {bundle}"}
        work = (self.context.state_root / "ota" / "staged").resolve()
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(bundle, "r:gz") as tf:
                import os
                for member in tf.getmembers():
                    target = (work / member.name).resolve()
                    if os.path.commonpath([str(work), str(target)]) != str(work):
                        return {"ok": False, "error": f"unsafe tar member: {member.name}"}
                tf.extractall(work)
            roots = [p for p in work.iterdir() if p.is_dir()]
            if not roots:
                return {"ok": False, "error": "bundle has no root directory"}
            root = roots[0]
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            payloads = manifest.get("payloads", {})
            results: dict[str, Any] = {"ok": True, "bundle": str(bundle), "manifest": manifest, "steps": {}}
            daemon_info = payloads.get("daemonApk")
            if daemon_info:
                apk = root / daemon_info["path"]
                results["steps"]["daemonInstall"] = self.install_daemon(str(apk))
                results["steps"]["daemonStart"] = self.start_daemon_service()
                results["steps"]["daemonForward"] = self.forward_daemon_port()
            helper_info = payloads.get("inputHelper")
            if helper_info:
                helper = root / helper_info["path"]
                results["steps"]["inputDeploy"] = self.deploy_input_helper(str(helper), helper_info.get("remotePath", "/data/local/tmp/xenoid-input"))
            hide_info = payloads.get("hideHelper")
            if hide_info:
                helper = root / hide_info["path"]
                results["steps"]["hideDeploy"] = self.deploy_hide_helper(str(helper), hide_info.get("remotePath", "/data/local/tmp/xenoid-hide-helper"))
            profile_info = payloads.get("profileHelper")
            if profile_info:
                helper = root / profile_info["path"]
                results["steps"]["profileDeploy"] = self.deploy_profile_helper(str(helper), profile_info.get("remotePath", "/data/local/tmp/xenoid-profile-helper"))
            netctl_info = payloads.get("netctlHelper")
            if netctl_info:
                helper = root / netctl_info["path"]
                results["steps"]["netctlDeploy"] = self.deploy_netctl_helper(str(helper), netctl_info.get("remotePath", "/data/local/tmp/xenoid-netctl"))
            frida_scripts = payloads.get("fridaScripts")
            if frida_scripts:
                scripts = root / frida_scripts["path"]
                results["steps"]["fridaScriptsDeploy"] = self.deploy_frida_scripts(str(scripts), frida_scripts.get("remotePath", "/data/local/tmp/xenoid-frida"))
            results["ok"] = all(not isinstance(v, dict) or v.get("ok", True) for v in results["steps"].values())
            return results
        except Exception as e:
            return {"ok": False, "error": str(e), "bundle": str(bundle)}

    def deploy_frida(self, frida_server_path: str, remote_path: str = "/data/system/.core/svc.bin") -> dict[str, Any]:
        p = Path(frida_server_path).expanduser().resolve()
        if not p.exists():
            return {"ok": False, "error": f"frida-server not found: {p}"}
        staging = "/data/local/tmp/.svc.staging"
        push = self.adb(["push", str(p), staging])
        remote_q = shlex.quote(remote_path)
        remote_dir_q = shlex.quote(str(Path(remote_path).parent))
        move_cmd = f"mkdir -p {remote_dir_q} && chmod 700 {remote_dir_q} && mv -f {shlex.quote(staging)} {remote_q} && chmod 700 {remote_q}"
        move = self.docker_exec(["sh", "-c", move_cmd]) if push.get("ok") else {"ok": False, "skipped": True}
        cleanup = self.adb(["shell", "rm", "-f", staging]) if push.get("ok") else {"ok": False, "skipped": True}
        return {"ok": bool(push.get("ok") and move.get("ok")), "push": push, "move": move, "cleanup": cleanup, "remotePath": remote_path}

    def deploy_input_helper(self, helper_path: str, remote_path: str = "/data/local/tmp/xenoid-input") -> dict[str, Any]:
        p = Path(helper_path).expanduser().resolve()
        if not p.exists():
            return {"ok": False, "error": f"xenoid-input helper not found: {p}"}
        push = self.adb(["push", str(p), remote_path])
        chmod = self.adb(["shell", "chmod", "755", remote_path]) if push.get("ok") else {"ok": False, "skipped": True}
        return {"ok": bool(push.get("ok") and chmod.get("ok")), "push": push, "chmod": chmod, "remotePath": remote_path}

    def deploy_hide_helper(self, helper_path: str, remote_path: str = "/data/local/tmp/xenoid-hide-helper") -> dict[str, Any]:
        p = Path(helper_path).expanduser().resolve()
        if not p.exists():
            return {"ok": False, "error": f"xenoid-hide helper not found: {p}"}
        push = self.adb(["push", str(p), remote_path])
        chmod = self.adb(["shell", "chmod", "755", remote_path]) if push.get("ok") else {"ok": False, "skipped": True}
        return {"ok": bool(push.get("ok") and chmod.get("ok")), "push": push, "chmod": chmod, "remotePath": remote_path}

    def deploy_netctl_helper(self, helper_path: str, remote_path: str = "/data/local/tmp/xenoid-netctl") -> dict[str, Any]:
        p = Path(helper_path).expanduser().resolve()
        if not p.exists():
            return {"ok": False, "error": f"xenoid-netctl helper not found: {p}"}
        push = self.adb(["push", str(p), remote_path])
        chmod = self.adb(["shell", "chmod", "755", remote_path]) if push.get("ok") else {"ok": False, "skipped": True}
        return {"ok": bool(push.get("ok") and chmod.get("ok")), "push": push, "chmod": chmod, "remotePath": remote_path}

    def netctl_status(self, ifname: str = "rmnet_data0") -> dict[str, Any]:
        safe_ifname = "".join(c for c in ifname if c.isalnum() or c in "_.:-") or "rmnet_data0"
        cmd = "test -x /data/local/tmp/xenoid-netctl && /data/local/tmp/xenoid-netctl status " + safe_ifname + " || echo '{\"ok\":false,\"error\":\"netctl-helper-missing\"}'"
        r = self.adb(["shell", cmd])
        out: dict[str, Any] = {"ok": bool(r.get("ok")), "adb": r}
        try:
            out["status"] = json.loads(str(r.get("stdout") or "{}"))
            out["ok"] = bool(out["status"].get("ok"))
        except Exception as e:
            out["ok"] = False; out["error"] = str(e)
        return out

    def netctl_set_mac(self, mac: str, ifname: str = "rmnet_data0") -> dict[str, Any]:
        safe_ifname = "".join(c for c in ifname if c.isalnum() or c in "_.:-") or "rmnet_data0"
        safe_mac = "".join(c for c in mac.lower() if c in "0123456789abcdef:")
        cmd = "test -x /data/local/tmp/xenoid-netctl && /data/local/tmp/xenoid-netctl set-mac " + safe_ifname + " " + safe_mac + " || echo '{\"ok\":false,\"error\":\"netctl-helper-missing\"}'"
        r = self.adb(["shell", cmd])
        out: dict[str, Any] = {"ok": bool(r.get("ok")), "adb": r}
        try:
            out["result"] = json.loads(str(r.get("stdout") or "{}"))
            out["ok"] = bool(out["result"].get("ok"))
        except Exception as e:
            out["ok"] = False; out["error"] = str(e)
        return out




    def overlay_status(self) -> dict[str, Any]:
        r = self.adb(["shell", "test -x /data/local/tmp/xenoid-overlay-helper && /data/local/tmp/xenoid-overlay-helper status-json || echo '{\"ok\":false,\"error\":\"overlay-helper-missing\"}'"])
        out = {"ok": bool(r.get("ok")), "adb": r}
        try:
            out["status"] = json.loads(str(r.get("stdout") or "{}"))
            out["ok"] = bool(out["status"].get("ok"))
        except Exception as e:
            out["ok"] = False; out["error"] = str(e)
        return out

    def overlay_cleanup(self) -> dict[str, Any]:
        cmd = "test -x /data/local/tmp/xenoid-overlay-helper && (nohup /data/local/tmp/xenoid-overlay-helper cleanup >/data/local/tmp/xenoid-overlay-cleanup.log 2>&1 & echo '{\"ok\":true,\"started\":true,\"log\":\"/data/local/tmp/xenoid-overlay-cleanup.log\"}') || echo '{\"ok\":false,\"error\":\"overlay-helper-missing\"}'"
        r = self.adb(["shell", cmd])
        out = {"ok": bool(r.get("ok")), "adb": r}
        try:
            out["result"] = json.loads(str(r.get("stdout") or "{}"))
            out["ok"] = bool(out["result"].get("ok"))
        except Exception as e:
            out["ok"] = False; out["error"] = str(e)
        return out

    def deploy_frida_scripts(self, scripts_dir: str = "frida/scripts", remote_dir: str = "/data/local/tmp/xenoid-frida") -> dict[str, Any]:
        src = Path(scripts_dir).expanduser().resolve()
        if not src.exists():
            return {"ok": False, "error": f"frida scripts dir not found: {src}"}
        # Image COPY leaves scripts root:root 644; adb push as shell cannot overwrite.
        # Prepare via rootd (preferred) or docker exec so push can replace files.
        prep_cmd = (
            f"mkdir -p {remote_dir} && chmod 777 {remote_dir} && "
            f"rm -f {remote_dir}/*.js && chown shell:shell {remote_dir} 2>/dev/null || true"
        )
        prep = self.docker_exec(["sh", "-c", prep_cmd])
        mkdir = self.adb(["shell", "mkdir", "-p", remote_dir])
        results = []
        for script in sorted(src.glob("*.js")):
            results.append({"script": str(script), "push": self.adb(["push", str(script), f"{remote_dir}/{script.name}"])})
        ok = bool(prep.get("ok")) and mkdir.get("ok") and all(r["push"].get("ok") for r in results)
        return {"ok": bool(ok), "remoteDir": remote_dir, "prep": prep, "mkdir": mkdir, "scripts": results}

    def load_frida_script(self, package: str, script_path: str, spawn: bool = False, oneshot: bool = False) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9_.]+", package or ""):
            return {"ok": False, "error": f"invalid package name: {package!r}"}
        owned, error = self._owned_container()
        if not owned:
            return {"ok": False, "error": "resource_conflict", "message": error}
        frida_bin = which("frida")
        if frida_bin is None:
            return {"ok": False, "error": "frida CLI not found; install frida-tools", "fix": "python3 -m pip install frida-tools"}
        script = Path(script_path).expanduser().resolve()
        if not script.exists():
            return {"ok": False, "error": f"script not found: {script}"}
        # -t 30: frida-tools quiet mode exits immediately after _ready when the
        # timeout is 0 (repl.py waits only when _quiet_timeout > 0); scripts with
        # delayed callbacks (self-tests, scan capture) need the linger window.
        cmd = [frida_bin, "-D", self.adb_target, "-q", "-t", "30", "--exit-on-error"]
        if spawn:
            # frida-tools 17 removed --no-pause; --spawn already keeps the
            # process paused until the script is loaded, no extra flag needed.
            cmd += ["-f", package]
        else:
            # Attach by PID: frida -n matches the app *label*, not the process
            # name, so name attach can miss. Resolve via pidof first; fall back
            # to exact ps NAME match (pkg or pkg:subproc) with strict input
            # validation — never substring-grep unsanitized input.
            pid_out = self.adb(["shell", f"pidof {package}"])
            pid = str(pid_out.get("stdout", "")).strip().split()
            if not (pid and pid[0].isdigit()) and re.fullmatch(r"[A-Za-z0-9_.]+", package):
                ps_out = self.adb(["shell", f"ps -A -o PID,NAME | awk '$2 == \"{package}\" || index($2, \"{package}:\") == 1 {{print $1; exit}}'"])
                pid = str(ps_out.get("stdout", "")).strip().split()
            if pid and pid[0].isdigit():
                cmd += ["-p", pid[0]]
            else:
                cmd += ["-n", package]
        cmd += ["-l", str(script)]
        if not oneshot:
            # Production default: keep the script resident after the CLI exits.
            # Without this the REPL unload on exit removes every hook.
            cmd += ["--eternalize"]
        try:
            # stdin=DEVNULL: frida REPL exits on EOF after script load (one-shot,
            # deterministic under TTY and non-TTY alike). Timeout must exceed -t.
            proc = run(cmd, timeout=45, stdin=subprocess.DEVNULL)
        except Exception as e:
            return {"ok": False, "error": str(e), "command": cmd}
        result = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "command": cmd, "eternalized": not oneshot}
        # Hook-hit evidence: the script's self-test invokes the hooked File.exists
        # and SystemProperties.get and logs whether the JS replacements fired.
        st = [line for line in (proc.stdout or "").splitlines() if "[xenoid-selftest]" in line]
        result["selfTest"] = st[-1].strip() if st else None
        result["hooksProven"] = any("fileHit=true" in line and "propHit=true" in line for line in st)
        return result

    def generate_profile_frida(self, profile_path: str, out: Optional[str] = None, keep_unique: bool = False) -> dict[str, Any]:
        script = self.context.project_root / "scripts" / "generate-profile-frida.py"
        output = self._instance_output_path(out, "frida/generated-profile.js")
        output.parent.mkdir(parents=True, exist_ok=True)
        cmd = [str(script), profile_path, "--out", str(output)]
        if keep_unique:
            cmd.append("--keep-unique")
        proc = run(cmd)
        data: dict[str, Any] = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip(), "command": cmd}
        try:
            data.update(json.loads(proc.stdout))
        except Exception:
            pass
        return data

    def automation_plan(self, script_path: str) -> dict[str, Any]:
        script = self.context.project_root / "scripts" / "automation-plan.py"
        proc = run([str(script), script_path])
        data: dict[str, Any] = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip()}
        try:
            data.update(json.loads(proc.stdout))
        except Exception:
            pass
        return data

    def automation_run_host(self, script_path: str, execute: bool = False, endpoint: Optional[str] = None) -> dict[str, Any]:
        node = which("node")
        runner = self.context.project_root / "scripts" / "xenoid-js-runner.mjs"
        if node is None:
            plan = self.automation_plan(script_path)
            plan["node"] = False
            plan["note"] = "node not found; returned static automation plan"
            return plan
        expected_endpoint = f"http://127.0.0.1:{self.lease.host_daemon_port}"
        if endpoint is not None and endpoint != expected_endpoint:
            return {
                "ok": False,
                "error": "resource_conflict",
                "message": "automation endpoint does not match instance daemon",
            }
        cmd = [node, str(runner), str(Path(script_path).resolve()), f"--endpoint={expected_endpoint}"]
        if execute:
            cmd.append("--execute")
        proc = run(cmd)
        data = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip(), "command": cmd, "node": node}
        try:
            data.update(json.loads(proc.stdout))
        except Exception:
            pass
        return data

    def deploy_profile_helper(self, helper_path: str, remote_path: str = "/data/local/tmp/xenoid-profile-helper") -> dict[str, Any]:
        p = Path(helper_path).expanduser().resolve()
        if not p.exists():
            return {"ok": False, "error": f"xenoid-profile helper not found: {p}"}
        push = self.adb(["push", str(p), remote_path])
        chmod = self.adb(["shell", "chmod", "755", remote_path]) if push.get("ok") else {"ok": False, "skipped": True}
        return {"ok": bool(push.get("ok") and chmod.get("ok")), "push": push, "chmod": chmod, "remotePath": remote_path}

    def generate_service_frida(self, profile_path: str, out: Optional[str] = None, keep_unique: bool = False) -> dict[str, Any]:
        script = self.context.project_root / "scripts" / "generate-service-frida.py"
        output = self._instance_output_path(out, "frida/generated-service-profile.js")
        output.parent.mkdir(parents=True, exist_ok=True)
        cmd = [str(script), profile_path, "--out", str(output)]
        if keep_unique:
            cmd.append("--keep-unique")
        proc = run(cmd)
        data: dict[str, Any] = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip(), "command": cmd}
        try:
            data.update(json.loads(proc.stdout))
        except Exception:
            pass
        return data


    def runtime_logs(self, out_dir: Optional[str] = None) -> dict[str, Any]:
        out = self._instance_output_path(out_dir, "logs")
        out.mkdir(parents=True, exist_ok=True)
        result: dict[str, Any] = {"ok": True, "outDir": str(out), "files": {}}
        if which("docker") is not None:
            container, error = self._owned_container_record()
            if container is None:
                return {"ok": False, "error": "resource_conflict", "message": error}
            logs = run(
                [*self.docker_base_cmd(), "logs", container["Id"]],
                env=self.docker_env(),
            )
            p = out / "docker.log"; p.write_text((logs.stdout or "") + (logs.stderr or "")); result["files"]["docker"] = str(p)
            inspect = run(
                [*self.docker_base_cmd(), "inspect", container["Id"]],
                env=self.docker_env(),
            )
            p = out / "docker-inspect.json"; p.write_text(inspect.stdout or inspect.stderr or ""); result["files"]["dockerInspect"] = str(p)
        else:
            result["docker"] = "not found"
        if which("adb") is not None:
            props = self.adb(["shell", "getprop"]); p = out / "getprop.txt"; p.write_text(props.get("stdout", "") + props.get("stderr", "")); result["files"]["getprop"] = str(p)
            logcat = self.adb(["logcat", "-d", "-t", "1000"]); p = out / "logcat.txt"; p.write_text(logcat.get("stdout", "") + logcat.get("stderr", "")); result["files"]["logcat"] = str(p)
        else:
            result["adb"] = "not found"
        return result

    def view(self) -> dict[str, Any]:
        scrcpy = which("scrcpy")
        if scrcpy is None:
            return {"ok": False, "error": "scrcpy not found", "fix": "brew install scrcpy"}
        owned, error = self._owned_container()
        if not owned:
            return {"ok": False, "error": "resource_conflict", "message": error}
        # redroid images commonly lack an Opus encoder; scrcpy 4.x enables audio by default.
        # Disable audio for the default Xenoid view path to avoid server startup failure.
        proc = run([scrcpy, "-s", self.adb_target, "--no-audio", "--video-codec=h264", "--max-size=1024"], capture=True)
        return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}

    @staticmethod
    def _proxy_failure(code: str) -> dict[str, Any]:
        if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code or "") is None:
            code = "engine_unavailable"
        return {"ok": False, "code": code, "error": code}

    @staticmethod
    def _proxy_json_document(text: str) -> Any:
        def exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = value
            return result

        return json.loads(text, object_pairs_hook=exact_object)

    @property
    def _proxy_manifest_path(self) -> str:
        return f"{self._proxy_runtime_path}/manifest.json"

    @property
    def _proxy_state_path(self) -> str:
        return f"/var/lib/xenoid/proxy/instances/{self.context.instance_id}"

    @property
    def _proxy_runtime_path(self) -> str:
        return f"/run/xenoid/proxy/{self.context.resource_tag}"

    @property
    def _proxy_installed_helper(self) -> str:
        return "/usr/libexec/xenoid-proxy-engine.py"


    def _proxy_transport_prefix(self) -> list[str]:
        endpoint = self.docker_endpoint_host()
        if (self.cfg.docker_context or "").strip() and not endpoint:
            raise InstanceError("resource_conflict", "Docker engine host transport is unavailable")
        if endpoint.startswith("tcp://"):
            raise InstanceError("resource_conflict", "proxy engine access requires a local or SSH Docker host")
        if endpoint.startswith("ssh://"):
            from urllib.parse import urlparse

            parsed = urlparse(endpoint)
            if (
                parsed.scheme != "ssh"
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
                or not parsed.hostname
                or re.fullmatch(r"[A-Za-z0-9_.:-]+", parsed.hostname) is None
                or (
                    parsed.username is not None
                    and re.fullmatch(r"[A-Za-z0-9_.-]+", parsed.username) is None
                )
            ):
                raise InstanceError("resource_conflict", "SSH Docker engine identity is invalid")
            ssh = which("ssh")
            if ssh is None:
                raise InstanceError("engine_unavailable", "SSH transport is unavailable")
            host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
            target = f"{parsed.username}@{host}" if parsed.username else host
            prefix = [ssh, "-T", "-o", "BatchMode=yes"]
            if parsed.port is not None:
                prefix.extend(["-p", str(parsed.port)])
            return [*prefix, target, "sudo", "-n", "--"]
        if self.should_use_colima():
            colima = which("colima")
            if colima is None:
                raise InstanceError("engine_unavailable", "Colima host transport is unavailable")
            return [colima, "ssh", "--", "sudo", "-n", "--"]
        if endpoint and not endpoint.startswith("unix://"):
            raise InstanceError("resource_conflict", "proxy engine access requires a local or SSH Docker host")
        if host_info().get("system") != "Linux":
            raise InstanceError("resource_conflict", "native proxy engine access requires Linux")
        sudo = which("sudo")
        if sudo is None:
            raise InstanceError("engine_unavailable", "root proxy engine transport is unavailable")
        return [sudo, "-n", "--"]

    def _proxy_process(
        self,
        argv: list[str],
        *,
        payload: Optional[bytes | bytearray] = None,
        stdin_file: Any = None,
        timeout: int = 120,
        output_limit: int = 8192,
    ) -> tuple[int, bytes]:
        if payload is not None and stdin_file is not None:
            raise InstanceError("internal_contract_error", "proxy transport received conflicting input")
        if (
            not argv
            or timeout <= 0
            or output_limit <= 0
            or any(
                not isinstance(argument, str)
                or not argument
                or any(character in argument for character in ("\0", "\n", "\r"))
                for argument in argv
            )
        ):
            raise InstanceError("internal_contract_error", "proxy transport command is invalid")
        proc: Optional[subprocess.Popen[bytes]] = None
        selector = selectors.DefaultSelector()
        stdout = bytearray()
        stderr_size = 0
        input_view = memoryview(payload) if payload is not None else None
        input_offset = 0
        deadline = time.monotonic() + timeout
        try:
            proc = subprocess.Popen(
                argv,
                stdin=(
                    subprocess.PIPE
                    if input_view is not None
                    else stdin_file if stdin_file is not None else subprocess.DEVNULL
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            if proc.stdout is None or proc.stderr is None:
                raise OSError("proxy transport pipes unavailable")
            os.set_blocking(proc.stdout.fileno(), False)
            os.set_blocking(proc.stderr.fileno(), False)
            selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
            selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
            if input_view is not None:
                if proc.stdin is None:
                    raise OSError("proxy transport input unavailable")
                if len(input_view):
                    os.set_blocking(proc.stdin.fileno(), False)
                    selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
                else:
                    proc.stdin.close()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                events = selector.select(remaining)
                if not events:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key, _ in events:
                    stream = key.fileobj
                    if key.data == "stdin":
                        try:
                            written = os.write(
                                stream.fileno(),
                                input_view[input_offset : input_offset + 65536],
                            )
                        except BrokenPipeError:
                            written = 0
                            input_offset = len(input_view)
                        else:
                            input_offset += written
                        if input_offset == len(input_view):
                            selector.unregister(stream)
                            stream.close()
                        continue
                    try:
                        chunk = os.read(stream.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    if key.data == "stdout":
                        if len(stdout) + len(chunk) > output_limit:
                            raise InstanceError("engine_response_invalid", "proxy engine response exceeded its bound")
                        stdout.extend(chunk)
                    else:
                        stderr_size += len(chunk)
                        if stderr_size > output_limit:
                            raise InstanceError("engine_response_invalid", "proxy engine response exceeded its bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            returncode = proc.wait(timeout=remaining)
        except InstanceError:
            raise
        except (OSError, subprocess.SubprocessError) as exc:
            raise InstanceError("engine_unavailable", "proxy engine transport failed") from exc
        finally:
            selector.close()
            if proc is not None:
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait()
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
            if input_view is not None:
                input_view.release()
        return returncode, bytes(stdout)

    def _proxy_root_process(
        self,
        arguments: list[str],
        *,
        payload: Optional[bytes | bytearray] = None,
        stdin_file: Any = None,
        timeout: int = 120,
        output_limit: int = 8192,
    ) -> tuple[int, bytes]:
        return self._proxy_process(
            [*self._proxy_transport_prefix(), *arguments],
            payload=payload,
            stdin_file=stdin_file,
            timeout=timeout,
            output_limit=output_limit,
        )

    def _proxy_root_json(
        self,
        action: str,
        *,
        helper: Optional[str] = None,
        timeout: int = 120,
    ) -> dict[str, Any]:
        returncode, output = self._proxy_root_process(
            [helper or self._proxy_installed_helper, action, "--manifest", self._proxy_manifest_path],
            timeout=timeout,
            output_limit=65536 if action == "status" else 8192,
        )
        try:
            text = output.decode("ascii", "strict")
            body = text[:-1]
            if (
                not text.endswith("\n")
                or text.count("\n") != 1
                or not body
                or body.strip() != body
                or "\r" in body
            ):
                raise ValueError
            response = self._proxy_json_document(body)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return self._proxy_failure("engine_response_invalid")
        if not isinstance(response, dict):
            return self._proxy_failure("engine_response_invalid")
        if returncode != 0:
            if (
                set(response) == {"ok", "error"}
                and response.get("ok") is False
                and isinstance(response.get("error"), str)
            ):
                return self._proxy_failure(response["error"])
            return self._proxy_failure("engine_unavailable")
        if response == {"ok": True}:
            return response
        if (
            action == "check-control"
            and set(response) == {"ok", "controlDigest"}
            and response.get("ok") is True
            and isinstance(response.get("controlDigest"), str)
            and re.fullmatch(r"[0-9a-f]{64}", response["controlDigest"]) is not None
        ):
            return response
        if action in {"quarantine", "cleanup"} and response == {"notPrepared": True, "ok": True}:
            return response
        if action == "status" and self._proxy_valid_status(response):
            return response
        return self._proxy_failure("engine_response_invalid")

    @staticmethod
    def _proxy_valid_status(response: dict[str, Any]) -> bool:
        capabilities = response.get("capabilities")
        counters = response.get("counters")
        counter_keys = {
            "ingress", "proxyUplink", "egress",
            "ingressBytes", "proxyUplinkBytes", "egressBytes",
        }
        counter_keys.update(
            f"v{family}{capability}{stage}"
            for family in ("4", "6")
            for capability in ("Dns", "Tcp", "Udp")
            for stage in ("Ingress", "Uplink", "Egress")
        )
        return (
            set(response)
            == {
                "ok", "instanceId", "resourceTag", "runtimeEpoch", "generation",
                "manifestDigest", "phase", "structuralApplied", "dataPlaneVerified",
                "capabilities", "counters", "selectedNode", "nodeCount",
            }
            and response.get("ok") is True
            and all(isinstance(response.get(name), str) for name in ("instanceId", "resourceTag", "runtimeEpoch"))
            and isinstance(response.get("generation"), int)
            and not isinstance(response.get("generation"), bool)
            and response["generation"] >= 0
            and isinstance(response.get("manifestDigest"), str)
            and re.fullmatch(r"[0-9a-f]{64}", response["manifestDigest"]) is not None
            and response.get("phase")
            in {"quarantined", "applying", "ready", "active", "error", "disabled", "off", "stopped"}
            and isinstance(response.get("structuralApplied"), bool)
            and isinstance(response.get("dataPlaneVerified"), bool)
            and isinstance(capabilities, dict)
            and set(capabilities)
            == {"v4DnsProxy", "v4TcpProxy", "v4UdpProxy", "v6DnsProxy", "v6TcpProxy", "v6UdpProxy"}
            and all(isinstance(value, bool) for value in capabilities.values())
            and isinstance(counters, dict)
            and set(counters) == counter_keys
            and all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in counters.values())
            and isinstance(response.get("selectedNode"), str)
            and all(
                not 0xD800 <= ord(character) <= 0xDFFF
                for character in response["selectedNode"]
            )
            and len(response["selectedNode"].encode("utf-8")) <= 128
            and isinstance(response.get("nodeCount"), int)
            and not isinstance(response.get("nodeCount"), bool)
            and 0 <= response["nodeCount"] <= 512
        )

    def _proxy_root_simple(
        self,
        arguments: list[str],
        *,
        payload: Optional[bytes | bytearray] = None,
        stdin_file: Any = None,
        timeout: int = 120,
    ) -> bool:
        returncode, output = self._proxy_root_process(
            arguments,
            payload=payload,
            stdin_file=stdin_file,
            timeout=timeout,
        )
        return returncode == 0 and output in {b"", b"\n"}

    def _proxy_remote_exists(self, path: str) -> bool:
        returncode, output = self._proxy_root_process(["test", "-e", path], timeout=15)
        if output not in {b"", b"\n"}:
            raise InstanceError("engine_response_invalid", "proxy host probe response is invalid")
        if returncode == 0:
            return True
        if returncode == 1:
            return False
        raise InstanceError("engine_unavailable", "proxy host probe failed")

    def _proxy_remote_directory_valid(self, path: str, mode: int) -> bool:
        link_returncode, link_output = self._proxy_root_process(
            ["test", "-L", path],
            timeout=15,
        )
        if link_output not in {b"", b"\n"} or link_returncode not in {0, 1}:
            raise InstanceError("engine_unavailable", "proxy host directory probe failed")
        if link_returncode == 0:
            return False
        directory_returncode, directory_output = self._proxy_root_process(
            ["test", "-d", path],
            timeout=15,
        )
        if directory_output not in {b"", b"\n"} or directory_returncode != 0:
            return False
        returncode, output = self._proxy_root_process(
            ["stat", "-c", "%u:%g:%a", path],
            timeout=15,
            output_limit=128,
        )
        if returncode != 0:
            return False
        try:
            metadata = output.decode("ascii", "strict").strip()
        except UnicodeDecodeError:
            return False
        return metadata == f"0:0:{mode:o}"

    def _proxy_remote_regular_valid(self, path: str, mode: int) -> bool:
        link_returncode, link_output = self._proxy_root_process(
            ["test", "-L", path],
            timeout=15,
        )
        if link_output not in {b"", b"\n"} or link_returncode not in {0, 1}:
            raise InstanceError("engine_unavailable", "proxy host file probe failed")
        if link_returncode == 0:
            return False
        file_returncode, file_output = self._proxy_root_process(
            ["test", "-f", path],
            timeout=15,
        )
        if file_output not in {b"", b"\n"} or file_returncode != 0:
            return False
        returncode, output = self._proxy_root_process(
            ["stat", "-c", "%u:%g:%a:%h", path],
            timeout=15,
            output_limit=128,
        )
        if returncode != 0:
            return False
        try:
            metadata = output.decode("ascii", "strict").strip()
        except UnicodeDecodeError:
            return False
        return metadata == f"0:0:{mode:o}:1"

    def _proxy_install_directory(self, path: str, mode: int) -> None:
        if self._proxy_remote_exists(path):
            if not self._proxy_remote_directory_valid(path, mode):
                raise InstanceError("ownership_mismatch", "proxy directory ownership is invalid")
            return
        created = self._proxy_root_simple(
            ["install", "-d", "-o", "root", "-g", "root", "-m", f"{mode:04o}", path],
            timeout=30,
        )
        if (
            not created
            and not self._proxy_remote_exists(path)
            or not self._proxy_remote_directory_valid(path, mode)
        ):
            raise InstanceError("install_artifact_invalid", "proxy directory staging failed")

    def _proxy_stage_stream(
        self,
        target: str,
        stream: Any,
        mode: int,
        *,
        timeout: int = 120,
    ) -> None:
        if not self._proxy_root_simple(
            ["install", "-o", "root", "-g", "root", "-m", f"{mode:04o}", "/dev/stdin", target],
            stdin_file=stream,
            timeout=timeout,
        ):
            raise InstanceError("install_artifact_invalid", "proxy artifact staging failed")

    def _proxy_stage_bytes(
        self,
        target: str,
        payload: bytes | bytearray,
        mode: int,
    ) -> None:
        if not isinstance(payload, (bytes, bytearray)) or len(payload) > 65536:
            raise InstanceError("internal_contract_error", "proxy payload exceeded its bound")
        if not self._proxy_root_simple(
            ["install", "-o", "root", "-g", "root", "-m", f"{mode:04o}", "/dev/stdin", target],
            payload=payload,
            timeout=30,
        ):
            raise InstanceError("install_artifact_invalid", "proxy payload staging failed")

    def _proxy_remote_sha256(self, path: str) -> str:
        returncode, output = self._proxy_root_process(["sha256sum", "--", path], timeout=30)
        if returncode != 0:
            raise InstanceError("install_artifact_invalid", "proxy artifact verification failed")
        try:
            text = output.decode("ascii", "strict").rstrip("\n")
        except UnicodeDecodeError as exc:
            raise InstanceError("install_artifact_invalid", "proxy artifact verification failed") from exc
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", text)
        if match is None or match.group(2) != path:
            raise InstanceError("install_artifact_invalid", "proxy artifact verification failed")
        return match.group(1)

    @staticmethod
    def _proxy_open_local_file(
        path: Path,
        *,
        limit: int,
        exact_mode: Optional[int] = None,
    ) -> tuple[Any, str]:
        absolute = Path(os.path.abspath(os.fspath(path)))
        try:
            before = absolute.lstat()
        except OSError as exc:
            raise InstanceError("install_artifact_invalid", "local proxy artifact is unavailable") from exc
        mode = stat.S_IMODE(before.st_mode)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > limit
            or (exact_mode is not None and mode != exact_mode)
            or (exact_mode is None and mode & 0o022)
        ):
            raise InstanceError("install_artifact_invalid", "local proxy artifact ownership or mode is invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        stream: Any = None
        try:
            descriptor = os.open(absolute, flags)
            stream = os.fdopen(descriptor, "rb", closefd=True)
            current = os.fstat(stream.fileno())
            if (
                (current.st_dev, current.st_ino, current.st_size)
                != (before.st_dev, before.st_ino, before.st_size)
                or not stat.S_ISREG(current.st_mode)
                or current.st_uid != os.getuid()
                or current.st_nlink != 1
            ):
                raise OSError("local proxy artifact changed")
            digest = hashlib.sha256()
            remaining = limit + 1
            while remaining:
                chunk = stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
            if stream.read(1) or stream.tell() != current.st_size:
                raise OSError("local proxy artifact exceeded its bound")
            stream.seek(0)
            return stream, digest.hexdigest()
        except OSError as exc:
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
            raise InstanceError("install_artifact_invalid", "local proxy artifact validation failed") from exc

    def _proxy_stage_control_bundle(self, expected_digest: str) -> dict[str, str]:
        root = self.context.project_root
        staging = f"/var/lib/xenoid/proxy/control-{expected_digest}"
        ready = f"{staging}/READY"
        self._proxy_install_directory("/var/lib/xenoid", 0o755)
        self._proxy_install_directory("/var/lib/xenoid/proxy", 0o711)
        if self._proxy_remote_exists(staging):
            if not self._proxy_remote_directory_valid(staging, 0o700):
                raise InstanceError("ownership_mismatch", "proxy control staging ownership is invalid")
            creator = False
        else:
            creator = self._proxy_root_simple(
                ["mkdir", "-m", "0700", staging],
                timeout=30,
            )
            if not creator and not self._proxy_remote_directory_valid(staging, 0o700):
                raise InstanceError("install_artifact_invalid", "proxy control staging failed")
        if not self._proxy_remote_directory_valid(staging, 0o700):
            raise InstanceError("install_artifact_invalid", "proxy control staging ownership is invalid")
        populate = creator
        if not creator:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not self._proxy_remote_exists(ready):
                time.sleep(0.1)
            populate = not self._proxy_remote_exists(ready)
        if populate:
            self._proxy_install_directory(f"{staging}/xenoid", 0o755)
        elif not self._proxy_remote_directory_valid(f"{staging}/xenoid", 0o755):
            raise InstanceError("install_artifact_invalid", "proxy control staging is invalid")
        artifacts = (
            (root / "scripts" / "xenoid-proxy-engine.py", f"{staging}/xenoid-proxy-engine.py", 0o555),
            (root / "scripts" / "xenoid-proxy-agent.py", f"{staging}/xenoid-proxy-agent.py", 0o555),
            (root / "scripts" / "xenoid-proxy-compile-worker.py", f"{staging}/xenoid-proxy-compile-worker.py", 0o555),
            (root / "scripts" / "xenoid-proxy-fetch-worker.py", f"{staging}/xenoid-proxy-fetch-worker.py", 0o555),
            (root / "scripts" / "xenoid-proxy-agent@.service", f"{staging}/xenoid-proxy-agent@.service", 0o444),
            (
                root / "native" / "xenoid-proxy-sandbox" / "xenoid-proxy-sandbox",
                f"{staging}/xenoid-proxy-sandbox",
                0o555,
            ),
            (root / "src" / "xenoid" / "__init__.py", f"{staging}/xenoid/__init__.py", 0o444),
            (root / "src" / "xenoid" / "proxy_source.py", f"{staging}/xenoid/proxy_source.py", 0o444),
            (root / "src" / "xenoid" / "proxy_protocol.py", f"{staging}/xenoid/proxy_protocol.py", 0o444),
        )
        digests: dict[str, str] = {}
        total = 0
        for local, remote, target_mode in artifacts:
            stream, digest = self._proxy_open_local_file(local, limit=8 * 1024 * 1024)
            try:
                total += os.fstat(stream.fileno()).st_size
                if total > 32 * 1024 * 1024:
                    raise InstanceError("install_artifact_invalid", "proxy control bundle exceeded its bound")
                if populate:
                    self._proxy_stage_stream(remote, stream, target_mode)
            finally:
                stream.close()
            if (
                not self._proxy_remote_regular_valid(remote, target_mode)
                or self._proxy_remote_sha256(remote) != digest
            ):
                raise InstanceError("install_artifact_invalid", "proxy control bundle verification failed")
            digests[remote] = digest
        if self._proxy_expected_control_digest(digests, staging) != expected_digest:
            raise InstanceError("install_artifact_invalid", "proxy control bundle changed during staging")
        ready_payload = (expected_digest + "\n").encode("ascii")
        if populate:
            self._proxy_stage_bytes(ready, ready_payload, 0o444)
        returncode, ready_output = self._proxy_root_process(
            ["cat", "--", ready],
            timeout=15,
            output_limit=128,
        )
        if (
            returncode != 0
            or ready_output != ready_payload
            or not self._proxy_remote_regular_valid(ready, 0o444)
        ):
            raise InstanceError("install_artifact_invalid", "proxy control staging is incomplete")
        return digests

    def _proxy_expected_control_digest(
        self,
        staged: dict[str, str],
        base: str = "/var/lib/xenoid/proxy/control-v1",
    ) -> str:
        files = {
            "/usr/libexec/xenoid-proxy-engine.py": staged[f"{base}/xenoid-proxy-engine.py"],
            "/etc/systemd/system/xenoid-proxy-agent@.service": staged[f"{base}/xenoid-proxy-agent@.service"],
            "/usr/libexec/xenoid-proxy-sandbox": staged[f"{base}/xenoid-proxy-sandbox"],
            "/usr/libexec/xenoid-proxy-agent.py": staged[f"{base}/xenoid-proxy-agent.py"],
            "/usr/libexec/xenoid-proxy-compile-worker.py": staged[f"{base}/xenoid-proxy-compile-worker.py"],
            "/usr/libexec/xenoid-proxy-fetch-worker.py": staged[f"{base}/xenoid-proxy-fetch-worker.py"],
            "/usr/lib/xenoid-proxy/python/xenoid/__init__.py": staged[f"{base}/xenoid/__init__.py"],
            "/usr/lib/xenoid-proxy/python/xenoid/proxy_source.py": staged[f"{base}/xenoid/proxy_source.py"],
            "/usr/lib/xenoid-proxy/python/xenoid/proxy_protocol.py": staged[f"{base}/xenoid/proxy_protocol.py"],
        }
        return hashlib.sha256(
            json.dumps(files, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()

    def _proxy_live_identity(self, *, require_running: bool = True) -> tuple[str, str]:
        container, error = self._owned_container_record()
        if container is None:
            raise InstanceError("resource_conflict", error)
        state = container.get("State")
        if (
            not isinstance(state, dict)
            or (require_running and state.get("Running") is not True)
        ):
            raise InstanceError("runtime_identity_mismatch", "instance container state is invalid")
        network, _ = self._inspect_docker_object("network", self.lease.network_name)
        if network is None or not network or not self._network_matches_lease(network):
            raise InstanceError("runtime_identity_mismatch", "instance Docker network identity is invalid")
        container_id = container.get("Id")
        network_id = network.get("Id")
        networks = container.get("NetworkSettings", {}).get("Networks", {})
        endpoint = networks.get(self.lease.network_name) if isinstance(networks, dict) else None
        if (
            not isinstance(container_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
            or not isinstance(network_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", network_id) is None
            or not isinstance(endpoint, dict)
            or (
                require_running
                and endpoint.get("NetworkID") != network_id
            )
            or (
                not require_running
                and endpoint.get("NetworkID") not in ("", network_id)
            )
        ):
            raise InstanceError("runtime_identity_mismatch", "instance runtime identity is invalid")
        return container_id, network_id

    def _proxy_manifest_document(
        self,
        runtime_epoch: str,
        generation: int,
        container_id: str,
        network_id: str,
    ) -> dict[str, Any]:
        if (
            not isinstance(runtime_epoch, str)
            or re.fullmatch(r"[A-Za-z0-9._-]{16,128}", runtime_epoch) is None
            or not isinstance(generation, int)
            or isinstance(generation, bool)
            or not 0 <= generation < (1 << 63)
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", network_id) is None
        ):
            raise InstanceError("manifest_invalid", "proxy runtime identity is invalid")
        instance_id = self.context.instance_id
        tag = self.context.resource_tag
        state = f"/var/lib/xenoid/proxy/instances/{instance_id}"
        manifest: dict[str, Any] = {
            "schema": "dev.xenoid.proxy-engine/v1",
            "manifestDigest": "",
            "instanceId": instance_id,
            "resourceTag": tag,
            "runtimeEpoch": runtime_epoch,
            "generation": generation,
            "containerId": container_id,
            "networkId": network_id,
            "bridgeName": self.lease.bridge_name,
            "proxyNamespace": f"xenoid-p-{tag}",
            "android": {
                "ipv4": self.lease.ipv4_address,
                "ipv6": self.lease.ipv6_address,
                "mac": self.lease.mac_address.lower(),
            },
            "users": {
                "proxy": f"xpm{tag}",
                "fetcher": f"xpf{tag}",
                "compiler": f"xpc{tag}",
                "agent": f"xpa{tag}",
            },
            "veth": {
                "host": self.lease.host_veth,
                "proxy": self.lease.proxy_veth,
                "hostIpv4": self.lease.transfer_ipv4_host,
                "proxyIpv4": self.lease.transfer_ipv4_proxy,
                "hostIpv6": self.lease.transfer_ipv6_host,
                "proxyIpv6": self.lease.transfer_ipv6_proxy,
            },
            "routing": {
                "mark": self.lease.mark_base,
                "mask": self.lease.mark_mask,
                "tables": list(self.lease.route_tables),
                "rulePriorities": list(self.lease.rule_priorities),
            },
            "engine": {
                "binaryPath": "/usr/lib/xenoid/proxy/mihomo-v1.19.29",
                "binarySha256": "8e02308f672e89c076bfc2fa1b03379bd54e58b0bafa81ffb01113fcf6da348d",
            },
            "paths": {
                "config": f"{state}/config.yaml",
                "state": state,
                "key": f"{state}/agent.key",
            },
            "daemon": {
                "ip": self.lease.ipv4_address,
                "port": self.lease.android_daemon_port,
                "adbPort": self.lease.android_adb_port,
            },
        }
        digest_source = dict(manifest)
        digest_source.pop("manifestDigest")
        manifest["manifestDigest"] = hashlib.sha256(
            json.dumps(
                digest_source,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
        return manifest

    def _proxy_validate_manifest(
        self,
        document: Any,
        *,
        require_live: bool,
        allow_stopped: bool = False,
    ) -> dict[str, Any]:
        if (
            not isinstance(document, dict)
            or set(document)
            != {
                "schema", "manifestDigest", "instanceId", "resourceTag", "runtimeEpoch",
                "generation", "containerId", "networkId", "bridgeName", "proxyNamespace",
                "android", "users", "veth", "routing", "engine", "paths", "daemon",
            }
        ):
            raise InstanceError("manifest_invalid", "proxy manifest is invalid")
        container_id = document.get("containerId")
        network_id = document.get("networkId")
        if require_live:
            expected_container, expected_network = self._proxy_live_identity(
                require_running=not allow_stopped
            )
            if (container_id, network_id) != (expected_container, expected_network):
                raise InstanceError("runtime_identity_mismatch", "proxy manifest runtime identity is stale")
        elif (
            not isinstance(container_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
            or not isinstance(network_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", network_id) is None
        ):
            raise InstanceError("manifest_invalid", "proxy manifest is invalid")
        expected = self._proxy_manifest_document(
            document.get("runtimeEpoch"),
            document.get("generation"),
            container_id,
            network_id,
        )
        if document != expected:
            raise InstanceError("ownership_mismatch", "proxy manifest does not match this instance")
        return document

    def _proxy_read_manifest(
        self,
        *,
        require_live: bool,
        allow_absent: bool,
        allow_stopped: bool = False,
    ) -> Optional[dict[str, Any]]:
        if not self._proxy_remote_exists(self._proxy_manifest_path):
            if allow_absent:
                return None
            raise InstanceError("engine_not_prepared", "proxy engine is not prepared")
        returncode, output = self._proxy_root_process(
            ["cat", "--", self._proxy_manifest_path],
            timeout=30,
            output_limit=65536,
        )
        if returncode != 0 or len(output) < 3 or len(output) > 65536:
            raise InstanceError("manifest_invalid", "proxy manifest could not be read")
        try:
            document = self._proxy_json_document(output.decode("ascii", "strict"))
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            raise InstanceError("manifest_invalid", "proxy manifest is invalid") from exc
        validated = self._proxy_validate_manifest(
            document,
            require_live=require_live,
            allow_stopped=allow_stopped,
        )
        canonical = (
            json.dumps(
                validated,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
        if output != canonical:
            raise InstanceError("manifest_invalid", "proxy manifest encoding is invalid")
        return validated

    def _proxy_restore_manifest_from_ownership(
        self,
        *,
        allow_stopped: bool,
    ) -> dict[str, Any]:
        """Restore volatile proxy manifest state after an engine-host reboot."""
        owner_path = f"{self._proxy_state_path}/engine-ownership.json"
        if not self._proxy_remote_regular_valid(owner_path, 0o600):
            raise InstanceError("ownership_mismatch", "proxy ownership state is invalid")
        returncode, output = self._proxy_root_process(
            ["cat", "--", owner_path],
            timeout=30,
            output_limit=65536,
        )
        if returncode != 0 or not 3 <= len(output) <= 65536:
            raise InstanceError("ownership_mismatch", "proxy ownership state could not be read")
        try:
            owner = self._proxy_json_document(output.decode("ascii", "strict"))
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            raise InstanceError("ownership_mismatch", "proxy ownership state is invalid") from exc
        if (
            not isinstance(owner, dict)
            or set(owner)
            != {
                "schema", "instanceId", "resourceTag", "runtimeEpoch",
                "manifestDigest", "leaseDigest", "manifestGeneration",
                "appliedGeneration", "phase", "activeCandidate", "candidate",
                "previous", "binarySha256", "pythonPath", "resources",
            }
            or owner.get("schema") != "dev.xenoid.proxy-engine.ownership/v1"
            or owner.get("instanceId") != self.context.instance_id
            or owner.get("resourceTag") != self.context.resource_tag
            or not isinstance(owner.get("runtimeEpoch"), str)
            or not isinstance(owner.get("manifestGeneration"), int)
            or isinstance(owner.get("manifestGeneration"), bool)
            or not isinstance(owner.get("manifestDigest"), str)
            or re.fullmatch(r"[0-9a-f]{64}", owner["manifestDigest"]) is None
        ):
            raise InstanceError("ownership_mismatch", "proxy ownership state is invalid")
        canonical = (
            json.dumps(
                owner,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
        if output != canonical:
            raise InstanceError("ownership_mismatch", "proxy ownership encoding is invalid")
        container_id, network_id = self._proxy_live_identity(
            require_running=not allow_stopped
        )
        manifest = self._proxy_manifest_document(
            owner["runtimeEpoch"],
            owner["manifestGeneration"],
            container_id,
            network_id,
        )
        if manifest["manifestDigest"] != owner["manifestDigest"]:
            raise InstanceError("ownership_mismatch", "proxy ownership runtime identity is stale")
        self._proxy_stage_manifest(manifest)
        return manifest

    def _proxy_stage_manifest(self, manifest: dict[str, Any]) -> None:
        self._proxy_install_directory("/run/xenoid", 0o755)
        self._proxy_install_directory("/run/xenoid/proxy", 0o755)
        self._proxy_install_directory(self._proxy_runtime_path, 0o711)
        payload = (
            json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
            + b"\n"
        )
        staged_path = f"{self._proxy_runtime_path}/.manifest.json.new"
        self._proxy_stage_bytes(staged_path, payload, 0o600)
        if (
            not self._proxy_remote_regular_valid(staged_path, 0o600)
            or self._proxy_remote_sha256(staged_path)
            != hashlib.sha256(payload).hexdigest()
            or not self._proxy_root_simple(
                ["mv", "-f", "--", staged_path, self._proxy_manifest_path],
                timeout=30,
            )
        ):
            raise InstanceError("manifest_invalid", "proxy manifest staging failed")
        if self._proxy_read_manifest(require_live=True, allow_absent=False) != manifest:
            raise InstanceError("manifest_invalid", "staged proxy manifest verification failed")

    def _proxy_feature_absent(self) -> bool:
        fixed_paths = (
            self._proxy_state_path,
            self._proxy_runtime_path,
            f"/run/netns/xenoid-p-{self.context.resource_tag}",
            f"/sys/class/net/{self.lease.host_veth}",
        )
        any_path_exists = any(
            self._proxy_remote_exists(path) for path in fixed_paths
        )
        unit_active = self._proxy_root_simple(
            ["systemctl", "is-active", "--quiet", self._proxy_systemd_unit()],
            timeout=15,
        )
        if not any_path_exists and not unit_active:
            return True
        if not self._proxy_remote_exists(self._proxy_manifest_path):
            raise InstanceError("cleanup_incomplete", "partial proxy engine state remains")
        return False

    def _proxy_agent_active(self, manifest: dict[str, Any]) -> bool:
        if not self._proxy_root_simple(
            ["systemctl", "is-active", "--quiet", self._proxy_systemd_unit()],
            timeout=15,
        ):
            return False
        pid_returncode, pid_output = self._proxy_root_process(
            ["systemctl", "show", "--property=MainPID", "--value", self._proxy_systemd_unit()],
            timeout=15,
            output_limit=64,
        )
        try:
            pid_text = pid_output.decode("ascii", "strict").strip()
        except UnicodeDecodeError:
            return False
        if pid_returncode != 0 or re.fullmatch(r"[1-9][0-9]{0,9}", pid_text) is None:
            return False
        command_returncode, command_output = self._proxy_root_process(
            ["cat", "--", f"/proc/{pid_text}/cmdline"],
            timeout=15,
            output_limit=4096,
        )
        command = command_output.rstrip(b"\0").split(b"\0")
        if (
            command_returncode != 0
            or len(command) < 4
            or command[-3:]
            != [
                b"/usr/libexec/xenoid-proxy-agent.py",
                b"--manifest",
                self._proxy_manifest_path.encode("ascii"),
            ]
        ):
            return False
        user_returncode, user_output = self._proxy_root_process(
            ["stat", "-c", "%U", f"/proc/{pid_text}"],
            timeout=15,
            output_limit=64,
        )
        if (
            user_returncode != 0
            or user_output.decode("ascii", "ignore").strip()
            != f"xpa{self.context.resource_tag}"
        ):
            return False
        returncode, output = self._proxy_root_process(
            ["cat", "--", f"{self._proxy_state_path}/agent-status.json"],
            timeout=15,
            output_limit=4096,
        )
        if returncode != 0 or not 3 <= len(output) <= 4096:
            return False
        try:
            status = self._proxy_json_document(output.decode("ascii", "strict"))
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return False
        return (
            isinstance(status, dict)
            and set(status)
            == {"schema", "instanceId", "resourceTag", "runtimeEpoch", "generation", "phase", "errorCode", "updatedAt"}
            and status.get("schema") == "dev.xenoid.proxy-agent.status/v1"
            and status.get("instanceId") == self.context.instance_id
            and status.get("resourceTag") == self.context.resource_tag
            and status.get("runtimeEpoch") == manifest["runtimeEpoch"]
            and isinstance(status.get("generation"), int)
            and not isinstance(status.get("generation"), bool)
            and status["generation"] >= manifest["generation"]
            and status.get("phase") in {"starting", "quarantined", "applying", "ready", "error", "disabled"}
            and isinstance(status.get("errorCode"), str)
            and isinstance(status.get("updatedAt"), int)
            and not isinstance(status.get("updatedAt"), bool)
            and abs(time.time() - status["updatedAt"]) <= 90
        )

    def _proxy_local_control_digest(self) -> str:
        root = self.context.project_root
        base = "/var/lib/xenoid/proxy/control-v1"
        local_files = (
            (root / "scripts" / "xenoid-proxy-engine.py", f"{base}/xenoid-proxy-engine.py"),
            (root / "scripts" / "xenoid-proxy-agent.py", f"{base}/xenoid-proxy-agent.py"),
            (root / "scripts" / "xenoid-proxy-compile-worker.py", f"{base}/xenoid-proxy-compile-worker.py"),
            (root / "scripts" / "xenoid-proxy-fetch-worker.py", f"{base}/xenoid-proxy-fetch-worker.py"),
            (root / "scripts" / "xenoid-proxy-agent@.service", f"{base}/xenoid-proxy-agent@.service"),
            (root / "native" / "xenoid-proxy-sandbox" / "xenoid-proxy-sandbox", f"{base}/xenoid-proxy-sandbox"),
            (root / "src" / "xenoid" / "__init__.py", f"{base}/xenoid/__init__.py"),
            (root / "src" / "xenoid" / "proxy_source.py", f"{base}/xenoid/proxy_source.py"),
            (root / "src" / "xenoid" / "proxy_protocol.py", f"{base}/xenoid/proxy_protocol.py"),
        )
        digests: dict[str, str] = {}
        total = 0
        for local, staged in local_files:
            stream, digest = self._proxy_open_local_file(local, limit=8 * 1024 * 1024)
            try:
                total += os.fstat(stream.fileno()).st_size
            finally:
                stream.close()
            if total > 32 * 1024 * 1024:
                raise InstanceError("install_artifact_invalid", "proxy control bundle exceeded its bound")
            digests[staged] = digest
        return self._proxy_expected_control_digest(digests)

    def proxy_prerequisite(self, *, allow_stopped: bool = False) -> dict[str, Any]:
        self.ensure_instance_lease()
        container_id, network_id = self._proxy_live_identity(
            require_running=not allow_stopped
        )
        existing = self._proxy_read_manifest(
            require_live=True,
            allow_absent=True,
            allow_stopped=allow_stopped,
        )
        if existing is None:
            state_exists = self._proxy_remote_exists(self._proxy_state_path)
            runtime_exists = self._proxy_remote_exists(self._proxy_runtime_path)
            if state_exists:
                existing = self._proxy_restore_manifest_from_ownership(
                    allow_stopped=allow_stopped
                )
            elif runtime_exists:
                raise InstanceError("ownership_mismatch", "partial proxy instance state exists")
            else:
                existing = self._proxy_manifest_document(
                    f"control-{self.context.resource_tag}-{self.lease.transaction_id}",
                    0,
                    container_id,
                    network_id,
                )
                self._proxy_stage_manifest(existing)
        expected_digest = self._proxy_local_control_digest()
        checked = self._proxy_root_json("check-control")
        if checked.get("ok") is True and checked.get("controlDigest") == expected_digest:
            return self._proxy_root_json("prepare-host", timeout=90)
        owns_engine_state = (
            self._proxy_remote_exists(f"{self._proxy_state_path}/engine-ownership.json")
            or self._proxy_remote_exists(f"{self._proxy_state_path}/mustBlock")
        )
        agent_service_active = self._proxy_root_simple(
            ["systemctl", "is-active", "--quiet", self._proxy_systemd_unit()],
            timeout=15,
        )
        staged: Optional[dict[str, str]] = None
        staging = f"/var/lib/xenoid/proxy/control-{expected_digest}"
        if owns_engine_state or agent_service_active:
            quarantined = self._proxy_root_json("quarantine")
            if (
                quarantined.get("ok") is not True
                and quarantined.get("code") == "runtime_identity_mismatch"
            ):
                # Repair an older installed control helper that rejected Docker's
                # valid stopped-container representation. Staging is inert; the
                # candidate still validates the existing signed manifest/owner.
                staged = self._proxy_stage_control_bundle(expected_digest)
                quarantined = self._proxy_root_json(
                    "quarantine",
                    helper=f"{staging}/xenoid-proxy-engine.py",
                    timeout=180,
                )
            if quarantined.get("ok") is not True:
                return quarantined
            if not self._proxy_stop_agent():
                return self._proxy_failure("agent_stop_failed")
        if staged is None:
            staged = self._proxy_stage_control_bundle(expected_digest)
        installed = self._proxy_root_json(
            "install-control",
            helper=f"{staging}/xenoid-proxy-engine.py",
            timeout=900,
        )
        if installed.get("ok") is not True:
            return installed
        if self._proxy_remote_sha256(self._proxy_installed_helper) != staged[f"{staging}/xenoid-proxy-engine.py"]:
            return self._proxy_failure("install_artifact_invalid")
        rechecked = self._proxy_root_json("check-control")
        if rechecked.get("ok") is not True or rechecked.get("controlDigest") != expected_digest:
            return self._proxy_failure("install_artifact_invalid")
        return {"ok": True}
    def proxy_bootstrap_quarantine(self) -> dict[str, Any]:
        """Install the host fail-closed guard before a stopped Android container starts."""
        deadline = time.monotonic() + 30.0
        while True:
            try:
                prerequisite = self.proxy_prerequisite(allow_stopped=True)
            except InstanceError as exc:
                if exc.code == "runtime_identity_mismatch" and time.monotonic() < deadline:
                    time.sleep(0.1)
                    continue
                raise
            if prerequisite.get("ok") is True:
                break
            if prerequisite.get("code") != "runtime_identity_mismatch" or time.monotonic() >= deadline:
                return prerequisite
            time.sleep(0.1)
        while True:
            guarded = self._proxy_root_json("quarantine")
            if guarded.get("ok") is True:
                return {"ok": True, "quarantined": True}
            if guarded.get("code") != "runtime_identity_mismatch" or time.monotonic() >= deadline:
                return guarded
            time.sleep(0.1)


    def proxy_prepare_asset(self, asset_path: Optional[Path]) -> dict[str, Any]:
        self.ensure_instance_lease()
        prerequisite = self.proxy_prerequisite()
        if prerequisite.get("ok") is not True:
            return prerequisite
        if asset_path is not None:
            stream, digest = self._proxy_open_local_file(
                Path(asset_path),
                limit=64 * 1024 * 1024,
                exact_mode=0o600,
            )
            try:
                if digest != "9a868b5e40ad91d9d71e1b41b0cfce78aaba44360c30df74a723f8e3926a86c":
                    return self._proxy_failure("binary_digest_mismatch")
                self._proxy_install_directory("/run/xenoid", 0o755)
                self._proxy_install_directory("/run/xenoid/proxy", 0o755)
                self._proxy_install_directory(self._proxy_runtime_path, 0o711)
                self._proxy_stage_stream(
                    f"{self._proxy_runtime_path}/mihomo-v1.19.29.gz",
                    stream,
                    0o600,
                    timeout=180,
                )
            finally:
                stream.close()
        result = self._proxy_root_json("install-asset", timeout=900)
        if result.get("ok") is not True:
            return result
        if self._proxy_remote_exists(f"{self._proxy_runtime_path}/mihomo-v1.19.29.gz"):
            return self._proxy_failure("cleanup_incomplete")
        return {"ok": True}

    @staticmethod
    def _proxy_validate_secret(value: str) -> bool:
        if not isinstance(value, str) or len(value) != 44 or value[-1:] != "=":
            return False
        decoded: Optional[bytearray] = None
        try:
            decoded = bytearray(base64.b64decode(value, validate=True))
            return (
                len(decoded) == 32
                and base64.b64encode(decoded).decode("ascii") == value
            )
        except (ValueError, TypeError):
            return False
        finally:
            if decoded is not None:
                for index in range(len(decoded)):
                    decoded[index] = 0

    def _proxy_systemd_unit(self) -> str:
        return f"xenoid-proxy-agent@{self.context.resource_tag}.service"

    def _proxy_stop_agent(self) -> bool:
        returncode, output = self._proxy_root_process(
            ["systemctl", "stop", self._proxy_systemd_unit()],
            timeout=45,
        )
        return returncode in {0, 5} and output in {b"", b"\n"}

    def proxy_start_agent(
        self,
        runtime_epoch: str,
        generation: int,
        master_key: str,
        agent_token: str,
        enabled: bool,
    ) -> dict[str, Any]:
        self.ensure_instance_lease()
        if (
            not isinstance(enabled, bool)
            or not self._proxy_validate_secret(master_key)
            or not self._proxy_validate_secret(agent_token)
        ):
            return self._proxy_failure("agent_bootstrap_failed")
        container_id, network_id = self._proxy_live_identity()
        manifest = self._proxy_manifest_document(
            runtime_epoch,
            generation,
            container_id,
            network_id,
        )
        prerequisite = self.proxy_prerequisite()
        if prerequisite.get("ok") is not True:
            return prerequisite
        if enabled:
            prepared_asset = self.proxy_prepare_asset(None)
            if prepared_asset.get("ok") is not True:
                return prepared_asset
        previous = self._proxy_read_manifest(require_live=True, allow_absent=False)
        if previous is not None and generation < previous["generation"]:
            return self._proxy_failure("generation_stale")
        quarantined = self._proxy_root_json("quarantine")
        if quarantined.get("ok") is not True:
            return quarantined
        if not self._proxy_stop_agent():
            return self._proxy_failure("agent_stop_failed")
        self._proxy_stage_manifest(manifest)
        transitioned = self._proxy_root_json("prepare" if enabled else "off", timeout=180)
        if transitioned.get("ok") is not True:
            return transitioned
        key_path = f"{self._proxy_state_path}/agent.key"
        key_payload = bytearray(b'{"agentToken":"')
        key_payload.extend(ord(character) for character in agent_token)
        key_payload.extend(b'","masterKey":"')
        key_payload.extend(ord(character) for character in master_key)
        key_payload.extend(b'"}\n')
        try:
            self._proxy_stage_bytes(key_path, key_payload, 0o400)
            if not self._proxy_remote_regular_valid(key_path, 0o400):
                raise InstanceError("agent_bootstrap_failed", "proxy key staging failed")
        except InstanceError:
            self._proxy_root_json("discard-key")
            self._proxy_root_json("quarantine")
            raise
        finally:
            for index in range(len(key_payload)):
                key_payload[index] = 0
        self._proxy_root_process(
            ["systemctl", "reset-failed", self._proxy_systemd_unit()],
            timeout=30,
            output_limit=1024,
        )
        if not self._proxy_root_simple(
            ["systemctl", "start", self._proxy_systemd_unit()],
            timeout=60,
        ):
            self._proxy_root_json("discard-key")
            self._proxy_root_json("quarantine")
            return self._proxy_failure("agent_start_failed")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if (
                not self._proxy_remote_exists(key_path)
                and self._proxy_agent_active(manifest)
            ):
                break
            time.sleep(0.25)
        else:
            self._proxy_stop_agent()
            self._proxy_root_json("discard-key")
            self._proxy_root_json("quarantine")
            return self._proxy_failure("agent_start_failed")
        return {
            "ok": True,
            "instanceId": self.context.instance_id,
            "resourceTag": self.context.resource_tag,
            "runtimeEpoch": runtime_epoch,
            "generation": generation,
            "phase": "starting",
            "structuralApplied": False,
            "dataPlaneVerified": False,
        }

    def proxy_engine_status(self) -> dict[str, Any]:
        self.ensure_instance_lease()
        try:
            manifest = self._proxy_read_manifest(require_live=True, allow_absent=False)
            if manifest is None or not self._proxy_agent_active(manifest):
                return self._proxy_failure("agent_stale")
            result = self._proxy_root_json("status")
        except InstanceError as exc:
            return self._proxy_failure(exc.code)
        if result.get("ok") is not True:
            return result
        if (
            result.get("instanceId") != self.context.instance_id
            or result.get("resourceTag") != self.context.resource_tag
            or result.get("runtimeEpoch") != manifest["runtimeEpoch"]
            or result.get("manifestDigest") != manifest["manifestDigest"]
            or result.get("generation") < manifest["generation"]
        ):
            return self._proxy_failure("runtime_identity_mismatch")
        return result

    def proxy_quarantine(self, generation: Optional[int] = None) -> dict[str, Any]:
        self.ensure_instance_lease()
        if (
            generation is not None
            and (
                not isinstance(generation, int)
                or isinstance(generation, bool)
                or not 0 <= generation < (1 << 63)
            )
        ):
            return self._proxy_failure("generation_stale")
        try:
            if self._proxy_feature_absent():
                return {"ok": True, "notPrepared": True}
            manifest = self._proxy_read_manifest(require_live=False, allow_absent=False)
            if manifest is None:
                return self._proxy_failure("engine_not_prepared")
        except InstanceError as exc:
            return self._proxy_failure(exc.code)
        return self._proxy_root_json("quarantine")

    def proxy_off(self, generation: int) -> dict[str, Any]:
        self.ensure_instance_lease()
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or not 0 <= generation < (1 << 63)
        ):
            return self._proxy_failure("generation_stale")
        try:
            manifest = self._proxy_read_manifest(require_live=True, allow_absent=False)
        except InstanceError as exc:
            return self._proxy_failure(exc.code)
        if manifest is None:
            return self._proxy_failure("engine_not_prepared")
        if generation < manifest["generation"]:
            return self._proxy_failure("generation_stale")
        if generation != manifest["generation"]:
            manifest = self._proxy_manifest_document(
                manifest["runtimeEpoch"],
                generation,
                manifest["containerId"],
                manifest["networkId"],
            )
            self._proxy_stage_manifest(manifest)
        result = self._proxy_root_json("off", timeout=180)
        if result.get("ok") is not True:
            return result
        return {
            "ok": True,
            "phase": "off",
            "generation": generation,
            "structuralApplied": True,
            "dataPlaneVerified": True,
        }

    def proxy_cleanup(self) -> dict[str, Any]:
        self.ensure_instance_lease()
        try:
            if self._proxy_feature_absent():
                return {"ok": True, "notPrepared": True}
            self._proxy_read_manifest(require_live=False, allow_absent=False)
            if not self._proxy_stop_agent():
                return self._proxy_failure("agent_stop_failed")
            result = self._proxy_root_json("cleanup", timeout=180)
            if (
                result.get("ok") is not True
                and result.get("code") == "cleanup_incomplete"
            ):
                expected_digest = self._proxy_local_control_digest()
                self._proxy_stage_control_bundle(expected_digest)
                result = self._proxy_root_json(
                    "cleanup",
                    helper=(
                        f"/var/lib/xenoid/proxy/control-{expected_digest}"
                        "/xenoid-proxy-engine.py"
                    ),
                    timeout=180,
                )
        except InstanceError as exc:
            return self._proxy_failure(exc.code)
        if result.get("ok") is not True:
            return result
        try:
            if not self._proxy_feature_absent():
                return self._proxy_failure("cleanup_incomplete")
        except InstanceError as exc:
            return self._proxy_failure(exc.code)
        return result
