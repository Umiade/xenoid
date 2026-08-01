from __future__ import annotations

import hashlib
import os
import secrets
import shlex
import subprocess
import json
import lzma
import re
import shutil
import stat
import tarfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .config import DEFAULT_IMAGE, XenoidConfig, default_image_for_host
from .daemon_client import CAMERA_MUTATION_TIMEOUT_SECONDS
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
    def __init__(self, cfg: XenoidConfig):
        self.cfg = cfg

    @property
    def adb_target(self) -> str:
        return f"127.0.0.1:{self.cfg.adb_port}"

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
        return checks

    def colima_start_command(self) -> list[str]:
        return ["colima", "start", "--arch", "aarch64", "--vm-type", "vz", "--memory", "8", "--cpu", "8"]

    def effective_image(self) -> str:
        if self.cfg.auto_build_runtime_image:
            return self.cfg.runtime_image_tag
        # Auto-upgrade the stock default to the 64only variant on arm64 hosts
        # (Apple Silicon / ARM ECS): those CPUs have no AArch32, and the stock
        # image dies in boringssl_self_test32. A user-customized image wins.
        if self.cfg.image == DEFAULT_IMAGE:
            return default_image_for_host(host_info().get("machine"))
        return self.cfg.image

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
            probe = run(probe_cmd)
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
            proc = run(["colima", "ssh", "--", "sh", "-c", script], timeout=600)
            ok = proc.returncode == 0 and "BINDER_READY" in (proc.stdout or "")
            return {"ok": ok, "backend": "colima", "returncode": proc.returncode, "stdout": proc.stdout.strip()[-800:], "stderr": proc.stderr.strip()[-800:]}
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            proc = run([*ssh_cmd, "sh", "-c", script], timeout=600)
            ok = proc.returncode == 0 and "BINDER_READY" in (proc.stdout or "")
            return {"ok": ok, "backend": "remote-ssh", "ssh": ssh_cmd[-1], "returncode": proc.returncode, "stdout": proc.stdout.strip()[-800:], "stderr": proc.stderr.strip()[-800:]}
        if host_info()["system"] == "Linux":
            script_path = Path(__file__).resolve().parents[2] / "scripts" / "setup-linux-binderfs.sh"
            proc = run(["bash", str(script_path)], timeout=600)
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
        script = Path(__file__).resolve().parents[2] / "scripts" / "build-ebpf.sh"
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
        script = Path(__file__).resolve().parents[2] / "scripts" / "load-ebpf.sh"
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
        script = Path(__file__).resolve().parents[2] / "scripts" / "build-kmod.sh"
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
            proc = run(cmd, timeout=20)
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
            proc = run(cmd, timeout=60)
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
        return "colima" if self.should_use_colima() else ""

    def docker_env(self) -> dict[str, str]:
        env = os.environ.copy()
        context = self.effective_docker_context()
        if context:
            env["DOCKER_CONTEXT"] = context
        return env

    def docker_base_cmd(self) -> list[str]:
        docker = which("docker") or "docker"
        context = self.effective_docker_context()
        return [docker, "--context", context] if context else [docker]

    def docker_network_command(self) -> list[str]:
        return [*self.docker_base_cmd(), "network", "create", "--driver", "bridge", "--subnet", self.cfg.network_subnet, "--gateway", self.cfg.network_gateway, self.cfg.network_name]

    def ensure_network(self) -> dict[str, Any]:
        if not self.cfg.network_enabled:
            return {"ok": True, "skipped": True}
        inspect = run([*self.docker_base_cmd(), "network", "inspect", self.cfg.network_name])
        if inspect.returncode == 0:
            return {"ok": True, "exists": True}
        proc = run(self.docker_network_command())
        return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "command": self.docker_network_command()}

    def docker_run_command(self) -> list[str]:
        return [
            *self.docker_base_cmd(), "run", "-d", "--rm", "--privileged",
            "--name", self.cfg.container_name,
            "-p", f"127.0.0.1:{self.cfg.adb_port}:{self.cfg.android_adb_port}",
            "-v", f"{self.cfg.android_data_volume}:/data",
            *((["--network", self.cfg.network_name, "--ip", self.cfg.network_ip, "--mac-address", self.cfg.network_mac] if self.cfg.network_enabled else [])),
            *self.cfg.extra_docker_args,
            *self.binder_volume_args(),
            self.effective_image(),
            "androidboot.redroid_width=1080",
            "androidboot.redroid_height=1920",
            "androidboot.redroid_dpi=480",
            f"service.adb.tcp.port={self.cfg.android_adb_port}",
            "androidboot.use_memfd=true",
            # Import this immutable boot value before property areas are created.
            "androidboot.mode=normal",
        ]


    def docker_exec(self, args: list[str], timeout: int = 15) -> dict[str, Any]:
        if which("docker") is None:
            return {"ok": False, "error": "docker not found"}
        cmd = [*self.docker_base_cmd(), "exec", self.cfg.container_name, *args]
        try:
            proc = run(cmd, timeout=timeout)
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
        cmd = [
            *self.docker_base_cmd(),
            "exec",
            "-i",
            self.cfg.container_name,
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
                cmd, input=payload, text=True, capture_output=True, timeout=20
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
        """Move adbd to cfg.android_adb_port via docker exec, then hide the prop.

        Robust against redroid ignoring the cmdline prop and against later adbd
        restarts (adb root): caller should re-invoke after any adbd restart.
        """
        desired = str(self.cfg.android_adb_port)
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
        script = Path(__file__).resolve().parents[2] / "scripts" / "redroid-preflight.sh"
        proc = run([str(script)])
        try:
            data = json.loads(proc.stdout)
        except Exception:
            data = {"ok": proc.returncode == 0, "stdout": proc.stdout, "stderr": proc.stderr}
        data["returncode"] = proc.returncode
        return data

    def start(self, dry_run: bool = False, wait: bool = True, install_daemon_apk: Optional[str] = None, start_colima: bool = False, adb_root: bool = True, skip_preflight: bool = False, recreate: bool = False) -> dict[str, Any]:
        plan: dict[str, Any] = {
            "backend": self.cfg.backend,
            "colimaCommand": self.colima_start_command(),
            "effectiveImage": self.effective_image(),
            "adbTarget": self.adb_target,
            "daemonPort": self.cfg.daemon_port,
            "recreate": recreate,
        }
        if dry_run:
            plan["dockerCommand"] = self.docker_run_command()
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
        if self.cfg.auto_build_runtime_image:
            plan["runtimeContext"] = self.make_runtime_context(self.base_image_for_build())
            context = plan["runtimeContext"]
            if not context.get("ok") or not context.get("context"):
                return {"ok": False, "error": "runtime context generation failed", "plan": plan}
            build = run([*self.docker_base_cmd(), "build", "-t", self.cfg.runtime_image_tag, context["context"]])
            plan["runtimeImageBuild"] = {
                "ok": build.returncode == 0,
                "returncode": build.returncode,
                "stdout": build.stdout[-4000:],
                "stderr": build.stderr[-4000:],
            }
            if build.returncode != 0:
                return {"ok": False, "error": "runtime image build failed", "plan": plan}


        rootfs_images = self.ensure_rootfs_images()
        plan["rootfsImages"] = rootfs_images
        if not rootfs_images.get("ok"):
            return {"ok": False, "error": "rootfs/data image build failed", "plan": plan}

        binder = self.ensure_binder()
        plan["binder"] = binder
        if not binder.get("ok"):
            return {"ok": False, "error": "binder setup failed on docker host", "plan": plan}

        docker_cmd = self.docker_run_command()
        plan["dockerCommand"] = docker_cmd
        if not any("/dev/binder" in arg for arg in docker_cmd):
            return {"ok": False, "error": "binder device mounts unavailable after binder setup", "plan": plan}

        kmod_cmd = self.build_kmod_command()
        kmod = run(kmod_cmd, timeout=900)
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
        if self.cfg.network_enabled:
            plan["network"] = self.ensure_network()
            if not plan["network"].get("ok"):
                return {"ok": False, "error": "docker network setup failed", "plan": plan}

        existing = run([*self.docker_base_cmd(), "ps", "-a", "--filter", f"name=^{self.cfg.container_name}$", "--format", "{{.Names}}"])
        plan["containerLookup"] = {
            "ok": existing.returncode == 0,
            "returncode": existing.returncode,
            "stderr": existing.stderr.strip()[-300:],
        }
        if existing.returncode != 0:
            return {"ok": False, "error": "container lookup failed", "plan": plan}
        existing_present = self.cfg.container_name in existing.stdout.splitlines()
        if existing_present and recreate:
            remove = run([*self.docker_base_cmd(), "rm", "-f", self.cfg.container_name])
            plan["containerRecreate"] = {
                "ok": remove.returncode == 0,
                "returncode": remove.returncode,
                "stdout": remove.stdout.strip(),
                "stderr": remove.stderr.strip(),
            }
            if remove.returncode != 0:
                return {"ok": False, "error": "existing container removal failed", "plan": plan}
            existing_present = False
        if existing_present:
            result: dict[str, Any] = {"ok": True, "alreadyRunning": True, "container": self.cfg.container_name, "plan": plan}
        else:
            proc = run(docker_cmd)
            result = {
                "ok": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip(),
                "plan": plan,
            }
            if proc.returncode != 0:
                return result

        required: list[dict[str, Any]] = []
        if wait:
            result["dockerBootWait"] = self.docker_wait_boot()
            result["adbAuthorization"] = self.ensure_adb_authorized_key()
            required.extend([result["dockerBootWait"], result["adbAuthorization"]])
            if self.cfg.android_adb_port != 5555:
                result["dockerAdbPortSwitch"] = self.switch_adbd_port_via_docker()
                required.append(result["dockerAdbPortSwitch"])
            result["adbConnect"] = self.adb_connect()
            result["adbWait"] = self.adb_wait(timeout_sec=90)
            if self.cfg.android_adb_port != 5555 and not result["adbWait"].get("ok"):
                result["dockerAdbPortRetry"] = self.switch_adbd_port_via_docker()
                result["adbConnectRetry"] = self.adb_connect()
                result["adbWait"] = self.adb_wait(timeout_sec=60)
            required.append(result["adbWait"])
            if self.cfg.android_adb_port != 5555:
                result["androidAdbPort"] = self.ensure_android_adb_port()
                required.append(result["androidAdbPort"])
            if adb_root:
                result["adbRoot"] = self.enable_adb_root()
                required.append(result["adbRoot"])
                if self.cfg.android_adb_port != 5555 and result["adbRoot"].get("rooted"):
                    result["dockerAdbPortPostRoot"] = self.switch_adbd_port_via_docker()
                    result["adbConnectPostRoot"] = self.adb_connect()
                    result["adbWaitPostRoot"] = self.adb_wait(timeout_sec=60)
                    required.extend([result["dockerAdbPortPostRoot"], result["adbWaitPostRoot"]])
            result["daemonForward"] = self.forward_daemon_port()
            required.append(result["daemonForward"])

        if install_daemon_apk:
            result["daemonInstall"] = self.install_daemon(install_daemon_apk)
            result["daemonStart"] = self.start_daemon_service() if result["daemonInstall"].get("ok") else {"ok": False, "skipped": True}
            result["daemonForward"] = self.forward_daemon_port() if result["daemonStart"].get("ok") else {"ok": False, "skipped": True}
            required.extend([result["daemonInstall"], result["daemonStart"], result["daemonForward"]])

        # Start rootd after the daemon so both processes use the daemon's private
        # control token. This avoids a world-readable token under /data/local/tmp.
        result["rootdRoot"] = self.ensure_rootd_root()
        required.append(result["rootdRoot"])
        if install_daemon_apk:
            result["daemonReady"] = (
                self.ensure_daemon(
                    readiness_timeout=CAMERA_MUTATION_TIMEOUT_SECONDS
                )
                if result["daemonForward"].get("ok") and result["rootdRoot"].get("ok")
                else {"ok": False, "skipped": True}
            )
            required.append(result["daemonReady"])
        result["imageProtectionStatus"] = self.image_protection_status()
        required.append(result["imageProtectionStatus"])
        result["ok"] = all(bool(step.get("ok")) for step in required)
        if not result["ok"]:
            result["error"] = "one or more required runtime startup steps failed"
        return result

    def stop(self) -> dict[str, Any]:
        if which("docker") is None:
            return {"ok": False, "error": "docker not found"}
        proc = run([*self.docker_base_cmd(), "rm", "-f", self.cfg.container_name])
        return {"ok": proc.returncode == 0, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip()}

    def status(self) -> dict[str, Any]:
        if which("docker") is None:
            return {"ok": False, "error": "docker not found"}
        proc = run([*self.docker_base_cmd(), "ps", "--filter", f"name=^{self.cfg.container_name}$", "--format", "{{json .}}"])
        rows = [line for line in proc.stdout.splitlines() if line.strip()]
        adb_state: dict[str, Any] = {"ok": False, "error": "adb not found"}
        if which("adb") is not None:
            adb_state = self.adb(["get-state"])
        return {"ok": proc.returncode == 0, "running": bool(rows), "rows": rows, "adb": adb_state}

    def adb(self, args: list[str], timeout: Optional[float] = None) -> dict[str, Any]:
        adb_bin = which("adb")
        if adb_bin is None:
            return {"ok": False, "error": "adb not found"}
        if args and args[0] == "connect":
            cmd = [adb_bin, "connect", self.adb_target]
        elif args and args[0] in {"--version", "version", "devices", "start-server", "kill-server"}:
            cmd = [adb_bin, *args]
        else:
            cmd = [adb_bin, "-s", self.adb_target, *args]
        try:
            proc = run(cmd, timeout=15 if timeout is None else timeout)
        except Exception as e:
            return {"ok": False, "error": str(e), "command": cmd}
        return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "command": cmd}

    def adb_connect(self) -> dict[str, Any]:
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
        """Ensure adbd listens on the configured Android-internal port.

        Redroid images may ignore service.adb.tcp.port passed as a kernel-style
        argument and boot adbd on 5555.  Keep the host-facing tunnel stable and
        keep the Android-internal listener on the configured non-5555 port; app
        processes see service.adb.tcp.port=-1 through the LD_PRELOAD shim.
        """
        desired = str(self.cfg.android_adb_port)
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
        adb_bin = which("adb")
        if adb_bin is None:
            return {"ok": False, "rooted": False, "error": "adb not found"}
        root = run([adb_bin, "-s", self.adb_target, "root"])
        root_output = f"{root.stdout}\n{root.stderr}".lower()
        production_build = "cannot run as root in production builds" in root_output
        if not production_build:
            time.sleep(3)
        reconnect = self.adb_connect()
        wait = self.adb_wait(timeout_sec=15 if production_build else 45)
        uid = self.adb(["shell", "id", "-u"]) if wait.get("ok") else {"ok": False}
        uid_value = str(uid.get("stdout", "")).strip()
        rooted = root.returncode == 0 and bool(wait.get("ok")) and uid_value == "0"
        skipped = production_build and bool(wait.get("ok")) and uid_value != "0"
        return {
            "ok": rooted or skipped,
            "rooted": rooted,
            "skipped": skipped,
            "reason": "production-build" if skipped else None,
            "root": {"returncode": root.returncode, "stdout": root.stdout, "stderr": root.stderr},
            "reconnect": reconnect,
            "wait": wait,
            "uid": uid,
            "uidValue": uid_value,
        }

    def forward_daemon_port(self) -> dict[str, Any]:
        return self.adb(["forward", f"tcp:{self.cfg.daemon_port}", f"tcp:{self.cfg.daemon_port}"])

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

    def ensure_rootd_root(self, port: int = 18767) -> dict[str, Any]:
        """Start xenoid-rootd as uid=0 with the daemon's private control token."""
        if which("docker") is None:
            return {"ok": False, "skipped": True, "error": "docker not found"}
        abi = self.docker_exec(["getprop", "ro.product.cpu.abi"])
        abi_s = str(abi.get("stdout", ""))
        arch = "arm64" if ("arm64" in abi_s or "aarch64" in abi_s) else "x86_64"
        root = Path(__file__).resolve().parents[2]
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
        host_token = root / ".xenoid" / "daemon.token"
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
            rootd_cache = root / ".xenoid" / "rootd.token"
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
        launch = run([
            *self.docker_base_cmd(), "exec", "-d", "-e", f"XENOID_ROOTD_TOKEN={token}",
            self.cfg.container_name, "sh", "-c",
            f"exec /data/local/tmp/.netd-helper {port} >/data/local/tmp/.netd-helper.log 2>&1",
        ])
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


    def ensure_daemon(self, readiness_timeout: float = 30.0) -> dict[str, Any]:
        steps: dict[str, Any] = {}
        steps["forward"] = self.forward_daemon_port()
        try:
            from .daemon_client import DaemonClient
            client: Optional[DaemonClient] = DaemonClient(
                port=self.cfg.daemon_port,
                timeout=2.0,
            )
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
                    from .daemon_client import DaemonClient
                    client = DaemonClient(port=self.cfg.daemon_port, timeout=2.0)
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


    def fetch_frida(self, version: str = "latest", arch: str = "android-arm64", out_dir: str = ".xenoid/frida") -> dict[str, Any]:
        out = Path(out_dir).expanduser().resolve()
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
        out_dir: str = ".xenoid/frida",
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
        """Base image for runtime-context builds: host-appropriate stock image."""
        if self.cfg.image == DEFAULT_IMAGE:
            return default_image_for_host(host_info().get("machine"))
        return self.cfg.image

    def make_runtime_context(self, image: Optional[str] = None) -> dict[str, Any]:
        script = Path(__file__).resolve().parents[2] / "scripts" / "make-runtime-context.sh"
        proc = run([str(script), image or self.base_image_for_build()], env=self.docker_env())
        return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip(), "context": proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else None}

    def ensure_rootfs_images(self) -> dict[str, Any]:
        """Build/refresh the ext4 rootfs+data loop images the pivot entrypoint needs."""
        script = Path(__file__).resolve().parents[2] / "scripts" / "make-rootfs-image.sh"
        cmd = [str(script), self.effective_image(), self.cfg.android_data_volume]
        env = self.docker_env()
        ssh_cmd = self.remote_docker_ssh_cmd()
        if ssh_cmd:
            env["XENOID_ENGINE_SSH"] = ssh_cmd[-1]
            if "-p" in ssh_cmd:
                env["XENOID_ENGINE_SSH_PORT"] = ssh_cmd[ssh_cmd.index("-p") + 1]
        proc = run(cmd, timeout=1800, env=env)
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "command": cmd,
            "stdout": proc.stdout.strip()[-2000:],
            "stderr": proc.stderr.strip()[-2000:],
        }

    def make_ota_bundle(self, version: str = "0.1.0") -> dict[str, Any]:
        script = Path(__file__).resolve().parents[2] / "scripts" / "make-ota-bundle.sh"
        proc = run([str(script), version])
        return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip(), "bundle": proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else None}

    def apply_ota_bundle(self, bundle_path: str) -> dict[str, Any]:
        bundle = Path(bundle_path).expanduser().resolve()
        if not bundle.exists():
            return {"ok": False, "error": f"OTA bundle not found: {bundle}"}
        work = Path(".xenoid/ota/staged").resolve()
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

    def netctl_status(self, ifname: str = "eth0") -> dict[str, Any]:
        safe_ifname = "".join(c for c in ifname if c.isalnum() or c in "_.:-") or "eth0"
        cmd = "test -x /data/local/tmp/xenoid-netctl && /data/local/tmp/xenoid-netctl status " + safe_ifname + " || echo '{\"ok\":false,\"error\":\"netctl-helper-missing\"}'"
        r = self.adb(["shell", cmd])
        out: dict[str, Any] = {"ok": bool(r.get("ok")), "adb": r}
        try:
            out["status"] = json.loads(str(r.get("stdout") or "{}"))
            out["ok"] = bool(out["status"].get("ok"))
        except Exception as e:
            out["ok"] = False; out["error"] = str(e)
        return out

    def netctl_set_mac(self, mac: str, ifname: str = "eth0") -> dict[str, Any]:
        safe_ifname = "".join(c for c in ifname if c.isalnum() or c in "_.:-") or "eth0"
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
        frida_bin = which("frida")
        if frida_bin is None:
            return {"ok": False, "error": "frida CLI not found; install frida-tools", "fix": "python3 -m pip install frida-tools"}
        script = Path(script_path).expanduser().resolve()
        if not script.exists():
            return {"ok": False, "error": f"script not found: {script}"}
        # -t 30: frida-tools quiet mode exits immediately after _ready when the
        # timeout is 0 (repl.py waits only when _quiet_timeout > 0); scripts with
        # delayed callbacks (self-tests, scan capture) need the linger window.
        cmd = [frida_bin, "-U", "-q", "-t", "30", "--exit-on-error"]
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

    def generate_profile_frida(self, profile_path: str, out: str = ".xenoid/frida/generated-profile.js", keep_unique: bool = False) -> dict[str, Any]:
        script = Path(__file__).resolve().parents[2] / "scripts" / "generate-profile-frida.py"
        cmd = [str(script), profile_path, "--out", out]
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
        script = Path(__file__).resolve().parents[2] / "scripts" / "automation-plan.py"
        proc = run([str(script), script_path])
        data: dict[str, Any] = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip()}
        try:
            data.update(json.loads(proc.stdout))
        except Exception:
            pass
        return data

    def automation_run_host(self, script_path: str, execute: bool = False, endpoint: str = "http://127.0.0.1:18765") -> dict[str, Any]:
        node = which("node")
        runner = Path(__file__).resolve().parents[2] / "scripts" / "xenoid-js-runner.mjs"
        if node is None:
            plan = self.automation_plan(script_path)
            plan["node"] = False
            plan["note"] = "node not found; returned static automation plan"
            return plan
        cmd = [node, str(runner), str(Path(script_path).resolve()), f"--endpoint={endpoint}"]
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

    def generate_service_frida(self, profile_path: str, out: str = ".xenoid/frida/generated-service-profile.js", keep_unique: bool = False) -> dict[str, Any]:
        script = Path(__file__).resolve().parents[2] / "scripts" / "generate-service-frida.py"
        cmd = [str(script), profile_path, "--out", out]
        if keep_unique:
            cmd.append("--keep-unique")
        proc = run(cmd)
        data: dict[str, Any] = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip(), "command": cmd}
        try:
            data.update(json.loads(proc.stdout))
        except Exception:
            pass
        return data

    def make_compose(self, out: str = "dist/docker-compose.yml") -> dict[str, Any]:
        script = Path(__file__).resolve().parents[2] / "scripts" / "make-compose.py"
        proc = run([str(script), "--out", out])
        data = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip()}
        try:
            data.update(json.loads(proc.stdout))
        except Exception:
            pass
        return data

    def runtime_logs(self, out_dir: str = ".xenoid/logs") -> dict[str, Any]:
        out = Path(out_dir).expanduser().resolve(); out.mkdir(parents=True, exist_ok=True)
        result: dict[str, Any] = {"ok": True, "outDir": str(out), "files": {}}
        if which("docker") is not None:
            logs = run([*self.docker_base_cmd(), "logs", self.cfg.container_name])
            p = out / "docker.log"; p.write_text((logs.stdout or "") + (logs.stderr or "")); result["files"]["docker"] = str(p)
            inspect = run([*self.docker_base_cmd(), "inspect", self.cfg.container_name])
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
        # redroid images commonly lack an Opus encoder; scrcpy 4.x enables audio by default.
        # Disable audio for the default Xenoid view path to avoid server startup failure.
        proc = run([scrcpy, "-s", self.adb_target, "--no-audio", "--video-codec=h264", "--max-size=1024"], capture=True)
        return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
