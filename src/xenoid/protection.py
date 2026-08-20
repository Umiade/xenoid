from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time
import stat
from typing import Any, Mapping, Optional, Sequence

from .process import run_bounded
from .util import bounded_timeout, run


SCHEMA = "dev.xenoid.shared-protection/v1"
STATE_PARENT = "/var/lib/xenoid"
STATE_PATH = "/var/lib/xenoid/shared-protection/v1.json"
STATE_DIRECTORY = "/var/lib/xenoid/shared-protection"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_BUILD_ID = re.compile(r"[0-9a-f]{40}")
_RESOURCE_TAG = re.compile(r"[0-9a-f]{12}")
_INSTANCE_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)

KMOD_MODULES = ("xenoid_kmod",)
KMOD_PROBES = (
    "security_socket_create",
    "security_netlink_send",
    "binder_transaction",
    "vfs_statfs",
)
EBPF_LINKS = ("path", "selinuxPermission", "unameEntry", "unameReturn")
EBPF_MAPS = ("denyCount", "policyIdentity")
EBPF_PROBES = ("linkInventory", "unprivilegedDeny")


class SharedProtectionError(RuntimeError):
    def __init__(self, code: str, message: Optional[str] = None):
        super().__init__(message or code)
        self.code = code


@dataclass(frozen=True)
class ProtectionInputs:
    engine_id: str
    kernel_digest: str
    kmod_input_digest: str
    ebpf_input_digest: str
    expected_digest: str


@dataclass(frozen=True)
class RuntimeInventory:
    active_count: int
    sibling_active: bool
    inventory_digest: str
    inventory_count: int


@dataclass(frozen=True)
class BuildArtifacts:
    transaction: str
    kmod_build_id: str
    kmod_sha256: str
    ebpf_sha256: str


class SharedProtectionManager:
    """One deployment owner for protection shared by a Docker engine host.

    The RuntimeManager adapter supplies the selected Docker/Colima/SSH transport,
    the engine-host lock, and bounded command execution. Public results contain
    only safe codes, counts, logical inventory names, and content digests.
    """

    def __init__(self, runtime: Any):
        self.runtime = runtime
        self.project_root = Path(runtime.context.project_root)

    @staticmethod
    def _canonical(value: Any) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

    @classmethod
    def _digest(cls, value: Any) -> str:
        return hashlib.sha256(cls._canonical(value)).hexdigest()

    @staticmethod
    def _safe_error(exc: BaseException, fallback: str) -> str:
        code = getattr(exc, "code", None)
        return code if isinstance(code, str) and code.startswith("shared_protection_") else fallback

    def _source_digest(self, relative_paths: Sequence[str]) -> str:
        entries: list[dict[str, Any]] = []
        root = self.project_root.resolve(strict=True)
        for relative in sorted(set(relative_paths)):
            path = self.project_root / relative
            descriptor: Optional[int] = None
            try:
                parent = path.parent.resolve(strict=True)
                parent.relative_to(root)
                initial = path.lstat()
                if (
                    not stat.S_ISREG(initial.st_mode)
                    or initial.st_nlink != 1
                    or path.is_symlink()
                ):
                    raise SharedProtectionError(
                        "shared_protection_source_invalid"
                    )
                descriptor = os.open(
                    path,
                    os.O_RDONLY
                    | os.O_CLOEXEC
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                opened = os.fstat(descriptor)
                identity = (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_size,
                    opened.st_mtime_ns,
                    opened.st_mode,
                    opened.st_nlink,
                )
                if identity != (
                    initial.st_dev,
                    initial.st_ino,
                    initial.st_size,
                    initial.st_mtime_ns,
                    initial.st_mode,
                    initial.st_nlink,
                ):
                    raise SharedProtectionError(
                        "shared_protection_source_invalid"
                    )
                digest = hashlib.sha256()
                size = 0
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 32 * 1024 * 1024:
                        raise SharedProtectionError(
                            "shared_protection_source_invalid"
                        )
                    digest.update(chunk)
                final = os.fstat(descriptor)
                if identity != (
                    final.st_dev,
                    final.st_ino,
                    final.st_size,
                    final.st_mtime_ns,
                    final.st_mode,
                    final.st_nlink,
                ) or size != opened.st_size:
                    raise SharedProtectionError(
                        "shared_protection_source_changed"
                    )
                entries.append(
                    {
                        "path": relative,
                        "mode": stat.S_IMODE(opened.st_mode),
                        "size": size,
                        "sha256": digest.hexdigest(),
                    }
                )
            except SharedProtectionError:
                raise
            except (OSError, ValueError) as exc:
                raise SharedProtectionError(
                    "shared_protection_source_invalid"
                ) from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        return self._digest(entries)

    def _docker_identity(self) -> str:
        command = [
            *self.runtime.docker_base_cmd(),
            "info",
            "--format",
            "{{.ID}}|{{.ServerVersion}}|{{.OSType}}|{{.Architecture}}|{{.Driver}}",
        ]
        proc = run(command, timeout=30, env=self.runtime.docker_env())
        value = (proc.stdout or "").strip()
        if proc.returncode != 0 or not value or len(value) > 1024:
            raise SharedProtectionError("shared_protection_engine_unavailable")
        endpoint = str(self.runtime.docker_endpoint_host() or "local")
        transport = (
            "ssh"
            if endpoint.startswith("ssh://")
            else "tcp"
            if endpoint.startswith("tcp://")
            else "colima"
            if self.runtime.should_use_colima()
            else "local"
        )
        if transport == "tcp":
            raise SharedProtectionError("shared_protection_engine_unavailable")
        return self._digest({"docker": value})

    def _engine_facts(self) -> dict[str, str]:
        script = r'''
set -eu
sha_stream() { sha256sum | cut -d ' ' -f 1; }
file_hash() { if [ -r "$1" ] && [ -f "$1" ]; then resolved=$(readlink -f -- "$1") && [ -f "$resolved" ] && sha256sum "$resolved" | cut -d ' ' -f 1; else printf missing; fi; }
tool_hash() {
    if ! path=$(command -v "$1" 2>/dev/null); then printf missing; return; fi
    resolved=$(readlink -f -- "$path" 2>/dev/null || true)
    {
        if [ -n "$resolved" ] && [ -f "$resolved" ]; then
            sha256sum "$resolved"
            stat -c '%u:%g:%a:%s' "$resolved"
        else
            printf 'builtin:%s\n' "$path"
        fi
        "$1" --version 2>&1 || "$1" version 2>&1 || true
    } | sha_stream
}
libbpf_hash() {
    library=$(ldconfig -p 2>/dev/null | awk '$1 ~ /^libbpf[.]so/ {print $NF; exit}')
    if [ -z "$library" ] && ! command -v pkg-config >/dev/null 2>&1; then
        printf missing
        return
    fi
    {
        if [ -n "$library" ]; then file_hash "$library"; fi
        if command -v pkg-config >/dev/null 2>&1; then
            pkg-config --modversion libbpf 2>/dev/null || true
            pkg-config --libs --cflags libbpf 2>/dev/null || true
        fi
    } | sha_stream
}
tree_hash() {
    resolved=$(readlink -f -- "$1" 2>/dev/null || true)
    if [ -z "$resolved" ] || [ ! -d "$resolved" ]; then printf missing; return; fi
    (cd "$resolved" && find -L . -xdev -type f -print0 | LC_ALL=C sort -z |
        xargs -0r sha256sum) | sha_stream
}
library_hash() {
    pattern="$1"
    library=$(ldconfig -p 2>/dev/null | awk -v p="$pattern" '$1 ~ p {print $NF; exit}')
    if [ -n "$library" ]; then file_hash "$library"; else printf missing; fi
}
kernel=$(uname -r)
printf 'kernelReleaseSha256=%s\n' "$(printf %s "$kernel" | sha_stream)"
if [ -r /proc/config.gz ]; then config=$(gzip -cd /proc/config.gz | sha_stream); elif [ -r "/boot/config-$kernel" ]; then config=$(file_hash "/boot/config-$kernel"); else config=missing; fi
printf 'kernelConfigSha256=%s\n' "$config"
printf 'btfSha256=%s\n' "$(file_hash /sys/kernel/btf/vmlinux)"
printf 'headersSha256=%s\n' "$(tree_hash "/lib/modules/$kernel/build")"
printf 'moduleSymversSha256=%s\n' "$(file_hash "/lib/modules/$kernel/build/Module.symvers")"
printf 'userspaceHeadersSha256=%s\n' "$({ tree_hash /usr/include/bpf; tree_hash /usr/include/linux; file_hash /usr/include/elf.h; } | sha_stream)"
symbols=$(awk '$3 ~ /^vfs_statfs([.]|$)/ || $3 == "security_socket_create" || $3 == "security_netlink_send" || $3 == "binder_transaction" {print $3}' /proc/kallsyms | LC_ALL=C sort -u | sha_stream)
printf 'symbolsSha256=%s\n' "$symbols"
printf 'clangSha256=%s\n' "$(tool_hash clang)"
printf 'bpftoolSha256=%s\n' "$(tool_hash bpftool)"
printf 'llvmStripSha256=%s\n' "$(tool_hash llvm-strip)"
printf 'ccSha256=%s\n' "$(tool_hash cc)"
printf 'makeSha256=%s\n' "$(tool_hash make)"
printf 'libbpfSha256=%s\n' "$(libbpf_hash)"
printf 'libelfSha256=%s\n' "$(library_hash '^libelf[.]so')"
printf 'zlibSha256=%s\n' "$(library_hash '^libz[.]so')"
printf 'bpfLsmSha256=%s\n' "$(if [ -r /sys/kernel/security/lsm ]; then cat /sys/kernel/security/lsm | sha_stream; else printf missing; fi)"
'''
        proc = self.runtime._engine_host_shell(script, timeout=60)
        if proc.returncode != 0:
            raise SharedProtectionError("shared_protection_engine_unavailable")
        facts: dict[str, str] = {}
        for line in (proc.stdout or "").splitlines():
            key, separator, value = line.partition("=")
            if not separator or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]+", key):
                continue
            if value != "missing" and _SHA256.fullmatch(value) is None:
                raise SharedProtectionError("shared_protection_engine_probe_invalid")
            facts[key] = value
        expected = {
            "kernelReleaseSha256",
            "kernelConfigSha256",
            "btfSha256",
            "headersSha256",
            "moduleSymversSha256",
            "userspaceHeadersSha256",
            "symbolsSha256",
            "clangSha256",
            "llvmStripSha256",
            "bpftoolSha256",
            "ccSha256",
            "makeSha256",
            "libbpfSha256",
            "libelfSha256",
            "zlibSha256",
            "bpfLsmSha256",
        }
        if set(facts) != expected:
            raise SharedProtectionError("shared_protection_engine_probe_invalid")
        return facts

    def inputs(self) -> ProtectionInputs:
        engine_id = self._docker_identity()
        facts = self._engine_facts()
        kernel_digest = self._digest(
            {
                key: facts[key]
                for key in (
                    "kernelReleaseSha256",
                    "kernelConfigSha256",
                    "btfSha256",
                    "headersSha256",
                    "moduleSymversSha256",
                    "userspaceHeadersSha256",
                    "symbolsSha256",
                    "bpfLsmSha256",
                )
            }
        )
        kmod_source = self._source_digest(
            (
                "native/xenoid-kmod/Makefile",
                "native/xenoid-kmod/xenoid_kmod.c",
                "scripts/build-kmod.sh",
                "scripts/with-shared-protection-lock.py",
            )
        )
        ebpf_source = self._source_digest(
            (
                "native/xenoid-ebpf/Makefile",
                "native/xenoid-ebpf/loader.c",
                "native/xenoid-ebpf/xenoid_pathhide.bpf.c",
                "scripts/build-ebpf.sh",
                "scripts/load-ebpf.sh",
                "scripts/smoke-ebpf.sh",
                "scripts/with-shared-protection-lock.py",
            )
        )
        kmod_input = self._digest(
            {
                "engineId": engine_id,
                "kernelDigest": kernel_digest,
                "sourceSha256": kmod_source,
                "tools": {
                    "cc": facts["ccSha256"],
                    "make": facts["makeSha256"],
                    "moduleSymvers": facts["moduleSymversSha256"],
                },
                "modules": list(KMOD_MODULES),
                "probes": list(KMOD_PROBES),
            }
        )
        ebpf_input = self._digest(
            {
                "engineId": engine_id,
                "kernelDigest": kernel_digest,
                "sourceSha256": ebpf_source,
                "tools": {
                    "clang": facts["clangSha256"],
                    "llvmStrip": facts["llvmStripSha256"],
                    "userspaceHeaders": facts["userspaceHeadersSha256"],
                    "bpftool": facts["bpftoolSha256"],
                    "libbpf": facts["libbpfSha256"],
                    "libelf": facts["libelfSha256"],
                    "zlib": facts["zlibSha256"],
                    "make": facts["makeSha256"],
                },
                "attachModes": ["lsm", "fmod_ret", "kprobe"],
                "links": list(EBPF_LINKS),
                "maps": list(EBPF_MAPS),
                "probes": list(EBPF_PROBES),
            }
        )
        expected_digest = self._deployment_digest(
            engine_id,
            kernel_digest,
            kmod_input,
            ebpf_input,
        )
        return ProtectionInputs(
            engine_id=engine_id,
            kernel_digest=kernel_digest,
            kmod_input_digest=kmod_input,
            ebpf_input_digest=ebpf_input,
            expected_digest=expected_digest,
        )

    @classmethod
    def _deployment_digest(
        cls,
        engine_id: str,
        kernel_digest: str,
        kmod_input: str,
        ebpf_input: str,
    ) -> str:
        return cls._digest(
            {
                "schema": SCHEMA,
                "engineId": engine_id,
                "kernelDigest": kernel_digest,
                "kmodInputDigest": kmod_input,
                "ebpfInputDigest": ebpf_input,
                "inventory": {
                    "modules": list(KMOD_MODULES),
                    "links": list(EBPF_LINKS),
                    "maps": list(EBPF_MAPS),
                    "probes": [*KMOD_PROBES, *EBPF_PROBES],
                },
            }
        )

    @staticmethod
    def _last_json(stdout: str) -> dict[str, Any]:
        for line in reversed(stdout.splitlines()):
            value = line.strip()
            if not value.startswith("{") or not value.endswith("}"):
                continue
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
        return {}

    def _run_script(self, command: list[str], *, timeout: int = 1200) -> dict[str, Any]:
        capability = self.runtime._shared_protection_capability
        environment = self.runtime.docker_env()
        if (
            isinstance(capability, str)
            and _SHA256.fullmatch(capability) is not None
        ):
            environment["XENOID_SHARED_PROTECTION_CAPABILITY"] = capability
        else:
            environment.pop("XENOID_SHARED_PROTECTION_CAPABILITY", None)
        seconds = bounded_timeout(float(timeout)) or float(timeout)
        proc = run_bounded(
            command,
            cwd=self.project_root,
            deadline=time.monotonic() + max(0.001, seconds),
            cancelled=getattr(self.runtime, "cancellation_event", None),
            env=environment,
            project_root=self.project_root,
        )
        result = self._last_json(proc.stdout_tail or "")
        if proc.state == "timed_out":
            result = {
                "ok": False,
                "error": "shared_protection_timeout",
            }
        elif proc.state == "cancelled":
            result = {
                "ok": False,
                "error": "shared_protection_cancelled",
            }
        elif not result:
            result = {
                "ok": False,
                "error": proc.error_code or "shared_protection_command_failed",
            }
        if proc.state != "passed" or proc.returncode != 0:
            result["ok"] = False
            if not isinstance(result.get("error"), str):
                result["error"] = (
                    proc.error_code or "shared_protection_command_failed"
                )
        return result

    def _ebpf_command(
        self,
        action: str,
        *,
        input_digest: Optional[str] = None,
        artifact_sha256: Optional[str] = None,
        transaction: Optional[str] = None,
        maintenance: bool = False,
        preserve_record: bool = False,
    ) -> list[str]:
        base = self.runtime.ebpf_action_command(action)
        command = list(base[:-1])
        if input_digest is not None:
            command.extend(("--input-digest", input_digest))
        if artifact_sha256 is not None:
            command.extend(("--artifact-sha256", artifact_sha256))
        if transaction is not None:
            command.extend(("--transaction", transaction))
        if maintenance:
            command.append("--maintenance")
        if preserve_record:
            command.append("--preserve-record")
        command.append(action)
        return command

    def _native_kmod_status(self) -> dict[str, Any]:
        script = r'''
set -eu
if [ ! -d /sys/module/xenoid_kmod ]; then printf '{"ok":false,"loaded":false,"digest":null,"artifactSha256":null,"buildId":null,"probes":[]}\n'; exit 0; fi
digest=$(cat /sys/module/xenoid_kmod/parameters/deployment_digest 2>/dev/null || true)
artifact=$(cat /sys/module/xenoid_kmod/parameters/artifact_digest 2>/dev/null || true)
build_id=$(od -An -tx1 /sys/module/xenoid_kmod/notes/.note.gnu.build-id 2>/dev/null | tr -d ' \n' | tail -c 40)
case "$digest:$artifact:$build_id" in *[!0-9a-f:]* ) digest=invalid; artifact=invalid; build_id=invalid;; esac
if [ "${#digest}" -ne 64 ] || [ "${#artifact}" -ne 64 ] || [ "${#build_id}" -ne 40 ]; then digest=invalid; artifact=invalid; build_id=invalid; fi
if [ "$digest" = invalid ]; then printf '{"ok":false,"loaded":true,"digest":null,"artifactSha256":null,"buildId":null,"probes":[]}\n'; exit 0; fi
test -r /sys/fs/selinux/enforce
test -r /sys/fs/selinux/policyvers
printf '{"ok":true,"loaded":true,"digest":"%s","artifactSha256":"%s","buildId":"%s","probes":["security_socket_create","security_netlink_send","binder_transaction","vfs_statfs"]}\n' "$digest" "$artifact" "$build_id"
'''
        proc = self.runtime._engine_host_shell(script, timeout=30)
        data = self._last_json(proc.stdout or "")
        if proc.returncode != 0 or not data:
            return {
                "ok": False,
                "loaded": False,
                "digest": None,
                "probes": [],
                "error": "shared_protection_kmod_status_failed",
            }
        digest = data.get("digest")
        artifact_sha = data.get("artifactSha256")
        build_id = data.get("buildId")
        probes = data.get("probes")
        ok = (
            data.get("ok") is True
            and _SHA256.fullmatch(digest or "") is not None
            and _SHA256.fullmatch(artifact_sha or "") is not None
            and _BUILD_ID.fullmatch(build_id or "") is not None
            and probes == list(KMOD_PROBES)
        )
        return {
            "ok": ok,
            "loaded": data.get("loaded") is True,
            "digest": digest if _SHA256.fullmatch(digest or "") else None,
            "artifactSha256": (
                artifact_sha
                if _SHA256.fullmatch(artifact_sha or "")
                else None
            ),
            "buildId": (
                build_id if _BUILD_ID.fullmatch(build_id or "") else None
            ),
            "modules": list(KMOD_MODULES) if data.get("loaded") is True else [],
            "probes": list(KMOD_PROBES) if ok else [],
            **({} if ok else {"error": "shared_protection_kmod_not_ready"}),
        }

    def _native_ebpf_status(self) -> dict[str, Any]:
        result = self._run_script(self._ebpf_command("status"), timeout=60)
        digest = result.get("digest")
        artifact_sha = result.get("artifactSha256")
        program_tags = result.get("programTags")
        links = result.get("links")
        maps = result.get("maps")
        probes = result.get("probes")
        attach = result.get("attach")
        ok = (
            result.get("ok") is True
            and result.get("loaded") is True
            and _SHA256.fullmatch(digest or "") is not None
            and _SHA256.fullmatch(artifact_sha or "") is not None
            and _SHA256.fullmatch(program_tags or "") is not None
            and links == list(EBPF_LINKS)
            and maps == list(EBPF_MAPS)
            and probes == list(EBPF_PROBES)
            and attach in {"lsm", "fmod_ret", "kprobe"}
        )
        return {
            "ok": ok,
            "loaded": result.get("loaded") is True,
            "digest": digest if _SHA256.fullmatch(digest or "") else None,
            "artifactSha256": (
                artifact_sha
                if _SHA256.fullmatch(artifact_sha or "")
                else None
            ),
            "programTags": (
                program_tags
                if _SHA256.fullmatch(program_tags or "")
                else None
            ),
            "attach": attach if attach in {"lsm", "fmod_ret", "kprobe"} else None,
            "links": list(EBPF_LINKS) if links == list(EBPF_LINKS) else [],
            "maps": list(EBPF_MAPS) if maps == list(EBPF_MAPS) else [],
            "probes": list(EBPF_PROBES) if probes == list(EBPF_PROBES) else [],
            **({} if ok else {"error": str(result.get("error") or "shared_protection_ebpf_not_ready")}),
        }

    def _read_record(self) -> Optional[dict[str, Any]]:
        script = f'''
set -eu
p={STATE_PATH!r}
d={STATE_DIRECTORY!r}
parent={STATE_PARENT!r}
if [ -e "$parent" ]; then
    [ -d "$parent" ] && [ ! -L "$parent" ]
    [ "$(stat -c '%u:%g:%a' "$parent")" = '0:0:755' ]
fi
if [ -e "$d" ]; then
    [ -d "$d" ] && [ ! -L "$d" ]
    [ "$(stat -c '%u:%g:%a' "$d")" = '0:0:700' ]
fi
current="$d/current"
loader="$current/xenoid-ebpf-loader"
if [ -e "$current" ]; then
    [ -d "$current" ] && [ ! -L "$current" ]
    [ "$(stat -c '%u:%g:%a' "$current")" = '0:0:700' ]
fi
if [ -e "$loader" ]; then
    [ -f "$loader" ] && [ ! -L "$loader" ]
    [ "$(stat -c '%u:%g:%a:%h' "$loader")" = '0:0:700:1' ]
fi
if [ ! -e "$p" ]; then printf 'ABSENT\n'; exit 0; fi
[ -f "$p" ] && [ ! -L "$p" ]
[ "$(stat -c '%u:%g:%a:%h' "$p")" = '0:0:600:1' ]
size=$(stat -c %s "$p"); [ "$size" -gt 0 ] && [ "$size" -le 65536 ]
printf 'PRESENT\n'
base64 < "$p"
'''
        proc = self.runtime._engine_host_shell(script, timeout=30)
        lines = (proc.stdout or "").splitlines()
        if proc.returncode != 0 or not lines:
            raise SharedProtectionError("shared_protection_state_invalid")
        if lines[0] == "ABSENT":
            return None
        if lines[0] != "PRESENT":
            raise SharedProtectionError("shared_protection_state_invalid")
        try:
            raw = base64.b64decode("".join(lines[1:]), validate=True)
            if len(raw) > 65536 or not raw.endswith(b"\n"):
                raise ValueError
            value = json.loads(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            raise SharedProtectionError("shared_protection_state_invalid") from exc
        self._validate_record(value)
        canonical = self._canonical(value) + b"\n"
        if raw != canonical:
            raise SharedProtectionError("shared_protection_state_invalid")
        return value

    @classmethod
    def _validate_record(cls, value: Any) -> None:
        top = {
            "schema",
            "engineId",
            "kernelDigest",
            "expectedDigest",
            "currentDigest",
            "lastKnownGoodDigest",
            "inventory",
            "kmod",
            "ebpf",
        }
        if not isinstance(value, dict) or set(value) != top or value.get("schema") != SCHEMA:
            raise SharedProtectionError("shared_protection_state_invalid")
        for key in (
            "engineId",
            "kernelDigest",
            "expectedDigest",
            "currentDigest",
            "lastKnownGoodDigest",
        ):
            if _SHA256.fullmatch(value.get(key, "")) is None:
                raise SharedProtectionError("shared_protection_state_invalid")
        inventory = value.get("inventory")
        if inventory != {
            "modules": list(KMOD_MODULES),
            "links": list(EBPF_LINKS),
            "maps": list(EBPF_MAPS),
            "probes": [*KMOD_PROBES, *EBPF_PROBES],
        }:
            raise SharedProtectionError("shared_protection_state_invalid")
        kmod = value.get("kmod")
        ebpf = value.get("ebpf")
        if (
            not isinstance(kmod, dict)
            or set(kmod) != {"inputDigest", "artifactSha256", "buildId"}
            or _BUILD_ID.fullmatch(str(kmod.get("buildId") or "")) is None
        ):
            raise SharedProtectionError("shared_protection_state_invalid")
        if (
            not isinstance(ebpf, dict)
            or set(ebpf)
            != {"inputDigest", "artifactSha256", "attachMode", "programTags"}
            or _SHA256.fullmatch(str(ebpf.get("programTags") or "")) is None
        ):
            raise SharedProtectionError("shared_protection_state_invalid")
        for component in (kmod, ebpf):
            if _SHA256.fullmatch(component.get("inputDigest", "")) is None or _SHA256.fullmatch(
                component.get("artifactSha256", "")
            ) is None:
                raise SharedProtectionError("shared_protection_state_invalid")
        if ebpf.get("attachMode") not in {"lsm", "fmod_ret", "kprobe"}:
            raise SharedProtectionError("shared_protection_state_invalid")
        recomputed = cls._deployment_digest(
            str(value["engineId"]),
            str(value["kernelDigest"]),
            str(kmod["inputDigest"]),
            str(ebpf["inputDigest"]),
        )
        if (
            value["expectedDigest"] != recomputed
            or value["currentDigest"] != recomputed
            or value["lastKnownGoodDigest"] != recomputed
        ):
            raise SharedProtectionError("shared_protection_state_invalid")

    def _validate_artifact_parent(self, component: str, input_digest: str) -> None:
        if (
            component not in {"kmod", "ebpf"}
            or _SHA256.fullmatch(input_digest) is None
        ):
            raise SharedProtectionError("shared_protection_artifact_invalid")
        directories = (
            STATE_DIRECTORY,
            f"{STATE_DIRECTORY}/artifacts",
            f"{STATE_DIRECTORY}/artifacts/{component}",
            f"{STATE_DIRECTORY}/artifacts/{component}/{input_digest}",
        )
        script = (
            "set -eu; parent="
            + repr(STATE_PARENT)
            + "; if [ -e \"$parent\" ]; then [ -d \"$parent\" ] && [ ! -L \"$parent\" ]; "
            + "[ \"$(stat -c '%u:%g:%a' \"$parent\")\" = '0:0:755' ]; fi; "
            + "for d in "
            + " ".join(repr(value) for value in directories)
            + "; do if [ -e \"$d\" ]; then [ -d \"$d\" ] && [ ! -L \"$d\" ]; "
            + "[ \"$(stat -c '%u:%g:%a' \"$d\")\" = '0:0:700' ]; fi; done"
        )
        proc = self.runtime._engine_host_shell(script, timeout=30)
        if proc.returncode != 0:
            raise SharedProtectionError("shared_protection_artifact_invalid")

    def _artifact_valid(
        self,
        component: str,
        input_digest: str,
        expected_sha: str,
    ) -> bool:
        if (
            component not in {"kmod", "ebpf"}
            or _SHA256.fullmatch(input_digest) is None
            or _SHA256.fullmatch(expected_sha) is None
        ):
            return False
        name = "xenoid_kmod.ko" if component == "kmod" else "xenoid-ebpf-loader"
        directory = f"{STATE_DIRECTORY}/artifacts/{component}/{input_digest}"
        path = f"{directory}/{name}"
        mode = "600" if component == "kmod" else "700"
        script = (
            "set -eu; parent="
            + repr(STATE_PARENT)
            + "; [ -d \"$parent\" ] && [ ! -L \"$parent\" ]; "
            + "[ \"$(stat -c '%u:%g:%a' \"$parent\")\" = '0:0:755' ]; "
            + "for d in "
            + " ".join(
                repr(value)
                for value in (
                    STATE_DIRECTORY,
                    f"{STATE_DIRECTORY}/artifacts",
                    f"{STATE_DIRECTORY}/artifacts/{component}",
                    directory,
                )
            )
            + "; do [ -d \"$d\" ] && [ ! -L \"$d\" ]; "
            + "[ \"$(stat -c '%u:%g:%a' \"$d\")\" = '0:0:700' ]; done; p="
            + repr(path)
            + "; [ -f \"$p\" ] && [ ! -L \"$p\" ]; "
            + f"[ \"$(stat -c '%u:%g:%a:%h' \"$p\")\" = '0:0:{mode}:1' ]; "
            + "sha256sum \"$p\" | cut -d ' ' -f 1"
        )
        proc = self.runtime._engine_host_shell(script, timeout=30)
        return (
            proc.returncode == 0
            and (proc.stdout or "").strip() == expected_sha
        )

    def _current_loader_valid(self, expected_sha: str) -> bool:
        if _SHA256.fullmatch(expected_sha) is None:
            return False
        script = (
            "set -eu; p=/var/lib/xenoid/shared-protection/current/"
            "xenoid-ebpf-loader; [ -f \"$p\" ] && [ ! -L \"$p\" ]; "
            "[ \"$(stat -c '%u:%g:%a:%h' \"$p\")\" = '0:0:700:1' ]; "
            "sha256sum \"$p\" | cut -d ' ' -f 1"
        )
        result = self.runtime._engine_host_shell(script, timeout=30)
        return (
            result.returncode == 0
            and (result.stdout or "").strip() == expected_sha
        )

    def _record_valid_for(
        self,
        record: Optional[Mapping[str, Any]],
        inputs: ProtectionInputs,
        current_digest: Optional[str],
        attach_mode: Optional[str],
        kmod_artifact_sha256: Optional[str],
        ebpf_artifact_sha256: Optional[str],
        kmod_build_id: Optional[str],
        ebpf_program_tags: Optional[str],
    ) -> bool:
        if record is None or current_digest is None:
            return False
        if any(
            (
                record.get("engineId") != inputs.engine_id,
                record.get("kernelDigest") != inputs.kernel_digest,
                record.get("expectedDigest") != inputs.expected_digest,
                record.get("currentDigest") != current_digest,
                record.get("lastKnownGoodDigest") != current_digest,
                record.get("kmod", {}).get("inputDigest")
                != inputs.kmod_input_digest,
                record.get("ebpf", {}).get("inputDigest")
                != inputs.ebpf_input_digest,
                record.get("ebpf", {}).get("attachMode") != attach_mode,
                record.get("kmod", {}).get("artifactSha256")
                != kmod_artifact_sha256,
                record.get("ebpf", {}).get("artifactSha256")
                != ebpf_artifact_sha256,
                record.get("kmod", {}).get("buildId") != kmod_build_id,
                record.get("ebpf", {}).get("programTags")
                != ebpf_program_tags,
            )
        ):
            return False
        return (
            self._artifact_valid(
                "kmod",
                inputs.kmod_input_digest,
                str(record["kmod"]["artifactSha256"]),
            )
            and self._artifact_valid(
                "ebpf",
                inputs.ebpf_input_digest,
                str(record["ebpf"]["artifactSha256"]),
            )
            and self._current_loader_valid(
                str(record["ebpf"]["artifactSha256"])
            )
        )

    def _runtime_inventory(self) -> RuntimeInventory:
        list_command = [
            *self.runtime.docker_base_cmd(),
            "ps",
            "-aq",
            "--filter",
            "label=dev.xenoid.owner=xenoid",
        ]
        proc = run(list_command, timeout=30, env=self.runtime.docker_env())
        if proc.returncode != 0:
            raise SharedProtectionError("shared_protection_ownership_ambiguous")
        ids = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
        if any(re.fullmatch(r"[0-9a-f]{12,64}", value) is None for value in ids):
            raise SharedProtectionError("shared_protection_ownership_ambiguous")
        if not ids:
            return RuntimeInventory(0, False, self._digest([]), 0)
        inspected = run(
            [*self.runtime.docker_base_cmd(), "inspect", *ids],
            timeout=30,
            env=self.runtime.docker_env(),
        )
        if inspected.returncode != 0:
            raise SharedProtectionError("shared_protection_ownership_ambiguous")
        try:
            rows = json.loads(inspected.stdout or "")
        except json.JSONDecodeError as exc:
            raise SharedProtectionError("shared_protection_ownership_ambiguous") from exc
        if not isinstance(rows, list) or len(rows) != len(ids):
            raise SharedProtectionError("shared_protection_ownership_ambiguous")
        seen_instances: set[str] = set()
        seen_tags: set[str] = set()
        active = 0
        sibling_active = False
        inventory_rows: list[dict[str, Any]] = []
        for row in rows:
            config = row.get("Config") if isinstance(row, dict) else None
            labels = config.get("Labels") if isinstance(config, dict) else None
            state = row.get("State") if isinstance(row, dict) else None
            if not isinstance(labels, dict) or not isinstance(state, dict):
                raise SharedProtectionError("shared_protection_ownership_ambiguous")
            instance_id = labels.get("dev.xenoid.instance_id")
            resource_tag = labels.get("dev.xenoid.resource_tag")
            if (
                labels.get("dev.xenoid.owner") != "xenoid"
                or labels.get("dev.xenoid.schema") != "1"
                or _INSTANCE_ID.fullmatch(instance_id or "") is None
                or _RESOURCE_TAG.fullmatch(resource_tag or "") is None
                or not isinstance(labels.get("dev.xenoid.instance_name"), str)
                or not labels["dev.xenoid.instance_name"]
                or instance_id in seen_instances
                or resource_tag in seen_tags
            ):
                raise SharedProtectionError("shared_protection_ownership_ambiguous")
            seen_instances.add(instance_id)
            seen_tags.add(resource_tag)
            networks = row.get("NetworkSettings", {}).get("Networks", {})
            mounts = row.get("Mounts")
            inventory_rows.append({
                "instanceId": instance_id,
                "instanceName": labels["dev.xenoid.instance_name"],
                "resourceTag": resource_tag,
                "containerId": row.get("Id"),
                "imageId": row.get("Image"),
                "runtimeEpoch": labels.get("dev.xenoid.runtime_epoch"),
                "running": state.get("Running") is True,
                "volumes": sorted(
                    str(item.get("Name"))
                    for item in mounts
                    if isinstance(item, Mapping) and item.get("Type") == "volume"
                ) if isinstance(mounts, list) else [],
                "networks": sorted(
                    (
                        {
                            "name": str(name),
                            "id": str(value.get("NetworkID") or ""),
                            "ip": str(value.get("IPAddress") or ""),
                        }
                        for name, value in networks.items()
                        if isinstance(value, Mapping)
                    ),
                    key=lambda item: item["name"],
                ) if isinstance(networks, Mapping) else [],
            })
            if state.get("Running") is True:
                active += 1
                if instance_id != self.runtime.context.instance_id:
                    sibling_active = True
        inventory_rows.sort(key=lambda value: (value["instanceId"], value["containerId"] or ""))
        inventory_digest = hashlib.sha256(
            json.dumps(inventory_rows, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        return RuntimeInventory(
            active,
            sibling_active,
            inventory_digest,
            len(inventory_rows),
        )
    @staticmethod
    def _validate_transition_state(
        previous: Optional[Mapping[str, Any]],
        inputs: ProtectionInputs,
        kmod: Mapping[str, Any],
        ebpf: Mapping[str, Any],
    ) -> None:
        previous_kmod = (
            previous.get("kmod", {}).get("inputDigest")
            if isinstance(previous, Mapping)
            and isinstance(previous.get("kmod"), Mapping)
            else None
        )
        previous_ebpf = (
            previous.get("ebpf", {}).get("inputDigest")
            if isinstance(previous, Mapping)
            and isinstance(previous.get("ebpf"), Mapping)
            else None
        )
        for observed, desired, before in (
            (kmod, inputs.kmod_input_digest, previous_kmod),
            (ebpf, inputs.ebpf_input_digest, previous_ebpf),
        ):
            digest = observed.get("digest")
            loaded = observed.get("loaded") is True
            allowed = {desired}
            if isinstance(before, str):
                allowed.add(before)
            if loaded and (
                not isinstance(digest, str)
                or digest not in allowed
            ):
                raise SharedProtectionError(
                    "shared_protection_state_conflict"
                )


    def _unload_unbound_legacy_kmod(self) -> dict[str, Any]:
        result = self._run_script(
            [
                *self.runtime.build_kmod_command(),
                "--unload",
                "--maintenance",
            ],
            timeout=120,
        )
        if result.get("ok") is not True:
            raise SharedProtectionError(
                str(
                    result.get("error")
                    or "shared_protection_legacy_unload_failed"
                )
            )
        observed = self._native_kmod_status()
        if observed.get("loaded") is True:
            raise SharedProtectionError(
                "shared_protection_unload_unverified"
            )
        return observed

    def _observe(self, inputs: ProtectionInputs) -> tuple[dict[str, Any], dict[str, Any], Optional[str]]:
        kmod = self._native_kmod_status()
        ebpf = self._native_ebpf_status()
        current: Optional[str] = None
        if kmod.get("ok") is True and ebpf.get("ok") is True:
            current = self._deployment_digest(
                inputs.engine_id,
                inputs.kernel_digest,
                str(kmod["digest"]),
                str(ebpf["digest"]),
            )
        return kmod, ebpf, current

    def _status_locked(self) -> dict[str, Any]:
        try:
            inputs = self.inputs()
            inventory = self._runtime_inventory()
            record = self._read_record()
            kmod, ebpf, current = self._observe(inputs)
            state_valid = self._record_valid_for(
                record,
                inputs,
                current,
                ebpf.get("attach"),
                kmod.get("artifactSha256"),
                ebpf.get("artifactSha256"),
                kmod.get("buildId"),
                ebpf.get("programTags"),
            )
            native_matches = current == inputs.expected_digest
            ok = native_matches and state_valid
            kmod_replacement = (
                kmod.get("ok") is not True
                or kmod.get("digest") != inputs.kmod_input_digest
            )
            return {
                "ok": ok,
                "scope": "engine-host",
                "engineId": inputs.engine_id,
                "expectedDigest": inputs.expected_digest,
                "currentDigest": current,
                "reused": ok,
                "replacementRequired": not ok,
                "maintenanceRequired": bool(kmod_replacement),
                "siblingRuntimeActive": inventory.sibling_active,
                "activeRuntimeCount": inventory.active_count,
                "runtimeInventoryDigest": inventory.inventory_digest,
                "runtimeInventoryCount": inventory.inventory_count,
                "kernel": kmod,
                "ebpf": ebpf,
                **(
                    {}
                    if ok
                    else {
                        "error": "shared_protection_reload_requires_maintenance"
                        if kmod_replacement and inventory.active_count
                        else "shared_protection_state_invalid"
                        if native_matches and not state_valid
                        else "shared_protection_drift"
                    }
                ),
            }
        except BaseException as exc:
            return {
                "ok": False,
                "scope": "engine-host",
                "engineId": None,
                "expectedDigest": None,
                "currentDigest": None,
                "reused": False,
                "replacementRequired": True,
                "maintenanceRequired": False,
                "siblingRuntimeActive": False,
                "activeRuntimeCount": 0,
                "runtimeInventoryDigest": None,
                "runtimeInventoryCount": 0,
                "kernel": {"ok": False, "loaded": False},
                "ebpf": {"ok": False, "loaded": False},
                "error": self._safe_error(exc, "shared_protection_status_failed"),
            }
    def status(self) -> dict[str, Any]:
        if self.runtime._shared_protection_capability is not None:
            return self._status_locked()
        try:
            with self.runtime._shared_protection_engine_lock():
                return self._status_locked()
        except BaseException as exc:
            return {
                "ok": False,
                "scope": "engine-host",
                "engineId": None,
                "expectedDigest": None,
                "currentDigest": None,
                "reused": False,
                "replacementRequired": True,
                "maintenanceRequired": False,
                "siblingRuntimeActive": False,
                "activeRuntimeCount": 0,
                "runtimeInventoryDigest": None,
                "runtimeInventoryCount": 0,
                "kernel": {"ok": False, "loaded": False},
                "ebpf": {"ok": False, "loaded": False},
                "error": self._safe_error(
                    exc,
                    "shared_protection_status_failed",
                ),
            }

    def smoke(self) -> dict[str, Any]:
        status: dict[str, Any] = {}
        try:
            with self.runtime._shared_protection_engine_lock():
                status = self.status()
                if status.get("ok") is not True:
                    return status
                host_proof = r'''
set -eu
p=$(mktemp /var/tmp/.xenoid-shared-protection-proof.XXXXXXXX)
trap 'rm -f -- "$p"' EXIT HUP INT TERM
[ -f "$p" ] && [ ! -L "$p" ]
[ "$(stat -c '%u:%g:%a:%h' "$p")" = '0:0:600:1' ]
printf x >"$p"; chmod 0644 "$p"
cat "$p" >/dev/null
if command -v setpriv >/dev/null 2>&1; then
    if setpriv --reuid=10000 --regid=10000 --clear-groups cat "$p" >/dev/null 2>&1; then exit 1; fi
elif id nobody >/dev/null 2>&1; then
    if su -s /bin/sh nobody -c "cat '$p'" >/dev/null 2>&1; then exit 1; fi
else
    exit 2
fi
'''
                host = self.runtime._engine_host_shell(host_proof, timeout=30)
                if host.returncode != 0:
                    raise SharedProtectionError(
                        "shared_protection_host_deny_proof_failed"
                    )
                container, _ = self.runtime._owned_container_record(timeout=10)
                state = (
                    container.get("State")
                    if isinstance(container, Mapping)
                    else None
                )
                container_id = (
                    container.get("Id")
                    if isinstance(container, Mapping)
                    else None
                )
                if (
                    not isinstance(state, Mapping)
                    or state.get("Running") is not True
                    or not isinstance(container_id, str)
                    or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
                ):
                    raise SharedProtectionError(
                        "shared_protection_runtime_unavailable"
                    )
                probe = (
                    "if cat /sys/fs/selinux/enforce >/dev/null 2>&1; "
                    "then exit 1; fi; cat /dev/null >/dev/null"
                )
                for uid in ("10000", "99000"):
                    seconds = bounded_timeout(30.0) or 30.0
                    result = run_bounded(
                        [
                            *self.runtime.docker_base_cmd(),
                            "exec",
                            "--user",
                            uid,
                            container_id,
                            "sh",
                            "-c",
                            probe,
                        ],
                        cwd=self.project_root,
                        deadline=time.monotonic() + max(0.001, seconds),
                        env=self.runtime.docker_env(),
                        project_root=self.project_root,
                    )
                    if result.state != "passed" or result.returncode != 0:
                        raise SharedProtectionError(
                            "shared_protection_android_deny_proof_failed"
                        )
                final = self.status()
                if (
                    final.get("ok") is not True
                    or final.get("engineId") != status.get("engineId")
                    or final.get("currentDigest")
                    != status.get("currentDigest")
                ):
                    raise SharedProtectionError(
                        "shared_protection_state_conflict"
                    )
                return {
                    "ok": True,
                    "schema": "dev.xenoid.protection-smoke/v1",
                    "scope": "engine-host",
                    "engineId": final.get("engineId"),
                    "expectedDigest": final.get("expectedDigest"),
                    "currentDigest": final.get("currentDigest"),
                    "probes": [
                        "hostOrdinaryUserDeny",
                        "hostPrivilegedAllow",
                        "androidAppDeny",
                        "androidIsolatedDeny",
                    ],
                }
        except BaseException as exc:
            return {
                "ok": False,
                "schema": "dev.xenoid.protection-smoke/v1",
                "scope": "engine-host",
                "engineId": status.get("engineId"),
                "expectedDigest": status.get("expectedDigest"),
                "currentDigest": status.get("currentDigest"),
                "error": self._safe_error(
                    exc,
                    "shared_protection_smoke_failed",
                ),
            }

    def _build(self, inputs: ProtectionInputs) -> BuildArtifacts:
        self._validate_artifact_parent("kmod", inputs.kmod_input_digest)
        self._validate_artifact_parent("ebpf", inputs.ebpf_input_digest)
        transaction = secrets.token_hex(16)
        kmod = self._run_script(
            [
                *self.runtime.build_kmod_command(),
                "--input-digest",
                inputs.kmod_input_digest,
                "--transaction",
                transaction,
                "--stage-only",
            ]
        )
        if (
            kmod.get("ok") is not True
            or kmod.get("transaction") != transaction
            or _SHA256.fullmatch(str(kmod.get("artifactSha256") or "")) is None
            or _BUILD_ID.fullmatch(str(kmod.get("buildId") or "")) is None
        ):
            raise SharedProtectionError(
                str(kmod.get("error") or "shared_protection_kmod_build_failed")
            )
        ebpf = self._run_script(
            [
                *self.runtime.build_ebpf_command(),
                "--input-digest",
                inputs.ebpf_input_digest,
                "--transaction",
                transaction,
                "--stage-only",
            ]
        )
        if (
            ebpf.get("ok") is not True
            or ebpf.get("transaction") != transaction
            or _SHA256.fullmatch(str(ebpf.get("artifactSha256") or "")) is None
        ):
            raise SharedProtectionError(
                str(ebpf.get("error") or "shared_protection_ebpf_build_failed")
            )
        return BuildArtifacts(
            transaction=transaction,
            kmod_build_id=str(kmod["buildId"]),
            kmod_sha256=str(kmod["artifactSha256"]),
            ebpf_sha256=str(ebpf["artifactSha256"]),
        )

    def _publish_build(
        self,
        inputs: ProtectionInputs,
        artifacts: BuildArtifacts,
    ) -> None:
        for command, input_digest, artifact_sha, build_id in (
            (
                self.runtime.build_kmod_command(),
                inputs.kmod_input_digest,
                artifacts.kmod_sha256,
                artifacts.kmod_build_id,
            ),
            (
                self.runtime.build_ebpf_command(),
                inputs.ebpf_input_digest,
                artifacts.ebpf_sha256,
                None,
            ),
        ):
            result = self._run_script(
                [
                    *command,
                    "--input-digest",
                    input_digest,
                    "--transaction",
                    artifacts.transaction,
                    "--artifact-sha256",
                    artifact_sha,
                    "--publish-staged",
                ]
            )
            if (
                result.get("ok") is not True
                or result.get("artifactSha256") != artifact_sha
                or build_id is not None
                and result.get("buildId") != build_id
            ):
                raise SharedProtectionError(
                    str(
                        result.get("error")
                        or "shared_protection_artifact_publish_failed"
                    )
                )

    def _install_kmod(
        self,
        inputs: ProtectionInputs,
        artifacts: BuildArtifacts,
        previous: Optional[Mapping[str, Any]],
    ) -> dict[str, Any]:
        command = [
            *self.runtime.build_kmod_command(),
            "--input-digest",
            inputs.kmod_input_digest,
            "--artifact-sha256",
            artifacts.kmod_sha256,
            "--install",
        ]
        if previous is not None:
            previous_kmod = previous.get("kmod")
            if isinstance(previous_kmod, Mapping):
                command.extend(
                    (
                        "--rollback-input-digest",
                        str(previous_kmod.get("inputDigest")),
                        "--rollback-artifact-sha256",
                        str(previous_kmod.get("artifactSha256")),
                    )
                )
        return self._run_script(command)

    def _restore_kmod(
        self,
        previous: Optional[Mapping[str, Any]],
        current_inputs: ProtectionInputs,
        current_artifacts: BuildArtifacts,
    ) -> bool:
        if previous is None or not isinstance(previous.get("kmod"), Mapping):
            result = self._run_script(
                [*self.runtime.build_kmod_command(), "--unload", "--maintenance"]
            )
            return result.get("ok") is True
        previous_kmod = previous["kmod"]
        previous_inputs = str(previous_kmod.get("inputDigest"))
        command = [
            *self.runtime.build_kmod_command(),
            "--input-digest",
            previous_inputs,
            "--artifact-sha256",
            str(previous_kmod.get("artifactSha256")),
            "--rollback-input-digest",
            current_inputs.kmod_input_digest,
            "--rollback-artifact-sha256",
            current_artifacts.kmod_sha256,
            "--install",
        ]
        result = self._run_script(command)
        return result.get("ok") is True and result.get("deploymentDigest") == previous_inputs

    def _ebpf_transition(
        self,
        desired_input: str,
        desired_artifact_sha256: str,
        *,
        active_count: int,
        previous: Optional[Mapping[str, Any]],
    ) -> dict[str, Any]:
        transaction = secrets.token_hex(16)
        desired_args = {
            "input_digest": desired_input,
            "artifact_sha256": desired_artifact_sha256,
            "transaction": transaction,
        }
        stage = self._run_script(self._ebpf_command("stage", **desired_args))
        if stage.get("ok") is not True:
            self._run_script(
                self._ebpf_command("discard", **desired_args),
                timeout=60,
            )
            if active_count:
                return {
                    "ok": False,
                    "error": "shared_protection_reload_requires_maintenance",
                }
            return self._ebpf_nonatomic_transition(
                desired_input,
                desired_artifact_sha256,
                previous,
            )
        prove = self._run_script(
            self._ebpf_command("prove", **desired_args),
            timeout=120,
        )
        if prove.get("ok") is not True:
            self._run_script(
                self._ebpf_command("discard", **desired_args),
                timeout=60,
            )
            return {
                "ok": False,
                "error": str(prove.get("error") or "shared_protection_ebpf_proof_failed"),
            }
        activate = self._run_script(
            self._ebpf_command("activate", **desired_args),
            timeout=120,
        )
        if activate.get("ok") is True:
            return activate
        self._run_script(
            self._ebpf_command("discard", **desired_args),
            timeout=60,
        )
        if active_count:
            return {
                "ok": False,
                "error": "shared_protection_reload_requires_maintenance",
            }
        return self._ebpf_nonatomic_transition(
            desired_input,
            desired_artifact_sha256,
            previous,
        )

    def _ebpf_lkg_valid(
        self,
        previous: Optional[Mapping[str, Any]],
    ) -> bool:
        current = self._native_ebpf_status()
        if current.get("loaded") is not True:
            return True
        if previous is None or not isinstance(previous.get("ebpf"), Mapping):
            return False
        ebpf = previous["ebpf"]
        input_digest = str(ebpf.get("inputDigest"))
        artifact_sha = str(ebpf.get("artifactSha256"))
        return (
            current.get("ok") is True
            and current.get("digest") == input_digest
            and current.get("artifactSha256") == artifact_sha
            and current.get("programTags") == ebpf.get("programTags")
            and self._artifact_valid("ebpf", input_digest, artifact_sha)
        )

    def _ebpf_nonatomic_transition(
        self,
        desired_input: str,
        desired_artifact_sha256: str,
        previous: Optional[Mapping[str, Any]],
    ) -> dict[str, Any]:
        if not self._ebpf_lkg_valid(previous):
            return {
                "ok": False,
                "error": "shared_protection_rollback_unverified",
                "rollbackVerified": False,
            }
        unloaded = self._run_script(
            self._ebpf_command(
                "unload",
                input_digest=desired_input,
                artifact_sha256=desired_artifact_sha256,
                maintenance=True,
                preserve_record=True,
            ),
            timeout=120,
        )
        if unloaded.get("ok") is not True:
            return unloaded
        transaction = secrets.token_hex(16)
        desired_args = {
            "input_digest": desired_input,
            "artifact_sha256": desired_artifact_sha256,
            "transaction": transaction,
        }
        for action in ("stage", "prove", "activate"):
            result = self._run_script(
                self._ebpf_command(action, **desired_args),
                timeout=120,
            )
            if result.get("ok") is not True:
                self._run_script(
                    self._ebpf_command("discard", **desired_args),
                    timeout=60,
                )
                if self._restore_ebpf(previous):
                    return {
                        "ok": False,
                        "error": str(result.get("error") or "shared_protection_ebpf_replacement_failed"),
                        "rollbackVerified": True,
                    }
                return {
                    "ok": False,
                    "error": "shared_protection_rollback_unverified",
                    "rollbackVerified": False,
                }
        return result

    def _restore_ebpf(self, previous: Optional[Mapping[str, Any]]) -> bool:
        if previous is None or not isinstance(previous.get("ebpf"), Mapping):
            return True
        old_input = str(previous["ebpf"].get("inputDigest"))
        old_sha = str(previous["ebpf"].get("artifactSha256"))
        if (
            _SHA256.fullmatch(old_input) is None
            or _SHA256.fullmatch(old_sha) is None
            or not self._artifact_valid("ebpf", old_input, old_sha)
        ):
            return False
        transaction = secrets.token_hex(16)
        old_args = {
            "input_digest": old_input,
            "artifact_sha256": old_sha,
            "transaction": transaction,
        }
        for action in ("stage", "prove", "activate"):
            result = self._run_script(
                self._ebpf_command(action, **old_args),
                timeout=120,
            )
            if result.get("ok") is not True:
                self._run_script(
                    self._ebpf_command("discard", **old_args),
                    timeout=60,
                )
                return False
        status = self._native_ebpf_status()
        return (
            status.get("ok") is True
            and status.get("digest") == old_input
            and status.get("artifactSha256") == old_sha
            and status.get("programTags")
            == previous["ebpf"].get("programTags")
        )
    def _rollback_input_drift(
        self,
        previous: Optional[Mapping[str, Any]],
        inputs: ProtectionInputs,
        artifacts: BuildArtifacts,
        *,
        kmod_changed: bool,
        ebpf_changed: bool,
    ) -> bool:
        restored = True
        if ebpf_changed:
            if previous is not None:
                restored = self._restore_ebpf(previous) and restored
            else:
                unloaded = self._run_script(
                    self._ebpf_command(
                        "unload",
                        input_digest=inputs.ebpf_input_digest,
                        artifact_sha256=artifacts.ebpf_sha256,
                        maintenance=True,
                        preserve_record=True,
                    ),
                    timeout=120,
                )
                restored = unloaded.get("ok") is True and restored
        if kmod_changed:
            restored = (
                self._restore_kmod(previous, inputs, artifacts)
                and restored
            )
        return restored


    def _write_record(
        self,
        inputs: ProtectionInputs,
        artifacts: BuildArtifacts,
        attach_mode: str,
        program_tags: str,
    ) -> None:
        record = {
            "schema": SCHEMA,
            "engineId": inputs.engine_id,
            "kernelDigest": inputs.kernel_digest,
            "expectedDigest": inputs.expected_digest,
            "currentDigest": inputs.expected_digest,
            "lastKnownGoodDigest": inputs.expected_digest,
            "inventory": {
                "modules": list(KMOD_MODULES),
                "links": list(EBPF_LINKS),
                "maps": list(EBPF_MAPS),
                "probes": [*KMOD_PROBES, *EBPF_PROBES],
            },
            "kmod": {
                "inputDigest": inputs.kmod_input_digest,
                "artifactSha256": artifacts.kmod_sha256,
                "buildId": artifacts.kmod_build_id,
            },
            "ebpf": {
                "inputDigest": inputs.ebpf_input_digest,
                "artifactSha256": artifacts.ebpf_sha256,
                "attachMode": attach_mode,
                "programTags": program_tags,
            },
        }
        self._validate_record(record)
        encoded = base64.b64encode(self._canonical(record) + b"\n").decode("ascii")
        transaction = secrets.token_hex(16)
        script = f'''
set -eu
parent={STATE_PARENT!r}
base={STATE_DIRECTORY!r}
p={STATE_PATH!r}
t="$base/.v1.{transaction}.tmp"
if [ -e "$parent" ]; then
    [ -d "$parent" ] && [ ! -L "$parent" ] && [ "$(stat -c '%u:%g:%a' "$parent")" = '0:0:755' ]
else
    install -d -o root -g root -m 0755 "$parent"
fi
if [ -e "$base" ]; then
    [ -d "$base" ] && [ ! -L "$base" ] && [ "$(stat -c '%u:%g:%a' "$base")" = '0:0:700' ]
else
    install -d -o root -g root -m 0700 "$base"
fi
umask 077
printf %s {encoded!r} | base64 -d > "$t"
chown root:root "$t"; chmod 0600 "$t"
[ ! -L "$t" ] && [ "$(stat -c '%u:%g:%a:%h' "$t")" = '0:0:600:1' ]
sync -f "$t"
mv -f "$t" "$p"
sync -f "$base"
'''
        proc = self.runtime._engine_host_shell(script, timeout=30)
        if proc.returncode != 0:
            raise SharedProtectionError("shared_protection_state_publish_failed")

    def prepare(self) -> dict[str, Any]:
        try:
            with self.runtime._shared_protection_engine_lock():
                inputs = self.inputs()
                artifacts = self._build(inputs)
                if self.inputs() != inputs:
                    raise SharedProtectionError(
                        "shared_protection_inputs_changed"
                    )
                self._publish_build(inputs, artifacts)
                if self.inputs() != inputs:
                    raise SharedProtectionError(
                        "shared_protection_inputs_changed"
                    )
                return {
                    "ok": True,
                    "scope": "engine-host",
                    "engineId": inputs.engine_id,
                    "expectedDigest": inputs.expected_digest,
                    "kmodArtifactSha256": artifacts.kmod_sha256,
                    "ebpfArtifactSha256": artifacts.ebpf_sha256,
                }
        except BaseException as exc:
            return {
                "ok": False,
                "scope": "engine-host",
                "engineId": None,
                "expectedDigest": None,
                "error": self._safe_error(
                    exc,
                    "shared_protection_build_failed",
                ),
            }

    def unload_ebpf(self, *, maintenance: bool) -> dict[str, Any]:
        if not maintenance:
            return {
                "ok": False,
                "scope": "engine-host",
                "error": "shared_protection_maintenance_required",
            }
        try:
            with self.runtime._shared_protection_engine_lock():
                inventory = self._runtime_inventory()
                if inventory.active_count:
                    raise SharedProtectionError("shared_protection_in_use")
                record = self._read_record()
                if (
                    record is None
                    or not isinstance(record.get("ebpf"), Mapping)
                    or not isinstance(record.get("kmod"), Mapping)
                ):
                    raise SharedProtectionError("shared_protection_state_invalid")
                ebpf = record["ebpf"]
                kmod = record["kmod"]
                ebpf_input = str(ebpf.get("inputDigest"))
                ebpf_sha = str(ebpf.get("artifactSha256"))
                kmod_input = str(kmod.get("inputDigest"))
                kmod_sha = str(kmod.get("artifactSha256"))
                native_ebpf = self._native_ebpf_status()
                native_kmod = self._native_kmod_status()
                if (
                    not self._artifact_valid("ebpf", ebpf_input, ebpf_sha)
                    or not self._artifact_valid("kmod", kmod_input, kmod_sha)
                    or native_ebpf.get("ok") is not True
                    or native_ebpf.get("digest") != ebpf_input
                    or native_ebpf.get("artifactSha256") != ebpf_sha
                    or native_ebpf.get("programTags")
                    != ebpf.get("programTags")
                    or native_kmod.get("ok") is not True
                    or native_kmod.get("digest") != kmod_input
                    or native_kmod.get("artifactSha256") != kmod_sha
                    or native_kmod.get("buildId") != kmod.get("buildId")
                ):
                    raise SharedProtectionError(
                        "shared_protection_rollback_unverified"
                    )
                ebpf_result = self._run_script(
                    self._ebpf_command(
                        "unload",
                        input_digest=ebpf_input,
                        artifact_sha256=ebpf_sha,
                        maintenance=True,
                        preserve_record=True,
                    ),
                    timeout=120,
                )
                if ebpf_result.get("ok") is not True:
                    return ebpf_result
                kmod_result = self._run_script(
                    [
                        *self.runtime.build_kmod_command(),
                        "--unload",
                        "--maintenance",
                    ],
                    timeout=120,
                )
                if kmod_result.get("ok") is not True:
                    if not self._restore_ebpf(record):
                        raise SharedProtectionError(
                            "shared_protection_rollback_unverified"
                        )
                    return kmod_result
                removed = self.runtime._engine_host_shell(
                    "set -eu; p=/var/lib/xenoid/shared-protection/v1.json; "
                    "[ -f \"$p\" ] && [ ! -L \"$p\" ] && "
                    "[ \"$(stat -c '%u:%g:%a:%h' \"$p\")\" = '0:0:600:1' ]; "
                    "rm -f -- \"$p\"; "
                    "test ! -e \"$p\"; "
                    "sync -f /var/lib/xenoid/shared-protection",
                    timeout=30,
                )
                if removed.returncode != 0:
                    raise SharedProtectionError(
                        "shared_protection_state_publish_failed"
                    )
                return {
                    "ok": True,
                    "scope": "engine-host",
                    "engineId": record.get("engineId"),
                    "unloaded": ["ebpf", "kmod"],
                }
        except BaseException as exc:
            return {
                "ok": False,
                "scope": "engine-host",
                "engineId": None,
                "error": self._safe_error(
                    exc,
                    "shared_protection_unload_failed",
                ),
            }

    def ensure(self, expected_digest: Optional[str] = None) -> dict[str, Any]:
        try:
            inputs = self.inputs()
            if expected_digest is not None and (
                _SHA256.fullmatch(expected_digest) is None
                or expected_digest != inputs.expected_digest
            ):
                raise SharedProtectionError("shared_protection_inputs_changed")
            with self.runtime._shared_protection_engine_lock():
                inputs = self.inputs()
                if expected_digest is not None and expected_digest != inputs.expected_digest:
                    raise SharedProtectionError("shared_protection_inputs_changed")
                inventory = self._runtime_inventory()
                previous = self._read_record()
                kmod, ebpf, current = self._observe(inputs)
                if (
                    previous is None
                    and kmod.get("loaded") is True
                    and kmod.get("digest") is None
                ):
                    if ebpf.get("loaded") is True:
                        raise SharedProtectionError(
                            "shared_protection_state_conflict"
                        )
                    if inventory.active_count:
                        return {
                            "ok": False,
                            "scope": "engine-host",
                            "engineId": inputs.engine_id,
                            "expectedDigest": inputs.expected_digest,
                            "currentDigest": current,
                            "reused": False,
                            "replacementRequired": True,
                            "error": "shared_protection_reload_requires_maintenance",
                        }
                    kmod = self._unload_unbound_legacy_kmod()
                    current = None
                self._validate_transition_state(
                    previous,
                    inputs,
                    kmod,
                    ebpf,
                )
                if self._record_valid_for(
                    previous,
                    inputs,
                    current,
                    ebpf.get("attach"),
                    kmod.get("artifactSha256"),
                    ebpf.get("artifactSha256"),
                    kmod.get("buildId"),
                    ebpf.get("programTags"),
                ):
                    return {
                        "ok": True,
                        "scope": "engine-host",
                        "engineId": inputs.engine_id,
                        "expectedDigest": inputs.expected_digest,
                        "currentDigest": current,
                        "reused": True,
                        "replacementRequired": False,
                    }

                artifacts = self._build(inputs)
                if self.inputs() != inputs:
                    raise SharedProtectionError(
                        "shared_protection_inputs_changed"
                    )
                self._publish_build(inputs, artifacts)
                if self.inputs() != inputs:
                    raise SharedProtectionError(
                        "shared_protection_inputs_changed"
                    )
                kmod_changed = (
                    kmod.get("ok") is not True
                    or kmod.get("digest") != inputs.kmod_input_digest
                )
                ebpf_changed = (
                    ebpf.get("ok") is not True
                    or ebpf.get("digest") != inputs.ebpf_input_digest
                )
                if kmod_changed and inventory.active_count:
                    return {
                        "ok": False,
                        "scope": "engine-host",
                        "engineId": inputs.engine_id,
                        "expectedDigest": inputs.expected_digest,
                        "currentDigest": current,
                        "reused": False,
                        "replacementRequired": True,
                        "error": "shared_protection_reload_requires_maintenance",
                    }

                if kmod_changed:
                    installed = self._install_kmod(inputs, artifacts, previous)
                    if installed.get("ok") is not True:
                        error = str(installed.get("error") or "shared_protection_kmod_replacement_failed")
                        if installed.get("rollbackVerified") is not True:
                            error = "shared_protection_rollback_unverified"
                        raise SharedProtectionError(error)

                if ebpf_changed:
                    transitioned = self._ebpf_transition(
                        inputs.ebpf_input_digest,
                        artifacts.ebpf_sha256,
                        active_count=inventory.active_count,
                        previous=previous,
                    )
                    if transitioned.get("ok") is not True:
                        if kmod_changed and not self._restore_kmod(
                            previous,
                            inputs,
                            artifacts,
                        ):
                            raise SharedProtectionError("shared_protection_rollback_unverified")
                        raise SharedProtectionError(
                            str(transitioned.get("error") or "shared_protection_ebpf_replacement_failed")
                        )

                final_kmod, final_ebpf, final_digest = self._observe(inputs)
                if (
                    final_digest != inputs.expected_digest
                    or final_kmod.get("digest") != inputs.kmod_input_digest
                    or final_ebpf.get("digest") != inputs.ebpf_input_digest
                ):
                    raise SharedProtectionError("shared_protection_deployment_unverified")
                attach_mode = str(final_ebpf.get("attach") or "")
                if attach_mode not in {"lsm", "fmod_ret", "kprobe"}:
                    raise SharedProtectionError("shared_protection_deployment_unverified")
                program_tags = str(final_ebpf.get("programTags") or "")
                if _SHA256.fullmatch(program_tags) is None:
                    raise SharedProtectionError(
                        "shared_protection_deployment_unverified"
                    )
                if self.inputs() != inputs:
                    if not self._rollback_input_drift(
                        previous,
                        inputs,
                        artifacts,
                        kmod_changed=kmod_changed,
                        ebpf_changed=ebpf_changed,
                    ):
                        raise SharedProtectionError(
                            "shared_protection_rollback_unverified"
                        )
                    raise SharedProtectionError(
                        "shared_protection_inputs_changed"
                    )
                self._write_record(
                    inputs,
                    artifacts,
                    attach_mode,
                    program_tags,
                )
                published = self._read_record()
                if not self._record_valid_for(
                    published,
                    inputs,
                    final_digest,
                    final_ebpf.get("attach"),
                    final_kmod.get("artifactSha256"),
                    final_ebpf.get("artifactSha256"),
                    final_kmod.get("buildId"),
                    final_ebpf.get("programTags"),
                ):
                    raise SharedProtectionError("shared_protection_deployment_unverified")
                return {
                    "ok": True,
                    "scope": "engine-host",
                    "engineId": inputs.engine_id,
                    "expectedDigest": inputs.expected_digest,
                    "currentDigest": final_digest,
                    "reused": False,
                    "replacementRequired": False,
                }
        except BaseException as exc:
            return {
                "ok": False,
                "scope": "engine-host",
                "engineId": None,
                "expectedDigest": expected_digest,
                "currentDigest": None,
                "reused": False,
                "replacementRequired": True,
                "error": self._safe_error(exc, "shared_protection_ensure_failed"),
            }
