#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
kmod = (ROOT / "native/xenoid-kmod/xenoid_kmod.c").read_text()
checks = {
    "overlay_function": "overlay_kernel_hardening_sysctls" in src,
    "kptr": "/proc/sys/kernel/kptr_restrict" in src and "kernel_kptr_restrict" in src,
    "dmesg": "/proc/sys/kernel/dmesg_restrict" in src,
    "perf": "/proc/sys/kernel/perf_event_paranoid" in src,
    "modules_disabled": "/proc/sys/kernel/modules_disabled" in src,
    "bpf": "/proc/sys/kernel/unprivileged_bpf_disabled" in src,
    "ptrace_scope": "/proc/sys/kernel/yama/ptrace_scope" in src,
    "optional_mount": "overlay_text_optional" in src,
    "apply_calls": "kernel_hardening_sysctls=ok" in src,
    "isolated_ptrace_boundary": "security_ptrace_access_check" in kmod
    and "current_is_isolated_android_app()" in kmod
    and "regs_set_return_value(regs, -EPERM);" in kmod,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
