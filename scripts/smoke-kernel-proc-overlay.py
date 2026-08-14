#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
kmod = (ROOT / "native/xenoid-kmod/xenoid_kmod.c").read_text()
vfs_xattr = kmod.partition("static int vfs_xattr_post")[2].partition(
    "static struct kretprobe vfs_xattr_kp"
)[0]
checks = {
    "overlay_function": "overlay_kernel_proc_misc" in src,
    "proc_uptime_native": 'overlay_text_optional("proc_uptime"' not in src
    and '"/proc/uptime"' in src,
    "proc_loadavg": "/proc/loadavg" in src,
    "proc_filesystems": "/proc/filesystems" in src and "f2fs" in src and "binder" in src,
    "proc_swaps": "/proc/swaps" in src,
    "kernel_osrelease": "/proc/sys/kernel/osrelease" in src and "android13" in src,
    "kernel_ostype": "/proc/sys/kernel/ostype" in src,
    "optional_mount": "overlay_text_optional" in src,
    "app_hooks_runtime_scoped": kmod.count("current_is_xenoid_android_app()") >= 4,
    "selinux_hooks_runtime_scoped": kmod.count(
        "android_runtime = current_net_is_xenoid_android_runtime();"
    ) == 3
    and "if (!c->android_runtime || !c->value" in kmod,
    "selinux_xattr_nul_sized": "len = strlen(label) + 1;" in vfs_xattr,
    "readlink_preserves_anonymous_fds": "deny_memfd" not in kmod
    and "explicit Frida inspection" in kmod,
    "apply_calls": "kernel_proc_misc=ok" in src,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
