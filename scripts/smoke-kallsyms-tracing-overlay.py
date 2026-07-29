#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
body = src.split('overlay_kallsyms_tracing',1)[1].split('return fail',1)[0]
checks = {
    "overlay_function": "overlay_kallsyms_tracing" in src,
    "kallsyms": "/proc/kallsyms" in src and "start_kernel" in body,
    "debug_tracing": "/sys/kernel/debug/tracing/kprobe_events" in src and "/sys/kernel/debug/tracing/uprobe_events" in src,
    "kernel_tracing": "/sys/kernel/tracing/kprobe_events" in src and "/sys/kernel/tracing/uprobe_events" in src,
    "available_filter_functions": "available_filter_functions" in src,
    "empty_probe_events": "kprobe_events" in src and "uprobe_events" in src,
    "no_bad_defaults": all(x not in body.lower() for x in ["ksu", "kernelsu", "apatch", "magisk", "frida", "xen", "virtio", "qemu", "vbox", "vmw"]),
    "optional_mount": "overlay_text_optional" in src,
    "apply_calls": "kallsyms_tracing=ok" in src,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
