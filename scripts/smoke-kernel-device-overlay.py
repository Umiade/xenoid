#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
body = src.split('overlay_kernel_device_tables',1)[1].split('return fail',1)[0]
checks = {
    "overlay_function": "overlay_kernel_device_tables" in src,
    "proc_devices": "/proc/devices" in src and "binder" in body and "mmc" in body,
    "proc_misc": "/proc/misc" in src and "ashmem" in body and "uinput" in body,
    "tty_drivers": "/proc/tty/drivers" in src and "msm_serial_hs" in body,
    "driver_rtc": "/proc/driver/rtc" in src,
    "no_bad_defaults": all(x not in body.lower() for x in ["virtio", "qemu", "vbox", "xen", "vmw", "hvc", "xvc"]),
    "optional_mount": "overlay_text_optional" in src,
    "apply_calls": "kernel_device_tables=ok" in src,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
