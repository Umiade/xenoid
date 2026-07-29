#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
checks = {
    "kernel_text_function": "overlay_kernel_virtualization_texts" in src,
    "dmi_function": "overlay_dmi_hypervisor" in src,
    "proc_modules": "/proc/modules" in src and "proc_modules" in src,
    "proc_interrupts": "/proc/interrupts" in src,
    "proc_iomem": "/proc/iomem" in src,
    "dmi_product": "/sys/class/dmi/id/product_name" in src and "Pixel 6 Pro" in src,
    "dmi_vendor": "/sys/class/dmi/id/sys_vendor" in src and "Google" in src,
    "hypervisor_type": "/sys/hypervisor/type" in src,
    "optional_mount": "overlay_text_optional" in src,
    "apply_calls": "virtualization_texts=ok" in src and "dmi_hypervisor=ok" in src,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
