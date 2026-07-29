#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
daemon = (ROOT / "daemon/app/src/main/java/dev/xenoid/daemon/DeviceProfileManager.java").read_text()
profile = json.loads((ROOT / "examples/fingerprints/pixel-husky-template.json").read_text())
checks = {
    "overlay_function": "overlay_network_interface" in src,
    "reader_relative_proc_net": '"/proc/net/' not in src and "/proc/{self,net}" in src,
    "sysfs_mtu": "/sys/class/net/eth0/mtu" in src,
    "sysfs_operstate": "/sys/class/net/eth0/operstate" in src,
    "sysfs_addr_assign_type": "addr_assign_type" in src,
    "profile_mtu": "network_mtu" in src,
    "optional_mount": "overlay_text_optional" in src,
    "apply_calls": "network_interface=ok" in src,
    "daemon_network_mtu": "network.mtu" in daemon and "network_ifname" in daemon,
    "template_network": (profile.get("network") or {}).get("mtu") == 1500 and (profile.get("network") or {}).get("ifname") == "eth0",
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
