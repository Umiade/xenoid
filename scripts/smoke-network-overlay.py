#!/usr/bin/env python3
"""Source contract for one real rmnet data interface without sysfs overlays."""
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
overlay = (root / "native/xenoid-hide/xenoid_overlay.c").read_text()
netctl = (root / "native/xenoid-netctl/xenoid_netctl.c").read_text()
daemon = (root / "daemon/app/src/main/java/dev/xenoid/daemon/DeviceProfileManager.java").read_text()
backend = (root / "src/xenoid/backend.py").read_text()
proxy = (root / "scripts/xenoid-proxy-engine.py").read_text()
template = json.loads((root / "examples/fingerprints/pixel-raven-android13.json").read_text())
checks = {
    "early_rtnetlink_rename": "RTM_SETLINK" in netctl and 'new_name = "rmnet_data0"' in netctl,
    "real_sysfs_state": "/sys/class/net/eth0" not in overlay and "/sys/class/net/rmnet_data0" not in overlay,
    "location_network_owner": daemon.count("location_identity_owned") >= 2 and "set-mac eth0" not in daemon,
    "backend_default": 'ifname: str = "rmnet_data0"' in backend,
    "proxy_ipv6_interface": 'interface="rmnet_data0"' in proxy,
    "generic_profile_has_no_network": "network" not in template,
}
print(json.dumps({"ok": all(checks.values()), "checks": checks}, indent=2, sort_keys=True))
raise SystemExit(0 if all(checks.values()) else 1)
