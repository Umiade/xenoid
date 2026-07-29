#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, re, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = ROOT / "native/xenoid-netctl/xenoid_netctl.c"
text = src.read_text()
required = {
    "netlink_route_socket": "NETLINK_ROUTE" in text and "AF_NETLINK" in text,
    "rtm_setlink": "RTM_SETLINK" in text,
    "rtm_getlink_verify": "RTM_GETLINK" in text and "IFLA_ADDRESS" in text,
    "ioctl_verify": "SIOCGIFHWADDR" in text,
    "same_layer_fallback": "SIOCSIFHWADDR" in text,
    "json_status": "cmd_status" in text and "netlinkAfter" in text,
}
out = {"ok": all(required.values()), "source": str(src), "checks": required}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
