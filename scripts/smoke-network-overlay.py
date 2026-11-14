#!/usr/bin/env python3
"""Validate that network identity is not part of the generic device profile."""
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
template = json.loads((root / "examples/fingerprints/pixel-raven-android13.json").read_text())
checks = {
    "generic_profile_has_no_network": "network" not in template,
}
print(json.dumps({"ok": all(checks.values()), "checks": checks}, indent=2, sort_keys=True))
raise SystemExit(0 if all(checks.values()) else 1)
