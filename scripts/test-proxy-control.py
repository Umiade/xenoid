#!/usr/bin/env python3
"""Runtime-free contracts for generation-bound proxy data-plane proof."""
from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid.daemon_client import wait_for_proxy_check

INSTANCE = "123e4567-e89b-42d3-a456-426614174000"
EPOCH = "v1-abcdef012345-0123456789abcdef"


def require(value: bool) -> None:
    if not value:
        raise AssertionError


def capabilities() -> dict:
    return {
        "v4DnsProxy": True, "v4TcpProxy": True, "v4UdpProxy": True,
        "v6DnsProxy": True, "v6TcpProxy": True, "v6UdpProxy": True,
    }


def ready_status() -> dict:
    return {
        "ok": True, "enabled": True, "instanceId": INSTANCE,
        "runtimeEpoch": EPOCH, "generation": 7, "checkId": 9,
        "udpAllowed": True,
        "report": {
            "generation": 7, "checkId": 9, "phase": "active",
            "structuralApplied": True, "dataPlaneVerified": True,
            "capabilities": capabilities(), "errorCode": "",
        },
        "probe": {
            "checkId": 9, "elapsedMs": 50, "errorCode": "",
            "capabilities": capabilities(),
        },
    }


class FakeClient:
    def __init__(self, statuses: list[dict]):
        self.statuses = statuses
        self.index = 0

    def proxy_status(self) -> dict:
        value = self.statuses[min(self.index, len(self.statuses) - 1)]
        self.index += 1
        return copy.deepcopy(value)

    def proxy_check(self) -> dict:
        raise AssertionError("an exact in-flight check must not allocate a replacement")


def checked(status: dict) -> dict:
    return wait_for_proxy_check(
        FakeClient([status]), timeout=0, poll_interval=0.01,
        expected_check_id=9, expected_generation=7,
        expected_runtime_epoch=EPOCH,
    )


def test_accepts_one_exact_proof() -> None:
    result = checked(ready_status())
    require(result.get("ok") is True and result.get("checkCompleted") is True)


def test_rejects_stale_generation_and_epoch() -> None:
    stale = ready_status()
    stale["report"]["generation"] = 6
    require(checked(stale).get("error") == "proxy_check_timeout")
    stale = ready_status()
    stale["runtimeEpoch"] = "v1-other-0123456789abcdef"
    require(checked(stale).get("error") == "agent_stale")
    stale = ready_status()
    stale["checkId"] = 10
    require(checked(stale).get("error") == "agent_stale")


def test_rejects_region_shaped_probe_fields() -> None:
    # Removed region evidence must not resurrect: the readiness contract only
    # accepts the strict capability/phase keys and ignores nothing silently.
    mismatched = ready_status()
    mismatched["probe"]["egressRegion"] = {"regionKey": "HK/Asia/Hong_Kong"}
    mismatched["probe"]["capabilities"]["v4TcpProxy"] = False
    require(checked(mismatched).get("error") == "data_plane_unverified")
    replay = ready_status()
    replay["probe"]["checkId"] = 8
    replay["report"]["egressRegion"] = {"regionKey": "SG/Asia/Singapore"}
    require(checked(replay).get("error") == "proxy_check_timeout")


def test_preserves_fail_closed_error() -> None:
    failed = ready_status()
    failed["report"]["phase"] = "quarantined"
    failed["report"]["errorCode"] = "probe_failed"
    require(checked(failed).get("error") == "probe_failed")


def main() -> int:
    tests = [
        test_accepts_one_exact_proof,
        test_rejects_stale_generation_and_epoch,
        test_rejects_region_shaped_probe_fields,
        test_preserves_fail_closed_error,
    ]
    for test in tests:
        test()
    print("proxy control contracts ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
