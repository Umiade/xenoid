from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .backend import RuntimeManager
from .config import InstanceContext, InstanceLease, XenoidConfig
from .gates import GateRunner
from .live_observe import LiveAcceptance
from .process import Redactor, run_bounded


def _summary(name: str, section: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {"name": name, "ok": section.get("ok") is True}
    if section.get("skipped") is True:
        summary["skipped"] = True
    reason = section.get("reason")
    if isinstance(reason, str):
        summary["reason"] = reason
    return summary


def _sanitize(value: Any, redactor: Redactor) -> Any:
    if isinstance(value, str):
        return redactor(value)
    if isinstance(value, list):
        return [_sanitize(item, redactor) for item in value]
    if isinstance(value, dict):
        return {
            str(key): _sanitize(item, redactor)
            for key, item in value.items()
            if isinstance(key, str)
        }
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return "unsupported"


def _preflight(
    manager: RuntimeManager,
    project_root: Path,
    deadline: float,
) -> dict[str, Any]:
    result = run_bounded(
        [str(project_root / "scripts/redroid-preflight.sh"), "--observe-only"],
        cwd=project_root,
        deadline=deadline,
        env={**manager.docker_env(), "LC_ALL": "C", "TZ": "UTC"},
        project_root=project_root,
    )
    data: dict[str, Any]
    try:
        parsed = json.loads(result.stdout_tail) if result.stdout_tail else None
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        data = dict(parsed)
        data["ok"] = result.ok and data.get("ok") is True
    else:
        data = {
            "ok": False,
            "state": result.state,
            "errorCode": result.error_code or "runtime_preflight_failed",
        }
    data["durationMs"] = result.duration_ms
    if not result.ok and result.stderr_tail:
        data["stderrTail"] = result.stderr_tail
    return data


def build_doctor_report(
    context: InstanceContext,
    cfg: XenoidConfig,
    lease: InstanceLease,
    *,
    full: bool = False,
    require_runtime: bool = False,
) -> dict[str, Any]:
    """Build one strictly observational doctor report.

    Static evidence comes only from GateRunner. Live evidence comes only from a
    fresh LiveAcceptance observation; doctor never starts or repairs Android,
    ensures daemon/rootd, converges, builds artifacts/images, or packages a
    release.
    """

    started = time.monotonic()
    manager = RuntimeManager(context, cfg, lease)
    redactor = Redactor(project_root=context.project_root)

    host_checks = [asdict(check) for check in manager.doctor()]
    host_ok = all(check["ok"] or check["name"] == "scrcpy" for check in host_checks)
    host = {"ok": host_ok, "checks": _sanitize(host_checks, redactor)}

    status = manager.status()
    running = bool(status.get("running"))
    status_healthy = status.get("ok") is True
    preflight = _preflight(
        manager,
        context.project_root,
        time.monotonic() + (300.0 if full else 120.0),
    )

    observed_storage = manager.storage_status()
    if (
        not running
        and not require_runtime
        and observed_storage.get("error")
        in {"storage_not_initialized", "storage_volume_missing"}
    ):
        storage: dict[str, Any] = {
            "ok": True,
            "skipped": True,
            "reason": "runtime-absent",
            "observation": observed_storage,
        }
    else:
        storage = dict(observed_storage)
        storage["ok"] = storage.get("ok") is True

    gate_profile = "doctor-full" if full else "doctor"
    gate_runner = GateRunner(context.project_root)
    gate_report = gate_runner.observe_profile(gate_profile)
    records_complete = gate_report.get("complete") is True
    gates = {
        "ok": records_complete if full else True,
        "complete": records_complete,
        "skipped": not records_complete and not full,
        "reason": None if records_complete else "gate-records-incomplete",
        "schema": gate_report.get("schema"),
        "profile": gate_profile,
        "fresh": False,
        "failedGate": gate_report.get("failedGate"),
        "errorCode": gate_report.get("errorCode"),
        "durationMs": gate_report.get("durationMs", 0),
        "records": gate_report.get("gates", {}),
    }

    if running:
        live = LiveAcceptance(manager).observe(
            manager,
            {},
            gate_profile,
            time.monotonic() + (900.0 if full else 300.0),
            None,
        )
        live["fresh"] = True
    else:
        live = {
            "ok": not require_runtime,
            "fresh": True,
            "skipped": True,
            "reason": "runtime-absent",
        }

    runtime = {
        "ok": live.get("ok") is True and status_healthy,
        "running": running,
        "statusHealthy": status_healthy,
        "status": status,
        "acceptance": live,
    }
    if full:
        live_checks = live.get("checks")
        required_full = (
            "storageIdentity",
            "cellular",
            "camera",
            "googleBinding",
            "sharedProtection",
        )
        current_matrix_ok = isinstance(live_checks, dict) and all(
            isinstance(live_checks.get(name), dict)
            and live_checks[name].get("ok") is True
            for name in required_full
        )
        live_identity = live.get("observation")
        full_evidence = gate_runner.observe_full_evidence(
            context.instance_name,
            context.instance_id,
            live_identity if isinstance(live_identity, dict) else {},
        )
        full_matrix_ok = (
            current_matrix_ok and full_evidence.get("ok") is True
        )
    else:
        required_full = ()
        full_evidence = {"ok": True}
        full_matrix_ok = True
    sections: dict[str, dict[str, Any]] = {
        "host": host,
        "preflight": preflight,
        "storage": storage,
        "gates": gates,
        "runtime": runtime,
    }
    if full:
        sections["fullLiveMatrix"] = {
            "ok": full_matrix_ok,
            "fresh": True,
            "required": list(required_full),
            "reason": None if full_matrix_ok else "full-live-evidence-incomplete",
            "evidence": full_evidence,
        }
    checks = [_summary(name, section) for name, section in sections.items()]
    ok = all(check["ok"] for check in checks)
    complete = bool(
        ok
        and records_complete
        and full_matrix_ok
        and running
        and live.get("ok") is True
        and live.get("fresh") is True
    )

    selected = f"./xenoid --instance {context.instance_name}"
    next_actions: list[str] = []
    if not host_ok or preflight.get("ok") is not True:
        next_actions.append(f"{selected} install-runtime")
    if not running:
        next_actions.append(f"{selected} up")
    elif live.get("ok") is not True:
        next_actions.extend([f"{selected} status", f"{selected} logs"])
    if gates.get("ok") is not True and isinstance(gates.get("failedGate"), str):
        next_actions.append(f"rerun-gate:{gates['failedGate']}")

    report = {
        "instance": {
            **context.public_dict(),
            "slot": lease.slot,
            "leaseState": lease.state,
        },
        "schema": "dev.xenoid.doctor/v1",
        "ok": ok,
        "complete": complete,
        "full": full,
        "runtimeRequired": require_runtime,
        "runtimeAvailable": running,
        "checks": checks,
        "sections": sections,
        "durationMs": max(0, int((time.monotonic() - started) * 1000)),
        "nextActions": list(dict.fromkeys(next_actions)),
    }
    return _sanitize(report, redactor)
