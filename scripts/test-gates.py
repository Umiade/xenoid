#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid.gates import GateRunner, GateSpec
from xenoid.process import run_bounded


def require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="xenoid-gates-contract-") as raw:
        root = Path(raw)
        (root / "input.txt").write_text("one\n", encoding="utf-8")
        counter = root / "counter.txt"
        command = (
            sys.executable,
            "-c",
            "from pathlib import Path; p=Path('counter.txt'); p.write_text(str(int(p.read_text())+1) if p.exists() else '1')",
        )
        spec = GateSpec(
            name="cached",
            command=command,
            inputs=("input.txt",),
            tools=("python3",),
        )
        runner = GateRunner(root, specs={"cached": spec})
        first = runner.run(["cached"], deadline=time.monotonic() + 30)
        second = runner.run(["cached"], deadline=time.monotonic() + 30)
        require(first["ok"] is True and first["gates"]["cached"]["cacheHit"] is False, "first execution was not fresh")
        require(second["ok"] is True and second["gates"]["cached"]["cacheHit"] is True, "valid cache was not reused")
        require(counter.read_text() == "1", "cache hit executed the child")

        digest = second["gates"]["cached"]["inputSha256"]
        record = root / ".xenoid/cache/gates/v1/cached" / f"{digest}.json"
        record.write_text("{}\n", encoding="utf-8")
        os.chmod(record, 0o600)
        poisoned = runner.run(["cached"], deadline=time.monotonic() + 30)
        require(poisoned["ok"] is True and poisoned["gates"]["cached"]["cacheHit"] is False, "malformed cache did not force rerun")
        require(counter.read_text() == "2", "malformed cache was trusted")

        fresh = runner.run(["cached"], fresh=True, deadline=time.monotonic() + 30)
        require(fresh["ok"] is True and fresh["gates"]["cached"]["cacheHit"] is False, "fresh override reused cache")
        require(counter.read_text() == "3", "fresh override did not execute")

        observer = GateRunner(
            root,
            specs={
                "cached": spec,
                "doctor-default": GateSpec(
                    name="doctor-default",
                    dependencies=("cached",),
                    cacheable=False,
                ),
            },
        )
        observed = observer.observe_profile("doctor")
        require(
            observed["ok"] is True
            and observed["complete"] is True
            and counter.read_text() == "3",
            "observational record consumption executed or rejected a valid record",
        )
        record.unlink()
        missing = observer.observe_profile("doctor")
        require(
            missing["ok"] is False
            and missing["complete"] is False
            and counter.read_text() == "3",
            "missing record triggered gate execution",
        )

        independent_marker = root / "independent.txt"
        specs = {
            "fail": GateSpec(
                name="fail",
                command=(sys.executable, "-c", "raise SystemExit(7)"),
                inputs=("input.txt",),
                cacheable=False,
            ),
            "blocked": GateSpec(
                name="blocked",
                command=(sys.executable, "-c", "raise SystemExit(0)"),
                inputs=("input.txt",),
                dependencies=("fail",),
                cacheable=False,
            ),
            "independent": GateSpec(
                name="independent",
                command=(sys.executable, "-c", "from pathlib import Path; Path('independent.txt').write_text('ok')"),
                inputs=("input.txt",),
                cacheable=False,
            ),
        }
        dag = GateRunner(
            root,
            specs=specs,
            cache_root=root / ".cache-two",
            lock_root=root / ".locks-two",
        ).run(tuple(specs), deadline=time.monotonic() + 30)
        require(dag["ok"] is False, "failing DAG reported success")
        require(dag["gates"]["blocked"]["state"] == "blocked", "dependent gate was scheduled after failure")
        require(dag["gates"]["independent"]["state"] == "passed" and independent_marker.exists(), "independent gate did not finish")

        late = root / "late.txt"
        child = (
            "import subprocess,sys,time; "
            "subprocess.Popen([sys.executable,'-c',\"import time; time.sleep(2); open('late.txt','w').write('late')\"]); "
            "time.sleep(60)"
        )
        bounded = run_bounded(
            [sys.executable, "-c", child],
            cwd=root,
            deadline=time.monotonic() + 1.0,
            project_root=root,
        )
        require(bounded.state == "timed_out", "timeout state was not stable")
        time.sleep(2.5)
        require(not late.exists(), "timeout left a descendant process running")

        orphan = root / "orphan.txt"
        leader_exit = (
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable,'-c',"
            "\"import time; time.sleep(2); open('orphan.txt','w').write('late')\"])"
        )
        orphaned = run_bounded(
            [sys.executable, "-c", leader_exit],
            cwd=root,
            deadline=time.monotonic() + 1.0,
            project_root=root,
        )
        require(orphaned.state == "timed_out", "exited leader bypassed timeout")
        time.sleep(2.5)
        require(not orphan.exists(), "exited leader left its process group alive")

        callback_marker = root / "callback.txt"
        callback_child = (
            "import time; print('ready', flush=True); "
            "time.sleep(2); open('callback.txt','w').write('late')"
        )
        callback_result = run_bounded(
            [sys.executable, "-c", callback_child],
            cwd=root,
            deadline=time.monotonic() + 30,
            project_root=root,
            progress=lambda _stream, _detail: (_ for _ in ()).throw(
                RuntimeError("closed")
            ),
        )
        require(
            callback_result.error_code == "process_progress_failed",
            "progress failure did not cancel the child",
        )
        time.sleep(2.5)
        require(not callback_marker.exists(), "progress failure orphaned child")
        payload = b"x" * 8192
        rejected_input = run_bounded(
            [sys.executable, "-c", "raise SystemExit(0)"],
            cwd=root,
            deadline=time.monotonic() + 30,
            input_bytes=payload,
            project_root=root,
        )
        require(
            rejected_input.error_code == "process_input_too_large",
            "default bounded input cap changed",
        )
        accepted_input = run_bounded(
            [
                sys.executable,
                "-c",
                "import sys; raise SystemExit(0 if "
                "len(sys.stdin.buffer.read()) == 8192 else 1)",
            ],
            cwd=root,
            deadline=time.monotonic() + 30,
            input_bytes=payload,
            max_input_bytes=len(payload),
            project_root=root,
        )
        require(
            accepted_input.ok,
            "explicit bounded input contract rejected its payload",
        )

        outside = root / "outside-cache"
        outside.mkdir(mode=0o700)
        cache_link = root / "cache-link"
        cache_link.symlink_to(outside, target_is_directory=True)
        unsafe = GateRunner(
            root,
            specs={"cached": spec},
            cache_root=cache_link,
            lock_root=root / ".locks-three",
        ).run(["cached"], deadline=time.monotonic() + 30)
        require(
            unsafe["ok"] is False
            and unsafe.get("errorCode") == "gate_private_directory_invalid",
            "symlinked cache tree did not fail closed",
        )

    print(json.dumps({"schema": "dev.xenoid.gate-contract/v1", "ok": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
