#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import stat
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid.gates import (
    GOOGLE_ACCEPTANCE_NORMALIZED_SCHEMA,
    GOOGLE_ATTESTATION_SCHEMA,
    GOOGLE_CUTOVER_SCHEMA,
    GOOGLE_REPRODUCIBILITY_SCHEMA,
    GOOGLE_SMOKE_GATE_SCHEMA,
    GATE_DEPENDENCY_SNAPSHOT_SCHEMA,
    PROFILE_TARGETS,
    GateRunner,
    GateSpec,
    catalog,
)
from xenoid.process import run_bounded


def require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)

def canonical_document(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"


def catalog_contract() -> None:
    specs = catalog()
    expected_new = {
        "google-runtime",
        "google-reproducibility",
        "google-provider-cutover-contract",
        "google-release-acceptance",
        "release-google",
    }
    require(expected_new <= set(specs), "Google release gate set is incomplete")
    require(
        specs["google-runtime"].command
        == ("scripts/smoke-google-services-gate.sh",)
        and not specs["google-runtime"].cacheable
        and not specs["google-runtime"].runtime_free
        and specs["google-runtime"].mutating
        and specs["google-runtime"].privileged,
        "google-runtime does not use the non-recursive gate wrapper",
    )
    require(
        specs["google-provider-cutover-contract"].dependencies
        == ("runtime-image-contract",)
        and specs["google-provider-cutover-contract"].runtime_free
        and not specs["google-provider-cutover-contract"].mutating,
        "provider cutover contract policy drifted",
    )
    require(
        specs["google-reproducibility"].dependencies
        == ("runtime-image-contract", "google-provider-cutover-contract")
        and not specs["google-reproducibility"].runtime_free
        and specs["google-reproducibility"].mutating
        and specs["google-reproducibility"].privileged,
        "Google reproducibility gate policy drifted",
    )
    require(
        specs["google-release-acceptance"].dependencies
        == (
            "google-runtime",
            "google-reproducibility",
            "google-provider-cutover-contract",
        )
        and specs["google-release-acceptance"].sensitive
        and not specs["google-release-acceptance"].runtime_free
        and not specs["google-release-acceptance"].mutating
        and specs["google-release-acceptance"].privileged,
        "Google release acceptance policy drifted",
    )
    require(
        specs["release-google"].dependencies
        == (
            "static",
            "release-source-contract",
            "google-provider-cutover-contract",
            "google-release-acceptance",
        ),
        "release-google aggregate closure drifted",
    )
    require(
        specs["release"].dependencies
        == (
            "static",
            "release-source-contract",
            "google-provider-cutover-contract",
        ),
        "ordinary release aggregate lost cutover closure",
    )
    require(
        PROFILE_TARGETS
        == {
            "verify": "verify",
            "static": "ci-static",
            "runtime": "ci-runtime",
            "full": "ci-full",
            "doctor": "doctor-default",
            "doctor-full": "doctor-full",
            "release": "release",
            "release-google": "release-google",
            "audit": "audit",
        },
        "profile targets drifted",
    )
    require(
        all(
            not spec.cacheable
            for spec in specs.values()
            if spec.sensitive or spec.category == "release"
        ),
        "sensitive or release gate became cacheable",
    )


def stdout_document_and_attestation_contract(root: Path) -> None:
    def output_command(document: dict[str, object]) -> tuple[str, ...]:
        return (
            sys.executable,
            "-c",
            f"import sys;sys.stdout.write({canonical_document(document)!r})",
        )

    dependency_documents = {
        "google-runtime": {"schema": GOOGLE_SMOKE_GATE_SCHEMA, "ok": True},
        "google-reproducibility": {
            "schema": GOOGLE_REPRODUCIBILITY_SCHEMA,
            "ok": True,
        },
        "google-provider-cutover-contract": {
            "schema": GOOGLE_CUTOVER_SCHEMA,
            "ok": True,
            "mode": "production",
        },
    }
    acceptance_program = (
        "import json,sys;"
        "d=json.load(sys.stdin);"
        f"assert d['schema']=={GATE_DEPENDENCY_SNAPSHOT_SCHEMA!r};"
        "assert set(d)=={'schema','dependencies'};"
        "deps=d['dependencies'];"
        "assert set(deps)=={'google-runtime','google-reproducibility','google-provider-cutover-contract'};"
        "assert all(set(v)=={'state','inputSha256','result'} and v['state']=='passed' "
        "and isinstance(v['inputSha256'],str) and isinstance(v['result'],dict) "
        "for v in deps.values());"
        f"sys.stdout.write({canonical_document({'schema': GOOGLE_ACCEPTANCE_NORMALIZED_SCHEMA, 'ok': True})!r})"
    )
    specs = {
        name: GateSpec(
            name=name,
            command=output_command(document),
            inputs=("input.txt",),
            cacheable=False,
        )
        for name, document in dependency_documents.items()
    }
    specs["google-release-acceptance"] = GateSpec(
        name="google-release-acceptance",
        command=(sys.executable, "-c", acceptance_program),
        inputs=("input.txt",),
        dependencies=(
            "google-runtime",
            "google-reproducibility",
            "google-provider-cutover-contract",
        ),
        cacheable=False,
        sensitive=True,
    )
    runner = GateRunner(
        root,
        specs=specs,
        cache_root=root / ".document-cache",
        lock_root=root / ".document-locks",
    )
    report = runner.run(
        ["google-release-acceptance"],
        deadline=time.monotonic() + 30,
    )
    require(report["ok"] is True, "canonical gate stdout or dependency stdin failed")
    require(
        report["gates"]["google-release-acceptance"]["acceptance"]
        == {"schema": GOOGLE_ACCEPTANCE_NORMALIZED_SCHEMA, "ok": True},
        "normalized acceptance stdout was not retained",
    )
    for name, document in dependency_documents.items():
        require(
            report["gates"][name]["result"] == document,
            f"{name} canonical stdout was not retained",
        )

    noisy = GateRunner(
        root,
        specs={
            "google-runtime": GateSpec(
                name="google-runtime",
                command=(
                    sys.executable,
                    "-c",
                    "import sys;"
                    f"sys.stdout.write('progress\\n'+{canonical_document(dependency_documents['google-runtime'])!r})",
                ),
                inputs=("input.txt",),
                cacheable=False,
            )
        },
        cache_root=root / ".noisy-cache",
        lock_root=root / ".noisy-locks",
    ).run(["google-runtime"], deadline=time.monotonic() + 30)
    require(
        noisy["gates"]["google-runtime"].get("errorCode")
        == "gate_result_document_invalid",
        "stdout diagnostics were accepted by a document gate",
    )
    missing_newline = GateRunner(
        root,
        specs={
            "google-runtime": GateSpec(
                name="google-runtime",
                command=(
                    sys.executable,
                    "-c",
                    "import sys;"
                    f"sys.stdout.write({canonical_document(dependency_documents['google-runtime']).rstrip()!r})",
                ),
                inputs=("input.txt",),
                cacheable=False,
            )
        },
        cache_root=root / ".newline-cache",
        lock_root=root / ".newline-locks",
    ).run(["google-runtime"], deadline=time.monotonic() + 30)
    require(
        missing_newline["gates"]["google-runtime"].get("errorCode")
        == "gate_result_document_invalid",
        "stdout document without one trailing LF was accepted",
    )


    missing_snapshot = GateRunner(
        root,
        specs={
            "google-release-acceptance": GateSpec(
                name="google-release-acceptance",
                command=output_command(
                    {"schema": GOOGLE_ACCEPTANCE_NORMALIZED_SCHEMA, "ok": True}
                ),
                inputs=("input.txt",),
                cacheable=False,
            )
        },
        cache_root=root / ".missing-cache",
        lock_root=root / ".missing-locks",
    ).run(["google-release-acceptance"], deadline=time.monotonic() + 30)
    require(
        missing_snapshot["gates"]["google-release-acceptance"].get("errorCode")
        == "gate_dependency_snapshot_unavailable",
        "acceptance ran without its same-invocation dependency snapshot",
    )

    acceptance = {
        "schema": GOOGLE_ACCEPTANCE_NORMALIZED_SCHEMA,
        "provider": "microg",
        "release": "microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0",
        "specSha256": "1" * 64,
        "runtimeInputSha256": "2" * 64,
        "imageId": "sha256:" + "3" * 64,
        "privateEvidenceSha256": "4" * 64,
        "freshDataProofSha256": "5" * 64,
        "testArtifacts": {},
        "reproducibility": {},
        "effectivePlayStoreVersionCode": 83041711,
        "effectivePlayStoreSignerMatches": True,
        "checks": {},
    }
    runtime_gate_input = "6" * 64
    publication = runner.publish_google_release_attestation(
        {
            "ok": True,
            "gates": {
                "google-runtime": {
                    "state": "passed",
                    "inputSha256": runtime_gate_input,
                },
                "google-release-acceptance": {
                    "state": "passed",
                    "acceptance": acceptance,
                },
            },
        }
    )
    require(publication is not None, "valid normalized acceptance was not published")
    attestation = publication["attestation"]
    require(
        attestation.get("schema") == GOOGLE_ATTESTATION_SCHEMA
        and "privateEvidenceSha256" not in attestation,
        "private acceptance data leaked into the public attestation",
    )
    normalized_sha = hashlib.sha256(
        canonical_document(acceptance).encode("ascii")
    ).hexdigest()
    require(
        attestation.get("gateInputsSha256")
        == {
            "google-runtime": runtime_gate_input,
            "google-release-acceptance": normalized_sha,
        },
        "attestation gate input closure drifted",
    )
    published_path = Path(publication["path"])
    published_bytes = published_path.read_bytes()
    require(
        published_bytes == canonical_document(attestation).encode("ascii"),
        "attestation file is not canonical JSON",
    )
    require(
        stat.S_IMODE(published_path.stat().st_mode) == 0o600,
        "attestation file mode is not private",
    )
    require(
        stat.S_IMODE(published_path.parent.stat().st_mode) == 0o700,
        "attestation directory mode is not private",
    )
    require(
        hashlib.sha256(published_bytes).hexdigest() == publication["sha256"],
        "attestation evidence key does not cover its exact bytes",
    )
    rejected_publication = runner.publish_google_release_attestation(
        {
            "ok": True,
            "gates": {
                "google-runtime": {
                    "state": "passed",
                    "inputSha256": runtime_gate_input,
                },
                "google-release-acceptance": {
                    "state": "passed",
                    "acceptance": {**acceptance, "unexpected": True},
                },
            },
        }
    )
    require(
        rejected_publication is None,
        "attestation publisher accepted an extra normalized field",
    )


def main() -> int:
    catalog_contract()
    with tempfile.TemporaryDirectory(prefix="xenoid-gates-contract-") as raw:
        root = Path(raw)
        (root / "input.txt").write_text("one\n", encoding="utf-8")
        stdout_document_and_attestation_contract(root)
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
