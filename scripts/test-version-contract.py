#!/usr/bin/env python3
"""Runtime-free contract for the xenoid release version plumbing."""
from __future__ import annotations

import contextlib
import io
import json
import re
import sys
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from xenoid import __version__  # noqa: E402
from xenoid import remote_service  # noqa: E402
from xenoid.cli import build_parser  # noqa: E402

Case = Callable[[], None]
CASES: dict[str, Case] = {}


class ContractFailure(AssertionError):
    pass


def contract_case(name: str) -> Callable[[Case], Case]:
    def register(function: Case) -> Case:
        if name in CASES:
            raise RuntimeError(f"duplicate case: {name}")
        CASES[name] = function
        return function
    return register


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractFailure(message)


def source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def parse_semver(text: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", text)
    require(match is not None, f"not a semver triple: {text!r}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def changelog_headings(relative: str) -> list[str]:
    return re.findall(r"^## \[(\d+\.\d+\.\d+)\]", source(relative), flags=re.MULTILINE)


@contract_case("version_strings_identical")
def version_strings_identical() -> None:
    pyproject = re.search(r'(?m)^version = "([^"]+)"', source("pyproject.toml"))
    require(pyproject is not None, "pyproject.toml version missing")
    setup_py = re.search(r'version="([^"]+)"', source("setup.py"))
    require(setup_py is not None, "setup.py version missing")
    gradle = re.search(r"versionName '([^']+)'", source("daemon/app/build.gradle"))
    require(gradle is not None, "daemon/app/build.gradle versionName missing")
    candidates = {
        "src/xenoid/__init__.py": __version__,
        "pyproject.toml": pyproject.group(1),
        "setup.py": setup_py.group(1),
        "daemon/app/build.gradle": gradle.group(1),
    }
    distinct = set(candidates.values())
    require(len(distinct) == 1, f"version drift: {candidates}")
    parse_semver(__version__)


@contract_case("version_code_formula")
def version_code_formula() -> None:
    gradle = source("daemon/app/build.gradle")
    code = re.search(r"versionCode (\d+)", gradle)
    name = re.search(r"versionName '([^']+)'", gradle)
    require(code is not None and name is not None, "gradle versionCode/versionName missing")
    major, minor, patch = parse_semver(name.group(1))
    expected = major * 10000 + minor * 100 + patch
    require(int(code.group(1)) == expected,
            f"versionCode {code.group(1)} != formula {expected} for {name.group(1)}")


@contract_case("cli_version_action")
def cli_version_action() -> None:
    parser = build_parser()
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        with contextlib.suppress(SystemExit):
            parser.parse_args(["--version"])
    require(stdout.getvalue().strip() == __version__,
            f"--version printed {stdout.getvalue()!r}, want {__version__!r}")


@contract_case("remote_service_version_sourced")
def remote_service_version_sourced() -> None:
    require(remote_service.SERVER_INFO["version"] == __version__,
            f"SERVER_INFO version {remote_service.SERVER_INFO['version']!r} != {__version__!r}")

@contract_case("daemon_health_version_sourced")
def daemon_health_version_sourced() -> None:
    service = source("daemon/app/src/main/java/dev/xenoid/daemon/XenoidDaemonService.java")
    require(service.count("BuildConfig.VERSION_NAME") >= 2,
            "daemon /health version not sourced from BuildConfig")
    require(re.search(r'"version",\s*"[0-9]', service) is None,
            "daemon /health still carries a hardcoded version literal")
    require("buildConfig true" in source("daemon/app/build.gradle"),
            "BuildConfig generation disabled in daemon/app/build.gradle")


@contract_case("changelog_newest_matches_version")
def changelog_newest_matches_version() -> None:
    for relative in ("CHANGELOG.md", "CHANGELOG_CN.md"):
        headings = changelog_headings(relative)
        require(bool(headings), f"{relative} has no version headings")
        require(headings[0] == __version__,
                f"{relative} newest heading {headings[0]!r} != __version__ {__version__!r}")


@contract_case("changelog_heading_parity")
def changelog_heading_parity() -> None:
    en = changelog_headings("CHANGELOG.md")
    cn = changelog_headings("CHANGELOG_CN.md")
    require(en == cn, f"changelog heading drift: en={en} cn={cn}")


def main() -> int:
    selected = sys.argv[1:]
    unknown = [name for name in selected if name not in CASES]
    if unknown:
        print(json.dumps({"ok": False, "error": "unknown_case", "cases": unknown}))
        return 2
    ok, results = True, []
    for name in selected or list(CASES):
        try:
            CASES[name]()
            results.append({"name": name, "ok": True})
        except Exception as exc:
            ok = False
            results.append({"name": name, "ok": False,
                            "error": type(exc).__name__, "detail": str(exc)[:240]})
    print(json.dumps({"schema": "dev.xenoid.version-contract/v1",
                      "ok": ok, "cases": results}, separators=(",", ":"), sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
