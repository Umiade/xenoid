#!/usr/bin/env python3
"""Minimum-Python compatibility contract.

Xenoid pins ``requires-python >= 3.9`` (pyproject/setup) and ships no third-party
dependencies, so the host CLI, MCP server, and remote service must import and run
on a stock Python 3.9 interpreter (the macOS Command Line Tools interpreter is
3.9). Gates and developers normally run a newer interpreter, so a 3.10+ only
construct can pass every gate yet break ``./xenoid`` on a supported host.

This runtime-free contract rejects the two regressions that have actually
happened or are easy to reintroduce:

* ``@dataclass(..., slots=True)`` / ``kw_only=True`` — 3.10+ only keyword
  arguments that raise ``TypeError`` at class-definition (import) time on 3.9.
* any 3.10+ grammar (for example ``match`` statements) in tracked ``src`` or
  ``scripts`` Python, detected with ``ast.parse(feature_version=(3, 9))``.

It also asserts the declared minimum stays ``>= 3.9`` in both package manifests
so the contract and the metadata cannot silently diverge.
"""
from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MIN_VERSION = (3, 9)
MIN_SPEC = ">=3.9"

# Decorator keyword arguments introduced after the declared minimum.
_FORBIDDEN_DATACLASS_KWARGS = ("slots", "kw_only")


def _tracked_python_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "src/xenoid/*.py", "scripts/*.py"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()
    return [ROOT / rel for rel in out]


def _is_dataclass_decorator(node: ast.AST) -> bool:
    func = node.func if isinstance(node, ast.Call) else node
    if isinstance(func, ast.Attribute):
        return func.attr == "dataclass"
    if isinstance(func, ast.Name):
        return func.id == "dataclass"
    return False


def _check_dataclass_kwargs(path: Path, tree: ast.AST, failures: list[str]) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not _is_dataclass_decorator(decorator):
                continue
            for keyword in decorator.keywords:
                if keyword.arg in _FORBIDDEN_DATACLASS_KWARGS:
                    rel = path.relative_to(ROOT)
                    failures.append(
                        f"{rel}:{decorator.lineno}: dataclass({keyword.arg}=...) "
                        f"requires Python 3.10+, but the floor is {MIN_SPEC}"
                    )


def _check_grammar(path: Path, source: str, failures: list[str]) -> ast.AST | None:
    try:
        return compile(
            source,
            str(path),
            "exec",
            flags=ast.PyCF_ONLY_AST,
            dont_inherit=True,
            _feature_version=MIN_VERSION[1],
        )
    except SyntaxError as exc:
        rel = path.relative_to(ROOT)
        failures.append(
            f"{rel}:{exc.lineno}: syntax not valid on Python {MIN_VERSION[0]}."
            f"{MIN_VERSION[1]}: {exc.msg}"
        )
        return None


def _check_manifest_floor(failures: list[str]) -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    if not re.search(r'requires-python\s*=\s*">=3\.9"', pyproject):
        failures.append("pyproject.toml: requires-python must stay \">=3.9\"")
    setup = (ROOT / "setup.py").read_text(encoding="utf-8")
    if 'python_requires=">=3.9"' not in setup:
        failures.append("setup.py: python_requires must stay \">=3.9\"")


def main() -> int:
    failures: list[str] = []
    files = _tracked_python_files()
    for path in files:
        source = path.read_text(encoding="utf-8")
        tree = _check_grammar(path, source, failures)
        if tree is not None:
            _check_dataclass_kwargs(path, tree, failures)
    _check_manifest_floor(failures)

    summary = {
        "contract": "python-compat",
        "minPython": f"{MIN_VERSION[0]}.{MIN_VERSION[1]}",
        "filesScanned": len(files),
        "ok": not failures,
    }
    if failures:
        summary["failures"] = failures
        print(json.dumps(summary, indent=2, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
