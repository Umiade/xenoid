#!/usr/bin/env python3
"""Runtime-free behavioral smoke for app_process64 dependency injection."""
from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATCHER_PATH = ROOT / "scripts" / "patch-app-process-needed.py"
SPEC = importlib.util.spec_from_file_location("xenoid_app_process_patcher", PATCHER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load app_process patcher")
PATCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PATCHER)


def synthetic_app_process() -> bytes:
    data = bytearray(0x500)
    ident = b"\x7fELF" + bytes((2, 1, 1)) + bytes(9)
    phoff = PATCHER.ELF_HEADER.size
    headers = [
        [PATCHER.PT_LOAD, 4, 0, 0, 0, 0x200, 0x200, 0x1000],
        [PATCHER.PT_LOAD, 6, 0x300, 0x300, 0x300, 0x100, 0x100, 0x1000],
        [PATCHER.PT_DYNAMIC, 6, 0x300, 0x300, 0x300, 7 * PATCHER.DYNAMIC_ENTRY.size, 7 * PATCHER.DYNAMIC_ENTRY.size, 8],
    ]
    PATCHER.ELF_HEADER.pack_into(
        data,
        0,
        ident,
        3,
        PATCHER.EM_AARCH64,
        1,
        0,
        phoff,
        0,
        0,
        PATCHER.ELF_HEADER.size,
        PATCHER.PROGRAM_HEADER.size,
        len(headers),
        PATCHER.SECTION_HEADER.size,
        0,
        0,
    )
    for index, header in enumerate(headers):
        PATCHER.PROGRAM_HEADER.pack_into(
            data, phoff + index * PATCHER.PROGRAM_HEADER.size, *header
        )

    dynstr = b"libandroid_runtime.so\0"
    data[0x180 : 0x180 + len(dynstr)] = dynstr
    entries = [
        (PATCHER.DT_NEEDED, 0),
        (PATCHER.DT_FLAGS, PATCHER.DF_BIND_NOW),
        (PATCHER.DT_FLAGS_1, PATCHER.DF_1_NOW | 0x08000000),
        (21, 0),  # DT_DEBUG
        (PATCHER.DT_STRTAB, 0x180),
        (PATCHER.DT_STRSZ, len(dynstr)),
        (PATCHER.DT_NULL, 0),
    ]
    for index, entry in enumerate(entries):
        PATCHER.DYNAMIC_ENTRY.pack_into(
            data, 0x300 + index * PATCHER.DYNAMIC_ENTRY.size, *entry
        )
    return bytes(data)


def dynamic_entries(data: bytes) -> list[tuple[int, int]]:
    entries = []
    for offset in range(0x300, 0x370, PATCHER.DYNAMIC_ENTRY.size):
        tag, value = PATCHER.DYNAMIC_ENTRY.unpack_from(data, offset)
        entries.append((tag, value))
        if tag == PATCHER.DT_NULL:
            break
    return entries


def cstring(data: bytes, offset: int) -> str:
    return data[offset : data.index(b"\0", offset)].decode("ascii")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="xenoid-app-process-patch-") as tmp:
        source = Path(tmp) / "app_process64"
        patched = Path(tmp) / "app_process64.patched"
        twice = Path(tmp) / "app_process64.twice"
        source.write_bytes(synthetic_app_process())
        source.chmod(0o755)
        PATCHER.patch(source, patched, "libpiex_shim.so")
        PATCHER.patch(patched, twice, "libpiex_shim.so")

        output = patched.read_bytes()
        entries = dynamic_entries(output)
        values = {tag: value for tag, value in entries}
        strtab = values[PATCHER.DT_STRTAB]
        names = [cstring(output, strtab + value) for tag, value in entries if tag == PATCHER.DT_NEEDED]
        checks = {
            "leadingDependency": names == ["libpiex_shim.so", "libandroid_runtime.so"],
            "debugPreserved": entries.count((21, 0)) == 1,
            "legacyFlagsRemoved": PATCHER.DT_FLAGS not in values,
            "bindNowPreserved": bool(values.get(PATCHER.DT_FLAGS_1, 0) & PATCHER.DF_1_NOW),
            "idempotent": output == twice.read_bytes(),
            "executableMode": bool(patched.stat().st_mode & 0o100),
        }
        result = {"ok": all(checks.values()), "checks": checks, "needed": names}
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
