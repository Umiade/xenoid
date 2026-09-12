#!/usr/bin/env python3
"""Runtime-free behavioral smoke for the servicemanager dependency patcher."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATCHER_PATH = ROOT / "scripts" / "patch-servicemanager-needed.py"
SPEC = importlib.util.spec_from_file_location("xenoid_servicemanager_patcher", PATCHER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load servicemanager patcher")
PATCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PATCHER)

SHSTRTAB = b"\0.dynstr\0.shstrtab\0"


def synthetic_servicemanager() -> bytes:
    data = bytearray(0x500)
    ident = b"\x7fELF" + bytes((2, 1, 1)) + bytes(9)
    phoff = PATCHER.ELF_HEADER.size
    shoff = 0x400
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
        shoff,
        0,
        PATCHER.ELF_HEADER.size,
        PATCHER.PROGRAM_HEADER.size,
        len(headers),
        PATCHER.SECTION_HEADER.size,
        3,
        2,
    )
    for index, header in enumerate(headers):
        PATCHER.PROGRAM_HEADER.pack_into(
            data, phoff + index * PATCHER.PROGRAM_HEADER.size, *header
        )

    # The dynamic string table is flush against live data: no in-segment
    # padding, exercising the end-of-file relocation path.
    dynstr = b"libbase.so\0"
    data[0x100 : 0x100 + len(dynstr)] = dynstr
    data[0x100 + len(dynstr)] = 0xAA
    data[0x1C0 : 0x1C0 + len(SHSTRTAB)] = SHSTRTAB
    entries = [
        (PATCHER.DT_NEEDED, 0),
        (PATCHER.DT_FLAGS, PATCHER.DF_BIND_NOW),
        (PATCHER.DT_FLAGS_1, PATCHER.DF_1_NOW | 0x08000000),
        (21, 0),  # DT_DEBUG
        (PATCHER.DT_STRTAB, 0x100),
        (PATCHER.DT_STRSZ, len(dynstr)),
        (PATCHER.DT_NULL, 0),
    ]
    for index, entry in enumerate(entries):
        PATCHER.DYNAMIC_ENTRY.pack_into(
            data, 0x300 + index * PATCHER.DYNAMIC_ENTRY.size, *entry
        )
    sections = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 3, 0, 0x100, 0x100, len(dynstr), 0, 0, 1, 0],
        [9, 3, 0, 0, 0x1C0, len(SHSTRTAB), 0, 0, 1, 0],
    ]
    for index, section in enumerate(sections):
        PATCHER.SECTION_HEADER.pack_into(
            data, shoff + index * PATCHER.SECTION_HEADER.size, *section
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


def load_segments(data: bytes) -> list[tuple[int, int, int]]:
    phoff = 64
    segments = []
    for index in range(3):
        fields = PATCHER.PROGRAM_HEADER.unpack_from(
            data, phoff + index * PATCHER.PROGRAM_HEADER.size
        )
        if fields[0] == PATCHER.PT_LOAD:
            segments.append((fields[2], fields[3], fields[5]))
    return segments


def cstring(data: bytes, strtab_va: int, value: int) -> str:
    address = strtab_va + value
    for offset, va, filesz in load_segments(data):
        if va <= address < va + filesz:
            file_offset = offset + address - va
            return data[file_offset : data.index(b"\0", file_offset)].decode("ascii")
    raise AssertionError("dependency name is not mapped")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="xenoid-servicemanager-patch-") as tmp:
        source = Path(tmp) / "servicemanager"
        patched = Path(tmp) / "servicemanager.patched"
        twice = Path(tmp) / "servicemanager.twice"
        source.write_bytes(synthetic_servicemanager())
        source.chmod(0o755)
        PATCHER.patch(source, patched, "libxenoid_svcman.so")
        PATCHER.patch(patched, twice, "libxenoid_svcman.so")

        output = patched.read_bytes()
        entries = dynamic_entries(output)
        values = {tag: value for tag, value in entries}
        strsz = values[PATCHER.DT_STRSZ]
        strtab = values[PATCHER.DT_STRTAB]
        names = [
            cstring(output, strtab, value)
            for tag, value in entries
            if tag == PATCHER.DT_NEEDED
        ]
        mapped_tail = any(
            va <= strtab and strtab + strsz <= va + filesz
            for _, va, filesz in load_segments(output)
        )
        dynstr_header = PATCHER.SECTION_HEADER.unpack_from(output, 0x400 + PATCHER.SECTION_HEADER.size)
        checks = {
            "leadingDependency": names == ["libxenoid_svcman.so", "libbase.so"],
            "debugPreserved": entries.count((21, 0)) == 1,
            "legacyFlagsRemoved": PATCHER.DT_FLAGS not in values,
            "bindNowPreserved": bool(values.get(PATCHER.DT_FLAGS_1, 0) & PATCHER.DF_1_NOW),
            "strtabMapped": mapped_tail,
            "dynstrSectionMoved": dynstr_header[3] == strtab
            and dynstr_header[5] == strsz,
            "idempotent": output == twice.read_bytes(),
            "executableMode": bool(patched.stat().st_mode & 0o100),
        }
        result = {"ok": all(checks.values()), "checks": checks, "needed": names}
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
