#!/usr/bin/env python3
"""Add one leading DT_NEEDED entry to Android's servicemanager.

Sibling of patch-app-process-needed.py for binaries whose dynamic string
table has no zero padding inside its load segment: the expanded table is
appended at end of file and the last PT_LOAD is extended to map it. The
redundant DT_FLAGS BIND_NOW entry is reused, keeping DT_DEBUG intact.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
DYNAMIC_ENTRY = struct.Struct("<qQ")

PT_LOAD = 1
PT_DYNAMIC = 2
DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_STRSZ = 10
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
EM_AARCH64 = 183



def _cstring(data: bytes | bytearray, offset: int) -> str:
    end = data.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated ELF string")
    return bytes(data[offset:end]).decode("ascii")


def patch(source: Path, destination: Path, library: str) -> None:
    if not library or "/" in library or "\0" in library:
        raise ValueError("library must be a bare ELF dependency name")
    library_bytes = library.encode("ascii") + b"\0"

    original = source.read_bytes()
    data = bytearray(original)
    if len(data) < ELF_HEADER.size:
        raise ValueError("ELF header is truncated")
    header = list(ELF_HEADER.unpack_from(data))
    ident = header[0]
    if ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1:
        raise ValueError("expected a little-endian ELF64 binary")
    if header[2] != EM_AARCH64:
        raise ValueError("expected an AArch64 binary")

    phoff, shoff = header[5], header[6]
    phentsize, phnum = header[9], header[10]
    shentsize, shnum, shstrndx = header[11], header[12], header[13]
    if phentsize != PROGRAM_HEADER.size:
        raise ValueError("unexpected program-header size")

    programs: list[list[int]] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        programs.append(list(PROGRAM_HEADER.unpack_from(data, offset)))

    dynamic_program = next((program for program in programs if program[0] == PT_DYNAMIC), None)
    if dynamic_program is None:
        raise ValueError("PT_DYNAMIC is missing")
    dynamic_offset, dynamic_size = dynamic_program[2], dynamic_program[5]

    entries: list[tuple[int, int, int]] = []
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, DYNAMIC_ENTRY.size):
        tag, value = DYNAMIC_ENTRY.unpack_from(data, offset)
        entries.append((offset, tag, value))
        if tag == DT_NULL:
            break

    values = {tag: value for _, tag, value in entries if tag in (DT_STRTAB, DT_STRSZ)}
    if DT_STRTAB not in values or DT_STRSZ not in values:
        raise ValueError("dynamic string table is missing")
    strtab_address, strtab_size = values[DT_STRTAB], values[DT_STRSZ]

    load_segments = [program for program in programs if program[0] == PT_LOAD]
    if not load_segments:
        raise ValueError("PT_LOAD is missing")

    def file_offset_for(address: int) -> int | None:
        for program in load_segments:
            if program[3] <= address < program[3] + program[5]:
                return program[2] + address - program[3]
        return None

    strtab_offset = file_offset_for(strtab_address)
    if strtab_offset is None or strtab_offset + strtab_size > len(data):
        raise ValueError("dynamic string table is truncated")
    old_strtab = bytes(data[strtab_offset : strtab_offset + strtab_size])

    needed_entries = [(offset, value) for offset, tag, value in entries if tag == DT_NEEDED]
    if not needed_entries:
        raise ValueError("servicemanager has no DT_NEEDED entry")

    first_needed_offset, first_needed = needed_entries[0]
    if _cstring(data, strtab_offset + first_needed) == library:
        destination.write_bytes(original)
        destination.chmod(source.stat().st_mode)
        return

    # Same bind-now redundancy contract as the app_process64 patcher.
    flags_entries = [(offset, value) for offset, tag, value in entries if tag == DT_FLAGS]
    flags1_values = [value for _, tag, value in entries if tag == DT_FLAGS_1]
    if len(flags_entries) != 1 or flags_entries[0][1] != DF_BIND_NOW:
        raise ValueError("expected one redundant DT_FLAGS BIND_NOW entry")
    if len(flags1_values) != 1 or not flags1_values[0] & DF_1_NOW:
        raise ValueError("DT_FLAGS_1 does not preserve bind-now semantics")
    replacement_offset = flags_entries[0][0]

    # The string table has no in-segment padding: relocate the expanded table
    # behind the section header table and extend the last content segment.
    # A pure-bss segment (filesz == 0) must never receive the file mapping:
    # the loader anonymous-zeroes its whole page range, so the copy must start
    # above every later-loaded bss page, not just above its byte range.
    content_loads = [program for program in load_segments if program[5] > 0]
    if not content_loads:
        raise ValueError("no content PT_LOAD is available")
    last_load = max(content_loads, key=lambda program: program[2] + program[5])
    if shoff and shnum:
        sections_end = shoff + shnum * shentsize
        if sections_end > len(data):
            raise ValueError("section header table is truncated")
    new_strtab = old_strtab + library_bytes
    last_load = list(last_load)
    load_index = programs.index(last_load)
    delta = last_load[3] - last_load[2]

    def place(copy_offset: int) -> tuple[int, int]:
        copy_end = copy_offset + len(new_strtab)
        for program in load_segments:
            if program is last_load or program == last_load:
                continue
            extension = (last_load[3] + last_load[5], last_load[3] + copy_end - last_load[2])
            overlap = program[3] < extension[1] and extension[0] < program[3] + program[6]
            if not overlap:
                continue
            if program[5] > 0:
                raise ValueError("expanded segment would overlap mapped content")
            # A pure-bss range loads anonymously: its entire pages are
            # replaced, and only when it is loaded after our segment.
            if programs.index(program) < load_index:
                raise ValueError("expanded segment would shadow a later bss range")
            bss_page_end = (program[3] + program[6] + 0xFFF) & ~0xFFF
            if bss_page_end - delta > copy_offset:
                copy_offset = bss_page_end - delta
                return place(copy_offset)
        return copy_offset, copy_end

    copy_offset = (len(data) + 7) & ~7
    copy_offset, copy_end = place(copy_offset)
    padding = copy_offset - len(data)
    data += b"\0" * padding + new_strtab

    new_strtab_address = last_load[3] + copy_offset - last_load[2]
    new_library_offset = len(old_strtab)

    for offset, tag, _ in entries:
        if tag == DT_STRTAB:
            DYNAMIC_ENTRY.pack_into(data, offset, tag, new_strtab_address)
        elif tag == DT_STRSZ:
            DYNAMIC_ENTRY.pack_into(data, offset, tag, len(new_strtab))

    # Keep the injected library first in dependency order for symbol
    # interposition, then preserve the displaced stock dependency in the
    # redundant DT_FLAGS slot.
    DYNAMIC_ENTRY.pack_into(data, first_needed_offset, DT_NEEDED, new_library_offset)
    DYNAMIC_ENTRY.pack_into(data, replacement_offset, DT_NEEDED, first_needed)

    load_index = programs.index(last_load)
    last_load[5] = copy_end - last_load[2]
    last_load[6] = max(last_load[6], last_load[5])
    PROGRAM_HEADER.pack_into(data, phoff + load_index * phentsize, *last_load)

    if shoff and shnum:
        if shentsize != SECTION_HEADER.size or shstrndx >= shnum:
            raise ValueError("unexpected section-header layout")
        shstr_offset = shoff + shstrndx * shentsize
        shstr = SECTION_HEADER.unpack_from(data, shstr_offset)
        names_offset, names_size = shstr[4], shstr[5]
        for index in range(shnum):
            offset = shoff + index * shentsize
            section = list(SECTION_HEADER.unpack_from(data, offset))
            name_offset = names_offset + section[0]
            if name_offset >= names_offset + names_size:
                raise ValueError("section name is outside .shstrtab")
            if _cstring(data, name_offset) == ".dynstr":
                section[3] = new_strtab_address
                section[4] = copy_offset
                section[5] = len(new_strtab)
                SECTION_HEADER.pack_into(data, offset, *section)
                break
        else:
            raise ValueError(".dynstr section is missing")

    destination.write_bytes(data)
    destination.chmod(source.stat().st_mode)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path, nargs="?")
    parser.add_argument("--library", default="libxenoid_svcman.so")
    args = parser.parse_args()
    patch(args.source, args.destination or args.source, args.library)
    print(args.library)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
