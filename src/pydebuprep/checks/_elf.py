"""Which shared libraries an ELF file needs, read from its headers in Python.

`ldd` is never used: it can execute code from the file it inspects. Only the ELF header,
the program headers, the dynamic section and its string table are read.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from pydebuprep.system import System

PT_LOAD, PT_DYNAMIC = 1, 2
DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_RPATH, DT_RUNPATH = 0, 1, 5, 10, 15, 29
MAX_PHNUM = 128
MAX_DYNAMIC = 64 * 1024
MAX_STRTAB = 4 * 1024 * 1024


@dataclass
class ElfDependencies:
    machine: int
    needed: list[str]
    search: list[str]  # RUNPATH (or RPATH) directories, $ORIGIN expanded


def elf_dependencies(system: System, path: str) -> ElfDependencies | None:
    """The DT_NEEDED libraries and search path of a shared object, or None if it isn't
    a readable ELF file."""
    try:
        return _parse(system, path)
    except (struct.error, ValueError, IndexError):
        return None


def _parse(system: System, path: str) -> ElfDependencies | None:
    head = system.read_range(path, 0, 64)
    if not head or len(head) < 52 or head[:4] != b"\x7fELF" or head[4] not in (1, 2):
        return None
    wide = head[4] == 2
    end = "<" if head[5] == 1 else ">"
    machine = struct.unpack_from(end + "H", head, 18)[0]
    if wide:
        phoff = struct.unpack_from(end + "Q", head, 32)[0]
        phentsize, phnum = struct.unpack_from(end + "HH", head, 54)
        ph_fmt, dyn_fmt = end + "IIQQQQQQ", end + "qQ"
    else:
        phoff = struct.unpack_from(end + "I", head, 28)[0]
        phentsize, phnum = struct.unpack_from(end + "HH", head, 42)
        ph_fmt, dyn_fmt = end + "IIIIIIII", end + "iI"
    if phnum > MAX_PHNUM:
        return None
    table = system.read_range(path, phoff, phentsize * phnum) or b""
    loads: list[tuple[int, int, int]] = []  # (vaddr, memsz, offset)
    dynamic: tuple[int, int] | None = None
    for i in range(phnum):
        fields = struct.unpack_from(ph_fmt, table, i * phentsize)
        if wide:
            p_type, _, offset, vaddr, _, filesz, memsz, _ = fields
        else:
            p_type, offset, vaddr, _, filesz, memsz, _, _ = fields
        if p_type == PT_LOAD:
            loads.append((vaddr, memsz, offset))
        elif p_type == PT_DYNAMIC:
            dynamic = (offset, min(filesz, MAX_DYNAMIC))
    if dynamic is None:
        return ElfDependencies(machine, [], [])
    data = system.read_range(path, *dynamic) or b""
    size = struct.calcsize(dyn_fmt)
    needed, paths, strtab, strsz = [], [], None, MAX_STRTAB
    for i in range(len(data) // size):
        tag, value = struct.unpack_from(dyn_fmt, data, i * size)
        if tag == DT_NULL:
            break
        if tag == DT_NEEDED:
            needed.append(value)
        elif tag in (DT_RPATH, DT_RUNPATH):
            paths.append((tag, value))
        elif tag == DT_STRTAB:
            strtab = value
        elif tag == DT_STRSZ:
            strsz = min(value, MAX_STRTAB)
    if strtab is None:
        return None
    offset = next((off + strtab - va for va, sz, off in loads if va <= strtab < va + sz), None)
    if offset is None:
        return None
    strings = system.read_range(path, offset, strsz) or b""

    def text(at: int) -> str:
        return strings[at : strings.index(b"\0", at)].decode("utf-8", "replace")

    # RUNPATH wins over RPATH when both are set, as with the dynamic linker.
    chosen = [v for t, v in paths if t == DT_RUNPATH] or [v for t, v in paths if t == DT_RPATH]
    origin = os.path.dirname(path)
    search = [
        os.path.normpath(d.replace("${ORIGIN}", origin).replace("$ORIGIN", origin))
        for v in chosen
        for d in text(v).split(":")
        if d
    ]
    return ElfDependencies(machine, [text(v) for v in needed], search)
