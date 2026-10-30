"""python-venvs: broken entry points and missing native libraries (ELF read in Python)."""

from __future__ import annotations

import glob
import struct
from typing import Any

import pytest

from pydebuprep.checks._elf import elf_dependencies
from pydebuprep.checks.python_venvs import LDCONFIG, PythonVenvsCheck
from pydebuprep.model import Severity
from pydebuprep.system import System

from .helpers import make_ctx, titles

BASE = 0x400000


def build_elf(needed: list[str], runpath: str = "", machine: int = 62, cls: int = 64) -> bytes:
    """A minimal shared object: one load segment, a dynamic section and a string table."""
    names = [*needed, *([runpath] if runpath else [])]
    strtab = b"\0" + b"".join(n.encode() + b"\0" for n in names)
    offsets, pos = [], 1
    for n in names:
        offsets.append(pos)
        pos += len(n) + 1
    if cls == 64:
        ehsize, phsize, dynsize, dyn_fmt = 64, 56, 16, "<qQ"
    else:
        ehsize, phsize, dynsize, dyn_fmt = 52, 32, 8, "<iI"
    dyn_off = ehsize + 2 * phsize
    entries = [(1, o) for o in offsets[: len(needed)]]
    if runpath:
        entries.append((29, offsets[-1]))
    entries += [(5, 0), (10, len(strtab)), (0, 0)]
    str_off = dyn_off + len(entries) * dynsize
    entries = [(5, BASE + str_off) if tag == 5 else (tag, val) for tag, val in entries]
    dynamic = b"".join(struct.pack(dyn_fmt, tag, val) for tag, val in entries)
    total = str_off + len(strtab)
    ident = b"\x7fELF" + bytes([2 if cls == 64 else 1, 1, 1, 0]) + bytes(8)
    if cls == 64:
        header = ident + struct.pack(
            "<HHIQQQIHHHHHH", 3, machine, 1, 0, ehsize, 0, 0, ehsize, phsize, 2, 0, 0, 0
        )
        load = struct.pack("<IIQQQQQQ", 1, 5, 0, BASE, BASE, total, total, 0x1000)
        dyn = struct.pack(
            "<IIQQQQQQ",
            2,
            6,
            dyn_off,
            BASE + dyn_off,
            BASE + dyn_off,
            len(dynamic),
            len(dynamic),
            8,
        )
    else:
        header = ident + struct.pack(
            "<HHIIIIIHHHHHH", 3, machine, 1, 0, ehsize, 0, 0, ehsize, phsize, 2, 0, 0, 0
        )
        load = struct.pack("<IIIIIIII", 1, 0, BASE, BASE, total, total, 5, 0x1000)
        dyn = struct.pack(
            "<IIIIIIII",
            2,
            dyn_off,
            BASE + dyn_off,
            BASE + dyn_off,
            len(dynamic),
            len(dynamic),
            6,
            4,
        )
    return header + load + dyn + dynamic + strtab


def test_elf_dependencies_64_and_32_bit() -> None:
    for cls in (64, 32):
        data = build_elf(["libssl.so.3", "libc.so.6"], "$ORIGIN/../mylib.libs", cls=cls)
        ctx = make_ctx(files={"/v/lib/m.so": data})
        deps = elf_dependencies(ctx.system, "/v/lib/m.so")
        assert deps is not None
        assert deps.needed == ["libssl.so.3", "libc.so.6"]
        assert deps.search == ["/v/mylib.libs"]
        assert deps.machine == 62


@pytest.mark.parametrize(
    "data", [b"", b"not an elf", b"\x7fELF" + bytes(10), build_elf(["x"])[:100]]
)
def test_elf_dependencies_of_junk(data: bytes) -> None:
    assert elf_dependencies(make_ctx(files={"/x.so": data}).system, "/x.so") is None


def test_elf_dependencies_of_a_real_extension_module() -> None:
    modules = glob.glob("/usr/lib/python3*/lib-dynload/_ssl.*.so")
    if not modules:
        pytest.skip("no _ssl extension module here")
    deps = elf_dependencies(System(), modules[0])
    assert deps is not None
    assert any(n.startswith("libssl.so") for n in deps.needed)


# --- the check ------------------------------------------------------------------------

VENV = "/opt/app/.venv"
SITE = f"{VENV}/lib/python3.13/site-packages"
LDCONFIG_OUT = (
    "831 libs found in cache `/etc/ld.so.cache'\n"
    "\tlibc.so.6 (libc6,x86-64, OS ABI: Linux 3.2.0) => /lib/x86_64-linux-gnu/libc.so.6\n"
    "\tlibssl.so.3 (libc6,x86-64) => /lib/x86_64-linux-gnu/libssl.so.3\n"
)


def venv_files(**extra: Any) -> dict[str, Any]:
    return {
        f"{VENV}/pyvenv.cfg": "home = /usr/bin\nversion = 3.13.5\n",
        f"{VENV}/bin/python": "",
        f"{VENV}/bin/pip": "#!/opt/app/.venv/bin/python\nimport pip\n",
        f"{VENV}/bin/old-tool": "#!/srv/moved/.venv/bin/python3\nimport x\n",
        f"{VENV}/bin/envtool": "#!/usr/bin/env python3\n",
        f"{VENV}/bin/binary": b"\x7fELF\x02\x01\x01" + bytes(100),
        f"{SITE}/ok.cpython-313-x86_64-linux-gnu.so": build_elf(["libssl.so.3", "libc.so.6"]),
        f"{SITE}/old.cpython-313-x86_64-linux-gnu.so": build_elf(["libssl.so.1.1", "libc.so.6"]),
        f"{SITE}/bundled.so": build_elf(["libquux.so.2"], "$ORIGIN/../bundled.libs"),
        f"{VENV}/lib/python3.13/bundled.libs/libquux.so.2": "",
        f"{SITE}/arm.so": build_elf(["libnothing.so"], machine=183),
        f"{SITE}/readme.txt": "",
        "/bin/sh": build_elf([]),
        "/usr/bin/env": "",
        **extra,
    }


def venvs(files: dict[str, Any], **kw: Any) -> list[Any]:
    ctx = make_ctx(files=files, python="3.13", commands={LDCONFIG: LDCONFIG_OUT}, **kw)
    return PythonVenvsCheck().run(ctx)


def test_missing_libraries_and_broken_entry_points() -> None:
    fs = venvs(venv_files())
    assert [(f.severity, f.title, f.evidence) for f in fs] == [
        (Severity.WARNING, "1 compiled module in virtualenvs needs a library that is missing",
         [f"{SITE}/old.cpython-313-x86_64-linux-gnu.so: libssl.so.1.1"]),
        (Severity.WARNING, "1 virtualenv script starts an interpreter that doesn't exist",
         [f"{VENV}/bin/old-tool: #!/srv/moved/.venv/bin/python3"]),
    ]  # fmt: skip


def test_without_ldconfig_libraries_are_not_checked() -> None:
    fs = venvs(venv_files(), available={"python3"})
    assert titles(fs) == ["1 virtualenv script starts an interpreter that doesn't exist"]


def test_broken_venvs_are_not_scanned_again() -> None:
    files = venv_files()
    del files[f"{VENV}/bin/python"]
    assert titles(venvs(files)) == ["1 virtualenv points to a Python that no longer exists"]


def test_libraries_in_default_directories_count() -> None:
    files = venv_files(**{"/usr/lib/x86_64-linux-gnu/libssl.so.1.1": ""})
    assert titles(venvs(files)) == ["1 virtualenv script starts an interpreter that doesn't exist"]


def patched(fmt: str, offset: int, value: int) -> bytes:
    data = bytearray(build_elf(["libx.so.1"]))
    struct.pack_into(fmt, data, offset, value)
    return bytes(data)


def test_elf_edge_cases() -> None:
    def deps(data: bytes) -> Any:
        return elf_dependencies(make_ctx(files={"/m.so": data}).system, "/m.so")

    assert deps(patched("<H", 56, 999)) is None  # absurd program header count
    static = deps(patched("<I", 120, 0))  # no PT_DYNAMIC: a static object needs nothing
    assert static is not None and static.needed == []
    assert deps(patched("<Q", 120 + 32, 0)) is None  # empty dynamic section: no string table
    assert deps(patched("<Q", 64 + 16, 0x900000)) is None  # string table in no load segment


def test_absolute_library_paths() -> None:
    files = venv_files()
    files[f"{SITE}/abs.so"] = build_elf(["/opt/vendor/lib/libabs.so.1"])
    fs = venvs(files)
    assert f"{SITE}/abs.so: /opt/vendor/lib/libabs.so.1" in fs[0].evidence
    files["/opt/vendor/lib/libabs.so.1"] = ""
    assert f"{SITE}/abs.so: /opt/vendor/lib/libabs.so.1" not in venvs(files)[0].evidence


def test_bundled_wheel_libraries_find_their_siblings() -> None:
    # auditwheel puts a wheel's own copies of libraries in pkg.libs/; they need each
    # other without a search path, and the loader finds them as the parent loads them.
    files = venv_files()
    files[f"{SITE}/numpy.libs/libgfortran-0400.so.5.0.0"] = build_elf(["libquadmath-9697.so.0.0.0"])
    files[f"{SITE}/numpy.libs/libquadmath-9697.so.0.0.0"] = build_elf([])
    assert all("numpy.libs" not in e for f in venvs(files) for e in f.evidence)


# --- final review fixes --------------------------------------------------------------

from pydebuprep.system import CommandResult  # noqa: E402


def test_only_python_extension_modules_are_checked() -> None:
    # Optional plugins and per-backend libraries load only when used: not findings.
    files = venv_files()
    files[f"{SITE}/PySide6/Qt/plugins/sqldrivers/libqsqlpsql.so"] = build_elf(["libpq.so.5"])
    files[f"{SITE}/bitsandbytes/__init__.py"] = ""
    files[f"{SITE}/bitsandbytes/libbitsandbytes_cuda118.so"] = build_elf(["libcudart.so.11.0"])
    files[f"{SITE}/pkg/__init__.py"] = ""
    files[f"{SITE}/pkg/_speedups.so"] = build_elf(["libgone.so.1"])
    files[f"{SITE}/pkg/data/helper.so"] = build_elf(["libgone2.so.1"])  # not a package dir
    evidence = [e for f in venvs(files) for e in f.evidence]
    assert f"{SITE}/pkg/_speedups.so: libgone.so.1" in evidence
    assert not any(word in e for e in evidence for word in ("libpq", "libcudart", "libgone2"))


def test_a_failing_ldconfig_only_skips_the_library_check() -> None:
    fail = CommandResult(LDCONFIG, 1, "", "ldconfig: Can't open cache file /etc/ld.so.cache\n")
    ctx = make_ctx(files=venv_files(), python="3.13", commands={LDCONFIG: fail})
    assert titles(PythonVenvsCheck().run(ctx)) == [
        "1 virtualenv script starts an interpreter that doesn't exist"
    ]
