from __future__ import annotations

import fnmatch
import os
import re

from pydebuprep.checks._elf import elf_dependencies
from pydebuprep.checks.base import Check, Context, Option, count
from pydebuprep.model import Finding, Severity, truncate_evidence

SEARCH_PATHS = ["/opt", "/srv", "/usr/local", "/root", "/home", "/var/www"]
VERSION = re.compile(r"^version(?:_info)?\s*=\s*(\d+)\.(\d+)", re.MULTILINE)
LDCONFIG = ("ldconfig", "-p")
# Where the dynamic linker looks when a library isn't in its cache.
DEFAULT_LIB_DIRS = ("/lib", "/usr/lib", "/lib64", "/usr/lib64")
HOST_ELF = "/bin/sh"  # its machine type is this system's


# Python extension modules: name.cpython-313-x86_64-linux-gnu.so, name.abi3.so, name.pypy...
EXTENSION = re.compile(r"\.(cpython-[^.]+|abi3|pypy[^.]*)\.so$")


def _is_extension_module(ctx: Context, path: str) -> bool:
    """A module Python imports, rather than a library or plugin a package loads only when
    asked to (Qt's database drivers, CUDA variants, ...), which aren't checked."""
    name = os.path.basename(path)
    if EXTENSION.search(name):
        return True
    directory = os.path.dirname(path)
    return (
        name.endswith(".so")
        and not name.startswith("lib")
        and (directory.endswith("site-packages") or ctx.system.exists(f"{directory}/__init__.py"))
    )


def _linker_view(ctx: Context) -> tuple[set[str], list[str]] | None:
    """Library names in the linker cache, and the directories to look in; None without
    ldconfig (non-root PATH, or minimal systems)."""
    if not ctx.system.which("ldconfig"):
        return None
    names, dirs = set(), set(DEFAULT_LIB_DIRS)
    res = ctx.system.run(LDCONFIG)
    if not res.ok:
        return None  # no cache to ask (missing /etc/ld.so.cache, ...): libraries unchecked
    for line in res.stdout.splitlines():
        name, _, target = line.strip().partition(" => ")
        if target:
            names.add(name.split(" (", 1)[0])
            directory = os.path.dirname(target)
            dirs |= {directory, directory.removeprefix("/usr")}
            dirs.add("/usr" + directory if not directory.startswith("/usr/") else directory)
    return names, sorted(dirs)


def _findable(ctx: Context, lib: str, search: list[str], view: tuple[set[str], list[str]]) -> bool:
    """Whether the dynamic linker would find LIB: a path, the module's own search path,
    the linker cache, or the default directories."""
    if "/" in lib:
        return ctx.system.exists(lib)
    cached, dirs = view
    return lib in cached or any(ctx.system.exists(f"{d}/{lib}") for d in (*search, *dirs))


class PythonVenvsCheck(Check):
    id = "python-venvs"
    title = "Python virtualenvs"
    category = "applications"
    options = (
        Option("search_paths", SEARCH_PATHS, "Directories searched for virtualenvs (pyvenv.cfg)"),
        Option("max_depth", 5, "How many directories deep to search below each path"),
        Option(
            "exclude_paths",
            ["*/.cache/*"],
            "Virtualenvs to leave out (shell-style patterns), e.g. tools' throwaway "
            "environments under ~/.cache",
        ),
    )

    def validate(self) -> None:
        if self.opt("max_depth") < 1:
            raise ValueError("max_depth must be at least 1")

    def run(self, ctx: Context) -> list[Finding]:
        system_python = ctx.system.python_version()
        current = tuple(int(p) for p in system_python.split("."))
        broken: list[str] = []
        older: list[str] = []
        working: list[str] = []
        for cfg in ctx.system.find_files(
            self.opt("search_paths"), "pyvenv.cfg", self.opt("max_depth")
        ):
            m = VERSION.search(ctx.system.read_text(cfg) or "")
            if not m:
                continue
            venv = os.path.dirname(cfg)
            if any(fnmatch.fnmatchcase(venv, p) for p in self.opt("exclude_paths")):
                continue
            label = f"{venv} (Python {m.group(1)}.{m.group(2)})"
            if not ctx.system.exists(f"{venv}/bin/python"):
                broken.append(label)
                continue
            working.append(venv)
            if (int(m.group(1)), int(m.group(2))) < current:
                older.append(label)
        findings = []
        if broken:
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"{count(len(broken), 'virtualenv points', 'virtualenvs point')} to a Python "
                    "that no longer exists",
                    detail="The upgrade replaced the Python they were built with, so anything "
                    "they run fails.",
                    evidence=truncate_evidence(broken),
                    remediation=[
                        "Recreate each one: python3 -m venv --clear PATH, then reinstall its "
                        "requirements",
                    ],
                )
            )
        if older:
            findings.append(
                Finding(
                    Severity.INFO,
                    f"{count(len(older), 'virtualenv was', 'virtualenvs were')} built for an older "
                    f"Python than the system's {system_python}",
                    detail="They still work while that Python stays installed, but won't get "
                    "its security updates for long.",
                    evidence=truncate_evidence(older),
                    remediation=["Recreate them with the current python3 when convenient"],
                )
            )
        findings += self._libraries(ctx, working) + self._entry_points(ctx, working)
        return findings

    @staticmethod
    def _libraries(ctx: Context, venvs: list[str]) -> list[Finding]:
        """Compiled modules needing a shared library the dynamic linker can't find."""
        modules = [
            path
            for venv in venvs
            for path in ctx.system.walk_files(f"{venv}/lib")
            if _is_extension_module(ctx, path)
        ]
        view = _linker_view(ctx) if modules else None  # only ask ldconfig when needed
        if view is None:
            return []
        host = elf_dependencies(ctx.system, HOST_ELF)
        missing = []
        for path in modules:
            deps = elf_dependencies(ctx.system, path)
            if deps is None or (host is not None and deps.machine != host.machine):
                continue  # not ELF, or built for another architecture
            # Its own directory counts too: wheels bundle libraries side by side (pkg.libs/)
            # that need each other and are found as the parent module loads them.
            search = [*deps.search, os.path.dirname(path)]
            gone = [lib for lib in deps.needed if not _findable(ctx, lib, search, view)]
            if gone:
                missing.append(f"{path}: {', '.join(gone)}")
        if not missing:
            return []
        n = len(missing)
        return [
            Finding(
                Severity.WARNING,
                f"{n} compiled module{'s' if n > 1 else ''} in virtualenvs "
                f"{'need libraries that are' if n > 1 else 'needs a library that is'} missing",
                detail="The upgrade removed or renamed shared libraries these extension "
                "modules were built against (libssl.so.1.1 is a classic); importing them "
                "fails.",
                evidence=truncate_evidence(sorted(missing)),
                remediation=[
                    "Reinstall the package in the virtualenv, so it gets a build for this "
                    "release: VENV/bin/pip install --force-reinstall --no-cache-dir PACKAGE",
                    "Or install the library: apt-file search LIBRARY",
                ],
            )
        ]

    @staticmethod
    def _entry_points(ctx: Context, venvs: list[str]) -> list[Finding]:
        """Scripts in a virtualenv's bin/ whose #! interpreter doesn't exist."""
        broken = []
        for venv in venvs:
            for script in ctx.system.glob(f"{venv}/bin/*"):
                head = ctx.system.read_range(script, 0, 256) or b""
                if not head.startswith(b"#!"):
                    continue
                words = head[2:].split(b"\n", 1)[0].decode("utf-8", "replace").split()
                interpreter = words[0] if words else ""
                if interpreter.startswith("/") and not ctx.system.exists(interpreter):
                    broken.append(f"{script}: #!{interpreter}")
        if not broken:
            return []
        n = len(broken)
        return [
            Finding(
                Severity.WARNING,
                f"{n} virtualenv script{'s' if n > 1 else ''} "
                f"{'start' if n > 1 else 'starts'} an interpreter that doesn't exist",
                detail="Usually a virtualenv that was moved or copied: its scripts still "
                "name the old path, so running them fails.",
                evidence=truncate_evidence(sorted(broken)),
                remediation=[
                    "Recreate the virtualenv where it is: python3 -m venv --clear PATH, then "
                    "reinstall its requirements",
                ],
            )
        ]
