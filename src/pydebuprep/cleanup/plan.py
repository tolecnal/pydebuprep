"""What each cleanup option would remove: worked out from dpkg's package list, the
running kernel and GRUB's default, read through the read-only System."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass

from pydebuprep.cleanup.kernels import (
    Package,
    grub_default_abi,
    kept_abis,
    kernel_abi,
    kind,
    parse_packages,
    running_abi,
)
from pydebuprep.system import DPKG_PACKAGES_ARGV, MAX_OWNER_PATHS, OWNER_QUERY, System

PACKAGES_ARGV = DPKG_PACKAGES_ARGV
GRUBENV = "/boot/grub/grubenv"
MODULE_DIRS = "/lib/modules/*"
HEADER_DIRS = "/usr/src/linux-*headers-*"
LEFTOVER_DIR = re.compile(r"/lib/modules/[^/]+|/usr/src/linux-[a-z0-9.+-]*headers-[^/]+")

__all__ = ["OWNER_QUERY", "PACKAGES_ARGV", "Choice", "Plan", "Refused", "build_plan"]


class Refused(Exception):
    """A guardrail: the cleanup won't plan or act, for the reason given."""


@dataclass(frozen=True)
class Choice:
    kernels: bool
    modules: bool
    dirs: bool
    residual: bool
    keep: int
    keep_packages: frozenset[str]


@dataclass(frozen=True)
class Plan:
    kernels: tuple[Package, ...] = ()
    modules: tuple[Package, ...] = ()
    dirs: tuple[str, ...] = ()
    residual: tuple[Package, ...] = ()
    kept: tuple[str, ...] = ()  # kernel ABIs that stay
    skipped: tuple[str, ...] = ()  # packages left out with --keep-package

    @property
    def packages(self) -> tuple[str, ...]:
        return tuple(p.name for p in (*self.kernels, *self.modules, *self.residual))

    @property
    def size_kib(self) -> int:
        return sum(p.size_kib for p in (*self.kernels, *self.modules, *self.residual))


def leftover_dir_ok(path: str) -> bool:
    """One of the two kinds of directory the cleanup may remove, written plainly."""
    return os.path.normpath(path) == path and LEFTOVER_DIR.fullmatch(path) is not None


def _query(system: System, argv: Sequence[str], *, ok: tuple[int, ...] = (0,)) -> str:
    res = system.run(argv)
    if res.timed_out or res.returncode not in ok:
        detail = (res.stderr or res.stdout).strip().splitlines()
        raise Refused(f"{argv[0]} failed{': ' + detail[0] if detail else ''}")
    return res.stdout


def _dir_abi(path: str) -> str | None:
    name = os.path.basename(path)
    if path.startswith("/lib/modules/"):
        return running_abi(name)
    return kernel_abi(name)


def owners(system: System, paths: Sequence[str]) -> dict[str, set[str]]:
    """The packages owning files in or below each of PATHS (dpkg-query -S)."""
    found: dict[str, set[str]] = {p: set() for p in paths}
    for start in range(0, len(paths), MAX_OWNER_PATHS):
        chunk = paths[start : start + MAX_OWNER_PATHS]
        # Exit status 1 just means a path no package owns.
        out = _query(system, (*OWNER_QUERY, *chunk), ok=(0, 1))
        for line in out.splitlines():
            names, sep, file = line.partition(": ")
            if not sep:
                continue
            for path in chunk:
                if file == path or file.startswith(path + "/"):
                    found[path] |= {n.strip() for n in names.split(",")}
    return found


def _leftover_dirs(system: System, kept: set[str], purged: set[str]) -> tuple[str, ...]:
    """Kernel directories of kernels not kept, that no package owns or only packages
    this run purges (their DKMS leftovers stay behind after the purge)."""
    candidates = [
        p
        for p in sorted({*system.glob(MODULE_DIRS), *system.glob(HEADER_DIRS)})
        if leftover_dir_ok(p)
        and system.is_real_dir(p)
        and (abi := _dir_abi(p)) is not None
        and abi not in kept
    ]
    if not candidates:
        return ()
    found = owners(system, candidates)
    return tuple(p for p in candidates if found[p] <= purged)


def build_plan(system: System, choice: Choice) -> Plan:
    packages = sorted(parse_packages(_query(system, PACKAGES_ARGV)), key=lambda p: p.name)
    skipped = tuple(sorted(p.name for p in packages if p.name in choice.keep_packages))
    packages = [p for p in packages if p.name not in choice.keep_packages]
    residual = tuple(
        p for p in packages if choice.residual and p.status == "rc" and kernel_abi(p.name) is None
    )
    if not (choice.kernels or choice.modules or choice.dirs):
        return Plan(residual=residual, skipped=skipped)
    running = running_abi(_query(system, ("uname", "-r")))
    if running is None:
        raise Refused(
            "can't identify the running kernel (one built by hand?), so no kernel, module "
            "or directory is removed"
        )
    abis = [abi for p in packages if p.status.startswith("i") and (abi := kernel_abi(p.name))]
    grub = grub_default_abi(system.read_text(GRUBENV))
    kept = kept_abis(abis, running=running, grub=grub, keep=choice.keep)
    old = [p for p in packages if (abi := kernel_abi(p.name)) is not None and abi not in kept]
    kernels = tuple(p for p in old if choice.kernels and kind(p.name) == "image")
    modules = tuple(p for p in old if choice.modules and kind(p.name) == "modules")
    purged = {p.name for p in (*kernels, *modules)}
    return Plan(
        kernels=kernels,
        modules=modules,
        dirs=_leftover_dirs(system, kept, purged) if choice.dirs else (),
        residual=residual,
        kept=tuple(sorted(kept)),
        skipped=skipped,
    )
