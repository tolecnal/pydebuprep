"""What each cleanup option would remove: worked out from dpkg's package list, the
running kernel and GRUB's default, read through the read-only System."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass

from pydebuprep.cleanup.kernels import (
    Package,
    grub_entry_abi,
    kept_abis,
    kernel_abi,
    kind,
    parse_packages,
    running_abi,
)
from pydebuprep.system import (
    DPKG_ARCH_ARGV,
    DPKG_PACKAGES_ARGV,
    MAX_OWNER_PATHS,
    OWNER_QUERY,
    System,
)

PACKAGES_ARGV = DPKG_PACKAGES_ARGV
ARCH_ARGV = DPKG_ARCH_ARGV
GRUBENV = "/boot/grub/grubenv"
GRUB_DEFAULTS = "/etc/default/grub"
GRUB_DEFAULTS_D = "/etc/default/grub.d/*.cfg"
GRUB_DEFAULT = re.compile(r"^\s*(?:export\s+)?GRUB_DEFAULT=(.*)$", re.M)
GRUBENV_ENTRY = re.compile(r"^(?:saved_entry|next_entry)=(.*)$", re.M)
MODULE_DIRS = "/lib/modules/*"
HEADER_DIRS = "/usr/src/linux-*headers-*"
LEFTOVER_DIR = re.compile(r"/lib/modules/[^/]+|/usr/src/linux-[a-z0-9.+-]*headers-[^/]+")

__all__ = ["ARCH_ARGV", "OWNER_QUERY", "PACKAGES_ARGV", "Choice", "Plan", "Refused", "build_plan"]


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
    skipped: tuple[str, ...] = ()  # packages left alone: held, or --keep-package
    arch: str = ""  # dpkg's native architecture, which apt leaves out of package names

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


def _spellings(path: str) -> list[str]:
    """PATH, and its /usr/lib/modules twin: dpkg records Debian 13's kernels there, and
    doesn't treat /lib and /usr/lib as one path."""
    return [path, "/usr" + path] if path.startswith("/lib/modules/") else [path]


def owners(system: System, paths: Sequence[str]) -> dict[str, set[str]]:
    """The packages owning files in or below each of PATHS (dpkg-query -S), under
    either spelling of a kernel module directory."""
    found: dict[str, set[str]] = {p: set() for p in paths}
    queries = [(path, spelling) for path in paths for spelling in _spellings(path)]
    for start in range(0, len(queries), MAX_OWNER_PATHS):
        chunk = queries[start : start + MAX_OWNER_PATHS]
        # Exit status 1 just means a path no package owns.
        out = _query(system, (*OWNER_QUERY, *(s for _, s in chunk)), ok=(0, 1))
        for line in out.splitlines():
            names, sep, file = line.partition(": ")
            if not sep:
                continue
            for path, spelling in chunk:
                if file == spelling or file.startswith(spelling + "/"):
                    found[path] |= {n.strip() for n in names.split(",")}
    return found


def _installed(package: Package) -> bool:
    """Installed in any way (dpkg's actual state: not "not installed" or "config-files")."""
    return package.status[1:2] not in ("", "n", "c")


def _held(package: Package) -> bool:
    return package.status.startswith("h")


def _leftover_dirs(
    system: System, kept: set[str], purged: set[str], packages: Sequence[Package]
) -> tuple[str, ...]:
    """Kernel directories of kernels not kept, that no package owns or only packages
    this run purges (their DKMS leftovers stay behind after the purge). A kernel with
    any installed package this run doesn't purge keeps its directories, whatever
    dpkg-query -S says."""
    staying = {
        abi
        for p in packages
        if _installed(p) and p.name not in purged and (abi := kernel_abi(p.name)) is not None
    }
    candidates = [
        p
        for p in sorted({*system.glob(MODULE_DIRS), *system.glob(HEADER_DIRS)})
        if leftover_dir_ok(p)
        and system.is_real_dir(p)
        and (abi := _dir_abi(p)) is not None
        and abi not in kept
        and abi not in staying
    ]
    if not candidates:
        return ()
    found = owners(system, candidates)
    return tuple(p for p in candidates if found[p] <= purged)


def grub_pins(system: System) -> set[str]:
    """The kernels GRUB is set to boot: GRUB_DEFAULT (the last one set, as GRUB's own
    scripts read /etc/default/grub then grub.d) and grubenv's saved and next entries.
    A GRUB_DEFAULT that can't be matched to a kernel (a menu position, a title without
    a version) refuses: guessing could remove the kernel the host boots."""
    value = None
    for path in [GRUB_DEFAULTS, *sorted(system.glob(GRUB_DEFAULTS_D))]:
        for match in GRUB_DEFAULT.finditer(system.read_text(path) or ""):
            value = match.group(1).strip().strip("\"'")
    pins = set()
    if value not in (None, "", "0", "saved"):
        abi = grub_entry_abi(value)
        if abi is None:
            raise Refused(
                f"GRUB_DEFAULT={value} names a menu entry that can't be matched to a kernel, so "
                "no kernel, module or directory is removed; set it to the kernel's own entry, or "
                "to 0 or saved"
            )
        pins.add(abi)
    for entry in GRUBENV_ENTRY.findall(system.read_text(GRUBENV) or ""):
        if (abi := grub_entry_abi(entry)) is not None:
            pins.add(abi)
    return pins


def _kept_by_choice(package: Package, keep: frozenset[str]) -> bool:
    """Left alone: held (apt-mark hold), or named with --keep-package or in the config,
    with or without its architecture."""
    return _held(package) or package.name in keep or package.name.split(":")[0] in keep


def build_plan(system: System, choice: Choice) -> Plan:
    packages = sorted(parse_packages(_query(system, PACKAGES_ARGV)), key=lambda p: p.name)
    arch = _query(system, ARCH_ARGV).strip()
    skipped: list[str] = []

    def chosen(candidates: Sequence[Package]) -> tuple[Package, ...]:
        left = [p for p in candidates if _kept_by_choice(p, choice.keep_packages)]
        skipped.extend(p.name for p in left)
        return tuple(p for p in candidates if p not in left)

    residual = chosen([
        p for p in packages
        if choice.residual and p.status[1:2] == "c" and kernel_abi(p.name) is None
    ])  # fmt: skip
    if not (choice.kernels or choice.modules or choice.dirs):
        return Plan(residual=residual, skipped=tuple(sorted(skipped)), arch=arch)
    running = running_abi(_query(system, ("uname", "-r")))
    if running is None:
        raise Refused(
            "can't identify the running kernel (one built by hand?), so no kernel, module "
            "or directory is removed"
        )
    # Only installed images are kernels that boot: headers alone don't count.
    images = [
        abi
        for p in packages
        if _installed(p) and kind(p.name) == "image" and (abi := kernel_abi(p.name))
    ]
    kept = kept_abis(images, running=running, pinned=grub_pins(system), keep=choice.keep)
    old = [p for p in packages if (abi := kernel_abi(p.name)) is not None and abi not in kept]
    kernels = chosen([p for p in old if choice.kernels and kind(p.name) == "image"])
    modules = chosen([p for p in old if choice.modules and kind(p.name) == "modules"])
    purged = {p.name for p in (*kernels, *modules)}
    return Plan(
        kernels=kernels,
        modules=modules,
        dirs=_leftover_dirs(system, kept, purged, packages) if choice.dirs else (),
        residual=residual,
        kept=tuple(sorted(kept)),
        skipped=tuple(sorted(skipped)),
        arch=arch,
    )
