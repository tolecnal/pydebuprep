"""Which packages belong to which kernel, and which kernels to keep.

A kernel is identified by its ABI, the part of its version every package built for it
carries in its name:
- Debian 12 and Ubuntu: `6.1.0-18`, `6.8.0-45` (as in linux-image-6.8.0-45-generic);
- Debian 13 on: `6.12.48+deb13`, and point releases `6.12.115+deb13.1`;
  backports: `6.12.12+bpo`.

Packages without one (linux-image-generic, linux-image-amd64, linux-kbuild-6.1) are
meta or shared packages and are never planned for removal.
"""

from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass
from typing import Literal

KEEP_DEFAULT = 2
KEEP_MAX = 10
ABI = r"\d+\.\d+\.\d+(?:-\d+|\+[a-z0-9]+(?:\.\d+)*)"
PACKAGE = re.compile(rf"linux-(?P<prefix>[a-z0-9.-]*?)-(?P<abi>{ABI})(?:-[a-z0-9]+)*")
RELEASE = re.compile(rf"(?P<abi>{ABI})(?:-[a-z0-9]+)*")
IMAGE_PREFIXES = ("image", "image-unsigned")
ENTRY_ABI = re.compile(rf"(?P<abi>{ABI})")


@dataclass(frozen=True)
class Package:
    name: str
    status: str  # dpkg's abbreviation: ii installed, rc config files only, ...
    version: str
    size_kib: int


def parse_packages(text: str) -> list[Package]:
    """Packages from `dpkg-query -W -f='${db:Status-Abbrev}\\t${Package}\\t${Version}\\t
    ${Installed-Size}\\n'`."""
    found = []
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            continue
        status, name, version, size = fields
        found.append(Package(name, status.strip(), version, int(size) if size.isdigit() else 0))
    return found


def kernel_abi(name: str) -> str | None:
    match = PACKAGE.fullmatch(name)
    return match.group("abi") if match else None


def kind(name: str) -> Literal["image", "modules"] | None:
    """ "image" for a kernel image, "modules" for anything else built for one kernel
    (modules, headers, tools); None for packages that aren't."""
    match = PACKAGE.fullmatch(name)
    if match is None:
        return None
    return "image" if match.group("prefix") in IMAGE_PREFIXES else "modules"


def running_abi(uname: str) -> str | None:
    """The ABI of `uname -r`; None for a kernel we can't place (one built by hand)."""
    match = RELEASE.fullmatch(uname.strip())
    return match.group("abi") if match else None


def grub_entry_abi(entry: str) -> str | None:
    """The kernel a GRUB menu entry (title or ID) names, if any."""
    match = ENTRY_ABI.search(entry)
    return match.group("abi") if match else None


def _order(abi: str) -> tuple[int, ...]:
    """6.8.0-45 → (6, 8, 0, 45); 6.12.115+deb13.1 → (6, 12, 115, 0, 13, 1)."""
    base, sep, tail = re.split(r"([-+])", abi, maxsplit=1)
    numbers = tuple(int(n) for n in base.split("."))
    if sep == "-":
        return (*numbers, int(tail))
    return (*numbers, 0, *(int(n) for n in re.findall(r"\d+", tail)))


def kept_abis(
    installed: list[str], *, running: str | None, pinned: Collection[str] = (), keep: int
) -> set[str]:
    """The newest KEEP kernels, plus the running one and those GRUB is set to boot: so
    with a reboot pending (running older than newest), both stay."""
    newest = sorted(set(installed), key=_order, reverse=True)[:keep]
    return {*newest, *pinned, *([running] if running else [])}
