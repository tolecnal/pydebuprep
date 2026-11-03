"""Which packages belong to which kernel, and which kernels to keep.

A kernel is identified by its ABI, the part of its version every package built for it
carries in its name:
- Debian 12 and Ubuntu: `6.1.0-18`, `6.8.0-45` (as in linux-image-6.8.0-45-generic);
- Debian 13 on: `6.12.48+deb13`; backports: `6.12.12+bpo`.

Packages without one (linux-image-generic, linux-image-amd64, linux-kbuild-6.1) are
meta or shared packages and are never planned for removal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

KEEP_DEFAULT = 2
KEEP_MAX = 10
ABI = r"\d+\.\d+\.\d+(?:-\d+|\+[a-z0-9]+)"
PACKAGE = re.compile(rf"linux-(?P<prefix>[a-z0-9.-]*?)-(?P<abi>{ABI})(?:-[a-z0-9]+)*")
RELEASE = re.compile(rf"(?P<abi>{ABI})(?:-[a-z0-9]+)*")
IMAGE_PREFIXES = ("image", "image-unsigned")
SAVED_ENTRY = re.compile(rf"^saved_entry=.*?(?P<abi>{ABI})", re.M)


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


def grub_default_abi(grubenv: str | None) -> str | None:
    """The ABI of GRUB's saved default entry, when it names one."""
    match = SAVED_ENTRY.search(grubenv or "")
    return match.group("abi") if match else None


def _order(abi: str) -> tuple[int, ...]:
    numbers = [int(n) for n in re.findall(r"\d+", abi)]
    return (*numbers[:3], numbers[3] if "-" in abi and len(numbers) > 3 else 0)


def kept_abis(
    installed: list[str], *, running: str | None, grub: str | None, keep: int
) -> set[str]:
    """The newest KEEP kernels, plus the running one and GRUB's default: so with a
    reboot pending (running older than newest), both stay."""
    newest = sorted(set(installed), key=_order, reverse=True)[:keep]
    return {*newest, *(abi for abi in (running, grub) if abi)}
