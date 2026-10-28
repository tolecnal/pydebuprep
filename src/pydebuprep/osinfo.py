"""OS release detection and the table of supported releases."""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from pydebuprep.system import System


@dataclass(frozen=True)
class Release:
    codename: str
    version: str
    family: str
    previous: str
    notes_url: str


def _debian(codename: str, version: str, previous: str) -> Release:
    url = f"https://www.debian.org/releases/{codename}/releasenotes"
    return Release(codename, version, "debian", previous, url)


def _ubuntu(codename: str, version: str, previous: str) -> Release:
    url = f"https://discourse.ubuntu.com/t/{codename}-release-notes"
    return Release(codename, version, "ubuntu", previous, url)


RELEASES: dict[str, Release] = {
    r.codename: r
    for r in (
        _debian("bookworm", "12", "bullseye"),
        _debian("trixie", "13", "bookworm"),
        _ubuntu("jammy", "22.04", "focal"),
        _ubuntu("noble", "24.04", "jammy"),
        _ubuntu("resolute", "26.04", "noble"),
    )
}


@dataclass
class OsInfo:
    id: str
    version_id: str
    codename: str
    pretty_name: str
    release: Release | None

    @property
    def supported(self) -> bool:
        return self.release is not None

    @property
    def family(self) -> str:
        return self.release.family if self.release else self.id


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        try:
            parts = shlex.split(value)
        except ValueError:
            parts = [value.strip("\"'")]
        values[key.strip()] = parts[0] if parts else ""
    return values


def detect_os(system: System) -> OsInfo:
    text = system.read_text("/etc/os-release") or system.read_text("/usr/lib/os-release") or ""
    d = parse_os_release(text)
    os_id = d.get("ID", "unknown")
    codename = d.get("VERSION_CODENAME") or d.get("UBUNTU_CODENAME", "")
    release = RELEASES.get(codename)
    if release is not None and release.family != os_id:
        release = None
    return OsInfo(
        id=os_id,
        version_id=d.get("VERSION_ID", ""),
        codename=codename,
        pretty_name=d.get("PRETTY_NAME", d.get("NAME", os_id)),
        release=release,
    )


def known_codenames(family: str) -> set[str]:
    names: set[str] = set()
    for r in RELEASES.values():
        if r.family == family:
            names.update((r.codename, r.previous))
    return names
