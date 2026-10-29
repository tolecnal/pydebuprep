from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from pydebuprep.checks._apt_metadata import (
    keyring_findings,
    legacy_keyring_finding,
    metadata_findings,
    security_finding,
)
from pydebuprep.checks.base import Check, Context
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.osinfo import known_codenames
from pydebuprep.system import System

SOURCES_LIST = "/etc/apt/sources.list"
SOURCES_DIR = "/etc/apt/sources.list.d"
DISABLED_SUFFIXES = (".distUpgrade", ".save", ".disabled", ".dpkg-old", ".bak")
SUITE_SUFFIXES = ("-proposed-updates", "-updates", "-security", "-backports", "-proposed")
DISTRO_HOST_SUFFIXES = ("debian.org", "ubuntu.com", "canonical.com")
DISTRO_PATHS = ("/debian", "/debian-security", "/ubuntu", "/ubuntu-ports")
DEBIAN_ALIASES = {"stable", "oldstable", "oldoldstable", "testing", "unstable", "sid"}
UPGRADE_COMMENT = re.compile(r"disabled on upgrade to (\S+)")
COMMENTED_ENTRY = re.compile(r"^#+\s*(deb|deb-src)\s")


@dataclass
class SourceEntry:
    file: str
    type: str
    uri: str
    suite: str
    components: tuple[str, ...]
    enabled: bool
    disabled_reason: str | None
    line: str = ""
    signed_by: str = ""

    @property
    def suite_base(self) -> str:
        base = self.suite.removesuffix("/updates")
        for suffix in SUITE_SUFFIXES:
            if base.endswith(suffix):
                return base[: -len(suffix)]
        return base

    @property
    def norm_uri(self) -> str:
        return self.uri.rstrip("/")

    def describe(self) -> str:
        return f"{self.file}: {self.type} {self.uri} {self.suite} {' '.join(self.components)}"


def _parse_one_line(path: str, text: str, renamed: str | None) -> list[SourceEntry]:
    entries = []
    for raw in text.splitlines():
        line = raw.strip()
        enabled = True
        reason = renamed
        if line.startswith("#"):
            if not COMMENTED_ENTRY.match(line):
                continue
            enabled = False
            match = UPGRADE_COMMENT.search(line)
            reason = reason or (
                f"disabled on upgrade to {match.group(1)}" if match else "commented out"
            )
            line = line.lstrip("#").strip()
        content = line.split(" #", 1)[0].strip()
        if not content:
            continue
        options: dict[str, str] = {}
        if "[" in content and "]" in content:
            start, end = content.index("["), content.index("]")
            for item in content[start + 1 : end].split():
                key, _, value = item.partition("=")
                options[key.lower()] = value
            content = content[:start] + content[end + 1 :]
        tokens = content.split()
        if len(tokens) < 3 or tokens[0] not in ("deb", "deb-src"):
            continue
        entries.append(
            SourceEntry(
                path,
                tokens[0],
                tokens[1],
                tokens[2],
                tuple(tokens[3:]),
                enabled and renamed is None,
                reason,
                raw.strip(),
                options.get("signed-by", ""),
            )
        )
    return entries


def _parse_deb822(path: str, text: str, renamed: str | None) -> list[SourceEntry]:
    entries = []
    stanzas: list[dict[str, str]] = []
    current: dict[str, str] = {}
    key = ""
    for raw in [*text.splitlines(), ""]:
        if raw.startswith("#"):
            continue
        if not raw.strip():
            if current:
                stanzas.append(current)
            current, key = {}, ""
            continue
        if raw[0] in " \t" and key:
            current[key] += " " + raw.strip()
            continue
        key, _, value = raw.partition(":")
        key = key.strip().lower()
        current[key] = value.strip()
    for st in stanzas:
        enabled = st.get("enabled", "yes").lower() not in ("no", "false", "0")
        reason = renamed or (None if enabled else "Enabled: no")
        for typ in st.get("types", "").split():
            for uri in st.get("uris", "").split():
                for suite in st.get("suites", "").split():
                    entries.append(
                        SourceEntry(
                            path,
                            typ,
                            uri,
                            suite,
                            tuple(st.get("components", "").split()),
                            enabled and renamed is None,
                            reason,
                            signed_by=st.get("signed-by", ""),
                        )
                    )
    return entries


def parse_sources(system: System) -> list[SourceEntry]:
    entries: list[SourceEntry] = []
    for path in [SOURCES_LIST, *system.glob(f"{SOURCES_DIR}/*")]:
        text = system.read_text(path)
        if text is None:
            continue
        name = path
        renamed = None
        for suffix in DISABLED_SUFFIXES:
            if name.endswith(suffix):
                renamed = f"file renamed to *{suffix}"
                name = name[: -len(suffix)]
                break
        if name.endswith(".sources"):
            entries.extend(_parse_deb822(path, text, renamed))
        elif name.endswith(".list"):
            entries.extend(_parse_one_line(path, text, renamed))
    return entries


def is_distro(entry: SourceEntry, codename: str) -> bool:
    parsed = urlparse(entry.uri)
    host = parsed.hostname or ""
    if any(host == s or host.endswith("." + s) for s in DISTRO_HOST_SUFFIXES):
        return "ppa." not in host
    path = parsed.path.rstrip("/")
    return (
        path.endswith(DISTRO_PATHS)
        and "main" in entry.components
        and entry.suite_base in (codename, *DEBIAN_ALIASES)
    )


def _flagged_disabled(entry: SourceEntry) -> bool:
    reason = entry.disabled_reason or ""
    return not entry.enabled and reason != "commented out"


class AptSourcesCheck(Check):
    id = "apt-sources"
    title = "APT sources"
    category = "release"

    def run(self, ctx: Context) -> list[Finding]:
        codename = ctx.osinfo.codename
        family = ctx.osinfo.family
        entries = parse_sources(ctx.system)
        enabled = [e for e in entries if e.enabled]
        findings: list[Finding] = []

        old_suites: dict[str, list[SourceEntry]] = defaultdict(list)
        candidates = known_codenames(family) - {codename}
        for e in enabled:
            if e.suite_base in candidates:
                old_suites[e.suite_base].append(e)
        for suite, items in sorted(old_suites.items()):
            files = sorted({e.file for e in items})
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"Repository still targets {suite}",
                    detail=f"{len(items)} enabled source(s) use suite {suite}, "
                    f"but this system runs {codename}.",
                    evidence=truncate_evidence([e.describe() for e in items]),
                    remediation=[
                        *(
                            f"Edit {f}: change suite {suite} to {codename} (check the vendor "
                            f"supports {codename} first)"
                            for f in files
                        ),
                        "sudo apt update",
                    ],
                )
            )

        enabled_uris = {e.norm_uri for e in enabled}
        disabled = [
            e
            for e in entries
            if _flagged_disabled(e)
            and not is_distro(e, codename)
            and e.norm_uri not in enabled_uris
        ]
        if disabled:
            seen: dict[str, SourceEntry] = {}
            for e in disabled:
                seen.setdefault(e.norm_uri, e)
            findings.append(
                Finding(
                    Severity.WARNING,
                    "Third-party repository disabled",
                    detail="These repositories were disabled, usually by the release upgrade, "
                    "and nothing replaces them. Packages from them will not get updates.",
                    evidence=truncate_evidence(
                        [f"{e.describe()} ({e.disabled_reason})" for e in seen.values()]
                    ),
                    remediation=[
                        f"Check whether the vendor supports {codename}; if so re-enable the "
                        f"repository with suite {codename}, otherwise remove it",
                        "sudo apt update",
                    ],
                )
            )

        if family == "debian":
            aliases = sorted(
                {
                    e.suite_base
                    for e in enabled
                    if is_distro(e, codename) and e.suite_base in DEBIAN_ALIASES
                }
            )
            for alias in aliases:
                findings.append(
                    Finding(
                        Severity.INFO,
                        f"Debian archive uses suite alias '{alias}'",
                        detail="Aliases move to the next release automatically when it is "
                        "published, which can trigger an unplanned major upgrade.",
                        remediation=[f"Consider using the codename {codename} instead of {alias}"],
                    )
                )

        if not any(is_distro(e, codename) and e.type == "deb" for e in enabled):
            name = "Ubuntu" if family == "ubuntu" else "Debian"
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    f"No enabled repository for the {name} archive",
                    detail="No enabled source points at the distribution's own archive, so "
                    "security updates will not arrive.",
                    remediation=[
                        f"Add the {name} archive for {codename} to /etc/apt/sources.list.d/",
                        "sudo apt update",
                    ],
                )
            )

        findings += keyring_findings(ctx.system, enabled)
        findings += legacy_keyring_finding(ctx.system)
        findings += metadata_findings(ctx.system, enabled)
        distro = [e for e in enabled if is_distro(e, codename) and e.type == "deb"]
        findings += security_finding(codename, distro)

        groups: dict[tuple[str, str, str, str], list[SourceEntry]] = defaultdict(list)
        for e in enabled:
            for comp in e.components or ("",):
                groups[(e.type, e.norm_uri, e.suite, comp)].append(e)
        dupes = {k: v for k, v in groups.items() if len({e.file for e in v}) > 1 or len(v) > 1}
        if dupes:
            findings.append(
                Finding(
                    Severity.INFO,
                    "Duplicate repository entries",
                    detail="apt warns about targets configured multiple times.",
                    evidence=truncate_evidence(
                        [
                            f"{k[0]} {k[1]} {k[2]} {k[3]}: "
                            + ", ".join(sorted({e.file for e in v}))
                            for k, v in sorted(dupes.items())
                        ]
                    ),
                    remediation=["Remove the duplicate lines so each target appears once"],
                )
            )
        return findings

    def collect_baseline(self, ctx: Context) -> Any:
        return [
            {"file": e.file, "uri": e.uri, "suite": e.suite, "enabled": e.enabled}
            for e in parse_sources(ctx.system)
        ]

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now_enabled = {e.norm_uri for e in parse_sources(ctx.system) if e.enabled}
        lost: dict[str, dict[str, Any]] = {}
        for item in before:
            uri = str(item.get("uri", "")).rstrip("/")
            if item.get("enabled") and uri and uri not in now_enabled:
                lost.setdefault(uri, item)
        return [
            Finding(
                Severity.WARNING,
                f"Repository {uri} was enabled before the upgrade",
                detail=f"It was configured in {item.get('file')} with suite {item.get('suite')} "
                "and is now missing or disabled.",
                remediation=[
                    f"Re-enable it for {ctx.osinfo.codename} if the vendor supports it, "
                    "otherwise remove the packages that came from it",
                ],
            )
            for uri, item in sorted(lost.items())
        ]
