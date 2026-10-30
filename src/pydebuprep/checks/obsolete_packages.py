from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from pydebuprep.checks._apt_metadata import LISTS_DIR, parse_release
from pydebuprep.checks.apt_upgradable import package_lines
from pydebuprep.checks.base import Check, Context, count, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.system import apt_command

PKG_VERSIONS_ARGV = ("dpkg-query", "-W", "-f=${Package}\t${Version}\n")
# Hosts that serve the distributions' own archives (mirrors too: deb.debian.org, ...).
DISTRO_HOSTS = ("debian.org", "ubuntu.com", "canonical.com")
NAMES_SHOWN = 10


def installed_versions(ctx: Context) -> dict[str, str]:
    out = run_checked(ctx, PKG_VERSIONS_ARGV).stdout
    versions = {}
    for line in out.splitlines():
        name, _, version = line.partition("\t")
        if name and version:
            versions[name] = version
    return versions


def _distro(label: str) -> bool:
    """The distributions' own archives, Ubuntu Pro (UbuntuESM, UbuntuESMApps, ...) and
    Debian Backports included. Vendor labels carry their host: "Docker (download.docker.com)"."""
    return label.startswith(("Debian", "Ubuntu")) and not label.endswith(")")


def _origin_key(label: str) -> str:
    """What identifies an origin across a release upgrade: a vendor's host (their Origin
    often names the release, like "ubuntu icinga-noble"), or the distribution's name."""
    if label.endswith(")") and " (" in label:
        return label[label.rindex(" (") + 2 : -1]
    return label


def _origin_name(ctx: Context, path: str, inreleases: list[str]) -> str:
    """Who a Packages index comes from: "Debian" or "Ubuntu" for the distributions'
    archives, otherwise the vendor's Origin with its host ("Docker (download.docker.com)"),
    since vendors name their Origin freely."""
    head = path.split("_binary-", 1)[0]
    dists = [r for r in inreleases if head.startswith(r[: -len("InRelease")])]
    fields = parse_release(ctx.system.read_text(max(dists, key=len)) or "") if dists else {}
    host = unquote(path.rsplit("/", 1)[-1].split("_", 1)[0])
    origin = fields.get("Origin") or fields.get("Label") or ""
    if origin.startswith(("Debian", "Ubuntu")) and host.endswith(DISTRO_HOSTS):
        return origin
    return f"{origin} ({host})" if origin and origin != host else host


def package_origins(ctx: Context, installed: dict[str, str]) -> dict[str, str]:
    """Where each installed version comes from: the distribution's Origin when it has the
    version, otherwise the vendor's. Packages found in no index are left out."""
    inreleases = ctx.system.glob(f"{LISTS_DIR}/*_InRelease")
    found: dict[str, set[str]] = {}
    indexes = ctx.system.glob(f"{LISTS_DIR}/*_Packages") + ctx.system.glob(
        f"{LISTS_DIR}/*_Packages.gz"
    )
    for path in indexes:
        origin = _origin_name(ctx, path, inreleases)
        name = ""
        for line in ctx.system.lines(path):  # streamed: indexes can be tens of megabytes
            if line.startswith("Package:"):
                name = line[8:].strip()
            elif line.startswith("Version:") and installed.get(name) == line[8:].strip():
                found.setdefault(name, set()).add(origin)
    return {
        name: min(o for o in origins if _distro(o))
        if any(_distro(o) for o in origins)
        else min(origins)
        for name, origins in found.items()
    }


class ObsoletePackagesCheck(Check):
    id = "obsolete-packages"
    title = "Packages not available from any repository"
    category = "packages"
    requires_commands = ("apt", "dpkg-query")

    def run(self, ctx: Context) -> list[Finding]:
        return self._local(ctx) + self._third_party(ctx)

    @staticmethod
    def _third_party(ctx: Context) -> list[Finding]:
        origins = package_origins(ctx, installed_versions(ctx))
        vendors: dict[str, list[str]] = {}
        for name, origin in origins.items():
            if not _distro(origin):
                vendors.setdefault(origin, []).append(name)
        if not vendors:
            return []
        total = sum(len(names) for names in vendors.values())
        evidence = []
        for origin, names in sorted(vendors.items()):
            names.sort()
            more = f", … ({len(names)})" if len(names) > NAMES_SHOWN else ""
            evidence.append(f"{origin}: {', '.join(names[:NAMES_SHOWN])}{more}")
        return [
            Finding(
                Severity.INFO,
                f"{count(total, 'package comes', 'packages come')} from third-party repositories",
                detail="They get updates only from their vendors, not from the "
                "distribution's security team. Release upgrades often disable these "
                "repositories.",
                evidence=truncate_evidence(evidence),
                remediation=[
                    "Keep each vendor's repository enabled and pointing at this release",
                    "Inspect one with: apt policy PACKAGE",
                ],
            )
        ]

    @staticmethod
    def _local(ctx: Context) -> list[Finding]:
        out = run_checked(ctx, apt_command("apt", "list", "--installed")).stdout
        local = []
        for line in package_lines(out):
            if "[" not in line or "local" not in line.rsplit("[", 1)[1]:
                continue
            fields = line.split()
            local.append(f"{fields[0].split('/')[0]} {fields[1]}")
        if not local:
            return []
        return [
            Finding(
                Severity.WARNING,
                f"{count(len(local), 'installed package is', 'installed packages are')} "
                "not available from any configured repository",
                detail="Typically packages dropped from the new release or installed from "
                "a repository that is now disabled. They receive no security updates.",
                evidence=truncate_evidence(local),
                remediation=[
                    "Inspect each with: apt policy PACKAGE",
                    "Replace it with the new release's equivalent, or remove it: "
                    "sudo apt purge PACKAGE",
                ],
            )
        ]

    def collect_baseline(self, ctx: Context) -> Any:
        versions = installed_versions(ctx)
        return {"versions": versions, "origins": package_origins(ctx, versions)}

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        # Snapshots from before 0.4 hold the versions only.
        new_format = isinstance(before, dict) and isinstance(before.get("versions"), dict)
        versions = before["versions"] if new_format else before
        origins_before = before.get("origins", {}) if new_format else {}
        now = installed_versions(ctx)
        findings = []
        removed = sorted(name for name in versions if name not in now)
        if removed:
            findings.append(
                Finding(
                    Severity.INFO,
                    f"{count(len(removed), 'package')} removed since baseline",
                    detail="Removed by the upgrade or by hand; check nothing you rely on is gone.",
                    evidence=truncate_evidence([f"{n} {versions[n]}" for n in removed]),
                    remediation=["Reinstall anything still needed: sudo apt install PACKAGE"],
                )
            )
        if origins_before:
            origins_now = package_origins(ctx, now)
            moved = sorted(
                f"{name}: {old} → {origins_now[name]}"
                for name, old in origins_before.items()
                if name in origins_now and _origin_key(origins_now[name]) != _origin_key(old)
            )
            if moved:
                findings.append(
                    Finding(
                        Severity.WARNING,
                        f"{count(len(moved), 'package comes', 'packages come')} from a "
                        "different origin than before the upgrade",
                        detail="A vendor's package was replaced by the distribution's, or "
                        "the reverse; their versions, configuration and update policies can "
                        "differ.",
                        evidence=truncate_evidence(moved),
                        remediation=[
                            "Check each with: apt policy PACKAGE",
                            "Pin the origin you want in /etc/apt/preferences.d/ if needed",
                        ],
                    )
                )
        return findings
