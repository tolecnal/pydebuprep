from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from pydebuprep.checks._apt_metadata import LISTS_DIR, parse_release
from pydebuprep.checks.apt_upgradable import package_lines
from pydebuprep.checks.base import Check, Context, Option, count, run_checked
from pydebuprep.checks.kernel_running import compare_versions
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.system import apt_command

PKG_VERSIONS_ARGV = ("dpkg-query", "-W", "-f=${Package}\t${Version}\n")
# Hosts that serve the distributions' own archives (mirrors too: deb.debian.org, ...).
DISTRO_HOSTS = ("debian.org", "ubuntu.com", "canonical.com")
NAMES_SHOWN = 10
EXTENDED_STATES = "/var/lib/apt/extended_states"


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


def _automatic(ctx: Context) -> set[str] | None:
    """Packages APT installed as dependencies; None if its record can't be read."""
    text = ctx.system.read_text(EXTENDED_STATES)
    if text is None:
        return None
    automatic = set()
    name = ""
    for line in text.splitlines():
        if line.startswith("Package:"):
            name = line[8:].strip()
        elif line.replace(" ", "") == "Auto-Installed:1":
            automatic.add(name)
    return automatic


def _version_changes(before: dict[str, str], now: dict[str, str]) -> list[Finding]:
    """A sum of what changed: thousands of new versions are the point of an upgrade. Only an
    older version is unusual enough to name."""
    kept = [name for name in before if name in now and before[name] != now[name]]
    older = sorted(name for name in kept if compare_versions(now[name], before[name]) < 0)
    upgraded = len(kept) - len(older)
    new = sorted(name for name in now if name not in before)
    findings = []
    if older:
        findings.append(
            Finding(
                Severity.WARNING,
                f"{count(len(older), 'package has', 'packages have')} an older version "
                "than before the upgrade",
                detail="Unusual in an upgrade: a pin, or a package from another repository.",
                evidence=truncate_evidence([f"{n}: {before[n]} to {now[n]}" for n in older]),
                remediation=["Check each with: apt policy PACKAGE"],
            )
        )
    parts = [count(upgraded, "package") + " upgraded"] if upgraded else []
    parts += [f"{len(new)} new"] if new else []
    if parts:
        more = f", … ({len(new)})" if len(new) > NAMES_SHOWN else ""
        findings.append(
            Finding(
                Severity.INFO,
                f"Since the snapshot: {', '.join(parts)}",
                evidence=[f"New: {', '.join(new[:NAMES_SHOWN])}{more}"] if new else [],
            )
        )
    return findings


class ObsoletePackagesCheck(Check):
    id = "obsolete-packages"
    title = "Packages not available from any repository"
    category = "packages"
    requires_commands = ("apt", "dpkg-query")
    options = (
        Option(
            "protected_packages",
            [],
            "Packages that must stay installed: critical if one isn't",
        ),
    )

    def run(self, ctx: Context) -> list[Finding]:
        return self._protected(ctx) + self._local(ctx) + self._third_party(ctx)

    def _protected(self, ctx: Context) -> list[Finding]:
        if not self.opt("protected_packages"):
            return []
        now = installed_versions(ctx)
        gone = sorted(name for name in self.opt("protected_packages") if name not in now)
        if not gone:
            return []
        return [
            Finding(
                Severity.CRITICAL,
                f"{count(len(gone), 'protected package', 'protected packages')} "
                f"{'isn' if len(gone) == 1 else 'aren'}'t installed",
                evidence=gone,
                remediation=[f"sudo apt install {' '.join(gone)}"],
            )
        ]

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
        baseline: dict[str, Any] = {
            "versions": versions,
            "origins": package_origins(ctx, versions),
        }
        automatic = _automatic(ctx)
        if automatic is not None:
            baseline["manual"] = sorted(set(versions) - automatic)
        return baseline

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        # Snapshots from before 0.4 hold the versions only.
        new_format = isinstance(before, dict) and isinstance(before.get("versions"), dict)
        versions = before["versions"] if new_format else before
        origins_before = before.get("origins", {}) if new_format else {}
        now = installed_versions(ctx)
        findings = []
        manual_before = set(before.get("manual", [])) if new_format else set()
        removed = sorted(name for name in versions if name not in now)
        # A base system's libraries aren't marked automatic either, and upgrades rename them.
        by_hand = [n for n in removed if n in manual_before and not n.startswith("lib")]
        if by_hand:
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"{count(len(by_hand), 'package')} marked as installed by hand "
                    f"{'was' if len(by_hand) == 1 else 'were'} removed",
                    detail="APT doesn't mark it as a dependency, so someone may have asked for it, "
                    "or it came with the base system: check it isn't needed.",
                    evidence=truncate_evidence([f"{n} {versions[n]}" for n in by_hand]),
                    remediation=["Reinstall anything still needed: sudo apt install PACKAGE"],
                )
            )
        removed = [name for name in removed if name not in by_hand]
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
        findings += _version_changes(versions, now)
        automatic = _automatic(ctx)
        if automatic is not None:
            marked = sorted(name for name in manual_before & automatic if name in now)
            if marked:
                findings.append(
                    Finding(
                        Severity.WARNING,
                        f"{count(len(marked), 'package')} marked as installed by hand "
                        f"{'is' if len(marked) == 1 else 'are'} now marked automatic",
                        detail="`apt autoremove` can remove it once nothing depends on it.",
                        evidence=truncate_evidence(marked),
                        remediation=["sudo apt-mark manual PACKAGE"],
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
