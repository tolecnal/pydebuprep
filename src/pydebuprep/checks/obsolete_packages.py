from __future__ import annotations

from typing import Any

from pydebuprep.checks.apt_upgradable import package_lines
from pydebuprep.checks.base import Check, Context, count
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.system import apt_command

PKG_VERSIONS_ARGV = ("dpkg-query", "-W", "-f=${Package}\t${Version}\n")


def installed_versions(ctx: Context) -> dict[str, str]:
    out = ctx.system.run(list(PKG_VERSIONS_ARGV)).stdout
    versions = {}
    for line in out.splitlines():
        name, _, version = line.partition("\t")
        if name and version:
            versions[name] = version
    return versions


class ObsoletePackagesCheck(Check):
    id = "obsolete-packages"
    title = "Packages not available from any repository"
    category = "packages"
    requires_commands = ("apt", "dpkg-query")

    def run(self, ctx: Context) -> list[Finding]:
        out = ctx.system.run(apt_command("apt", "list", "--installed")).stdout
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
        return installed_versions(ctx)

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now = installed_versions(ctx)
        removed = sorted(name for name in before if name not in now)
        if not removed:
            return []
        return [
            Finding(
                Severity.INFO,
                f"{count(len(removed), 'package')} removed since baseline",
                detail="Removed by the upgrade or by hand; check nothing you rely on is gone.",
                evidence=truncate_evidence([f"{n} {before[n]}" for n in removed]),
                remediation=["Reinstall anything still needed: sudo apt install PACKAGE"],
            )
        ]
