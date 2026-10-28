from __future__ import annotations

from pydebuprep.checks.base import Check, Context, count
from pydebuprep.model import Finding, Severity, truncate_evidence

DPKG_RC_ARGV = ("dpkg-query", "-W", "-f=${db:Status-Abbrev} ${Package}\n")
PURGE_BATCH = 20


class DpkgRcCheck(Check):
    id = "dpkg-rc"
    title = "Leftover configuration of removed packages"
    category = "packages"
    requires_commands = ("dpkg-query",)

    def run(self, ctx: Context) -> list[Finding]:
        out = ctx.system.run(list(DPKG_RC_ARGV)).stdout
        pkgs = [line.split()[-1] for line in out.splitlines() if line.startswith("rc")]
        if not pkgs:
            return []
        batches = [pkgs[i : i + PURGE_BATCH] for i in range(0, len(pkgs), PURGE_BATCH)]
        return [
            Finding(
                Severity.INFO,
                f"{count(len(pkgs), 'removed package')} still "
                f"{'has' if len(pkgs) == 1 else 'have'} configuration files",
                detail="These are usually safe to purge once you know you don't need the config.",
                evidence=truncate_evidence(pkgs),
                remediation=[
                    "Review with: dpkg -l | grep ^rc",
                    *(f"sudo apt purge {' '.join(b)}" for b in batches),
                ],
            )
        ]
