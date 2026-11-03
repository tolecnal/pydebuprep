from __future__ import annotations

from pydebuprep.checks.base import Check, Context, count, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence

DPKG_RC_ARGV = ("dpkg-query", "-W", "-f=${db:Status-Abbrev} ${Package}\n")
PURGE_BATCH = 20
MAX_BATCHES = 5  # hundreds of leftovers on old hosts would swamp the report
PURGE_ALL = "sudo pydebuprep-cleanup --residual (shows what it would purge; add --apply to do it)"


class DpkgRcCheck(Check):
    id = "dpkg-rc"
    title = "Leftover configuration of removed packages"
    category = "packages"
    requires_commands = ("dpkg-query",)

    def run(self, ctx: Context) -> list[Finding]:
        out = run_checked(ctx, DPKG_RC_ARGV).stdout
        pkgs = [line.split()[-1] for line in out.splitlines() if line.startswith("rc")]
        if not pkgs:
            return []
        batches = [pkgs[i : i + PURGE_BATCH] for i in range(0, len(pkgs), PURGE_BATCH)]
        rest = len(pkgs) - PURGE_BATCH * MAX_BATCHES
        more = [f"... and {rest} more packages: {PURGE_ALL}"] if rest > 0 else []
        return [
            Finding(
                Severity.INFO,
                f"{count(len(pkgs), 'removed package')} still "
                f"{'has' if len(pkgs) == 1 else 'have'} configuration files",
                detail="These are usually safe to purge once you know you don't need the config.",
                evidence=truncate_evidence(pkgs),
                remediation=[
                    "Review with: dpkg -l | grep ^rc",
                    *(f"sudo apt purge {' '.join(b)}" for b in batches[:MAX_BATCHES]),
                    *more,
                ],
            )
        ]
