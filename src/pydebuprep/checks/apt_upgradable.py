from __future__ import annotations

from pydebuprep.checks.base import Check, Context, count, output_lines
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.system import apt_command


def package_lines(text: str) -> list[str]:
    """Package rows of `apt list` output, without the banner and CLI warnings."""
    return [
        line
        for line in output_lines(text)
        if "/" in line and not line.startswith(("Listing", "WARNING:"))
    ]


class AptUpgradableCheck(Check):
    id = "apt-upgradable"
    title = "Pending package upgrades"
    category = "packages"
    requires_commands = ("apt",)

    def run(self, ctx: Context) -> list[Finding]:
        lines = package_lines(ctx.system.run(apt_command("apt", "list", "--upgradable")).stdout)
        if not lines:
            return []
        return [
            Finding(
                Severity.WARNING,
                f"{count(len(lines), 'package')} can still be upgraded",
                detail="Stragglers after a release upgrade are often packages whose "
                "dependencies changed; a second full-upgrade pass usually picks them up.",
                evidence=truncate_evidence(lines),
                remediation=["sudo apt update && sudo apt full-upgrade"],
            )
        ]
