from __future__ import annotations

import re

from pydebuprep.checks.base import Check, Context, count, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.system import apt_command

REMV = re.compile(r"^Remv (.+)$")


class AptAutoremoveCheck(Check):
    id = "apt-autoremove"
    title = "Packages no longer needed"
    category = "packages"
    requires_commands = ("apt-get",)

    def run(self, ctx: Context) -> list[Finding]:
        out = run_checked(ctx, apt_command("apt-get", "-s", "autoremove")).stdout
        pkgs = [m.group(1).strip() for m in map(REMV.match, out.splitlines()) if m]
        if not pkgs:
            return []
        return [
            Finding(
                Severity.INFO,
                f"{count(len(pkgs), 'package is', 'packages are')} no longer needed",
                detail="Review before removing: some may be tools you installed by hand that "
                "were never marked as manually installed.",
                evidence=truncate_evidence(pkgs),
                remediation=[
                    "Keep anything you use: sudo apt-mark manual PACKAGE",
                    "sudo apt autoremove",
                ],
            )
        ]
