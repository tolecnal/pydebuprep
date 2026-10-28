from __future__ import annotations

import re

from pydebuprep.checks.base import Check, Context, output_lines
from pydebuprep.model import Finding, Severity

ANALYZE = ("systemd-analyze",)
BLAME = ("systemd-analyze", "blame", "--no-pager")
TOTAL = re.compile(r"=\s*(\S+)\s*$")
TOP = 10


class BootTimeCheck(Check):
    id = "boot-time"
    title = "Boot time"
    category = "services"
    requires_commands = ("systemd-analyze",)

    def run(self, ctx: Context) -> list[Finding]:
        res = ctx.system.run(list(ANALYZE))
        if "not yet finished" in res.stderr + res.stdout:
            return [
                Finding(
                    Severity.INFO,
                    "Boot has not finished yet",
                    detail="Some units are still starting or waiting; this can mean a hanging "
                    "job after the upgrade.",
                    remediation=["systemctl list-jobs"],
                )
            ]
        if not res.ok:
            return []
        lines = output_lines(res.stdout)
        match = TOTAL.search(lines[0]) if lines else None
        blame = [line.strip() for line in output_lines(ctx.system.run(list(BLAME)).stdout)][:TOP]
        return [
            Finding(
                Severity.INFO,
                f"Boot took {match.group(1)}" if match else "Boot time",
                detail=" ".join(lines),
                evidence=blame,
                remediation=["systemd-analyze critical-chain shows what the boot waited on"],
            )
        ]
