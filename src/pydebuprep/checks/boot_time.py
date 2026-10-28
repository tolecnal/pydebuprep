from __future__ import annotations

import re

from pydebuprep.checks._systemd import not_systemd
from pydebuprep.checks.base import (
    Check,
    CheckSkipped,
    CommandFailed,
    Context,
    output_lines,
    run_checked,
)
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
        res = run_checked(ctx, ANALYZE, ok_codes=None)
        if not_systemd(res):
            raise CheckSkipped("systemd is not running on this system")
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
            stderr = res.stderr.strip().splitlines()
            raise CommandFailed(stderr[0] if stderr else f"systemd-analyze exited {res.returncode}")
        lines = output_lines(res.stdout)
        match = TOTAL.search(lines[0]) if lines else None
        blame = [line.strip() for line in output_lines(run_checked(ctx, BLAME).stdout)][:TOP]
        return [
            Finding(
                Severity.INFO,
                f"Boot took {match.group(1)}" if match else "Boot time",
                detail=" ".join(lines),
                evidence=blame,
                remediation=["systemd-analyze critical-chain shows what the boot waited on"],
            )
        ]
