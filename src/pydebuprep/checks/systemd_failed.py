from __future__ import annotations

import fnmatch
from typing import Any

from pydebuprep.checks._systemd import run_systemctl, unit_rows
from pydebuprep.checks.base import Check, Context, Option
from pydebuprep.model import Finding, Severity, truncate_evidence

LIST = ("systemctl", "list-units", "--no-legend", "--plain", "--no-pager")
FAILED = (*LIST[:2], "--state=failed", *LIST[2:])
ACTIVE_SERVICES = (*LIST[:2], "--type=service", "--state=active", *LIST[2:])
GROUP_ABOVE = 5


class SystemdFailedCheck(Check):
    id = "systemd-failed"
    title = "Failed systemd units"
    category = "services"
    requires_commands = ("systemctl",)
    options = (Option("ignore_units", [], "Units to leave out (shell-style patterns)"),)

    def _ignored(self, unit: str) -> bool:
        return any(fnmatch.fnmatchcase(unit, p) for p in self.opt("ignore_units"))

    def run(self, ctx: Context) -> list[Finding]:
        rows = unit_rows(run_systemctl(ctx, FAILED).stdout)
        return [
            Finding(
                Severity.CRITICAL,
                f"Unit {row[0]} failed",
                detail=" ".join(row[4:]),
                remediation=[f"systemctl status {row[0]}", f"journalctl -u {row[0]} -b"],
            )
            for row in rows
            if not self._ignored(row[0])
        ]

    def collect_baseline(self, ctx: Context) -> Any:
        return sorted(row[0] for row in unit_rows(run_systemctl(ctx, ACTIVE_SERVICES).stdout))

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now = {row[0] for row in unit_rows(run_systemctl(ctx, ACTIVE_SERVICES).stdout)}
        gone = sorted(u for u in set(before) - now if not self._ignored(u))
        if len(gone) > GROUP_ABOVE:
            return [
                Finding(
                    Severity.WARNING,
                    f"{len(gone)} services were active before the upgrade but are not now",
                    evidence=truncate_evidence(gone),
                    remediation=[
                        "Check each: systemctl status UNIT",
                        "Start the ones you need: sudo systemctl enable --now UNIT",
                    ],
                )
            ]
        return [
            Finding(
                Severity.WARNING,
                f"{unit} was active before the upgrade but is not now",
                remediation=[f"systemctl status {unit}", f"sudo systemctl enable --now {unit}"],
            )
            for unit in gone
        ]
