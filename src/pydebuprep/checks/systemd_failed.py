from __future__ import annotations

from typing import Any

from pydebuprep.checks._systemd import run_systemctl, unit_rows
from pydebuprep.checks.base import Check, Context
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
        ]

    def collect_baseline(self, ctx: Context) -> Any:
        return sorted(row[0] for row in unit_rows(run_systemctl(ctx, ACTIVE_SERVICES).stdout))

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now = {row[0] for row in unit_rows(run_systemctl(ctx, ACTIVE_SERVICES).stdout)}
        gone = sorted(set(before) - now)
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
