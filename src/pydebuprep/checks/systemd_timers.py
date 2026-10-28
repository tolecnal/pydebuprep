from __future__ import annotations

from typing import Any

from pydebuprep.checks._systemd import run_systemctl, unit_rows
from pydebuprep.checks.base import Check, Context, count
from pydebuprep.model import Finding, Severity, truncate_evidence

TIMERS = (
    "systemctl",
    "list-units",
    "--type=timer",
    "--all",
    "--no-legend",
    "--plain",
    "--no-pager",
)


def _should_be_active(ctx: Context, unit: str) -> bool:
    """Enabled, and its start conditions hold (timers with unmet conditions idle by design)."""
    res = ctx.system.run(
        ["systemctl", "show", "-p", "UnitFileState", "-p", "ConditionResult", unit]
    )
    props = dict(line.partition("=")[::2] for line in res.stdout.splitlines())
    return props.get("UnitFileState") == "enabled" and props.get("ConditionResult") != "no"


def _timers(ctx: Context) -> list[list[str]]:
    return [row for row in unit_rows(run_systemctl(ctx, TIMERS).stdout) if len(row) >= 3]


class SystemdTimersCheck(Check):
    id = "systemd-timers"
    title = "systemd timers"
    category = "services"
    requires_commands = ("systemctl",)

    def run(self, ctx: Context) -> list[Finding]:
        return [
            Finding(
                Severity.WARNING,
                f"Timer {row[0]} is not active",
                detail=f"State: {row[1]} {row[2]}. Scheduled jobs it triggers will not run.",
                remediation=[f"systemctl status {row[0]}", f"sudo systemctl enable --now {row[0]}"],
            )
            for row in _timers(ctx)
            if row[1] == "loaded" and row[2] != "active" and _should_be_active(ctx, row[0])
        ]

    def collect_baseline(self, ctx: Context) -> Any:
        return sorted(row[0] for row in _timers(ctx) if row[2] == "active")

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        active = {row[0] for row in _timers(ctx) if row[2] == "active"}
        gone = sorted(set(before) - active)
        if not gone:
            return []
        return [
            Finding(
                Severity.WARNING,
                f"{count(len(gone), 'timer was', 'timers were')} active before the upgrade "
                f"but {'is' if len(gone) == 1 else 'are'} not now",
                evidence=truncate_evidence(gone),
                remediation=[
                    "systemctl list-timers --all",
                    "Re-enable the ones you need: sudo systemctl enable --now TIMER",
                ],
            )
        ]
