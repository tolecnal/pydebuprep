from __future__ import annotations

import fnmatch
from typing import Any

from pydebuprep.checks._systemd import run_systemctl, unit_rows
from pydebuprep.checks.base import Check, Context, Option
from pydebuprep.model import Finding, Severity, truncate_evidence

LIST = ("systemctl", "list-units", "--no-legend", "--plain", "--no-pager")
FAILED = (*LIST[:2], "--state=failed", *LIST[2:])
ACTIVE_SERVICES = (*LIST[:2], "--type=service", "--state=active", *LIST[2:])
ENABLED_SERVICES = (
    "systemctl",
    "list-unit-files",
    "--type=service",
    "--state=enabled",
    "--no-legend",
    "--no-pager",
)
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

    def _units(self, ctx: Context, argv: tuple[str, ...]) -> list[str]:
        return sorted(row[0] for row in unit_rows(run_systemctl(ctx, argv).stdout))

    def collect_baseline(self, ctx: Context) -> Any:
        return {
            "active": self._units(ctx, ACTIVE_SERVICES),
            "enabled": self._units(ctx, ENABLED_SERVICES),
        }

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        if isinstance(before, list):  # snapshots from 0.1.0 stored active units only
            before = {"active": before, "enabled": []}
        findings = self._lost(before.get("active", []), self._units(ctx, ACTIVE_SERVICES), "active")
        if before.get("enabled"):
            enabled_now = self._units(ctx, ENABLED_SERVICES)
            findings += self._lost(before["enabled"], enabled_now, "enabled")
        return findings

    def _lost(self, before: list[str], now: list[str], state: str) -> list[Finding]:
        gone = sorted(u for u in set(before) - set(now) if not self._ignored(u))
        if len(gone) > GROUP_ABOVE:
            return [
                Finding(
                    Severity.WARNING,
                    f"{len(gone)} services were {state} before the upgrade but are not now",
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
                f"{unit} was {state} before the upgrade but is not now",
                remediation=[f"systemctl status {unit}", f"sudo systemctl enable --now {unit}"],
            )
            for unit in gone
        ]
