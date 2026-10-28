from __future__ import annotations

from typing import Any

from pydebuprep.checks.base import Check, Context, count, output_lines, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.system import apt_command


def held_packages(ctx: Context) -> list[str]:
    return sorted(output_lines(run_checked(ctx, apt_command("apt-mark", "showhold")).stdout))


class AptHeldCheck(Check):
    id = "apt-held"
    title = "Held packages"
    category = "packages"
    requires_commands = ("apt-mark",)

    def run(self, ctx: Context) -> list[Finding]:
        held = held_packages(ctx)
        if not held:
            return []
        return [
            Finding(
                Severity.WARNING,
                f"{count(len(held), 'package is', 'packages are')} held back",
                detail="Held packages stay on their old version and can block or break "
                "dependencies on the new release.",
                evidence=truncate_evidence(held),
                remediation=["If a hold is no longer needed: sudo apt-mark unhold PACKAGE"],
            )
        ]

    def collect_baseline(self, ctx: Context) -> Any:
        return held_packages(ctx)

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now, old = set(held_packages(ctx)), set(before)
        findings = []
        if added := sorted(now - old):
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"{count(len(added), 'package')} newly held since baseline",
                    evidence=truncate_evidence(added),
                    remediation=["Check why: apt-mark showhold; unhold with sudo apt-mark unhold"],
                )
            )
        if removed := sorted(old - now):
            findings.append(
                Finding(
                    Severity.INFO,
                    f"{count(len(removed), 'package')} no longer held since baseline",
                    evidence=truncate_evidence(removed),
                    remediation=["Re-hold if still needed: sudo apt-mark hold PACKAGE"],
                )
            )
        return findings
