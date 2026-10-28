from __future__ import annotations

from pydebuprep.checks.base import Check, Context, output_lines, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.system import apt_command


class DpkgAuditCheck(Check):
    id = "dpkg-audit"
    title = "Broken or half-configured packages"
    category = "packages"
    requires_commands = ("dpkg", "apt-get")

    def run(self, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        audit = run_checked(ctx, ["dpkg", "--audit"], ok_codes=(0, 1))
        lines = output_lines(audit.stdout)
        if lines:
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    "dpkg reports broken or half-configured packages",
                    evidence=truncate_evidence(lines),
                    remediation=["sudo dpkg --configure -a", "sudo apt -f install"],
                )
            )
        check = run_checked(ctx, apt_command("apt-get", "check"), ok_codes=None)
        if not check.ok:
            evidence = output_lines(check.stderr) or output_lines(check.stdout)
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    "apt-get check reports unmet dependencies or a broken package database",
                    evidence=truncate_evidence(evidence),
                    remediation=["sudo apt -f install", "sudo dpkg --configure -a"],
                )
            )
        return findings
