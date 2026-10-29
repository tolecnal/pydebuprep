from __future__ import annotations

from pydebuprep.checks.base import Check, Context, output_lines, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence

POSTCONF = ("postconf", "-n")  # `postfix check` is not used: it creates missing directories


class PostfixCheck(Check):
    id = "postfix"
    title = "postfix configuration"
    category = "applications"
    requires_commands = ("postconf",)

    def run(self, ctx: Context) -> list[Finding]:
        res = run_checked(ctx, POSTCONF, ok_codes=None)
        problems = output_lines(res.stderr)
        if not res.ok:
            return [
                Finding(
                    Severity.CRITICAL,
                    "postfix can't read its configuration",
                    evidence=truncate_evidence(problems),
                    remediation=["sudo postconf -n", "sudo systemctl status postfix"],
                )
            ]
        if problems:
            return [
                Finding(
                    Severity.WARNING,
                    "postfix warns about its configuration",
                    detail="Often parameters renamed or removed in the new postfix version.",
                    evidence=truncate_evidence(problems),
                    remediation=["postconf -n", "Fix or remove the parameters it names"],
                )
            ]
        return []
