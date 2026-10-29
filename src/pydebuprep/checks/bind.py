from __future__ import annotations

from pydebuprep.checks.base import Check, Context, output_lines, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence

NAMED_CHECKCONF = ("named-checkconf",)


class BindCheck(Check):
    id = "bind"
    title = "BIND configuration"
    category = "applications"
    requires_root = True  # named.conf includes keys only root and the bind group can read
    requires_commands = ("named-checkconf",)

    def run(self, ctx: Context) -> list[Finding]:
        res = run_checked(ctx, NAMED_CHECKCONF, ok_codes=None)
        if res.ok:
            return []
        return [
            Finding(
                Severity.CRITICAL,
                "The BIND configuration is invalid",
                detail="named won't start or reload until it is fixed. Options are sometimes "
                "removed between BIND versions.",
                evidence=truncate_evidence(output_lines(res.stdout) + output_lines(res.stderr)),
                remediation=["sudo named-checkconf", "sudo systemctl status named"],
            )
        ]
