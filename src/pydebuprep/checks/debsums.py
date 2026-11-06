from __future__ import annotations

from pydebuprep.checks.base import Check, Context, Option, count, output_lines, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence

DEBSUMS_TIMEOUT = 600.0


MAX_TIMEOUT = 7200


class DebsumsCheck(Check):
    id = "debsums"
    title = "Package file checksums"
    category = "packages"
    requires_root = True
    requires_commands = ("debsums",)
    install_hint = "sudo apt install debsums"
    slow_note = "debsums reads every packaged file, which can take many minutes (--skip debsums)"
    options = (
        Option(
            "timeout_seconds",
            int(DEBSUMS_TIMEOUT),
            f"Give up after this many seconds (at most {MAX_TIMEOUT})",
        ),
    )

    def validate(self) -> None:
        if not 0 < self.opt("timeout_seconds") <= MAX_TIMEOUT:
            raise ValueError(f"timeout_seconds must be between 1 and {MAX_TIMEOUT}")

    def run(self, ctx: Context) -> list[Finding]:
        # debsums exits 2 when files changed and 1 when files are missing; both are findings.
        res = run_checked(
            ctx, ["debsums", "-c"], ok_codes=(0, 1, 2), timeout=self.opt("timeout_seconds")
        )
        changed = output_lines(res.stdout)
        missing = [line for line in output_lines(res.stderr) if "missing file" in line]
        problems = changed + missing
        if not problems:
            return []
        return [
            Finding(
                Severity.WARNING,
                f"{count(len(problems), 'package file differs', 'package files differ')} "
                "from or are missing compared to their packages"
                if len(problems) != 1
                else "1 package file differs from or is missing compared to its package",
                detail="Files outside /etc that don't match their package can mean an "
                "interrupted upgrade, a manual overwrite or disk corruption.",
                evidence=truncate_evidence(problems),
                remediation=[
                    "Find the owner: dpkg -S PATH",
                    "Restore it: sudo apt install --reinstall PACKAGE",
                ],
            )
        ]
