from __future__ import annotations

import re
from collections import Counter

from pydebuprep.checks.base import (
    Check,
    CheckSkipped,
    CommandFailed,
    Context,
    Option,
    count,
    output_lines,
    run_checked,
)
from pydebuprep.checks.journal_errors import compile_patterns
from pydebuprep.model import Finding, Severity, truncate_evidence

DMESG_ERR = ("dmesg", "--level=err", "--notime")
DMESG_WARN = ("dmesg", "--level=warn", "--notime")


def _counted(text: str, ignore: list[re.Pattern[str]]) -> tuple[int, list[str]]:
    lines = [line.strip() for line in output_lines(text)]
    lines = [line for line in lines if not any(p.search(line) for p in ignore)]
    counts = Counter(lines)
    return len(lines), [f"{n}x {line}" for line, n in counts.most_common()]


class DmesgErrorsCheck(Check):
    id = "dmesg-errors"
    title = "Kernel errors and warnings"
    category = "services"
    requires_root = True
    requires_commands = ("dmesg",)
    options = (Option("ignore", [], "Regular expressions; matching kernel messages are left out"),)

    def validate(self) -> None:
        self.patterns = compile_patterns(self.opt("ignore"))

    def run(self, ctx: Context) -> list[Finding]:
        findings = []
        for argv, severity, kind in (
            (DMESG_ERR, Severity.WARNING, "error"),
            (DMESG_WARN, Severity.INFO, "warning"),
        ):
            res = run_checked(ctx, argv, ok_codes=None)
            if "Operation not permitted" in res.stderr:
                raise CheckSkipped(
                    "kernel log is not readable here (container or kernel.dmesg_restrict)"
                )
            if not res.ok:
                stderr = res.stderr.strip().splitlines()
                raise CommandFailed(stderr[0] if stderr else f"dmesg exited {res.returncode}")
            total, evidence = _counted(res.stdout, self.patterns)
            if total:
                findings.append(
                    Finding(
                        severity,
                        f"{count(total, f'kernel {kind} message')} since boot",
                        detail="Look for driver or firmware problems introduced by the new kernel.",
                        evidence=truncate_evidence(evidence),
                        remediation=[
                            f"sudo dmesg --level={'err' if kind == 'error' else 'warn'} -T",
                            "Missing firmware: install the matching firmware-* package",
                        ],
                    )
                )
        return findings
