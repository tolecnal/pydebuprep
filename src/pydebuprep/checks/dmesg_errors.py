from __future__ import annotations

from collections import Counter

from pydebuprep.checks.base import Check, Context, count, output_lines
from pydebuprep.model import Finding, Severity, truncate_evidence

DMESG_ERR = ("dmesg", "--level=err", "--notime")
DMESG_WARN = ("dmesg", "--level=warn", "--notime")


def _counted(text: str) -> tuple[int, list[str]]:
    lines = [line.strip() for line in output_lines(text)]
    counts = Counter(lines)
    return len(lines), [f"{n}x {line}" for line, n in counts.most_common()]


class DmesgErrorsCheck(Check):
    id = "dmesg-errors"
    title = "Kernel errors and warnings"
    category = "services"
    requires_root = True
    requires_commands = ("dmesg",)

    def run(self, ctx: Context) -> list[Finding]:
        findings = []
        for argv, severity, kind in (
            (DMESG_ERR, Severity.WARNING, "error"),
            (DMESG_WARN, Severity.INFO, "warning"),
        ):
            total, evidence = _counted(ctx.system.run(list(argv)).stdout)
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
