"""Free-space thresholds shared by boot-space and disk-space."""

from __future__ import annotations

from pydebuprep.checks.base import Check, Option
from pydebuprep.model import Finding, Severity
from pydebuprep.system import DiskUsage

CRITICAL_PCT = 10.0
WARNING_PCT = 25.0


def _human(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    size = float(n)
    for unit in ("KiB", "MiB", "GiB"):
        size /= 1024
        if size < 1024:
            return f"{size:.1f} {unit}"
    return f"{size / 1024:.1f} TiB"


THRESHOLD_OPTIONS = (
    Option("warning_pct", WARNING_PCT, "Warn when free space or inodes drop below this percentage"),
    Option(
        "critical_pct",
        CRITICAL_PCT,
        "Critical when free space or inodes drop below this percentage",
    ),
)


def validate_thresholds(check: Check) -> None:
    warning, critical = check.opt("warning_pct"), check.opt("critical_pct")
    if not (0 <= critical <= 100 and 0 <= warning <= 100):
        raise ValueError("warning_pct and critical_pct must be between 0 and 100")
    if critical >= warning:
        raise ValueError("critical_pct must be lower than warning_pct")


def _severity(pct: float, warning_pct: float, critical_pct: float) -> Severity | None:
    if pct < critical_pct:
        return Severity.CRITICAL
    if pct < warning_pct:
        return Severity.WARNING
    return None


def space_findings(
    label: str,
    usage: DiskUsage,
    remediation: list[str],
    *,
    warning_pct: float = WARNING_PCT,
    critical_pct: float = CRITICAL_PCT,
) -> list[Finding]:
    findings = []
    if usage.total > 0:
        pct = usage.free * 100 / usage.total
        sev = _severity(pct, warning_pct, critical_pct)
        if sev is not None:
            findings.append(
                Finding(
                    sev,
                    f"Low free space on {label}: {pct:.0f}% free",
                    detail=f"{_human(usage.free)} free of {_human(usage.total)}.",
                    remediation=list(remediation),
                )
            )
    if usage.inodes_total > 0:
        pct = usage.inodes_free * 100 / usage.inodes_total
        sev = _severity(pct, warning_pct, critical_pct)
        if sev is not None:
            findings.append(
                Finding(
                    sev,
                    f"Low free inodes on {label}: {pct:.0f}% free",
                    detail=f"{usage.inodes_free} of {usage.inodes_total} inodes free.",
                    remediation=[
                        f"Find directories with many small files: sudo du --inodes -x {label} "
                        "| sort -n | tail",
                    ],
                )
            )
    return findings
