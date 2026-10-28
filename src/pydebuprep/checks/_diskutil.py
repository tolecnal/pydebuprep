"""Free-space thresholds shared by boot-space and disk-space."""

from __future__ import annotations

from pydebuprep.model import Finding, Severity
from pydebuprep.system import DiskUsage

CRITICAL_PCT = 10.0
WARNING_PCT = 25.0


def _human(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{n} B"


def _severity(pct: float) -> Severity | None:
    if pct < CRITICAL_PCT:
        return Severity.CRITICAL
    if pct < WARNING_PCT:
        return Severity.WARNING
    return None


def space_findings(label: str, usage: DiskUsage, remediation: list[str]) -> list[Finding]:
    findings = []
    if usage.total > 0:
        pct = usage.free * 100 / usage.total
        sev = _severity(pct)
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
        sev = _severity(pct)
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
