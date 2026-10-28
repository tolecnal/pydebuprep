"""Wording and grouping shared by the human-readable renderers."""

from __future__ import annotations

from itertools import groupby

from pydebuprep.model import CheckResult, Report

NO_BASELINE = "no baseline"
NOT_APPLICABLE = "not applicable"
NO_CHANGES = "no changes"


def baseline_state(report: Report, result: CheckResult) -> str | None:
    """Short wording for the baseline section, or None when there are diff findings."""
    if report.baseline is None:
        return NO_BASELINE
    if result.baseline_diff is None:
        return NOT_APPLICABLE
    if not result.baseline_diff:
        return NO_CHANGES
    return None


def by_category(report: Report) -> list[tuple[str, list[CheckResult]]]:
    return [(cat, list(items)) for cat, items in groupby(report.results, key=lambda r: r.category)]


def host_line(report: Report) -> str:
    h = report.host
    root = "" if h.is_root else " (not run as root: some checks skipped)"
    return (
        f"Host: {h.hostname} | OS: {h.os_id} {h.os_version} ({h.codename}) | "
        f"Kernel: {h.kernel}{root}"
    )


def baseline_line(report: Report) -> str:
    b = report.baseline
    if b is None:
        return "Baseline: none"
    return f"Baseline: {b.path} (taken {b.created_at} on {b.hostname}, OS {b.os_version})"


def summary_line(report: Report) -> str:
    s = report.summary
    return (
        f"{s.critical} critical, {s.warning} warning, {s.info} info | "
        f"checks: {s.ok} ok, {s.skipped} skipped, {s.error} error | exit code {s.exit_code}"
    )
