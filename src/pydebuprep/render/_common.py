"""Wording and grouping shared by the human-readable renderers."""

from __future__ import annotations

import dataclasses
import re
from itertools import groupby

from pydebuprep.model import CheckResult, Finding, Host, Report

NO_BASELINE = "no baseline"
NOT_APPLICABLE = "not applicable"
NO_CHANGES = "no changes"


# C0 controls except tab/newline, DEL and C1 controls: journal and dmesg text is written by
# other users and must not be able to drive the reader's terminal.
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def valid_utf8(text: str) -> str:
    """Turn surrogate-escaped bytes (from non-UTF-8 file names) into U+FFFD."""
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        pass
    try:
        return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except UnicodeEncodeError:
        return text.encode("utf-8", "replace").decode("utf-8")


def clean(text: str) -> str:
    return CONTROL.sub("?", valid_utf8(text))


def _clean_finding(f: Finding) -> Finding:
    return dataclasses.replace(
        f,
        title=clean(f.title),
        detail=clean(f.detail),
        evidence=[clean(e) for e in f.evidence],
        remediation=[clean(r) for r in f.remediation],
        references=[clean(r) for r in f.references],
    )


def _clean_result(r: CheckResult) -> CheckResult:
    return dataclasses.replace(
        r,
        title=clean(r.title),
        findings=[_clean_finding(f) for f in r.findings],
        baseline_diff=None
        if r.baseline_diff is None
        else [_clean_finding(f) for f in r.baseline_diff],
        skipped_reason=None if r.skipped_reason is None else clean(r.skipped_reason),
        error=None if r.error is None else clean(r.error),
    )


def clean_report(report: Report) -> Report:
    """A copy of the report that is safe to print to a terminal."""
    h = report.host
    return dataclasses.replace(
        report,
        host=Host(
            clean(h.hostname),
            clean(h.os_id),
            clean(h.os_version),
            clean(h.codename),
            clean(h.kernel),
            h.is_root,
        ),
        results=[_clean_result(r) for r in report.results],
    )


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
