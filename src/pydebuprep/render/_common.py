"""Wording and grouping shared by the human-readable renderers."""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from itertools import groupby
from typing import Any

from pydebuprep.model import (
    BaselineInfo,
    CheckResult,
    ConfigInfo,
    Finding,
    Host,
    Report,
    Severity,
    Status,
)

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


def safe_url(url: str) -> bool:
    """Whether URL is an http(s) link with no whitespace, control characters or angle brackets."""
    return (
        url.startswith(("https://", "http://"))
        and not any(c.isspace() or c in "<>" for c in url)
        and CONTROL.search(url) is None
    )


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
    b = report.baseline
    c = report.config
    return dataclasses.replace(
        report,
        generated_at=clean(report.generated_at),
        host=Host(
            clean(h.hostname),
            clean(h.os_id),
            clean(h.os_version),
            clean(h.codename),
            clean(h.kernel),
            h.is_root,
            None if h.machine_id is None else clean(h.machine_id),
        ),
        baseline=None
        if b is None
        else BaselineInfo(
            clean(b.path), clean(b.created_at), clean(b.os_version), clean(b.hostname)
        ),
        results=[_clean_result(r) for r in report.results],
        config=None if c is None else ConfigInfo(clean(c.source), clean(c.fetched_at), c.stale),
    )


def has_baseline_section(report: Report) -> bool:
    """Whether checks get a "Changes since baseline" section; without a baseline the
    header says so once instead."""
    return report.baseline is not None


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
    machine = "" if h.machine_id is None else f" | Machine: {h.machine_id}"
    return (
        f"Host: {h.hostname} | OS: {h.os_id} {h.os_version} ({h.codename}) | "
        f"Kernel: {h.kernel}{machine}{root}"
    )


def baseline_line(report: Report) -> str:
    b = report.baseline
    if b is None:
        return "Baseline: none"
    return f"Baseline: {b.path} (taken {b.created_at} on {b.hostname}, OS {b.os_version})"


def config_line(report: Report) -> str | None:
    """Where a config fetched from a URL came from; None for a local config."""
    c = report.config
    if c is None:
        return None
    if c.stale:
        return (
            f"Config from {c.source} could not be fetched; used the copy fetched on "
            f"{c.fetched_at} — it may not be the latest"
        )
    return f"Config: {c.source} (fetched {c.fetched_at})"


def summary_line(report: Report) -> str:
    s = report.summary
    return (
        f"{s.critical} critical, {s.warning} warning, {s.info} info | "
        f"checks: {s.ok} ok, {s.skipped} skipped, {s.error} error | exit code {s.exit_code}"
    )


# --- the TODO checklist (--todo) -------------------------------------------------------

CONFIRM = "Run pydebuprep again to confirm everything is fixed"
NOTHING_TO_DO = "Nothing to do."


@dataclass
class TodoItem:
    title: str
    severity: str | None = None
    check: str | None = None
    steps: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        """The item as one line of plain text."""
        if self.severity:
            return f"{self.severity.upper()} {self.check}: {self.title}"
        return self.title

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "check": self.check,
            "title": self.title,
            "steps": list(self.steps),
        }


def todo_items(report: Report) -> list[TodoItem]:
    """What needs doing: critical then warning findings (with their remediation as steps),
    checks that failed to run, a root re-run if root checks were skipped, and a final
    confirmation run. Info findings are for awareness, not action. Empty if nothing."""
    items = [
        TodoItem(f.title, severity.value, r.id, list(f.remediation))
        for severity in (Severity.CRITICAL, Severity.WARNING)
        for r in report.results
        for f in [*r.findings, *(r.baseline_diff or [])]
        if f.severity == severity
    ]
    items += [
        TodoItem(f"Find out why {r.id} failed to run: {r.error}", check=r.id)
        for r in report.results
        if r.status == Status.ERROR
    ]
    need_root = [
        r
        for r in report.results
        if r.status == Status.SKIPPED and (r.skipped_reason or "").startswith("requires root")
    ]
    if need_root and not report.host.is_root:
        checks = "1 check was" if len(need_root) == 1 else f"{len(need_root)} checks were"
        items.append(TodoItem(f"Run pydebuprep as root: {checks} skipped without it"))
    if items:
        items.append(TodoItem(CONFIRM))
    return items


def report_data(report: Report, todo: bool) -> dict[str, Any]:
    """The JSON/YAML form of a report, with the TODO list when asked for."""
    data = report.to_dict()
    if todo:
        data["todo"] = [item.to_dict() for item in todo_items(report)]
    return data
