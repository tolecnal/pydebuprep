"""Keeping a report within what Jira accepts, for both of its formats.

Jira refuses a description or comment over 32,767 characters, which a host with
hundreds of findings exceeds. Over JIRA_LIMIT bytes (a margin for what Jira adds), the
report is rendered again from shorter copies, keeping every critical and warning title,
and as a last resort cut off; either way it says so at the top or the end.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Iterator

from pydebuprep.model import Finding, Report, Severity, truncate_evidence

JIRA_LIMIT = 32_000
SHORTENED = (
    "_Shortened to fit Jira's size limit{}; the full report is in the other formats (html, json)._"
)
CUT = "_... Cut off at Jira's size limit; the full report is in the other formats._\n"


def _fits(text: str) -> bool:
    return len(text.encode()) <= JIRA_LIMIT


def _trim(f: Finding, lines: int, *, keep_detail: bool) -> Finding:
    return dataclasses.replace(
        f,
        detail=f.detail if keep_detail else "",
        evidence=truncate_evidence(f.evidence, lines) if lines else [],
        remediation=truncate_evidence(f.remediation, lines) if lines else [],
    )


def _map(report: Report, change: Callable[[Finding], Finding | None]) -> Report:
    def apply(findings: list[Finding] | None) -> list[Finding] | None:
        if findings is None:
            return None
        return [g for f in findings if (g := change(f)) is not None]

    results = [
        dataclasses.replace(
            r, findings=apply(r.findings) or [], baseline_diff=apply(r.baseline_diff)
        )
        for r in report.results
    ]
    return dataclasses.replace(report, results=results)


def _shorter(report: Report) -> Iterator[tuple[Report, str]]:
    """Ever shorter copies of REPORT, each with what the note should add."""
    yield _map(report, lambda f: _trim(f, 5, keep_detail=True)), ""
    yield _map(report, lambda f: _trim(f, 2, keep_detail=f.severity is not Severity.INFO)), ""
    infos = sum(
        f.severity is Severity.INFO
        for r in report.results
        for f in [*r.findings, *(r.baseline_diff or [])]
    )
    without_info = _map(
        report, lambda f: None if f.severity is Severity.INFO else _trim(f, 2, keep_detail=False)
    )
    left_out = f" ({infos} info findings left out)" if infos else ""
    yield without_info, left_out
    yield _map(without_info, lambda f: _trim(f, 0, keep_detail=False)), left_out


def _cut(text: str) -> str:
    room = JIRA_LIMIT - len(CUT.encode())
    head = text.encode()[:room].decode(errors="ignore")
    return head[: head.rfind("\n") + 1] + CUT


def fit(report: Report, draw: Callable[[Report], str], heading: str) -> str:
    """DRAW(report), or a shorter version with a note under HEADING if it is too big."""
    out = draw(report)
    if _fits(out):
        return out
    for shorter, extra in _shorter(report):
        out = draw(shorter).replace(heading, heading + SHORTENED.format(extra) + "\n", 1)
        if _fits(out):
            return out
    return _cut(out)
