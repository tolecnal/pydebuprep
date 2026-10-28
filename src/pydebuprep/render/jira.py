"""Jira wiki markup, for pasting into a Jira issue or comment (text mode)."""

from __future__ import annotations

from pydebuprep.model import CheckResult, Finding, Report
from pydebuprep.render._wiki import esc, finding_body, render_wiki

COLORS = {
    "critical": "#de350b",
    "warning": "#ff991f",
    "info": "#0052cc",
    "ok": "#00875a",
    "findings": "#de350b",
    "skipped": "#6b778c",
    "error": "#de350b",
}


def _check_heading(r: CheckResult) -> list[str]:
    status = r.status.value
    return [
        f"h3. {{{{{r.id}}}}} - {esc(r.title)}",
        f"Status: {{color:{COLORS[status]}}}*{status.upper()}*{{color}}",
    ]


def _finding(f: Finding) -> list[str]:
    sev = f.severity.value
    return [f"{{color:{COLORS[sev]}}}*{sev.upper()}*{{color}}: {esc(f.title)}", *finding_body(f)]


def render(report: Report) -> str:
    return render_wiki(report, check_heading=_check_heading, finding=_finding)
