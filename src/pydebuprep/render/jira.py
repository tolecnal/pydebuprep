"""Jira wiki markup, for on-prem Jira: paste it into an issue or comment in text mode.

Jira Cloud's editor doesn't read wiki markup; see jira_cloud.py.
"""

from __future__ import annotations

from pydebuprep.model import CheckResult, Finding, Report
from pydebuprep.render._common import status_colour
from pydebuprep.render._jira_limit import fit
from pydebuprep.render._wiki import esc, finding_body, render_wiki

HEADING = "h1. pydebuprep report\n"

COLORS = {
    "critical": "#de350b",
    "warning": "#ff991f",
    "info": "#0052cc",
    "ok": "#00875a",
    "skipped": "#6b778c",
    "error": "#de350b",
}


def _check_heading(r: CheckResult) -> list[str]:
    status = r.status.value
    return [
        f"h3. {{{{{r.id}}}}} - {esc(r.title)}",
        f"Status: {{color:{COLORS[status_colour(r)]}}}*{status.upper()}*{{color}}",
    ]


def _severity(sev: str) -> str:
    return f"{{color:{COLORS[sev]}}}*{sev.upper()}*{{color}}"


def _finding(f: Finding) -> list[str]:
    return [f"{_severity(f.severity.value)}: {esc(f.title)}", *finding_body(f)]


def _wiki(report: Report, todo: bool) -> str:
    return render_wiki(
        report, check_heading=_check_heading, finding=_finding, severity=_severity, todo=todo
    )


def render(report: Report, *, todo: bool = False) -> str:
    return fit(report, lambda shown: _wiki(shown, todo), HEADING)
