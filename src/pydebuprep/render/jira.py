"""Jira wiki markup, for on-prem Jira: paste it into an issue or comment in text mode.

Jira Cloud's editor doesn't read wiki markup; see jira_cloud.py.
"""

from __future__ import annotations

from pydebuprep.model import CheckResult, Finding, Report
from pydebuprep.render._common import since_note, status_colour
from pydebuprep.render._jira_limit import fit
from pydebuprep.render._wiki import coloured, esc, finding_body, render_wiki

HEADING = "h1. pydebuprep report\n"


def _check_heading(r: CheckResult) -> list[str]:
    status = r.status.value
    return [
        f"h3. {{{{{esc(r.id)}}}}} - {esc(r.title)}",
        f"Status: {coloured(status, status_colour(r))}",
    ]


def _finding(f: Finding) -> list[str]:
    return [f"{coloured(f.severity.value)}: {esc(f.title)}{since_note(f)}", *finding_body(f)]


def _wiki(report: Report, todo: bool) -> str:
    return render_wiki(report, check_heading=_check_heading, finding=_finding, todo=todo)


def render(report: Report, *, todo: bool = False) -> str:
    return fit(report, lambda shown: _wiki(shown, todo), HEADING)
