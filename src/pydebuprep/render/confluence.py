"""Confluence wiki markup for on-prem Confluence (Insert > Markup > Confluence wiki), using
status and panel macros. Confluence Cloud's editor doesn't read it; see _cloud_markdown.py.
"""

from __future__ import annotations

from pydebuprep.model import CheckResult, Finding, Report
from pydebuprep.render._common import status_colour
from pydebuprep.render._wiki import esc, finding_body, render_wiki

STATUS_COLOURS = {
    "critical": "Red",
    "warning": "Yellow",
    "info": "Blue",
    "ok": "Green",
    "skipped": "Grey",
    "error": "Red",
}
PANELS = {"critical": "warning", "warning": "note", "info": "info"}


def _status(word: str, colour: str | None = None) -> str:
    return f"{{status:colour={STATUS_COLOURS[colour or word]}|title={word.upper()}}}"


def _check_heading(r: CheckResult) -> list[str]:
    return [f"h3. {esc(r.id)} - {esc(r.title)} {_status(r.status.value, status_colour(r))}"]


def _finding(f: Finding) -> list[str]:
    sev = f.severity.value
    panel = PANELS[sev]
    return [
        f"{{{panel}}}",
        f"{_status(sev)} *{esc(f.title)}*",
        *finding_body(f),
        f"{{{panel}}}",
    ]


def render(report: Report, *, todo: bool = False) -> str:
    return render_wiki(
        report, check_heading=_check_heading, finding=_finding, severity=_status, todo=todo
    )
