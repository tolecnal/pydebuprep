"""Markdown for Jira Cloud, within the size Jira accepts."""

from __future__ import annotations

from pydebuprep.model import Report
from pydebuprep.render._cloud_markdown import HEADING, render_markdown
from pydebuprep.render._jira_limit import fit


def render(report: Report, *, todo: bool = False) -> str:
    return fit(report, lambda shown: render_markdown(shown, todo=todo), HEADING)
