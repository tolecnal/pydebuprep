"""Render a Report in one of the supported output formats."""

from __future__ import annotations

from pydebuprep.model import Report
from pydebuprep.render import confluence, html, jira, jira_cloud, json_, markdown, text, yaml_
from pydebuprep.render._cloud_markdown import render_markdown
from pydebuprep.render._common import clean_report, valid_utf8

FORMATS = (
    "text",
    "json",
    "yaml",
    "html",
    "markdown",
    "jira",
    "jira-legacy",
    "jira-cloud",
    "confluence",
    "confluence-legacy",
    "confluence-cloud",
)
EXTENSIONS = {
    "text": "txt",
    "json": "json",
    "yaml": "yaml",
    "html": "html",
    "markdown": "md",
    "jira": "jira.txt",
    "jira-legacy": "jira.txt",
    "jira-cloud": "jira-cloud.md",
    "confluence": "confluence.txt",
    "confluence-legacy": "confluence.txt",
    "confluence-cloud": "confluence-cloud.md",
}


def render(report: Report, fmt: str, *, color: bool = False, todo: bool = False) -> str:
    """Render to a string that always encodes as UTF-8; todo adds the TODO checklist."""
    return valid_utf8(_render(report, fmt, color, todo))


def _render(report: Report, fmt: str, color: bool, todo: bool) -> str:
    if fmt == "text":
        return text.render(clean_report(report), color=color, todo=todo)
    if fmt == "json":
        return json_.render(report, todo=todo)
    if fmt == "yaml":
        return yaml_.render(report, todo=todo)
    if fmt == "html":
        return html.render(clean_report(report), todo=todo)
    if fmt == "markdown":
        return markdown.render(clean_report(report), todo=todo)
    if fmt in ("jira", "jira-legacy"):
        return jira.render(clean_report(report), todo=todo)
    if fmt == "jira-cloud":
        return jira_cloud.render(clean_report(report), todo=todo)
    if fmt in ("confluence", "confluence-legacy"):
        return confluence.render(clean_report(report), todo=todo)
    if fmt == "confluence-cloud":
        return render_markdown(clean_report(report), todo=todo)
    raise ValueError(f"unknown format: {fmt}")
