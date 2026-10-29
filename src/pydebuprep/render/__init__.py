"""Render a Report in one of the supported output formats."""

from __future__ import annotations

from pydebuprep.model import Report
from pydebuprep.render import confluence, html, jira, json_, markdown, text, yaml_
from pydebuprep.render._common import clean_report, valid_utf8

FORMATS = ("text", "json", "yaml", "html", "markdown", "jira", "confluence")
EXTENSIONS = {
    "text": "txt",
    "json": "json",
    "yaml": "yaml",
    "html": "html",
    "markdown": "md",
    "jira": "jira.txt",
    "confluence": "confluence.txt",
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
        return html.render(report, todo=todo)
    if fmt == "markdown":
        return markdown.render(clean_report(report), todo=todo)
    if fmt == "jira":
        return jira.render(clean_report(report), todo=todo)
    if fmt == "confluence":
        return confluence.render(clean_report(report), todo=todo)
    raise ValueError(f"unknown format: {fmt}")
