"""Render a Report in one of the supported output formats."""

from __future__ import annotations

from pydebuprep.model import Report
from pydebuprep.render import html, json_, markdown, text, yaml_
from pydebuprep.render._common import clean_report, valid_utf8

FORMATS = ("text", "json", "yaml", "html", "markdown")
EXTENSIONS = {"text": "txt", "json": "json", "yaml": "yaml", "html": "html", "markdown": "md"}


def render(report: Report, fmt: str, *, color: bool = False) -> str:
    """Render to a string that always encodes as UTF-8."""
    return valid_utf8(_render(report, fmt, color))


def _render(report: Report, fmt: str, color: bool) -> str:
    if fmt == "text":
        return text.render(clean_report(report), color=color)
    if fmt == "json":
        return json_.render(report)
    if fmt == "yaml":
        return yaml_.render(report)
    if fmt == "html":
        return html.render(report)
    if fmt == "markdown":
        return markdown.render(clean_report(report))
    raise ValueError(f"unknown format: {fmt}")
