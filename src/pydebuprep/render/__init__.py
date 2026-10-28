"""Render a Report in one of the supported output formats."""

from __future__ import annotations

from pydebuprep.model import Report
from pydebuprep.render import html, json_, markdown, text, yaml_

FORMATS = ("text", "json", "yaml", "html", "markdown")
EXTENSIONS = {"text": "txt", "json": "json", "yaml": "yaml", "html": "html", "markdown": "md"}


def render(report: Report, fmt: str, *, color: bool = False) -> str:
    if fmt == "text":
        return text.render(report, color=color)
    if fmt == "json":
        return json_.render(report)
    if fmt == "yaml":
        return yaml_.render(report)
    if fmt == "html":
        return html.render(report)
    if fmt == "markdown":
        return markdown.render(report)
    raise ValueError(f"unknown format: {fmt}")
