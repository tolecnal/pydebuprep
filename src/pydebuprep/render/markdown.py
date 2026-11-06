from __future__ import annotations

import re

from pydebuprep.model import Finding, Report
from pydebuprep.render._common import (
    NOTHING_TO_DO,
    baseline_state,
    by_category,
    has_baseline_section,
    header_lines,
    safe_url,
    since_note,
    summary_line,
    todo_items,
)

_SPECIAL = re.compile(r"([\\`*_|<>\[\]])")


def esc(text: str) -> str:
    return _SPECIAL.sub(r"\\\1", text)


def _fence(lines: list[str]) -> list[str]:
    body = "\n".join(lines)
    ticks = "```"
    while ticks in body:
        ticks += "`"
    return [ticks, *lines, ticks]


def _finding(f: Finding) -> list[str]:
    out = [f"- **{f.severity.value.upper()}**: {esc(f.title)}{since_note(f)}"]
    if f.detail:
        out += ["", *(f"  {esc(d)}" for d in f.detail.splitlines())]
    if f.evidence:
        out += ["", "  Evidence:", "", *(f"  {line}" for line in _fence(f.evidence))]
    if f.remediation:
        out += ["", "  Remediation:", ""]
        out += [f"  {i}. {esc(step)}" for i, step in enumerate(f.remediation, 1)]
    if f.references:
        out += ["", "  References:", ""]
        out += [f"  - <{ref}>" if safe_url(ref) else f"  - {esc(ref)}" for ref in f.references]
    out.append("")
    return out


def render(report: Report, *, todo: bool = False) -> str:
    out = ["# pydebuprep report", ""]
    out += [f"- {line}" for line in header_lines(report, lambda s: f"**{s}**", esc)]
    out += ["", "## Summary", "", esc(summary_line(report))]
    for category, results in by_category(report):
        out += ["", f"## {category.capitalize()}", ""]
        for r in results:
            out += [f"### `{r.id}` - {esc(r.title)}", "", f"Status: **{r.status.value}**", ""]
            if r.skipped_reason:
                out += [f"Skipped: {esc(r.skipped_reason)}", ""]
            if r.error:
                out += [f"Error: {esc(r.error)}", ""]
            for f in r.findings:
                out += _finding(f)
            if has_baseline_section(report):
                state = baseline_state(report, r)
                if state is not None:
                    out += [f"Changes since baseline: {state}", ""]
                else:
                    out += ["Changes since baseline:", ""]
                    for f in r.baseline_diff or []:
                        out += _finding(f)
    if todo:
        out += ["", "## TODO", ""]
        items = todo_items(report)
        out += [NOTHING_TO_DO] if not items else []
        for item in items:
            label = (
                f"**{item.severity.upper()}** `{item.check}`: {esc(item.title)}"
                if item.severity
                else esc(item.title)
            )
            out.append(f"- [ ] {label}")
            out.extend(f"  - [ ] {esc(step)}" for step in item.steps)
    return "\n".join(out).rstrip() + "\n"
