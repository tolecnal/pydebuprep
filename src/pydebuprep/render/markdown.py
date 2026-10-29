from __future__ import annotations

import re

from pydebuprep.model import Finding, Report
from pydebuprep.render._common import (
    baseline_line,
    baseline_state,
    by_category,
    has_baseline_section,
    host_line,
    summary_line,
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
    out = [f"- **{f.severity.value.upper()}**: {esc(f.title)}"]
    if f.detail:
        out += ["", *(f"  {esc(d)}" for d in f.detail.splitlines())]
    if f.evidence:
        out += ["", "  Evidence:", "", *(f"  {line}" for line in _fence(f.evidence))]
    if f.remediation:
        out += ["", "  Remediation:", ""]
        out += [f"  {i}. {esc(step)}" for i, step in enumerate(f.remediation, 1)]
    if f.references:
        out += ["", "  References:", ""]
        out += [f"  - <{ref}>" for ref in f.references]
    out.append("")
    return out


def render(report: Report) -> str:
    out = ["# pydebuprep report", ""]
    out += [f"- {esc(host_line(report))}", f"- Generated: {esc(report.generated_at)}"]
    out += [f"- {esc(baseline_line(report))}", "", "## Summary", "", esc(summary_line(report))]
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
    return "\n".join(out).rstrip() + "\n"
