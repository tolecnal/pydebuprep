"""Markdown for pasting into Jira Cloud's editor, which doesn't read wiki markup.

What a paste into the editor converts: headings, bold, lists, quotes, code blocks, tables
and emoji characters. What it doesn't: text colour, `:name:` emoji and action items, so
emoji carry the severity and status. Nothing is indented, and table cells have no line
breaks, as neither has been seen to survive a paste.
"""

from __future__ import annotations

import re

from pydebuprep.model import CheckResult, Finding, Report
from pydebuprep.render._common import (
    NOTHING_TO_DO,
    baseline_line,
    baseline_state,
    bold_label,
    by_category,
    config_line,
    has_baseline_section,
    host_fields,
    host_note,
    one_line,
    safe_url,
    status_colour,
    todo_items,
)
from pydebuprep.render._jira_limit import fit
from pydebuprep.render.markdown import _fence
from pydebuprep.render.markdown import esc as _markdown_esc

HEADING = "# pydebuprep report\n"
EMOJI = {
    "critical": "🔴",
    "warning": "🟠",
    "info": "🔵",
    "ok": "🟢",
    "skipped": "⚪",
    "error": "🔴",
}
UNRESOLVED = "\N{HEAVY MINUS SIGN}"
TODO_LEGEND = (
    f"Change a row's icon as you go: {UNRESOLVED} unresolved, ⚠️ needs attention, ✅ resolved."
)
# What makes a line of text a heading, list, rule or code block. Inline markup, quotes and
# "***" are already escaped by then.
_BLOCK = re.compile(r"^(?=#{1,6}(?:\s|$)|[-+](?:\s|$)|---|===|~~~)")
_ORDERED = re.compile(r"^(\d+)([.)])(?=\s|$)")
# A line of pipes and dashes under a line with pipes would make a table.
_TABLE_RULE = re.compile(r"^(?=[\s:|-]*\|)[\s:|-]+$")


def _esc(text: str) -> str:
    """Pipes only need escaping in tables, which _row does."""
    return _markdown_esc(text).replace(r"\|", "|")


def _inline(text: str) -> str:
    return _esc(one_line(text))


def _line(text: str) -> str:
    """A line of its own, which must not turn into a block."""
    if _TABLE_RULE.match(text):
        return text.replace("|", r"\|")
    return _BLOCK.sub(r"\\", _ORDERED.sub(r"\1\\\2", _esc(text)))


def _code(text: str) -> str:
    return _inline(text) if any(c in text for c in "`|\n") else f"`{text}`"


def _row(cells: list[str]) -> str:
    escaped = (cell.replace("|", r"\|") for cell in cells)
    return "|" + "|".join(f" {cell} " if cell else " " for cell in escaped) + "|"


def _link(url: str) -> str:
    plain = safe_url(url) and not any(c in url for c in "()[]")
    return f"[{_esc(url)}]({url})" if plain else _esc(url)


def _bold(text: str) -> str:
    return f"**{text}**"


def _header(report: Report) -> list[str]:
    fields = " | ".join(f"{_bold(k + ':')} {_inline(v)}" for k, v in host_fields(report))
    lines = [f"Generated: {report.generated_at}", baseline_line(report)]
    lines += [line for line in [config_line(report)] if line]
    return [
        f"- {fields}{_inline(host_note(report))}",
        *(f"- {bold_label(line, _bold, _inline)}" for line in lines),
    ]


def _severity(sev: str) -> str:
    return f"{EMOJI[sev]} **{sev.upper()}**"


def _finding(f: Finding) -> list[str]:
    out = [f"{_severity(f.severity.value)}: {_inline(f.title)}", ""]
    if f.detail:
        out += [*(_line(line) for line in f.detail.splitlines()), ""]
    if f.evidence:
        out += ["**Evidence:**", "", *_fence(f.evidence), ""]
    if f.remediation:
        steps = (f"{n}. {_inline(step)}" for n, step in enumerate(f.remediation, 1))
        out += ["**Remediation:**", "", *steps, ""]
    if f.references:
        out += ["**References:**", "", *(f"- {_link(ref)}" for ref in f.references), ""]
    return out


def _check(report: Report, r: CheckResult) -> list[str]:
    status = f"{EMOJI[status_colour(r)]} **{r.status.value.upper()}**"
    out = [f"### {_code(r.id)} - {_inline(r.title)}", "", f"Status: {status}", ""]
    if r.skipped_reason:
        out += [f"Skipped: {_inline(r.skipped_reason)}", ""]
    if r.error:
        out += [f"**Error:** {_inline(r.error)}", ""]
    for f in r.findings:
        out += _finding(f)
    if has_baseline_section(report):
        state = baseline_state(report, r)
        if state is not None:
            out += [f"_Changes since baseline: {state}_", ""]
        else:
            out += ["**Changes since baseline:**", ""]
            for f in r.baseline_diff or []:
                out += _finding(f)
    return out


def _todo(report: Report) -> list[str]:
    out = ["## TODO", ""]
    items = todo_items(report)
    if not items:
        return [*out, NOTHING_TO_DO]
    out += [TODO_LEGEND, ""]
    out += [_row(["Status", "Severity", "Check", "Finding", "Fix"]), "|---|---|---|---|---|"]
    for item in items:
        steps = " ".join(f"{n}. {_inline(step)}" for n, step in enumerate(item.steps, 1))
        out.append(
            _row(
                [
                    UNRESOLVED,
                    _severity(item.severity) if item.severity else "",
                    _code(item.check) if item.check else "",
                    _inline(item.title),
                    steps,
                ]
            )
        )
    return out


def _markdown(report: Report, todo: bool) -> str:
    s = report.summary
    out = [
        HEADING.rstrip(),
        "",
        *_header(report),
        "",
        "## Summary",
        "",
        _row(["Critical", "Warning", "Info", "OK", "Skipped", "Error", "Exit code"]),
        "|---|---|---|---|---|---|---|",
        _row(
            [str(n) for n in (s.critical, s.warning, s.info, s.ok, s.skipped, s.error, s.exit_code)]
        ),
        "",
    ]
    for category, results in by_category(report):
        out += [f"## {category.capitalize()}", ""]
        for r in results:
            out += _check(report, r)
    if todo:
        out += _todo(report)
    return "\n".join(out).rstrip() + "\n"


def render(report: Report, *, todo: bool = False) -> str:
    return fit(report, lambda shown: _markdown(shown, todo), HEADING)
