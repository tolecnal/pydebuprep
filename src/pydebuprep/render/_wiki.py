"""Shared pieces of the Jira and Confluence wiki-markup renderers.

The two products use related but different markup dialects, so each renderer decides
how findings and statuses look; escaping and the overall layout live here.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from pydebuprep.model import CheckResult, Finding, Report
from pydebuprep.render._common import (
    NOTHING_TO_DO,
    TodoItem,
    baseline_line,
    baseline_state,
    bold_label,
    by_category,
    config_line,
    has_baseline_section,
    host_fields,
    host_note,
    safe_url,
    todo_items,
)

_SPECIAL = re.compile(r"([\\{}\[\]|*_!^~+#])")
# A '-' starting a word opens a list item or -strikethrough-; "--" becomes a dash.
_DASH = re.compile(r"(?<![^\s-])-|-(?=-)")
# Icons such as (i), (x), (on), (/), (+); the inner '+', '!' and '*' are already escaped.
_EMOTICON = re.compile(r"\((?=(?:[ynix/?-]|on|off|\\[!+]|\\\*[rgby]?)\))")
# Block markup that only works at the start of a line.
_BLOCK_START = re.compile(r"^(?=h[1-6]\.|bq\.)")
ZERO_WIDTH_SPACE = "\u200b"
# Wiki markup has no checkbox. Every row starts with this icon, which whoever works through
# the list replaces, in Jira and Confluence alike.
OPEN = "(-)"
TODO_LEGEND = "Change a row's icon as you go: (-) unresolved, (!) needs attention, (/) resolved."
LINE_BREAK = " \\\\ "
EMPTY_CELL = " "


def esc(text: str) -> str:
    text = _SPECIAL.sub(r"\\\1", text)
    text = _DASH.sub(r"\\-", text)
    text = text.replace("??", r"\?\?")
    text = _EMOTICON.sub(r"\\(", text)
    # These have no backslash escape; an invisible character stops the match.
    return _BLOCK_START.sub(ZERO_WIDTH_SPACE, text)


def noformat(lines: list[str]) -> list[str]:
    # A literal {noformat} inside the block would end it early.
    body = [line.replace("{noformat}", "{ noformat}") for line in lines]
    return ["{noformat}", *body, "{noformat}"]


def link(url: str) -> str:
    return f"[{url}]" if safe_url(url) and not any(c in url for c in "[]|{}") else esc(url)


def finding_body(f: Finding) -> list[str]:
    out = []
    if f.detail:
        out += [esc(line) for line in f.detail.splitlines()]
    if f.evidence:
        out += ["*Evidence:*", *noformat(f.evidence)]
    if f.remediation:
        out += ["*Remediation:*", *(f"# {esc(step)}" for step in f.remediation)]
    if f.references:
        out += ["*References:*", *(f"* {link(ref)}" for ref in f.references)]
    return out


def summary_table(report: Report) -> list[str]:
    s = report.summary
    return [
        "||Critical||Warning||Info||OK||Skipped||Error||Exit code||",
        f"|{s.critical}|{s.warning}|{s.info}|{s.ok}|{s.skipped}|{s.error}|{s.exit_code}|",
    ]


def todo_table(items: list[TodoItem], severity: Callable[[str], str]) -> list[str]:
    rows = [TODO_LEGEND, "", "||Status||Severity||Check||Finding||Fix||"]
    for item in items:
        steps = LINE_BREAK.join(f"{n}. {esc(step)}" for n, step in enumerate(item.steps, 1))
        cells = (
            OPEN,
            severity(item.severity) if item.severity else EMPTY_CELL,
            f"{{{{{esc(item.check)}}}}}" if item.check else EMPTY_CELL,
            esc(item.title),
            steps or EMPTY_CELL,
        )
        rows.append(f"|{'|'.join(cells)}|")
    return rows


def _bold(text: str) -> str:
    return f"*{text}*"


def _header(report: Report) -> list[str]:
    fields = r" \| ".join(f"{_bold(k + ':')} {esc(v)}" for k, v in host_fields(report))
    lines = [f"Generated: {report.generated_at}", baseline_line(report)]
    lines += [line for line in [config_line(report)] if line]
    return [fields + esc(host_note(report)), *(bold_label(ln, _bold, esc) for ln in lines)]


def render_wiki(
    report: Report,
    *,
    check_heading: Callable[[CheckResult], list[str]],
    finding: Callable[[Finding], list[str]],
    severity: Callable[[str], str],
    todo: bool = False,
) -> str:
    out = [
        "h1. pydebuprep report",
        "",
        *_header(report),
        "",
        "h2. Summary",
        "",
        *summary_table(report),
    ]
    for category, results in by_category(report):
        out += ["", f"h2. {category.capitalize()}"]
        for r in results:
            out += ["", *check_heading(r)]
            if r.skipped_reason:
                out.append(f"_Skipped: {esc(r.skipped_reason)}_")
            if r.error:
                out.append(f"*Error:* {esc(r.error)}")
            for f in r.findings:
                out += ["", *finding(f)]
            if has_baseline_section(report):
                state = baseline_state(report, r)
                if state is not None:
                    out += ["", f"_Changes since baseline: {state}_"]
                else:
                    out += ["", "*Changes since baseline:*"]
                    for f in r.baseline_diff or []:
                        out += ["", *finding(f)]
    if todo:
        out += ["", "h2. TODO", ""]
        items = todo_items(report)
        out += todo_table(items, severity) if items else [NOTHING_TO_DO]
    return "\n".join(out) + "\n"
