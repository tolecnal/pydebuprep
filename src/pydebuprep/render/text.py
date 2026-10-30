from __future__ import annotations

from pydebuprep.model import Finding, Report
from pydebuprep.render._common import (
    NOTHING_TO_DO,
    baseline_line,
    baseline_state,
    by_category,
    config_line,
    has_baseline_section,
    host_line,
    summary_line,
    todo_items,
)

COLORS = {
    "critical": "\x1b[1;31m",
    "warning": "\x1b[1;33m",
    "info": "\x1b[36m",
    "ok": "\x1b[32m",
    "skipped": "\x1b[2m",
    "error": "\x1b[1;35m",
    "findings": "\x1b[1m",
}
RESET = "\x1b[0m"


def _paint(word: str, key: str, color: bool) -> str:
    return f"{COLORS[key]}{word}{RESET}" if color else word


def _finding(f: Finding, indent: str, color: bool) -> list[str]:
    sev = _paint(f.severity.value.upper(), f.severity.value, color)
    lines = [f"{indent}{sev}: {f.title}"]
    sub = indent + "    "
    if f.detail:
        lines.extend(f"{sub}{d}" for d in f.detail.splitlines())
    if f.evidence:
        lines.append(f"{sub}Evidence:")
        lines.extend(f"{sub}  {e}" for e in f.evidence)
    if f.remediation:
        lines.append(f"{sub}Remediation:")
        lines.extend(f"{sub}  {i}. {step}" for i, step in enumerate(f.remediation, 1))
    if f.references:
        lines.append(f"{sub}References:")
        lines.extend(f"{sub}  - {ref}" for ref in f.references)
    return lines


def render(report: Report, *, color: bool = False, todo: bool = False) -> str:
    title = "pydebuprep report"
    out = [title, "=" * len(title), host_line(report), f"Generated: {report.generated_at}"]
    out += [baseline_line(report)]
    out += [line for line in [config_line(report)] if line]
    out += ["", f"Summary: {summary_line(report)}"]
    for category, results in by_category(report):
        out += ["", category.upper(), "-" * len(category)]
        for r in results:
            status = _paint(f"[{r.status.value.upper()}]", r.status.value, color)
            out.append(f"{status} {r.id} - {r.title}")
            if r.skipped_reason:
                out.append(f"  Skipped: {r.skipped_reason}")
            if r.error:
                out.append(f"  Error: {r.error}")
            for f in r.findings:
                out += _finding(f, "  ", color)
            if has_baseline_section(report):
                state = baseline_state(report, r)
                if state is not None:
                    out.append(f"  Changes since baseline: {state}")
                else:
                    out.append("  Changes since baseline:")
                    for f in r.baseline_diff or []:
                        out += _finding(f, "    ", color)
    if todo:
        out += ["", "TODO", "----"]
        items = todo_items(report)
        out += [NOTHING_TO_DO] if not items else []
        for item in items:
            out.append(f"[ ] {item.label}")
            out.extend(f"    [ ] {step}" for step in item.steps)
    return "\n".join(out) + "\n"
