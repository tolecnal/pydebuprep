from __future__ import annotations

from html import escape

from pydebuprep.model import Finding, Report
from pydebuprep.render._common import (
    NOTHING_TO_DO,
    baseline_line,
    baseline_state,
    by_category,
    config_line,
    has_baseline_section,
    host_line,
    safe_url,
    summary_line,
    todo_items,
)

STYLE = """
ul.todo, ul.todo ul { list-style: none; padding-left: 1.2em; }
:root { --bg:#ffffff; --fg:#1d1f21; --muted:#5f6368; --line:#d9dce1; --code:#f4f5f7;
  --critical:#b3261e; --warning:#8a5a00; --info:#0b5cad; --ok:#1e7d32; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#16181b; --fg:#e6e7e9; --muted:#9aa0a6; --line:#33373d; --code:#202328;
    --critical:#f2847c; --warning:#f0bf5a; --info:#7cb7f5; --ok:#7fd189; }
}
body { background:var(--bg); color:var(--fg); margin:0 auto; max-width:60rem;
  padding:1.5rem 1rem; font:15px/1.5 system-ui, sans-serif; }
h1 { margin:0 0 .5rem; } h2 { border-bottom:1px solid var(--line); padding-bottom:.25rem;
  margin-top:2rem; } h3 { margin:1.25rem 0 .25rem; font-size:1rem; }
.meta, .muted { color:var(--muted); } code, pre { background:var(--code); border-radius:4px; }
pre { padding:.5rem .75rem; overflow-x:auto; white-space:pre-wrap; word-break:break-word; }
.sev { font-weight:700; text-transform:uppercase; }
.critical { color:var(--critical); } .warning { color:var(--warning); }
.info { color:var(--info); } .ok { color:var(--ok); }
.finding { border-left:3px solid var(--line); padding-left:.75rem; margin:.5rem 0; }
.finding.critical-b { border-color:var(--critical); }
.finding.warning-b { border-color:var(--warning); }
.finding.info-b { border-color:var(--info); }
.finding .title { color:var(--fg); }
@media print { body { max-width:none; } pre { white-space:pre-wrap; } }
"""


def _finding(f: Finding) -> list[str]:
    sev = f.severity.value
    out = [
        f'<div class="finding {sev}-b">',
        f'<div><span class="sev {sev}">{sev}</span>: <span class="title">{escape(f.title)}</span>'
        "</div>",
    ]
    if f.detail:
        out.append(f"<p>{escape(f.detail)}</p>")
    if f.evidence:
        out.append(f"<div>Evidence:</div><pre>{escape(chr(10).join(f.evidence))}</pre>")
    if f.remediation:
        out.append("<div>Remediation:</div><ol>")
        out += [f"<li><code>{escape(step)}</code></li>" for step in f.remediation]
        out.append("</ol>")
    if f.references:
        out.append("<div>References:</div><ul>")
        out += [
            f'<li><a href="{escape(ref, quote=True)}">{escape(ref)}</a></li>'
            if safe_url(ref)
            else f"<li>{escape(ref)}</li>"
            for ref in f.references
        ]
        out.append("</ul>")
    out.append("</div>")
    return out


def render(report: Report, *, todo: bool = False) -> str:
    out = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>pydebuprep report - {escape(report.host.hostname)}</title>",
        f"<style>{STYLE}</style></head><body>",
        "<h1>pydebuprep report</h1>",
        f'<p class="meta">{escape(host_line(report))}<br>Generated: '
        f"{escape(report.generated_at)}<br>{escape(baseline_line(report))}"
        + "".join(f"<br>{escape(line)}" for line in [config_line(report)] if line)
        + "</p>",
        f"<h2>Summary</h2><p>{escape(summary_line(report))}</p>",
    ]
    for category, results in by_category(report):
        out.append(f"<h2>{escape(category.capitalize())}</h2>")
        for r in results:
            out.append(
                f"<section><h3><code>{escape(r.id)}</code> - {escape(r.title)} "
                f'<span class="muted">[{r.status.value}]</span></h3>'
            )
            if r.skipped_reason:
                out.append(f'<p class="muted">Skipped: {escape(r.skipped_reason)}</p>')
            if r.error:
                out.append(f'<p class="critical">Error: {escape(r.error)}</p>')
            for f in r.findings:
                out += _finding(f)
            if has_baseline_section(report):
                state = baseline_state(report, r)
                if state is not None:
                    out.append(f'<p class="muted">Changes since baseline: {state}</p>')
                else:
                    out.append("<p>Changes since baseline:</p>")
                    for f in r.baseline_diff or []:
                        out += _finding(f)
            out.append("</section>")
    if todo:
        out.append('<h2 id="todo">TODO</h2>')
        items = todo_items(report)
        if not items:
            out.append(f"<p>{NOTHING_TO_DO}</p>")
        else:
            out.append('<ul class="todo">')
            for item in items:
                label = (
                    f'<span class="sev {item.severity}">{item.severity}</span> '
                    f"<code>{escape(item.check or '')}</code>: {escape(item.title)}"
                    if item.severity
                    else escape(item.title)
                )
                steps = "".join(
                    f'<li><label><input type="checkbox"> <code>{escape(step)}</code></label></li>'
                    for step in item.steps
                )
                out.append(
                    f'<li><label><input type="checkbox"> {label}</label>'
                    + (f"<ul>{steps}</ul>" if steps else "")
                    + "</li>"
                )
            out.append("</ul>")
    out.append("</body></html>")
    return "\n".join(out) + "\n"
