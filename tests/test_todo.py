"""The TODO checklist at the end of a report (--todo)."""

from __future__ import annotations

import dataclasses
import json

import pytest
import yaml

from conftest import make_sample_report
from pydebuprep.model import CheckResult, Finding, Report, Severity, Status
from pydebuprep.render import FORMATS, render
from pydebuprep.render._common import todo_items
from pydebuprep.reportfile import load_report

CONFIRM = "Run pydebuprep again to confirm everything is fixed"


def report_with_extras() -> Report:
    """The sample report plus an errored check and a check skipped for lack of root."""
    report = make_sample_report()
    results = [
        *report.results,
        CheckResult("dkms", "DKMS", "boot", Status.ERROR, error="dkms timed out"),
        CheckResult(
            "firewall", "Firewall", "network", Status.SKIPPED,
            skipped_reason="requires root (run with sudo for this check)",
        ),
    ]  # fmt: skip
    host = dataclasses.replace(report.host, is_root=False)
    return dataclasses.replace(report, results=results, host=host)


def test_items_critical_first_then_warnings_with_steps() -> None:
    items = todo_items(report_with_extras())
    assert [(i.severity, i.check, i.title, i.steps) for i in items] == [
        (
            "critical",
            "apt-sources",
            "Repository still targets bookworm",
            ["Edit /etc/apt/sources.list: change bookworm to trixie"],
        ),
        (
            "warning",
            "apt-sources",
            "Repository https://example.com was enabled before the upgrade",
            ["Re-enable it once the vendor supports trixie"],
        ),
        (None, "dkms", "Find out why dkms failed to run: dkms timed out", []),
        (None, None, "Run pydebuprep as root: 1 check was skipped without it", []),
        (None, None, CONFIRM, []),
    ]


def test_info_findings_are_not_todo_items() -> None:
    titles = [i.title for i in todo_items(make_sample_report())]
    assert "Duplicate source entry" not in titles  # an info finding


def test_nothing_to_do() -> None:
    report = make_sample_report()
    quiet = [dataclasses.replace(r, findings=[], baseline_diff=None) for r in report.results]
    assert todo_items(dataclasses.replace(report, results=quiet)) == []
    for fmt in FORMATS:
        if fmt not in ("json", "yaml"):
            assert "Nothing to do" in render(
                dataclasses.replace(report, results=quiet), fmt, todo=True
            )


@pytest.mark.parametrize("fmt", FORMATS)
def test_without_todo_the_report_is_unchanged(fmt: str) -> None:
    report = make_sample_report()
    assert render(report, fmt) == render(report, fmt, todo=False)
    assert "TODO" not in render(report, fmt) or fmt in ("json", "yaml")


@pytest.mark.parametrize("fmt", ["text", "markdown", "html", "jira", "confluence"])
def test_todo_is_the_last_section(fmt: str) -> None:
    out = render(report_with_extras(), fmt, todo=True)
    todo_at = out.index("TODO")
    assert out.index("Repository still targets bookworm") < todo_at
    assert out.rindex("Repository still targets bookworm") > todo_at
    assert out.rindex(CONFIRM) > out.rindex("Edit /etc/apt/sources.list")


def test_text_checklist() -> None:
    out = render(report_with_extras(), "text", todo=True)
    tail = out[out.index("TODO") :]
    assert "[ ] CRITICAL apt-sources: Repository still targets bookworm\n" in tail
    assert "    [ ] Edit /etc/apt/sources.list: change bookworm to trixie\n" in tail
    assert f"[ ] {CONFIRM}\n" in tail


def test_markdown_task_list() -> None:
    out = render(report_with_extras(), "markdown", todo=True)
    assert "## TODO" in out
    assert "- [ ] **CRITICAL** `apt-sources`: Repository still targets bookworm" in out
    assert "  - [ ] Edit /etc/apt/sources.list: change bookworm to trixie" in out


def test_html_checkboxes_without_script() -> None:
    out = render(report_with_extras(), "html", todo=True)
    assert '<h2 id="todo">TODO</h2>' in out
    assert out.count('<input type="checkbox">') == 7  # 5 items + 2 steps
    assert "<script" not in out


@pytest.mark.parametrize("fmt", ["jira", "confluence"])
def test_wiki_checklists(fmt: str) -> None:
    out = render(report_with_extras(), fmt, todo=True)
    assert "h2. TODO" in out
    assert "* ☐ *CRITICAL* apt-sources: Repository still targets bookworm" in out
    assert "** ☐ Edit /etc/apt/sources.list: change bookworm to trixie" in out


@pytest.mark.parametrize("fmt", ["json", "yaml"])
def test_data_formats_carry_a_todo_list(fmt: str) -> None:
    out = render(report_with_extras(), fmt, todo=True)
    data = json.loads(out) if fmt == "json" else yaml.safe_load(out)
    assert data["todo"][0] == {
        "severity": "critical",
        "check": "apt-sources",
        "title": "Repository still targets bookworm",
        "steps": ["Edit /etc/apt/sources.list: change bookworm to trixie"],
    }
    assert data["todo"][-1] == {"severity": None, "check": None, "title": CONFIRM, "steps": []}
    assert "todo" not in json.loads(render(report_with_extras(), "json"))
    # A report with a todo list reads back like any other.
    assert load_report(out) == report_with_extras()


def test_todo_respects_hidden_findings() -> None:
    report = make_sample_report()
    hidden = [
        dataclasses.replace(r, findings=[f for f in r.findings if f.severity != Severity.CRITICAL])
        for r in report.results
    ]
    titles = [i.title for i in todo_items(dataclasses.replace(report, results=hidden))]
    assert "Repository still targets bookworm" not in titles


def test_todo_text_is_cleaned_of_control_sequences() -> None:
    report = make_sample_report()
    report.results[0].findings[0] = Finding(
        Severity.CRITICAL, "bad \x1b[31mred", remediation=["run \x1b]0;x\x07this"]
    )
    out = render(report, "text", todo=True)
    assert "\x1b" not in out[out.index("TODO") :]
