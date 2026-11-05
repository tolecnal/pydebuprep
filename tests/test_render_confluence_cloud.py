"""Confluence Cloud's editor takes the same pasted Markdown as Jira Cloud's."""

from __future__ import annotations

import dataclasses

import pytest

from conftest import make_sample_report
from pydebuprep.model import CheckResult, ConfigInfo, Finding, Report, Severity, Status
from pydebuprep.render import EXTENSIONS, FORMATS, render
from pydebuprep.render._jira_limit import JIRA_LIMIT


def _huge_report() -> Report:
    report = make_sample_report()
    lines = [f"/very/long/path/number/{i}/that/takes/up/space.conf" for i in range(20)]
    for n in range(60):
        finding = Finding(Severity.INFO, f"Finding number {n}", detail="A detail. " * 20, evidence=list(lines))  # fmt: skip
        report.results.append(CheckResult(f"c{n}", f"Check {n}", "system", Status.FINDINGS, findings=[finding]))  # fmt: skip
    return report


def test_legacy_and_the_confluence_alias_are_the_same_wiki_markup() -> None:
    report = make_sample_report()
    assert render(report, "confluence-legacy", todo=True) == render(report, "confluence", todo=True)
    assert render(report, "confluence-legacy").startswith("h1. pydebuprep report\n")
    assert "{status:colour=" in render(report, "confluence-legacy")
    assert {"confluence", "confluence-legacy", "confluence-cloud"} <= set(FORMATS)
    assert EXTENSIONS["confluence-legacy"] == EXTENSIONS["confluence"] == "confluence.txt"
    assert EXTENSIONS["confluence-cloud"] == "confluence-cloud.md"


@pytest.mark.parametrize("todo", [False, True])
def test_cloud_is_the_same_markdown_as_jira_cloud(todo: bool) -> None:
    report = make_sample_report()
    out = render(report, "confluence-cloud", todo=todo)
    assert out == render(report, "jira-cloud", todo=todo)
    assert out.startswith("# pydebuprep report\n")
    assert "{status" not in out


def test_cloud_has_no_size_limit() -> None:
    report = _huge_report()
    assert "Shortened" in render(report, "jira-cloud")
    out = render(report, "confluence-cloud", todo=True)
    assert len(out.encode()) > JIRA_LIMIT
    assert "Shortened" not in out
    assert "Cut off" not in out
    for n in range(60):
        assert f"Finding number {n}" in out


def _header_report() -> Report:
    report = make_sample_report()
    return dataclasses.replace(
        report,
        host=dataclasses.replace(report.host, machine_id="m1"),
        config=ConfigInfo("https://portal/c", "2026-11-01", False),
    )


def test_markdown_header_labels_are_bold() -> None:
    out = render(_header_report(), "markdown")
    assert (
        "- **Host:** testhost | **OS:** debian 13 (trixie) | **Kernel:** 6.12.0-1-amd64 | **Machine:** m1\n"
        in out
    )
    assert "- **Generated:** 2026-10-28" in out
    assert "- **Baseline:** /var/lib/" in out
    assert "- **Config:** https://portal/c (fetched 2026-11-01)\n" in out


def test_html_header_labels_are_bold() -> None:
    out = render(_header_report(), "html")
    assert "<strong>Host:</strong> testhost | <strong>OS:</strong> debian 13 (trixie)" in out
    assert "<strong>Machine:</strong> m1" in out
    assert "<br><strong>Generated:</strong> 2026-10-28" in out
    assert "<br><strong>Baseline:</strong> /var/lib/" in out
    assert "<br><strong>Config:</strong> https://portal/c" in out


@pytest.mark.parametrize(("fmt", "value"), [("markdown", r"a\*b\<c"), ("html", "a*b&lt;c")])
def test_header_values_stay_escaped(fmt: str, value: str) -> None:
    report = make_sample_report()
    report = dataclasses.replace(
        report, host=dataclasses.replace(report.host, hostname="a*b<c", is_root=False)
    )
    out = render(report, fmt)
    assert value in out
    assert "(not run as root: some checks skipped)" in out


def test_text_header_is_not_marked_up() -> None:
    out = render(_header_report(), "text")
    assert "Host: testhost | OS: debian 13 (trixie)" in out
    assert "Generated: 2026-10-28" in out
