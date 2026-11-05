"""Jira Cloud's editor takes pasted Markdown, not wiki markup."""

from __future__ import annotations

import dataclasses

import pytest

from conftest import make_sample_report
from pydebuprep.model import CheckResult, ConfigInfo, Finding, Report, Severity, Status
from pydebuprep.render import EXTENSIONS, FORMATS, render
from pydebuprep.render._cloud_markdown import UNRESOLVED
from pydebuprep.render._jira_limit import JIRA_LIMIT


def _one_check(*findings: Finding, status: Status = Status.FINDINGS, **kwargs: str) -> Report:
    result = CheckResult("demo", "Demo", "system", status, findings=list(findings), **kwargs)
    return dataclasses.replace(make_sample_report(), results=[result])


def test_jira_legacy_and_the_jira_alias_are_the_same_wiki_markup() -> None:
    report = make_sample_report()
    assert render(report, "jira-legacy") == render(report, "jira")
    assert render(report, "jira-legacy").startswith("h1. pydebuprep report\n")
    assert {"jira", "jira-legacy", "jira-cloud"} <= set(FORMATS)
    assert EXTENSIONS["jira-legacy"] == EXTENSIONS["jira"] == "jira.txt"
    assert EXTENSIONS["jira-cloud"] == "jira-cloud.md"


def test_cloud_is_markdown_without_wiki_markup() -> None:
    out = render(make_sample_report(), "jira-cloud", todo=True)
    assert out.startswith("# pydebuprep report\n")
    assert "## Summary" in out
    assert "### `apt-sources` - APT sources" in out
    for wiki in ("h1.", "h2.", "h3.", "{color", "{noformat}", "||"):
        assert wiki not in out


def test_cloud_summary_is_a_table() -> None:
    s = make_sample_report().summary
    out = render(make_sample_report(), "jira-cloud")
    assert "| Critical | Warning | Info | OK | Skipped | Error | Exit code |\n" in out
    assert "|---|---|---|---|---|---|---|\n" in out
    row = f"| {s.critical} | {s.warning} | {s.info} | {s.ok} | {s.skipped} | {s.error} | {s.exit_code} |\n"
    assert row in out


@pytest.mark.parametrize(
    ("severity", "shown"),
    [
        (Severity.CRITICAL, "🔴 **CRITICAL**: a problem"),
        (Severity.WARNING, "🟠 **WARNING**: a problem"),
        (Severity.INFO, "🔵 **INFO**: a problem"),
    ],
)
def test_cloud_findings_show_severity_as_emoji_and_words(severity: Severity, shown: str) -> None:
    assert shown in render(_one_check(Finding(severity, "a problem")), "jira-cloud")


@pytest.mark.parametrize(
    ("severity", "emoji"),
    [(Severity.CRITICAL, "🔴"), (Severity.WARNING, "🟠"), (Severity.INFO, "🔵")],
)
def test_cloud_status_follows_the_worst_finding(severity: Severity, emoji: str) -> None:
    report = _one_check(Finding(Severity.INFO, "note"), Finding(severity, "a problem"))
    assert f"Status: {emoji} **FINDINGS**" in render(report, "jira-cloud")


@pytest.mark.parametrize(
    ("status", "emoji"), [(Status.OK, "🟢"), (Status.SKIPPED, "⚪"), (Status.ERROR, "🔴")]
)
def test_cloud_other_statuses(status: Status, emoji: str) -> None:
    out = render(_one_check(status=status), "jira-cloud")
    assert f"Status: {emoji} **{status.value.upper()}**" in out


def test_cloud_skipped_and_error_reasons() -> None:
    assert "Skipped: not here" in render(
        _one_check(status=Status.SKIPPED, skipped_reason="not here"), "jira-cloud"
    )
    assert "**Error:** it broke" in render(
        _one_check(status=Status.ERROR, error="it broke"), "jira-cloud"
    )


def test_cloud_finding_body_is_not_indented() -> None:
    finding = Finding(
        Severity.WARNING,
        "t",
        detail="line one\nline two",
        evidence=["/etc/foo {x} | y"],
        remediation=["first", "second"],
        references=["https://example.com/a_b"],
    )
    out = render(_one_check(finding), "jira-cloud")
    assert "\nline one\nline two\n" in out
    assert "\n**Evidence:**\n\n```\n/etc/foo {x} | y\n```\n" in out
    assert "\n**Remediation:**\n\n1. first\n2. second\n" in out
    assert "\n**References:**\n\n- [https://example.com/a\\_b](https://example.com/a_b)\n" in out


def test_cloud_evidence_cannot_close_its_code_block() -> None:
    out = render(_one_check(Finding(Severity.INFO, "t", evidence=["```", "x"])), "jira-cloud")
    assert "\n````\n```\nx\n````\n" in out


@pytest.mark.parametrize("url", ["javascript:alert(1)", "https://example.com/a)b", "http://a b"])
def test_cloud_unsafe_or_awkward_references_are_not_links(url: str) -> None:
    out = render(_one_check(Finding(Severity.INFO, "t", references=[url])), "jira-cloud")
    assert f"]({url}" not in out


def test_cloud_dashes_stay_as_typed() -> None:
    out = render(_one_check(Finding(Severity.INFO, "a -- b and (-) (/) (!)")), "jira-cloud")
    assert "a -- b and (-) (/) (!)" in out


@pytest.mark.parametrize(
    "start",
    [
        "# big",
        "###### big",
        "- item",
        "+ item",
        "1. item",
        "2) item",
        "> quote",
        "---",
        "***",
        "```",
    ],
)
def test_cloud_text_cannot_start_a_block(start: str) -> None:
    out = render(_one_check(Finding(Severity.INFO, "t", detail=f"ok\n{start}")), "jira-cloud")
    assert f"\n{start}" not in out


def test_cloud_inline_markup_is_escaped() -> None:
    out = render(_one_check(Finding(Severity.INFO, "a|b *c* _d_ [e](f) `g` <h>")), "jira-cloud")
    assert r"a|b \*c\* \_d\_ \[e\](f) \`g\` \<h\>" in out


def test_cloud_a_multi_line_title_stays_on_its_line() -> None:
    out = render(_one_check(Finding(Severity.INFO, "one\n# two")), "jira-cloud")
    assert "🔵 **INFO**: one # two" in out


def test_cloud_awkward_check_id_is_not_code() -> None:
    report = _one_check(Finding(Severity.CRITICAL, "t"))
    report.results[0].id = "a`b|c"
    out = render(report, "jira-cloud", todo=True)
    assert r"### a\`b|c - Demo" in out
    assert r"| a\`b\|c |" in out


def test_cloud_baseline_sections() -> None:
    report = make_sample_report()
    assert report.baseline is not None
    out = render(report, "jira-cloud")
    assert "_Changes since baseline: " in out or "**Changes since baseline:**" in out
    report.results[0].baseline_diff = [Finding(Severity.WARNING, "new here")]
    report.results.append(CheckResult("quiet", "Quiet", "system", Status.OK))
    out = render(report, "jira-cloud")
    assert "**Changes since baseline:**\n\n🟠 **WARNING**: new here" in out
    assert "_Changes since baseline: not applicable_" in out


def test_cloud_unresolved_icon_is_the_heavy_minus_sign() -> None:
    assert UNRESOLVED == "\u2796"


def test_cloud_todo_is_a_table_with_status_emoji() -> None:
    report = make_sample_report()
    report.results[0].findings[0].remediation = ["First a|b", "Second"]
    report.results.append(CheckResult("dkms", "DKMS", "boot", Status.ERROR, error="timed out"))
    out = render(report, "jira-cloud", todo=True)
    tail = out[out.index("## TODO") :]
    assert f"{UNRESOLVED} unresolved, ⚠️ needs attention, ✅ resolved" in tail
    assert "| Status | Severity | Check | Finding | Fix |\n|---|---|---|---|---|\n" in tail
    assert (
        f"| {UNRESOLVED} | 🔴 **CRITICAL** | `apt-sources` | Repository still targets bookworm | "
        r"1. First a\|b 2. Second |" + "\n"
    ) in tail
    assert f"| {UNRESOLVED} | | `dkms` | Find out why dkms failed to run: timed out | |\n" in tail
    assert f"| {UNRESOLVED} | | | Run pydebuprep again to confirm everything is fixed | |\n" in tail


def test_cloud_nothing_to_do() -> None:
    out = render(_one_check(status=Status.OK), "jira-cloud", todo=True)
    assert out.rstrip().endswith("## TODO\n\nNothing to do.")


def _huge_report() -> Report:
    report = make_sample_report()
    lines = [f"/very/long/path/number/{i}/that/takes/up/space.conf" for i in range(20)]
    for n in range(60):
        severity = (Severity.CRITICAL, Severity.WARNING, Severity.INFO, Severity.INFO)[n % 4]
        finding = Finding(severity, f"Finding number {n}", detail="A detail. " * 20, evidence=list(lines),
                          remediation=[f"step {i} " * 10 for i in range(12)])  # fmt: skip
        report.results.append(CheckResult(f"c{n}", f"Check {n}", "system", Status.FINDINGS, findings=[finding]))  # fmt: skip
    return report


@pytest.mark.parametrize("todo", [False, True])
def test_cloud_stays_within_jiras_size_limit(todo: bool) -> None:
    out = render(_huge_report(), "jira-cloud", todo=todo)
    assert len(out.encode()) <= JIRA_LIMIT
    assert out.startswith("# pydebuprep report\n_Shortened to fit Jira's size limit")
    for n in range(60):
        if n % 4 < 2:
            assert f"Finding number {n}" in out


def test_cloud_small_reports_are_not_shortened() -> None:
    assert "Shortened" not in render(make_sample_report(), "jira-cloud")


def test_cloud_pipes_are_only_escaped_in_tables() -> None:
    report = _one_check(Finding(Severity.CRITICAL, "a|b", detail="c|d", remediation=["e|f"]))
    out = render(report, "jira-cloud", todo=True)
    head, tail = out[: out.index("## TODO")], out[out.index("## TODO") :]
    assert "\\|" not in head
    for text in ("a|b", "c|d", "e|f"):
        assert text in head
    assert r"| a\|b | 1. e\|f |" in tail


def test_cloud_text_cannot_make_a_table() -> None:
    finding = Finding(Severity.INFO, "t", detail="| a | b |\n|---|---|\n| c | d |")
    out = render(_one_check(finding), "jira-cloud")
    assert r"\|---\|---\|" in out
    assert "\n|---|---|\n" not in out.replace(
        "| Critical | Warning | Info | OK | Skipped | Error | Exit code |\n|---|---|---|---|---|---|---|",
        "",
    )


def test_cloud_header_labels_are_bold() -> None:
    report = make_sample_report()
    report = dataclasses.replace(
        report,
        host=dataclasses.replace(report.host, machine_id="m1"),
        config=ConfigInfo("https://portal/c", "2026-11-01", False),
    )
    out = render(report, "jira-cloud")
    assert (
        "- **Host:** testhost | **OS:** debian 13 (trixie) | **Kernel:** 6.12.0-1-amd64 | **Machine:** m1\n"
        in out
    )
    assert "- **Generated:** 2026-10-28" in out
    assert "- **Baseline:** /var/lib/" in out
    assert "- **Config:** https://portal/c (fetched 2026-11-01)\n" in out


@pytest.mark.parametrize("fmt", ["jira", "jira-legacy", "confluence"])
def test_wiki_header_labels_are_bold(fmt: str) -> None:
    report = make_sample_report()
    report = dataclasses.replace(
        report,
        host=dataclasses.replace(report.host, machine_id="m1"),
        config=ConfigInfo("https://portal/c", "2026-11-01", False),
    )
    out = render(report, fmt)
    assert (
        r"*Host:* testhost \| *OS:* debian 13 (trixie) \| *Kernel:* 6.12.0-1-amd64 \| *Machine:* m1"
        in out
    )
    assert "\n*Generated:* 2026-10-28" in out
    assert "\n*Baseline:* /var/lib/" in out
    assert "\n*Config:* https://portal/c (fetched 2026-11-01)\n" in out


@pytest.mark.parametrize(("fmt", "bold"), [("jira", "*"), ("jira-cloud", "**")])
def test_header_keeps_its_notes_and_values_escaped(fmt: str, bold: str) -> None:
    report = make_sample_report()
    report = dataclasses.replace(
        report,
        host=dataclasses.replace(report.host, hostname="a*b", is_root=False),
        baseline=None,
        config=ConfigInfo("https://portal/c", "2026-11-01", True),
    )
    out = render(report, fmt)
    assert f"{bold}Host:{bold} a\\*b" in out
    assert "(not run as root: some checks skipped)" in out
    assert f"{bold}Baseline:{bold} none" in out
    # The stale config line is a sentence, with no label to make bold.
    assert "Config from https://portal/c could not be fetched" in out
