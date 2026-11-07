"""Snapshots record each check's findings, so a report can tell new ones from old ones."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import pytest

from conftest import make_sample_report
from fakes import FakeSystem
from pydebuprep.checks.base import Check, Context
from pydebuprep.findings_history import ALREADY, NEW, WORSE, classify, fingerprint
from pydebuprep.model import CheckResult, Finding, Severity, Status
from pydebuprep.osinfo import detect_os
from pydebuprep.render import FORMATS, render
from pydebuprep.reportfile import ReportFileError, load_report, report_from_dict
from pydebuprep.runner import run_check
from pydebuprep.schema import report_schema
from pydebuprep.snapshot import build_snapshot


def finding(title: str, *evidence: str, severity: Severity = Severity.WARNING) -> Finding:
    return Finding(severity, title, evidence=list(evidence))


def classified(now: Finding, was: Finding) -> str:
    return classify(now, [fingerprint(was)])


def test_a_finding_not_there_before_is_new() -> None:
    assert classified(finding("Unit b.service failed"), finding("Unit a.service failed")) == NEW


def test_the_same_finding_is_already_there() -> None:
    assert classified(finding("Unit a.service failed"), finding("Unit a.service failed")) == ALREADY


@pytest.mark.parametrize(
    ("was", "now"),
    [
        ("1 package is held back", "3 packages are held back"),
        ("2 processes were killed", "1 process was killed"),
        ("1 published container port doesn't answer", "2 published container ports don't answer"),
        ("1 protected package isn't installed", "2 protected packages aren't installed"),
        ("1 package has an older version", "2 packages have an older version"),
        ("Low free space on /var: 9% free", "Low free space on /var: 8% free"),
    ],
)
def test_a_changing_number_is_the_same_finding(was: str, now: str) -> None:
    assert classified(finding(now), finding(was)) == ALREADY


def test_names_with_digits_stay_different() -> None:
    assert classified(finding("Unit foo1 failed"), finding("Unit foo2 failed")) == NEW


def test_new_evidence_is_worse() -> None:
    assert classified(finding("2 units", "a", "b"), finding("1 unit", "a")) == WORSE


def test_less_evidence_is_already_there() -> None:
    assert classified(finding("1 unit", "a"), finding("2 units", "a", "b")) == ALREADY


def test_changing_numbers_in_evidence_are_not_new_evidence() -> None:
    was = finding("Errors", "5x sshd: failed at 2026-10-01 10:00:00")
    assert classified(finding("Errors", "9x sshd: failed at 2026-11-01 12:30:01"), was) == ALREADY


def test_a_higher_severity_is_worse() -> None:
    was = finding("Low free space on /", severity=Severity.WARNING)
    now = finding("Low free space on /", severity=Severity.CRITICAL)
    assert classified(now, was) == WORSE


def test_a_lower_severity_is_already_there() -> None:
    was = finding("Low free space on /", severity=Severity.CRITICAL)
    now = finding("Low free space on /", severity=Severity.WARNING)
    assert classified(now, was) == ALREADY


@pytest.mark.parametrize(
    "before",
    [[{"evidence": "not a list", "title": "x", "severity": "warning"}], [{"title": "x"}]],
)
def test_incomplete_records_count_as_having_no_evidence(before: list[dict[str, Any]]) -> None:
    assert classify(finding("x", "a"), before) == WORSE


def test_records_that_are_not_mappings_are_ignored() -> None:
    assert classify(finding("x"), ["nonsense", 1]) == NEW  # type: ignore[list-item]


class Failing(Check):
    id = "failing"
    title = "Failing"
    category = "services"
    found: tuple[Finding, ...] = (finding("Unit a failed"), finding("Unit b failed"))

    def run(self, ctx: Context) -> list[Finding]:
        return list(self.found)

    def collect_baseline(self, ctx: Context) -> Any:
        return {"x": 1}

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        return [finding("Changed since")]


class Broken(Failing):
    id = "broken"

    def run(self, ctx: Context) -> list[Finding]:
        raise RuntimeError("no")


class NeedsRoot(Failing):
    id = "needs-root"
    requires_root = True


def ctx_with(baseline: dict[str, Any] | None = None, **kw: Any) -> Context:
    system = FakeSystem(
        files={"/etc/os-release": "ID=debian\nVERSION_ID=13\n"},
        commands={("uname", "-r"): "6.12.0\n"},
        **kw,
    )
    return Context(system, detect_os(system), baseline)


def test_a_snapshot_records_what_each_check_finds() -> None:
    snap = build_snapshot([Failing()], ctx_with())
    assert snap["findings"]["failing"] == [
        {"title": "Unit a failed", "evidence": [], "severity": "warning"},
        {"title": "Unit b failed", "evidence": [], "severity": "warning"},
    ]
    assert snap["checks"]["failing"] == {"x": 1}


def test_a_check_that_could_not_run_records_nothing() -> None:
    snap = build_snapshot([Broken(), NeedsRoot()], ctx_with(root=False))
    assert snap["findings"] == {}


def test_a_check_with_nothing_to_report_records_that() -> None:
    class Quiet(Failing):
        found = ()

    assert build_snapshot([Quiet()], ctx_with())["findings"] == {"failing": []}


def test_a_snapshot_can_leave_findings_out() -> None:
    assert "findings" not in build_snapshot([Failing()], ctx_with(), findings=False)


def test_a_report_labels_findings_but_not_changes() -> None:
    before = {"failing": [fingerprint(finding("Unit a failed"))]}
    result = run_check(Failing(), ctx_with({"checks": {"failing": {"x": 1}}, "findings": before}))
    assert [(f.title, f.since_snapshot) for f in result.findings] == [
        ("Unit a failed", ALREADY),
        ("Unit b failed", NEW),
    ]
    assert [f.since_snapshot for f in result.baseline_diff or []] == [None]


def test_findings_are_not_labelled_without_a_record() -> None:
    for baseline in (None, {"checks": {}}, {"checks": {}, "findings": {}}, {"findings": "bad"},
                     {"findings": {"failing": "bad"}}):  # fmt: skip
        result = run_check(Failing(), ctx_with(baseline))
        assert [f.since_snapshot for f in result.findings] == [None, None], baseline


def test_a_check_with_no_findings_then_reports_new_ones() -> None:
    result = run_check(Failing(), ctx_with({"checks": {}, "findings": {"failing": []}}))
    assert {f.since_snapshot for f in result.findings} == {NEW}


def labelled_report() -> Any:
    report = make_sample_report()
    found = [
        replace(finding("Newly broken"), since_snapshot=NEW),
        replace(finding("Getting worse"), since_snapshot=WORSE),
        replace(finding("Long broken"), since_snapshot=ALREADY),
        finding("Not compared"),
    ]
    result = CheckResult("x", "X", "services", Status.FINDINGS, findings=found)
    return replace(report, results=[result])


@pytest.mark.parametrize("fmt", [f for f in FORMATS if f not in ("json", "yaml")])
def test_every_format_shows_the_labels(fmt: str) -> None:
    out = render(labelled_report(), fmt)
    assert "new since the snapshot" in out
    assert "worse than at the snapshot" in out
    assert "already there at the snapshot" in out
    assert "1 new, 1 worse, 1 already there" in out


@pytest.mark.parametrize("fmt", [f for f in FORMATS if f not in ("json", "yaml")])
def test_a_report_without_labels_has_no_such_line(fmt: str) -> None:
    assert "Since the snapshot" not in render(make_sample_report(), fmt)


def test_the_label_survives_saving_and_loading() -> None:
    data = json.loads(render(labelled_report(), "json"))
    found = data["results"][0]["findings"]
    assert [f.get("since_snapshot") for f in found] == [NEW, WORSE, ALREADY, None]
    assert "since_snapshot" not in found[3]
    assert [f.since_snapshot for f in load_report(json.dumps(data)).results[0].findings] == [
        NEW,
        WORSE,
        ALREADY,
        None,
    ]


def test_a_bad_label_is_refused() -> None:
    data = json.loads(render(labelled_report(), "json"))
    data["results"][0]["findings"][0]["since_snapshot"] = "<script>"
    with pytest.raises(ReportFileError, match="since_snapshot"):
        report_from_dict(data)


def test_the_schema_allows_exactly_these_labels() -> None:
    jsonschema = pytest.importorskip("jsonschema")  # not there when the package is built
    validator = jsonschema.Draft202012Validator(report_schema())
    data = json.loads(render(labelled_report(), "json"))
    assert list(validator.iter_errors(data)) == []
    data["results"][0]["findings"][0]["since_snapshot"] = "other"
    assert list(validator.iter_errors(data)) != []


@pytest.mark.parametrize(
    ("fmt", "label"),
    [
        ("markdown", "**Since the snapshot:**"),
        ("jira-cloud", "**Since the snapshot:**"),
        ("jira-legacy", "*Since the snapshot:*"),
        ("html", "<strong>Since the snapshot:</strong>"),
    ],
)
def test_the_header_line_has_a_bold_label(fmt: str, label: str) -> None:
    assert label in render(labelled_report(), fmt)
