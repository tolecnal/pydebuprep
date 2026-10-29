"""Reading back a saved JSON or YAML report, for `pydebuprep convert`."""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest

from conftest import make_sample_report
from pydebuprep.model import CheckResult, Report, Status
from pydebuprep.render import FORMATS, render
from pydebuprep.reportfile import ReportFileError, load_report, report_from_dict


def full_report() -> Report:
    """The sample report plus an errored check, so every field is exercised."""
    report = make_sample_report()
    errored = CheckResult("dkms", "DKMS", "boot", Status.ERROR, error="dkms timed out")
    return dataclasses.replace(report, results=[*report.results, errored])


@pytest.mark.parametrize("fmt", FORMATS)
def test_converting_json_gives_the_same_output_as_reporting(fmt: str) -> None:
    report = full_report()
    loaded = load_report(render(report, "json"))
    assert render(loaded, fmt) == render(report, fmt)


@pytest.mark.parametrize("fmt", FORMATS)
def test_converting_yaml_gives_the_same_output_as_reporting(fmt: str) -> None:
    report = full_report()
    loaded = load_report(render(report, "yaml"))
    assert render(loaded, fmt) == render(report, fmt)


def test_report_without_baseline_round_trips() -> None:
    report = dataclasses.replace(full_report(), baseline=None)
    assert load_report(render(report, "json")) == report


@pytest.mark.parametrize(
    "text",
    [
        "pydebuprep report\n=================\nHost: x\n",  # the text format
        "<!DOCTYPE html><html><body>report</body></html>",
        "# pydebuprep report\n\n| Check | Status |\n",  # markdown
        "h1. pydebuprep report\n",  # jira
        "",
        "[1, 2, 3]",
    ],
)
def test_rendered_formats_are_refused_with_a_hint(text: str) -> None:
    with pytest.raises(ReportFileError, match="JSON or YAML"):
        load_report(text)


def test_broken_json_names_the_position() -> None:
    with pytest.raises(ReportFileError, match="line 1"):
        load_report('{"schema_version": "1",')


def report_dict() -> dict[str, Any]:
    return full_report().to_dict()


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d.update(schema_version="2"), "schema_version: unsupported version '2'"),
        (lambda d: d.pop("host"), "host: missing"),
        (lambda d: d["host"].update(is_root="yes"), "host.is_root: expected true or false"),
        (lambda d: d["summary"].update(critical="1"), "summary.critical: expected an integer"),
        (lambda d: d["summary"].update(critical=True), "summary.critical: expected an integer"),
        (lambda d: d.update(results={}), "results: expected a list"),
        (lambda d: d["results"][0].update(status="fine"), "results[0].status: expected one of"),
        (
            lambda d: d["results"][0]["findings"][0].update(severity="urgent"),
            "results[0].findings[0].severity: expected one of",
        ),
        (
            lambda d: d["results"][0]["findings"][0].update(evidence="x"),
            "results[0].findings[0].evidence: expected a list of strings",
        ),
        (
            lambda d: d["results"][0]["findings"][0].update(evidence=[1]),
            "results[0].findings[0].evidence: expected a list of strings",
        ),
        (lambda d: d["results"][0].update(baseline_diff="x"), "results[0].baseline_diff"),
        (lambda d: d["results"][0].update(findings="x"), "results[0].findings: expected a list"),
        (lambda d: d.update(baseline=[]), "baseline: expected a mapping"),
        (lambda d: d.update(tool={"name": 1}), "tool: expected a mapping of strings"),
        (lambda d: d.update(generated_at=5), "generated_at: expected a string"),
        (lambda d: d.update(generated_at="yesterday"), "generated_at: not an ISO 8601 time"),
        (lambda d: d["results"][0].update(error=3), "results[0].error: expected a string"),
    ],
)
def test_malformed_reports_name_the_field(change: Any, message: str) -> None:
    data = report_dict()
    change(data)
    with pytest.raises(ReportFileError, match=message.replace("[", r"\[").replace("]", r"\]")):
        report_from_dict(data)


def test_optional_finding_fields_may_be_missing() -> None:
    data = report_dict()
    finding = data["results"][0]["findings"][1]
    for key in ("detail", "evidence", "remediation", "references"):
        finding.pop(key)
    loaded = report_from_dict(data)
    assert loaded.results[0].findings[1].remediation == []


def test_yaml_is_loaded_safely() -> None:
    with pytest.raises(ReportFileError):
        load_report("!!python/object/apply:os.system ['true']\n")


def test_json_with_unicode_round_trips() -> None:
    report = full_report()
    report.results[0].findings[0].title = "Café ☕ und Grüße"
    text = json.dumps(report.to_dict(), ensure_ascii=True)
    assert load_report(text).results[0].findings[0].title == "Café ☕ und Grüße"
