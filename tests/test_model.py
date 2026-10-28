from __future__ import annotations

from conftest import make_sample_report
from pydebuprep.model import (
    CheckResult,
    Finding,
    Severity,
    Status,
    compute_summary,
    sort_findings,
    sort_results,
    truncate_evidence,
)


def test_summary_exit_code_critical() -> None:
    r = [CheckResult("a", "A", "packages", Status.FINDINGS, [Finding(Severity.CRITICAL, "x")])]
    assert compute_summary(r).exit_code == 2


def test_summary_exit_code_warning_from_baseline_diff() -> None:
    r = [
        CheckResult(
            "a",
            "A",
            "packages",
            Status.FINDINGS,
            [],
            baseline_diff=[Finding(Severity.WARNING, "x")],
        )
    ]
    s = compute_summary(r)
    assert (s.warning, s.exit_code) == (1, 1)


def test_summary_ignores_skipped_and_error() -> None:
    r = [
        CheckResult("a", "A", "boot", Status.SKIPPED, skipped_reason="requires root"),
        CheckResult("b", "B", "boot", Status.ERROR, error="boom"),
        CheckResult("c", "C", "boot", Status.OK),
    ]
    s = compute_summary(r)
    assert (s.skipped, s.error, s.ok, s.exit_code) == (1, 1, 1, 1)


def test_summary_skipped_only_exit_0() -> None:
    r = [CheckResult("a", "A", "boot", Status.SKIPPED, skipped_reason="requires root")]
    assert compute_summary(r).exit_code == 0


def test_summary_error_does_not_lower_critical() -> None:
    r = [
        CheckResult("b", "B", "boot", Status.ERROR, error="boom"),
        CheckResult("c", "C", "boot", Status.FINDINGS, [Finding(Severity.CRITICAL, "x")]),
    ]
    assert compute_summary(r).exit_code == 2


def test_info_only_exit_0() -> None:
    r = [CheckResult("a", "A", "boot", Status.FINDINGS, [Finding(Severity.INFO, "x")])]
    s = compute_summary(r)
    assert (s.info, s.exit_code) == (1, 0)


def test_truncate_evidence() -> None:
    out = truncate_evidence([str(i) for i in range(25)])
    assert len(out) == 21
    assert out[-1] == "... (+5 more)"
    assert truncate_evidence(["a"]) == ["a"]


def test_sort_results_by_category_then_id() -> None:
    ids = [
        r.id
        for r in sort_results(
            [
                CheckResult("z", "", "storage", Status.OK),
                CheckResult("b", "", "release", Status.OK),
                CheckResult("a", "", "release", Status.OK),
            ]
        )
    ]
    assert ids == ["a", "b", "z"]


def test_sort_findings_by_severity_stable() -> None:
    fs = [
        Finding(Severity.INFO, "i1"),
        Finding(Severity.CRITICAL, "c"),
        Finding(Severity.INFO, "i2"),
        Finding(Severity.WARNING, "w"),
    ]
    assert [f.title for f in sort_findings(fs)] == ["c", "w", "i1", "i2"]


def test_report_to_dict_key_order_and_enum_values() -> None:
    d = make_sample_report().to_dict()
    assert list(d) == [
        "schema_version",
        "tool",
        "generated_at",
        "host",
        "baseline",
        "summary",
        "results",
    ]
    assert d["results"][0]["findings"][0]["severity"] == "critical"
    assert d["results"][0]["status"] == "findings"
