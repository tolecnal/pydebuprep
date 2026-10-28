from __future__ import annotations

from typing import Any

import pytest

from fakes import FakeSystem
from pydebuprep import checks
from pydebuprep.checks.base import Check, Context
from pydebuprep.model import Finding, Severity, Status
from pydebuprep.osinfo import OsInfo
from pydebuprep.runner import run_check, run_checks

OS = OsInfo("debian", "13", "trixie", "Debian 13", None)


class OkCheck(Check):
    id = "ok-check"
    title = "OK"
    category = "boot"

    def run(self, ctx: Context) -> list[Finding]:
        return []


class RootCheck(Check):
    id = "root-check"
    title = "Root"
    category = "boot"
    requires_root = True
    ran = False

    def run(self, ctx: Context) -> list[Finding]:
        RootCheck.ran = True
        return [Finding(Severity.CRITICAL, "x")]


class DkmsLike(Check):
    id = "dkms-like"
    title = "D"
    category = "boot"
    requires_commands = ("dkms",)
    install_hint = "apt install dkms"

    def run(self, ctx: Context) -> list[Finding]:
        return []


class Boom(Check):
    id = "boom"
    title = "Boom"
    category = "release"

    def run(self, ctx: Context) -> list[Finding]:
        raise RuntimeError("boom")


class WithBaseline(Check):
    id = "with-baseline"
    title = "B"
    category = "services"

    def run(self, ctx: Context) -> list[Finding]:
        return []

    def collect_baseline(self, ctx: Context) -> Any:
        return ["a"]

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        return [Finding(Severity.WARNING, f"was {before}")]


def ctx(**kw: Any) -> Context:
    baseline = kw.pop("baseline", None)
    return Context(FakeSystem(**kw), OS, baseline)


def test_non_root_skips_root_checks() -> None:
    RootCheck.ran = False
    r = run_check(RootCheck(), ctx(root=False))
    assert r.status is Status.SKIPPED
    assert r.skipped_reason is not None
    assert r.skipped_reason.startswith("requires root")
    assert not RootCheck.ran


def test_missing_command_skips() -> None:
    r = run_check(DkmsLike(), ctx(available=set()))
    assert r.status is Status.SKIPPED
    assert r.skipped_reason == "command not found: dkms; apt install dkms"


def test_check_exception_becomes_error() -> None:
    r = run_check(Boom(), ctx())
    assert r.status is Status.ERROR
    assert r.error == "RuntimeError: boom"
    results = run_checks([OkCheck(), Boom()], ctx())
    assert [x.id for x in results] == ["boom", "ok-check"]


def test_findings_status() -> None:
    assert run_check(RootCheck(), ctx()).status is Status.FINDINGS
    assert run_check(OkCheck(), ctx()).status is Status.OK


def test_baseline_diff_none_without_baseline() -> None:
    assert run_check(WithBaseline(), ctx()).baseline_diff is None
    assert run_check(OkCheck(), ctx(baseline={"checks": {}})).baseline_diff is None


def test_baseline_diff_list_with_baseline() -> None:
    r = run_check(WithBaseline(), ctx(baseline={"checks": {"with-baseline": ["a"]}}))
    assert r.status is Status.FINDINGS
    assert r.baseline_diff is not None
    assert [f.title for f in r.baseline_diff] == ["was ['a']"]


def test_baseline_missing_key_gives_none() -> None:
    r = run_check(WithBaseline(), ctx(baseline={"checks": {}}))
    assert r.baseline_diff is None
    assert r.status is Status.OK


def test_supports_baseline() -> None:
    assert WithBaseline().supports_baseline
    assert not OkCheck().supports_baseline


def test_get_checks_unknown_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checks, "ALL_CHECKS", [OkCheck, Boom])
    with pytest.raises(ValueError, match="unknown check: nope"):
        checks.get_checks(["nope"])
    with pytest.raises(ValueError, match="unknown check: nope"):
        checks.get_checks(skip=["nope"])


def test_get_checks_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checks, "ALL_CHECKS", [OkCheck, Boom])
    assert [c.id for c in checks.get_checks(skip=["boom"])] == ["ok-check"]
    assert [c.id for c in checks.get_checks(["boom"])] == ["boom"]
