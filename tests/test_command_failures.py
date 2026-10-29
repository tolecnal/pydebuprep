"""Every command failing or timing out must yield error/skipped, never ok or false findings."""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from fakes import FakeSystem
from pydebuprep import checks
from pydebuprep.checks.base import Context
from pydebuprep.model import Status
from pydebuprep.osinfo import detect_os
from pydebuprep.runner import run_check
from pydebuprep.snapshot import build_snapshot
from pydebuprep.system import CommandResult, check_allowed

OS_RELEASE = 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n'


class BrokenSystem(FakeSystem):
    def __init__(self, result: str) -> None:
        super().__init__(files={"/etc/os-release": OS_RELEASE}, strict=False)
        self.result = result

    def run(self, argv: Sequence[str], timeout: float = 30.0) -> CommandResult:
        check_allowed(argv)
        args = tuple(argv)
        self.calls.append(args)
        if self.result == "timeout":
            return CommandResult(args, -1, "", "", timed_out=True)
        return CommandResult(args, 127, "", "No such file or directory")


@pytest.mark.parametrize("result", ["timeout", "missing"])
@pytest.mark.parametrize("check_id", [cls.id for cls in checks.ALL_CHECKS])
def test_failed_commands_never_report_ok(result: str, check_id: str) -> None:
    system = BrokenSystem(result)
    (check,) = checks.get_checks([check_id])
    r = run_check(check, Context(system, detect_os(system)))
    if system.calls:
        assert r.status in (Status.ERROR, Status.SKIPPED), (r.status, r.findings)


@pytest.mark.parametrize("check_id", [cls.id for cls in checks.ALL_CHECKS])
def test_failed_commands_never_compare(check_id: str) -> None:
    system = BrokenSystem("timeout")
    (check,) = checks.get_checks([check_id])
    ctx = Context(system, detect_os(system), {"checks": {check_id: ["x"]}})
    if not check.supports_baseline:
        return
    r = run_check(check, ctx)
    if system.calls:
        assert r.status in (Status.ERROR, Status.SKIPPED)


def test_snapshot_skips_checks_whose_commands_fail() -> None:
    system = BrokenSystem("timeout")
    snap = build_snapshot(checks.get_checks(), Context(system, detect_os(system)))
    # These read only files, so failing commands can't stop them.
    assert set(snap["checks"]) <= {"os-release", "apt-sources", "cron"}
    assert snap["kernel"] == "unknown"
