"""oom-events: processes the kernel killed for lack of memory this boot."""

from __future__ import annotations

from pydebuprep.checks.oom_events import JOURNAL_OOM, OomEventsCheck
from pydebuprep.model import Severity, Status
from pydebuprep.runner import run_check
from pydebuprep.system import CommandResult, check_allowed

from .helpers import make_ctx


def test_the_query_is_allowed() -> None:
    check_allowed(JOURNAL_OOM)


def test_no_events_is_silent() -> None:
    assert OomEventsCheck().run(make_ctx(commands={JOURNAL_OOM: "-- No entries --\n"})) == []


def test_events_are_counted_by_process() -> None:
    out = (
        "Out of memory: Killed process 1 (mysqld) total-vm:1kB, anon-rss:1kB\n"
        "Memory cgroup out of memory: Killed process 2 (mysqld) total-vm:1kB\n"
        "Out of memory: Killed process 3 (java) total-vm:1kB\n"
    )
    (f,) = OomEventsCheck().run(make_ctx(commands={JOURNAL_OOM: out}))
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "3 processes were killed for lack of memory this boot",
    )
    assert f.evidence == ["2x mysqld", "1x java"]


def test_no_matches_exit_status_is_fine() -> None:
    res = CommandResult(JOURNAL_OOM, 1, "", "")
    assert OomEventsCheck().run(make_ctx(commands={JOURNAL_OOM: res})) == []


def test_needs_root() -> None:
    result = run_check(OomEventsCheck(), make_ctx(root=False))
    assert result.status == Status.SKIPPED
