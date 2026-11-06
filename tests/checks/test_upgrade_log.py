"""upgrade-log: what APT, dpkg and the release upgrader logged since the snapshot. The samples
are real output from a package whose post-installation script fails."""

from __future__ import annotations

import gzip
from typing import Any

import pytest

from pydebuprep.checks.upgrade_log import UpgradeLogCheck
from pydebuprep.model import Finding, Severity

from .helpers import make_ctx

HISTORY = "/var/log/apt/history.log"
TERM = "/var/log/apt/term.log"
DPKG = "/var/log/dpkg.log"
UPGRADER = "/var/log/dist-upgrade/main.log"

FAILED_RUN = """
Start-Date: 2026-10-20  23:08:48
Commandline: apt-get install -y /tmp/failpkg.deb
Install: failpkg:amd64 (1.0)
Error: Sub-process /usr/bin/dpkg returned an error code (1)
End-Date: 2026-10-20  23:08:48
"""
GOOD_RUN = """
Start-Date: 2026-10-20  20:00:00
Commandline: apt full-upgrade -y
Upgrade: bash:amd64 (5.2, 5.3)
End-Date: 2026-10-20  20:10:00
"""
REMOVING_RUN = """
Start-Date: 2026-10-20  21:00:00
Commandline: apt full-upgrade -y
Remove: libold1:amd64 (1.0), tool:amd64 (2.0, automatic)
Purge: gone:amd64 (3.0)
End-Date: 2026-10-20  21:00:01
"""
UNFINISHED_RUN = """
Start-Date: 2026-10-20  22:00:00
Commandline: apt full-upgrade -y
Upgrade: bash:amd64 (5.2, 5.3)
"""
FAILED_TERM = """
Log started: 2026-10-20  23:08:48
Selecting previously unselected package failpkg.
Setting up failpkg (1.0) ...
boom
dpkg: error processing package failpkg (--configure):
 installed failpkg package post-installation script subprocess returned error exit status 3
Errors were encountered while processing:
 failpkg
Log ended: 2026-10-20  23:08:48
"""
FAILED_DPKG = """2026-10-20 23:08:48 startup packages configure
2026-10-20 23:08:48 status unpacked failpkg:all 1.0
2026-10-20 23:08:48 status half-configured failpkg:all 1.0
"""
FIXED_DPKG = FAILED_DPKG + "2026-10-20 23:30:00 status installed failpkg:all 1.0\n"
QUIET = {HISTORY: GOOD_RUN, TERM: "\nLog started: 2026-10-20  20:00:00\nLog ended: 2026-10-20  20:10:00\n",
         DPKG: "2026-10-20 20:00:00 status installed bash:amd64 5.3\n"}  # fmt: skip
SNAPSHOT = {"created_at": "2026-10-20T12:00:00+00:00", "checks": {}}


def run(snapshot: dict[str, Any] | None = None, days: int = 30, **files: str) -> list[Finding]:
    ctx = make_ctx(files={**QUIET, **{_PATHS[k]: v for k, v in files.items()}})
    ctx.baseline = snapshot
    return UpgradeLogCheck({"days": days}).run(ctx)


_PATHS = {"history": HISTORY, "term": TERM, "dpkg": DPKG, "upgrader": UPGRADER}


def summary(findings: list[Finding]) -> list[tuple[Severity, str]]:
    return [(f.severity, f.title) for f in findings]


def test_a_clean_upgrade_is_silent() -> None:
    assert run() == []


def test_a_run_that_reported_an_error() -> None:
    (f,) = run(history=FAILED_RUN)
    assert summary([f]) == [(Severity.WARNING, "1 APT run reported errors")]
    assert f.evidence == [
        "2026-10-20 23:08:48: apt-get install -y /tmp/failpkg.deb: "
        "Sub-process /usr/bin/dpkg returned an error code (1)"
    ]


def test_a_run_that_never_finished() -> None:
    (f,) = run(history=UNFINISHED_RUN + GOOD_RUN)
    assert summary([f]) == [(Severity.WARNING, "1 APT run didn't finish")]
    assert f.evidence == ["2026-10-20 22:00:00: apt full-upgrade -y"]


def test_a_last_run_that_never_finished() -> None:
    assert summary(run(history=UNFINISHED_RUN)) == [(Severity.WARNING, "1 APT run didn't finish")]


def test_removed_packages_are_listed() -> None:
    (f,) = run(history=REMOVING_RUN)
    assert summary([f]) == [(Severity.INFO, "3 packages were removed or purged")]
    assert f.evidence == ["gone", "libold1", "tool"]


def test_a_failed_package_is_a_warning() -> None:
    (f,) = run(term=FAILED_TERM, dpkg=FAILED_DPKG)
    assert summary([f]) == [(Severity.WARNING, "1 package failed during installation or upgrade")]
    assert f.evidence == [
        "failpkg (--configure): installed failpkg package post-installation script "
        "subprocess returned error exit status 3"
    ]


def test_a_failure_after_progress_output_on_the_same_line_is_found() -> None:
    term = "\nLog started: 2026-10-20  23:08:48\n(Reading 5%\rdpkg: error processing package x (--unpack):\n oops\nLog ended: 2026-10-20  23:08:48\n"
    (f,) = run(term=term)
    assert f.evidence == ["x (--unpack): oops"]


def test_a_failure_with_no_reason_following() -> None:
    term = "\nLog started: 2026-10-20  23:08:48\ndpkg: error processing package x (--unpack):"
    (f,) = run(term=term)
    assert f.evidence == ["x (--unpack)"]


def test_a_package_that_was_configured_later_is_only_for_information() -> None:
    (f,) = run(term=FAILED_TERM, dpkg=FIXED_DPKG)
    assert summary([f]) == [(Severity.INFO, "1 package failed, then installed correctly later")]


def test_the_same_failure_twice_counts_once() -> None:
    (f,) = run(term=FAILED_TERM + FAILED_TERM, dpkg=FAILED_DPKG)
    assert f.title == "1 package failed during installation or upgrade"


def test_only_what_happened_since_the_snapshot_counts() -> None:
    late = {"created_at": "2026-10-21T12:00:00+00:00", "checks": {}}
    assert run(late, history=FAILED_RUN, term=FAILED_TERM, dpkg=FAILED_DPKG) == []


def test_a_snapshot_with_a_bad_time_falls_back_to_days() -> None:
    bad = {"created_at": "yesterday", "checks": {}}
    assert summary(run(bad, history=FAILED_RUN)) == [
        (Severity.WARNING, "1 APT run reported errors")
    ]


def test_a_snapshot_without_a_time_falls_back_to_days() -> None:
    assert summary(run({"checks": {}}, history=FAILED_RUN)) == [
        (Severity.WARNING, "1 APT run reported errors")
    ]


def test_without_a_snapshot_only_the_last_days_count() -> None:
    # The fake clock says 2026-10-28.
    assert run(days=1, history=FAILED_RUN, term=FAILED_TERM, dpkg=FAILED_DPKG) == []
    assert run(days=30, history=FAILED_RUN) != []


def test_rotated_and_compressed_logs_are_read() -> None:
    ctx = make_ctx(
        files={
            **QUIET,
            f"{HISTORY}.1": REMOVING_RUN,
            f"{HISTORY}.2.gz": gzip.compress(FAILED_RUN.encode()),  # type: ignore[dict-item]
        }
    )
    assert summary(UpgradeLogCheck().run(ctx)) == [
        (Severity.WARNING, "1 APT run reported errors"),
        (Severity.INFO, "3 packages were removed or purged"),
    ]


def test_missing_logs_are_no_evidence_not_good_news() -> None:
    (f,) = UpgradeLogCheck().run(make_ctx())
    assert summary([f]) == [(Severity.INFO, "3 upgrade logs are missing")]
    assert f.evidence == [HISTORY, TERM, DPKG]


def test_unreadable_logs_are_reported() -> None:
    ctx = make_ctx(files=dict(QUIET))
    ctx.system.read_range = (  # type: ignore[method-assign]
        lambda path, offset, size: None if path == TERM else b"x"
    )
    (f,) = UpgradeLogCheck().run(ctx)
    assert summary([f]) == [(Severity.INFO, "1 upgrade log can't be read")]
    assert f.evidence == [TERM]


def test_logs_that_begin_after_the_snapshot_are_said_to() -> None:
    assert summary(run(SNAPSHOT, dpkg="2026-10-25 10:00:00 status installed a:all 1\n")) == [
        (Severity.INFO, "The upgrade logs begin after the snapshot")
    ]


def test_logs_that_reach_back_to_the_snapshot_say_nothing() -> None:
    old = "2026-10-01 10:00:00 status installed a:all 1\n2026-10-25 10:00:00 status installed a:all 2\n"
    assert run(SNAPSHOT, dpkg=old) == []


def test_lines_that_are_not_log_entries_are_ignored() -> None:
    assert run(SNAPSHOT, dpkg="junk\n2026-10-01 10:00:00 startup\n") == []


def test_a_history_entry_with_a_bad_time_is_ignored() -> None:
    assert run(history="\nStart-Date: soon\nError: x\n") == []


def test_release_upgrader_errors() -> None:
    log = (
        "2026-10-20 20:00:00,123 INFO fine\n"
        "2026-10-20 20:01:00,123 ERROR something broke\n"
        "2026-10-20 20:02:00,123 CRITICAL very broken\n"
        "2020-01-01 20:01:00,123 ERROR long ago\n"
    )
    (f,) = run(upgrader=log)
    assert summary([f]) == [(Severity.WARNING, "The release upgrader logged 2 errors")]
    assert f.evidence == ["something broke", "very broken"]


def test_earlier_release_upgrades_are_read_too() -> None:
    path = "/var/log/dist-upgrade/20261020-2000/main.log"
    ctx = make_ctx(files={**QUIET, path: "2026-10-20 20:01:00,123 ERROR old run\n"})
    assert summary(UpgradeLogCheck().run(ctx)) == [
        (Severity.WARNING, "The release upgrader logged 1 error")
    ]


@pytest.mark.parametrize("days", [0, -1, 366])
def test_days_is_bounded(days: int) -> None:
    with pytest.raises(ValueError, match="days"):
        UpgradeLogCheck({"days": days})


def test_an_error_whose_failed_package_was_put_right_is_only_for_information() -> None:
    fs = run(history=FAILED_RUN, term=FAILED_TERM, dpkg=FIXED_DPKG)
    assert summary(fs) == [
        (Severity.INFO, "1 APT run reported errors"),
        (Severity.INFO, "1 package failed, then installed correctly later"),
    ]


def test_an_error_is_a_warning_while_a_package_is_still_failed() -> None:
    fs = run(history=FAILED_RUN, term=FAILED_TERM, dpkg=FAILED_DPKG)
    assert summary(fs)[0] == (Severity.WARNING, "1 APT run reported errors")


def test_rotated_dpkg_logs_count_by_time_not_by_file_order() -> None:
    ctx = make_ctx(
        files={
            **QUIET,
            TERM: FAILED_TERM,
            f"{DPKG}.1": "2026-10-20 23:30:00 status installed failpkg:all 1.0\n",
            f"{DPKG}.2.gz": gzip.compress(FAILED_DPKG.encode()),  # type: ignore[dict-item]
        }
    )
    assert summary(UpgradeLogCheck().run(ctx)) == [
        (Severity.INFO, "1 package failed, then installed correctly later")
    ]
