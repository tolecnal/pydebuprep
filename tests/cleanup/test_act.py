"""Acting on a plan: backups, purges, directories, and a log of every step."""

from __future__ import annotations

import syslog
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fakes import FakeRunner, FakeSystem
from pydebuprep.cleanup.act import CONFFILES_HEAD, backup_conffiles, execute, remove_dir
from pydebuprep.cleanup.kernels import Package
from pydebuprep.cleanup.log import Log
from pydebuprep.cleanup.plan import OWNER_QUERY, Plan, Refused
from pydebuprep.cleanup.runner import APT_PURGE
from pydebuprep.system import CommandResult, check_allowed

NOW = datetime(2026, 11, 3, 15, 4, 5, tzinfo=timezone.utc)
CONFFILES = " /etc/hello/hello.conf 1234abcd\n /etc/hello/gone.conf 5678 obsolete\n /etc/hello/link.conf ab\n"


@pytest.fixture
def syslogged(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    monkeypatch.setattr(syslog, "openlog", lambda *a, **k: None)
    monkeypatch.setattr(syslog, "closelog", lambda: None)
    monkeypatch.setattr(syslog, "syslog", lambda level, text: lines.append((level, text)))
    return lines


def test_backup_has_the_conffiles(tmp_path: Path) -> None:
    system = FakeSystem(
        files={"/etc/hello/hello.conf": "greeting = hi\n"},
        links={"/etc/hello/link.conf": "hello.conf"},
        commands={(*CONFFILES_HEAD, "hello"): CONFFILES},
    )
    path = backup_conffiles(system, ["hello"], NOW, backup_dir=str(tmp_path))
    assert path == str(tmp_path / "rc-20261103T150405Z.tar.gz")
    assert oct(Path(path).stat().st_mode & 0o777) == "0o600"
    with tarfile.open(path) as tar:
        members = {m.name: m for m in tar.getmembers()}
        assert set(members) == {"etc/hello/hello.conf", "etc/hello/link.conf"}  # gone.conf is gone
        assert (
            members["etc/hello/link.conf"].issym()
            and members["etc/hello/link.conf"].linkname == "hello.conf"
        )
        assert tar.extractfile("etc/hello/hello.conf").read() == b"greeting = hi\n"  # type: ignore[union-attr] # a regular member


def test_backup_none_when_nothing(tmp_path: Path) -> None:
    system = FakeSystem(commands={(*CONFFILES_HEAD, "cowsay"): ""})
    assert backup_conffiles(system, ["cowsay"], NOW, backup_dir=str(tmp_path)) is None
    assert list(tmp_path.iterdir()) == []


def test_conffiles_query_is_allowlisted_exactly() -> None:
    from pydebuprep.system import DisallowedCommandError

    check_allowed((*CONFFILES_HEAD, "hello", "libfoo1.2"))
    for bad in (
        (*CONFFILES_HEAD,),
        (*CONFFILES_HEAD, "-x"),
        ("dpkg-query", "-W", "-f=${Conffiles}", "x"),
    ):
        with pytest.raises(DisallowedCommandError):
            check_allowed(bad)


def test_remove_dir_refuses_links_and_other_paths() -> None:
    removed: list[str] = []
    system = FakeSystem(
        files={"/lib/modules/6.8.0-30-generic/x.ko": ""},
        links={"/lib/modules/6.8.0-29-generic": "/etc"},
    )
    remove_dir(system, "/lib/modules/6.8.0-30-generic", remove=removed.append)
    assert removed == ["/lib/modules/6.8.0-30-generic"]
    for path in (
        "/lib/modules/6.8.0-29-generic",
        "/etc",
        "/lib/modules/../etc",
        "/lib/modules/6.8.0-31-generic",
    ):
        with pytest.raises(Refused):
            remove_dir(system, path, remove=removed.append)
    assert removed == ["/lib/modules/6.8.0-30-generic"]


def plan() -> Plan:
    return Plan(
        kernels=(Package("linux-image-6.8.0-40-generic", "ii", "1", 15000),),
        modules=(Package("linux-modules-6.8.0-40-generic", "ii", "1", 90000),),
        dirs=("/lib/modules/6.8.0-40-generic",),
        residual=(Package("hello", "rc", "1", 0),),
    )


def test_execute_order_and_log(tmp_path: Path, syslogged: list[tuple[int, str]]) -> None:
    system = FakeSystem(
        files={"/lib/modules/6.8.0-40-generic/updates/dkms/zfs.ko": "", "/etc/hello/hello.conf": "x"},
        commands={(*CONFFILES_HEAD, "hello"): " /etc/hello/hello.conf 1\n",
                  (*OWNER_QUERY, "/lib/modules/6.8.0-40-generic"): ""},
    )  # fmt: skip
    purging = "Removing linux-image-6.8.0-40-generic ...\nPurging configuration files ...\n"
    runner = FakeRunner({(*APT_PURGE, "linux-image-6.8.0-40-generic"): purging})
    removed: list[str] = []
    log = Log(str(tmp_path / "cleanup.log"), run_id="r1")
    code = execute(
        plan(), runner, system, log, NOW, backup_dir=str(tmp_path), remove=removed.append
    )
    log.close()
    assert code == 0
    assert runner.calls == [
        (*APT_PURGE, "linux-image-6.8.0-40-generic"),
        (*APT_PURGE, "linux-modules-6.8.0-40-generic"),
        (*APT_PURGE, "hello"),
    ]
    assert removed == ["/lib/modules/6.8.0-40-generic"]
    text = (tmp_path / "cleanup.log").read_text()
    assert "rc-20261103T150405Z.tar.gz" in text and "[r1]" in text
    assert text.index("purge kernels") < text.index("purge modules") < text.index("purge residual")
    assert "removed /lib/modules/6.8.0-40-generic" in text and text.rstrip().endswith("done")
    assert "]   Purging configuration files ..." in text
    assert [t for _, t in syslogged] == [line.split("] ", 1)[1] for line in text.splitlines()]


def test_a_directory_still_owned_after_the_purges_stays(
    tmp_path: Path, syslogged: list[tuple[int, str]]
) -> None:
    system = FakeSystem(
        files={"/lib/modules/6.8.0-40-generic/x.ko": ""},
        commands={
            (
                *OWNER_QUERY,
                "/lib/modules/6.8.0-40-generic",
            ): "linux-foo: /lib/modules/6.8.0-40-generic/x.ko\n"
        },
    )
    only_dir = Plan(dirs=("/lib/modules/6.8.0-40-generic",))
    removed: list[str] = []
    log = Log(str(tmp_path / "cleanup.log"), run_id="r2")
    assert (
        execute(
            only_dir,
            FakeRunner(),
            system,
            log,
            NOW,
            backup_dir=str(tmp_path),
            remove=removed.append,
        )
        == 0
    )
    assert removed == []
    assert (
        "kept /lib/modules/6.8.0-40-generic: still has files of linux-foo"
        in (tmp_path / "cleanup.log").read_text()
    )


def test_failure_stops_and_reports(tmp_path: Path, syslogged: list[tuple[int, str]]) -> None:
    failing = (*APT_PURGE, "linux-modules-6.8.0-40-generic")
    runner = FakeRunner(
        {
            failing: CommandResult(
                failing, 100, "", "E: Sub-process /usr/bin/dpkg returned an error code (1)\n"
            )
        }
    )
    system = FakeSystem(commands={(*CONFFILES_HEAD, "hello"): ""})
    removed: list[str] = []
    log = Log(str(tmp_path / "cleanup.log"), run_id="r3")
    code = execute(
        plan(), runner, system, log, NOW, backup_dir=str(tmp_path), remove=removed.append
    )
    assert code == 2
    assert runner.calls[-1] == failing and removed == []
    text = (tmp_path / "cleanup.log").read_text()
    assert "failed (exit 100): E: Sub-process /usr/bin/dpkg returned an error code (1)" in text
    assert "not done: purge residual (hello); remove /lib/modules/6.8.0-40-generic" in text
    assert any(level == syslog.LOG_ERR for level, _ in syslogged)


def test_log_goes_to_file_and_syslog(tmp_path: Path, syslogged: list[tuple[int, str]]) -> None:
    log = Log(str(tmp_path / "cleanup.log"), run_id="r4", now=lambda: NOW)
    log.line("two\nlines")
    log.close()
    assert oct((tmp_path / "cleanup.log").stat().st_mode & 0o777) == "0o640"
    assert (tmp_path / "cleanup.log").read_text() == (
        "2026-11-03T15:04:05Z [r4] two\n2026-11-03T15:04:05Z [r4] lines\n"
    )
    assert syslogged == [(syslog.LOG_INFO, "two"), (syslog.LOG_INFO, "lines")]


def test_log_without_its_file_still_goes_to_syslog(
    tmp_path: Path, syslogged: list[tuple[int, str]]
) -> None:
    log = Log(str(tmp_path / "missing-dir" / "cleanup.log"), run_id="r5")
    assert log.file_error is not None
    log.line("planned")
    log.close()
    assert syslogged == [(syslog.LOG_INFO, "planned")]


def test_log_never_follows_a_symlink(tmp_path: Path, syslogged: list[tuple[int, str]]) -> None:
    (tmp_path / "target").write_text("")
    (tmp_path / "cleanup.log").symlink_to(tmp_path / "target")
    log = Log(str(tmp_path / "cleanup.log"), run_id="r6")
    log.line("x")
    log.close()
    assert log.file_error is not None and (tmp_path / "target").read_text() == ""


def test_timeouts_and_failed_removals_stop_too(
    tmp_path: Path, syslogged: list[tuple[int, str]]
) -> None:
    purge = (*APT_PURGE, "linux-image-6.8.0-40-generic")
    slow = FakeRunner({purge: CommandResult(purge, -1, "", "", timed_out=True)})
    log = Log(str(tmp_path / "cleanup.log"), run_id="r7")
    kernels_only = Plan(kernels=(Package("linux-image-6.8.0-40-generic", "ii", "1", 1),))
    assert execute(kernels_only, slow, FakeSystem(), log, NOW, backup_dir=str(tmp_path)) == 2
    system = FakeSystem(
        files={"/lib/modules/6.8.0-40-generic/x.ko": ""},
        commands={(*OWNER_QUERY, "/lib/modules/6.8.0-40-generic"): ""},
    )

    def denied(path: str) -> None:
        raise PermissionError(13, "Permission denied", path)

    only_dir = Plan(dirs=("/lib/modules/6.8.0-40-generic",))
    assert (
        execute(only_dir, FakeRunner(), system, log, NOW, backup_dir=str(tmp_path), remove=denied)
        == 2
    )
    log.close()
    text = (tmp_path / "cleanup.log").read_text()
    assert "failed (timed out)" in text and "failed: [Errno 13] Permission denied" in text


def test_a_directory_the_purge_already_removed_is_fine(
    tmp_path: Path, syslogged: list[tuple[int, str]]
) -> None:
    # dpkg removes a package's directories once they're empty: nothing left to remove.
    only_dir = Plan(dirs=("/usr/src/linux-headers-6.8.0-10-generic",))
    removed: list[str] = []
    log = Log(str(tmp_path / "cleanup.log"), run_id="r8")
    assert (
        execute(
            only_dir,
            FakeRunner(),
            FakeSystem(),
            log,
            NOW,
            backup_dir=str(tmp_path),
            remove=removed.append,
        )
        == 0
    )
    log.close()
    assert removed == []
    assert (
        "already gone: /usr/src/linux-headers-6.8.0-10-generic"
        in (tmp_path / "cleanup.log").read_text()
    )
