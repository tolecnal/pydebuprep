"""Acting on a plan: backups, purges, directories, and a log of every step."""

from __future__ import annotations

import syslog
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cleanup.test_plan import owner_query
from fakes import FakeRunner, FakeSystem
from pydebuprep.cleanup.act import CONFFILES_HEAD, backup_conffiles, execute, remove_dir
from pydebuprep.cleanup.kernels import Package
from pydebuprep.cleanup.log import Log
from pydebuprep.cleanup.plan import Plan, Refused
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
                  owner_query("/lib/modules/6.8.0-40-generic"): ""},
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
    from pydebuprep.cleanup.runner import APT_SIMULATE

    assert runner.calls == [  # each purge simulated again right before it
        (*APT_SIMULATE, "linux-image-6.8.0-40-generic"),
        (*APT_PURGE, "linux-image-6.8.0-40-generic"),
        (*APT_SIMULATE, "linux-modules-6.8.0-40-generic"),
        (*APT_PURGE, "linux-modules-6.8.0-40-generic"),
        (*APT_SIMULATE, "hello"),
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
            owner_query("/lib/modules/6.8.0-40-generic"): (
                "linux-foo: /lib/modules/6.8.0-40-generic/x.ko\n"
            )
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
        commands={owner_query("/lib/modules/6.8.0-40-generic"): ""},
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


def test_each_purge_is_simulated_again_right_before_it_runs(
    tmp_path: Path, syslogged: list[tuple[int, str]]
) -> None:
    # Between the plan and the purge (a long confirmation, unattended-upgrades), apt may
    # have come to want more: the purge is simulated again, and stops if so.
    from pydebuprep.cleanup.runner import APT_SIMULATE

    images = Plan(kernels=(Package("linux-image-6.8.0-40-generic", "ii", "1", 1),), arch="amd64")
    simulate_now = (*APT_SIMULATE, "linux-image-6.8.0-40-generic")
    widened = FakeRunner(
        {simulate_now: "Purg linux-image-6.8.0-40-generic [1]\nRemv linux-generic [1]\n"}
    )
    log = Log(str(tmp_path / "cleanup.log"), run_id="r9")
    assert execute(images, widened, FakeSystem(), log, NOW, backup_dir=str(tmp_path)) == 2
    log.close()
    assert widened.calls == [simulate_now]  # never purged
    assert "apt would now also change: linux-generic" in (tmp_path / "cleanup.log").read_text()


def test_interrupted_run_is_logged_and_exits_2(
    tmp_path: Path, syslogged: list[tuple[int, str]]
) -> None:
    class Interrupted(FakeRunner):
        def run(self, argv, timeout=None):  # type: ignore[no-untyped-def,override] # a fake runner
            if argv[:3] == APT_PURGE:
                raise KeyboardInterrupt
            return super().run(argv)

    log = Log(str(tmp_path / "cleanup.log"), run_id="r10")
    assert execute(plan(), Interrupted(), FakeSystem(commands={(*CONFFILES_HEAD, "hello"): ""}), log, NOW,
                   backup_dir=str(tmp_path)) == 2  # fmt: skip
    log.close()
    text = (tmp_path / "cleanup.log").read_text()
    assert "interrupted" in text and "not done: purge modules" in text


def test_failed_re_simulation_stops(tmp_path: Path, syslogged: list[tuple[int, str]]) -> None:
    from pydebuprep.cleanup.runner import APT_SIMULATE

    sim = (*APT_SIMULATE, "linux-image-6.8.0-40-generic")
    broken = FakeRunner({sim: CommandResult(sim, 100, "", "E: dpkg was interrupted\n")})
    images = Plan(kernels=(Package("linux-image-6.8.0-40-generic", "ii", "1", 1),))
    log = Log(str(tmp_path / "cleanup.log"), run_id="r11")
    assert execute(images, broken, FakeSystem(), log, NOW, backup_dir=str(tmp_path)) == 2
    log.close()
    assert (
        "failed: apt-get can't plan this: E: dpkg was interrupted"
        in (tmp_path / "cleanup.log").read_text()
    )


def test_many_rc_packages_are_backed_up_in_chunks(tmp_path: Path) -> None:
    names = [f"pkg{i}" for i in range(450)]
    commands = {
        (*CONFFILES_HEAD, *names[i : i + 200]): "".join(
            f" /etc/{n}.conf x\n" for n in names[i : i + 200]
        )
        for i in range(0, 450, 200)
    }
    system = FakeSystem(files={f"/etc/{n}.conf": n for n in names}, commands=commands)
    path = backup_conffiles(system, names, NOW, backup_dir=str(tmp_path))
    assert path is not None
    with tarfile.open(path) as tar:
        assert len(tar.getmembers()) == 450


def test_unreadable_conffiles_and_a_failed_backup_are_logged(
    tmp_path: Path, syslogged: list[tuple[int, str]]
) -> None:
    # A config file that can't be read (too big, a FIFO) isn't backed up: said so, by name.
    system = FakeSystem(commands={(*CONFFILES_HEAD, "hello"): " /etc/hello/big.conf x\n /etc/hello/a.conf y\n"},
                        files={"/etc/hello/a.conf": "a", "/etc/hello/big.conf": "b"})  # fmt: skip
    system.unreadable = {"/etc/hello/big.conf"}  # type: ignore[attr-defined] # see FakeSystem.read_bytes
    residual = Plan(residual=(Package("hello", "rc", "1", 0),))
    log = Log(str(tmp_path / "cleanup.log"), run_id="r12")
    assert execute(residual, FakeRunner(), system, log, NOW, backup_dir=str(tmp_path)) == 0
    # The backup directory missing: the purge doesn't go ahead without its backup.
    assert (
        execute(residual, FakeRunner(), system, log, NOW, backup_dir=str(tmp_path / "missing")) == 2
    )
    log.close()
    text = (tmp_path / "cleanup.log").read_text()
    assert "not backed up (can't be read): /etc/hello/big.conf" in text
    assert "failed: can't write the backup" in text and "not done: purge residual (hello)" in text


def test_conffile_paths_with_spaces(tmp_path: Path) -> None:
    listed = (" /etc/odd dir/my file.conf 1234abcd\n /etc/odd dir/old.conf 5678 obsolete\n"
              " /etc/odd dir/gone.conf 9abc remove-on-upgrade\n")  # fmt: skip
    system = FakeSystem(
        files={
            "/etc/odd dir/my file.conf": "a",
            "/etc/odd dir/old.conf": "b",
            "/etc/odd dir/gone.conf": "c",
        },
        commands={(*CONFFILES_HEAD, "odd"): listed},
    )
    path = backup_conffiles(system, ["odd"], NOW, backup_dir=str(tmp_path))
    assert path is not None
    with tarfile.open(path) as tar:
        assert sorted(tar.getnames()) == [
            "etc/odd dir/gone.conf",
            "etc/odd dir/my file.conf",
            "etc/odd dir/old.conf",
        ]


def test_every_output_line_and_exit_status_are_logged(
    tmp_path: Path, syslogged: list[tuple[int, str]]
) -> None:
    output = "".join(f"line {n}\n" for n in range(30))
    purge = (*APT_PURGE, "linux-image-6.8.0-40-generic")
    runner = FakeRunner({purge: output})
    kernels_only = Plan(kernels=(Package("linux-image-6.8.0-40-generic", "ii", "1", 1),))
    log = Log(str(tmp_path / "cleanup.log"), run_id="r13")
    assert execute(kernels_only, runner, FakeSystem(), log, NOW, backup_dir=str(tmp_path)) == 0
    log.close()
    text = (tmp_path / "cleanup.log").read_text()
    assert "]   line 0" in text and "]   line 29" in text
    assert "apt-get purge -y linux-image-6.8.0-40-generic: exit 0" in text
