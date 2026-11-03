"""The cleanup's runner: its allowlist, the checks before acting, and the simulation."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
from typing import ClassVar

import pytest

from fakes import FakeRunner, FakeSystem
from pydebuprep.cleanup.plan import Refused
from pydebuprep.cleanup.runner import (
    APT_PURGE,
    APT_SIMULATE,
    DPKG_AUDIT,
    Lock,
    Runner,
    beyond_plan,
    check_cleanup_allowed,
    preflight,
    simulate,
)
from pydebuprep.system import CommandResult, DisallowedCommandError


@pytest.mark.parametrize(
    "argv",
    [
        ("apt-get", "install", "-y", "hello"),
        ("apt-get", "purge", "hello"),  # without -y
        (*APT_PURGE, "-o", "x"),  # an option smuggled in as a package
        (*APT_PURGE,),  # nothing to purge
        (*APT_SIMULATE, "Hello"),
        ("rm", "-rf", "/lib/modules/x"),
        ("dpkg", "--purge", "hello"),
    ],
)
def test_runner_refuses_anything_else(argv: tuple[str, ...]) -> None:
    with pytest.raises(DisallowedCommandError):
        check_cleanup_allowed(argv)


def test_runner_allows_exactly_its_commands() -> None:
    check_cleanup_allowed(DPKG_AUDIT)
    check_cleanup_allowed((*APT_SIMULATE, "linux-image-6.8.0-40-generic", "hello"))
    check_cleanup_allowed((*APT_PURGE, "libfoo1.2+git", "g++-12"))


class FakePopen:
    """Stands in for subprocess.Popen: records how it was started, answers communicate()."""

    started: ClassVar[list[dict[str, object]]] = []

    def __init__(self, args, **kw):  # type: ignore[no-untyped-def] # mirrors Popen
        self.args, self.kw, self.returncode, self.calls = args, kw, 0, 0
        self.killed = False
        FakePopen.started.append({"args": args, **kw})

    def communicate(self, timeout=None):  # type: ignore[no-untyped-def] # mirrors Popen
        self.calls += 1
        return self.answer(timeout)

    def answer(self, timeout):  # type: ignore[no-untyped-def] # overridden per test
        return b"ok", b""

    def kill(self) -> None:
        self.killed = True


def test_runner_env_session_and_no_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    FakePopen.started.clear()
    monkeypatch.setenv("APT_CONFIG", "/tmp/evil.conf")
    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    res = Runner().run((*APT_PURGE, "hello"))
    assert (res.returncode, res.stdout) == (0, "ok")
    [seen] = FakePopen.started
    env = seen["env"]
    assert (
        isinstance(env, dict)
        and env["LC_ALL"] == "C"
        and env["DEBIAN_FRONTEND"] == "noninteractive"
    )
    assert "APT_CONFIG" not in env and seen["args"] == (*APT_PURGE, "hello")
    assert seen["start_new_session"] is True and seen["stdin"] == subprocess.DEVNULL


def test_runner_timeouts_and_missing_programs(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    class Slow(FakePopen):
        def answer(self, timeout):  # type: ignore[no-untyped-def] # a query that hangs
            if self.calls == 1:
                raise subprocess.TimeoutExpired(self.args, timeout)
            return b"partial", b""

    def missing(args, **kw):  # type: ignore[no-untyped-def] # no such program
        raise FileNotFoundError("apt-get")

    monkeypatch.setattr(subprocess, "Popen", Slow)
    res = Runner().run(DPKG_AUDIT, timeout=1)
    assert res.timed_out and res.stdout == "partial"
    monkeypatch.setattr(subprocess, "Popen", missing)
    assert Runner().run(DPKG_AUDIT).returncode == 127


def test_interrupted_runner_waits_for_apt(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    made: list[FakePopen] = []

    class Interrupted(FakePopen):
        def __init__(self, args, **kw):  # type: ignore[no-untyped-def] # mirrors Popen
            super().__init__(args, **kw)
            made.append(self)

        def answer(self, timeout):  # type: ignore[no-untyped-def] # Ctrl-C while waiting
            if self.calls == 1:
                raise KeyboardInterrupt
            return b"", b""

    monkeypatch.setattr(subprocess, "Popen", Interrupted)
    with pytest.raises(KeyboardInterrupt):
        Runner().run((*APT_PURGE, "hello"))
    [proc] = made
    assert proc.calls == 2 and not proc.killed  # waited for apt, never killed it


def test_preflight_reasons(tmp_path: Path) -> None:
    lock = tmp_path / "lock-frontend"
    ok = preflight(FakeSystem(root=True), FakeRunner(), dpkg_lock=str(lock))
    assert ok == []
    assert preflight(FakeSystem(root=False), FakeRunner(), dpkg_lock=str(lock)) == [
        "pydebuprep-cleanup must be run as root"
    ]
    broken = FakeRunner({DPKG_AUDIT: "The following packages are only half configured:\n x\n"})
    [reason] = preflight(FakeSystem(root=True), broken, dpkg_lock=str(lock))
    assert reason.startswith("dpkg --audit reports problems: The following packages")
    lock.write_text("")
    fd = os.open(lock, os.O_RDWR)
    pid = os.fork()
    if pid == 0:  # another process holds dpkg's lock, as apt does
        fcntl.lockf(fd, fcntl.LOCK_EX)
        os.write(os.open(tmp_path / "held", os.O_WRONLY | os.O_CREAT), b"1")
        import time

        time.sleep(5)
        os._exit(0)
    try:
        while not (tmp_path / "held").exists():
            pass
        [reason] = preflight(FakeSystem(root=True), FakeRunner(), dpkg_lock=str(lock))
        assert reason == "apt or dpkg is running (its lock is held); try again when it's done"
    finally:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        os.close(fd)


SIMULATION = """\
NOTE: This is only a Simulation!
Reading package lists...
Purg linux-image-6.8.0-40-generic [6.8.0-40.40]
Purg hello [2.10-3]
Remv linux-generic [6.8.0-49.49]
Conf something [1.0]
"""


def test_simulation_lists_what_apt_would_touch() -> None:
    runner = FakeRunner(
        {
            (*APT_SIMULATE, "hello", "linux-image-6.8.0-40-generic"): SIMULATION
            + "Inst new-dep [1]\n"
        }
    )
    touched = simulate(runner, ["hello", "linux-image-6.8.0-40-generic"])
    assert touched == {"linux-image-6.8.0-40-generic", "hello", "linux-generic", "new-dep"}


def test_failed_simulation_refuses() -> None:
    args = (*APT_SIMULATE, "hello")
    runner = FakeRunner({args: CommandResult(args, 100, "", "E: Unable to locate package hello")})
    with pytest.raises(Refused, match="Unable to locate package hello"):
        simulate(runner, ["hello"])


def test_widened_plan_is_refused() -> None:
    planned = ["linux-image-6.8.0-40-generic", "hello"]
    assert beyond_plan(planned, {"linux-image-6.8.0-40-generic", "hello"}, "amd64") == set()
    widened = {"linux-image-6.8.0-40-generic", "hello", "linux-generic"}
    assert beyond_plan(planned, widened, "amd64") == {"linux-generic"}


def test_beyond_plan_with_architectures() -> None:
    # apt names native packages without their architecture, foreign ones with it.
    planned = ["libfoo1:amd64", "libbar1:i386"]
    assert beyond_plan(planned, {"libfoo1", "libbar1:i386"}, "amd64") == set()
    assert beyond_plan(planned, {"libfoo1", "libbar1"}, "amd64") == {
        "libbar1"
    }  # native libbar1 isn't planned


def test_lock_excludes_a_second_run(tmp_path: Path) -> None:
    path = str(tmp_path / "cleanup.lock")
    with Lock(path):
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"
        with pytest.raises(Refused, match="already running"), Lock(path):
            pass
    with Lock(path):  # released again
        pass


def test_lock_never_follows_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_text("keep")
    (tmp_path / "cleanup.lock").symlink_to(target)
    with pytest.raises(Refused, match="lock"), Lock(str(tmp_path / "cleanup.lock")):
        pass
    assert target.read_text() == "keep"


def test_free_dpkg_lock_and_an_unused_lock(tmp_path: Path) -> None:
    lock = tmp_path / "lock-frontend"
    lock.write_text("")
    assert preflight(FakeSystem(root=True), FakeRunner(), dpkg_lock=str(lock)) == []
    Lock(str(tmp_path / "never")).__exit__(None, None, None)  # left without being taken


def test_dpkg_audit_that_cant_run_refuses(tmp_path: Path) -> None:
    lock = str(tmp_path / "lock-frontend")
    for result in (CommandResult(DPKG_AUDIT, 127, "", "dpkg: not found"),
                   CommandResult(DPKG_AUDIT, -1, "", "", timed_out=True)):  # fmt: skip
        [reason] = preflight(
            FakeSystem(root=True), FakeRunner({DPKG_AUDIT: result}), dpkg_lock=lock
        )
        assert reason.startswith("dpkg --audit couldn't run")
