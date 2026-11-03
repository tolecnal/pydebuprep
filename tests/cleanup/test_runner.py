"""The cleanup's runner: its allowlist, the checks before acting, and the simulation."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path

import pytest

from fakes import FakeRunner, FakeSystem
from pydebuprep.cleanup.kernels import Package
from pydebuprep.cleanup.plan import Plan, Refused
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


def test_runner_env(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    seen = {}

    def fake_run(args, **kw):  # type: ignore[no-untyped-def] # stands in for subprocess.run
        seen.update(kw["env"], args=args)
        return subprocess.CompletedProcess(args, 0, b"ok", b"")

    monkeypatch.setenv("APT_CONFIG", "/tmp/evil.conf")
    monkeypatch.setattr(subprocess, "run", fake_run)
    res = Runner().run(DPKG_AUDIT)
    assert (res.returncode, res.stdout) == (0, "ok")
    assert seen["LC_ALL"] == "C" and seen["DEBIAN_FRONTEND"] == "noninteractive"
    assert "APT_CONFIG" not in seen and seen["args"] == DPKG_AUDIT


def test_runner_failures_are_results(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    def timeout(args, **kw):  # type: ignore[no-untyped-def] # stands in for subprocess.run
        raise subprocess.TimeoutExpired(args, 1, b"partial", b"")

    def missing(args, **kw):  # type: ignore[no-untyped-def] # stands in for subprocess.run
        raise FileNotFoundError("apt-get")

    monkeypatch.setattr(subprocess, "run", timeout)
    assert Runner().run(DPKG_AUDIT).timed_out
    monkeypatch.setattr(subprocess, "run", missing)
    assert Runner().run(DPKG_AUDIT).returncode == 127


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


def test_simulation_parses_purg_and_remv() -> None:
    runner = FakeRunner({(*APT_SIMULATE, "hello", "linux-image-6.8.0-40-generic"): SIMULATION})
    purged, removed = simulate(runner, ["hello", "linux-image-6.8.0-40-generic"])
    assert purged == {"linux-image-6.8.0-40-generic", "hello"}
    assert removed == {"linux-generic"}


def test_failed_simulation_refuses() -> None:
    args = (*APT_SIMULATE, "hello")
    runner = FakeRunner({args: CommandResult(args, 100, "", "E: Unable to locate package hello")})
    with pytest.raises(Refused, match="Unable to locate package hello"):
        simulate(runner, ["hello"])


def test_widened_plan_is_refused() -> None:
    plan = Plan(kernels=(Package("linux-image-6.8.0-40-generic", "ii", "1", 1),),
                residual=(Package("hello", "rc", "1", 0),))  # fmt: skip
    assert beyond_plan(plan, {"linux-image-6.8.0-40-generic", "hello"}, set()) == set()
    assert beyond_plan(plan, {"linux-image-6.8.0-40-generic", "hello"}, {"linux-generic"}) == {
        "linux-generic"
    }


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
