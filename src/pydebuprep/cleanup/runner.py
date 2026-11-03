"""The cleanup's command runner: the only part of pydebuprep that runs commands which
change the system. Its allowlist is its own and exact; pydebuprep report never uses it.
"""

from __future__ import annotations

import errno
import fcntl
import os
import re
import subprocess  # nosec B404 # this module exists to run the purges, from an exact allowlist
from collections.abc import Iterable, Sequence
from types import TracebackType

from pydebuprep.cleanup.plan import Refused
from pydebuprep.system import (
    CLIENT_ENV,
    CommandResult,
    DisallowedCommandError,
    System,
)

APT_SIMULATE = ("apt-get", "-s", "purge")
APT_PURGE = ("apt-get", "purge", "-y")
DPKG_AUDIT = ("dpkg", "--audit")
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]+(?::[a-z0-9]+)?")  # with a multiarch suffix
LOCK_PATH = "/run/pydebuprep-cleanup.lock"
DPKG_LOCK = "/var/lib/dpkg/lock-frontend"
SIMULATED = re.compile(r"^(?:Purg|Remv|Inst) (\S+)", re.M)


def _allowed(argv: tuple[str, ...]) -> bool:
    if argv == DPKG_AUDIT:
        return True
    for head in (APT_SIMULATE, APT_PURGE):
        names = argv[len(head) :]
        if argv[: len(head)] == head and names:
            return all(PACKAGE_NAME.fullmatch(n) for n in names)
    return False


def check_cleanup_allowed(argv: Sequence[str]) -> None:
    if not _allowed(tuple(argv)):
        raise DisallowedCommandError(
            f"command not on the cleanup's allowlist: {' '.join(argv) or '(empty)'}"
        )


def _decode(data: bytes | None) -> str:
    return (data or b"").decode("utf-8", "replace")


class Runner:
    def run(self, argv: Sequence[str], timeout: float | None = None) -> CommandResult:
        """Run ARGV and wait for it. A purge has no timeout and runs in a session of its
        own: Ctrl-C at the terminal doesn't reach apt and dpkg, and if this process is
        interrupted it waits for them to finish rather than killing them halfway."""
        check_cleanup_allowed(argv)
        args = tuple(argv)
        env = {k: v for k, v in os.environ.items() if not k.startswith(CLIENT_ENV)}
        env.update(LC_ALL="C", LANG="C", DEBIAN_FRONTEND="noninteractive")
        try:
            # Fixed, allowlisted argv; never a shell.
            proc = subprocess.Popen(  # nosec B603 # argv checked against the exact allowlist above
                args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=env, start_new_session=True,
            )  # fmt: skip
        except OSError as exc:
            return CommandResult(args, 127, "", str(exc))
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:  # only the read-only queries have a timeout
            proc.kill()
            out, err = proc.communicate()
            return CommandResult(args, -1, _decode(out), _decode(err), True)
        except KeyboardInterrupt:
            proc.communicate()  # let apt and dpkg finish what they started
            raise
        return CommandResult(args, proc.returncode, _decode(out), _decode(err))


def _dpkg_locked(path: str) -> bool:
    """Whether apt or dpkg holds dpkg's frontend lock. The file is opened as it is (never
    created) and the lock, if we get it, is released at once."""
    try:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return False
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        return exc.errno in (errno.EACCES, errno.EAGAIN)
    else:
        fcntl.lockf(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def preflight(system: System, runner: Runner, *, dpkg_lock: str = DPKG_LOCK) -> list[str]:
    """Reasons not to act now; empty when it's safe to go on."""
    if not system.is_root():
        return ["pydebuprep-cleanup must be run as root"]
    if _dpkg_locked(dpkg_lock):
        return ["apt or dpkg is running (its lock is held); try again when it's done"]
    res = runner.run(DPKG_AUDIT, timeout=60)
    if res.returncode != 0 or res.timed_out:
        detail = (res.stderr or "timed out").strip().splitlines()
        return [f"dpkg --audit couldn't run: {detail[0] if detail else res.returncode}"]
    audit = res.stdout.strip()
    if audit:
        return [f"dpkg --audit reports problems: {audit.splitlines()[0]} (fix them first)"]
    return []


def simulate(runner: Runner, packages: Sequence[str]) -> set[str]:
    """Every package apt would purge, remove or install for PACKAGES, without doing it."""
    res = runner.run((*APT_SIMULATE, *sorted(packages)), timeout=300)
    if res.returncode != 0 or res.timed_out:
        detail = (res.stderr or res.stdout).strip().splitlines()
        raise Refused(f"apt-get can't plan this: {detail[-1] if detail else 'it failed'}")
    return set(SIMULATED.findall(res.stdout))


def beyond_plan(planned: Iterable[str], touched: set[str], arch: str) -> set[str]:
    """What apt would touch beyond PLANNED. apt leaves the native architecture out of
    package names (libc6, but libc6:i386); dpkg's binary names may carry it."""

    def plain(name: str) -> str:
        return name.removesuffix(f":{arch}") if arch else name

    return {plain(t) for t in touched} - {plain(p) for p in planned}


class Lock:
    """One cleanup at a time: an exclusive lock on the cleanup's own lock file."""

    def __init__(self, path: str = LOCK_PATH) -> None:
        self.path = path
        self.fd: int | None = None

    def __enter__(self) -> Lock:
        try:
            self.fd = os.open(
                self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
            )
        except OSError as exc:
            raise Refused(f"can't open the lock {self.path}: {exc.strerror or exc}") from None
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            raise Refused("another pydebuprep-cleanup is already running") from None
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
