"""The cleanup's command runner: the only part of pydebuprep that runs commands which
change the system. Its allowlist is its own and exact; pydebuprep report never uses it.
"""

from __future__ import annotations

import errno
import fcntl
import os
import re
import subprocess  # nosec B404 # this module exists to run the purges, from an exact allowlist
from collections.abc import Sequence
from types import TracebackType

from pydebuprep.cleanup.plan import Plan, Refused
from pydebuprep.system import (
    CLIENT_ENV,
    CommandResult,
    DisallowedCommandError,
    System,
)

APT_SIMULATE = ("apt-get", "-s", "purge")
APT_PURGE = ("apt-get", "purge", "-y")
DPKG_AUDIT = ("dpkg", "--audit")
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]+")
PURGE_TIMEOUT = 1800.0  # a kernel's initramfs and GRUB updates take a while
LOCK_PATH = "/run/pydebuprep-cleanup.lock"
DPKG_LOCK = "/var/lib/dpkg/lock-frontend"
SIMULATED = re.compile(r"^(Purg|Remv) (\S+)", re.M)


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
    def run(self, argv: Sequence[str], timeout: float = PURGE_TIMEOUT) -> CommandResult:
        check_cleanup_allowed(argv)
        args = tuple(argv)
        env = {k: v for k, v in os.environ.items() if not k.startswith(CLIENT_ENV)}
        env.update(LC_ALL="C", LANG="C", DEBIAN_FRONTEND="noninteractive")
        try:
            # Fixed, allowlisted argv; never a shell.
            proc = subprocess.run(  # nosec B603 # argv checked against the exact allowlist above
                args, capture_output=True, timeout=timeout, env=env, check=False,
                stdin=subprocess.DEVNULL,
            )  # fmt: skip
        except subprocess.TimeoutExpired as exc:
            return CommandResult(args, -1, _decode(exc.stdout), _decode(exc.stderr), True)
        except OSError as exc:
            return CommandResult(args, 127, "", str(exc))
        return CommandResult(args, proc.returncode, _decode(proc.stdout), _decode(proc.stderr))


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
    audit = runner.run(DPKG_AUDIT, timeout=60).stdout.strip()
    if audit:
        return [f"dpkg --audit reports problems: {audit.splitlines()[0]} (fix them first)"]
    return []


def simulate(runner: Runner, packages: Sequence[str]) -> tuple[set[str], set[str]]:
    """What apt would purge and remove for PACKAGES, without doing it."""
    res = runner.run((*APT_SIMULATE, *sorted(packages)), timeout=300)
    if res.returncode != 0 or res.timed_out:
        detail = (res.stderr or res.stdout).strip().splitlines()
        raise Refused(f"apt-get can't plan this: {detail[-1] if detail else 'it failed'}")
    purged: set[str] = set()
    removed: set[str] = set()
    for action, name in SIMULATED.findall(res.stdout):
        (purged if action == "Purg" else removed).add(name)
    return purged, removed


def extra(plan: Plan, purged: set[str], removed: set[str]) -> set[str]:
    """What apt would purge or remove beyond the plan (a dependency, a meta package)."""
    return (purged | removed) - set(plan.packages)


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
