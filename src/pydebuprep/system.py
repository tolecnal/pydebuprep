"""The only module that runs commands or reads system state.

Every command must match a read-only allowlist entry; nothing here writes.
"""

from __future__ import annotations

import glob as _glob
import os
import shutil
import socket
import subprocess
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

# Stop apt from taking locks or regenerating its binary caches (which it does
# even for read-only queries when run as root).
APT_RO_OPTS: tuple[str, ...] = (
    "-o",
    "Debug::NoLocking=1",
    "-o",
    "Dir::Cache::pkgcache=",
    "-o",
    "Dir::Cache::srcpkgcache=",
)

APT_PROGRAMS = ("apt", "apt-get", "apt-cache")

ALLOWED_PREFIXES: tuple[tuple[str, ...], ...] = (
    ("dpkg", "--audit"),
    ("dpkg", "--compare-versions"),
    ("dpkg-query", "-W"),
    ("apt-get", "check"),
    ("apt-get", "-s", "autoremove"),
    ("apt", "list"),
    ("apt-cache", "policy"),
    ("apt-mark", "showhold"),
    ("debsums", "-c"),
    ("uname", "-r"),
    ("needrestart", "-b", "-r", "l"),
    ("dkms", "status"),
    ("efibootmgr", "-v"),
    ("systemctl", "list-units"),
    ("systemctl", "list-timers"),
    ("systemd-analyze",),
    ("journalctl", "-p"),
    ("dmesg", "--level=err"),
    ("dmesg", "--level=warn"),
    ("findmnt", "--verify"),
    ("findmnt", "-rn"),
    ("df", "-P"),
)

# Commands whose whole argv must match exactly, because any further argument
# could change state.
EXACT_ONLY: dict[str, tuple[tuple[str, ...], ...]] = {
    "systemd-analyze": (("systemd-analyze",), ("systemd-analyze", "blame", "--no-pager")),
}

DEFAULT_TIMEOUT = 30.0


class DisallowedCommandError(Exception):
    pass


def _strip_apt_opts(argv: Sequence[str]) -> tuple[str, ...]:
    argv = tuple(argv)
    n = len(APT_RO_OPTS)
    if argv and argv[0] in APT_PROGRAMS and argv[1 : 1 + n] == APT_RO_OPTS:
        return (argv[0], *argv[1 + n :])
    return argv


def check_allowed(argv: Sequence[str]) -> None:
    stripped = _strip_apt_opts(argv)
    if not stripped:
        raise DisallowedCommandError("empty command")
    exact = EXACT_ONLY.get(stripped[0])
    if exact is not None:
        if stripped in exact:
            return
    elif any(stripped[: len(p)] == p for p in ALLOWED_PREFIXES):
        return
    raise DisallowedCommandError(f"command not on the read-only allowlist: {' '.join(argv)}")


@dataclass
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


@dataclass
class DiskUsage:
    total: int
    free: int
    inodes_total: int
    inodes_free: int


def _decode(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    return data.decode("utf-8", errors="replace")


class System:
    """Read-only access to the running system."""

    def run(self, argv: Sequence[str], timeout: float = DEFAULT_TIMEOUT) -> CommandResult:
        check_allowed(argv)
        args = tuple(argv)
        env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                timeout=timeout,
                env=env,
                check=False,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(args, -1, _decode(exc.stdout), _decode(exc.stderr), True)
        except FileNotFoundError as exc:
            return CommandResult(args, 127, "", str(exc))
        except OSError as exc:
            return CommandResult(args, 126, "", str(exc))
        return CommandResult(args, proc.returncode, _decode(proc.stdout), _decode(proc.stderr))

    def which(self, name: str) -> bool:
        return shutil.which(name) is not None

    def read_text(self, path: str) -> str | None:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def glob(self, pattern: str) -> list[str]:
        return sorted(_glob.glob(pattern))

    def mtime(self, path: str) -> float | None:
        try:
            return os.stat(path).st_mtime
        except OSError:
            return None

    def walk_files(self, root: str, errors: list[str] | None = None) -> Iterator[str]:
        def onerror(exc: OSError) -> None:
            if errors is not None:
                errors.append(f"{exc.filename}: {exc.strerror}")

        for dirpath, dirnames, filenames in os.walk(root, onerror=onerror, followlinks=False):
            dirnames.sort()
            for name in sorted(filenames):
                yield os.path.join(dirpath, name)

    def disk_usage(self, path: str) -> DiskUsage | None:
        try:
            st = os.statvfs(path)
        except OSError:
            return None
        return DiskUsage(
            total=st.f_blocks * st.f_frsize,
            free=st.f_bavail * st.f_frsize,
            inodes_total=st.f_files,
            inodes_free=st.f_favail,
        )

    def is_root(self) -> bool:
        return os.geteuid() == 0

    def hostname(self) -> str:
        return socket.gethostname()

    def now(self) -> datetime:
        return datetime.now(timezone.utc)
