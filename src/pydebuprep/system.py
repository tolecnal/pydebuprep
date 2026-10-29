"""The only module that runs commands or reads system state.

Every command must match a read-only allowlist entry; nothing here writes.
"""

from __future__ import annotations

import ctypes
import glob as _glob
import os
import re
import shutil
import socket

# The only module that starts processes; every argv is checked against ALLOWED_COMMANDS.
import subprocess  # nosec B404
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

# Stop apt from taking locks or regenerating its binary caches (which it does
# even for read-only queries when run as root), and from writing its solver log
# (/var/log/apt/eipp.log.xz), which `apt-get -s autoremove` replaces whenever there is
# something to remove.
APT_RO_OPTS: tuple[str, ...] = (
    "-o",
    "Debug::NoLocking=1",
    "-o",
    "Dir::Cache::pkgcache=",
    "-o",
    "Dir::Cache::srcpkgcache=",
    "-o",
    "Dir::Log::Planner=",
)

APT_PROGRAMS = ("apt", "apt-get", "apt-cache", "apt-mark")

_DF_EXCLUDE = ("-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay", "-x", "efivarfs")
_UNITS = ("--no-legend", "--plain", "--no-pager")

# Every command pydebuprep may run, matched against the WHOLE argv: any extra argument,
# however harmless it looks, is rejected. apt commands must carry APT_RO_OPTS right after
# the program name; they are written here without them.
ALLOWED_COMMANDS: set[tuple[str, ...]] = {
    ("dpkg", "--audit"),
    ("dpkg-query", "-W", "-f=${db:Status-Abbrev} ${Package}\n"),
    ("dpkg-query", "-W", "-f=${Package}\t${Version}\n"),
    ("apt-get", "check"),
    ("apt-get", "-s", "autoremove"),
    ("apt", "list", "--upgradable"),
    ("apt", "list", "--installed"),
    ("apt-mark", "showhold"),
    ("debsums", "-c"),
    ("uname", "-r"),
    ("needrestart", "-b", "-r", "l"),
    ("dkms", "status"),
    ("efibootmgr", "-v"),
    ("systemctl", "list-units", "--state=failed", *_UNITS),
    ("systemctl", "list-units", "--type=service", "--state=active", *_UNITS),
    ("systemctl", "list-units", "--type=timer", "--all", *_UNITS),
    (
        "systemctl",
        "list-unit-files",
        "--type=service",
        "--state=enabled",
        "--no-legend",
        "--no-pager",
    ),
    ("systemd-analyze",),
    ("systemd-analyze", "blame", "--no-pager"),
    ("systemd-analyze", "critical-chain", "--no-pager"),
    ("ip", "-j", "addr", "show"),
    ("ip", "-j", "route", "show", "default"),
    ("ip", "-j", "-6", "route", "show", "default"),
    ("resolvectl", "dns"),
    # Only run when the matching kernel module is already loaded: listing rules can
    # otherwise make the kernel load it. (`ufw status` is not used: it writes a lock file.)
    ("nft", "-j", "list", "ruleset"),
    ("iptables-legacy-save",),
    ("journalctl", "-b", "-k", "--no-pager", "-o", "cat", '--grep=apparmor="DENIED"'),
    ("apt-config", "dump"),
    ("sshd", "-t"),
    ("pg_lsclusters", "--no-header"),
    ("mariadbd", "--version"),
    ("postconf", "-n"),
    ("named-checkconf",),
    # Only when docker.service is already running: with just docker.socket active, a
    # client command would start the daemon.
    ("docker", "ps", "--all", "--no-trunc", "--format", "{{json .}}"),
    ("journalctl", "-p", "err", "-b", "--no-pager", "-o", "json"),
    ("dmesg", "--level=err", "--notime"),
    ("dmesg", "--level=warn", "--notime"),
    ("findmnt", "--verify"),
    ("findmnt", "-rn", "-o", "TARGET,SOURCE,FSTYPE"),
    ("df", "-P", "-T", "-l", *_DF_EXCLUDE),
    ("df", "-P", "-i", "-l", *_DF_EXCLUDE),
    ("df", "-P", "-T", *_DF_EXCLUDE),
    ("df", "-P", "-i", *_DF_EXCLUDE),
}

# Commands taking exactly one trailing operand, which must be a plain unit name.
UNIT_QUERIES: set[tuple[str, ...]] = {
    ("systemctl", "show", "-p", "UnitFileState", "-p", "ConditionResult"),
}
UNIT_NAME = re.compile(r"^[A-Za-z0-9@_.:\\-]+$")

DEFAULT_TIMEOUT = 30.0
TIME_ERROR = 5  # adjtimex(): the clock is not synchronised


class DisallowedCommandError(Exception):
    pass


def _strip_apt_opts(argv: Sequence[str]) -> tuple[str, ...]:
    argv = tuple(argv)
    n = len(APT_RO_OPTS)
    if argv and argv[0] in APT_PROGRAMS and argv[1 : 1 + n] == APT_RO_OPTS:
        return (argv[0], *argv[1 + n :])
    return argv


def _is_allowed(argv: tuple[str, ...]) -> bool:
    if argv and argv[0] in APT_PROGRAMS:
        n = len(APT_RO_OPTS)
        if argv[1 : 1 + n] != APT_RO_OPTS:
            return False
        argv = (argv[0], *argv[1 + n :])
    if argv in ALLOWED_COMMANDS:
        return True
    head, operand = argv[:-1], argv[-1] if argv else ""
    return head in UNIT_QUERIES and not operand.startswith("-") and bool(UNIT_NAME.match(operand))


def check_allowed(argv: Sequence[str]) -> None:
    if not _is_allowed(tuple(argv)):
        raise DisallowedCommandError(
            f"command not on the read-only allowlist: {' '.join(argv) or '(empty)'}"
        )


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
            # Fixed, allowlisted argv; never a shell.
            proc = subprocess.run(  # nosec B603
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

    def clock_synchronized(self) -> bool | None:
        """The kernel's NTP state, as timedatectl's NTPSynchronized reports it.

        adjtimex() with modes=0 only reads; it changes nothing. None if unavailable.
        """
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            # Zeroed and larger than struct timex, so modes=0 and the kernel's reply fits.
            state = int(libc.adjtimex(ctypes.create_string_buffer(512)))
        except (OSError, AttributeError):
            return None
        if state < 0:
            return None
        return state != TIME_ERROR

    def find_files(self, roots: Sequence[str], name: str, max_depth: int) -> list[str]:
        """Files called NAME at most MAX_DEPTH directories below each root, sorted.

        Symlinked directories aren't followed, so a tree is never searched twice.
        """
        found = []
        for root in roots:
            base = root.rstrip("/").count("/")
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                if dirpath.rstrip("/").count("/") - base >= max_depth:
                    dirnames[:] = []
                if name in filenames:
                    found.append(os.path.join(dirpath, name))
        return sorted(found)

    def python_version(self) -> str:
        """MAJOR.MINOR of the Python running pydebuprep: the system python3 when packaged."""
        return f"{sys.version_info.major}.{sys.version_info.minor}"

    def loaded_modules(self) -> set[str]:
        return {
            line.split()[0]
            for line in (self.read_text("/proc/modules") or "").splitlines()
            if line.strip()
        }


def apt_command(program: str, *args: str) -> list[str]:
    """Build an apt/apt-get/apt-cache argv that cannot lock or write caches."""
    return [program, *APT_RO_OPTS, *args]
