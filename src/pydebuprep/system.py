"""The only module that runs commands or reads system state.

Every command must match a read-only allowlist entry; nothing here writes.
"""

from __future__ import annotations

import ctypes
import glob as _glob
import gzip
import http.client
import io
import os
import re
import shutil
import socket
import ssl
import stat

# The only module that starts processes; every argv is checked against ALLOWED_COMMANDS.
import subprocess  # nosec B404
import sys
import tempfile
import zlib
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import BinaryIO
from urllib.parse import urlsplit

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
    ("ldconfig", "-p"),  # prints /etc/ld.so.cache; never rebuilds it
    ("apt-get", "-s", "upgrade"),
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

# `systemctl show` with these properties for one or more units, each operand a plain
# unit name (validated like UNIT_QUERIES' operand).
SHOW_UNITS: tuple[str, ...] = (
    "systemctl",
    "show",
    "--property=Id,Names,LoadState,ActiveState,SubState,UnitFileState,ConditionResult,"
    "ConditionTimestamp,TriggeredBy,Requires,BindsTo,ControlGroup",
    "--",
)
MAX_UNITS = 256

# Scratch files: some commands need a file to write to (sqv), or a key in a form they
# can read (gpgv and armored keys). They go in a private directory of pydebuprep's own
# under /tmp (mode 0700, files 0600), removed before the run ends; never anywhere else.
SCRATCH_ROOT = "/tmp"  # nosec B108 - a private mkdtemp directory, not a fixed path
SCRATCH_PREFIX = "pydebuprep-"
SCRATCH_DIR = re.compile(r"^/tmp/pydebuprep-[A-Za-z0-9_]+$")
_ACTIVE_SCRATCH: set[str] = set()

# Verifying an apt repository's InRelease against keyrings (apt-sources): any number of
# keyrings from apt's own directories or the scratch directory, and the file to verify
# from apt's lists. sqv also needs an output file, which must be in the scratch directory.
SIGNATURE_PROGRAMS = ("sqv", "gpgv")
KEYRING_DIRS = ("/etc/apt/", "/usr/share/keyrings/")
APT_LISTS_DIR = "/var/lib/apt/lists/"

# Readiness probes (opt-in): ask PostgreSQL and MariaDB/MySQL whether they answer. Only
# these exact forms; the port, the PostgreSQL user and credential files are the variable
# parts, each validated. The query is always SELECT 1.
PG_SOCKET_DIR = "/var/run/postgresql"
PSQL_FLAGS = ("psql", "-X", "-A", "-t", "-w")
AS_POSTGRES = ("setpriv", "--reuid=postgres", "--regid=postgres", "--init-groups", "--")
CLIENT_ENV = ("PG", "MYSQL", "MARIADB", "APT_", "DOCKER_")
PG_USER = re.compile(r"[A-Za-z0-9_.-]+")
CONNINFO = re.compile(
    rf"host={PG_SOCKET_DIR} port=([0-9]{{1,5}}) dbname=postgres "
    r"user=[A-Za-z0-9_.-]+ passfile=(/\S+)"
)
MYSQL_ADMIN = ("mariadb-admin", "mysqladmin")
MYSQL_CLIENT = ("mariadb", "mysql")
MYSQL_QUERY = ("-N", "-B", "-e", "SELECT 1", "information_schema")
DEFAULTS_FILE = "--defaults-extra-file="

DEFAULT_TIMEOUT = 30.0
TIME_ERROR = 5  # adjtimex(): the clock is not synchronised
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
MAX_READ_BYTES = 16 << 20


def _open_regular(path: str) -> BinaryIO:
    """Open a regular file (following symlinks to a regular file, never a FIFO or device)."""
    real = os.path.realpath(path)
    if not stat.S_ISREG(os.lstat(real).st_mode):
        raise OSError(f"{path}: not a regular file")
    fd = os.open(real, READ_FLAGS)
    # Checked again on what was opened: the path may have been swapped in between.
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(f"{path}: not a regular file")
    return os.fdopen(fd, "rb")


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
    if argv and argv[0] in SIGNATURE_PROGRAMS:
        return _is_signature_check(argv)
    if argv and argv[0] in ("pg_isready", "setpriv", "psql", *MYSQL_ADMIN, *MYSQL_CLIENT):
        return _is_probe(argv)
    if argv[: len(SHOW_UNITS)] == SHOW_UNITS:
        units = argv[len(SHOW_UNITS) :]
        return 0 < len(units) <= MAX_UNITS and all(_plain_unit(u) for u in units)
    head, operand = argv[:-1], argv[-1] if argv else ""
    return head in UNIT_QUERIES and _plain_unit(operand)


def _normal_path(path: str) -> bool:
    return path.startswith("/") and os.path.normpath(path) == path


def _in_scratch(path: str) -> bool:
    return _normal_path(path) and SCRATCH_DIR.match(os.path.dirname(path)) is not None


def _is_signature_check(argv: tuple[str, ...]) -> bool:
    rest = list(argv[1:])
    keyrings = 0
    while len(rest) >= 2 and rest[0] == "--keyring":
        ring = rest[1]
        if not (_normal_path(ring) and (ring.startswith(KEYRING_DIRS) or _in_scratch(ring))):
            return False
        keyrings += 1
        rest = rest[2:]
    if argv[0] == "sqv":
        if rest[:2] != ["--cleartext", "--output"] or len(rest) < 3 or not _in_scratch(rest[2]):
            return False
        rest = rest[3:]
    target = rest[0] if len(rest) == 1 else ""
    name = target.removeprefix(APT_LISTS_DIR)
    return (
        keyrings > 0
        and _normal_path(target)
        and target.startswith(APT_LISTS_DIR)
        and "/" not in name
        and name.endswith("_InRelease")
    )


def _port(text: str) -> bool:
    return text.isdigit() and 0 < int(text) < 65536


def _without_defaults_file(args: tuple[str, ...]) -> tuple[str, ...] | None:
    """MySQL client arguments after an optional leading --defaults-extra-file=/path."""
    if args and args[0].startswith(DEFAULTS_FILE):
        return args[1:] if _normal_path(args[0][len(DEFAULTS_FILE) :]) else None
    return args


def _is_probe(argv: tuple[str, ...]) -> bool:
    if argv[:3] == ("pg_isready", "-h", PG_SOCKET_DIR):
        return len(argv) == 5 and argv[3] == "-p" and _port(argv[4])
    if argv[: len(AS_POSTGRES)] == AS_POSTGRES:
        rest = argv[len(AS_POSTGRES) :]
        return (
            rest[:7] == (*PSQL_FLAGS, "-h", PG_SOCKET_DIR)
            and len(rest) == 13
            and rest[7] == "-p"
            and _port(rest[8])
            and rest[9:] == ("-d", "postgres", "-c", "SELECT 1")
        )
    if argv[:6] == (*PSQL_FLAGS, "-d"):
        match = CONNINFO.fullmatch(argv[6]) if len(argv) == 9 else None
        return (
            match is not None
            and _port(match.group(1))
            and _normal_path(match.group(2))
            and argv[7:] == ("-c", "SELECT 1")
        )
    if argv[0] in MYSQL_ADMIN:
        return _without_defaults_file(argv[1:]) == ("ping",)
    return argv[0] in MYSQL_CLIENT and _without_defaults_file(argv[1:]) == MYSQL_QUERY


def _plain_unit(name: str) -> bool:
    return not name.startswith("-") and bool(UNIT_NAME.match(name))


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
        # Client settings for PostgreSQL and MySQL (PGHOST, PGSSLKEYLOGFILE, MYSQL_PWD, ...)
        # could redirect a probe or make a client write a file: never pass them on.
        env = {k: v for k, v in os.environ.items() if not k.startswith(CLIENT_ENV)}
        env.update(LC_ALL="C", LANG="C")
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
        data = self.read_bytes(path)
        return None if data is None else data.decode("utf-8", errors="replace")

    def read_bytes(self, path: str) -> bytes | None:
        try:
            with _open_regular(path) as fh:
                data = fh.read(MAX_READ_BYTES + 1)
        except OSError:
            return None
        return data if len(data) <= MAX_READ_BYTES else None

    def read_range(self, path: str, offset: int, size: int) -> bytes | None:
        """SIZE bytes from OFFSET (fewer at the end of the file), or None if unreadable."""
        if size < 0 or size > MAX_READ_BYTES:
            return None
        try:
            with _open_regular(path) as fh:
                fh.seek(offset)
                return fh.read(size)
        except (OSError, ValueError, OverflowError):
            return None

    def lines(self, path: str) -> Iterator[str]:
        """A text file's lines, read as they are needed (gzip when PATH ends in .gz);
        none if it can't be read. For files too big to read whole, like APT's indexes."""
        try:
            with _open_regular(path) as raw:
                if path.endswith(".gz"):
                    with gzip.open(raw, "rt", encoding="utf-8", errors="replace") as fh:
                        yield from fh
                else:
                    with io.TextIOWrapper(raw, encoding="utf-8", errors="replace") as fh:
                        yield from fh
        except (OSError, EOFError, zlib.error):
            return

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    @contextmanager
    def scratch_dir(self) -> Iterator[str]:
        """A private directory for scratch files, removed with everything in it after."""
        path = tempfile.mkdtemp(prefix=SCRATCH_PREFIX, dir=SCRATCH_ROOT)
        _ACTIVE_SCRATCH.add(path)
        try:
            yield path
        finally:
            _ACTIVE_SCRATCH.discard(path)
            shutil.rmtree(path, ignore_errors=True)

    def write_scratch(self, directory: str, name: str, data: bytes) -> str:
        """Create NAME (mode 0600) in an active scratch directory; never anywhere else."""
        if directory not in _ACTIVE_SCRATCH:
            raise ValueError(f"{directory} is not a pydebuprep scratch directory")
        if not name or "/" in name or name in (".", ".."):
            raise ValueError(f"{name!r} is not a plain file name")
        path = os.path.join(directory, name)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        with os.fdopen(os.open(path, flags, 0o600), "wb") as fh:
            fh.write(data)
        return path

    def tcp_connect(self, host: str, port: int, timeout: float) -> str | None:
        """Whether something answers on a TCP port: None if so, else why not.

        Accepting the connection isn't enough: Docker's userland proxy accepts on every
        published port and hangs up at once when nothing listens behind it. A working
        service waits for the client (no data within a second) or greets it.
        """
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(min(timeout, 1.0))
                try:
                    if sock.recv(1) == b"":
                        return "closed at once, nothing listens behind it"
                except TimeoutError:
                    pass  # waiting for us to speak: alive
                return None
        except OSError as exc:
            return exc.strerror or str(exc) or type(exc).__name__

    def http_get(self, url: str, timeout: float) -> tuple[int | None, str | None]:
        """GET URL without following redirects or proxies: (status, None) or (None, error)."""
        try:
            parts = urlsplit(url)
            host, port = parts.hostname or "", parts.port
            target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        except ValueError as exc:
            return None, str(exc)
        conn: http.client.HTTPConnection
        if parts.scheme == "https":
            # Probes only reach localhost, whose certificate rarely names "localhost":
            # this checks that the service answers, not who it is.
            context = ssl._create_unverified_context()  # nosec B323
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("GET", target)
            return conn.getresponse().status, None
        except (OSError, ValueError, http.client.HTTPException) as exc:
            return None, str(exc) or type(exc).__name__
        finally:
            conn.close()

    def readlink(self, path: str) -> str | None:
        try:
            return os.readlink(path)
        except OSError:
            return None

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
