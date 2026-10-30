"""In-memory System used by every test that would otherwise touch the host."""

from __future__ import annotations

import fnmatch
import gzip
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime, timezone

from pydebuprep.system import CommandResult, DiskUsage, System, _strip_apt_opts, check_allowed

FROZEN_NOW = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)


class FakeSystem(System):
    def __init__(
        self,
        *,
        commands: dict[tuple[str, ...], CommandResult | str] | None = None,
        files: dict[str, str] | None = None,
        mtimes: dict[str, float] | None = None,
        disks: dict[str, DiskUsage] | None = None,
        root: bool = True,
        available: set[str] | None = None,
        hostname: str = "testhost",
        now: datetime = FROZEN_NOW,
        walk_errors: list[str] | None = None,
        clock_synced: bool | None = True,
        python: str = "3.13",
        strict: bool = True,
        links: dict[str, str] | None = None,
        ports: set[tuple[str, int]] | None = None,
        http: dict[str, int] | None = None,
    ) -> None:
        self.commands = commands or {}
        self.files = files or {}
        self.links = links or {}
        self.scratch_files: dict[str, bytes] = {}
        self.whole_reads: list[str] = []
        self.ports = ports or set()
        self.http = http or {}
        self.mtimes = mtimes or {}
        self.disks = disks or {}
        self.root = root
        self.available = available
        self._hostname = hostname
        self._now = now
        self.walk_errors = walk_errors or []
        self.clock_synced = clock_synced
        self.python = python
        self.strict = strict
        self.calls: list[tuple[str, ...]] = []
        self.timeouts: list[float] = []

    def run(self, argv: Sequence[str], timeout: float = 30.0) -> CommandResult:
        check_allowed(argv)
        args = tuple(argv)
        self.calls.append(args)
        self.timeouts.append(timeout)
        key = _strip_apt_opts(args)
        if key not in self.commands:
            if self.strict:
                raise AssertionError(f"unexpected command in test: {key}")
            return CommandResult(args, 0, "", "")
        value = self.commands[key]
        if isinstance(value, str):
            return CommandResult(args, 0, value, "")
        return value

    def which(self, name: str) -> bool:
        return self.available is None or name in self.available

    def read_text(self, path: str) -> str | None:
        self.whole_reads.append(path)
        return self.files.get(path)

    def lines(self, path: str) -> Iterator[str]:
        data: str | bytes | None = self.files.get(path)
        if isinstance(data, bytes):
            try:
                data = gzip.decompress(data).decode("utf-8", "replace")
            except (OSError, EOFError):
                return
        yield from (data or "").splitlines(keepends=True)

    def read_bytes(self, path: str) -> bytes | None:
        self.whole_reads.append(path)
        data: str | bytes | None = self.files.get(path)
        if isinstance(data, bytes):  # binary test files may be given as bytes
            return data
        return None if data is None else data.encode("utf-8")

    def exists(self, path: str) -> bool:
        prefix = path.rstrip("/") + "/"
        return (
            path in self.files
            or path in self.disks
            or any(f.startswith(prefix) for f in self.files)
        )

    def readlink(self, path: str) -> str | None:
        return self.links.get(path)

    def tcp_connect(self, host: str, port: int, timeout: float) -> str | None:
        return None if (host, port) in self.ports else "Connection refused"

    def http_get(self, url: str, timeout: float) -> tuple[int | None, str | None]:
        return (self.http[url], None) if url in self.http else (None, "Connection refused")

    @contextmanager
    def scratch_dir(self) -> Iterator[str]:
        yield "/tmp/pydebuprep-test"

    def write_scratch(self, directory: str, name: str, data: bytes) -> str:
        path = f"{directory}/{name}"
        self.scratch_files[path] = data
        return path

    def glob(self, pattern: str) -> list[str]:
        return sorted(f for f in (*self.files, *self.links) if fnmatch.fnmatch(f, pattern))

    def mtime(self, path: str) -> float | None:
        return self.mtimes.get(path)

    def walk_files(self, root: str, errors: list[str] | None = None) -> Iterator[str]:
        if errors is not None:
            errors.extend(self.walk_errors)
        prefix = root.rstrip("/") + "/"
        yield from sorted(f for f in self.files if f.startswith(prefix))

    def disk_usage(self, path: str) -> DiskUsage | None:
        return self.disks.get(path)

    def is_root(self) -> bool:
        return self.root

    def hostname(self) -> str:
        return self._hostname

    def now(self) -> datetime:
        return self._now

    def clock_synchronized(self) -> bool | None:
        return self.clock_synced

    def python_version(self) -> str:
        return self.python

    def find_files(self, roots: Sequence[str], name: str, max_depth: int) -> list[str]:
        found = []
        for root in roots:
            prefix = root.rstrip("/") + "/"
            for path in self.files:
                rel = path[len(prefix) :] if path.startswith(prefix) else None
                if rel is not None and rel.split("/")[-1] == name and rel.count("/") <= max_depth:
                    found.append(path)
        return sorted(found)
