"""In-memory System used by every test that would otherwise touch the host."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterator, Sequence
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
        strict: bool = True,
    ) -> None:
        self.commands = commands or {}
        self.files = files or {}
        self.mtimes = mtimes or {}
        self.disks = disks or {}
        self.root = root
        self.available = available
        self._hostname = hostname
        self._now = now
        self.walk_errors = walk_errors or []
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
        return self.files.get(path)

    def exists(self, path: str) -> bool:
        prefix = path.rstrip("/") + "/"
        return (
            path in self.files
            or path in self.disks
            or any(f.startswith(prefix) for f in self.files)
        )

    def glob(self, pattern: str) -> list[str]:
        return sorted(f for f in self.files if fnmatch.fnmatch(f, pattern))

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
