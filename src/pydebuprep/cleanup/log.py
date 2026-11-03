"""The cleanup's log: every line to its own file and to syslog (the journal), so what
was planned and done can be read back later."""

from __future__ import annotations

import os
import secrets
import syslog
from collections.abc import Callable
from datetime import datetime, timezone

LOG_PATH = "/var/log/pydebuprep/cleanup.log"
IDENT = "pydebuprep-cleanup"
LOG_FLAGS = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Log:
    def __init__(
        self,
        path: str = LOG_PATH,
        *,
        ident: str = IDENT,
        run_id: str | None = None,
        now: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.run_id = run_id or secrets.token_hex(4)
        self.now = now
        self.fd: int | None = None
        self.file_error: str | None = None
        try:
            self.fd = os.open(path, LOG_FLAGS, 0o640)
        except OSError as exc:
            # A dry run as an ordinary user, or no package directory: syslog still gets it.
            self.file_error = f"can't write {path}: {exc.strerror or exc}"
        syslog.openlog(ident, syslog.LOG_PID, syslog.LOG_USER)

    def line(self, text: str, *, level: int = syslog.LOG_INFO) -> None:
        stamp = self.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        for part in text.splitlines() or [""]:
            if self.fd is not None:
                os.write(self.fd, f"{stamp} [{self.run_id}] {part}\n".encode())
            syslog.syslog(level, part)

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        syslog.closelog()
