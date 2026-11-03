"""Acting on a plan: back up the config files of the packages to purge, purge, remove
leftover directories, and log each step; stop at the first failure."""

from __future__ import annotations

import io
import os
import shutil
import syslog
import tarfile
import time
from collections.abc import Callable, Sequence
from datetime import datetime

from pydebuprep.cleanup.log import Log
from pydebuprep.cleanup.plan import Plan, Refused, leftover_dir_ok, owners
from pydebuprep.cleanup.runner import APT_PURGE, Runner
from pydebuprep.system import CONFFILES_HEAD, System

BACKUP_DIR = "/var/backups/pydebuprep"
BACKUP_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
OUTPUT_LINES = 20  # of a failed or noisy command, in the log

__all__ = ["CONFFILES_HEAD", "backup_conffiles", "execute", "remove_dir"]


def _conffiles(system: System, packages: Sequence[str]) -> list[str]:
    res = system.run((*CONFFILES_HEAD, *packages))
    return sorted(
        {line.split()[0] for line in res.stdout.splitlines() if line.strip().startswith("/")}
    )


def backup_conffiles(
    system: System, packages: Sequence[str], when: datetime, *, backup_dir: str = BACKUP_DIR
) -> str | None:
    """A tarball of the config files dpkg still lists for PACKAGES, before they're
    purged; None when none of them exist any more. Files are read through System's
    safe reader; links are kept as links."""
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    for path in _conffiles(system, packages):
        info = tarfile.TarInfo(path.lstrip("/"))
        info.mtime = int(time.time())
        target = system.readlink(path)
        if target is not None:
            info.type, info.linkname = tarfile.SYMTYPE, target
            members.append((info, None))
            continue
        data = system.read_bytes(path)
        if data is not None:
            info.size, info.mode = len(data), 0o600
            members.append((info, data))
    if not members:
        return None
    target_path = os.path.join(backup_dir, f"rc-{when.strftime('%Y%m%dT%H%M%SZ')}.tar.gz")
    with (
        os.fdopen(os.open(target_path, BACKUP_FLAGS, 0o600), "wb") as fh,
        tarfile.open(fileobj=fh, mode="w:gz") as tar,
    ):
        for info, data in members:
            tar.addfile(info, None if data is None else io.BytesIO(data))
    return target_path


def remove_dir(system: System, path: str, *, remove: Callable[[str], None] = shutil.rmtree) -> None:
    """Remove a leftover kernel directory, after checking again that it is one."""
    if not leftover_dir_ok(path) or not system.is_real_dir(path):
        raise Refused(f"not a leftover kernel directory: {path}")
    remove(path)


def _output(res_text: str) -> list[str]:
    lines = [line for line in res_text.splitlines() if line.strip()]
    return lines[-OUTPUT_LINES:]


def execute(
    plan: Plan,
    runner: Runner,
    system: System,
    log: Log,
    now: datetime,
    *,
    backup_dir: str = BACKUP_DIR,
    remove: Callable[[str], None] = shutil.rmtree,
) -> int:
    """Carry out PLAN; 0 when done, 2 when a step failed (the rest is left undone)."""
    steps: list[tuple[str, Callable[[], bool]]] = []
    if plan.residual:
        names = [p.name for p in plan.residual]

        def backup() -> bool:
            path = backup_conffiles(system, names, now, backup_dir=backup_dir)
            log.line(
                f"config files backed up to {path}" if path else "no config files left to back up"
            )
            return True

        steps.append(("back up config files", backup))
    for label, packages in (
        ("kernels", plan.kernels),
        ("modules", plan.modules),
        ("residual", plan.residual),
    ):
        if packages:
            names = [p.name for p in packages]
            steps.append((f"purge {label} ({' '.join(names)})", _purge(runner, log, names)))
    for path in plan.dirs:
        steps.append((f"remove {path}", _remove(system, log, path, remove)))
    for n, (label, step) in enumerate(steps):
        log.line(label)
        if not step():
            undone = [name for name, _ in steps[n + 1 :]]
            if undone:
                log.line(f"not done: {'; '.join(undone)}", level=syslog.LOG_ERR)
            return 2
    log.line("done")
    return 0


def _purge(runner: Runner, log: Log, names: list[str]) -> Callable[[], bool]:
    def step() -> bool:
        res = runner.run((*APT_PURGE, *names))
        for line in _output(res.stdout):
            log.line(f"  {line}")
        if res.returncode != 0 or res.timed_out:
            detail = _output(res.stderr or res.stdout)
            reason = "timed out" if res.timed_out else f"exit {res.returncode}"
            log.line(f"failed ({reason}): {detail[-1] if detail else ''}", level=syslog.LOG_ERR)
            return False
        return True

    return step


def _remove(
    system: System, log: Log, path: str, remove: Callable[[str], None]
) -> Callable[[], bool]:
    def step() -> bool:
        if not system.exists(path) and system.readlink(path) is None:
            log.line(f"already gone: {path}")  # dpkg removes a package's empty directories
            return True
        still = owners(system, [path])[path]
        if still:
            log.line(f"kept {path}: still has files of {', '.join(sorted(still))}")
            return True
        try:
            remove_dir(system, path, remove=remove)
        except (Refused, OSError) as exc:
            log.line(f"failed: {exc}", level=syslog.LOG_ERR)
            return False
        log.line(f"removed {path}")
        return True

    return step
