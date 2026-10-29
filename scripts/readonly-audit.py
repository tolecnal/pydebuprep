#!/usr/bin/env python3
"""Fail if a traced pydebuprep run changed anything on the system.

Reads an `strace -f` log of the syscalls listed in readonly-audit.sh and reports
every call that could change persistent state. Allowed: temporary files and
directories under /tmp that are deleted again before the run ends, anonymous O_TMPFILE
files, writes to /dev/null and terminals, signal 0 (an existence probe), and the paths
passed with --allow (the snapshot directory for `pydebuprep snapshot`). A failed call
changed nothing and is ignored, except under a --strict prefix, where even an attempt
to write is a violation (UEFI variables are immutable files, so a write there would
fail rather than show up). Exit status 1 on any violation.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence

WRITE_FLAGS = re.compile(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND")
HARMLESS = ("/dev/null", "/dev/tty", "/dev/pts/")
# Prefix of short-lived files programs create and delete again; matched, never written to.
TMP = "/tmp/"  # nosec B108
LINE = re.compile(r"(\d+)\s+(.*)")
CALL = re.compile(r"(\w+)\((.*)\)\s+=\s+(-?\d+|\?)")
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
# Calls whose first argument is a directory descriptor their (first) path is relative to.
DIRFD_CALLS = ("openat", "openat2", "unlinkat", "mkdirat", "fchmodat", "fchownat", "mknodat")


class Auditor:
    def __init__(self, allow: Sequence[str], strict: Sequence[str] = ()) -> None:
        self.allow = tuple(allow)
        self.strict = tuple(strict)
        self.programs: dict[str, str] = {}
        self.pending: dict[str, str] = {}
        self.created_tmp: dict[str, str] = {}
        self.violations: list[str] = []
        self.run_pids: set[str] = set()  # every process and thread in the traced run
        self.signals: list[tuple[str, str]] = []  # (target pid, where), judged in finish()
        self.fds: dict[tuple[str, str], str] = {}  # (pid, fd) -> path it was opened as

    def allowed(self, path: str) -> bool:
        return path.startswith(HARMLESS) or path.startswith(self.allow)

    def scratch_or_allowed(self, path: str) -> bool:
        return path.startswith(TMP) or self.allowed(path)

    def feed(self, raw: str) -> None:
        m = LINE.match(raw.rstrip("\n"))
        if not m:
            return
        pid, rest = m.groups()
        self.run_pids.add(pid)
        if "<unfinished ...>" in rest:
            self.pending[pid] = rest.split("<unfinished")[0]
            return
        if rest.startswith("<... "):
            rest = self.pending.pop(pid, "") + rest.split("resumed>", 1)[-1]
        if rest.startswith("execve(") and rest.rstrip().endswith("= 0"):
            argv = re.search(r"\[(.*?)\]", rest)
            self.programs[pid] = argv.group(1).replace('"', "")[:80] if argv else rest[:80]
            return
        call = CALL.match(rest)
        if not call:
            return
        name, args, result = call.groups()
        where = f"{self.programs.get(pid, f'pid {pid}')}: {name}({args[:160]})"
        targets = QUOTED.findall(args)
        if name in DIRFD_CALLS and targets and not targets[0].startswith("/"):
            # Relative to an open directory (shutil.rmtree does this): resolve it, or mark
            # it unknown so it can't pass as a scratch file.
            dirfd = args.split(",", 1)[0].strip()
            base = self.fds.get((pid, dirfd), f"<fd {dirfd}>")
            targets[0] = f"{base.rstrip('/')}/{targets[0]}"
        if name.startswith("open") and result.isdigit() and targets:
            self.fds[(pid, result)] = targets[0]
        if result.startswith("-"):
            if self.strict_attempt(name, args, targets):
                self.violations.append(f"{where} (failed attempt)")
            return
        self.check(name, args, targets, where)

    def strict_attempt(self, name: str, args: str, targets: list[str]) -> bool:
        if not any(t.startswith(self.strict) for t in targets):
            return False
        return bool(WRITE_FLAGS.search(args)) if name.startswith("open") else True

    def check(self, name: str, args: str, targets: list[str], where: str) -> None:
        if name.startswith("open") or name == "creat":
            self.check_open(name, args, targets[0] if targets else "", where)
        elif name in ("unlink", "unlinkat", "rmdir"):
            path = targets[-1] if targets else ""
            if path in self.created_tmp:
                del self.created_tmp[path]
            elif not self.allowed(path):
                self.violations.append(where)
        elif name in ("rename", "renameat", "renameat2"):
            if not all(self.scratch_or_allowed(t) for t in targets):
                self.violations.append(where)
            elif len(targets) == 2 and targets[0] in self.created_tmp:
                self.created_tmp[targets[1]] = self.created_tmp.pop(targets[0])
        elif name in ("adjtimex", "clock_adjtime"):
            if not re.search(r"\bmodes=0\b", args):  # modes=0 only reads the clock state
                self.violations.append(where)
        elif name in ("kill", "tkill", "tgkill"):
            if not re.search(r",\s*0\)?$", args):  # signal 0 only probes for existence
                target = args.split(",", 1)[0].strip().lstrip("-")
                self.signals.append((target, where))
        elif name in ("mkdir", "mkdirat") and targets and targets[-1].startswith(TMP):
            self.created_tmp.setdefault(targets[-1], where)
        elif not (targets and all(self.scratch_or_allowed(t) for t in targets)):
            self.violations.append(where)

    def check_open(self, name: str, args: str, path: str, where: str) -> None:
        if "O_TMPFILE" in args:
            return  # anonymous, never linked into the filesystem
        if name != "creat" and not WRITE_FLAGS.search(args):
            return
        if self.allowed(path):
            return
        if path.startswith(TMP):
            if "O_CREAT" in args:
                self.created_tmp.setdefault(path, where)
            return
        self.violations.append(where)

    def finish(self) -> list[str]:
        leftovers = [f"left behind {p} ({w})" for p, w in self.created_tmp.items()]
        # Signals between the run's own processes and threads are internal (Go programs
        # preempt their threads with SIGURG); signalling anything else is a change.
        signals = [where for target, where in self.signals if target not in self.run_pids]
        return [*self.violations, *signals, *leftovers]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log")
    parser.add_argument(
        "--allow", action="append", default=[], help="path prefix allowed to change"
    )
    parser.add_argument(
        "--strict",
        action="append",
        default=[],
        help="path prefix where even a failed attempt to change it is a violation",
    )
    opts = parser.parse_args()
    auditor = Auditor(opts.allow, opts.strict)
    with open(opts.log, errors="replace") as fh:
        for raw in fh:
            auditor.feed(raw)
    violations = auditor.finish()
    for v in violations:
        print(f"VIOLATION: {v}")
    print(f"{len(violations)} violation(s) in {opts.log}")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
