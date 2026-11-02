#!/usr/bin/env python3
"""Fail if a traced pydebuprep run changed anything on the system.

Reads an `strace -f` log of the syscalls listed in readonly-audit.sh and reports
every call that could change persistent state. Allowed: temporary files and
directories under /tmp that are deleted again before the run ends, anonymous O_TMPFILE
files, writes to /dev/null and terminals, signal 0 (an existence probe), the paths
passed with --allow (the snapshot directory for `pydebuprep snapshot`), and the side
effects agreed with the user (AGREED_WRITES, documented in docs/about/read-only.md under
"Agreed side effects"): those only by the program they were agreed for, or a process it
started. A failed call
changed nothing and is ignored, except under a --strict prefix, where even an attempt
to write is a violation (UEFI variables are immutable files, so a write there would
fail rather than show up). Exit status 1 on any violation.
"""

from __future__ import annotations

import argparse
import posixpath
import re
import sys
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass

WRITE_FLAGS = re.compile(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND")
HARMLESS = ("/dev/null", "/dev/tty", "/dev/pts/")
# Prefix of short-lived files programs create and delete again; matched, never written to.
TMP = "/tmp/"  # nosec B108
LINE = re.compile(r"(\d+)\s+(.*)")
CALL = re.compile(r"(\w+)\((.*)\)\s+=\s+(-?\d+|\?)")
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
# Calls whose first argument is a directory descriptor their (first) path is relative to.
DIRFD_CALLS = ("openat", "openat2", "unlinkat", "mkdirat", "fchmodat", "fchownat", "mknodat")


PROCESS_CALLS = ("clone", "clone3", "fork", "vfork")
# Writes are judged where their file was opened, except into a file whose opening was
# agreed (a PID file, a log): it may be opened, never written to.
WRITE_CALLS = ("write", "pwrite64", "writev", "pwritev", "pwritev2")
# Calls that change the file behind a descriptor: judged as changes to the path it was
# opened as (newer coreutils chown and chmod work this way).
FD_CALLS = ("fchown", "fchmod", "ftruncate", "fsetxattr", "fremovexattr", "fallocate")
OPEN_CALLS = ("open", "openat", "openat2", "creat")


@dataclass(frozen=True)
class Agreed:
    """A change PROGRAM (an executable's name), or a process it started, may make: CALLS
    on paths matching PATH (every path of the call); for opens, only with FLAGS and
    never truncating."""

    program: str
    calls: tuple[str, ...]
    path: re.Pattern[str]
    flags: re.Pattern[str] | None = None


# Measured on Debian 13 and Ubuntu 24.04 (2026-11-02); agreeing to another is a code
# change, reviewed like any other, never a setting.
AGREED_WRITES = (
    # nginx -t: opens its PID file (creating it, never writing it) and its logs for
    # appending, and creates its temp directories (owned by www-data) if missing.
    Agreed("nginx", OPEN_CALLS, re.compile(r"/run/nginx\.pid"), re.compile(r"O_RDWR\|O_CREAT")),
    Agreed(
        "nginx", OPEN_CALLS, re.compile(r"/var/log/nginx/(?!\.\.?$)[^/]+"), re.compile(r"O_APPEND")
    ),
    Agreed(
        "nginx",
        ("mkdir", "mkdirat", "chown", "fchown", "fchownat", "lchown"),
        re.compile(r"/var/lib/nginx/(body|proxy|fastcgi|uwsgi|scgi)"),
    ),
    # apache2ctl -t: creates Apache's run and lock directories if missing; the socket
    # directory is made under a temporary name and renamed into place.
    Agreed(
        "apache2ctl",
        ("mkdir", "mkdirat", "chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat",
         "rename", "renameat", "renameat2"),
        re.compile(
            r"(/var)?/run/apache2(/socks(\.\w+)?)?|(/var)?/run/lock/apache2(\.\w+)?"
            r"|/var/lock/apache2(\.\w+)?"
        ),
    ),
    # mkdir -p walks relative path components from a working directory the trace doesn't
    # show; creating a directory is all a bare name may do (an existing one fails).
    Agreed("apache2ctl", ("mkdir", "mkdirat"), re.compile(r"apache2|run|lock")),
)  # fmt: skip


def joined(lines: Iterable[str]) -> Iterator[tuple[str, str]]:
    """(pid, call) for each line of an strace -f log, a call strace split into
    "<unfinished ...>" and "<... resumed>" lines joined into one."""
    pending: dict[str, str] = {}
    for raw in lines:
        m = LINE.match(raw.rstrip("\n"))
        if not m:
            continue
        pid, rest = m.groups()
        if "<unfinished ...>" in rest:
            pending[pid] = rest.split("<unfinished")[0]
            continue
        if rest.startswith("<... "):
            rest = pending.pop(pid, "") + rest.split("resumed>", 1)[-1]
        yield pid, rest


def executed_program(rest: str) -> str | None:
    """The program a successful execve call ran (its file name), or None."""
    if not (rest.startswith("execve(") and rest.rstrip().endswith("= 0")):
        return None
    path = QUOTED.search(rest)
    return posixpath.basename(path.group(1)) if path else ""


class ProcessTree:
    """Who started whom, and what each process ran. Read in a first pass over the whole
    log: strace prints a parent's fork result after the child has already run."""

    def __init__(self) -> None:
        self.parents: dict[str, str] = {}
        self.execs: dict[str, set[str]] = {}

    def add(self, pid: str, rest: str) -> None:
        program = executed_program(rest)
        if program is not None:
            self.execs.setdefault(pid, set()).add(program)
            return
        call = CALL.match(rest)
        if call and call.group(1) in PROCESS_CALLS and call.group(3).isdigit():
            self.parents[call.group(3)] = pid

    @classmethod
    def from_lines(cls, lines: Iterable[str]) -> ProcessTree:
        tree = cls()
        for pid, rest in joined(lines):
            tree.add(pid, rest)
        return tree

    def programs(self, pid: str) -> frozenset[str]:
        """What PID and the processes that started it ran."""
        found: set[str] = set()
        seen: set[str] = set()
        current: str | None = pid
        while current is not None and current not in seen:
            seen.add(current)
            found |= self.execs.get(current, set())
            current = self.parents.get(current)
        return frozenset(found)


class Auditor:
    def __init__(
        self, allow: Sequence[str], strict: Sequence[str] = (), tree: ProcessTree | None = None
    ) -> None:
        self.allow = tuple(allow)
        self.strict = tuple(strict)
        self.programs: dict[str, str] = {}
        self.pending: dict[str, str] = {}
        self.created_tmp: dict[str, str] = {}
        self.violations: list[str] = []
        self.run_pids: set[str] = set()  # every process and thread in the traced run
        self.signals: list[tuple[str, str]] = []  # (target pid, where), judged in finish()
        self.fds: dict[tuple[str, str], str] = {}  # (pid, fd) -> path it was opened as
        self.tree = tree if tree is not None else ProcessTree()  # built as it goes if None
        self.prescanned = tree is not None
        self.agreed_fds: set[tuple[str, str]] = set()  # (pid, fd) of agreed opens

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
        if not self.prescanned:
            self.tree.add(pid, rest)
        if executed_program(rest) is not None:
            argv = re.search(r"\[(.*?)\]", rest)
            self.programs[pid] = argv.group(1).replace('"', "")[:80] if argv else rest[:80]
            return
        call = CALL.match(rest)
        if not call:
            return
        name, args, result = call.groups()
        if name in PROCESS_CALLS:
            return  # in the process tree
        where = f"{self.programs.get(pid, f'pid {pid}')}: {name}({args[:160]})"
        targets = QUOTED.findall(args)
        if name in DIRFD_CALLS and targets and not targets[0].startswith("/"):
            # Relative to an open directory (shutil.rmtree does this): resolve it, or mark
            # it unknown so it can't pass as a scratch file.
            dirfd = args.split(",", 1)[0].strip()
            base = self.fds.get((pid, dirfd), f"<fd {dirfd}>")
            targets[0] = f"{base.rstrip('/')}/{targets[0]}"
        if name in FD_CALLS and not targets:
            fd = args.split(",", 1)[0].strip()
            targets = [self.fds.get((pid, fd), f"<fd {fd}>")]
            where = f"{where} on {targets[0]}"
        if name in WRITE_CALLS:
            fd = args.split(",", 1)[0].strip()
            if (pid, fd) in self.agreed_fds and result.isdigit() and int(result) > 0:
                self.violations.append(f"{where} (wrote into {self.fds[(pid, fd)]})")
            return
        if name.startswith("open") and result.isdigit() and targets:
            self.fds[(pid, result)] = targets[0]
            self.agreed_fds.discard((pid, result))
        if result.startswith("-"):
            if self.strict_attempt(name, args, targets):
                self.violations.append(f"{where} (failed attempt)")
            return
        if not self.agreed(pid, name, args, targets):
            self.check(name, args, targets, where)
        elif name in OPEN_CALLS and result.isdigit():
            self.agreed_fds.add((pid, result))

    def agreed(self, pid: str, name: str, args: str, targets: list[str]) -> bool:
        """Whether this call is a side effect agreed for a program PID descends from."""
        programs = self.tree.programs(pid)
        return any(
            rule.program in programs
            and name in rule.calls
            and bool(targets)
            and all(rule.path.fullmatch(t) for t in targets)
            and (rule.flags is None or (bool(rule.flags.search(args)) and "O_TRUNC" not in args))
            for rule in AGREED_WRITES
        )

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
    parser.add_argument(
        "--executed",
        action="store_true",
        help="only list the programs the traced run executed, one per line",
    )
    opts = parser.parse_args()
    with open(opts.log, errors="replace") as fh:
        tree = ProcessTree.from_lines(fh)
    if opts.executed:
        print("\n".join(sorted(set().union(*tree.execs.values()))))
        return 0
    auditor = Auditor(opts.allow, opts.strict, tree)
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
