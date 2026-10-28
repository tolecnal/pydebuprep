#!/usr/bin/env python3
"""Fail if a traced pydebuprep run changed anything on the system.

Reads an `strace -f` log of the syscalls listed in readonly-audit.sh and reports
every call that could change persistent state. Allowed: temporary files under /tmp
that are deleted again before the run ends, anonymous O_TMPFILE files, writes to
/dev/null and terminals, signal 0 (an existence probe), and the paths passed with
--allow (the snapshot directory for `pydebuprep snapshot`). Exit status 1 on any
violation.
"""

from __future__ import annotations

import argparse
import re
import sys

WRITE_FLAGS = re.compile(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND")
HARMLESS = ("/dev/null", "/dev/tty", "/dev/pts/")
CALL = re.compile(r"(\w+)\((.*)\)\s+=\s+(-?\d+|\?)")


def paths(args: str) -> list[str]:
    return re.findall(r'"((?:[^"\\]|\\.)*)"', args)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log")
    parser.add_argument("--allow", action="append", default=[], help="path prefix allowed to change")
    opts = parser.parse_args()

    programs: dict[str, str] = {}
    pending: dict[str, str] = {}
    created_tmp: dict[str, str] = {}
    violations: list[str] = []

    def allowed(path: str) -> bool:
        return path.startswith(HARMLESS) or any(path.startswith(a) for a in opts.allow)

    for raw in open(opts.log, errors="replace"):
        m = re.match(r"(\d+)\s+(.*)", raw.rstrip("\n"))
        if not m:
            continue
        pid, rest = m.groups()
        if "<unfinished ...>" in rest:
            pending[pid] = rest.split("<unfinished")[0]
            continue
        if rest.startswith("<... "):
            rest = pending.pop(pid, "") + rest.split("resumed>", 1)[-1]
        if rest.startswith("execve(") and rest.rstrip().endswith("= 0"):
            argv = re.search(r"\[(.*?)\]", rest)
            programs[pid] = argv.group(1).replace('"', "")[:80] if argv else rest[:80]
            continue
        call = CALL.match(rest)
        if not call or call.group(3).startswith("-"):
            continue  # unparsable, or failed (a failed call changed nothing)
        name, args, _ = call.groups()
        who = programs.get(pid, f"pid {pid}")
        targets = paths(args)
        where = f"{who}: {name}({args[:160]})"
        if name.startswith("open") or name == "creat":
            if "O_TMPFILE" in args:
                continue  # anonymous, never linked into the filesystem
            if name != "creat" and not WRITE_FLAGS.search(args):
                continue
            path = targets[0] if targets else ""
            if allowed(path):
                continue
            if path.startswith("/tmp/"):
                if "O_CREAT" in args:
                    created_tmp.setdefault(path, where)
                continue
            violations.append(where)
        elif name in ("unlink", "unlinkat", "rmdir"):
            path = targets[-1] if targets else ""
            if path in created_tmp:
                del created_tmp[path]
            elif not allowed(path):
                violations.append(where)
        elif name in ("rename", "renameat", "renameat2"):
            if not all(t.startswith("/tmp/") or allowed(t) for t in targets):
                violations.append(where)
            elif len(targets) == 2 and targets[0] in created_tmp:
                created_tmp[targets[1]] = created_tmp.pop(targets[0])
        elif name in ("kill", "tkill", "tgkill"):
            if not re.search(r",\s*0\)?$", args):  # signal 0 only probes for existence
                violations.append(where)
        elif name in ("mkdir", "mkdirat"):
            path = targets[-1] if targets else ""
            if not (path.startswith("/tmp/") or allowed(path)):
                violations.append(where)
        elif targets and all(t.startswith("/tmp/") or allowed(t) for t in targets):
            continue
        else:
            violations.append(where)

    for path, where in created_tmp.items():
        violations.append(f"left behind {path} ({where})")
    for v in violations:
        print(f"VIOLATION: {v}")
    print(f"{len(violations)} violation(s) in {opts.log}")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
