from __future__ import annotations

import re
from typing import Any

from pydebuprep.checks.base import Check, Context, count, output_lines
from pydebuprep.model import Finding, Severity, truncate_evidence

FINDMNT_VERIFY = ("findmnt", "--verify")
FINDMNT_LIST = ("findmnt", "-rn", "-o", "TARGET,SOURCE,FSTYPE")
VIRTUAL_FS = {
    "proc", "sysfs", "tmpfs", "devtmpfs", "cgroup2", "cgroup", "securityfs", "pstore", "bpf",
    "debugfs", "tracefs", "configfs", "fusectl", "mqueue", "hugetlbfs", "devpts", "autofs",
    "binfmt_misc", "efivarfs", "squashfs", "nsfs", "overlay", "ramfs", "rpc_pipefs",
}  # fmt: skip
MARKER = re.compile(r"^\s+\[([EW])\]\s*(.*)$")
PERMISSION_NOISE = "(Permission denied)"
SWAPFILE_NOTE = "is a directory or regular file"
ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")


def _unescape(text: str) -> str:
    return ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)


def _mounted(ctx: Context) -> list[str]:
    targets = []
    for line in ctx.system.run(list(FINDMNT_LIST)).stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[-1] not in VIRTUAL_FS:
            targets.append(_unescape(fields[0]))
    return sorted(targets)


class FstabCheck(Check):
    id = "fstab"
    title = "/etc/fstab and mounts"
    category = "storage"
    requires_commands = ("findmnt",)

    def run(self, ctx: Context) -> list[Finding]:
        res = ctx.system.run(list(FINDMNT_VERIFY))
        problems: dict[str, list[str]] = {"E": [], "W": []}
        target = ""
        unverified = False
        for line in res.stdout.splitlines():
            match = MARKER.match(line)
            if match:
                message = match.group(2)
                if PERMISSION_NOISE in message and not ctx.is_root:
                    unverified = True
                elif target == "none" and SWAPFILE_NOTE in message:
                    continue  # swap files are listed with source=file; findmnt notes it
                else:
                    problems[match.group(1)].append(f"{target}: {message}")
            elif line.strip() and not line[0].isspace():
                target = line.strip()
        remediation = [
            "Fix the entries in /etc/fstab",
            "Re-check with: sudo findmnt --verify",
            "When ready, test mounting everything with: sudo mount -a",
        ]
        findings = []
        if problems["E"]:
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    f"/etc/fstab has {count(len(problems['E']), 'error')}",
                    detail="A bad fstab entry can drop the next boot into emergency mode.",
                    evidence=truncate_evidence(problems["E"]),
                    remediation=remediation,
                )
            )
        if problems["W"]:
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"/etc/fstab has {count(len(problems['W']), 'warning')}",
                    evidence=truncate_evidence(problems["W"]),
                    remediation=remediation,
                )
            )
        if unverified:
            findings.append(
                Finding(
                    Severity.INFO,
                    "Some fstab entries could not be fully verified without root",
                    remediation=["Run as root for complete results"],
                )
            )
        if not res.ok and not problems["E"] and not problems["W"]:
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    "findmnt --verify failed",
                    evidence=truncate_evidence(
                        output_lines(res.stderr) or output_lines(res.stdout)
                    ),
                    remediation=remediation,
                )
            )
        return findings

    def collect_baseline(self, ctx: Context) -> Any:
        return _mounted(ctx)

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now = set(_mounted(ctx))
        return [
            Finding(
                Severity.WARNING,
                f"{target} was mounted before the upgrade but is not now",
                remediation=[
                    f"Check its fstab entry and mount unit: findmnt --fstab {target}",
                    f"sudo mount {target}",
                ],
            )
            for target in sorted(set(before) - now)
        ]
