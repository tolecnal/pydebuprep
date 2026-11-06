"""Processes the kernel killed for lack of memory: a new release's services may need more."""

from __future__ import annotations

import re
from collections import Counter

from pydebuprep.checks.base import Check, Context, count, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence

# Without its first letter: the kernel writes both "Out of memory" and "Memory cgroup out of
# memory", and journalctl only ignores case in a pattern that is all lower case.
JOURNAL_OOM = (
    "journalctl",
    "-b",
    "-k",
    "--no-pager",
    "-o",
    "cat",
    "--grep=ut of memory: Killed process",
)
KILLED = re.compile(r"ut of memory: Killed process \d+ \(([^)]*)\)")


class OomEventsCheck(Check):
    id = "oom-events"
    title = "Processes killed for lack of memory"
    category = "services"
    requires_root = True
    requires_commands = ("journalctl",)

    def run(self, ctx: Context) -> list[Finding]:
        out = run_checked(ctx, JOURNAL_OOM, ok_codes=(0, 1)).stdout
        killed = Counter(m.group(1) for m in map(KILLED.search, out.splitlines()) if m)
        if not killed:
            return []
        total = sum(killed.values())
        return [
            Finding(
                Severity.WARNING,
                f"{count(total, 'process was', 'processes were')} killed for lack of memory "
                "this boot",
                detail="What was killed may not have come back, and the machine may need more "
                "memory or swap than before.",
                evidence=truncate_evidence([f"{n}x {name}" for name, n in killed.most_common()]),
                remediation=["sudo journalctl -b -k --grep='ut of memory'", "free -h"],
            )
        ]
