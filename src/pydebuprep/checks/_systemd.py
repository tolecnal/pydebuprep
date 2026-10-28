"""Helpers for checks that query systemd."""

from __future__ import annotations

from collections.abc import Sequence

from pydebuprep.checks.base import CheckSkipped, CommandFailed, Context
from pydebuprep.system import CommandResult

NOT_SYSTEMD_MARKERS = ("not been booted with systemd", "Failed to connect to bus")


def not_systemd(res: CommandResult) -> bool:
    return not res.ok and any(m in res.stderr for m in NOT_SYSTEMD_MARKERS)


def run_systemctl(ctx: Context, argv: Sequence[str]) -> CommandResult:
    res = ctx.system.run(argv)
    if res.timed_out:
        raise CommandFailed(f"{argv[0]} timed out")
    if not_systemd(res):
        raise CheckSkipped("systemd is not running on this system")
    if not res.ok and not res.stdout:
        first = res.stderr.strip().splitlines()[:1]
        raise CommandFailed(first[0] if first else f"{argv[0]} exited with {res.returncode}")
    return res


def unit_rows(text: str) -> list[list[str]]:
    rows = []
    for line in text.splitlines():
        fields = line.replace("●", " ").split()
        if fields:
            rows.append(fields)
    return rows
