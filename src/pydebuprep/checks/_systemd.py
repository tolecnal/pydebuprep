"""Helpers for checks that query systemd."""

from __future__ import annotations

from collections.abc import Sequence

from pydebuprep.checks.base import CheckSkipped, Context
from pydebuprep.system import CommandResult

NOT_SYSTEMD_MARKERS = ("not been booted with systemd", "Failed to connect to bus")


def run_systemctl(ctx: Context, argv: Sequence[str]) -> CommandResult:
    res = ctx.system.run(argv)
    if not res.ok and any(m in res.stderr for m in NOT_SYSTEMD_MARKERS):
        raise CheckSkipped("systemd is not running on this system")
    if not res.ok and not res.stdout:
        first = res.stderr.strip().splitlines()[:1]
        raise RuntimeError(first[0] if first else f"{argv[0]} exited with {res.returncode}")
    return res


def unit_rows(text: str) -> list[list[str]]:
    rows = []
    for line in text.splitlines():
        fields = line.replace("●", " ").split()
        if fields:
            rows.append(fields)
    return rows
