"""Helpers for checks that query systemd."""

from __future__ import annotations

from collections.abc import Sequence

from pydebuprep.checks.base import CheckSkipped, CommandFailed, Context
from pydebuprep.system import CommandResult

LIST = ("systemctl", "list-units", "--no-legend", "--plain", "--no-pager")
ACTIVE_SERVICES = (*LIST[:2], "--type=service", "--state=active", *LIST[2:])
ENABLED_SERVICES = (
    "systemctl",
    "list-unit-files",
    "--type=service",
    "--state=enabled",
    "--no-legend",
    "--no-pager",
)
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


def active_services(ctx: Context) -> set[str] | None:
    """Names of active services, or None when systemd isn't running (e.g. a container)."""
    try:
        return {row[0] for row in unit_rows(run_systemctl(ctx, ACTIVE_SERVICES).stdout)}
    except CheckSkipped:
        return None
