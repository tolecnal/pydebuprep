"""What happened during the upgrade, from the logs of APT, dpkg and Ubuntu's release upgrader.
The state a machine ends up in doesn't always show what went wrong on the way."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from pydebuprep.checks.base import Check, Context, Option, count
from pydebuprep.model import Finding, Severity, truncate_evidence

HISTORY = "/var/log/apt/history.log"
TERM = "/var/log/apt/term.log"
DPKG = "/var/log/dpkg.log"
UPGRADER_LOGS = ("/var/log/dist-upgrade/main.log", "/var/log/dist-upgrade/*/main.log")
MAX_DAYS = 365
STAMP_LENGTH = len("2026-10-20 20:00:00")
# Logs keep local time. Lexical order of these strings is time order.
STAMP = "%Y-%m-%d %H:%M:%S"
# Not anchored: dpkg's progress output can come before it on the same line.
FAILED = re.compile(r"dpkg: error processing (?:package|archive) (\S+) \((--[a-z-]+)\):")
DPKG_STATUS = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) status (\S+) (\S+)")
UPGRADER_ERROR = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ (?:ERROR|CRITICAL) (.*)")
PACKAGE_IN_LIST = re.compile(r"(?:^|\), )([^\s:,]+)(?::\S+)? \(")
FINISHED_STATES = {"installed"}


def _stamp(text: str) -> str:
    """'2026-10-20  20:00:00', as APT writes it, with one space, as dpkg does."""
    return " ".join(text.split())


@dataclass
class _Run:
    start: str
    command: str = ""
    errors: list[str] = field(default_factory=list)
    finished: bool = False


class UpgradeLogCheck(Check):
    id = "upgrade-log"
    title = "What happened during the upgrade"
    category = "packages"
    options = (
        Option("days", 30, f"Without a snapshot, how many days of logs to read (1 to {MAX_DAYS})"),
    )

    def validate(self) -> None:
        if not 1 <= self.opt("days") <= MAX_DAYS:
            raise ValueError(f"days must be between 1 and {MAX_DAYS}")

    def _window(self, ctx: Context) -> tuple[str, bool]:
        """Where to start reading, in the logs' local time, and whether that's a snapshot's."""
        created = (ctx.baseline or {}).get("created_at")
        if isinstance(created, str):
            try:
                when = datetime.fromisoformat(created)
            except ValueError:
                pass
            else:
                return when.astimezone().strftime(STAMP), True
        start = ctx.system.now() - timedelta(days=self.opt("days"))
        return start.astimezone().strftime(STAMP), False

    def run(self, ctx: Context) -> list[Finding]:
        start, from_snapshot = self._window(ctx)
        last_status, first_stamp = _dpkg_log(ctx, start)
        failed, fixed = _failures(ctx, start, last_status)
        findings = [
            *_apt_runs(ctx, start, Severity.INFO if fixed and not failed else Severity.WARNING),
            *_failure_findings(failed, fixed),
            *_upgrader_errors(ctx, start),
            *_availability(ctx),
        ]
        if from_snapshot and first_stamp is not None and first_stamp > start:
            findings.append(
                Finding(
                    Severity.INFO,
                    "The upgrade logs begin after the snapshot",
                    detail="Older logs may have been rotated away, so what happened before "
                    f"{first_stamp} isn't known.",
                )
            )
        return findings


def _rotated(ctx: Context, path: str) -> list[str]:
    return [*ctx.system.glob(f"{path}.*"), *ctx.system.glob(path)]


def _lines(ctx: Context, path: str) -> Iterator[str]:
    for file in _rotated(ctx, path):
        yield from ctx.system.lines(file)


def _dpkg_log(ctx: Context, start: str) -> tuple[dict[str, tuple[str, str]], str | None]:
    """Each package's last (time, status) since START, and the log's first time."""
    last: dict[str, tuple[str, str]] = {}
    first = None
    for line in _lines(ctx, DPKG):
        stamp = line[:STAMP_LENGTH]
        if not stamp[:1].isdigit():
            continue
        if first is None or stamp < first:
            first = stamp
        match = DPKG_STATUS.match(line)
        if match and stamp >= start:
            package = match.group(3).split(":")[0]
            if package not in last or stamp >= last[package][0]:
                last[package] = (stamp, match.group(2))
    return last, first


def _history(ctx: Context, start: str) -> Iterator[tuple[_Run, list[str]]]:
    """Each APT run since START, with the packages it removed."""
    run: _Run | None = None
    removed: list[str] = []
    for line in _lines(ctx, HISTORY):
        key, _, value = line.strip().partition(": ")
        if key == "Start-Date":
            if run is not None:
                yield run, removed
            stamp = _stamp(value)
            run, removed = (
                (_Run(stamp), []) if stamp[:1].isdigit() and stamp >= start else (None, [])
            )
        elif run is not None:
            if key == "Commandline":
                run.command = value
            elif key == "Error":
                run.errors.append(value)
            elif key in ("Remove", "Purge"):
                removed += PACKAGE_IN_LIST.findall(value)
            elif key == "End-Date":
                run.finished = True
    if run is not None:
        yield run, removed


def _apt_runs(ctx: Context, start: str, error_severity: Severity) -> list[Finding]:
    errors, unfinished = [], []
    removed: set[str] = set()
    for run, packages in _history(ctx, start):
        removed.update(packages)
        errors += [f"{run.start}: {run.command}: {error}" for error in run.errors]
        if not run.finished:
            unfinished.append(f"{run.start}: {run.command}")
    findings = []
    if errors:
        findings.append(
            Finding(
                error_severity,
                f"{count(len(errors), 'APT run')} reported errors",
                detail="It may have been put right since; dpkg-audit shows the state now.",
                evidence=truncate_evidence(sorted(errors)),
                remediation=["Read what happened: less /var/log/apt/term.log"],
            )
        )
    if unfinished:
        findings.append(
            Finding(
                Severity.WARNING,
                f"{count(len(unfinished), 'APT run')} didn't finish",
                detail="It was interrupted, or is still running.",
                evidence=truncate_evidence(sorted(unfinished)),
                remediation=["sudo dpkg --configure -a", "sudo apt -f install"],
            )
        )
    if removed:
        findings.append(
            Finding(
                Severity.INFO,
                f"{count(len(removed), 'package was', 'packages were')} removed or purged",
                evidence=truncate_evidence(sorted(removed)),
                remediation=["Reinstall anything still needed: sudo apt install PACKAGE"],
            )
        )
    return findings


def _term_failures(ctx: Context, start: str) -> dict[tuple[str, str], tuple[str, str]]:
    """(package, dpkg's action) -> (when, why), for failures since START."""
    failures: dict[tuple[str, str], tuple[str, str]] = {}
    stamp = ""
    pending: tuple[str, str] | None = None
    for line in _lines(ctx, TERM):
        text = line.strip()
        if pending is not None:
            failures[pending] = (stamp, text)
            pending = None
        if text.startswith("Log started: "):
            stamp = _stamp(text.removeprefix("Log started: "))
        elif stamp >= start and (match := FAILED.search(text)):
            pending = (match.group(1), match.group(2))
            failures[pending] = (stamp, "")
    return failures


def _failures(
    ctx: Context, start: str, last_status: dict[str, tuple[str, str]]
) -> tuple[list[str], list[str]]:
    """Failures since START: those not put right, and those that were."""
    open_failures, fixed = [], []
    for (package, action), (stamp, why) in sorted(_term_failures(ctx, start).items()):
        name = package.split(":")[0]
        line = f"{package} ({action})" + (f": {why}" if why else "")
        later = last_status.get(name)
        if later is not None and later[1] in FINISHED_STATES and later[0] >= stamp:
            fixed.append(line)
        else:
            open_failures.append(line)
    return open_failures, fixed


def _failure_findings(open_failures: list[str], fixed: list[str]) -> list[Finding]:
    findings = []
    if open_failures:
        findings.append(
            Finding(
                Severity.WARNING,
                f"{count(len(open_failures), 'package')} failed during installation or upgrade",
                detail="Its script may have left something half done, even if dpkg-audit finds "
                "nothing wrong now.",
                evidence=truncate_evidence(open_failures),
                remediation=[
                    "sudo dpkg --configure -a",
                    "Read what happened: less /var/log/apt/term.log",
                ],
            )
        )
    if fixed:
        findings.append(
            Finding(
                Severity.INFO,
                f"{count(len(fixed), 'package')} failed, then installed correctly later",
                evidence=truncate_evidence(fixed),
            )
        )
    return findings


def _upgrader_errors(ctx: Context, start: str) -> list[Finding]:
    errors = []
    for pattern in UPGRADER_LOGS:
        for path in ctx.system.glob(pattern):
            for line in ctx.system.lines(path):
                match = UPGRADER_ERROR.match(line)
                if match and match.group(1) >= start:
                    errors.append(match.group(2).strip())
    if not errors:
        return []
    return [
        Finding(
            Severity.WARNING,
            f"The release upgrader logged {count(len(errors), 'error')}",
            detail="Not every error stops an upgrade; check these were dealt with.",
            evidence=truncate_evidence(errors),
            remediation=["Read the rest: less /var/log/dist-upgrade/main.log"],
        )
    ]


def _availability(ctx: Context) -> list[Finding]:
    """A log that isn't there says nothing, which mustn't look like nothing went wrong."""
    missing, unreadable = [], []
    for path in (HISTORY, TERM, DPKG):
        files = _rotated(ctx, path)
        if not files:
            missing.append(path)
        elif ctx.system.read_range(files[-1], 0, 1) is None:
            unreadable.append(path)
    findings = []
    if missing:
        findings.append(
            Finding(
                Severity.INFO,
                f"{count(len(missing), 'upgrade log is', 'upgrade logs are')} missing",
                detail="What they would show isn't known.",
                evidence=missing,
            )
        )
    if unreadable:
        findings.append(
            Finding(
                Severity.INFO,
                f"{count(len(unreadable), 'upgrade log')} can't be read",
                detail="What it would show isn't known.",
                evidence=unreadable,
                remediation=["Run as root, or add your user to the adm group"],
            )
        )
    return findings
