from __future__ import annotations

import os
import re
from typing import Any

from pydebuprep.checks._systemd import active_services
from pydebuprep.checks.base import Check, Context, count
from pydebuprep.model import Finding, Severity, truncate_evidence

SYSTEM_CRONTABS = ("/etc/crontab", "/etc/cron.d/*")
USER_CRONTABS = "/var/spool/cron/crontabs/*"  # readable by root only
CRON_DAEMONS = {"cron.service", "cronie.service", "crond.service"}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SEPARATORS = re.compile(r"\s*(?:;|&&|\|\||\||\{|\})\s*")
GUARD = re.compile(r"(?:\btest|\[)\s+-x\s+(\S+)")


def parse_crontab(text: str, *, system: bool) -> list[tuple[int, str, str]]:
    """(line number, schedule, command) for each job; system crontabs have a user field."""
    jobs = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or ASSIGNMENT.match(line):
            continue
        schedule_fields = 1 if line.startswith("@") else 5
        skip = schedule_fields + (1 if system else 0)
        fields = line.split(maxsplit=skip)
        if len(fields) <= skip:
            continue
        jobs.append((n, " ".join(fields[:schedule_fields]), fields[skip]))
    return jobs


def missing_programs(command: str, exists: Any) -> list[str]:
    """Absolute programs a command runs that don't exist, unless it checks them with -x."""
    guarded = set(GUARD.findall(command))
    missing = []
    for segment in SEPARATORS.split(command):
        words = [w for w in segment.split() if not ASSIGNMENT.match(w)]
        program = words[0] if words else ""
        if program.startswith("/") and program not in guarded and not exists(program):
            missing.append(program)
    return missing


class CronCheck(Check):
    id = "cron"
    title = "cron jobs"
    category = "services"

    def _jobs(self, ctx: Context) -> list[tuple[str, int, str, str]]:
        jobs = []
        files = [(p, True) for pattern in SYSTEM_CRONTABS for p in ctx.system.glob(pattern)]
        files += [(p, False) for p in ctx.system.glob(USER_CRONTABS)]
        for path, system in files:
            if path.startswith("/etc/cron.d/") and "." in os.path.basename(path):
                continue  # cron ignores these, e.g. dpkg's *.dpkg-dist leftovers
            text = ctx.system.read_text(path) or ""
            jobs += [(path, n, sched, cmd) for n, sched, cmd in parse_crontab(text, system=system)]
        return jobs

    def run(self, ctx: Context) -> list[Finding]:
        jobs = self._jobs(ctx)
        findings = []
        missing = [
            f"{path}:{n}: {program}"
            for path, n, _, cmd in jobs
            for program in missing_programs(cmd, ctx.system.exists)
        ]
        if missing:
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"{count(len(missing), 'cron job runs', 'cron jobs run')} programs "
                    "that don't exist",
                    detail="The upgrade may have removed or moved them (old Python versions "
                    "are a common case). These jobs now fail every time they run.",
                    evidence=truncate_evidence(missing),
                    remediation=[
                        "Find what provided it: dpkg -S PROGRAM, or apt-file search PROGRAM",
                        "Install the replacement and update the job, or remove the job",
                    ],
                )
            )
        active = active_services(ctx)
        if jobs and active is not None and not active & CRON_DAEMONS:
            findings.append(
                Finding(
                    Severity.WARNING,
                    "No cron daemon is running",
                    detail=f"{count(len(jobs), 'cron job')} won't run.",
                    remediation=["sudo apt install cron", "sudo systemctl enable --now cron"],
                )
            )
        return findings

    def collect_baseline(self, ctx: Context) -> Any:
        return sorted({f"{path}: {sched} {cmd}" for path, _, sched, cmd in self._jobs(ctx)})

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now = set(self.collect_baseline(ctx))
        removed = [job for job in before if job not in now]
        if not removed:
            return []
        return [
            Finding(
                Severity.INFO,
                f"{count(len(removed), 'cron job was', 'cron jobs were')} removed by the upgrade",
                detail="Package-provided jobs come and go with packages; check none of yours "
                "is among them.",
                evidence=truncate_evidence(removed),
                remediation=["Restore any you still need from your backups"],
            )
        ]
