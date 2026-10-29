from __future__ import annotations

from typing import Any

from pydebuprep.checks._systemd import ACTIVE_SERVICES
from pydebuprep.checks.cron import CronCheck, parse_crontab
from pydebuprep.model import Severity
from pydebuprep.system import CommandResult

from .helpers import make_ctx, titles

CRONTAB = """SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
"""
CRON_D = """# backup job
MAILTO=root
30 2 * * * root /usr/local/bin/backup.sh --full > /dev/null 2>&1
@reboot    root  /opt/legacy/start-agent.py
*/5 * * * * root [ -x /usr/lib/sysstat/debian-sa1 ] && /usr/lib/sysstat/debian-sa1 1 1
0 3 * * * www-data PYTHON=/usr/bin/python2 /usr/bin/python2 /srv/app/cleanup.py; /usr/bin/true
"""
USER = "@daily /home/alice/bin/sync\n0 * * * * echo hi | /usr/bin/logger\nbroken line\n"


def cron_ctx(**kw: Any) -> Any:
    files = {
        "/etc/crontab": CRONTAB,
        "/etc/cron.d/backup": CRON_D,
        "/etc/cron.d/old.dpkg-dist": "* * * * * root /nonexistent\n",  # cron ignores names with dots
        "/var/spool/cron/crontabs/alice": USER,
        # programs that exist:
        "/usr/local/bin/backup.sh": "",
        "/usr/bin/true": "",
        "/usr/bin/logger": "",
        **kw.pop("files", {}),
    }
    commands = {ACTIVE_SERVICES: kw.pop("services", "cron.service loaded active running x\n")}
    return make_ctx(files=files, commands=commands, **kw)


def test_parse_system_and_user_crontabs() -> None:
    assert parse_crontab(CRON_D, system=True) == [
        (3, "30 2 * * *", "/usr/local/bin/backup.sh --full > /dev/null 2>&1"),
        (4, "@reboot", "/opt/legacy/start-agent.py"),
        (5, "*/5 * * * *", "[ -x /usr/lib/sysstat/debian-sa1 ] && /usr/lib/sysstat/debian-sa1 1 1"),
        (
            6,
            "0 3 * * *",
            "PYTHON=/usr/bin/python2 /usr/bin/python2 /srv/app/cleanup.py; /usr/bin/true",
        ),
    ]
    assert parse_crontab(USER, system=False) == [
        (1, "@daily", "/home/alice/bin/sync"),
        (2, "0 * * * *", "echo hi | /usr/bin/logger"),
    ]


def test_missing_programs_reported() -> None:
    (f,) = CronCheck().run(cron_ctx())
    assert (f.severity, f.title) == (Severity.WARNING, "3 cron jobs run programs that don't exist")
    assert f.evidence == [
        "/etc/cron.d/backup:4: /opt/legacy/start-agent.py",
        "/etc/cron.d/backup:6: /usr/bin/python2",
        "/var/spool/cron/crontabs/alice:1: /home/alice/bin/sync",
    ]


def test_guarded_and_relative_programs_are_not_reported() -> None:
    files = {
        "/etc/cron.d/backup": "*/5 * * * * root [ -x /usr/lib/x ] && /usr/lib/x\n10 * * * * root test -x /opt/y && /opt/y; run-parts /etc/cron.hourly\n",
        "/var/spool/cron/crontabs/alice": "",
    }
    assert CronCheck().run(cron_ctx(files=files)) == []


def test_no_cron_daemon() -> None:
    files = {"/etc/cron.d/backup": "", "/var/spool/cron/crontabs/alice": ""}
    fs = CronCheck().run(cron_ctx(files=files, services="ssh.service loaded active running x\n"))
    assert [(f.severity, f.title) for f in fs] == [(Severity.WARNING, "No cron daemon is running")]


def test_without_systemd_daemon_state_is_unknown() -> None:
    files = {"/etc/cron.d/backup": "", "/var/spool/cron/crontabs/alice": ""}
    no_systemd = CommandResult(ACTIVE_SERVICES, 1, "", "System has not been booted with systemd\n")
    assert CronCheck().run(cron_ctx(files=files, services=no_systemd)) == []


def test_no_jobs_no_findings() -> None:
    ctx = make_ctx(commands={ACTIVE_SERVICES: ""})
    assert CronCheck().run(ctx) == []


def test_cron_baseline_and_removed_jobs() -> None:
    ctx = cron_ctx()
    base = CronCheck().collect_baseline(ctx)
    assert "/etc/crontab: 17 * * * * cd / && run-parts --report /etc/cron.hourly" in base
    gone = make_ctx(files={"/etc/crontab": CRONTAB}, commands={ACTIVE_SERVICES: ""})
    (f,) = CronCheck().compare(gone, base)
    assert (f.severity, f.title) == (Severity.INFO, "6 cron jobs were removed by the upgrade")
    assert CronCheck().compare(ctx, base) == []
    assert titles(CronCheck().compare(ctx, base[:1])) == []
