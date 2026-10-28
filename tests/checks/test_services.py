from __future__ import annotations

import json

from pydebuprep.checks.boot_time import ANALYZE, BLAME, BootTimeCheck
from pydebuprep.checks.dmesg_errors import DMESG_ERR, DMESG_WARN, DmesgErrorsCheck
from pydebuprep.checks.journal_errors import JOURNAL, JournalErrorsCheck
from pydebuprep.checks.systemd_failed import ACTIVE_SERVICES, FAILED, SystemdFailedCheck
from pydebuprep.checks.systemd_timers import TIMERS, SystemdTimersCheck
from pydebuprep.model import Severity, Status
from pydebuprep.runner import run_check
from pydebuprep.system import CommandResult

from .helpers import make_ctx, titles


def test_failed_units_critical() -> None:
    out = "nginx.service loaded failed failed A high performance web server\n"
    (f,) = SystemdFailedCheck().run(make_ctx(commands={FAILED: out}))
    assert (f.severity, f.title) == (Severity.CRITICAL, "Unit nginx.service failed")
    assert f.remediation == ["systemctl status nginx.service", "journalctl -u nginx.service -b"]


def test_bullet_prefix_stripped() -> None:
    out = "● php8.2-fpm.service loaded failed failed PHP FPM\n"
    assert titles(SystemdFailedCheck().run(make_ctx(commands={FAILED: out}))) == [
        "Unit php8.2-fpm.service failed"
    ]


def test_no_systemd_skips() -> None:
    res = CommandResult(
        FAILED,
        1,
        "",
        "System has not been booted with systemd as init system (PID 1). Can't operate.\n",
    )
    r = run_check(SystemdFailedCheck(), make_ctx(commands={FAILED: res}))
    assert r.status is Status.SKIPPED
    assert r.skipped_reason is not None
    assert "systemd" in r.skipped_reason


def test_compare_service_no_longer_active() -> None:
    out = "cron.service loaded active running Regular background program processing daemon\n"
    ctx = make_ctx(commands={ACTIVE_SERVICES: out})
    assert SystemdFailedCheck().collect_baseline(ctx) == ["cron.service"]
    fs = SystemdFailedCheck().compare(ctx, ["cron.service", "postgresql@15-main.service"])
    assert [(f.severity, f.title) for f in fs] == [
        (
            Severity.WARNING,
            "postgresql@15-main.service was active before the upgrade but is not now",
        )
    ]


def test_compare_many_services_grouped() -> None:
    ctx = make_ctx(commands={ACTIVE_SERVICES: ""})
    fs = SystemdFailedCheck().compare(ctx, [f"s{i}.service" for i in range(7)])
    assert titles(fs) == ["7 services were active before the upgrade but are not now"]


TIMER_OUT = (
    "apt-daily.timer loaded active waiting Daily apt download activities\n"
    "certbot.timer loaded inactive dead Run certbot twice daily\n"
    "fstrim.timer not-found inactive dead fstrim.timer\n"
)


def test_inactive_timer_warns() -> None:
    commands = dict([(TIMERS, TIMER_OUT), show("certbot.timer", "enabled", "yes")])
    (f,) = SystemdTimersCheck().run(make_ctx(commands=commands))
    assert (f.severity, f.title) == (Severity.WARNING, "Timer certbot.timer is not active")


def test_compare_missing_timer() -> None:
    ctx = make_ctx(commands={TIMERS: TIMER_OUT})
    assert SystemdTimersCheck().collect_baseline(ctx) == ["apt-daily.timer"]
    fs = SystemdTimersCheck().compare(
        ctx, ["apt-daily.timer", "certbot.timer", "e2scrub_all.timer"]
    )
    assert titles(fs) == ["2 timers were active before the upgrade but are not now"]
    assert fs[0].evidence == ["certbot.timer", "e2scrub_all.timer"]


def jline(ident: str, msg: object) -> str:
    return json.dumps({"SYSLOG_IDENTIFIER": ident, "MESSAGE": msg, "PRIORITY": "3"})


def test_journal_groups_and_counts() -> None:
    out = "\n".join(
        [
            jline("sshd", "error: kex failed"),
            jline("sshd", "error: kex failed"),
            jline("kernel", "ACPI Error: x"),
            "not json",
        ]
    )
    (f,) = JournalErrorsCheck().run(make_ctx(commands={JOURNAL: out}))
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "3 error messages in the current boot (2 distinct)",
    )
    assert f.evidence == ["2x sshd: error: kex failed", "1x kernel: ACPI Error: x"]


def test_journal_message_as_byte_array() -> None:
    out = json.dumps({"_COMM": "foo", "MESSAGE": list(b"bad \xff bytes")})
    (f,) = JournalErrorsCheck().run(make_ctx(commands={JOURNAL: out}))
    assert f.evidence[0].startswith("1x foo: bad ")


def test_journal_permission_hint_info() -> None:
    res = CommandResult(
        JOURNAL,
        0,
        "",
        "Hint: You are currently not seeing messages from other users and the system.\n",
    )
    (f,) = JournalErrorsCheck().run(make_ctx(commands={JOURNAL: res}))
    assert f.severity is Severity.INFO
    assert "adm" in f.remediation[0]


def test_journal_empty_ok() -> None:
    assert JournalErrorsCheck().run(make_ctx(commands={JOURNAL: ""})) == []


def test_dmesg_err_warns() -> None:
    ctx = make_ctx(commands={DMESG_ERR: "nouveau: firmware missing\n", DMESG_WARN: "w1\n"})
    fs = DmesgErrorsCheck().run(ctx)
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.WARNING, "1 kernel error message since boot"),
        (Severity.INFO, "1 kernel warning message since boot"),
    ]


def test_dmesg_warn_only_info() -> None:
    fs = DmesgErrorsCheck().run(make_ctx(commands={DMESG_ERR: "", DMESG_WARN: "w1\n"}))
    assert [f.severity for f in fs] == [Severity.INFO]


def test_dmesg_dedupe() -> None:
    ctx = make_ctx(commands={DMESG_ERR: "a\na\nb\n", DMESG_WARN: ""})
    (f,) = DmesgErrorsCheck().run(ctx)
    assert f.evidence == ["2x a", "1x b"]


ANALYZE_OUT = (
    "Startup finished in 3.512s (kernel) + 9.843s (userspace) = 13.355s\n"
    "graphical.target reached after 9.700s in userspace.\n"
)


def test_boot_time_info_with_top10() -> None:
    blame = "".join(f"{i}.000s unit{i}.service\n" for i in range(15, 0, -1))
    (f,) = BootTimeCheck().run(make_ctx(commands={ANALYZE: ANALYZE_OUT, BLAME: blame}))
    assert (f.severity, f.title) == (Severity.INFO, "Boot took 13.355s")
    assert len(f.evidence) == 10
    assert f.evidence[0] == "15.000s unit15.service"


def test_boot_not_finished() -> None:
    res = CommandResult(
        ANALYZE,
        1,
        "",
        "Bootup is not yet finished (org.freedesktop.systemd1.Manager.FinishTimestampMonotonic=0).\n",
    )
    (f,) = BootTimeCheck().run(make_ctx(commands={ANALYZE: res, BLAME: ""}))
    assert (f.severity, f.title) == (Severity.INFO, "Boot has not finished yet")
    assert f.remediation == ["systemctl list-jobs"]


def test_journal_groups_messages_differing_only_by_ids() -> None:
    out = "\n".join(
        [
            jline("networkctl", 'Interface "veth44bbc08" not found.'),
            jline("networkctl", 'Interface "veth789bd3a" not found.'),
            jline("networkctl", 'Interface "veth2f6e785" not found.'),
        ]
    )
    (f,) = JournalErrorsCheck().run(make_ctx(commands={JOURNAL: out}))
    assert f.title == "3 error messages in the current boot (1 distinct)"
    assert f.evidence == ['3x networkctl: Interface "veth44bbc08" not found. (and similar)']


def show(unit: str, state: str, condition: str) -> tuple[tuple[str, ...], str]:
    argv = ("systemctl", "show", "-p", "UnitFileState", "-p", "ConditionResult", unit)
    return argv, f"UnitFileState={state}\nConditionResult={condition}\n"


def test_inactive_timer_with_unmet_condition_or_disabled_ignored() -> None:
    out = (
        "ua-timer.timer loaded inactive dead Ubuntu Pro Timer\n"
        "old.timer loaded inactive dead Disabled timer\n"
        "certbot.timer loaded inactive dead Run certbot twice daily\n"
    )
    commands = dict(
        [
            (TIMERS, out),
            show("ua-timer.timer", "enabled", "no"),
            show("old.timer", "disabled", "yes"),
            show("certbot.timer", "enabled", "yes"),
        ]
    )
    assert titles(SystemdTimersCheck().run(make_ctx(commands=commands))) == [
        "Timer certbot.timer is not active"
    ]


def test_boot_time_without_systemd_skips() -> None:
    res = CommandResult(
        ANALYZE,
        1,
        "",
        "System has not been booted with systemd as init system (PID 1). Can't operate.\n",
    )
    r = run_check(BootTimeCheck(), make_ctx(commands={ANALYZE: res}))
    assert r.status is Status.SKIPPED
    assert r.skipped_reason == "systemd is not running on this system"


def test_dmesg_not_permitted_skips() -> None:
    res = CommandResult(
        DMESG_ERR, 1, "", "dmesg: read kernel buffer failed: Operation not permitted\n"
    )
    r = run_check(DmesgErrorsCheck(), make_ctx(commands={DMESG_ERR: res}))
    assert r.status is Status.SKIPPED
    assert r.skipped_reason is not None
    assert "kernel log is not readable" in r.skipped_reason


def test_journal_ignore_patterns() -> None:
    out = "\n".join([jline("networkctl", 'Interface "veth1" not found.'), jline("sshd", "boom")])
    (f,) = JournalErrorsCheck({"ignore": ["^networkctl: Interface"]}).run(
        make_ctx(commands={JOURNAL: out})
    )
    assert f.evidence == ["1x sshd: boom"]
    assert "1 ignored" in f.detail


def test_journal_all_ignored_ok() -> None:
    out = jline("networkctl", 'Interface "veth1" not found.')
    assert JournalErrorsCheck({"ignore": ["veth"]}).run(make_ctx(commands={JOURNAL: out})) == []


def test_journal_invalid_regex_rejected() -> None:
    import pytest

    with pytest.raises(ValueError, match="journal-errors: invalid ignore pattern"):
        JournalErrorsCheck({"ignore": ["("]})


def test_dmesg_ignore_patterns() -> None:
    ctx = make_ctx(commands={DMESG_ERR: "ACPI BIOS Error x\nreal error\n", DMESG_WARN: ""})
    (f,) = DmesgErrorsCheck({"ignore": ["^ACPI"]}).run(ctx)
    assert f.evidence == ["1x real error"]


def test_systemd_failed_ignore_units() -> None:
    out = "nginx.service loaded failed failed x\nfoo@1.service loaded failed failed y\n"
    fs = SystemdFailedCheck({"ignore_units": ["foo@*"]}).run(make_ctx(commands={FAILED: out}))
    assert titles(fs) == ["Unit nginx.service failed"]


def test_systemd_timers_ignore_units() -> None:
    commands = dict([(TIMERS, TIMER_OUT)])
    assert (
        SystemdTimersCheck({"ignore_units": ["certbot.timer"]}).run(make_ctx(commands=commands))
        == []
    )
