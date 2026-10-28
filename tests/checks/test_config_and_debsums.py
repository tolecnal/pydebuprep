from __future__ import annotations

from pydebuprep.checks.base import Context
from pydebuprep.checks.config_conflicts import ConfigConflictsCheck
from pydebuprep.checks.debsums import DebsumsCheck
from pydebuprep.model import Severity, Status
from pydebuprep.runner import run_check
from pydebuprep.system import CommandResult

from .helpers import make_ctx, titles


def ctx_with(*paths: str, **kw: object) -> Context:
    return make_ctx(files={p: "" for p in paths}, **kw)  # type: ignore[arg-type]


def test_sshd_conflict_critical() -> None:
    fs = ConfigConflictsCheck().run(
        ctx_with("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.dpkg-dist")
    )
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.CRITICAL, "Unmerged package config for /etc/ssh/sshd_config")
    ]
    assert fs[0].remediation[0] == "diff -u /etc/ssh/sshd_config /etc/ssh/sshd_config.dpkg-dist"


def test_sudoers_d_critical() -> None:
    fs = ConfigConflictsCheck().run(ctx_with("/etc/sudoers.d/admins.ucf-old"))
    assert fs[0].severity is Severity.CRITICAL


def test_other_conflicts_single_warning() -> None:
    fs = ConfigConflictsCheck().run(
        ctx_with(
            "/etc/nginx/nginx.conf.dpkg-new",
            "/etc/php/8.4/fpm/php.ini.ucf-dist",
            "/etc/default/grub.ucf-old",
        )
    )
    assert titles(fs) == ["3 config files have unmerged package versions"]
    assert fs[0].severity is Severity.WARNING
    assert fs[0].evidence == [
        "/etc/default/grub.ucf-old",
        "/etc/nginx/nginx.conf.dpkg-new",
        "/etc/php/8.4/fpm/php.ini.ucf-dist",
    ]


def test_none_ok() -> None:
    assert ConfigConflictsCheck().run(ctx_with("/etc/hosts", "/etc/foo.dpkg-new.txt")) == []


def test_unreadable_dirs_info_when_not_root() -> None:
    ctx = ctx_with(root=False, walk_errors=["/etc/ssl/private: Permission denied"])
    (f,) = ConfigConflictsCheck().run(ctx)
    assert f.severity is Severity.INFO
    assert f.evidence == ["/etc/ssl/private: Permission denied"]


DEBSUMS = ("debsums", "-c")


def test_debsums_changed_files_warn() -> None:
    res = CommandResult(
        DEBSUMS,
        2,
        "/usr/bin/foo\n/usr/lib/x/y.so\n",
        "debsums: missing file /usr/share/doc/bar/README (from bar package)\n",
    )
    (f,) = DebsumsCheck().run(make_ctx(commands={DEBSUMS: res}))
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "3 package files differ from or are missing compared to their packages",
    )
    assert f.evidence[0] == "/usr/bin/foo"
    assert "missing file /usr/share/doc/bar/README" in f.evidence[2]


def test_debsums_clean_ok() -> None:
    assert DebsumsCheck().run(make_ctx(commands={DEBSUMS: ""})) == []


def test_runner_skips_debsums_when_missing() -> None:
    r = run_check(DebsumsCheck(), make_ctx(available=set()))
    assert r.status is Status.SKIPPED
    assert r.skipped_reason == "command not found: debsums; sudo apt install debsums"
