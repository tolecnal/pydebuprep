"""auth-config: sudoers, PAM and the name service, the chain a login depends on."""

from __future__ import annotations

from typing import Any

from pydebuprep.checks.auth_config import VISUDO, AuthConfigCheck
from pydebuprep.model import Finding, Severity
from pydebuprep.system import CommandResult, check_allowed

from .helpers import make_ctx

SECURITY = "/usr/lib/x86_64-linux-gnu/security"
LIBS = "/usr/lib/x86_64-linux-gnu"
NSS = "/etc/nsswitch.conf"


def run(root: bool = True, **kw: Any) -> list[Finding]:
    available = kw.pop("available", set())
    return AuthConfigCheck().run(make_ctx(root=root, available=available, **kw))


def summary(findings: list[Finding]) -> list[tuple[Severity, str, list[str]]]:
    return [(f.severity, f.title, f.evidence) for f in findings]


def test_visudo_query_is_allowed() -> None:
    check_allowed(VISUDO)


def test_valid_sudoers_are_silent() -> None:
    assert run(available={"visudo"}, commands={VISUDO: "/etc/sudoers: parsed OK\n"}) == []


def test_invalid_sudoers_are_critical() -> None:
    bad = CommandResult(VISUDO, 1, ">>> /etc/sudoers: syntax error near line 3 <<<\n", "")
    (f,) = run(available={"visudo"}, commands={VISUDO: bad})
    assert (f.severity, f.title) == (Severity.CRITICAL, "The sudoers configuration is invalid")
    assert f.evidence == [">>> /etc/sudoers: syntax error near line 3 <<<"]


def test_invalid_sudoers_report_what_visudo_wrote_to_stderr() -> None:
    bad = CommandResult(VISUDO, 1, "", "visudo: /etc/sudoers: bad\n")
    (f,) = run(available={"visudo"}, commands={VISUDO: bad})
    assert f.evidence == ["visudo: /etc/sudoers: bad"]


def test_without_root_or_visudo_sudoers_are_not_checked() -> None:
    assert run(root=False, available={"visudo"}) == []
    assert run(available=set()) == []


def test_pam_modules_that_exist_are_silent() -> None:
    files = {
        "/etc/pam.d/sshd": "# comment\n\n@include common-auth\nauth required pam_unix.so nullok\n"
        "session [success=ok default=ignore] pam_limits.so\n"
        "auth include other\nauth substack system\n",
        f"{SECURITY}/pam_unix.so": "",
        f"{SECURITY}/pam_limits.so": "",
    }
    assert run(files=files) == []


def test_a_missing_module_in_a_login_path_is_critical() -> None:
    (f,) = run(files={"/etc/pam.d/common-auth": "auth required pam_gone.so\n"})
    assert (f.severity, f.title) == (Severity.CRITICAL, "PAM uses modules that don't exist")
    assert f.evidence == ["common-auth: pam_gone.so"]


def test_a_missing_module_elsewhere_is_a_warning() -> None:
    (f,) = run(files={"/etc/pam.d/someapp": "auth required pam_gone.so\n"})
    assert (f.severity, f.title) == (Severity.WARNING, "PAM uses modules that don't exist")


def test_a_module_marked_optional_with_a_dash_may_be_missing() -> None:
    assert run(files={"/etc/pam.d/login": "-session optional pam_gone.so\n"}) == []


def test_a_module_named_by_its_path() -> None:
    files = {"/etc/pam.d/x": "auth required /opt/pam_a.so\nauth required /opt/pam_b.so\n",
             "/opt/pam_a.so": ""}  # fmt: skip
    (f,) = run(files=files)
    assert f.evidence == ["x: /opt/pam_b.so"]


def test_lines_that_are_not_module_lines_are_ignored() -> None:
    assert run(files={"/etc/pam.d/x": "auth required\njust words here\n"}) == []


def test_a_nss_service_that_exists_or_is_built_in_is_silent() -> None:
    files = {
        NSS: "# comment\n\npasswd: files systemd\nhosts: files dns [!UNAVAIL=return] resolve\nbad\n",
        f"{LIBS}/libnss_systemd.so.2": "",
        f"{LIBS}/libnss_resolve.so.2": "",
    }
    assert run(files=files) == []


def test_a_missing_nss_service_is_a_warning() -> None:
    (f,) = run(files={NSS: "passwd: files sss\ngroup: files sss\nhosts: files ldap\n"})
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "The name service uses modules that don't exist",
    )
    assert f.evidence == ["group: sss", "hosts: ldap", "passwd: sss"]


def test_baseline_and_nothing_changed() -> None:
    ctx = make_ctx(
        files={
            "/etc/pam.d/common-auth": "@include x\n-auth optional pam_a.so\nauth required pam_b.so\n",
            NSS: "passwd: files sss\n",
        },
        available=set(),
    )
    check = AuthConfigCheck()
    before = check.collect_baseline(ctx)
    assert before == {
        "pam": {"common-auth": ["pam_b.so"]},
        "nss": {"passwd": ["files", "sss"]},
    }
    assert check.compare(ctx, before) == []


def test_what_is_lost_since_the_snapshot() -> None:
    ctx = make_ctx(
        files={
            "/etc/pam.d/common-auth": "auth required pam_unix.so\n",
            "/etc/pam.d/someapp": "auth required pam_unix.so\n",
            NSS: "passwd: files\ngroup: files sss\n",
        }
    )
    fs = AuthConfigCheck().compare(
        ctx,
        {
            "pam": {
                "common-auth": ["pam_unix.so", "pam_ldap.so"],
                "someapp": ["pam_unix.so", "pam_extra.so"],
                "removed-app": ["pam_unix.so"],
            },
            "nss": {"passwd": ["files", "sss"], "group": ["files", "sss"], "shadow": ["files"]},
        },
    )
    assert summary(fs) == [
        (Severity.WARNING, "PAM login paths lost modules since the snapshot",
         ["common-auth: pam_ldap.so"]),
        (Severity.WARNING, "The name service lost modules since the snapshot",
         ["passwd: sss", "shadow: files"]),
    ]  # fmt: skip


def test_a_snapshot_without_these_is_silent() -> None:
    assert AuthConfigCheck().compare(make_ctx(), {}) == []


def test_a_missing_optional_module_is_only_a_warning_even_in_a_login_path() -> None:
    """As a real upgrade to Ubuntu 24.04 left pam_lastlog.so in /etc/pam.d/login."""
    (f,) = run(files={"/etc/pam.d/login": "session optional pam_lastlog.so\n"})
    assert (f.severity, f.evidence) == (Severity.WARNING, ["login: pam_lastlog.so"])


def test_a_line_that_ignores_an_unknown_module_may_name_a_missing_one() -> None:
    line = "session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close\n"
    assert run(files={"/etc/pam.d/login": line}) == []


def test_a_bracketed_control_that_does_not_ignore_it_counts() -> None:
    line = "auth [success=1 default=ignore] pam_gone.so\n"
    (f,) = run(files={"/etc/pam.d/common-auth": line})
    assert f.severity == Severity.CRITICAL


def test_a_module_used_twice_is_looked_up_once_and_listed_twice() -> None:
    files = {"/etc/pam.d/a": "auth required pam_gone.so\nsession required pam_gone.so\n"}
    (f,) = run(files=files)
    assert f.evidence == ["a: pam_gone.so", "a: pam_gone.so"]


def test_stock_entries_for_legacy_databases_are_left_alone() -> None:
    """Debian's and Ubuntu's own nsswitch.conf names db and nis, normally absent."""
    text = (
        "protocols: db files\nservices: db files\nethers: db files\nrpc: db files\nnetgroup: nis\n"
    )
    assert run(files={NSS: text}) == []


def test_the_databases_that_matter_are_checked() -> None:
    text = "shadow: files sss\ngshadow: files sss\nsudoers: files ldap\nhosts: files mdns4\n"
    (f,) = run(files={NSS: text})
    assert f.evidence == ["gshadow: sss", "hosts: mdns4", "shadow: sss", "sudoers: ldap"]


def test_an_optional_pam_module_lost_is_not_a_change() -> None:
    ctx = make_ctx(files={"/etc/pam.d/login": "session optional pam_lastlog.so\n"})
    assert AuthConfigCheck().collect_baseline(ctx)["pam"] == {"login": []}


def test_lines_naming_something_other_than_a_module_are_ignored() -> None:
    assert run(files={"/etc/pam.d/x": "auth required notamodule\nauth include other\n"}) == []


def test_leftover_files_are_not_services() -> None:
    assert run(files={"/etc/pam.d/login.dpkg-old": "auth required pam_gone.so\n"}) == []
