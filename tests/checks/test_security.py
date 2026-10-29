from __future__ import annotations

from typing import Any

from pydebuprep.checks.apparmor import AA_ENABLED, AA_PROFILES, JOURNAL_DENIALS, AppArmorCheck
from pydebuprep.checks.dpkg_rc import DPKG_RC_ARGV
from pydebuprep.checks.ssh_server import SSHD_TEST, SshServerCheck
from pydebuprep.checks.unattended_upgrades import APT_CONFIG_DUMP, UnattendedUpgradesCheck
from pydebuprep.model import Severity, Status
from pydebuprep.runner import run_check
from pydebuprep.system import CommandResult

from .helpers import make_ctx, titles

# --- apparmor ------------------------------------------------------------------------

PROFILES = "/usr/sbin/cupsd (enforce)\nnvidia_modprobe (complain)\nsnap.lxd.lxc (enforce)\n"
DENIAL = (
    'audit: type=1400 apparmor="DENIED" operation="open" class="file" profile="/usr/sbin/cupsd" '
    'name="/etc/x" pid=1 comm="cupsd" requested_mask="r" denied_mask="r"'
)


def aa_ctx(**kw: Any) -> Any:
    files = {AA_ENABLED: kw.pop("enabled", "Y\n"), AA_PROFILES: kw.pop("profiles", PROFILES)}
    commands = {JOURNAL_DENIALS: kw.pop("denials", CommandResult(JOURNAL_DENIALS, 1, "", ""))}
    return make_ctx(files=files, commands=commands, **kw)


def test_apparmor_complain_profiles_info() -> None:
    (f,) = AppArmorCheck().run(aa_ctx())
    assert (f.severity, f.title) == (Severity.INFO, "1 AppArmor profile is in complain mode")
    assert f.evidence == ["nvidia_modprobe"]


def test_apparmor_disabled() -> None:
    fs = AppArmorCheck().run(aa_ctx(enabled="N\n", profiles=""))
    assert [(f.severity, f.title) for f in fs] == [(Severity.WARNING, "AppArmor is disabled")]


def test_apparmor_denials() -> None:
    out = "\n".join([DENIAL, DENIAL, DENIAL.replace('"open"', '"exec"')]) + "\n"
    fs = AppArmorCheck().run(aa_ctx(profiles="/usr/sbin/cupsd (enforce)\n", denials=out))
    assert titles(fs) == ["3 AppArmor denials this boot"]
    assert fs[0].evidence == ["2x /usr/sbin/cupsd: open", "1x /usr/sbin/cupsd: exec"]


def test_apparmor_without_journal_still_checks_profiles() -> None:
    ctx = aa_ctx(available={"uname"})
    assert titles(AppArmorCheck().run(ctx)) == ["1 AppArmor profile is in complain mode"]


def test_apparmor_not_in_kernel_skips() -> None:
    ctx = make_ctx()
    assert run_check(AppArmorCheck(), ctx).status is Status.SKIPPED


def test_apparmor_baseline_and_lost_enforcement() -> None:
    base = AppArmorCheck().collect_baseline(aa_ctx())
    assert base == {
        "enabled": True,
        "profiles": {
            "/usr/sbin/cupsd": "enforce",
            "nvidia_modprobe": "complain",
            "snap.lxd.lxc": "enforce",
        },
    }
    now = aa_ctx(profiles="/usr/sbin/cupsd (complain)\nnvidia_modprobe (complain)\n")
    (f,) = AppArmorCheck().compare(now, base)
    assert (f.severity, f.title) == (Severity.WARNING, "2 AppArmor profiles are no longer enforced")
    assert f.evidence == ["/usr/sbin/cupsd: now complain", "snap.lxd.lxc: no longer loaded"]


# --- unattended-upgrades -------------------------------------------------------------

INSTALLED = "ii  bash\nii  unattended-upgrades\n"
DUMP_OK = (
    'APT::Periodic::Update-Package-Lists "1";\n'
    'APT::Periodic::Unattended-Upgrade "1";\n'
    'Unattended-Upgrade::Origins-Pattern "";\n'
    'Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=${distro_codename},label=Debian-Security";\n'
)


def uu_ctx(**kw: Any) -> Any:
    commands = {
        DPKG_RC_ARGV: kw.pop("packages", INSTALLED),
        APT_CONFIG_DUMP: kw.pop("dump", DUMP_OK),
    }
    return make_ctx(commands=commands, **kw)


def test_unattended_ok() -> None:
    assert UnattendedUpgradesCheck().run(uu_ctx()) == []


def test_unattended_not_installed_is_not_a_finding() -> None:
    assert (
        UnattendedUpgradesCheck().run(uu_ctx(packages="ii  bash\nrc  unattended-upgrades\n")) == []
    )


def test_unattended_disabled() -> None:
    for dump in (
        DUMP_OK.replace('Unattended-Upgrade "1"', 'Unattended-Upgrade "0"'),
        DUMP_OK + 'APT::Periodic::Enable "0";\n',
        'APT::Periodic::Update-Package-Lists "1";\n',
    ):
        fs = UnattendedUpgradesCheck().run(uu_ctx(dump=dump))
        assert titles(fs) == ["unattended-upgrades is installed but disabled"], dump


def test_unattended_hardcoded_old_codename() -> None:
    dump = DUMP_OK + 'Unattended-Upgrade::Allowed-Origins:: "Debian:bookworm-security";\n'
    fs = UnattendedUpgradesCheck().run(uu_ctx(dump=dump))
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.WARNING, "unattended-upgrades still names the old release bookworm")
    ]
    assert fs[0].evidence == ['Unattended-Upgrade::Allowed-Origins:: "Debian:bookworm-security";']


def test_unattended_removed_since_baseline() -> None:
    ctx = uu_ctx(packages="ii  bash\n")
    assert UnattendedUpgradesCheck().collect_baseline(uu_ctx()) == {
        "installed": True,
        "enabled": True,
    }
    assert titles(UnattendedUpgradesCheck().compare(ctx, {"installed": True, "enabled": True})) == [
        "unattended-upgrades was removed by the upgrade"
    ]
    assert UnattendedUpgradesCheck().compare(uu_ctx(), {"installed": True, "enabled": True}) == []


# --- ssh-server ----------------------------------------------------------------------


def test_sshd_ok() -> None:
    assert SshServerCheck().run(make_ctx(commands={SSHD_TEST: ""})) == []


def test_sshd_invalid_config_is_critical() -> None:
    res = CommandResult(
        SSHD_TEST, 255, "", "/etc/ssh/sshd_config line 12: Bad configuration option: Protocl\n"
    )
    (f,) = SshServerCheck().run(make_ctx(commands={SSHD_TEST: res}))
    assert (f.severity, f.title) == (Severity.CRITICAL, "The SSH server configuration is invalid")
    assert f.evidence == ["/etc/ssh/sshd_config line 12: Bad configuration option: Protocl"]


def test_sshd_warnings() -> None:
    res = CommandResult(
        SSHD_TEST, 0, "", "/etc/ssh/sshd_config line 3: Deprecated option UsePrivilegeSeparation\n"
    )
    (f,) = SshServerCheck().run(make_ctx(commands={SSHD_TEST: res}))
    assert (f.severity, f.title) == (Severity.WARNING, "sshd warns about its configuration")


def test_dsa_keys_in_authorized_keys() -> None:
    files = {
        "/root/.ssh/authorized_keys": "ssh-ed25519 AAAA root@x\n",
        "/home/alice/.ssh/authorized_keys": "ssh-dss AAAA old@laptop\nssh-ed25519 AAAA new\n",
        "/home/bob/.ssh/authorized_keys2": "# ssh-dss commented out is fine\n",
    }
    fs = SshServerCheck().run(make_ctx(commands={SSHD_TEST: ""}, files=files))
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.WARNING, "DSA keys in authorized_keys no longer work")
    ]
    assert fs[0].evidence == ["/home/alice/.ssh/authorized_keys"]


def test_apparmor_ignores_unparsable_lines() -> None:
    ctx = aa_ctx(
        profiles="garbage without mode\n/usr/sbin/cupsd (enforce)\n",
        denials='some kernel line that matched the search\naudit: apparmor="ALLOWED" profile="x"\n',
    )
    assert AppArmorCheck().run(ctx) == []
    assert AppArmorCheck().collect_baseline(ctx)["profiles"] == {"/usr/sbin/cupsd": "enforce"}


def test_apparmor_compare_nothing_lost() -> None:
    base = {"enabled": True, "profiles": {"/usr/sbin/cupsd": "enforce", "old": "complain"}}
    assert AppArmorCheck().compare(aa_ctx(profiles="/usr/sbin/cupsd (enforce)\n"), base) == []


def test_unattended_ignores_unparsable_config_lines() -> None:
    assert UnattendedUpgradesCheck().run(uu_ctx(dump=DUMP_OK + "garbage\n")) == []


def test_sshd_missing_runtime_directory_is_not_a_config_error() -> None:
    """sshd isn't running (or is socket-activated): systemd creates /run/sshd on start."""
    res = CommandResult(SSHD_TEST, 255, "", "Missing privilege separation directory: /run/sshd\n")
    assert SshServerCheck().run(make_ctx(commands={SSHD_TEST: res})) == []


def test_sshd_config_error_still_reported_with_missing_runtime_directory() -> None:
    res = CommandResult(
        SSHD_TEST,
        255,
        "",
        "/etc/ssh/sshd_config line 5: Bad configuration option: Foo\n"
        "Missing privilege separation directory: /run/sshd\n",
    )
    (f,) = SshServerCheck().run(make_ctx(commands={SSHD_TEST: res}))
    assert f.severity is Severity.CRITICAL
    assert f.evidence == ["/etc/ssh/sshd_config line 5: Bad configuration option: Foo"]
