from __future__ import annotations

from pydebuprep.checks.apt_autoremove import AptAutoremoveCheck
from pydebuprep.checks.apt_held import AptHeldCheck
from pydebuprep.checks.apt_upgradable import AptUpgradableCheck
from pydebuprep.checks.dpkg_audit import DpkgAuditCheck
from pydebuprep.checks.dpkg_rc import DPKG_RC_ARGV, DpkgRcCheck
from pydebuprep.checks.obsolete_packages import PKG_VERSIONS_ARGV, ObsoletePackagesCheck
from pydebuprep.model import Severity
from pydebuprep.system import CommandResult

from .helpers import make_ctx, titles

AUDIT = ("dpkg", "--audit")
CHECK = ("apt-get", "check")
UPGRADABLE = ("apt", "list", "--upgradable")
HELD = ("apt-mark", "showhold")
AUTOREMOVE = ("apt-get", "-s", "autoremove")
INSTALLED = ("apt", "list", "--installed")


def test_dpkg_clean() -> None:
    ctx = make_ctx(commands={AUDIT: "", CHECK: "Reading package lists...\n"})
    assert DpkgAuditCheck().run(ctx) == []


def test_audit_output_critical() -> None:
    out = "The following packages are only half configured:\n foo  Foo package\n"
    ctx = make_ctx(commands={AUDIT: out, CHECK: ""})
    (f,) = DpkgAuditCheck().run(ctx)
    assert f.severity is Severity.CRITICAL
    assert "sudo dpkg --configure -a" in f.remediation
    assert " foo  Foo package" in f.evidence


def test_apt_check_failure_critical() -> None:
    bad = CommandResult(CHECK, 100, "", "E: Unmet dependencies.\n")
    ctx = make_ctx(commands={AUDIT: "", CHECK: bad})
    (f,) = DpkgAuditCheck().run(ctx)
    assert f.severity is Severity.CRITICAL
    assert f.evidence == ["E: Unmet dependencies."]


def test_upgradable_none() -> None:
    ctx = make_ctx(commands={UPGRADABLE: "Listing... Done\n"})
    assert AptUpgradableCheck().run(ctx) == []


def test_upgradable_some_warns_with_count() -> None:
    out = (
        "Listing... Done\n"
        "\nWARNING: apt does not have a stable CLI interface.\n"
        "curl/stable 8.14.1-2 amd64 [upgradable from: 8.14.1-1]\n"
        "libcurl4t64/stable 8.14.1-2 amd64 [upgradable from: 8.14.1-1]\n"
    )
    (f,) = AptUpgradableCheck().run(make_ctx(commands={UPGRADABLE: out}))
    assert (f.severity, f.title) == (Severity.WARNING, "2 packages can still be upgraded")
    assert f.evidence[0].startswith("curl/stable")


def test_held_warns() -> None:
    (f,) = AptHeldCheck().run(make_ctx(commands={HELD: "linux-image-amd64\nzfsutils-linux\n"}))
    assert f.severity is Severity.WARNING
    assert f.evidence == ["linux-image-amd64", "zfsutils-linux"]


def test_held_none() -> None:
    assert AptHeldCheck().run(make_ctx(commands={HELD: ""})) == []


def test_held_compare_new_hold() -> None:
    ctx = make_ctx(commands={HELD: "b\nc\n"})
    fs = AptHeldCheck().compare(ctx, ["a", "b"])
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.WARNING, "1 package newly held since baseline"),
        (Severity.INFO, "1 package no longer held since baseline"),
    ]


def test_autoremove_parses_remv_lines() -> None:
    out = (
        "NOTE: This is only a simulation!\n"
        "Reading package lists...\n"
        "Remv libfoo1 [1.0-1]\n"
        "Remv linux-image-6.1.0-25-amd64 [6.1.106-3]\n"
    )
    (f,) = AptAutoremoveCheck().run(make_ctx(commands={AUTOREMOVE: out}))
    assert (f.severity, f.title) == (Severity.INFO, "2 packages are no longer needed")
    assert f.evidence == ["libfoo1 [1.0-1]", "linux-image-6.1.0-25-amd64 [6.1.106-3]"]


def test_autoremove_none() -> None:
    assert AptAutoremoveCheck().run(make_ctx(commands={AUTOREMOVE: "0 upgraded\n"})) == []


def test_rc_packages_info() -> None:
    out = "ii  bash\nrc  oldpkg\nrc  other\nii  zsh\n"
    (f,) = DpkgRcCheck().run(make_ctx(commands={DPKG_RC_ARGV: out}))
    assert (f.severity, f.title) == (
        Severity.INFO,
        "2 removed packages still have configuration files",
    )
    assert f.remediation[-1] == "sudo apt purge oldpkg other"


def test_rc_purge_command_batches_of_20() -> None:
    out = "".join(f"rc  p{i}\n" for i in range(45))
    (f,) = DpkgRcCheck().run(make_ctx(commands={DPKG_RC_ARGV: out}))
    purges = [r for r in f.remediation if r.startswith("sudo apt purge")]
    assert len(purges) == 3


def test_local_packages_warn() -> None:
    out = (
        "Listing... Done\n"
        "bash/stable,now 5.2.37-2 amd64 [installed]\n"
        "oldlib/now 1.2-3 amd64 [installed,local]\n"
        "mytool/now 0.1 all [installed,local]\n"
    )
    (f,) = ObsoletePackagesCheck().run(make_ctx(commands={INSTALLED: out}))
    assert f.severity is Severity.WARNING
    assert f.title == "2 installed packages are not available from any configured repository"
    assert f.evidence == ["oldlib 1.2-3", "mytool 0.1"]


def test_no_local_packages() -> None:
    out = "Listing... Done\nbash/stable,now 5.2.37-2 amd64 [installed]\n"
    assert ObsoletePackagesCheck().run(make_ctx(commands={INSTALLED: out})) == []


def test_compare_removed_packages() -> None:
    ctx = make_ctx(commands={PKG_VERSIONS_ARGV: "bash\t5.2\nzsh\t5.9\n"})
    assert ObsoletePackagesCheck().collect_baseline(ctx) == {"bash": "5.2", "zsh": "5.9"}
    fs = ObsoletePackagesCheck().compare(ctx, {"bash": "5.1", "python3.11": "3.11.2", "zsh": "5.9"})
    assert titles(fs) == ["1 package removed since baseline"]
    assert fs[0].evidence == ["python3.11 3.11.2"]
