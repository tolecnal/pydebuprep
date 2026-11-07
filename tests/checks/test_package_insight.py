"""apt-upgradable groups, dpkg-audit states, obsolete-packages origins."""

from __future__ import annotations

from typing import Any

from pydebuprep.checks.apt_upgradable import SIMULATE_UPGRADE, AptUpgradableCheck
from pydebuprep.model import Finding, Severity

from .helpers import make_ctx

UPGRADABLE = ("apt", "list", "--upgradable")
LIST = (
    "Listing... Done\n"
    "\nWARNING: apt does not have a stable CLI interface.\n"
    "base-files/noble-updates 13ubuntu10.5 amd64 [upgradable from: 13ubuntu10.4]\n"
    "libc6/noble-updates,noble-security 2.39-0ubuntu8.9 amd64 [upgradable from: 2.39-0ubuntu8.7]\n"
    "liblzma5/oldstable-security 5.4.1-1+deb12u2 amd64 [upgradable from: 5.4.1-1]\n"
    "mesa-vulkan-drivers/noble-updates 25.0.7 amd64 [upgradable from: 24.2.8]\n"
    "linux-generic/noble-updates 6.8.0.90 amd64 [upgradable from: 6.8.0.85]\n"
)
SIMULATION = """Reading package lists...
Calculating upgrade...
The following upgrades have been deferred due to phasing:
  mesa-vulkan-drivers
The following packages have been kept back:
  linux-generic
The following packages will be upgraded:
  base-files libc6 liblzma5
3 upgraded, 0 newly installed, 0 to remove and 2 not upgraded.
"""


def upgradable(list_out: str = LIST, simulation: str = SIMULATION) -> list[Any]:
    commands = {UPGRADABLE: list_out, SIMULATE_UPGRADE: simulation}
    return AptUpgradableCheck().run(make_ctx(commands=commands))


def test_upgrades_are_grouped() -> None:
    fs = upgradable()
    assert [(f.severity, f.title, f.evidence) for f in fs] == [
        (Severity.WARNING, "2 security updates are pending", [
            "libc6 2.39-0ubuntu8.9 (noble-updates,noble-security)",
            "liblzma5 5.4.1-1+deb12u2 (oldstable-security)",
        ]),
        (Severity.WARNING, "1 package is kept back", ["linux-generic"]),
        (Severity.INFO, "1 update is deferred by phasing", ["mesa-vulkan-drivers"]),
        (Severity.INFO, "1 other package can be upgraded", ["base-files 13ubuntu10.5 (noble-updates)"]),
    ]  # fmt: skip
    assert fs[1].remediation[0] == "See why: sudo apt-get -s install linux-generic"
    assert "phased" in fs[2].detail


def test_only_ordinary_updates() -> None:
    out = "Listing...\ncurl/stable 8.14.1-2 amd64 [upgradable from: 8.14.1-1]\n"
    (f,) = upgradable(out, "Calculating upgrade...\n1 upgraded, 0 newly installed\n")
    assert (f.severity, f.title) == (Severity.INFO, "1 other package can be upgraded")


def test_nothing_upgradable_runs_no_simulation() -> None:
    ctx = make_ctx(commands={UPGRADABLE: "Listing... Done\n"})
    assert AptUpgradableCheck().run(ctx) == []
    assert SIMULATE_UPGRADE not in [c[:1] + c[-2:] for c in ctx.system.calls]  # type: ignore[attr-defined]


def test_kept_back_security_update_counts_as_security() -> None:
    simulation = "The following packages have been kept back:\n  libc6\n0 upgraded\n"
    out = "Listing...\nlibc6/noble-security 2.39 amd64 [upgradable from: 2.38]\n"
    (f,) = upgradable(out, simulation)
    assert f.title == "1 security update is pending"


# --- dpkg-audit ----------------------------------------------------------------------

from pydebuprep.checks.dpkg_audit import DpkgAuditCheck  # noqa: E402
from pydebuprep.checks.dpkg_rc import DPKG_RC_ARGV  # noqa: E402

AUDIT = ("dpkg", "--audit")
CHECK = ("apt-get", "check")
DPKG_AUDIT_OUT = "The following packages are only half configured:\n foo  Foo\n"


def audit(states: str, dpkg_audit: str = "") -> list[Any]:
    commands = {AUDIT: dpkg_audit, CHECK: "", DPKG_RC_ARGV: states}
    return DpkgAuditCheck().run(make_ctx(commands=commands))


def test_package_states_are_separate_findings() -> None:
    states = "ii  bash\niU  libfoo1\niF  foo\niH  bar\niiR baz\niW  qux\nit  quux\nrc  old\n"
    fs = audit(states, DPKG_AUDIT_OUT)
    assert [(f.severity, f.title, f.evidence, f.remediation[0]) for f in fs] == [
        (Severity.CRITICAL, "2 packages are unpacked but not configured",
         ["foo (half-configured)", "libfoo1 (unpacked)"], "sudo dpkg --configure -a"),
        (Severity.CRITICAL, "2 packages need reinstalling",
         ["bar (half-installed)", "baz (reinstall required)"], "sudo apt install --reinstall bar baz"),
        (Severity.WARNING, "2 packages are waiting for triggers",
         ["quux (triggers pending)", "qux (triggers awaited)"], "sudo dpkg --triggers-only -a"),
    ]  # fmt: skip


def test_dpkg_audit_output_is_kept_when_states_look_fine() -> None:
    # dpkg --audit also reports what states don't show (e.g. missing file lists).
    out = "The following packages are missing the list control file:\n foo\n"
    (f,) = audit("ii  bash\n", out)
    assert f.title == "dpkg reports broken or half-configured packages"
    assert audit("ii  bash\n") == []


# --- obsolete-packages: origins ------------------------------------------------------

import gzip  # noqa: E402

from pydebuprep.checks.obsolete_packages import PKG_VERSIONS_ARGV, ObsoletePackagesCheck  # noqa: E402

LISTS = "/var/lib/apt/lists"
INSTALLED_LIST = ("apt", "list", "--installed")
INSTALLED = "bash\t5.2.37-2\ndocker-ce\t5:28.1\ncontainerd.io\t1.7\nterraform\t1.9.0\nmytool\t0.1\ncurl\t8.14\n"


def release(origin: str) -> str:
    return f"Origin: {origin}\nLabel: {origin}\nSuite: stable\n"


def packages(*entries: tuple[str, str]) -> str:
    return "\n".join(f"Package: {n}\nArchitecture: amd64\nVersion: {v}\n" for n, v in entries)


LIST_FILES: dict[str, Any] = {
    f"{LISTS}/deb.debian.org_debian_dists_trixie_InRelease": release("Debian"),
    f"{LISTS}/deb.debian.org_debian_dists_trixie_main_binary-amd64_Packages": packages(
        ("bash", "5.2.37-2"), ("curl", "8.14"), ("containerd.io", "1.6")
    ),
    f"{LISTS}/download.docker.com_linux_debian_dists_trixie_InRelease": release("Docker"),
    f"{LISTS}/download.docker.com_linux_debian_dists_trixie_stable_binary-amd64_Packages": packages(
        ("docker-ce", "5:28.1"), ("containerd.io", "1.7")
    ),
    # no InRelease: named after the host
    f"{LISTS}/apt.releases.hashicorp.com_dists_trixie_main_binary-all_Packages": packages(
        ("terraform", "1.9.0"), ("curl", "8.14")
    ),
}


def obsolete(files: dict[str, Any] | None = None, installed: str = INSTALLED) -> Any:
    commands = {INSTALLED_LIST: "Listing... Done\n", PKG_VERSIONS_ARGV: installed}
    return make_ctx(commands=commands, files=LIST_FILES if files is None else files)


def test_third_party_packages_grouped_by_origin() -> None:
    (f,) = ObsoletePackagesCheck().run(obsolete())
    assert (f.severity, f.title) == (
        Severity.INFO,
        "3 packages come from third-party repositories",
    )
    assert f.evidence == [
        "Docker (download.docker.com): containerd.io, docker-ce",
        "apt.releases.hashicorp.com: terraform",
    ]


def test_compressed_lists_are_read() -> None:
    files = {k: v for k, v in LIST_FILES.items() if "docker" not in k}
    name = f"{LISTS}/download.docker.com_linux_debian_dists_trixie_stable_binary-amd64_Packages"
    files[f"{LISTS}/download.docker.com_linux_debian_dists_trixie_InRelease"] = release("Docker")
    files[name + ".gz"] = gzip.compress(packages(("docker-ce", "5:28.1")).encode())
    files[name.replace("binary-amd64", "binary-i386") + ".lz4"] = "unreadable here"
    (f,) = ObsoletePackagesCheck().run(obsolete(files))
    assert "Docker (download.docker.com): docker-ce" in f.evidence


def test_no_lists_no_origins() -> None:
    assert ObsoletePackagesCheck().run(obsolete({})) == []


def test_origin_changes_since_the_snapshot() -> None:
    check = ObsoletePackagesCheck()
    before = check.collect_baseline(obsolete())
    assert before["origins"]["docker-ce"] == "Docker (download.docker.com)"
    assert before["origins"]["bash"] == "Debian"
    assert "mytool" not in before["origins"]  # origin unknown
    # Upgrade: containerd.io now from Debian, terraform's repository gone.
    after = obsolete(installed=INSTALLED.replace("containerd.io\t1.7", "containerd.io\t1.6"))
    fs = check.compare(after, before)
    assert [(f.severity, f.title, f.evidence) for f in fs if "origin" in f.title] == [
        (Severity.WARNING, "1 package comes from a different origin than before the upgrade",
         ["containerd.io: Docker (download.docker.com) → Debian"]),
    ]  # fmt: skip


def test_malformed_dpkg_query_lines_are_skipped() -> None:
    assert audit("garbage\nii\n\nii  bash\n") == []


def test_corrupt_compressed_list_is_skipped() -> None:
    files = {
        f"{LISTS}/download.docker.com_linux_debian_dists_trixie_InRelease": release("Docker"),
        f"{LISTS}/download.docker.com_linux_debian_dists_trixie_stable_binary-amd64_Packages.gz": b"not gzip",
    }
    assert ObsoletePackagesCheck().run(obsolete(files)) == []


def test_unchanged_origins_report_nothing() -> None:
    check = ObsoletePackagesCheck()
    before = check.collect_baseline(obsolete())
    assert check.compare(obsolete(), before) == []


# --- final review fixes --------------------------------------------------------------

from pydebuprep.system import CommandResult  # noqa: E402


def test_broken_dependencies_dont_stop_the_upgrade_groups() -> None:
    broken = CommandResult(
        SIMULATE_UPGRADE, 100, "", "E: Unmet dependencies. Try 'apt --fix-broken install'\n"
    )
    commands = {UPGRADABLE: LIST, SIMULATE_UPGRADE: broken}
    fs = AptUpgradableCheck().run(make_ctx(commands=commands))
    assert fs[0].title == "2 security updates are pending"


def test_vendor_origin_renamed_with_the_release_is_not_a_change() -> None:
    files = dict(LIST_FILES)
    docker = f"{LISTS}/download.docker.com_linux_debian_dists_trixie_InRelease"
    files[docker] = release("Docker bookworm")
    before = ObsoletePackagesCheck().collect_baseline(obsolete(files))
    files[docker] = release("Docker trixie")
    assert ObsoletePackagesCheck().compare(obsolete(files), before) == []


def test_ubuntu_pro_origins_are_the_distribution() -> None:
    files = dict(LIST_FILES)
    esm = f"{LISTS}/esm.ubuntu.com_apps_ubuntu_dists_noble-apps-security"
    files[f"{esm}_InRelease"] = release("UbuntuESMApps")
    files[f"{esm}_main_binary-amd64_Packages"] = packages(("mytool", "0.1"))
    (f,) = ObsoletePackagesCheck().run(obsolete(files))
    assert all("mytool" not in e for e in f.evidence)


def test_package_indexes_are_streamed() -> None:
    # Never read whole: Ubuntu's indexes are tens of megabytes each.
    ctx = obsolete()
    ObsoletePackagesCheck().run(ctx)
    assert not any("_Packages" in p for p in ctx.system.whole_reads)  # type: ignore[attr-defined]


# --- obsolete-packages: what changed ----------------------------------------------------

EXTENDED = "/var/lib/apt/extended_states"
STATES_FILE = (
    "Package: libfoo\nArchitecture: amd64\nAuto-Installed: 1\n\n"
    "Package: bar\nArchitecture: amd64\nAuto-Installed: 0\n\n"
    "Package: lib2\nAuto-Installed: 1\n"
)


def _versions(**versions: str) -> str:
    return "".join(f"{name}\t{version}\n" for name, version in versions.items())


def _compare_changes(before: dict[str, object], now: str, files: dict[str, str] | None = None,
                     check: ObsoletePackagesCheck | None = None) -> list[Finding]:  # fmt: skip
    ctx = make_ctx(commands={PKG_VERSIONS_ARGV: now}, files=files or {})
    return (check or ObsoletePackagesCheck()).compare(ctx, before)


def test_baseline_records_manual_packages() -> None:
    ctx = make_ctx(
        commands={PKG_VERSIONS_ARGV: _versions(libfoo="1", bar="1", baz="1")},
        files={EXTENDED: STATES_FILE},
    )
    assert ObsoletePackagesCheck().collect_baseline(ctx)["manual"] == ["bar", "baz"]


def test_baseline_without_apt_states_records_no_manual_packages() -> None:
    ctx = make_ctx(commands={PKG_VERSIONS_ARGV: _versions(bar="1")})
    assert "manual" not in ObsoletePackagesCheck().collect_baseline(ctx)


def test_version_changes_are_summed_up_not_listed() -> None:
    fs = _compare_changes(
        {"versions": {"a": "1", "b": "2", "c": "1"}},
        _versions(a="2", b="2", c="2", d="1", e="1"),
    )
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.INFO, "Since the snapshot: 2 packages upgraded, 2 new")
    ]
    assert fs[0].evidence == ["New: d, e"]


def test_a_downgrade_is_a_warning() -> None:
    fs = _compare_changes({"versions": {"a": "2"}}, _versions(a="1"))
    assert [(f.severity, f.title, f.evidence) for f in fs] == [
        (Severity.WARNING, "1 package has an older version than before the upgrade", ["a: 2 to 1"])
    ]


def test_a_removed_manual_package_is_a_warning() -> None:
    fs = _compare_changes({"versions": {"a": "1", "b": "1", "c": "1"}, "manual": ["a", "c"]},
                          _versions(c="1"))  # fmt: skip
    assert [(f.severity, f.title, f.evidence) for f in fs] == [
        (Severity.WARNING, "1 package marked as installed by hand was removed", ["a 1"]),
        (Severity.INFO, "1 package removed since baseline", ["b 1"]),
    ]


def test_a_manual_package_now_automatic_is_a_warning() -> None:
    fs = _compare_changes(
        {"versions": {"libfoo": "1", "bar": "1"}, "manual": ["libfoo", "bar"]},
        _versions(libfoo="1", bar="1"),
        {EXTENDED: STATES_FILE},
    )
    assert [(f.severity, f.title, f.evidence) for f in fs] == [
        (
            Severity.WARNING,
            "1 package marked as installed by hand is now marked automatic",
            ["libfoo"],
        )
    ]


def test_no_apt_states_now_says_nothing_about_marks() -> None:
    assert _compare_changes({"versions": {"a": "1"}, "manual": ["a"]}, _versions(a="1")) == []


def test_a_protected_package_that_is_gone_is_critical() -> None:
    check = ObsoletePackagesCheck({"protected_packages": ["openssh-server", "bash"]})
    fs = check._protected(make_ctx(commands={PKG_VERSIONS_ARGV: _versions(bash="5")}))
    assert [(f.severity, f.title, f.evidence) for f in fs] == [
        (Severity.CRITICAL, "1 protected package isn't installed", ["openssh-server"])
    ]


def test_no_protected_packages_asks_nothing() -> None:
    assert ObsoletePackagesCheck()._protected(make_ctx()) == []


def test_protected_packages_that_are_installed_are_silent() -> None:
    check = ObsoletePackagesCheck({"protected_packages": ["bash"]})
    assert check._protected(make_ctx(commands={PKG_VERSIONS_ARGV: _versions(bash="5")})) == []


def test_a_manual_package_still_manual_is_silent() -> None:
    fs = _compare_changes(
        {"versions": {"bar": "1"}, "manual": ["bar"]}, _versions(bar="1"), {EXTENDED: STATES_FILE}
    )
    assert fs == []


def test_a_removed_library_is_not_called_installed_by_hand() -> None:
    """A base system's libraries aren't marked automatic either, and upgrades rename them."""
    fs = _compare_changes(
        {"versions": {"libssl3": "3", "tool": "1"}, "manual": ["libssl3", "tool"]}, _versions()
    )
    assert [(f.severity, f.title, f.evidence) for f in fs] == [
        (Severity.WARNING, "1 package marked as installed by hand was removed", ["tool 1"]),
        (Severity.INFO, "1 package removed since baseline", ["libssl3 3"]),
    ]
