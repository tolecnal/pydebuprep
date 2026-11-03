"""The plan: what each cleanup option would remove."""

from __future__ import annotations

from typing import Any

import pytest

from fakes import FakeSystem
from pydebuprep.cleanup.kernels import Package
from pydebuprep.cleanup.plan import (
    OWNER_QUERY,
    PACKAGES_ARGV,
    Choice,
    Refused,
    build_plan,
    leftover_dir_ok,
)
from pydebuprep.system import DisallowedCommandError, check_allowed

PACKAGES = (
    "\n".join(
        "\t".join(row)
        for row in [
            ("ii ", "linux-image-6.8.0-40-generic", "6.8.0-40.40", "15000"),
            ("ii ", "linux-modules-6.8.0-40-generic", "6.8.0-40.40", "90000"),
            ("ii ", "linux-headers-6.8.0-40-generic", "6.8.0-40.40", "3000"),
            ("ii ", "linux-headers-6.8.0-40", "6.8.0-40.40", "70000"),
            ("rc ", "linux-image-6.8.0-38-generic", "6.8.0-38.38", ""),
            ("ii ", "linux-modules-6.8.0-36-generic", "6.8.0-36.36", "90000"),  # image gone
            ("ii ", "linux-image-6.8.0-45-generic", "6.8.0-45.45", "15000"),
            ("ii ", "linux-image-6.8.0-49-generic", "6.8.0-49.49", "15000"),
            ("ii ", "linux-image-generic", "6.8.0-49.49", "20"),
            ("rc ", "hello", "2.10-3", ""),
            ("rc ", "cowsay", "3.03", ""),
            ("ii ", "bash", "5.2", "7000"),
        ]
    )
    + "\n"
)


def system(**kw: Any) -> FakeSystem:
    files = {
        "/lib/modules/6.8.0-49-generic/modules.dep": "",
        "/lib/modules/6.8.0-45-generic/modules.dep": "",
        "/lib/modules/6.8.0-40-generic/modules.dep": "",
        "/lib/modules/6.8.0-30-generic/updates/dkms/zfs.ko": "",  # left by DKMS
        "/lib/modules/6.8.0-31-generic/kernel/x.ko": "",  # still owned by a package
        "/usr/src/linux-headers-6.8.0-30-generic/Makefile": "",
        **kw.pop("files", {}),
    }
    query = (
        *OWNER_QUERY,
        "/lib/modules/6.8.0-30-generic",
        "/lib/modules/6.8.0-31-generic",
        "/lib/modules/6.8.0-40-generic",
        "/usr/src/linux-headers-6.8.0-30-generic",
    )
    owned = (
        "linux-modules-6.8.0-31-generic: /lib/modules/6.8.0-31-generic/kernel/x.ko\n"
        "linux-modules-6.8.0-40-generic, linux-image-6.8.0-40-generic: "
        "/lib/modules/6.8.0-40-generic/modules.dep\n"
    )
    commands = {
        PACKAGES_ARGV: PACKAGES,
        ("uname", "-r"): "6.8.0-49-generic\n",
        query: owned,
        **kw.pop("commands", {}),
    }
    return FakeSystem(files=files, commands=commands, links=kw.pop("links", {}), **kw)


ALL = Choice(
    kernels=True, modules=True, dirs=True, residual=True, keep=2, keep_packages=frozenset()
)


def names(packages: tuple[Package, ...]) -> list[str]:
    return [p.name for p in packages]


def test_plan_kernels_and_modules() -> None:
    plan = build_plan(system(), ALL)
    assert set(plan.kept) == {"6.8.0-45", "6.8.0-49"}
    assert names(plan.kernels) == ["linux-image-6.8.0-38-generic", "linux-image-6.8.0-40-generic"]
    assert "linux-image-generic" not in plan.packages
    assert plan.size_kib == 15000 + 90000 + 3000 + 70000 + 90000


def test_modules_of_already_removed_images() -> None:
    plan = build_plan(system(), ALL)
    assert names(plan.modules) == [
        "linux-headers-6.8.0-40", "linux-headers-6.8.0-40-generic",
        "linux-modules-6.8.0-36-generic", "linux-modules-6.8.0-40-generic",
    ]  # fmt: skip


def test_dirs_only_unowned_unkept_real_directories() -> None:
    sys_ = system(links={"/lib/modules/6.8.0-29-generic": "/etc"})
    plan = build_plan(sys_, ALL)
    # -40's directory belongs to packages this run purges; -31's to one it doesn't.
    assert plan.dirs == (
        "/lib/modules/6.8.0-30-generic", "/lib/modules/6.8.0-40-generic",
        "/usr/src/linux-headers-6.8.0-30-generic",
    )  # fmt: skip
    only_dirs = Choice(
        kernels=False, modules=False, dirs=True, residual=False, keep=2, keep_packages=frozenset()
    )
    assert "/lib/modules/6.8.0-40-generic" not in build_plan(sys_, only_dirs).dirs
    for path in (
        "/lib/modules/../etc",
        "/lib/modules/6.8.0-30-generic/updates",
        "/etc",
        "/usr/src/linux-6.8",
        "/lib/modules/",
        "/usr/src/linux-headers-6.8.0-30-generic/..",
    ):
        assert not leftover_dir_ok(path), path  # fmt: skip
    assert leftover_dir_ok("/usr/src/linux-hwe-6.8-headers-6.8.0-30")


def test_residual_excludes_kernel_packages() -> None:
    assert names(build_plan(system(), ALL).residual) == ["cowsay", "hello"]


def test_keep_package_is_skipped() -> None:
    choice = Choice(
        **{**ALL.__dict__, "keep_packages": frozenset({"hello", "linux-headers-6.8.0-40"})}
    )
    plan = build_plan(system(), choice)
    assert "hello" not in plan.packages and "linux-headers-6.8.0-40" not in plan.packages
    assert plan.skipped == ("hello", "linux-headers-6.8.0-40")


def test_nothing_chosen_plans_nothing() -> None:
    nothing = Choice(
        kernels=False, modules=False, dirs=False, residual=False, keep=2, keep_packages=frozenset()
    )
    sys_ = system()
    plan = build_plan(sys_, nothing)
    assert (plan.packages, plan.dirs) == ((), ())
    assert sys_.calls == [PACKAGES_ARGV]


def test_unknown_running_kernel_refuses_kernel_cleanup() -> None:
    sys_ = system(commands={("uname", "-r"): "6.12.0-custom\n"})
    with pytest.raises(Refused, match="running kernel"):
        build_plan(sys_, ALL)
    residual = Choice(
        kernels=False, modules=False, dirs=False, residual=True, keep=2, keep_packages=frozenset()
    )
    assert names(build_plan(sys_, residual).residual) == ["cowsay", "hello"]


def test_failed_queries_refuse() -> None:
    from pydebuprep.system import CommandResult

    broken = system(
        commands={PACKAGES_ARGV: CommandResult(PACKAGES_ARGV, 2, "", "dpkg-query: error")}
    )
    with pytest.raises(Refused, match="dpkg-query"):
        build_plan(broken, ALL)


def test_grub_default_is_kept() -> None:
    grubenv = "saved_entry=gnulinux-advanced-x>gnulinux-6.8.0-40-generic-advanced-x\n"
    query = (*OWNER_QUERY, "/lib/modules/6.8.0-30-generic", "/lib/modules/6.8.0-31-generic",
             "/usr/src/linux-headers-6.8.0-30-generic")  # fmt: skip
    sys_ = system(files={"/boot/grub/grubenv": grubenv}, commands={query: ""})
    plan = build_plan(sys_, ALL)
    assert "6.8.0-40" in plan.kept and "linux-image-6.8.0-40-generic" not in plan.packages


def test_allowlist_dpkg_query_s_shape() -> None:
    check_allowed(PACKAGES_ARGV)
    check_allowed([*OWNER_QUERY, "/lib/modules/6.8.0-40-generic"])
    check_allowed(
        [*OWNER_QUERY, "/lib/modules/6.8.0-40-generic", "/usr/src/linux-headers-6.8.0-40"]
    )
    for paths in (["/etc/passwd"], ["/lib/modules/../x"], [], ["/lib/modules"], ["-x"],
                  ["/usr/src/linux-headers-6.8.0-40/../../etc"]):  # fmt: skip
        with pytest.raises(DisallowedCommandError):
            check_allowed([*OWNER_QUERY, *paths])


def test_no_candidate_dirs_asks_nothing_and_odd_owner_lines_are_ignored() -> None:
    from pydebuprep.cleanup.plan import owners

    files = {"/lib/modules/6.8.0-49-generic/modules.dep": ""}
    sys_ = FakeSystem(
        files=files, commands={PACKAGES_ARGV: PACKAGES, ("uname", "-r"): "6.8.0-49-generic\n"}
    )
    assert build_plan(sys_, ALL).dirs == ()
    assert not any(c[:2] == OWNER_QUERY for c in sys_.calls)
    query = (*OWNER_QUERY, "/lib/modules/x")
    odd = FakeSystem(commands={query: "garbage\ndiversion by foo to: /lib/modules/x.real\n"})
    assert owners(odd, ["/lib/modules/x"]) == {"/lib/modules/x": set()}
