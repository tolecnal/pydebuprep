"""The plan: what each cleanup option would remove."""

from __future__ import annotations

from typing import Any

import pytest

from fakes import FakeSystem
from pydebuprep.cleanup.kernels import Package
from pydebuprep.cleanup.plan import (
    ARCH_ARGV,
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


def owner_query(*paths: str) -> tuple[str, ...]:
    """dpkg-query -S as the planner asks it: each kernel module directory under both of
    its spellings."""
    spellings = [
        q for p in paths for q in ([p, "/usr" + p] if p.startswith("/lib/modules/") else [p])
    ]
    return (*OWNER_QUERY, *spellings)


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
    query = owner_query(
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
        ARCH_ARGV: "amd64\n",
        query: owned,
        # Asked when kernel 6.8.0-40 stays: its directory is left out up front.
        owner_query(
            "/lib/modules/6.8.0-30-generic",
            "/lib/modules/6.8.0-31-generic",
            "/usr/src/linux-headers-6.8.0-30-generic",
        ): owned,
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
    assert sys_.calls == [PACKAGES_ARGV, ARCH_ARGV]


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
    sys_ = system(files={"/boot/grub/grubenv": grubenv}, commands={GRUB_QUERY: ""})
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
        files=files,
        commands={
            PACKAGES_ARGV: PACKAGES,
            ARCH_ARGV: "amd64\n",
            ("uname", "-r"): "6.8.0-49-generic\n",
        },
    )
    assert build_plan(sys_, ALL).dirs == ()
    assert not any(c[:2] == OWNER_QUERY for c in sys_.calls)
    query = owner_query("/lib/modules/x")
    odd = FakeSystem(commands={query: "garbage\ndiversion by foo to: /lib/modules/x.real\n"})
    assert owners(odd, ["/lib/modules/x"]) == {"/lib/modules/x": set()}


def test_usr_lib_modules_owners_count(tmp_path: object) -> None:
    # Debian 13 records kernel files under /usr/lib/modules; dpkg doesn't alias /lib.
    query = owner_query("/lib/modules/6.8.0-30-generic")
    sys_ = FakeSystem(
        files={"/lib/modules/6.8.0-30-generic/kernel/x.ko": ""},
        commands={
            query: "linux-image-6.8.0-30-generic: /usr/lib/modules/6.8.0-30-generic/kernel/x.ko\n"
        },
    )
    from pydebuprep.cleanup.plan import owners

    assert owners(sys_, ["/lib/modules/6.8.0-30-generic"]) == {
        "/lib/modules/6.8.0-30-generic": {"linux-image-6.8.0-30-generic"}
    }


def test_installed_kernel_directory_never_planned_whatever_dpkg_says() -> None:
    # Even if dpkg-query -S misses it, a directory whose kernel still has an installed
    # package that this run doesn't purge stays.
    rows = PACKAGES + "ii \tlinux-image-6.8.0-30-generic\t6.8.0-30.30\t15000\n"
    keep_30 = Choice(
        kernels=False, modules=False, dirs=True, residual=False, keep=2, keep_packages=frozenset()
    )
    only_31 = owner_query("/lib/modules/6.8.0-31-generic")  # -30 and -40 left out up front
    sys_ = system(commands={PACKAGES_ARGV: rows, only_31: ""})
    assert "/lib/modules/6.8.0-30-generic" not in build_plan(sys_, keep_30).dirs


def test_held_and_half_installed_packages() -> None:
    rows = (
        "\n".join(
            [
                "hi \tlinux-image-6.8.0-40-generic\t6.8.0-40.40\t15000",  # held: kept, and counts
                "iU \tlinux-image-6.8.0-38-generic\t6.8.0-38.38\t15000",  # unpacked: installed
                "ii \tlinux-image-6.8.0-49-generic\t6.8.0-49.49\t15000",
                "ii \tlinux-image-6.8.0-45-generic\t6.8.0-45.45\t15000",
                "hc \theld-config\t1\t",
                "rc \thello\t2.10-3\t",
            ]
        )
        + "\n"
    )
    sys_ = system(commands={PACKAGES_ARGV: rows})
    plan = build_plan(sys_, ALL)
    assert "linux-image-6.8.0-40-generic" not in plan.packages
    assert "linux-image-6.8.0-40-generic" in plan.skipped and "held-config" in plan.skipped
    assert names(plan.kernels) == ["linux-image-6.8.0-38-generic"]
    assert names(plan.residual) == ["hello"]


def test_headers_only_kernels_dont_count_as_kept_kernels() -> None:
    # Headers of a newer kernel whose image isn't installed (yet) must not crowd the
    # kept set: the newest image and the running one stay.
    rows = (
        "\n".join(
            [
                "ii \tlinux-image-6.8.0-45-generic\t6.8.0-45.45\t15000",
                "ii \tlinux-image-6.8.0-48-generic\t6.8.0-48.48\t15000",
                "ii \tlinux-headers-6.8.0-50-generic\t6.8.0-50.50\t3000",
            ]
        )
        + "\n"
    )
    one = Choice(
        kernels=True, modules=False, dirs=False, residual=False, keep=1, keep_packages=frozenset()
    )
    sys_ = system(commands={PACKAGES_ARGV: rows, ("uname", "-r"): "6.8.0-45-generic\n"})
    plan = build_plan(sys_, one)
    assert set(plan.kept) >= {"6.8.0-45", "6.8.0-48"} and plan.kernels == ()


def test_foreign_architecture_names() -> None:
    rows = "rc \tlibfoo1:i386\t1\t\nrc \tlibfoo1:amd64\t1\t\n"
    nothing_but_residual = Choice(
        kernels=False,
        modules=False,
        dirs=False,
        residual=True,
        keep=2,
        keep_packages=frozenset({"libfoo1:amd64"}),
    )
    plan = build_plan(system(commands={PACKAGES_ARGV: rows}), nothing_but_residual)
    assert names(plan.residual) == ["libfoo1:i386"] and plan.skipped == ("libfoo1:amd64",)
    plain = Choice(
        kernels=False,
        modules=False,
        dirs=False,
        residual=True,
        keep=2,
        keep_packages=frozenset({"libfoo1"}),
    )
    assert (
        build_plan(system(commands={PACKAGES_ARGV: rows}), plain).residual == ()
    )  # a base name keeps both


GRUB_QUERY = owner_query(
    "/lib/modules/6.8.0-30-generic",
    "/lib/modules/6.8.0-31-generic",
    "/usr/src/linux-headers-6.8.0-30-generic",
)


@pytest.mark.parametrize(
    "files,kept",
    [
        (
            {
                "/etc/default/grub": 'GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux 6.8.0-40-generic"\n'
            },
            "6.8.0-40",
        ),
        (
            {
                "/etc/default/grub": "GRUB_DEFAULT=0\n",
                "/etc/default/grub.d/50-pin.cfg": "GRUB_DEFAULT='gnulinux-6.8.0-40-generic-advanced-x'\n",
            },
            "6.8.0-40",
        ),
        (
            {
                "/etc/default/grub": "GRUB_DEFAULT=saved\n",
                "/boot/grub/grubenv": "saved_entry=0\nnext_entry=gnulinux-6.8.0-40-generic-advanced-x\n",
            },
            "6.8.0-40",
        ),
    ],
)
def test_grub_pins_are_kept(files: dict[str, str], kept: str) -> None:
    plan = build_plan(system(files=files, commands={GRUB_QUERY: ""}), ALL)
    assert kept in plan.kept and "linux-image-6.8.0-40-generic" not in plan.packages


@pytest.mark.parametrize("value", ["2", '"1>2"', "'Debian GNU/Linux'"])
def test_grub_default_we_cant_resolve_refuses_kernel_cleanup(value: str) -> None:
    sys_ = system(files={"/etc/default/grub": f"# comment\nGRUB_DEFAULT={value}\n"})
    with pytest.raises(Refused, match="GRUB_DEFAULT"):
        build_plan(sys_, ALL)
    residual = Choice(
        kernels=False, modules=False, dirs=False, residual=True, keep=2, keep_packages=frozenset()
    )
    assert build_plan(sys_, residual).residual  # the rest still works


def test_grub_default_zero_and_saved_pin_nothing_extra() -> None:
    for text in ("GRUB_DEFAULT=0\n", "GRUB_DEFAULT=saved\n", "export GRUB_DEFAULT=\n"):
        plan = build_plan(system(files={"/etc/default/grub": text}), ALL)
        assert set(plan.kept) == {"6.8.0-45", "6.8.0-49"}, text


def test_plan_knows_the_native_architecture() -> None:
    assert build_plan(system(), ALL).arch == "amd64"
    from pydebuprep.system import check_allowed

    check_allowed(ARCH_ARGV)
