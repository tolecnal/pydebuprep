"""Which packages belong to which kernel, and which kernels the cleanup keeps."""

from __future__ import annotations

import pytest

from pydebuprep.cleanup.kernels import (
    KEEP_DEFAULT,
    Package,
    grub_default_abi,
    kept_abis,
    kernel_abi,
    kind,
    parse_packages,
    running_abi,
)


def test_parse_packages() -> None:
    text = "ii \tlinux-image-6.8.0-45-generic\t6.8.0-45.45\t15000\nrc \thello\t2.10-3\t\n"
    assert parse_packages(text) == [
        Package("linux-image-6.8.0-45-generic", "ii", "6.8.0-45.45", 15000),
        Package("hello", "rc", "2.10-3", 0),
    ]
    assert parse_packages("garbage\n\n") == []


@pytest.mark.parametrize(
    "name,abi",
    [
        ("linux-image-6.1.0-18-amd64", "6.1.0-18"),
        ("linux-headers-6.1.0-18-common", "6.1.0-18"),
        ("linux-headers-6.1.0-18-amd64", "6.1.0-18"),
        ("linux-image-6.8.0-45-generic", "6.8.0-45"),
        ("linux-modules-extra-6.8.0-45-generic", "6.8.0-45"),
        ("linux-hwe-6.8-headers-6.8.0-45", "6.8.0-45"),
        ("linux-aws-headers-6.8.0-1012", "6.8.0-1012"),
        ("linux-image-unsigned-6.8.0-45-generic", "6.8.0-45"),
        ("linux-headers-6.8.0-45", "6.8.0-45"),
        ("linux-image-6.12.48+deb13-amd64", "6.12.48+deb13"),  # Debian 13 on
        ("linux-headers-6.12.48+deb13-common", "6.12.48+deb13"),
        ("linux-image-6.12.12+bpo-amd64", "6.12.12+bpo"),  # backports
        ("linux-image-6.12.48+deb13-cloud-amd64", "6.12.48+deb13"),
    ],
)
def test_kernel_abi_debian_and_ubuntu(name: str, abi: str) -> None:
    assert kernel_abi(name) == abi


@pytest.mark.parametrize(
    "name",
    ["linux-image-generic", "linux-image-amd64", "linux-generic-hwe-24.04", "linux-kbuild-6.1",
     "linux-libc-dev", "linux-base", "hello", "linux-firmware", "linux-image-6.8"],
)  # fmt: skip
def test_unversioned_packages_never_planned(name: str) -> None:
    assert kernel_abi(name) is None and kind(name) is None


def test_kind() -> None:
    assert kind("linux-image-6.8.0-45-generic") == "image"
    assert kind("linux-image-unsigned-6.8.0-45-generic") == "image"
    for name in ("linux-modules-6.8.0-45-generic", "linux-headers-6.1.0-18-common",
                 "linux-tools-6.8.0-45-generic", "linux-hwe-6.8-headers-6.8.0-45"):  # fmt: skip
        assert kind(name) == "modules"


def test_running_and_grub_abi() -> None:
    assert running_abi("6.8.0-45-generic\n") == "6.8.0-45"
    assert running_abi("6.12.48+deb13-amd64") == "6.12.48+deb13"
    assert running_abi("6.12.0-custom") is None  # a kernel built by hand: unknown
    grubenv = "# GRUB Environment Block\nsaved_entry=gnulinux-advanced-x>gnulinux-6.8.0-40-generic-advanced-x\n"
    assert grub_default_abi(grubenv) == "6.8.0-40"
    assert grub_default_abi("saved_entry=0\n") is None
    assert grub_default_abi(None) is None


ABIS = ["6.8.0-40", "6.8.0-45", "6.8.0-47", "6.8.0-49"]


def test_kept_newest_two_and_running() -> None:
    assert KEEP_DEFAULT == 2
    assert kept_abis(ABIS, running="6.8.0-49", grub=None, keep=2) == {"6.8.0-47", "6.8.0-49"}


def test_pending_reboot_keeps_both() -> None:
    assert kept_abis(ABIS, running="6.8.0-45", grub=None, keep=1) == {"6.8.0-45", "6.8.0-49"}


def test_grub_default_kept() -> None:
    kept = kept_abis(ABIS, running="6.8.0-49", grub="6.8.0-40", keep=2)
    assert kept == {"6.8.0-40", "6.8.0-47", "6.8.0-49"}


def test_unknown_running_still_keeps_the_newest() -> None:
    assert kept_abis(ABIS, running=None, grub=None, keep=1) == {"6.8.0-49"}
    assert kept_abis([], running="6.8.0-1", grub=None, keep=2) == {"6.8.0-1"}


def test_debian_13_versions_sort_by_patch_level() -> None:
    kept = kept_abis(
        ["6.12.38+deb13", "6.12.48+deb13", "6.12.41+deb13"], running=None, grub=None, keep=2
    )
    assert kept == {"6.12.48+deb13", "6.12.41+deb13"}


def test_numeric_sort() -> None:
    kept = kept_abis(["6.8.0-99", "6.8.0-100", "6.10.0-1"], running=None, grub=None, keep=1)
    assert kept == {"6.10.0-1"}
