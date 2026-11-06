"""boot-config: initramfs per kernel, kernel command line and Secure Boot."""

from __future__ import annotations

from pydebuprep.checks.boot_config import SECURE_BOOT_VAR, BootConfigCheck
from pydebuprep.model import Severity

from .helpers import make_ctx, titles

CMDLINE = "/proc/cmdline"
ON = b"\x06\x00\x00\x00\x01"
OFF = b"\x06\x00\x00\x00\x00"


def test_every_kernel_has_an_initramfs() -> None:
    ctx = make_ctx(files={"/boot/vmlinuz-6.1.0": "", "/boot/initrd.img-6.1.0": ""})
    assert BootConfigCheck().run(ctx) == []


def test_a_kernel_without_an_initramfs_is_reported() -> None:
    ctx = make_ctx(files={"/boot/vmlinuz-6.1.0": "", "/boot/vmlinuz-6.12.0": "",
                          "/boot/initrd.img-6.1.0": ""})  # fmt: skip
    (f,) = BootConfigCheck().run(ctx)
    assert (f.severity, f.title) == (Severity.WARNING, "1 kernel has no initramfs")
    assert f.evidence == ["6.12.0"]
    assert f.remediation == ["sudo update-initramfs -c -k 6.12.0"]


def test_baseline_records_the_command_line_and_secure_boot() -> None:
    ctx = make_ctx(files={CMDLINE: "root=UUID=a quiet\n", SECURE_BOOT_VAR: ON})
    assert BootConfigCheck().collect_baseline(ctx) == {
        "cmdline": "root=UUID=a quiet",
        "secure_boot": True,
    }


def test_baseline_without_efi_or_cmdline() -> None:
    assert BootConfigCheck().collect_baseline(make_ctx()) == {"cmdline": None, "secure_boot": None}


def _compare(before: str, now: str, check: BootConfigCheck | None = None) -> list:  # type: ignore[type-arg]
    ctx = make_ctx(files={CMDLINE: now})
    return (check or BootConfigCheck()).compare(ctx, {"cmdline": before})


def test_same_command_line_is_silent() -> None:
    assert _compare("root=UUID=a quiet", "root=UUID=a quiet\n") == []


def test_a_removed_parameter_is_a_warning() -> None:
    (f,) = _compare("root=UUID=a quiet intel_iommu=on", "root=UUID=a quiet")
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "1 kernel parameter was removed or changed since the snapshot",
    )
    assert f.evidence == ["removed: intel_iommu=on"]


def test_a_changed_value_shows_both_values() -> None:
    (f,) = _compare("root=UUID=a mitigations=auto", "root=UUID=a mitigations=off")
    assert f.severity == Severity.WARNING
    assert f.evidence == ["changed: mitigations=auto to mitigations=off"]


def test_a_new_parameter_is_for_information() -> None:
    (f,) = _compare("quiet", "quiet splash")
    assert (f.severity, f.title) == (Severity.INFO, "1 kernel parameter is new since the snapshot")
    assert f.evidence == ["splash"]


def test_the_kernel_image_name_is_left_out_by_default() -> None:
    assert _compare("BOOT_IMAGE=/vmlinuz-6.1.0 quiet", "BOOT_IMAGE=/vmlinuz-6.12.0 quiet") == []


def test_parameters_can_be_left_out() -> None:
    check = BootConfigCheck({"ignore_parameters": ["console", "cloud*"]})
    assert _compare("console=ttyS0 cloud-init=x quiet", "quiet", check) == []


def test_an_unreadable_command_line_is_not_a_change() -> None:
    assert BootConfigCheck().compare(make_ctx(), {"cmdline": "quiet"}) == []


def test_a_snapshot_without_a_command_line_is_not_a_change() -> None:
    assert BootConfigCheck().compare(make_ctx(files={CMDLINE: "quiet"}), {"cmdline": None}) == []


def test_secure_boot_turned_off_is_a_warning() -> None:
    ctx = make_ctx(files={SECURE_BOOT_VAR: OFF})
    (f,) = BootConfigCheck().compare(ctx, {"secure_boot": True})
    assert (f.severity, f.title) == (Severity.WARNING, "Secure Boot was on before and is off now")


def test_secure_boot_turned_on_is_for_information() -> None:
    ctx = make_ctx(files={SECURE_BOOT_VAR: ON})
    assert titles(BootConfigCheck().compare(ctx, {"secure_boot": False})) == [
        "Secure Boot was off before and is on now"
    ]


def test_unknown_or_same_secure_boot_state_is_silent() -> None:
    assert BootConfigCheck().compare(make_ctx(), {"secure_boot": True}) == []
    ctx = make_ctx(files={SECURE_BOOT_VAR: ON})
    assert BootConfigCheck().compare(ctx, {"secure_boot": None}) == []
    assert BootConfigCheck().compare(ctx, {"secure_boot": True}) == []


def test_a_short_efi_variable_is_unknown() -> None:
    ctx = make_ctx(files={SECURE_BOOT_VAR: b"\x06"})
    assert BootConfigCheck().collect_baseline(ctx)["secure_boot"] is None
