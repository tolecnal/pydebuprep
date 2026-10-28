from __future__ import annotations

import pytest

from pydebuprep.checks._diskutil import space_findings
from pydebuprep.checks.boot_space import BootSpaceCheck
from pydebuprep.checks.bootloader import BootloaderCheck
from pydebuprep.checks.dkms import DkmsCheck, parse_dkms_status
from pydebuprep.checks.kernel_running import (
    KernelRunningCheck,
    compare_versions,
    installed_kernels,
)
from pydebuprep.checks.needrestart import NeedrestartCheck
from pydebuprep.model import Severity
from pydebuprep.system import DiskUsage

from .helpers import make_ctx, titles

UNAME = ("uname", "-r")
OLD, NEW = "6.8.0-45-generic", "6.8.0-100-generic"
VMLINUZ = {f"/boot/vmlinuz-{OLD}": "", f"/boot/vmlinuz-{NEW}": ""}


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("6.8.0-45-generic", "6.8.0-100-generic", -1),
        ("6.12.48+deb13-amd64", "6.12.48+deb13-amd64", 0),
        ("6.1.0-26-amd64", "6.12.48+deb13-amd64", -1),
        ("1.0~rc1", "1.0", -1),
        ("1:1.0", "2.0", 1),
        ("1.0a", "1.0", 1),
        ("1.0-1", "1.0+1", -1),
    ],
)
def test_compare_versions(a: str, b: str, expected: int) -> None:
    assert compare_versions(a, b) == expected
    assert compare_versions(b, a) == -expected


def test_installed_kernels_sorted() -> None:
    assert installed_kernels(make_ctx(files=VMLINUZ).system) == [OLD, NEW]


def test_running_newest_ok() -> None:
    ctx = make_ctx(files=VMLINUZ, commands={UNAME: NEW + "\n"})
    assert KernelRunningCheck().run(ctx) == []


def test_older_running_critical() -> None:
    ctx = make_ctx(files=VMLINUZ, commands={UNAME: OLD + "\n"})
    (f,) = KernelRunningCheck().run(ctx)
    assert (f.severity, f.title) == (
        Severity.CRITICAL,
        f"Running kernel {OLD} is older than installed {NEW}",
    )
    assert f.remediation == ["sudo reboot"]


def test_reboot_required_critical() -> None:
    files = {
        **VMLINUZ,
        "/run/reboot-required": "*** System restart required ***\n",
        "/run/reboot-required.pkgs": "linux-image-6.8.0-100-generic\nlibc6\n",
    }
    ctx = make_ctx(files=files, commands={UNAME: NEW + "\n"})
    (f,) = KernelRunningCheck().run(ctx)
    assert (f.severity, f.title) == (Severity.CRITICAL, "A reboot is required")
    assert f.evidence == ["linux-image-6.8.0-100-generic", "libc6"]


def test_kernel_compare_same_kernel_warns() -> None:
    ctx = make_ctx(files=VMLINUZ, commands={UNAME: OLD + "\n"})
    assert KernelRunningCheck().collect_baseline(ctx) == {"running": OLD, "installed": [OLD, NEW]}
    (f,) = KernelRunningCheck().compare(ctx, {"running": OLD, "installed": [OLD]})
    assert f.severity is Severity.WARNING
    assert f.title == f"Still running the pre-upgrade kernel {OLD}"


def test_kernel_compare_changed_info() -> None:
    ctx = make_ctx(files=VMLINUZ, commands={UNAME: NEW + "\n"})
    (f,) = KernelRunningCheck().compare(ctx, {"running": OLD, "installed": [OLD]})
    assert (f.severity, f.title) == (Severity.INFO, f"Kernel changed from {OLD} to {NEW}")


NR = ("needrestart", "-b", "-r", "l")


def test_needrestart_services_warn() -> None:
    out = (
        "NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.8.0-100-generic\n"
        "NEEDRESTART-KSTA: 1\nNEEDRESTART-SVC: ssh.service\nNEEDRESTART-SVC: cron.service\n"
    )
    (f,) = NeedrestartCheck().run(make_ctx(commands={NR: out}))
    assert (f.severity, f.title) == (Severity.WARNING, "2 services run outdated libraries")
    assert f.remediation[0] == "sudo systemctl restart cron.service ssh.service"


def test_needrestart_ksta_1_ok() -> None:
    assert NeedrestartCheck().run(make_ctx(commands={NR: "NEEDRESTART-KSTA: 1\n"})) == []


def test_needrestart_ksta_3_warns() -> None:
    fs = NeedrestartCheck().run(make_ctx(commands={NR: "NEEDRESTART-KSTA: 3\n"}))
    assert titles(fs) == ["needrestart reports a pending kernel upgrade"]


DKMS = ("dkms", "status")


def test_dkms_parse_formats() -> None:
    entries = parse_dkms_status(
        "nvidia/550.120, 6.8.0-100-generic, x86_64: installed\n"
        "zfs, 2.1.5, 6.8.0-45-generic, x86_64: installed (WARNING! Diff between built and installed module!)\n"
        "virtualbox/7.0.20: added\n"
    )
    assert [(e.name, e.version, e.kernel, e.status) for e in entries] == [
        ("nvidia", "550.120", "6.8.0-100-generic", "installed"),
        ("zfs", "2.1.5", "6.8.0-45-generic", "installed"),
        ("virtualbox", "7.0.20", None, "added"),
    ]


def test_dkms_new_format_installed_ok() -> None:
    ctx = make_ctx(commands={UNAME: NEW, DKMS: f"nvidia/550.120, {NEW}, x86_64: installed\n"})
    assert DkmsCheck().run(ctx) == []


def test_dkms_missing_for_running_kernel_critical() -> None:
    out = f"zfs, 2.1.5, {OLD}, x86_64: installed\n"
    (f,) = DkmsCheck().run(make_ctx(commands={UNAME: NEW, DKMS: out}))
    assert (f.severity, f.title) == (
        Severity.CRITICAL,
        "DKMS module zfs is not built for the running kernel",
    )
    assert f.remediation[0] == f"sudo dkms autoinstall -k {NEW}"


def test_dkms_added_status_only_critical() -> None:
    (f,) = DkmsCheck().run(make_ctx(commands={UNAME: NEW, DKMS: "virtualbox/7.0.20: added\n"}))
    assert f.severity is Severity.CRITICAL


def test_dkms_compare_missing_module() -> None:
    ctx = make_ctx(commands={UNAME: NEW, DKMS: f"nvidia/550, {NEW}, x86_64: installed\n"})
    assert DkmsCheck().collect_baseline(ctx) == ["nvidia"]
    assert titles(DkmsCheck().compare(ctx, ["nvidia", "zfs"])) == [
        "DKMS module zfs was registered before the upgrade"
    ]


GRUB = "/boot/grub/grub.cfg"
EFI = "/sys/firmware/efi/fw_platform_size"
EFIBOOT = ("efibootmgr", "-v")


def test_grub_references_kernel_ok() -> None:
    files = {**VMLINUZ, GRUB: f"linux /boot/vmlinuz-{NEW} root=UUID=x\n"}
    assert BootloaderCheck().run(make_ctx(files=files, available={"uname"})) == []


def test_grub_missing_kernel_warns() -> None:
    files = {**VMLINUZ, GRUB: f"linux /boot/vmlinuz-{OLD} root=UUID=x\n"}
    (f,) = BootloaderCheck().run(make_ctx(files=files, available=set()))
    assert (f.severity, f.title) == (
        Severity.WARNING,
        f"grub.cfg does not reference newest kernel {NEW}",
    )
    assert f.remediation == ["sudo update-grub"]


def test_efi_bootcurrent_missing_warns() -> None:
    files = {**VMLINUZ, GRUB: f"vmlinuz-{NEW}\n", EFI: "64"}
    out = "BootOrder: 0001\nBoot0001* debian\tHD(1,GPT,...)/File(\\EFI\\debian\\shimx64.efi)\n"
    fs = BootloaderCheck().run(make_ctx(files=files, commands={EFIBOOT: out}))
    assert titles(fs) == ["UEFI firmware did not report which entry booted this system"]


def test_efi_bootcurrent_unknown_entry_warns() -> None:
    files = {**VMLINUZ, GRUB: f"vmlinuz-{NEW}\n", EFI: "64"}
    out = "BootCurrent: 0003\nBoot0001* debian\tHD(...)\n"
    fs = BootloaderCheck().run(make_ctx(files=files, commands={EFIBOOT: out}))
    assert titles(fs) == ["UEFI boot entry 0003 is no longer listed"]


def test_efi_ok() -> None:
    files = {**VMLINUZ, GRUB: f"vmlinuz-{NEW}\n", EFI: "64"}
    out = "BootCurrent: 0001\nBootOrder: 0001\nBoot0001* debian\tHD(...)\n"
    assert BootloaderCheck().run(make_ctx(files=files, commands={EFIBOOT: out})) == []


def test_efibootmgr_absent_still_checks_grub() -> None:
    files = {**VMLINUZ, GRUB: f"vmlinuz-{OLD}\n", EFI: "64"}
    fs = BootloaderCheck().run(make_ctx(files=files, available=set()))
    assert titles(fs) == [f"grub.cfg does not reference newest kernel {NEW}"]


def test_no_grub_info() -> None:
    (f,) = BootloaderCheck().run(make_ctx(files=VMLINUZ, available=set()))
    assert (f.severity, f.title) == (Severity.INFO, "No GRUB config found; bootloader not verified")


GB = 1024**3


def usage(pct_free: float, inode_pct: float = 50.0) -> DiskUsage:
    return DiskUsage(
        total=100 * GB, free=int(pct_free * GB), inodes_total=1000, inodes_free=int(inode_pct * 10)
    )


def test_space_findings_thresholds() -> None:
    assert space_findings("/boot", usage(50), ["x"]) == []
    (f,) = space_findings("/boot", usage(20), ["x"])
    assert (f.severity, f.title) == (Severity.WARNING, "Low free space on /boot: 20% free")
    (f,) = space_findings("/boot", usage(5), ["x"])
    assert f.severity is Severity.CRITICAL
    (f,) = space_findings("/boot", usage(50, inode_pct=5), ["x"])
    assert (f.severity, f.title) == (Severity.CRITICAL, "Low free inodes on /boot: 5% free")


def test_space_findings_vfat_no_inodes() -> None:
    assert space_findings("/boot/efi", DiskUsage(100, 90, 0, 0), ["x"]) == []


def test_boot_space_low_critical() -> None:
    ctx = make_ctx(disks={"/": usage(80), "/boot": usage(5)})
    (f,) = BootSpaceCheck().run(ctx)
    assert f.severity is Severity.CRITICAL
    assert "sudo apt autoremove --purge" in f.remediation


def test_boot_space_same_fs_as_root_skipped() -> None:
    ctx = make_ctx(disks={"/": usage(5), "/boot": usage(5)})
    assert BootSpaceCheck().run(ctx) == []


def test_boot_space_esp_checked() -> None:
    ctx = make_ctx(disks={"/": usage(80), "/boot": usage(5), "/boot/efi": usage(20)})
    assert [f.severity for f in BootSpaceCheck().run(ctx)] == [Severity.CRITICAL, Severity.WARNING]


def test_boot_space_thresholds_configurable() -> None:
    ctx = make_ctx(disks={"/": usage(80), "/boot": usage(20)})
    assert BootSpaceCheck({"warning_pct": 15}).run(ctx) == []


def test_boot_space_critical_threshold_configurable() -> None:
    ctx = make_ctx(disks={"/": usage(80), "/boot": usage(5)})
    (f,) = BootSpaceCheck({"critical_pct": 3}).run(ctx)
    assert f.severity is Severity.WARNING
