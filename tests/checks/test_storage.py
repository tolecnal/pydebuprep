from __future__ import annotations

import pytest

from pydebuprep.checks.disk_space import (
    DF_INODES,
    DF_INODES_ALL,
    DF_SPACE,
    DF_SPACE_ALL,
    DiskSpaceCheck,
)
from pydebuprep.checks.fstab import FINDMNT_LIST, FINDMNT_VERIFY, FstabCheck
from pydebuprep.model import Severity
from pydebuprep.system import CommandResult

from .helpers import make_ctx, titles

VERIFY_ERR = """/
   [W] recommended root FS passno is 1 (current is 0)
/data
   [E] unreachable source: UUID=dead-beef
   [E] unknown filesystem type 'foo'

0 parse errors, 2 errors, 1 warning
"""


def test_fstab_errors_critical() -> None:
    res = CommandResult(FINDMNT_VERIFY, 1, VERIFY_ERR, "")
    fs = FstabCheck().run(make_ctx(commands={FINDMNT_VERIFY: res}))
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.CRITICAL, "/etc/fstab has 2 errors"),
        (Severity.WARNING, "/etc/fstab has 1 warning"),
    ]
    assert fs[0].evidence == [
        "/data: unreachable source: UUID=dead-beef",
        "/data: unknown filesystem type 'foo'",
    ]


def test_fstab_warnings_warn() -> None:
    out = "/\n   [W] recommended root FS passno is 1 (current is 0)\n\n0 parse errors, 0 errors, 1 warning\n"
    fs = FstabCheck().run(make_ctx(commands={FINDMNT_VERIFY: out}))
    assert [f.severity for f in fs] == [Severity.WARNING]


def test_fstab_clean_ok() -> None:
    out = "Success, no errors or warnings detected\n"
    assert FstabCheck().run(make_ctx(commands={FINDMNT_VERIFY: out})) == []


def test_fstab_failure_without_parse_critical() -> None:
    res = CommandResult(FINDMNT_VERIFY, 1, "", "findmnt: cannot parse /etc/fstab\n")
    (f,) = FstabCheck().run(make_ctx(commands={FINDMNT_VERIFY: res}))
    assert f.severity is Severity.CRITICAL
    assert f.evidence == ["findmnt: cannot parse /etc/fstab"]


MOUNTS = "/ /dev/sda1 ext4\n/proc proc proc\n/home /dev/sda3 ext4\n/run tmpfs tmpfs\n/mnt/nas\\x20share //nas/share cifs\n"


def test_fstab_baseline_and_compare_missing_mount() -> None:
    ctx = make_ctx(commands={FINDMNT_LIST: MOUNTS})
    assert FstabCheck().collect_baseline(ctx) == ["/", "/home", "/mnt/nas share"]
    fs = FstabCheck().compare(ctx, ["/", "/srv/backup", "/home"])
    assert titles(fs) == ["/srv/backup was mounted before the upgrade but is not now"]


GB_BLOCKS = 1024 * 1024  # 1 GiB in 1K blocks

DF_OUT = f"""Filesystem     Type 1024-blocks      Used Available Capacity Mounted on
/dev/sda1      ext4 {100 * GB_BLOCKS} {95 * GB_BLOCKS} {5 * GB_BLOCKS} 95% /
/dev/sda2      ext4 {GB_BLOCKS} {GB_BLOCKS // 2} {GB_BLOCKS // 2} 50% /boot
/dev/sda3      ext4 {100 * GB_BLOCKS} {10 * GB_BLOCKS} {90 * GB_BLOCKS} 10% /home
"""
DFI_OUT = """Filesystem      Inodes  IUsed   IFree IUse% Mounted on
/dev/sda1      1000000 100000  900000   10% /
/dev/sda2        65536  65000     536  100% /boot
/dev/sda3      1000000 950000   50000   95% /home
"""


def test_root_full_critical_inodes_low_and_boot_excluded() -> None:
    ctx = make_ctx(commands={DF_SPACE: DF_OUT, DF_INODES: DFI_OUT})
    fs = DiskSpaceCheck().run(ctx)
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.CRITICAL, "Low free space on /: 5% free"),
        (Severity.CRITICAL, "Low free inodes on /home: 5% free"),
    ]


def test_disk_space_ok() -> None:
    out = f"Filesystem Type 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 ext4 {10 * GB_BLOCKS} 0 {10 * GB_BLOCKS} 0% /\n"
    assert DiskSpaceCheck().run(make_ctx(commands={DF_SPACE: out, DF_INODES: ""})) == []


def test_fstab_non_root_permission_noise_filtered() -> None:
    out = (
        "/\n   [W] cannot detect on-disk filesystem type (Permission denied)\n"
        "none\n   [W] non-bind mount source /swap.img is a directory or regular file\n"
        "/data\n   [W] target specified more than once\n"
    )
    res = CommandResult(FINDMNT_VERIFY, 0, out, "")
    fstab = {"/etc/fstab": "/swap.img none swap sw 0 0\n"}
    fs = FstabCheck().run(make_ctx(commands={FINDMNT_VERIFY: res}, root=False, files=fstab))
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.WARNING, "/etc/fstab has 1 warning"),
        (Severity.INFO, "Some fstab entries could not be fully verified without root"),
    ]


def test_fuse_mounts_excluded() -> None:
    space = (
        "Filesystem Type 1024-blocks Used Available Capacity Mounted on\n"
        f"gdrive: fuse.rclone {GB_BLOCKS} {GB_BLOCKS} 0 100% /home/u/mnt/gdrive\n"
    )
    inodes = "Filesystem Inodes IUsed IFree IUse% Mounted on\ngdrive: 1000 1000 0 100% /home/u/mnt/gdrive\n"
    assert DiskSpaceCheck().run(make_ctx(commands={DF_SPACE: space, DF_INODES: inodes})) == []


def test_disk_space_default_is_local_only() -> None:
    assert "-l" in DF_SPACE
    assert "-l" in DF_INODES
    assert "-l" not in DF_SPACE_ALL
    assert "-l" not in DF_INODES_ALL


NAS = (
    "Filesystem Type 1024-blocks Used Available Capacity Mounted on\n"
    f"nas:/export nfs4 {100 * GB_BLOCKS} {99 * GB_BLOCKS} {GB_BLOCKS} 99% /mnt/nas\n"
    f"gdrive: fuse.rclone {100 * GB_BLOCKS} {99 * GB_BLOCKS} {GB_BLOCKS} 99% /mnt/gdrive\n"
)
NAS_INODES = (
    "Filesystem Inodes IUsed IFree IUse% Mounted on\n"
    "nas:/export 1000 990 10 99% /mnt/nas\n"
    "gdrive: 1000 1000 0 100% /mnt/gdrive\n"
)


def test_include_remote_checks_network_and_fuse_space() -> None:
    ctx = make_ctx(commands={DF_SPACE_ALL: NAS, DF_INODES_ALL: NAS_INODES})
    fs = DiskSpaceCheck({"include_remote": True}).run(ctx)
    assert titles(fs) == [
        "Low free space on /mnt/nas: 1% free",
        "Low free inodes on /mnt/nas: 1% free",
        "Low free space on /mnt/gdrive: 1% free",
    ]


def test_disk_space_thresholds_configurable() -> None:
    ctx = make_ctx(commands={DF_SPACE: DF_OUT, DF_INODES: ""})
    fs = DiskSpaceCheck({"critical_pct": 2, "warning_pct": 6}).run(ctx)
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.WARNING, "Low free space on /: 5% free")
    ]


def test_disk_space_exclude_mounts() -> None:
    ctx = make_ctx(commands={DF_SPACE: DF_OUT, DF_INODES: DFI_OUT})
    fs = DiskSpaceCheck({"exclude_mounts": ["/", "/ho*"]}).run(ctx)
    assert fs == []


def test_disk_space_threshold_validation() -> None:
    with pytest.raises(ValueError, match="critical_pct must be lower than warning_pct"):
        DiskSpaceCheck({"critical_pct": 30})


SWAPFILE_NOTE = "   [W] non-bind mount source {src} is a directory or regular file\n"


@pytest.mark.parametrize(
    ("fstab", "target"),
    [
        ("/swapfile swap swap defaults 0 0\n", "swap"),  # Debian's usual entry
        ("/swap.img\tnone\tswap\tsw\t0\t0\n", "none"),  # Ubuntu's installer
        ("# comment\nUUID=x / ext4 defaults 0 1\n/var/swap  swap  swap  pri=5  0  0\n", "swap"),
    ],
)
def test_fstab_swap_files_not_reported(fstab: str, target: str) -> None:
    src = fstab.split("\n")[-2].split(maxsplit=1)[0]
    out = f"{target}\n" + SWAPFILE_NOTE.format(src=src)
    ctx = make_ctx(commands={FINDMNT_VERIFY: out}, files={"/etc/fstab": fstab})
    assert FstabCheck().run(ctx) == []


def test_fstab_regular_file_that_is_not_swap_still_reported() -> None:
    out = "/mnt/disk\n" + SWAPFILE_NOTE.format(src="/srv/disk.img")
    ctx = make_ctx(
        commands={FINDMNT_VERIFY: out},
        files={
            "/etc/fstab": "/swapfile swap swap defaults 0 0\n/srv/disk.img /mnt/disk ext4 defaults 0 2\n"
        },
    )
    assert titles(FstabCheck().run(ctx)) == ["/etc/fstab has 1 warning"]


BIG_DF = f"""Filesystem Type 1024-blocks Used Available Capacity Mounted on
/dev/sda1 ext4 {200 * GB_BLOCKS} {199 * GB_BLOCKS} {GB_BLOCKS // 2} 99% /
/dev/sdb1 ext4 {4000 * GB_BLOCKS} {3000 * GB_BLOCKS} {1000 * GB_BLOCKS} 75% /var
/dev/sdc1 ext4 {10 * GB_BLOCKS} {8 * GB_BLOCKS} {GB_BLOCKS // 2} 95% /srv
"""


def test_important_mounts_absolute_floor() -> None:
    ctx = make_ctx(commands={DF_SPACE: BIG_DF, DF_INODES: ""})
    fs = DiskSpaceCheck({"warning_pct": 0.1, "critical_pct": 0.05}).run(ctx)
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.CRITICAL, "Only 512.0 MiB free on /"),
    ]


def test_important_mounts_warning_band_and_options() -> None:
    df = BIG_DF.replace(f"{GB_BLOCKS // 2} 99% /\n", f"{3 * GB_BLOCKS} 98% /\n")
    ctx = make_ctx(commands={DF_SPACE: df, DF_INODES: ""})
    check = DiskSpaceCheck({"warning_pct": 0.1, "critical_pct": 0.05, "min_free_mib": 4096})
    assert [(f.severity, f.title) for f in check.run(ctx)] == [
        (Severity.WARNING, "Only 3.0 GiB free on /")
    ]
    off = DiskSpaceCheck({"warning_pct": 0.1, "critical_pct": 0.05, "min_free_mib": 0})
    assert off.run(ctx) == []
    srv = DiskSpaceCheck({"warning_pct": 0.1, "critical_pct": 0.05, "important_mounts": ["/srv"]})
    assert titles(srv.run(ctx)) == ["Only 512.0 MiB free on /srv"]


def test_important_mount_with_percentage_finding_is_not_doubled() -> None:
    ctx = make_ctx(commands={DF_SPACE: DF_OUT, DF_INODES: ""})
    assert titles(DiskSpaceCheck().run(ctx)) == ["Low free space on /: 5% free"]


def test_min_free_mib_must_not_be_negative() -> None:
    with pytest.raises(ValueError, match="min_free_mib must not be negative"):
        DiskSpaceCheck({"min_free_mib": -1})
