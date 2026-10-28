from __future__ import annotations

from pydebuprep.checks.disk_space import DF_INODES, DF_SPACE, DiskSpaceCheck
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
    out = f"Filesystem Type 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 ext4 {GB_BLOCKS} 0 {GB_BLOCKS} 0% /\n"
    assert DiskSpaceCheck().run(make_ctx(commands={DF_SPACE: out, DF_INODES: ""})) == []


def test_fstab_non_root_permission_noise_filtered() -> None:
    out = (
        "/\n   [W] cannot detect on-disk filesystem type (Permission denied)\n"
        "none\n   [W] non-bind mount source /swap.img is a directory or regular file\n"
        "/data\n   [W] target specified more than once\n"
    )
    res = CommandResult(FINDMNT_VERIFY, 0, out, "")
    fs = FstabCheck().run(make_ctx(commands={FINDMNT_VERIFY: res}, root=False))
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
