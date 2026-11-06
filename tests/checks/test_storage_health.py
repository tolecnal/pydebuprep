"""storage-health: RAID, encrypted devices, swap, ZFS and Btrfs, from /proc and /sys."""

from __future__ import annotations

from typing import Any

from pydebuprep.checks.storage_health import StorageHealthCheck
from pydebuprep.model import Finding, Severity

from .helpers import make_ctx

HEALTHY = """Personalities : [raid1]
md0 : active raid1 sdb1[1] sda1[0]
      1046528 blocks super 1.2 [2/2] [UU]

unused devices: <none>
"""
DEGRADED = """md0 : active raid1 sda1[0]
      1046528 blocks super 1.2 [2/1] [U_]

"""
REBUILDING = """md0 : active raid1 sdb1[2] sda1[0]
      1046528 blocks super 1.2 [2/1] [U_]
      [==>..................]  recovery = 12.6% (132096/1046528) finish=1.1min speed=13209K/sec

"""
RESYNCING = """md0 : active raid1 sdb1[1] sda1[0]
      1046528 blocks super 1.2 [2/2] [UU]
      [==>..................]  resync = 12.6% (132096/1046528) finish=1.1min speed=13209K/sec

"""
INACTIVE = "md1 : inactive sdc1[0](S)\n      1046528 blocks\n\n"
SWAPS_HEADER = "Filename\tType\tSize\tUsed\tPriority\n"


def run(**kw: Any) -> list[Finding]:
    return StorageHealthCheck().run(make_ctx(**kw))


def summary(findings: list[Finding]) -> list[tuple[Severity, str, list[str]]]:
    return [(f.severity, f.title, f.evidence) for f in findings]


def test_a_host_without_any_of_it_is_silent() -> None:
    assert run() == []


def test_a_healthy_array_is_silent() -> None:
    assert run(files={"/proc/mdstat": HEALTHY}) == []


def test_a_degraded_array_is_critical() -> None:
    assert summary(run(files={"/proc/mdstat": DEGRADED})) == [
        (Severity.CRITICAL, "1 RAID array is degraded", ["md0: [U_]"])
    ]


def test_a_rebuilding_array_is_a_warning() -> None:
    assert summary(run(files={"/proc/mdstat": REBUILDING})) == [
        (Severity.WARNING, "1 RAID array is being rebuilt", ["md0: recovery = 12.6%"])
    ]


def test_a_resync_of_a_healthy_array_is_for_information() -> None:
    assert summary(run(files={"/proc/mdstat": RESYNCING})) == [
        (Severity.INFO, "1 RAID array is resynchronising", ["md0: resync = 12.6%"])
    ]


def test_an_inactive_array_is_critical() -> None:
    assert summary(run(files={"/proc/mdstat": INACTIVE})) == [
        (Severity.CRITICAL, "1 RAID array is degraded", ["md1: inactive"])
    ]


def test_crypttab_entries_must_be_open() -> None:
    crypttab = (
        "# comment\n\ncryptroot UUID=a none luks\nbackup UUID=b none luks,noauto\ndata UUID=c\n"
    )
    fs = run(
        files={
            "/etc/crypttab": crypttab,
            "/sys/block/dm-0/dm/name": "cryptroot\n",
            "/sys/block/dm-0/dm/uuid": "CRYPT-LUKS2-abc\n",
            "/sys/block/dm-1/dm/name": "data\n",
            "/sys/block/dm-1/dm/uuid": "LVM-abc\n",
        }
    )
    assert summary(fs) == [
        (Severity.WARNING, "1 encrypted device in crypttab isn't open", ["data"])
    ]


def test_a_device_mapper_device_without_a_uuid_is_not_encrypted() -> None:
    fs = run(files={"/etc/crypttab": "data UUID=c\n", "/sys/block/dm-0/dm/name": "data\n"})
    assert summary(fs) == [
        (Severity.WARNING, "1 encrypted device in crypttab isn't open", ["data"])
    ]


def test_active_swap_is_silent() -> None:
    fs = run(
        files={
            "/etc/fstab": "/swapfile none swap sw 0 0\nUUID=abc none swap sw 0 0\n",
            "/proc/swaps": f"{SWAPS_HEADER}/swapfile file 1 0 -2\n/dev/sda2 partition 1 0 -3\n",
            "/dev/sda2": "",
        },
        links={"/dev/disk/by-uuid/abc": "../../sda2"},
    )
    assert fs == []


def test_configured_swap_that_is_not_active_is_a_warning() -> None:
    fs = run(files={"/etc/fstab": "/swapfile none swap sw 0 0\nLABEL=x none swap sw 0 0\n",
                    "/proc/swaps": SWAPS_HEADER})  # fmt: skip
    assert summary(fs) == [
        (Severity.WARNING, "2 swap entries in /etc/fstab aren't active", ["/swapfile", "LABEL=x"])
    ]


def test_swap_marked_noauto_is_left_out() -> None:
    fs = run(
        files={"/etc/fstab": "/swapfile none swap sw,noauto 0 0\n", "/proc/swaps": SWAPS_HEADER}
    )
    assert fs == []


def test_an_unreadable_swap_list_says_nothing() -> None:
    assert run(files={"/etc/fstab": "/swapfile none swap sw 0 0\n"}) == []


def test_zfs_pools() -> None:
    fs = run(files={"/proc/spl/kstat/zfs/tank/state": "DEGRADED\n",
                    "/proc/spl/kstat/zfs/ok/state": "ONLINE\n"})  # fmt: skip
    assert summary(fs) == [(Severity.CRITICAL, "1 ZFS pool isn't healthy", ["tank: DEGRADED"])]


def test_btrfs_missing_devices_and_errors() -> None:
    base = "/sys/fs/btrfs/abc/devinfo"
    fs = run(
        files={
            f"{base}/1/missing": "0\n",
            f"{base}/1/error_stats": "write_errs 0\nread_errs 0\n",
            f"{base}/2/missing": "1\n",
            f"{base}/3/missing": "0\n",
            f"{base}/3/error_stats": "write_errs 0\nread_errs 4\nnot a pair here\n",
        }
    )
    assert summary(fs) == [
        (Severity.CRITICAL, "1 Btrfs device is missing", ["abc device 2"]),
        (Severity.WARNING, "1 Btrfs device has recorded errors", ["abc device 3: read_errs 4"]),
    ]


def test_baseline_and_nothing_changed() -> None:
    ctx = make_ctx(
        files={
            "/proc/mdstat": HEALTHY,
            "/sys/block/dm-0/dm/name": "cryptroot\n",
            "/sys/block/dm-0/dm/uuid": "CRYPT-LUKS2-abc\n",
            "/proc/swaps": f"{SWAPS_HEADER}/swapfile file 1 0 -2\n",
            "/proc/spl/kstat/zfs/tank/state": "ONLINE\n",
        }
    )
    check = StorageHealthCheck()
    before = check.collect_baseline(ctx)
    assert before == {
        "arrays": ["md0"],
        "encrypted": ["cryptroot"],
        "swaps": ["/swapfile"],
        "pools": ["tank"],
    }
    assert check.compare(ctx, before) == []


def test_what_is_gone_since_the_snapshot() -> None:
    before = {"arrays": ["md0"], "encrypted": ["data"], "swaps": ["/swapfile"], "pools": ["tank"]}
    assert summary(StorageHealthCheck().compare(make_ctx(), before)) == [
        (Severity.CRITICAL, "1 RAID array from before the upgrade is gone", ["md0"]),
        (Severity.WARNING, "1 encrypted device from before the upgrade isn't open", ["data"]),
        (Severity.WARNING, "1 swap area from before the upgrade isn't active", ["/swapfile"]),
        (Severity.CRITICAL, "1 ZFS pool from before the upgrade is gone", ["tank"]),
    ]


def test_a_snapshot_without_these_is_silent() -> None:
    assert StorageHealthCheck().compare(make_ctx(), {}) == []
