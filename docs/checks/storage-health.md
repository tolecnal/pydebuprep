# storage-health — RAID, LVM, encrypted devices, swap, ZFS and Btrfs

Free space and mounts say little about whether the storage underneath is healthy. A
degraded RAID array still mounts, and another failure can lose its data.

<!-- facts: storage-health -->

## What it checks

Each only where the technology is in use, read from `/proc`, `/sys` and `/etc`: no tool has
to be installed and no device is opened.

- **Software RAID** (`/proc/mdstat`): arrays that are inactive, degraded, being rebuilt or
  resynchronising.
- **Encrypted devices**: entries in `/etc/crypttab` not marked `noauto` must be open.
- **Swap**: entries in `/etc/fstab` not marked `noauto` must be in `/proc/swaps`.
- **ZFS** (`/proc/spl/kstat/zfs/*/state`): pools that aren't `ONLINE`.
- **Btrfs** (`/sys/fs/btrfs/*/devinfo/*`): missing devices, and recorded errors.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | *N* RAID arrays are degraded | `sudo mdadm --detail /dev/ARRAY`. Fix this before rebooting. |
| warning | *N* RAID arrays are being rebuilt | No redundancy until it finishes: `cat /proc/mdstat`. |
| info | *N* RAID arrays are resynchronising | Nothing; it's routine. |
| warning | *N* encrypted devices in crypttab aren't open | `sudo cryptdisks_start NAME`; check its entry in `/etc/crypttab`. |
| warning | *N* swap entries in /etc/fstab aren't active | `sudo swapon --all --verbose`. |
| critical | *N* ZFS pools aren't healthy | `sudo zpool status -v`. |
| critical | *N* Btrfs devices are missing | `sudo btrfs filesystem show`. |
| warning | *N* Btrfs devices have recorded errors | `sudo btrfs device stats MOUNT`. These counters last until reset, so they may be old. |
| critical | *N* RAID arrays from before the upgrade are gone | `cat /proc/mdstat`; `sudo mdadm --assemble --scan`. |
| warning | *N* encrypted devices from before the upgrade aren't open | As above. |
| warning | *N* swap areas from before the upgrade aren't active | As above. |
| critical | *N* ZFS pools from before the upgrade are gone | `sudo zpool import`. |
| warning | *N* LVM volumes from before the upgrade aren't active | `sudo lvs`; `sudo vgchange -ay`. A missing physical volume is a common cause. |

## Compared with a snapshot

The snapshot records the RAID arrays, active LVM volumes, open encrypted devices, active swap
and ZFS pools.
A problem that was already there before the upgrade is reported the same way.

## Commands it runs

None; it reads the files above.

## Limitations

- It sees what the kernel reports, not what the disks would say: SMART and NVMe health
  aren't covered.
- For LVM it sees only which volumes are active, from `/sys`. It can't report a missing physical
  volume while its volumes still run, or a thin pool filling up: LVM's own commands try to
  rewrite `/run/lvm/hints`, even with `--readonly`, so they aren't used.
- Hardware RAID controllers are invisible to it.
- The ZFS and Btrfs parts depend on files recent kernels provide; on others they say nothing.

<!-- options: storage-health -->
