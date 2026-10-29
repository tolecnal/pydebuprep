# disk-space — Free disk space and inodes

Release upgrades download and unpack hundreds of packages under `/var` and `/`, and
the new release is often bigger than the old one.

<!-- facts: disk-space -->

## What it checks

- Free space and free inodes, as a percentage, on every local filesystem
  (temporary and virtual ones such as `tmpfs`, `squashfs`, `overlay` and
  `efivarfs` are left out). With `include_remote: true`, network and FUSE
  filesystems too.
- An absolute floor for the `important_mounts` (`/` and `/var` by default): at
  least `min_free_mib` free whatever their size, since a large filesystem can be
  "only 5% full" and still too full for an upgrade.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical / warning | Low free space on *mount*: *N*% free | Below `critical_pct` / `warning_pct`. Find what uses the space: `sudo du -xh --max-depth=2 MOUNT | sort -h | tail`. Common culprits after an upgrade: `sudo apt clean`; `sudo journalctl --vacuum-size=200M`. |
| critical / warning | Low free inodes on *mount*: *N*% free | As above; usually many small files (caches, mail queues). |
| critical / warning | Only *size* free on *mount* | An important mount below `min_free_mib` (critical below half of it). |

## Commands it runs

```sh
df -P -T -l -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs
df -P -i -l -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs
```

With `include_remote: true`, without `-l` (local filesystems only):

```sh
df -P -T -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs
df -P -i -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs
```

`/boot` and the EFI partition have their own check, [`boot-space`](boot-space.md).

## Limitations

- Network filesystems are off by default: an unreachable NFS server can make `df`
  hang (the command has a timeout).
- Filesystems that report no inode counts (btrfs, some network filesystems) are only
  checked for space.

<!-- options: disk-space -->
