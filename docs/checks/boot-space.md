# boot-space — Free space on /boot and the EFI partition

A small separate `/boot` fills up with old kernels; when it's full, installing the
next kernel fails half-way and can leave the system unbootable.

<!-- facts: boot-space -->

## What it checks

- Free space and free inodes on `/boot` and `/boot/efi`, when they are separate
  filesystems. If `/boot` is just a directory on `/`, it's covered by
  [`disk-space`](disk-space.md) instead.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical / warning | Low free space on *mount*: *N*% free | Below `critical_pct` / `warning_pct`. For `/boot`: list kernels with `dpkg -l 'linux-image-*'`, then `sudo apt autoremove --purge`. For `/boot/efi`: remove vendor directories under `/boot/efi/EFI/` you no longer boot. |
| critical / warning | Low free inodes on *mount*: *N*% free | As above. |

## Commands it runs

None: it reads filesystem statistics (`statvfs`).

## Limitations

- Percentages suit small partitions; a nearly full but large `/boot` may still have
  room for several kernels.

<!-- options: boot-space -->
