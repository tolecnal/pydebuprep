# fstab — /etc/fstab and mounts

A bad `/etc/fstab` entry can drop the next boot into emergency mode — and the
upgrade's reboot is often the first boot in a long time.

<!-- facts: fstab -->

## What it checks

- `findmnt --verify`: errors and warnings in `/etc/fstab` (unknown devices, missing
  mount points, unsupported filesystem types, bad options).
- With a snapshot: filesystems that were mounted before and aren't now.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | /etc/fstab has *N* errors | Fix the entries named in the evidence before rebooting. |
| critical | findmnt --verify failed | Run `findmnt --verify` yourself to see why. |
| warning | /etc/fstab has *N* warnings | Review the entries named in the evidence. |
| warning | *mount* was mounted before the upgrade but is not now | `findmnt --fstab MOUNT`; `sudo mount MOUNT`. |
| info | Some fstab entries could not be fully verified without root | Run as root. |

## Compared with a snapshot

The snapshot records the mounted filesystems (virtual ones are left out).

## Commands it runs

```sh
findmnt --verify
findmnt -rn -o TARGET,SOURCE,FSTYPE
```

## Limitations

- `findmnt --verify` checks what it can see: a device that's just not plugged in
  (an external disk) looks the same as one that's gone.
- Mounts managed outside fstab (systemd mount units, autofs) are only covered by the
  snapshot comparison.

<!-- options: fstab -->
