# libvirt — libvirt virtual machines

Virtual machines are easy to forget during an upgrade: one set to start at boot may
not come back, and a domain may still name an emulator the new release renamed or a
disk on a filesystem that isn't mounted, so it won't start at all.

<!-- facts: libvirt -->

## What it checks

For every QEMU/KVM domain defined in `/etc/libvirt/qemu/*.xml`:

- whether it is set to start at boot (a link in `/etc/libvirt/qemu/autostart/`) but
  isn't running (no status file in `/run/libvirt/qemu/`);
- whether its emulator, and the file or device behind each of its disks, exists.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | Virtual machines use files that don't exist (a machine that starts at boot is affected) | Mount or restore the disks, or correct the paths with `sudo virsh edit NAME`; for an emulator, use the one this release installs. |
| warning | Virtual machines use files that don't exist (only machines that don't start at boot) | As above. |
| warning | Virtual machines set to start at boot aren't running | `sudo virsh start NAME`; if none run, `sudo systemctl status libvirtd`. |

## Commands it runs

None: it reads libvirt's own files. `virsh` isn't used: it can start the libvirt
daemon, and creates configuration directories on first use.

## Limitations

- Only QEMU/KVM domains of the system instance (`qemu:///system`) are checked, not
  per-user sessions, LXC or Xen.
- Network disks (`<source protocol=...>`) and storage pool volumes are left out.
- Needs root: libvirt's directories are readable by root only. Skipped when no
  domain is defined.

<!-- options: libvirt -->
