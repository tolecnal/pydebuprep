# boot-config — Initramfs, kernel command line and Secure Boot

A machine can boot fine after an upgrade and still have lost what a workload needs: a
kernel parameter such as `intel_iommu=on`, or Secure Boot. A kernel without an initramfs
may not boot at all next time.

<!-- facts: boot-config -->

## What it checks

- Every installed kernel (`/boot/vmlinuz-*`) has an initramfs (`/boot/initrd.img-*`).
- With a snapshot: the kernel's command line (`/proc/cmdline`), and whether Secure Boot is
  on, from its UEFI variable.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* kernels have no initramfs | `sudo update-initramfs -c -k VERSION`. |
| warning | *N* kernel parameters were removed or changed since the snapshot | The evidence shows each one. Check `GRUB_CMDLINE_LINUX` in `/etc/default/grub` and `/etc/default/grub.d/`, then `sudo update-grub`. |
| info | *N* kernel parameters are new since the snapshot | Check they're what you want. |
| warning | Secure Boot was on before and is off now | Check the firmware's settings; `mokutil --sb-state`. |
| info | Secure Boot was off before and is on now | Unsigned kernel modules no longer load. |

## Compared with a snapshot

The snapshot records the command line and the Secure Boot state. `BOOT_IMAGE` and `initrd`
name the kernel, so they change with it and are left out; `ignore_parameters` sets which
are. A command line can hold secrets: the snapshot is readable by root only, and reports
redact what looks like one.

## Commands it runs

None; it reads the files above.

## Limitations

- A kernel built to boot without an initramfs is reported too.
- It doesn't judge a parameter, only that it changed. A change can be just what you wanted.
- On a machine without UEFI, or a kernel that doesn't show the variable, Secure Boot isn't
  compared.

<!-- options: boot-config -->
