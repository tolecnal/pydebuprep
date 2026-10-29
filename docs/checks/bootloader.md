# bootloader — Bootloader configuration

After an upgrade, the next boot should start the new kernel from a boot entry that
still exists. This check looks for the two most common ways that goes wrong.

<!-- facts: bootloader -->

## What it checks

- **GRUB:** whether `/boot/grub/grub.cfg` references the newest installed kernel
  (from `/boot/vmlinuz-*`).
- **UEFI** (when the system booted with UEFI and `efibootmgr` is installed): that
  the firmware reports which entry booted the system (`BootCurrent`), and that this
  entry still exists.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | grub.cfg does not reference newest kernel *version* | `sudo update-grub`; the next boot may otherwise start an old kernel. |
| warning | UEFI boot entry *N* is no longer listed | Inspect with `sudo efibootmgr -v`; reinstall the bootloader entry if needed (`sudo grub-install` for GRUB on UEFI). |
| warning | UEFI firmware did not report which entry booted this system | As above. |
| info | /boot/grub/grub.cfg is not readable | Run as root. |
| info | efibootmgr could not read UEFI boot entries | Run as root: `sudo efibootmgr -v`. |
| info | No GRUB config found; bootloader not verified | Check your bootloader (systemd-boot, …) by hand. |

## Commands it runs

```sh
efibootmgr -v
```

Only on UEFI systems. It reads the UEFI variables; it never writes them (the
read-only audit verifies that, including failed write attempts).

## Limitations

- Only GRUB's configuration is examined. systemd-boot, rEFInd and others aren't
  verified.
- It checks that the newest kernel is *referenced*, not which entry is the default.

<!-- options: bootloader -->
