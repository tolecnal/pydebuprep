# dkms — Out-of-tree kernel modules (DKMS)

Modules built with DKMS (NVIDIA, VirtualBox, ZFS on some systems, vendor drivers)
must be rebuilt for every new kernel. If the build failed during the upgrade, the
hardware or filesystem they drive stops working after the reboot.

<!-- facts: dkms -->

## What it checks

- Every DKMS module from `dkms status`, and whether it's installed for the running
  kernel.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | DKMS module *name* is not built for the running kernel | `sudo dkms autoinstall -k $(uname -r)`; if the build fails, read `/var/lib/dkms/NAME/VERSION/build/make.log`. |
| warning | DKMS module *name* was registered before the upgrade | It's no longer known to DKMS; reinstall the package providing it if you still need it. |

## Compared with a snapshot

The snapshot records the registered modules; the report flags those that are gone.

## Commands it runs

```sh
dkms status
```

## Limitations

- "Installed" is what DKMS reports; a module DKMS installed but the kernel refuses
  to load (for example with Secure Boot and an unsigned module) isn't detected.

<!-- options: dkms -->
