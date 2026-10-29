# kernel-running — Running kernel

A release upgrade isn't finished until you reboot into the new kernel. Until then,
the new kernel, its modules and many fixes aren't in use.

<!-- facts: kernel-running -->

## What it checks

- The running kernel (`uname -r`) against the newest installed one
  (`/boot/vmlinuz-*`).
- Whether a package asked for a reboot (`/run/reboot-required`).
- With a snapshot: whether the kernel changed since.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | Running kernel *X* is older than installed *Y* | `sudo reboot`. |
| critical | A reboot is required | `sudo reboot`. The evidence lists the packages that asked for it. |
| warning | Still running the pre-upgrade kernel *X* | `sudo reboot`. |
| info | Kernel changed from *X* to *Y* | For the record. |

## Compared with a snapshot

The snapshot records the running and installed kernels.

## Commands it runs

```sh
uname -r
```

## Limitations

- Kernels are found as `/boot/vmlinuz-*`; systems booting kernels from elsewhere
  (some cloud and container setups) report less.

<!-- options: kernel-running -->
