# dmesg-errors — Kernel errors and warnings

A new kernel can bring driver or firmware problems: missing firmware files,
devices that fail to initialise, filesystem warnings.

<!-- facts: dmesg-errors -->

## What it checks

- Kernel messages at error and warning level since boot, grouped.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* kernel error messages since boot | `sudo dmesg --level=err -T`; for missing firmware, install the matching `firmware-*` package. |
| info | *N* kernel warning messages since boot | `sudo dmesg --level=warn -T`. |

## Commands it runs

```sh
dmesg --level=err --notime
dmesg --level=warn --notime
```

## Limitations

- Some kernel messages are harmless on particular hardware and appear on every
  boot. Silence them with `ignore` here, or in `logs: ignore:` to hide them in
  [`journal-errors`](journal-errors.md) too.
- The kernel ring buffer is limited; on a long-running system the oldest messages
  may be gone.

<!-- options: dmesg-errors -->
