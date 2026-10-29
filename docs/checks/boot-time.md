# boot-time — Boot time

A boot that suddenly takes minutes after an upgrade usually means a unit waiting
for something that no longer exists — a device, a mount, a network that never comes
up.

<!-- facts: boot-time -->

## What it checks

- The total boot time, the slowest units, and the critical chain of units the
  boot waited on, from `systemd-analyze`.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| info | Boot took *time* | The evidence lists the slowest units; `systemd-analyze blame` shows them all. |
| info | Boot critical chain | Units with a `+time` delayed the boot. `systemd-analyze critical-chain UNIT` for one unit. |
| info | Boot has not finished yet | Some units are still starting; `systemctl list-jobs` shows what's waiting. |

All findings are informational: boot time depends too much on the system to judge.

## Commands it runs

```sh
systemd-analyze
systemd-analyze blame --no-pager
systemd-analyze critical-chain --no-pager
```

## Limitations

- In containers, and on systems without systemd as PID 1, it's skipped.
- It reports this boot only; compare with an earlier report to see a change.

<!-- options: boot-time -->
