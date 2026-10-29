# systemd-timers — systemd timers

Timers replace cron jobs on modern systems. An enabled timer that isn't active
means its scheduled job silently never runs.

<!-- facts: systemd-timers -->

## What it checks

- Every timer unit: enabled timers that aren't active. Timers skipped by a
  condition (for example ones meant only for physical machines) are left out.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | Timer *name* is not active | `systemctl status TIMER`; `sudo systemctl enable --now TIMER`. |
| warning | *N* timers were active before the upgrade but aren't now | `systemctl list-timers --all`; re-enable the ones you need. |

## Compared with a snapshot

The snapshot records the active timers.

## Commands it runs

```sh
systemctl list-units --type=timer --all --no-legend --plain --no-pager
systemctl show -p UnitFileState -p ConditionResult TIMER
```

## Limitations

- It checks that timers are active, not that their last run succeeded; a failed
  run shows up as a failed service in [`systemd-failed`](systemd-failed.md).

<!-- options: systemd-timers -->
