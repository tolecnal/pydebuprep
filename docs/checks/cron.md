# cron — cron jobs

Upgrades remove or move programs — old Python versions are the classic case — and a
cron job calling one fails silently every time it runs.

<!-- facts: cron -->

## What it checks

- System crontabs (`/etc/crontab`, `/etc/cron.d/*`) and, as root, user crontabs
  (`/var/spool/cron/crontabs/*`).
- For each job, whether the program it runs (an absolute path) exists. Jobs that
  guard themselves with `test -x PROGRAM &&` or `[ -x PROGRAM ] &&` are left out,
  since they're written to cope.
- Whether a cron daemon (`cron`, `cronie` or `crond`) is running when there are jobs.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* cron jobs run programs that don't exist | Find what provided the program (`dpkg -S`, `apt-file search`); install the replacement and update the job, or remove it. |
| warning | No cron daemon is running | `sudo apt install cron && sudo systemctl enable --now cron`. |
| info | *N* cron jobs were removed by the upgrade | Package-provided jobs come and go with their packages; check none of yours is among them. |

## Compared with a snapshot

The snapshot records every job (file, schedule, command).

## Commands it runs

```sh
systemctl list-units --type=service --state=active --no-legend --plain --no-pager
```

To see which cron daemon runs; skipped without systemd.

## Limitations

- Only absolute program paths are checked; commands found through `PATH` aren't.
- Without root, user crontabs aren't read.
- systemd timers are covered by [`systemd-timers`](systemd-timers.md).

<!-- options: cron -->
