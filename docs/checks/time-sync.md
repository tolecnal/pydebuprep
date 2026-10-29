# time-sync — Time synchronisation

Releases sometimes switch time services (ntp, chrony, systemd-timesyncd), and the
old one may be removed without the new one configured. A wrong clock breaks TLS,
Kerberos, log correlation and scheduled jobs.

<!-- facts: time-sync -->

## What it checks

- That one of `chrony`, `systemd-timesyncd`, `ntpsec`, `ntp` or `openntpd` is
  running.
- That the kernel considers the clock synchronised — read directly from the
  kernel, without asking any daemon.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | No time synchronisation service is running | `sudo apt install systemd-timesyncd` (or chrony) and enable it. |
| warning | The system clock is not synchronised | Right after boot this can take a few minutes. `timedatectl status`; `chronyc tracking` with chrony. |
| info | Time synchronisation moved from *old* to *new* | Check the new service's servers and pools match what you had. |

## Compared with a snapshot

The snapshot records which service ran and whether the clock was synchronised.

## Commands it runs

```sh
systemctl list-units --type=service --state=active --no-legend --plain --no-pager
```

The synchronisation state comes from the kernel (`adjtimex` with no changes
requested), not from a command.

## Limitations

- Without systemd (for example in a container) the service part is skipped; the
  clock state is still checked.
- Containers share the host's clock, so their result says more about the host.

<!-- options: time-sync -->
