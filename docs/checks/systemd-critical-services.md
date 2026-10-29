# systemd-critical-services — Critical systemd units

A release upgrade can change a service's enablement, mask it, rename its unit, or
drop a dependency — without any package error, and without the unit counting as
*failed*. This check validates the units you can't do without: a built-in list,
plus the ones you configure.

<!-- facts: systemd-critical-services -->

## What it checks

**Which units:**

- Built in (turn off with `builtin: false`): `ssh.service`, `cron.service` and
  `systemd-journald.service` — each only where it's installed, so a host without
  SSH gets no noise. They must be both running and enabled.
- Yours: `required_active` (must be running, or socket-activated) and
  `required_enabled` (must be enabled), added to the built-in list. A unit you list
  that doesn't exist is a finding.
- `ignore_units` leaves units out, built-in or not.

**For each unit**, one `systemctl show` reads its load state, active state, unit
file state, conditions, trigger sockets and dependencies, and tells apart:

- **not found** — renamed or removed by the upgrade;
- **masked**;
- **can't be loaded** — a broken unit file;
- **not running**, distinguishing a socket-activated service (fine while its socket
  listens) and a unit skipped by a condition (fine: for example timesyncd in a
  container);
- **starting, stopping or reloading**;
- **running while a unit it requires is down**;
- **not enabled** — `static`, `indirect` and `generated` units, and services
  enabled through their socket, count as enabled.

Failed units are left to [`systemd-failed`](systemd-failed.md), and time
synchronisation to [`time-sync`](time-sync.md), so nothing is reported twice.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | *unit* does not exist | `systemctl list-unit-files 'NAME*'` — the upgrade may have renamed it. |
| critical | *unit* is masked | `sudo systemctl unmask UNIT`. |
| critical | *unit* can't be loaded (*state*) | `systemctl status UNIT`; `systemd-analyze verify UNIT`. |
| critical | *unit* is not running | `sudo systemctl start UNIT`. |
| critical | *unit* is socket-activated but *socket* isn't listening | `sudo systemctl start SOCKET`. |
| warning | *unit* is running but needs *dependency*, which is inactive/failed | `systemctl list-dependencies UNIT`. |
| warning | *unit* is activating / deactivating / reloading | Look again; `systemctl status UNIT`. |
| warning | *unit* is not enabled | `sudo systemctl enable UNIT` — it won't start at boot. |

## Compared with a snapshot

The snapshot records the state of the critical units and every enabled service,
and — as root — the TCP and UDP ports each critical unit listens on. The report
then flags:

| Severity | Finding |
|---|---|
| critical | *unit* was loaded before the upgrade and is now masked |
| warning | *unit* existed before the upgrade and is gone |
| warning | *unit* listened on *tcp/443, …* before the upgrade, not now |

Services that were enabled or running before and aren't now are reported by
[`systemd-failed`](systemd-failed.md).

## Commands it runs

```sh
systemctl show --property=Id,Names,LoadState,ActiveState,SubState,UnitFileState,ConditionResult,ConditionTimestamp,TriggeredBy,Requires,BindsTo,ControlGroup -- UNIT...
systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager
```

The second only when taking a snapshot. Listening ports are read from
`/proc/net/{tcp,tcp6,udp,udp6}` and matched to the unit's processes through
`/proc/PID/fd`.

## Limitations

- **Active is not healthy.** A running unit shows the process exists, not that the
  service works; findings about running units say so. Application checks (and, for
  some services, the planned readiness probes) cover more.
- Template units (`getty@.service`) can't be required; name an instance
  (`getty@tty1.service`).
- UDP sockets on ephemeral ports (rpc.statd, resolvers) change on every restart and
  aren't counted as listeners. Listeners in a unit's child cgroups aren't seen.
- An alias and its unit (`sshd.service` and `ssh.service`) listed separately are
  checked separately.

<!-- options: systemd-critical-services -->
