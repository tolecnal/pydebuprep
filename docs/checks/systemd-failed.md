# systemd-failed — Failed systemd units

The first thing to look at after any upgrade: units systemd tried to start and
couldn't.

<!-- facts: systemd-failed -->

## What it checks

- Units in the `failed` state.
- With a snapshot: services that were **active** or **enabled** before and aren't
  now.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | Unit *name* failed | `systemctl status UNIT`, `journalctl -u UNIT -b`. |
| warning | *service* was active / enabled before the upgrade but is not now | `systemctl status SERVICE`; `sudo systemctl enable --now SERVICE` if you still need it. More than five are grouped into one finding. |

## Compared with a snapshot

The snapshot records active and enabled services.

## Commands it runs

```sh
systemctl list-units --state=failed --no-legend --plain --no-pager
systemctl list-units --type=service --state=active --no-legend --plain --no-pager
systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager
```

## Limitations

- A service that was stopped on purpose shows up in the comparison: the check can't
  know your intentions. Use `ignore_units` for units that are expected to come and
  go.
- Without systemd (for example in a container) the check is skipped.
- A unit can be active without working; see
  [`systemd-critical-services`](systemd-critical-services.md).

<!-- options: systemd-failed -->
