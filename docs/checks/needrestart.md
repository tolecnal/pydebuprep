# needrestart — Services using outdated libraries

Services started before their libraries were upgraded keep using the old copies in
memory — including old versions with security holes — until they restart.

<!-- facts: needrestart -->

## What it checks

- `needrestart` in batch mode, listing services that use outdated libraries and
  whether a newer kernel is pending.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* services run outdated libraries | Restart them (the remediation lists the exact `systemctl restart` command), or reboot. |
| warning | needrestart reports a pending kernel upgrade | `sudo reboot`. |

## Commands it runs

```sh
needrestart -b -r l
```

`-r l` is **list** mode: needrestart only reports; it never restarts anything.

## Limitations

- Needs the `needrestart` package (recommended by pydebuprep's package) and root.
- After a reboot there's usually nothing to report; it matters most when you
  can't reboot right away.

<!-- options: needrestart -->
