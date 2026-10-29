# apparmor — AppArmor

Debian and Ubuntu confine many services with AppArmor. An upgrade can bring
profiles that don't fit your configuration (and start denying), or leave profiles
unloaded.

<!-- facts: apparmor -->

## What it checks

- Whether AppArmor is enabled in the kernel.
- Profiles in **complain** mode (logging instead of blocking).
- **Denials** in the kernel log this boot, grouped by profile and operation.
- With a snapshot: profiles that were enforced and now aren't (in complain mode, or
  no longer loaded).

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | AppArmor is disabled | Check the kernel command line (`apparmor=0`, `security=`); `sudo systemctl enable --now apparmor`. |
| warning | *N* AppArmor denials this boot | `sudo journalctl -b -k --grep='apparmor="DENIED"'`; a profile from the new release may not fit your configuration. |
| warning | *N* AppArmor profiles are no longer enforced | `sudo aa-status`; `sudo aa-enforce PROFILE`. |
| info | *N* AppArmor profiles are in complain mode | `sudo aa-enforce PROFILE` once it no longer logs denials. |

## Compared with a snapshot

The snapshot records whether AppArmor was enabled and each profile's mode.

## Commands it runs

```sh
journalctl -b -k --no-pager -o cat --grep='apparmor="DENIED"'
```

Profiles and their modes are read from `/sys/kernel/security/apparmor/profiles`.

## Limitations

- Needs root to read the profile list.
- Denials are read from the journal; without journald, only the profile part runs.
- Skipped when the kernel has no AppArmor support.

<!-- options: apparmor -->
