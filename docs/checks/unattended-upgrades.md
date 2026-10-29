# unattended-upgrades — Automatic security updates

If automatic security updates stop after the upgrade, nothing tells you — the host
just quietly stops getting patched.

<!-- facts: unattended-upgrades -->

## What it checks

From APT's effective configuration (`apt-config dump`), when `unattended-upgrades`
is installed:

- that it's enabled (`APT::Periodic::Unattended-Upgrade "1"`, and
  `APT::Periodic::Enable` not `0`);
- that its allowed origins don't name an old release (they should use
  `${distro_codename}`).

With a snapshot: whether it was installed or enabled before and isn't now.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | unattended-upgrades is installed but disabled | `sudo dpkg-reconfigure -plow unattended-upgrades`. |
| warning | unattended-upgrades still names the old release *codename* | Edit `/etc/apt/apt.conf.d/50unattended-upgrades` to use `${distro_codename}`; test with `sudo unattended-upgrade --dry-run --debug`. |
| warning | unattended-upgrades was removed by the upgrade | `sudo apt install unattended-upgrades`. |

## Compared with a snapshot

The snapshot records whether it was installed and enabled.

## Commands it runs

```sh
apt-config dump
dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n'
```

## Limitations

- Not having unattended-upgrades installed isn't a finding: many hosts patch
  through other means.
- It checks the configuration, not whether updates actually ran recently
  (`/var/log/unattended-upgrades/`).

<!-- options: unattended-upgrades -->
