# apt-upgradable — Pending package upgrades

Packages still upgradable after a release upgrade are usually stragglers whose
dependencies changed; a second `full-upgrade` pass normally picks them up.

<!-- facts: apt-upgradable -->

## What it checks

The packages APT lists as upgradable, sorted into what they mean:

- **security updates** — from a suite ending in `-security` (`noble-security`,
  `trixie-security`, `oldstable-security`);
- **kept back** — upgrades `apt upgrade` won't install because their dependencies
  changed (from a simulated `apt-get upgrade`); after a release upgrade, often
  leftovers of the old release;
- **deferred by phasing** — Ubuntu rolls some updates out gradually, and this machine
  gets them later: expected, nothing to do;
- **everything else.**

A security update that is kept back counts as a security update.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* security updates are pending | `sudo apt update && sudo apt upgrade`. |
| warning | *N* packages are kept back | See why: `sudo apt-get -s install PACKAGE`; then `sudo apt full-upgrade`. |
| info | *N* updates are deferred by phasing | Nothing; apt installs them once the phase reaches this machine. |
| info | *N* other packages can be upgraded | `sudo apt update && sudo apt full-upgrade`. |

## Commands it runs

```sh
apt list --upgradable
apt-get -s upgrade
```

The second only when something is upgradable. `-s` simulates: nothing is installed.
Like every apt command pydebuprep runs, both get options that stop apt from taking
locks, regenerating its caches or writing its solver log.

## Limitations

- Based on the downloaded package lists; pydebuprep never runs `apt update`. See
  [`apt-lists-age`](apt-lists-age.md).
- "Security" is judged by the suite name. Vendors' repositories rarely have a
  separate security suite, so their fixes count as other updates.

<!-- options: apt-upgradable -->
