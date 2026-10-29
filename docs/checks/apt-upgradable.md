# apt-upgradable — Pending package upgrades

Packages still upgradable after a release upgrade are usually stragglers whose
dependencies changed; a second `full-upgrade` pass normally picks them up.

<!-- facts: apt-upgradable -->

## What it checks

- The packages APT lists as upgradable.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* packages can still be upgraded | `sudo apt update && sudo apt full-upgrade`. |

## Commands it runs

```sh
apt list --upgradable
```

## Limitations

- Based on the downloaded package lists; pydebuprep never runs `apt update`. See
  [`apt-lists-age`](apt-lists-age.md).
- It doesn't tell security updates from other updates, or explain why a package is
  held back; `apt-get -s full-upgrade` shows that.

<!-- options: apt-upgradable -->
