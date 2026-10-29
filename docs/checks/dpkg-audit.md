# dpkg-audit — Broken or half-configured packages

An interrupted upgrade can leave packages unpacked but not configured, or the
dependency database inconsistent. Most other package operations fail until that's
fixed.

<!-- facts: dpkg-audit -->

## What it checks

- `dpkg --audit`: packages that are half-installed, half-configured, or waiting
  for triggers.
- `apt-get check`: unmet dependencies and a broken package database.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | dpkg reports broken or half-configured packages | `sudo dpkg --configure -a`, then `sudo apt -f install`. |
| critical | apt-get check reports unmet dependencies or a broken package database | `sudo apt -f install`, then `sudo dpkg --configure -a`. |

The evidence shows the tools' own output.

## Commands it runs

```sh
dpkg --audit
apt-get check
```

## Limitations

- It reports what dpkg and apt report, grouped into one finding each; the
  evidence has the details.

<!-- options: dpkg-audit -->
