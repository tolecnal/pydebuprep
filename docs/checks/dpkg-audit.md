# dpkg-audit — Broken or half-configured packages

An interrupted upgrade can leave packages unpacked but not configured, or the
dependency database inconsistent. Most other package operations fail until that's
fixed.

<!-- facts: dpkg-audit -->

## What it checks

- Every package's dpkg state, with each kind of problem reported separately because
  each has its own fix:
    - **unpacked** or **half-configured** — the upgrade stopped before configuring them;
    - **half-installed**, or marked **reinstall required** — their files may be
      incomplete;
    - **triggers awaited** or **triggers pending** — post-install processing (man
      pages, libraries, caches) hasn't run yet.
- `dpkg --audit`, for what the states don't show (for example a package missing its
  file list).
- `apt-get check`: unmet dependencies and a broken package database.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | *N* packages are unpacked but not configured | `sudo dpkg --configure -a`, then `sudo apt -f install`. |
| critical | *N* packages need reinstalling | `sudo apt install --reinstall PACKAGE…` (the remediation lists them). |
| warning | *N* packages are waiting for triggers | `sudo dpkg --triggers-only -a`. |
| critical | dpkg reports broken or half-configured packages | Only when the states above look fine: read dpkg's own words in the evidence. |
| critical | apt-get check reports unmet dependencies or a broken package database | `sudo apt -f install`, then `sudo dpkg --configure -a`. |

## Commands it runs

```sh
dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n'
dpkg --audit
apt-get check
```

## Limitations

- It reports dpkg's and apt's view of the package database. Damaged files of a
  correctly installed package are [`debsums`](debsums.md)'s job.

<!-- options: dpkg-audit -->
