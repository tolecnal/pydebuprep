# dpkg-rc — Leftover configuration of removed packages

Packages removed (but not purged) during an upgrade leave their configuration
behind, in state `rc`.

<!-- facts: dpkg-rc -->

## What it checks

- Packages in state `rc` (removed, config files remain).

## Findings

| Severity | Finding | What to do |
|---|---|---|
| info | *N* removed packages still have configuration files | Review with `dpkg -l | grep ^rc`; purge what you don't need with `sudo apt purge PACKAGE…`. The remediation lists them in batches of 20, at most 5; beyond 100 packages it adds one command that purges them all. |

## Commands it runs

```sh
dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n'
```

## Limitations

- Purging is usually safe, but the configuration may hold settings you want if you
  reinstall the package later.

<!-- options: dpkg-rc -->
