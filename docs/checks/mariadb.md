# mariadb — MariaDB data directory

After a major MariaDB upgrade, the system tables must be upgraded too (with
`mariadb-upgrade`). Until then, some features and permissions may misbehave.

<!-- facts: mariadb -->

## What it checks

- The server version (`mariadbd --version`) against the version the data directory
  was last upgraded for (`/var/lib/mysql/mariadb_upgrade_info`, or
  `mysql_upgrade_info`).

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | MariaDB data was last upgraded for *X.Y*; the server is *X.Y* | `sudo mariadb-upgrade`. |

## Commands it runs

```sh
mariadbd --version
```

It never connects to the server.

## Limitations

- Only MariaDB is checked. Oracle MySQL upgrades its system tables itself at
  startup.
- It doesn't check that the server runs; see
  [`systemd-failed`](systemd-failed.md) and
  [`systemd-critical-services`](systemd-critical-services.md).
- Needs root: the data directory is readable only by `mysql` and root.

<!-- options: mariadb -->
