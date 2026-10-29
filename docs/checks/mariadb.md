# mariadb — MariaDB and MySQL

After a major MariaDB upgrade, the system tables must be upgraded too (with
`mariadb-upgrade`); until then, some features and permissions may misbehave.
Optionally, it also asks the server — MariaDB or Oracle MySQL — whether it answers.

<!-- facts: mariadb -->

## What it checks

- **MariaDB:** the server version (`mariadbd --version`) against the version the data
  directory was last upgraded for (`/var/lib/mysql/mariadb_upgrade_info`, or
  `mysql_upgrade_info`).
- **MySQL** (`mysqld`) is recognised too. It upgrades its system tables itself at
  startup, so it only takes part in the probe.

**Readiness probe** (`probe: true`, off by default), two separate questions:

1. **Is the server alive?** `mariadb-admin ping` (or `mysqladmin ping`).
2. **Does it run a query?** `SELECT 1` against `information_schema`.

Both log in as `root` over the Unix socket, the default on Debian and Ubuntu. With
`credentials_file`, an option file with a `[client]` section (`user=`, `password=`)
is used instead — for example `/etc/mysql/debian.cnf` where it exists. A refused login
is reported as such, not as a broken server.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | MariaDB data was last upgraded for *X.Y*; the server is *X.Y* | `sudo mariadb-upgrade`. |
| warning | The MariaDB/MySQL server doesn't answer | (probe) `sudo systemctl status mariadb` (or `mysql`) and its journal. |
| warning | The MariaDB/MySQL server answers but doesn't run queries | (probe) The evidence shows the error; check the server's error log. |
| info | Couldn't log in to the MariaDB/MySQL server to probe it | (probe) Set `credentials_file`. |

## Commands it runs

```sh
mariadbd --version
```

With `probe: true` (MariaDB's names, or MySQL's `mysqladmin` and `mysql`):

```sh
mariadb-admin [--defaults-extra-file=FILE] ping
mariadb [--defaults-extra-file=FILE] -N -B -e 'SELECT 1' information_schema
```

The allowlist accepts only these forms; the query is always `SELECT 1`.

## Limitations

- **The probe connects to the server**, which may log it; pydebuprep itself writes
  nothing. That's why it's off by default.
- It doesn't check that the service is enabled or running beyond the probe; see
  [`systemd-failed`](systemd-failed.md) and
  [`systemd-critical-services`](systemd-critical-services.md).
- Needs root: the data directory is readable only by `mysql` and root, and the probe
  logs in as root.
- Skipped when neither MariaDB nor MySQL is installed; the probe is skipped when
  their client tools aren't.

<!-- options: mariadb -->
