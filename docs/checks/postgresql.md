# postgresql — PostgreSQL clusters

A Debian or Ubuntu release upgrade installs the new PostgreSQL major version, but
leaves existing clusters on the old one until you migrate them with
`pg_upgradecluster` — and the old server version stops getting updates once its
packages are gone. Optionally, it also asks each cluster whether it really serves.

<!-- facts: postgresql -->

## What it checks

From `pg_lsclusters` and the installed server versions:

- clusters still on an older major version than the newest installed server;
- old clusters left behind after migrating (a newer cluster with the same name
  exists);
- clusters that are down although their `start.conf` says they should start
  automatically.

**Readiness probe** (`probe: true`, off by default). For each **online** cluster, two
separate questions:

1. **Does it accept connections?** `pg_isready` on the cluster's port, over the
   local socket. No login needed.
2. **Does it answer a query?** `SELECT 1` on the `postgres` database, logged in as
   the `postgres` system user (peer authentication, never prompting for a password).
   With `credentials_file` (a [`.pgpass`](https://www.postgresql.org/docs/current/libpq-pgpass.html)
   file), the user of its first entry logs in with that file instead.

A cluster can pass the first and fail the second (for example while it recovers), and
the report says which. Passing both shows the server works; it doesn't prove every
database, extension or application query does.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | PostgreSQL cluster *V/name* still uses version *V*; *N* is installed | `sudo pg_upgradecluster V NAME` — or, if it was already migrated, check the new cluster has your data, then `sudo pg_dropcluster V NAME`. |
| warning | PostgreSQL cluster *V/name* is down | `sudo systemctl status postgresql@V-NAME`; read its log under `/var/log/postgresql/`. |
| warning | PostgreSQL cluster *V/name* doesn't accept connections | (probe) It's listed as online but `pg_isready` gets no answer, or it's starting or shutting down. Check its service and log. |
| warning | PostgreSQL cluster *V/name* accepts connections but doesn't answer queries | (probe) The evidence shows psql's error. Check the log. |
| info | Couldn't log in to PostgreSQL cluster *V/name* to probe it | (probe) The server refused the probe's login; set `credentials_file`. |
| info | Can't use the PostgreSQL credentials file *path* | (probe) It's missing, unreadable, or has no entry with a user name. |
| info | Readiness probes need root; not run | (probe) Run as root. |
| warning | PostgreSQL clusters online before the upgrade aren't now | `pg_lsclusters`; a migrated cluster may have a new version. |

## Compared with a snapshot

The snapshot records the clusters that were online.

## Commands it runs

```sh
pg_lsclusters --no-header
```

With `probe: true`, for each online cluster:

```sh
pg_isready -h /var/run/postgresql -p PORT
setpriv --reuid=postgres --regid=postgres --init-groups -- psql -X -A -t -w -h /var/run/postgresql -p PORT -d postgres -c 'SELECT 1'
# or, with credentials_file:
psql -X -A -t -w -d 'host=/var/run/postgresql port=PORT dbname=postgres user=USER passfile=FILE' -c 'SELECT 1'
```

`setpriv` switches to the `postgres` user without PAM, so no login session is
logged. `-X` skips `~/.psqlrc`, `-w` never prompts. The allowlist accepts only these
forms, with the port, user and file validated; the query is always `SELECT 1`.

## Limitations

- Only clusters managed by Debian's `postgresql-common` are seen.
- **The probe connects to the server**, so PostgreSQL may log the connection or
  count it in its statistics — pydebuprep itself writes nothing. That's why it's off
  by default.
- Clusters listening only on TCP, or with a socket directory other than
  `/var/run/postgresql`, can't be probed.

<!-- options: postgresql -->
