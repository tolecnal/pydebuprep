# postgresql — PostgreSQL clusters

A Debian or Ubuntu release upgrade installs the new PostgreSQL major version, but
leaves existing clusters on the old one until you migrate them with
`pg_upgradecluster` — and the old server version stops getting updates once its
packages are gone.

<!-- facts: postgresql -->

## What it checks

From `pg_lsclusters` and the installed server versions:

- clusters still on an older major version than the newest installed server;
- old clusters left behind after migrating (a newer cluster with the same name
  exists);
- clusters that are down although their `start.conf` says they should start
  automatically.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | PostgreSQL cluster *V/name* still uses version *V*; *N* is installed | `sudo pg_upgradecluster V NAME` — or, if it was already migrated, check the new cluster has your data, then `sudo pg_dropcluster V NAME`. |
| warning | PostgreSQL cluster *V/name* is down | `sudo systemctl status postgresql@V-NAME`; read its log under `/var/log/postgresql/`. |
| warning | PostgreSQL clusters online before the upgrade aren't now | `pg_lsclusters`; a migrated cluster may have a new version. |

## Compared with a snapshot

The snapshot records the clusters that were online.

## Commands it runs

```sh
pg_lsclusters --no-header
```

It never connects to a database.

## Limitations

- Only clusters managed by Debian's `postgresql-common` are seen.
- Whether a cluster answers queries isn't tested.

<!-- options: postgresql -->
