# Snapshots and baselines

A **snapshot** records how the system looks, so that a later report can say what
changed. Taken before an upgrade, it becomes the **baseline** for the report after.

## Taking a snapshot

```sh
sudo pydebuprep snapshot
# /var/lib/pydebuprep/snapshots/20261028T120000Z.json
```

Each check that supports comparison stores what it needs. The check pages say
whether a check takes part ("Compares with a snapshot"). The snapshot is a JSON
file, readable only by root: the directory is created with mode `0700` and each
file with mode `0600`, because it lists the system's services, network and
packages.

Use `--snapshot-dir DIR` (or `snapshot_dir` in the configuration) to keep snapshots
elsewhere. The same directory is where `report` looks for them.

!!! note "A snapshot is the one thing pydebuprep writes"
    `snapshot` writes its own file and nothing else. The read-only audit allows
    exactly that one path for it.

## Comparing against a baseline

`report` uses the newest snapshot in the snapshot directory automatically. Each
check that has baseline data adds a **"Changes since baseline"** section. Choose
another baseline, or none:

```sh
sudo pydebuprep report --baseline /var/lib/pydebuprep/snapshots/20261020T080000Z.json
sudo pydebuprep report --no-baseline
```

or in the configuration file: `baseline: auto | none | /path/to/snapshot.json`.

Without a baseline, the report says so once, in its header, and each check reports
only what it sees now.

## When the baseline looks wrong

The report warns when the baseline

- was taken on **another host** (snapshots copied between machines), or
- was taken on the **same release** as now — it may be a snapshot taken after the
  upgrade by mistake, in which case "nothing changed" means little.

## What a comparison can and can't tell you

A comparison reports what was there **before** and isn't **now**: a service no
longer running, a repository disabled, an interface without its address. It can't
tell whether the change was intended — you may have removed that service on
purpose. Treat these findings as questions to answer, not errors to undo.

A snapshot reflects one moment. Services that were stopped by chance when you took
it won't be missed later, and containers or VMs that come and go create noise; some
checks have options to ignore those (for example
[`network`](../checks/network.md)'s `ignore_interfaces`).
