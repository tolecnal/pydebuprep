# Check matrix

Each of pydebuprep's checks looks at several things. This page lists all of them, and
when each one runs. For what a finding means and what to do about it, follow a check's
name to its page.

Every check is on by default. To leave one out, use `enabled: false` in the
[configuration file](../configuration/index.md), or `--skip ID` for one run.

**Always** still depends on the check being able to run: a check is skipped when it needs
root and doesn't have it, when a program it needs isn't installed, or when the software it
looks at isn't there.

| Runs | Meaning |
|---|---|
| Always | On every report |
| As root | On every report run as root; otherwise that part is left out, while the rest of the check runs |
| With a snapshot | Only when the report compares with a [snapshot](../guide/snapshots.md) |
| On by default | On every report, unless the option named turns it off |
| Opt-in | Only when the option named turns it on |

<!-- check-matrix -->
