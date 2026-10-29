# apt-lists-age — Age of downloaded package lists

Several checks ([`apt-upgradable`](apt-upgradable.md),
[`obsolete-packages`](obsolete-packages.md), [`apt-autoremove`](apt-autoremove.md))
work from the package lists APT downloaded the last time `apt update` ran.
pydebuprep never refreshes them itself, so this check tells you how current that
data is.

<!-- facts: apt-lists-age -->

## What it checks

- The modification time of the newest `*_InRelease` / `*_Release` file in
  `/var/lib/apt/lists`.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | No downloaded package lists | `sudo apt update`. The package checks have no data until then. |
| info | Package lists are *N* days old | `sudo apt update`, then run pydebuprep again for current results. |

## Commands it runs

None: it only reads file times.

## Limitations

- It measures when the lists were downloaded, not whether the repositories they
  came from are still reachable or correct; see [`apt-sources`](apt-sources.md).

<!-- options: apt-lists-age -->
