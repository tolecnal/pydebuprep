# obsolete-packages — Packages not available from any repository

Packages that no configured repository provides any more get no security updates.
After a release upgrade these are usually packages dropped from the new release,
or installed from a repository that was disabled.

<!-- facts: obsolete-packages -->

## What it checks

- Installed packages APT marks as `local`: not available from any enabled
  repository.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* installed packages are not available from any configured repository | Inspect each with `apt policy PACKAGE`; replace it with the new release's equivalent, or remove it. |
| info | *N* packages removed since baseline | Check nothing you rely on is gone; reinstall with `sudo apt install PACKAGE`. |

## Compared with a snapshot

The snapshot records every installed package and version; the report lists those
that are gone.

## Commands it runs

```sh
apt list --installed
dpkg-query -W -f='${Package}\t${Version}\n'
```

## Limitations

- Based on the downloaded package lists: a repository that's configured but whose
  lists were never downloaded makes its packages look obsolete. Run `sudo apt update`
  first; see [`apt-lists-age`](apt-lists-age.md).
- Packages you built or installed from `.deb` files yourself always show up here.

<!-- options: obsolete-packages -->
