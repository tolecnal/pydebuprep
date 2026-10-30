# obsolete-packages — Packages not available from any repository

Packages that no configured repository provides any more get no security updates.
After a release upgrade these are usually packages dropped from the new release,
or installed from a repository that was disabled.

<!-- facts: obsolete-packages -->

## What it checks

- **Obsolete:** installed packages APT marks as `local` — not available from any
  enabled repository.
- **Third-party:** where each installed version comes from, read from APT's
  downloaded package indexes (`/var/lib/apt/lists/*_Packages`, plain or `.gz`). A
  version the distribution's archive has counts as the distribution's; the others are
  grouped by vendor, named by their repository's `Origin` and host
  (`Docker (download.docker.com)`).
- With a snapshot: packages that were removed, and packages whose origin changed — a
  vendor's package replaced by the distribution's, or the reverse.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* installed packages are not available from any configured repository | Inspect each with `apt policy PACKAGE`; replace it with the new release's equivalent, or remove it. |
| info | *N* packages come from third-party repositories | They get updates only from their vendors: keep those repositories enabled and pointing at this release. |
| warning | *N* packages come from a different origin than before the upgrade | Check each with `apt policy PACKAGE`; pin the origin you want in `/etc/apt/preferences.d/` if needed. |
| info | *N* packages removed since baseline | Check nothing you rely on is gone; reinstall with `sudo apt install PACKAGE`. |

## Compared with a snapshot

The snapshot records every installed package, its version, and where it came from.
Snapshots taken by versions before 0.4 have no origins; with those, only removed
packages are compared.

## Commands it runs

```sh
apt list --installed
dpkg-query -W -f='${Package}\t${Version}\n'
```

The origins come from reading APT's package index files.

## Limitations

- Based on the downloaded package lists: a repository that's configured but whose
  lists were never downloaded makes its packages look obsolete. Run `sudo apt update`
  first; see [`apt-lists-age`](apt-lists-age.md).
- Indexes compressed with anything but gzip (some container images use lz4) aren't
  read, so their packages' origins are unknown.
- Packages you built or installed from `.deb` files yourself always show up as
  obsolete.

<!-- options: obsolete-packages -->
