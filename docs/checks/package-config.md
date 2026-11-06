# package-config — APT pinning, architectures, diversions and alternatives

These settings decide which package you get and which program a command runs. An upgrade
can change them without any package looking wrong.

<!-- facts: package-config -->

## What it checks

- Every alternative (`/var/lib/dpkg/alternatives/*`) whose link in `/etc/alternatives`
  points to something that exists.
- With a snapshot, everything below.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* alternatives point to nothing | `sudo update-alternatives --config NAME`. |
| warning | *N* APT pinning files are gone | Packages they pinned may come from elsewhere now: `apt policy PACKAGE`. |
| info | *N* APT pinning files are new or changed | As above. |
| warning | *N* package architectures are no longer enabled | `sudo dpkg --add-architecture ARCHITECTURE`. |
| info | *N* package architectures are newly enabled | Check you want them. |
| warning | *N* local diversions are gone | A file you diverted is back under its package's control: `dpkg-divert --list`. |
| info | *N* diversions have new owners | Usually a package taking over from another. |
| warning | *N* alternatives chosen by hand are different now | `sudo update-alternatives --config NAME`. |
| info | *N* automatic alternatives point elsewhere | Usually expected: a newer version took over. |

## Compared with a snapshot

The snapshot records a checksum of `/etc/apt/preferences` and each file in
`/etc/apt/preferences.d/`, the enabled architectures (`/var/lib/dpkg/arch`), the diversions
(`/var/lib/dpkg/diversions`) and each alternative's mode and target. A package's own
diversion that goes away is expected, so only an administrator's are reported as gone.

## Commands it runs

None; it reads the files above.

## Limitations

- It says that a pinning file changed, not how: the snapshot keeps only a checksum.
- Only each alternative's main link is checked, not its followers such as man pages.

<!-- options: package-config -->
