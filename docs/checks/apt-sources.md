# apt-sources — APT sources

The upgrader rewrites the distribution's own sources, but third-party repositories
are usually disabled, left on the old release, or both. This check reads every
APT source and reports what still points at the past.

<!-- facts: apt-sources -->

## What it checks

It reads `/etc/apt/sources.list` and the files in `/etc/apt/sources.list.d/`, in
both the one-line (`.list`) and deb822 (`.sources`) formats, including entries the
upgrader commented out or disabled by renaming the file (`.distUpgrade`, `.save`,
`.disabled`, `.dpkg-old`, `.bak`).

- **Old release:** enabled sources whose suite names a different release than the
  one running (for example `bookworm` or `bookworm-security` on trixie).
- **Disabled third-party repositories** that nothing replaces.
- **Missing distribution archive:** no enabled source for Debian's or Ubuntu's own
  archive, so no security updates.
- **Duplicates:** the same target configured twice.
- **Debian suite aliases** (`stable`, `testing`, …), which move to the next release
  on their own.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | No enabled repository for the Debian/Ubuntu archive | Add the archive for the running release under `/etc/apt/sources.list.d/`, then `sudo apt update`. |
| warning | Repository still targets *suite* | Change the suite to the running release in the named file — after checking the vendor supports it. |
| warning | Third-party repository disabled | Re-enable it for the new release if the vendor supports it, otherwise remove it and the packages that came from it. |
| info | Duplicate repository entries | Remove the duplicate lines. |
| info | Debian archive uses suite alias *alias* | Consider the codename instead, so a new Debian release isn't installed unplanned. |

## Compared with a snapshot

The snapshot records every enabled repository. The report flags each one that was
enabled before and is now missing or disabled.

## Commands it runs

None: it only reads the source files.

## Limitations

- It checks configuration, not whether a repository works: it doesn't download
  anything, so it can't tell whether a repository is reachable or its signing key
  is valid. [`apt-lists-age`](apt-lists-age.md) shows how current the downloaded
  data is.
- "Third-party" means any host other than the Debian and Ubuntu archives
  (`debian.org`, `ubuntu.com`, `canonical.com`). Local mirrors of the distribution
  archive on other hosts count as third-party.

<!-- options: apt-sources -->
