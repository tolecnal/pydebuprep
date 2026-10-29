# apt-sources — APT sources

The upgrader rewrites the distribution's own sources, but third-party repositories
are usually disabled, left on the old release, or both — and keys and metadata can
break without any configuration change. This check reads every APT source and what
APT downloaded for it, and reports what no longer works or still points at the past.

<!-- facts: apt-sources -->

## What it checks

It reads `/etc/apt/sources.list` and the files in `/etc/apt/sources.list.d/`, in
both the one-line (`.list`) and deb822 (`.sources`) formats, including entries the
upgrader commented out or disabled by renaming the file (`.distUpgrade`, `.save`,
`.disabled`, `.dpkg-old`, `.bak`).

**Configuration:**

- **Old release:** enabled sources whose suite names a different release than the
  one running (for example `bookworm` or `bookworm-security` on trixie).
- **Disabled third-party repositories** that nothing replaces.
- **Missing distribution archive:** no enabled source for Debian's or Ubuntu's own
  archive, so no updates at all.
- **Missing security archive:** the distribution archive without its
  `<codename>-security` suite (not reported on Debian unstable, which has none).
- **Duplicates:** the same target configured twice.
- **Debian suite aliases** (`stable`, `testing`, …), which move to the next release
  on their own.

**Keys:**

- **Missing keyring:** a source's `Signed-By` keyring file doesn't exist, so apt
  refuses the repository.
- **Legacy keyring:** keys left in `/etc/apt/trusted.gpg`, which newer apt versions
  warn about or ignore.

**What APT downloaded** (in `/var/lib/apt/lists`, from the last `apt update`):

- **No metadata:** no `InRelease` or `Release` file for an enabled repository — its
  last update failed (a wrong key, a suite the vendor doesn't publish, a network
  problem).
- **Different release:** the repository's metadata names another `Suite` and
  `Codename` than the source asks for. Like apt, a vendor suite such as
  `jammy/mongodb-org/7.0` also matches without its last part.
- **Signature:** each downloaded `InRelease` is verified again against the keys apt
  would use — the `Signed-By` keyring (wherever it is), an inline key, or the
  default `trusted.gpg.d` keyrings. APT verified the file when it downloaded it, so a
  failure now means the keys changed since (removed, replaced, expired): the next
  `apt update` will reject the repository.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | No enabled repository for the Debian/Ubuntu archive | Add the archive for the running release under `/etc/apt/sources.list.d/`, then `sudo apt update`. |
| critical | Signing keyring *path* is missing | Reinstall the vendor's keyring package, or download its key again to that path; then `sudo apt update`. |
| critical | Metadata of *N* repositories doesn't verify against its keys | Get the vendor's current key and point `Signed-By` at it; then `sudo apt update`. The evidence shows the verifier's reason. |
| warning | Repository still targets *suite* | Change the suite to the running release in the named file — after checking the vendor supports it. |
| warning | Third-party repository disabled | Re-enable it for the new release if the vendor supports it, otherwise remove it and the packages that came from it. |
| warning | No security updates repository for *codename* | Add `CODENAME-security` next to the archive (`security.debian.org/debian-security` or `security.ubuntu.com/ubuntu`). |
| warning | Keys in the legacy keyring /etc/apt/trusted.gpg | Export each vendor's key to `/etc/apt/keyrings/`, reference it with `signed-by=`, then remove `/etc/apt/trusted.gpg`. |
| warning | No downloaded metadata for *N* repositories | `sudo apt update`, and read the errors it prints. |
| warning | *N* repositories serve a different release than configured | Set each source's suite to what the vendor publishes for this release. |
| info | Duplicate repository entries | Remove the duplicate lines. |
| info | Debian archive uses suite alias *alias* | Consider the codename instead, so a new Debian release isn't installed unplanned. |

A source whose keyring is missing isn't also reported for missing metadata or
signatures: that's the cause. When `apt update` has never run, nothing is reported
about metadata; [`apt-lists-age`](apt-lists-age.md) reports that.

## Compared with a snapshot

The snapshot records every enabled repository. The report flags each one that was
enabled before and is now missing or disabled.

## Commands it runs

One of these per repository, to verify its `InRelease`, depending on what's
installed — `sqv` on Debian 13, `gpgv` on the other releases:

```sh
sqv --keyring SCRATCH/key-N-0.gpg [--keyring ...] --cleartext --output SCRATCH/out-N /var/lib/apt/lists/..._InRelease
gpgv --keyring SCRATCH/key-N-0.gpg [--keyring ...] /var/lib/apt/lists/..._InRelease
```

`SCRATCH` is a private directory pydebuprep creates under `/tmp` (mode `0700`) and
removes before the check returns. The keys are copied there in binary form — `gpgv`
can't read ASCII-armored keys, so pydebuprep de-armors them itself — and `sqv` writes
its output there. The allowlist accepts these commands only with keyrings from
`/etc/apt/`, `/usr/share/keyrings/` or the scratch directory, output into the
scratch directory, and an `InRelease` from APT's lists. See
[Read-only by design](../about/read-only.md#what-it-does-write).

Everything else comes from reading files.

## Limitations

- **It never runs `apt update`.** Metadata findings describe the last update; whether
  a repository is reachable right now can't be known. Each finding says so.
  [`apt-lists-age`](apt-lists-age.md) shows how old that data is.
- A local `Release` past its `Valid-Until` date only means the lists are stale, so
  it isn't reported separately.
- Signatures aren't verified when neither `sqv` nor `gpgv` is installed, for
  repositories that only have a `Release` file (no `InRelease`), or when `Signed-By`
  names key fingerprints instead of files.
- Flat repositories (`deb URL ./`), local `file:` sources, CD-ROMs, `mirror+` and
  `tor+` sources have no metadata files pydebuprep can locate; they're checked for
  configuration only.
- "Third-party" means any host other than the Debian and Ubuntu archives
  (`debian.org`, `ubuntu.com`, `canonical.com`). Local mirrors of the distribution
  archive on other hosts count as third-party.

<!-- options: apt-sources -->
