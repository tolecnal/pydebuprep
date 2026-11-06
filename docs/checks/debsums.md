# debsums — Package file checksums

Package files that no longer match their recorded checksums can mean an
interrupted upgrade, a file overwritten by hand, or disk corruption.

!!! warning "This check can take a long time"
    It reads every file of every installed package: many minutes on a large system or slow
    disks, especially on a cold cache. It gives up after `timeout_seconds` (600). Leave it
    out with `--skip debsums`, or `enabled: false` in the configuration file.

<!-- facts: debsums -->

## What it checks

- Every installed package's files outside `/etc` against the MD5 sums dpkg
  recorded, with `debsums -c` (changed files only).

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* package files differ from or are missing compared to their packages | Find the owner with `dpkg -S PATH`, restore with `sudo apt install --reinstall PACKAGE`. |

## Commands it runs

```sh
debsums -c
```

## Limitations

- It's slow, as the warning above says. If it gives up, the check reports an error; raise
  `timeout_seconds` (at most 7200) or turn the check off.
- MD5 sums detect accidents, not tampering: anyone who can replace a file can
  replace its checksum too.
- Configuration files are skipped; see [`config-conflicts`](config-conflicts.md).
- Needs the `debsums` package (recommended by pydebuprep's package) and root.

<!-- options: debsums -->
