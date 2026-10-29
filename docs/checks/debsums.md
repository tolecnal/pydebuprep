# debsums — Package file checksums

Package files that no longer match their recorded checksums can mean an
interrupted upgrade, a file overwritten by hand, or disk corruption.

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

- It reads every packaged file, which takes minutes on large systems, especially
  the first time (cold cache); `timeout_seconds` limits it. Turn the check off on
  hosts where that's too slow.
- MD5 sums detect accidents, not tampering: anyone who can replace a file can
  replace its checksum too.
- Configuration files are skipped; see [`config-conflicts`](config-conflicts.md).
- Needs the `debsums` package (recommended by pydebuprep's package) and root.

<!-- options: debsums -->
