# apt-autoremove — Packages no longer needed

After an upgrade, libraries and tools from the old release often stay installed
although nothing depends on them any more.

<!-- facts: apt-autoremove -->

## What it checks

- What `apt autoremove` **would** remove, by simulating it (`-s`). Nothing is
  removed.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| info | *N* packages are no longer needed | Review the list first: some may be tools you installed by hand that were never marked as manual (`sudo apt-mark manual PACKAGE`). Then `sudo apt autoremove`. |

## Commands it runs

```sh
apt-get -s autoremove
```

Like every apt command pydebuprep runs, it adds options that stop apt from taking
locks, regenerating its caches or writing its solver log; see
[Read-only by design](../about/read-only.md).

## Limitations

- The result depends on APT's "automatically installed" marks, which may be wrong
  for packages installed in unusual ways.
- It uses the downloaded package lists; see [`apt-lists-age`](apt-lists-age.md).

<!-- options: apt-autoremove -->
