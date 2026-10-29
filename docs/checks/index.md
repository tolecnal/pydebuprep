# Checks

pydebuprep runs 37 checks, in eight categories, in the order below. Each check's
page explains what it looks at, what it can report and what to do about it, which
commands it runs, how it uses a snapshot, its options, and its limits.

**Root** means the check needs root to read what it inspects; without it the check
is reported as skipped. **Snapshot** means it records state when you take a
snapshot and reports what changed since.

<!-- checks-index -->

## Choosing checks

- For one run: `--checks ID,...` or `--skip ID,...`.
- Permanently: `enabled: false` under the check in the
  [configuration file](../configuration/index.md).
- `pydebuprep list-checks --verbose` lists every check with its options.
