# os-release — Operating system release

Confirms the system runs a supported release and, with a snapshot, shows the
upgrade path and sanity-checks the baseline itself.

<!-- facts: os-release -->

## What it checks

- `/etc/os-release`: the distribution, version and codename.
- With a baseline: the release it was taken on, and the host it was taken on.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | Unsupported release *name* | Confirm it's the release you meant to upgrade to. pydebuprep supports Debian 12–13 and Ubuntu 22.04–26.04; on others its results may be incomplete. |
| warning | Baseline is from host *other* | The snapshot was taken on a different machine; pass the right one with `--baseline`, or use `--no-baseline`. |
| warning | Baseline was taken on the same release | It may be a post-upgrade snapshot; pick the pre-upgrade one with `--baseline FILE`. |
| info | Upgraded from *old* to *new* | Read the release notes' known-issues section for this path. |

## Compared with a snapshot

The baseline's release and host are compared with the current ones, as above.

## Commands it runs

None: it reads `/etc/os-release`.

## Limitations

- It trusts `/etc/os-release`. A half-finished upgrade can leave it on the new
  release while many packages are still old; the package checks catch that.

<!-- options: os-release -->
