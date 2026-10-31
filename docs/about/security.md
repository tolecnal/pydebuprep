# Security and releases

## Verifying a release

Every release is built by GitHub Actions from a release tag, installed and
[audited](read-only.md#3-its-audited) on each supported release, and published with
a `SHA256SUMS` file and a signed **build-provenance attestation**:

```sh
gh release download v0.6.0 -R tolecnal/pydebuprep
sha256sum -c SHA256SUMS
gh attestation verify pydebuprep_0.6.0_all.deb -R tolecnal/pydebuprep
```

`gh attestation verify` checks that the package was built by this repository's
release workflow, from a release tag, and hasn't been modified since. Install only
packages that pass both checks.

## How the project stays secure

- Every command pydebuprep runs must match a complete entry in a read-only
  allowlist, and every pull request and release is traced to prove a root run
  changes nothing. See [Read-only by design](read-only.md).
- Reports may contain text from logs and files written by other users; the
  human-readable formats escape it and strip terminal control sequences. Saved
  reports read back by `convert` are validated field by field, and YAML is loaded
  safely.
- Snapshots are readable only by root (directory `0700`, files `0600`).
- CodeQL, Bandit, ShellCheck, pip-audit and zizmor run on every change, and pull
  requests get a dependency review. Dependabot keeps pinned actions and tools up to
  date.
- GitHub Actions are pinned to commit hashes and run with least-privilege
  permissions. Release tags are protected; only maintainers can create them.

## Reporting a vulnerability

Please **don't** open a public issue. Report it privately through GitHub's
[security advisories](https://github.com/tolecnal/pydebuprep/security/advisories/new).
The [security policy](https://github.com/tolecnal/pydebuprep/blob/main/SECURITY.md)
lists what's in scope, what to include, and what to expect.

Anything that makes pydebuprep change the system it inspects is in scope — the
read-only promise is its most important property.
