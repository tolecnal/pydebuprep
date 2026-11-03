# Security and releases

## Verifying a release

Every release is built by GitHub Actions from a release tag, installed and
[audited](read-only.md#3-its-audited) on each supported release, and published with
a `SHA256SUMS` file and a signed **build-provenance attestation**:

```sh
gh release download v0.9.0 -R tolecnal/pydebuprep
sha256sum -c SHA256SUMS
gh attestation verify pydebuprep_0.9.0_all.deb -R tolecnal/pydebuprep
```

`gh attestation verify` checks that the package was built by this repository's
release workflow, from a release tag, and hasn't been modified since. Install only
packages that pass both checks.

## How the project stays secure

- Every command `pydebuprep report` and `snapshot` run must match a complete entry in
  a read-only allowlist, and every pull request and release is traced to prove a root
  run changes no system state or configuration. `pydebuprep-cleanup`, which changes
  the system on purpose, has an exact allowlist of its own. See
  [What pydebuprep changes](read-only.md).
- Reports may contain text from logs and files written by other users; the
  human-readable formats escape it and strip terminal control sequences. Saved
  reports read back by `convert` are validated field by field, and YAML is loaded
  safely.
- Snapshots are readable only by root (directory `0700`, files `0600`).
- The nginx and apache checks connect to this host's own TLS sites to compare the
  certificate served with the file configured. They connect only to loopback or to an
  address and port the kernel lists as listening here, and only to listeners owned by
  root (so not to a user's process holding a port a stopped server should have), never look a name up, and
  don't verify the certificate: it's compared, not trusted, and a connection that
  verified would fail on exactly the certificates worth reporting.
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
