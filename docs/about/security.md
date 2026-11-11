# Security and releases

## Verifying a release

Every release is built by GitHub Actions from a release tag, installed and
[audited](what-it-changes.md#3-its-audited) on each supported release, and published with
a `SHA256SUMS` file and a signed **build-provenance attestation**:

```sh
gh release download v0.16.0 -R tolecnal/pydebuprep
sha256sum -c SHA256SUMS
gh attestation verify pydebuprep_0.16.0_all.deb -R tolecnal/pydebuprep
```

`gh attestation verify` checks that the package was built by this repository's
release workflow, from a release tag, and hasn't been modified since. Install only
packages that pass both checks.

## How the project stays secure

- Every command `pydebuprep report` and `snapshot` run must match a complete entry in
  a allowlist, and every pull request and release is traced to prove a root
  run changes no system state or configuration. `pydebuprep-cleanup`, which changes
  the system on purpose, has an exact allowlist of its own. See
  [What pydebuprep changes](what-it-changes.md).
- Reports may contain text from logs and files written by other users; the
  human-readable formats escape it and strip terminal control sequences. Saved
  reports read back by `convert` are validated field by field, and YAML is loaded
  safely.
- Passwords, tokens and keys are redacted from everything a report quotes, by the shape
  of what is usually secret (`password=...`, `mysql -p...`, `user:secret@host`, ...). That
  can't recognise every secret, so treat reports as private, including on a portal. A quoted
  line longer than 2000 characters loses its tail.
- Snapshots are readable only by root (directory `0700`, files `0600`).
- Files that other users control are opened one directory at a time, refusing symlinks
  on the way, so swapping a directory for a link can't make root open a device.
- Regular expressions from a config are limited in number, length and shape, and
  matching stops after a minute, so a config can't keep a CPU busy for ever.
- The upload token is never passed on to the commands pydebuprep runs, and a command
  running as another user, such as PostgreSQL's probe, gets almost no environment.
- Don't give an unprivileged user `sudo` rights to `pydebuprep`. It is a tool for root:
  `--output`, `--config` and `--baseline` name files it writes and reads as root.
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
promise to change nothing is its most important property.
