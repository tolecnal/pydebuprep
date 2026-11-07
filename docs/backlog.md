# Backlog

What is still open, as of 2026-11-07 (after pydebuprep 0.15.1 and the portal release built on it). Remove items as they are done.

## GitHub repository settings

Done on 2026-10-29: Dependabot alerts and security updates, secret scanning with push
protection, private vulnerability reporting, CodeQL default setup off (the workflow is
an advanced setup), and these rulesets next to the owner's `protet-main-branch`
(no deletion or force-push of `main`):

- `main: pull requests and checks`: changes go through a pull request; tests on all
  Python versions, the Security/CodeQL jobs and, since 2026-11-05, the package audits
  (plain and systemd containers) on Ubuntu 22.04 and 26.04 and Debian 13 must pass.
- `release tags: admins only, immutable`: only admins create `v*` tags, and they can't
  be moved or deleted.

Secret scanning for non-provider patterns and validity checks: asked for on
2026-11-01, but GitHub doesn't turn them on for repositories of a personal account
(they come with GitHub Secret Protection); the API accepts the change and nothing
happens. Revisit if the repositories move to an organization.

## Release

Released `v0.2.0` on 2026-10-29: built and audited on all five releases, published
with `SHA256SUMS`, and the SLSA provenance attestation verified with
`gh attestation verify`.

`v0.3.0` and `v0.3.1` (the apt solver log fix) released on 2026-10-29, both built
and audited on all five releases, published with `SHA256SUMS` and a verified
provenance attestation.

`v0.4.0` released on 2026-10-30, built and audited on all five releases, published
with `SHA256SUMS` and a verified provenance attestation; what it contains is in
`debian/changelog`.

`v0.5.0` (portal support in the CLI) released on 2026-10-31, published with
`SHA256SUMS` and a verified provenance attestation.

`v0.6.0` (security hardening from an external review) released on 2026-10-31,
published with `SHA256SUMS` and a verified provenance attestation.

`v0.7.0` (limits on config regular expressions, re-checked opens, a typed package)
released on 2026-10-31, published with `SHA256SUMS` and a verified provenance
attestation.

`v0.8.0` (a hashed machine ID in reports; the nginx, apache and libvirt checks)
released on 2026-11-01, published with `SHA256SUMS` and a verified provenance
attestation.

`v0.9.0` (TLS certificates, snapshot comparisons, a certificate probe and the
configuration tests in the nginx and apache checks; the php and certbot checks; the
first agreed side effects) released on 2026-11-02, published with `SHA256SUMS` and a
verified provenance attestation. Its report format is unchanged, so portal 0.3.0 and
newer take its reports.

`v0.15.0` (2026-11-07) has a tag but no release: `tests/test_since_snapshot.py` needed
`jsonschema`, which package builds don't have, and pull requests skip that test run. Tags
can't be moved, so `v0.15.1` followed, with the same content and the fix. The manual CI run
in the README's release steps exists because of this.

- [ ] Before the next release: bump `debian/changelog` (`dch -v X.Y.Z`) and
      `__version__` together. The Release workflow refuses a tag that doesn't
      match both.
- Decided on 2026-11-01: no APT repository for now; the package stays a release asset.
  Revisit if hosts should get updates through `apt`.

## Portal

[pydebuprep-portal](https://github.com/tolecnal/pydebuprep-portal) has the same
rulesets as this repository: changes go through a pull request, and the tests, the
Docker smoke test and the security checks (Bandit, ShellCheck, pip-audit, zizmor,
CodeQL, dependency review) must pass; only admins create `v*` tags. Released `v0.1.0`
on 2026-11-01: the image `ghcr.io/tolecnal/pydebuprep-portal`, public, with a
verified provenance attestation. `v0.2.0` (the sidebar layout) and `v0.3.0` (machine
IDs, hosts by release, kernel and silence, full-text findings, CSV; built on pydebuprep
0.8.0) followed the same day, then `v0.4.0` (PostgreSQL 18, moved over with
`scripts/upgrade-postgres-18.sh`) and, on 2026-11-03, `v0.5.0` (built on pydebuprep
0.9.0: what each report was compared with and the changes since its snapshot, a
host's upgrades as a chain, and the new checks and options in the config generator).
Dependabot keeps its actions, Python dependencies and images current, like this
repository's.

- [ ] Before each release: bump `__version__`, the `CHANGELOG.md` heading and the
      image tag in `compose.yaml` together; the Release workflow refuses a tag that
      doesn't match the version.
- [ ] When a pydebuprep release adds report fields, release a portal built on it
      before hosts upgrade: a portal refuses fields its pydebuprep doesn't know.

## Checks not implemented yet

Done on 2026-10-29: network, firewall, time-sync, AppArmor, unattended-upgrades, cron,
ssh-server, the boot critical chain, the `/` and `/var` free-space floor, and the
application checks postgresql, mariadb, postfix, bind, docker and python-venvs. Each
passes `scripts/readonly-audit.sh` with the service installed.

Done on 2026-11-02 (0.9.0): TLS certificates, crypto OpenSSL refuses and server names
in the nginx and apache checks; their modules, configuration files and listeners
compared with the snapshot; a probe comparing served certificates with the files;
`nginx -t` and `apache2ctl -t` as the first agreed side effects (listed in
docs/about/what-it-changes.md); and the php and certbot checks.

Done on 2026-11-03 (0.10.0): `pydebuprep-cleanup`, a separate command in
`/usr/sbin` that purges old kernels, their modules and headers, leftover kernel
directories and removed packages' configuration (dry run by default, conffiles backed
up, logged to a file and syslog), with its man page and completions. The docs no longer
promise "read-only": pydebuprep changes no settings or runtime state, keeps scratch
files under `/tmp` or `/var/tmp` and removes them, and leaves nothing else behind.

- [ ] Dropped from the wish list, with reasons:
      - WireGuard/OpenVPN tunnels: covered by the network check's interface comparison;
      - `postfix check`: creates missing directories, so postfix uses `postconf -n`;
      - Podman, LXD (`lxc`) and libvirt (`virsh`) clients: they create configuration or
        storage directories on first use, or need a daemon that may not be running;
      - `ufw status`: writes `/run/ufw.lock`, so the firewall check reads ufw's config
        and the loaded rules instead;
      - loaded DKMS modules (`lsmod`), `~` versions, `apt policy` for key packages:
        little value beyond the existing dkms and obsolete-packages checks.

## Verification gaps

Closed on 2026-10-29: CI builds the package on every pull request and audits it in
containers booted with systemd (services running, the runner's UEFI variables mounted)
and on the Ubuntu runner VMs, so `systemctl`, `journalctl`, `systemd-analyze`,
`resolvectl`, `docker` and `efibootmgr` are now exercised; `AUDIT_EXPECT` fails the
audit if one of them stops running.

- [ ] Paste a report with `--todo` into real on-prem Jira (`jira-legacy`, for the bold
      header labels) and on-prem Confluence (`confluence-legacy`): the TODO tables and
      icons render. The TODO table no longer uses Confluence's status macro, whose `|` can
      end a table cell (it uses `{color}`, as Jira does). `jira-cloud` and
      `confluence-cloud` are confirmed in the real products.
- [ ] Still only on real hosts: `docker` on Debian (no runner VM), and the checks'
      behaviour on real hardware (RAID, multiple disks, physical NICs).

## Enhancement plan

From a review of proposed improvements on 2026-11-07. Phase 1 (small file-read checks) and
phase 2 (the upgrade-transaction audit) are done, and so is phase 3; the rest as we go.

- [ ] Check on real hosts: `storage-health` on RAID, LUKS, ZFS and Btrfs. `upgrade-log` was
      checked on real upgrades, Debian 12 to 13 and Ubuntu 22.04 to 24.04, in containers.

- [x] Phase 3: `snapshot` runs every check and records what it finds, and reports label each
      finding new, worse or pre-existing. Severity and exit codes don't change.
- [ ] Before hosts upload reports with these labels, release a portal built on the same
      pydebuprep version: older portals refuse `since_snapshot`.
- [ ] Phase 4: a listening-socket inventory; PAM and NSS from their files; `visudo -c` and
      LVM once the read-only audit passes them.
- [ ] Phase 5: functional probes. Agreed: a root process may contact external hosts when
      the local config asks for it; opt-in, and never from a config fetched from a URL.
- [ ] Phase 6: a release-transition knowledge base, shipped inside the package.
- Parked: SMART and NVMe (raw device access, optional tools, no hardware in CI); Podman,
  Snap and Flatpak through their clients; gateway reachability.

## Decisions to revisit

- The documentation site moved from Material for MkDocs (end of life 2027-05-05) to
  Zensical on 2026-11-01, while Zensical is still at 0.0.x. Zensical runs no MkDocs
  hooks, so `tools/docs_build.py` expands the generated sections first; if Zensical
  gains its own extension mechanism, move the expansion there.

- Container images in workflows track tags (`debian:bookworm`, `ubuntu:24.04`, ...)
  rather than digests, so builds get current security updates; Dependabot cannot
  update digests inside workflow files. CI's weekly run audits against them.
- Since 2026-11-03, to keep CI short: pull requests audit Ubuntu 22.04 and 26.04 and
  Debian 13 (and only the Ubuntu 24.04 runner VM) and skip the package's own test run;
  CI no longer runs on merges to `main`. A release, the weekly run and a manual run
  audit everything, so a problem on the other releases can first show up there. Revisit
  if that happens often.
  The portal's CI matches: no run on merges, weekly instead, and its Release now runs
  the lint and test jobs before building the image.
- `--format jira` and `--format confluence` are other names for the `-legacy` formats,
  for on-prem products that end in 2029. Don't switch them to the Cloud formats silently:
  deprecate them nearer the time.
- The Release workflow builds the `.deb` once on Debian 12 and installs that same
  file everywhere. Revisit if a dependency ever needs a per-release build.
