# Backlog

What is still open, as of 2026-10-29. Remove items as they are done.

## GitHub repository settings

Done on 2026-10-29: Dependabot alerts and security updates, secret scanning with push
protection, private vulnerability reporting, CodeQL default setup off (the workflow is
an advanced setup), and these rulesets next to the owner's `protet-main-branch`
(no deletion or force-push of `main`):

- `main: pull requests and checks`: changes go through a pull request; tests on all
  Python versions and the Security/CodeQL jobs must pass.
- `release tags: admins only, immutable`: only admins create `v*` tags, and they can't
  be moved or deleted.

- [ ] Optional: secret scanning for non-provider patterns and validity checks.

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

`v0.5.0` (portal support in the CLI) is being released on 2026-10-31; what it
contains is in `debian/changelog`.

- [ ] Before the next release: bump `debian/changelog` (`dch -v X.Y.Z`) and
      `__version__` together. The Release workflow refuses a tag that doesn't
      match both.
- [ ] Decide whether to publish an APT repository as well, for example signed and
      served from GitHub Pages, so hosts can `apt install pydebuprep` and get
      updates. Today the package is published only as a release asset.

## Checks not implemented yet

Done on 2026-10-29: network, firewall, time-sync, AppArmor, unattended-upgrades, cron,
ssh-server, the boot critical chain, the `/` and `/var` free-space floor, and the
application checks postgresql, mariadb, postfix, bind, docker and python-venvs. Each
passes `scripts/readonly-audit.sh` with the service installed.

- [ ] Dropped from the wish list, with reasons:
      - WireGuard/OpenVPN tunnels: covered by the network check's interface comparison;
      - nginx and Apache config tests: `nginx -t` writes its PID file, cache directories
        and logs; `apache2ctl -t` creates run directories. A broken config still shows
        up in systemd-failed once the service fails to start;
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

- [ ] Still only on real hosts: `docker` on Debian (no runner VM), and the checks'
      behaviour on real hardware (RAID, multiple disks, physical NICs).

## Decisions to revisit

- The documentation site uses Material for MkDocs, which reaches end of life on
  2027-05-05 (security fixes until then). Its successor, Zensical, reads the same
  `mkdocs.yml`; evaluate moving before then.

- Container images in workflows track tags (`debian:bookworm`, `ubuntu:24.04`, ...)
  rather than digests, so builds get current security updates; Dependabot cannot
  update digests inside workflow files. CI's weekly run audits against them.
- The Release workflow builds the `.deb` once on Debian 12 and installs that same
  file everywhere. Revisit if a dependency ever needs a per-release build.
