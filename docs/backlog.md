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

- [ ] Before the next release: bump `debian/changelog` (`dch -v X.Y.Z`) and
      `__version__` together. The Release workflow refuses a tag that doesn't
      match both. Changes waiting for the next changelog entry:
      - without a baseline, the report says so once instead of in every check;
      - fstab: swap files no longer warned about when the fstab target is `swap`
        (Debian); swap sources are read from `/etc/fstab`;
      - config-conflicts: `ignore_paths` option for files a tool like Ansible manages;
      - shared `logs: ignore:` regex list for journal-errors and dmesg-errors;
        dmesg-errors reports how many messages were ignored;
      - runs without PyYAML when YAML isn't needed, with an install hint otherwise;
      - `SECURITY.md`;
      - snapshots are private: directory 0700 and files 0600 (CodeQL
        py/overly-permissive-file); upgrading the package tightens existing directories;
      - new checks: network, firewall, time-sync, apparmor, unattended-upgrades, cron,
        ssh-server; boot critical chain; a free-space floor for `/` and `/var`;
      - application checks: postgresql, mariadb, postfix, bind, docker, python-venvs;
      - README badges; README, man page (new CHECKS section) and package description
        brought up to date, with tests that keep the check lists in sync;
      - 100% line and branch coverage, enforced.
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

- [ ] Packages are built and audited only by the Release workflow (a release tag, or a
      manual run), not on every push; run it manually on a branch that touches
      commands or packaging before tagging.
- [ ] The read-only audit runs in containers without systemd, so `systemctl`,
      `journalctl` and `systemd-analyze` are audited only by manual runs on a real
      host. Consider a VM-based job, or a container booted with systemd as PID 1.
- [ ] `efibootmgr -v` has never been exercised by the audit (no EFI firmware in CI
      containers). It is read-only by design and by the exact-argv allowlist.

## Decisions to revisit

- Container images in workflows track tags (`debian:bookworm`, `ubuntu:24.04`, ...)
  rather than digests, so builds get current security updates; Dependabot cannot
  update digests inside workflow files.
- The Release workflow builds the `.deb` once on Debian 12 and installs that same
  file everywhere. Revisit if a dependency ever needs a per-release build.
