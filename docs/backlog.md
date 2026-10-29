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
      - `SECURITY.md`.
- [ ] Decide whether to publish an APT repository as well, for example signed and
      served from GitHub Pages, so hosts can `apt install pydebuprep` and get
      updates. Today the package is published only as a release asset.

## Checks not implemented yet

Version 1 covers packages, boot, services, logs and storage. These items from the
original wish list are still open. Each new check must pass `scripts/readonly-audit.sh`.
Some of the obvious commands write state: `nginx -t` can create log files, and
`certbot renew --dry-run` and `unattended-upgrade --dry-run` write state files.

- [ ] Networking: addresses, routes, DNS (`ip`, `resolvectl`). Watch for a switch
      between ifupdown, netplan, NetworkManager and systemd-networkd.
- [ ] Firewall rules loaded (`nft list ruleset`, `iptables -S`, `ufw status`).
- [ ] Time synchronisation (`timedatectl`).
- [ ] AppArmor status and recent denials (`aa-status`, journal).
- [ ] unattended-upgrades enabled, with the right origins for the new release.
- [ ] cron jobs and timers review.
- [ ] Services:
      - PostgreSQL old clusters (`pg_lsclusters`); MariaDB/MySQL upgrade state;
      - nginx/apache config validity, done without writing;
      - postfix and BIND config checks;
      - WireGuard/OpenVPN;
      - Docker/Podman/libvirt/LXD;
      - Python virtualenvs built against the old system Python;
      - SSH algorithms clients still use.
- [ ] Smaller ideas:
      - `systemd-analyze critical-chain`;
      - DKMS/out-of-tree modules loaded (`lsmod`);
      - packages with `~` versions;
      - `apt policy` for key packages.
- [ ] `disk-space`: the design asked to emphasise `/` and `/var`. Today all local
      filesystems are treated the same.

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
