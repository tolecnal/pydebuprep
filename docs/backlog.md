# Backlog

What is still open, as of 2026-10-29. Remove items as they are done.

## Housekeeping

- [ ] Close Dependabot PR #1 (raises the `setuptools>=59` build floor to 84.2.1).
      #2 stops Dependabot from proposing it again; the closing comment explains why.

## GitHub repository settings

These need a repository admin. A workflow cannot change them.

- [ ] **Dependabot alerts** and **Dependabot security updates** (Settings → Code security).
      Version updates already run from `.github/dependabot.yml`.
- [ ] **Secret scanning** and **push protection**. These are free on public repositories.
- [ ] **Private vulnerability reporting**, so people can report issues privately; maybe
      with a short `SECURITY.md` that points to it.
- [ ] Keep CodeQL **default setup off**. `.github/workflows/codeql.yml` is an advanced
      setup, and GitHub refuses advanced-setup uploads while default setup is on.
- [ ] **Branch ruleset for `main`**: require pull requests and require these checks:
      CI, Security and CodeQL. Optionally require signed commits.
- [ ] **Tag ruleset for `v*`**, so only maintainers can create release tags.

## Release

- [ ] Tag the first release, `v0.2.0`, and check the Release workflow end to end:
      GitHub Release, `SHA256SUMS`, and `gh attestation verify`.
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

- [ ] The read-only audit in CI runs in containers without systemd, so `systemctl`,
      `journalctl` and `systemd-analyze` are audited only by manual runs on a real
      host. Consider a VM-based job, or a container booted with systemd as PID 1.
- [ ] `efibootmgr -v` has never been exercised by the audit (no EFI firmware in CI
      containers). It is read-only by design and by the exact-argv allowlist.
- [ ] Branch coverage is enforced at 95% (`fail_under` in `pyproject.toml`). Raise it
      as coverage improves; `system.py` (82%) is the main gap.

## Decisions to revisit

- Container images in workflows track tags (`debian:bookworm`, `ubuntu:24.04`, ...)
  rather than digests, so builds get current security updates; Dependabot cannot
  update digests inside workflow files.
- The Release workflow builds the `.deb` once on Debian 12 and installs that same
  file everywhere. Revisit if a dependency ever needs a per-release build.
