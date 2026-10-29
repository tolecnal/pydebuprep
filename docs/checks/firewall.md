# firewall — Firewall rules

A firewall that's configured but didn't load its rules after the upgrade leaves the
host more exposed than you think — and nothing else complains about it.

<!-- facts: firewall -->

## What it checks

- The rules loaded in the kernel: nftables (`nft`) and, if loaded, legacy iptables.
- Whether **ufw** is enabled in `/etc/ufw/ufw.conf` but its chains aren't in the
  running ruleset.
- Whether **nftables.service** is enabled but no rules are loaded.
- Whether any rules are loaded at all.

It only lists rules for kernel modules that are already loaded (`nf_tables`,
`ip_tables`): listing rules can otherwise make the kernel load a module, which
would be a change.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | Firewall rules were loaded before the upgrade but none are now | `systemctl status ufw nftables netfilter-persistent`; reload your rules before exposing services. |
| warning | ufw is enabled but its rules aren't loaded | `sudo ufw status verbose`; `sudo systemctl restart ufw`. |
| warning | nftables.service is enabled but no rules are loaded | Check the file with `sudo nft -c -f /etc/nftables.conf`, then `sudo systemctl restart nftables`. |
| info | No firewall rules are loaded | Fine if the host relies on a network firewall; otherwise consider ufw or nftables. |
| info | Firewall frontend changed from *old* to *new* | Check the new frontend has the rules you expect. |

## Compared with a snapshot

The snapshot records the number of loaded rules and the frontends in use (ufw,
nftables, iptables-legacy).

## Commands it runs

```sh
nft -j list ruleset
iptables-legacy-save
systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager
```

`ufw status` isn't used: it writes a lock file. The check reads ufw's configuration
and the loaded rules instead.

## Limitations

- It counts rules; it doesn't judge them. A loaded but permissive ruleset passes.
- Needs root (`CAP_NET_ADMIN`) to read the rules; in containers without it, it's
  skipped.
- firewalld isn't recognised as a frontend; its rules are still counted through
  nftables.

<!-- options: firewall -->
