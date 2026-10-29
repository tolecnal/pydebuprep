# network — Network interfaces, routes and DNS

Interface names can change between releases, and network configuration may move to
a different tool (ifupdown, netplan, NetworkManager, systemd-networkd). A host that
loses its address or route after the reboot may be unreachable — so check this one
from the console if you can't log in.

<!-- facts: network -->

## What it checks

- That there's a default route and at least one DNS server.
- With systemd-resolved, the upstream DNS servers it uses (not just its local stub).
- With a snapshot: interfaces that were up and aren't, addresses that are gone, a
  changed default route or DNS servers, and a change of network manager.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | No default route | `ip route`; check your network manager's configuration. Expected only on isolated hosts. |
| warning | No DNS servers configured | `resolvectl status` (systemd-resolved) or `/etc/resolv.conf`. |
| warning | Interface *name* was up before the upgrade and is down / gone | `ip -br link`, `ip -br addr` — the name may have changed. |
| warning | *name* lost addresses it had before the upgrade | `ip addr show NAME`. |
| warning | The default route changed | `ip route`. |
| warning | Network configuration moved from *old* to *new* | Make sure the old configuration was migrated: `networkctl status`, `nmcli device`. |
| info | DNS servers changed | `resolvectl status`. |

## Compared with a snapshot

The snapshot records interfaces, their state and addresses, default routes (IPv4
and IPv6), DNS servers and the active network managers (`NetworkManager`,
`systemd-networkd`, `networking` for ifupdown).

## Commands it runs

```sh
ip -j addr show
ip -j route show default
ip -j -6 route show default
resolvectl dns
systemctl list-units --type=service --state=active --no-legend --plain --no-pager
```

`resolvectl dns` only when `/etc/resolv.conf` points at the systemd-resolved stub.

## Limitations

- Virtual interfaces created by containers and VMs come and go; they're left out of
  the comparison by `ignore_interfaces`. Add your own (VPN tunnels, …) there.
- It doesn't test connectivity: no pings, no DNS lookups.

<!-- options: network -->
