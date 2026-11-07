# listeners — What listens on this host

A service can be enabled and running and no longer listen where clients expect it. A new
default can also expose something that only listened on this host before.

<!-- facts: listeners -->

## What it checks

With a snapshot, it compares every listening TCP and UDP socket, and every Unix socket with
a path, with their address, port or path and the name of the process behind them. Without
a snapshot it reports nothing: what listens is only a finding once it's different.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* listeners from before the upgrade are gone | `sudo ss -tulpn`. The service may have stopped, or moved to another port. |
| warning | *N* ports are now reachable from other hosts | It listened on this host only before. Check the service's bind address and the firewall. |
| warning | *N* new listeners can be reached from other hosts | Check you expect it: `sudo ss -tulpn`. |
| info | *N* ports listen on other addresses | Check it's what you want. |
| info | *N* new local listeners | For the record. |
| info | *N* Unix sockets from before the upgrade are gone | `sudo ss -xlp`. |
| info | *N* listeners have another process behind them | Often a renamed program, such as `mysqld` to `mariadbd`. |

## Compared with a snapshot

The snapshot records each listener and its process's name, not its PID, which changes.

## Commands it runs

None; it reads `/proc/net/*` and each process's open files in `/proc`.

## Limitations

- Random local ports are left out, as they change at every restart: UDP ones anywhere, TCP
  ones on loopback. So are some Unix sockets (`ignore_listeners`).
- A new listener isn't necessarily a problem, and a firewall may block one that looks
  reachable: "reachable" means it isn't bound to loopback only.
- A service that moved from a port to a Unix socket shows as one gone and one new.
- Something listening only part of the time, or started on demand, can look like a change.
- In a container it sees that container's sockets.

<!-- options: listeners -->
