"""Which TCP/UDP ports a systemd unit's processes listen on, read from /proc (root only)."""

from __future__ import annotations

from pydebuprep.system import System

# /proc/net/<file>: (protocol, socket state that means "listening")
PROC_NET = {
    "tcp": ("tcp", "0A"),  # TCP_LISTEN
    "tcp6": ("tcp", "0A"),
    "udp": ("udp", "07"),  # TCP_CLOSE: an unconnected, bound UDP socket
    "udp6": ("udp", "07"),
}


def ephemeral_ports(system: System) -> range:
    """The kernel's range for random local ports (ip_local_port_range); empty if unknown."""
    fields = (system.read_text("/proc/sys/net/ipv4/ip_local_port_range") or "").split()
    if len(fields) == 2 and all(f.isdigit() for f in fields):
        return range(int(fields[0]), int(fields[1]) + 1)
    return range(0)


def listening_sockets(system: System) -> dict[str, str]:
    """Socket inode -> "tcp/PORT" or "udp/PORT" for every listening socket.

    UDP sockets on random ports (rpc.statd, resolvers) are left out: they get a new
    port on every restart, so they aren't listeners anyone relies on.
    """
    ephemeral = ephemeral_ports(system)
    sockets: dict[str, str] = {}
    for name, (proto, listen) in PROC_NET.items():
        for line in (system.read_text(f"/proc/net/{name}") or "").splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[3] != listen:
                continue
            port = int(fields[1].rsplit(":", 1)[1], 16)
            if proto == "udp" and port in ephemeral:
                continue
            sockets[fields[9]] = f"{proto}/{port}"
    return sockets


def unit_listeners(system: System, control_group: str, sockets: dict[str, str]) -> list[str]:
    """Listening ports held by the processes in a unit's cgroup (v2, or v1's systemd tree)."""
    if not control_group:
        return []
    procs = system.read_text(f"/sys/fs/cgroup{control_group}/cgroup.procs")
    if procs is None:
        procs = system.read_text(f"/sys/fs/cgroup/systemd{control_group}/cgroup.procs") or ""
    found = set()
    for pid in procs.split():
        if not pid.isdigit():
            continue
        for fd in system.glob(f"/proc/{pid}/fd/*"):
            target = system.readlink(fd) or ""
            if target.startswith("socket:[") and target[8:-1] in sockets:
                found.add(sockets[target[8:-1]])
    return sorted(found)
