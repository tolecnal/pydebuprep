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


def listening_sockets(system: System) -> dict[str, str]:
    """Socket inode -> "tcp/PORT" or "udp/PORT" for every listening socket."""
    sockets: dict[str, str] = {}
    for name, (proto, listen) in PROC_NET.items():
        for line in (system.read_text(f"/proc/net/{name}") or "").splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[3] != listen:
                continue
            port = int(fields[1].rsplit(":", 1)[1], 16)
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
