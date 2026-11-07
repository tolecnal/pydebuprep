"""Everything that listens on this host, compared with the snapshot: services that stopped
listening, and ones that can now be reached from other hosts. Read from /proc; only root can
see which process holds which socket."""

from __future__ import annotations

import fnmatch
import ipaddress
from typing import Any

from pydebuprep.checks._listeners import PROC_NET, _address, ephemeral_ports
from pydebuprep.checks.base import Check, Context, Option, count
from pydebuprep.model import Finding, Severity, truncate_evidence
from pydebuprep.system import System

ACCEPTING = "00010000"  # __SO_ACCEPTCON in /proc/net/unix: a socket that listens
UNIX_PREFIX = "unix:"


def _network_listeners(system: System) -> dict[str, str]:
    """Socket inode -> "tcp/ADDRESS:PORT". Random local ports are left out: they change at
    every restart. So is anything on UDP in that range, wherever it's bound."""
    ephemeral = ephemeral_ports(system)
    found = {}
    for name, (proto, listen) in PROC_NET.items():
        for line in (system.read_text(f"/proc/net/{name}") or "").splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[3] != listen:
                continue
            hex_address, _, hex_port = fields[1].partition(":")
            address, port = _address(hex_address), int(hex_port, 16)
            if port in ephemeral and (proto == "udp" or _is_local(address)):
                continue
            shown = f"[{address}]" if ":" in address else address
            found[fields[9]] = f"{proto}/{shown}:{port}"
    return found


def _unix_listeners(system: System) -> dict[str, str]:
    """Socket inode -> "unix:PATH", for sockets with a path that accept connections."""
    found = {}
    for line in (system.read_text("/proc/net/unix") or "").splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 8 and fields[3] == ACCEPTING and fields[7].startswith("/"):
            found[fields[6]] = f"{UNIX_PREFIX}{fields[7]}"
    return found


def _socket_owners(system: System) -> dict[str, str]:
    """Socket inode -> the name of a process holding it. Not its PID, which changes."""
    owners = {}
    for fd in system.glob("/proc/[0-9]*/fd/*"):
        target = system.readlink(fd) or ""
        if target.startswith("socket:["):
            pid = fd.split("/")[2]
            owners[target[8:-1]] = (system.read_text(f"/proc/{pid}/comm") or "").strip()
    return owners


def _is_local(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    mapped = getattr(ip, "ipv4_mapped", None)
    return bool((mapped or ip).is_loopback)


def _split(key: str) -> tuple[str, str]:
    """ "tcp/[::1]:80" -> ("tcp/80", "::1")."""
    proto, _, rest = key.partition("/")
    address, _, port = rest.rpartition(":")
    return f"{proto}/{port}", address.strip("[]")


def _shown(key: str, owner: str) -> str:
    return f"{key} ({owner})" if owner else key


def _by_port(listeners: dict[str, str]) -> dict[str, list[str]]:
    ports: dict[str, list[str]] = {}
    for key in listeners:
        if not key.startswith(UNIX_PREFIX):
            port, address = _split(key)
            ports.setdefault(port, []).append(address)
    return ports


class ListenersCheck(Check):
    id = "listeners"
    title = "What listens on this host"
    category = "network"
    requires_root = True
    options = (
        Option(
            "ignore_listeners",
            ["unix:/run/user/*", "unix:/run/systemd/*", "unix:/tmp/*", "unix:/var/tmp/*"],
            "Listeners to leave out, such as tcp/*:8080 or unix:/run/app* (shell-style patterns)",
        ),
    )

    def run(self, ctx: Context) -> list[Finding]:
        return []  # what listens is only a finding once it's different

    def _kept(self, listeners: dict[str, str]) -> dict[str, str]:
        return {
            key: owner
            for key, owner in listeners.items()
            if not any(fnmatch.fnmatchcase(key, p) for p in self.opt("ignore_listeners"))
        }

    def collect_baseline(self, ctx: Context) -> Any:
        owners = _socket_owners(ctx.system)
        sockets = {**_network_listeners(ctx.system), **_unix_listeners(ctx.system)}
        return self._kept({key: owners.get(inode, "") for inode, key in sockets.items()})

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        old, new = self._kept(before), self.collect_baseline(ctx)
        ports_old, ports_new = _by_port(old), _by_port(new)
        findings = [
            *_gone(old, new, ports_new),
            *_moved(old, new, ports_old, ports_new),
            *_added(new, old, ports_old),
        ]
        changed = sorted(
            f"{key}: {old[key]} to {owner}"
            for key, owner in new.items()
            if owner and old.get(key) and old[key] != owner
        )
        if changed:
            findings.append(
                Finding(
                    Severity.INFO,
                    f"{count(len(changed), 'listener has', 'listeners have')} "
                    "another process behind it",
                    detail="Often a renamed program; check it's the one you expect.",
                    evidence=truncate_evidence(changed),
                )
            )
        return findings


def _gone(
    old: dict[str, str], new: dict[str, str], ports_new: dict[str, list[str]]
) -> list[Finding]:
    network, unix = [], []
    for key, owner in sorted(old.items()):
        if key.startswith(UNIX_PREFIX):
            if key not in new:
                unix.append(_shown(key, owner))
        elif _split(key)[0] not in ports_new:
            network.append(_shown(key, owner))
    findings = []
    if network:
        findings.append(
            Finding(
                Severity.WARNING,
                f"{count(len(network), 'listener')} from before the upgrade "
                f"{'is' if len(network) == 1 else 'are'} gone",
                detail="The service may have stopped, or moved to another port.",
                evidence=truncate_evidence(network),
                remediation=["See what listens now: sudo ss -tulpn"],
            )
        )
    if unix:
        findings.append(
            Finding(
                Severity.INFO,
                f"{count(len(unix), 'Unix socket')} from before the upgrade "
                f"{'is' if len(unix) == 1 else 'are'} gone",
                evidence=truncate_evidence(unix),
                remediation=["See what listens now: sudo ss -xlp"],
            )
        )
    return findings


def _moved(
    old: dict[str, str],
    new: dict[str, str],
    ports_old: dict[str, list[str]],
    ports_new: dict[str, list[str]],
) -> list[Finding]:
    wider: list[str] = []
    other: list[str] = []
    owners = {_split(key)[0]: owner for key, owner in new.items() if owner}
    for port, addresses in sorted(ports_old.items()):
        now = ports_new.get(port)
        if now is None or set(now) == set(addresses):
            continue
        line = (
            f"{_shown(port, owners.get(port, ''))}: "
            f"{', '.join(sorted(addresses))} to {', '.join(sorted(now))}"
        )
        reaches_further = all(map(_is_local, addresses)) and not all(map(_is_local, now))
        (wider if reaches_further else other).append(line)
    findings = []
    if wider:
        findings.append(
            Finding(
                Severity.WARNING,
                f"{count(len(wider), 'port is', 'ports are')} now reachable from other hosts",
                detail="It listened on this host only before the upgrade. A new default can "
                "expose a service that was never meant to be reached.",
                evidence=truncate_evidence(wider),
                remediation=["Check the service's bind address, and the firewall"],
            )
        )
    if other:
        findings.append(
            Finding(
                Severity.INFO,
                f"{count(len(other), 'port listens', 'ports listen')} on other addresses",
                evidence=truncate_evidence(other),
            )
        )
    return findings


def _added(
    new: dict[str, str], old: dict[str, str], ports_old: dict[str, list[str]]
) -> list[Finding]:
    outside: list[str] = []
    local: list[str] = []
    for key, owner in sorted(new.items()):
        if key.startswith(UNIX_PREFIX):
            if key not in old:
                local.append(_shown(key, owner))
            continue
        port, address = _split(key)
        if port not in ports_old:
            (local if _is_local(address) else outside).append(_shown(key, owner))
    findings = []
    if outside:
        findings.append(
            Finding(
                Severity.WARNING,
                f"{count(len(outside), 'new listener')} can be reached from other hosts",
                detail="Not necessarily a problem, but check you expect it.",
                evidence=truncate_evidence(outside),
                remediation=["See what it is: sudo ss -tulpn"],
            )
        )
    if local:
        findings.append(
            Finding(
                Severity.INFO,
                f"{count(len(local), 'new local listener')}",
                evidence=truncate_evidence(local),
            )
        )
    return findings
