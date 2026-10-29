from __future__ import annotations

import fnmatch
import json
from typing import Any

from pydebuprep.checks._systemd import active_services
from pydebuprep.checks.base import Check, Context, Option, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence

IP_ADDR = ("ip", "-j", "addr", "show")
IP_ROUTE4 = ("ip", "-j", "route", "show", "default")
IP_ROUTE6 = ("ip", "-j", "-6", "route", "show", "default")
RESOLVECTL_DNS = ("resolvectl", "dns")
RESOLVED_STUBS = ("127.0.0.53", "127.0.0.54")
MANAGERS = {
    "NetworkManager.service": "NetworkManager",
    "systemd-networkd.service": "systemd-networkd",
    "networking.service": "ifupdown",
}
VIRTUAL_INTERFACES = ["lo", "veth*", "docker*", "br-*", "virbr*", "vnet*", "tap*", "cni*",
                      "flannel*", "cali*"]  # fmt: skip


def _json(text: str) -> list[dict[str, Any]]:
    data = json.loads(text or "[]")
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


class NetworkCheck(Check):
    id = "network"
    title = "Network interfaces, routes and DNS"
    category = "network"
    requires_commands = ("ip",)
    options = (
        Option(
            "ignore_interfaces",
            VIRTUAL_INTERFACES,
            "Interfaces left out of the baseline comparison (shell-style patterns); "
            "containers and VMs create and remove these all the time",
        ),
    )

    def _interfaces(self, ctx: Context) -> dict[str, dict[str, Any]]:
        result = {}
        for link in _json(run_checked(ctx, IP_ADDR).stdout):
            name = str(link.get("ifname", ""))
            if not name or any(fnmatch.fnmatchcase(name, p) for p in self.opt("ignore_interfaces")):
                continue
            flags = link.get("flags") or []
            addrs = [
                f"{a['local']}/{a['prefixlen']}"
                for a in link.get("addr_info") or []
                if a.get("scope") == "global" and "local" in a
            ]
            result[name] = {
                "up": "UP" in flags and link.get("operstate") != "DOWN",
                "addresses": addrs,
            }
        return dict(sorted(result.items()))

    def _routes(self, ctx: Context) -> list[str]:
        routes = []
        for argv in (IP_ROUTE4, IP_ROUTE6):
            for r in _json(run_checked(ctx, argv).stdout):
                via = f"via {r['gateway']} " if r.get("gateway") else ""
                routes.append(f"{via}dev {r.get('dev', '?')}")
        return routes

    def _dns(self, ctx: Context) -> list[str]:
        servers = [
            line.split()[1]
            for line in (ctx.system.read_text("/etc/resolv.conf") or "").splitlines()
            if line.startswith("nameserver") and len(line.split()) > 1
        ]
        if not any(s in RESOLVED_STUBS for s in servers) or not ctx.system.which("resolvectl"):
            return servers
        # The local systemd-resolved stub: ask it which upstream servers it uses.
        res = run_checked(ctx, RESOLVECTL_DNS, ok_codes=None)
        if not res.ok:
            return servers
        upstream: list[str] = []
        for line in res.stdout.splitlines():
            if line.startswith("Global:"):
                rest = line[len("Global:") :]
            elif line.startswith("Link ") and "):" in line:
                rest = line.split("):", 1)[1]
            else:
                continue
            upstream += [s for s in rest.split() if s not in upstream]
        return upstream

    def _managers(self, ctx: Context) -> list[str]:
        active = active_services(ctx) or set()
        managers = [name for unit, name in MANAGERS.items() if unit in active]
        if ctx.system.glob("/etc/netplan/*.yaml"):
            managers.append("netplan")
        return sorted(managers)

    def run(self, ctx: Context) -> list[Finding]:
        findings = []
        if not self._routes(ctx):
            findings.append(
                Finding(
                    Severity.WARNING,
                    "No default route",
                    detail="Without a default route the host can only reach directly "
                    "connected networks. Expected only on isolated hosts.",
                    remediation=["ip route", "Check the configuration of your network manager"],
                )
            )
        if not self._dns(ctx):
            findings.append(
                Finding(
                    Severity.WARNING,
                    "No DNS servers configured",
                    remediation=[
                        "resolvectl status   # with systemd-resolved",
                        "cat /etc/resolv.conf",
                    ],
                )
            )
        return findings

    def collect_baseline(self, ctx: Context) -> Any:
        return {
            "interfaces": self._interfaces(ctx),
            "default_routes": self._routes(ctx),
            "dns": self._dns(ctx),
            "managers": self._managers(ctx),
        }

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now = self.collect_baseline(ctx)
        old_ifaces, new_ifaces = before.get("interfaces") or {}, now["interfaces"]
        findings: list[Finding] = []
        lost: list[Finding] = []
        for name, old in sorted(old_ifaces.items()):
            new = new_ifaces.get(name)
            if old.get("up") and (new is None or not new["up"]):
                state = "is gone now" if new is None else "is down now"
                findings.append(
                    Finding(
                        Severity.WARNING,
                        f"Interface {name} was up before the upgrade and {state}",
                        detail="Interface names can change between releases, and network "
                        "configuration may have moved to a different tool.",
                        remediation=["ip -br link", "ip -br addr"],
                    )
                )
            if new is None:
                continue  # already reported as gone
            missing = [a for a in old.get("addresses") or [] if a not in new["addresses"]]
            if missing:
                lost.append(
                    Finding(
                        Severity.WARNING,
                        f"{name} lost addresses it had before the upgrade",
                        evidence=truncate_evidence(missing),
                        remediation=[f"ip addr show {name}"],
                    )
                )
        findings += lost
        if before.get("default_routes") and before["default_routes"] != now["default_routes"]:
            findings.append(
                Finding(
                    Severity.WARNING,
                    "The default route changed",
                    evidence=[
                        f"before: {', '.join(before['default_routes'])}",
                        f"now: {', '.join(now['default_routes']) or 'none'}",
                    ],
                    remediation=["ip route"],
                )
            )
        old_mgr = before.get("managers") or []
        if old_mgr and old_mgr != now["managers"]:
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"Network configuration moved from {', '.join(old_mgr)} to "
                    f"{', '.join(now['managers']) or 'nothing'}",
                    detail="Releases sometimes switch between ifupdown, netplan, NetworkManager "
                    "and systemd-networkd. Make sure the old configuration was migrated.",
                    remediation=["networkctl status   # systemd-networkd", "nmcli device"],
                )
            )
        if before.get("dns") and before["dns"] != now["dns"]:
            findings.append(
                Finding(
                    Severity.INFO,
                    "DNS servers changed",
                    evidence=[
                        f"before: {', '.join(before['dns'])}",
                        f"now: {', '.join(now['dns']) or 'none'}",
                    ],
                    remediation=["resolvectl status"],
                )
            )
        return findings
