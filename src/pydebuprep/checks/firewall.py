from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from pydebuprep.checks._systemd import ENABLED_SERVICES, run_systemctl, unit_rows
from pydebuprep.checks.base import Check, CheckSkipped, CommandFailed, Context, run_checked
from pydebuprep.model import Finding, Severity

NFT_RULESET = ("nft", "-j", "list", "ruleset")
IPTABLES_LEGACY = ("iptables-legacy-save",)
UFW_CONF = "/etc/ufw/ufw.conf"
NOT_PERMITTED = "Operation not permitted"


@dataclass
class Ruleset:
    rules: int = 0
    ufw_chains: bool = False
    frontends: set[str] = field(default_factory=set)


def _ufw_enabled(ctx: Context) -> bool:
    for line in (ctx.system.read_text(UFW_CONF) or "").splitlines():
        key, _, value = line.strip().partition("=")
        if key == "ENABLED":
            return value.strip().strip("'\"").lower() == "yes"
    return False


def _enabled_services(ctx: Context) -> set[str]:
    try:
        return {row[0] for row in unit_rows(run_systemctl(ctx, ENABLED_SERVICES).stdout)}
    except CheckSkipped:
        return set()


def _query(ctx: Context, argv: tuple[str, ...]) -> str:
    res = run_checked(ctx, argv, ok_codes=None)
    if NOT_PERMITTED in res.stderr:
        raise CheckSkipped("firewall rules can't be read here (no CAP_NET_ADMIN, e.g. a container)")
    if not res.ok:
        first = res.stderr.strip().splitlines()[:1]
        raise CommandFailed(first[0] if first else f"{argv[0]} exited {res.returncode}")
    return res.stdout


def read_ruleset(ctx: Context) -> Ruleset:
    rs = Ruleset()
    # Only ask a backend whose kernel module is already loaded: listing rules can
    # otherwise make the kernel load the module, which would change the system.
    modules = ctx.system.loaded_modules()
    if "nf_tables" in modules and ctx.system.which("nft"):
        items = json.loads(_query(ctx, NFT_RULESET) or "{}").get("nftables", [])
        rs.rules += sum(1 for item in items if "rule" in item)
        rs.ufw_chains |= any(
            str(item.get("chain", {}).get("name", "")).startswith("ufw-") for item in items
        )
    if "ip_tables" in modules and ctx.system.which("iptables-legacy-save"):
        lines = _query(ctx, IPTABLES_LEGACY).splitlines()
        legacy = sum(1 for line in lines if line.startswith("-A "))
        if legacy:
            rs.frontends.add("iptables-legacy")
        rs.rules += legacy
        rs.ufw_chains |= any(line.startswith(":ufw-") for line in lines)
    if _ufw_enabled(ctx):
        rs.frontends.add("ufw")
    if "nftables.service" in _enabled_services(ctx):
        rs.frontends.add("nftables")
    return rs


class FirewallCheck(Check):
    id = "firewall"
    title = "Firewall rules"
    category = "network"
    requires_root = True

    def run(self, ctx: Context) -> list[Finding]:
        rs = read_ruleset(ctx)
        findings = []
        if "ufw" in rs.frontends and not rs.ufw_chains:
            findings.append(
                Finding(
                    Severity.WARNING,
                    "ufw is enabled but its rules aren't loaded",
                    detail=f"{UFW_CONF} says ENABLED=yes, but no ufw chains are in the "
                    "running ruleset, so the host is less protected than configured.",
                    remediation=["sudo ufw status verbose", "sudo systemctl restart ufw"],
                )
            )
        if "nftables" in rs.frontends and rs.rules == 0:
            findings.append(
                Finding(
                    Severity.WARNING,
                    "nftables.service is enabled but no rules are loaded",
                    remediation=[
                        "sudo nft -c -f /etc/nftables.conf   # check the rules file",
                        "sudo systemctl restart nftables",
                    ],
                )
            )
        if rs.rules == 0 and not rs.frontends:
            findings.append(
                Finding(
                    Severity.INFO,
                    "No firewall rules are loaded",
                    detail="Fine if this host relies on a network firewall; otherwise "
                    "consider ufw or nftables.",
                    remediation=["sudo apt install ufw   # or nftables"],
                )
            )
        return findings

    def collect_baseline(self, ctx: Context) -> Any:
        rs = read_ruleset(ctx)
        return {"rules": rs.rules, "frontends": sorted(rs.frontends)}

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        rs = read_ruleset(ctx)
        findings = []
        if before.get("rules") and rs.rules == 0:
            findings.append(
                Finding(
                    Severity.CRITICAL,
                    "Firewall rules were loaded before the upgrade but none are now",
                    detail=f"The baseline had {before['rules']} rules. The firewall service "
                    "may have failed to start, or its configuration was not migrated.",
                    remediation=[
                        "systemctl status ufw nftables netfilter-persistent",
                        "Reload your rules before exposing services",
                    ],
                )
            )
        old, new = before.get("frontends") or [], sorted(rs.frontends)
        if old and new and old != new:
            findings.append(
                Finding(
                    Severity.INFO,
                    f"Firewall frontend changed from {', '.join(old)} to {', '.join(new)}",
                    remediation=["Check the new frontend has the rules you expect"],
                )
            )
        return findings
