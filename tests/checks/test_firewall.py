from __future__ import annotations

import json
from typing import Any

from pydebuprep.checks._systemd import ENABLED_SERVICES
from pydebuprep.checks.firewall import IPTABLES_LEGACY, NFT_RULESET, FirewallCheck
from pydebuprep.model import Severity, Status
from pydebuprep.runner import run_check
from pydebuprep.system import CommandResult

from .helpers import make_ctx, titles

MODULES = "nf_tables 1 2 - Live 0x0\nip_tables 1 0 - Live 0x0\nx_tables 1 0 - Live 0x0\n"


def nft(*chains: str, rules: int = 0) -> str:
    items: list[dict[str, Any]] = [
        {"metainfo": {"version": "1.1.3"}},
        {"table": {"family": "inet", "name": "filter"}},
    ]
    items += [{"chain": {"family": "inet", "table": "filter", "name": c}} for c in chains]
    items += [
        {"rule": {"family": "inet", "table": "filter", "chain": "input", "expr": []}}
        for _ in range(rules)
    ]
    return json.dumps({"nftables": items})


def fw_ctx(**kw: Any) -> Any:
    commands = {
        NFT_RULESET: kw.pop("nft", nft()),
        IPTABLES_LEGACY: kw.pop("legacy", ""),
        ENABLED_SERVICES: kw.pop("enabled", ""),
    }
    files = {"/proc/modules": kw.pop("modules", MODULES), **kw.pop("files", {})}
    return make_ctx(commands=commands, files=files, **kw)


UFW_ON = {"/etc/ufw/ufw.conf": "# comment\nENABLED=yes\nLOGLEVEL=low\n"}


def test_rules_loaded_ok() -> None:
    assert FirewallCheck().run(fw_ctx(nft=nft("input", rules=12))) == []


def test_no_firewall_at_all_is_info() -> None:
    (f,) = FirewallCheck().run(fw_ctx())
    assert (f.severity, f.title) == (Severity.INFO, "No firewall rules are loaded")


def test_ufw_enabled_but_not_loaded() -> None:
    fs = FirewallCheck().run(fw_ctx(files=UFW_ON))
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.WARNING, "ufw is enabled but its rules aren't loaded")
    ]


def test_ufw_rules_found_via_legacy_iptables() -> None:
    legacy = "*filter\n:INPUT DROP [0:0]\n:ufw-user-input - [0:0]\n-A INPUT -j ufw-before-input\n-A ufw-user-input -p tcp --dport 22 -j ACCEPT\nCOMMIT\n"
    assert FirewallCheck().run(fw_ctx(files=UFW_ON, legacy=legacy)) == []


def test_ufw_rules_found_via_nftables() -> None:
    assert FirewallCheck().run(fw_ctx(files=UFW_ON, nft=nft("ufw-user-input", rules=3))) == []


def test_nftables_service_enabled_but_empty() -> None:
    fs = FirewallCheck().run(fw_ctx(enabled="nftables.service enabled enabled\n"))
    assert titles(fs) == ["nftables.service is enabled but no rules are loaded"]


def test_modules_not_loaded_means_nothing_is_queried() -> None:
    ctx = fw_ctx(modules="ext4 1 0 - Live 0x0\n")
    (f,) = FirewallCheck().run(ctx)
    assert f.title == "No firewall rules are loaded"
    assert not any(c[0] in ("nft", "iptables-legacy-save") for c in ctx.system.calls)


def test_not_permitted_is_skipped() -> None:
    res = CommandResult(NFT_RULESET, 1, "", "Error: Operation not permitted (you must be root)\n")
    r = run_check(FirewallCheck(), fw_ctx(nft=res))
    assert r.status is Status.SKIPPED
    assert "can't be read" in (r.skipped_reason or "")


def test_other_nft_failure_is_an_error() -> None:
    res = CommandResult(NFT_RULESET, 1, "", "netlink: Error: something else\n")
    assert run_check(FirewallCheck(), fw_ctx(nft=res)).status is Status.ERROR


def test_firewall_baseline_and_rules_lost() -> None:
    ctx = fw_ctx(
        nft=nft("ufw-user-input", rules=5),
        files=UFW_ON,
        enabled="nftables.service enabled enabled\n",
    )
    assert FirewallCheck().collect_baseline(ctx) == {"rules": 5, "frontends": ["nftables", "ufw"]}
    (f,) = FirewallCheck().compare(fw_ctx(), {"rules": 5, "frontends": ["ufw"]})
    assert (f.severity, f.title) == (
        Severity.CRITICAL,
        "Firewall rules were loaded before the upgrade but none are now",
    )


def test_firewall_frontend_change_is_info() -> None:
    ctx = fw_ctx(nft=nft("input", rules=4), enabled="nftables.service enabled enabled\n")
    (f,) = FirewallCheck().compare(ctx, {"rules": 4, "frontends": ["iptables-legacy"]})
    assert (f.severity, f.title) == (
        Severity.INFO,
        "Firewall frontend changed from iptables-legacy to nftables",
    )
    assert FirewallCheck().compare(ctx, {"rules": 4, "frontends": ["nftables"]}) == []


def test_without_systemd_the_service_state_is_unknown() -> None:
    no_systemd = CommandResult(ENABLED_SERVICES, 1, "", "System has not been booted with systemd\n")
    ctx = fw_ctx(nft=nft("input", rules=2), enabled=no_systemd)
    assert FirewallCheck().collect_baseline(ctx) == {"rules": 2, "frontends": []}
