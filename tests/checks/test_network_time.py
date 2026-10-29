from __future__ import annotations

import json
from typing import Any

from pydebuprep.checks._systemd import ACTIVE_SERVICES
from pydebuprep.checks.network import (
    IP_ADDR,
    IP_ROUTE4,
    IP_ROUTE6,
    RESOLVECTL_DNS,
    NetworkCheck,
)
from pydebuprep.checks.time_sync import TimeSyncCheck
from pydebuprep.model import Severity, Status
from pydebuprep.runner import run_check
from pydebuprep.system import CommandResult

from .helpers import make_ctx, titles

NO_SYSTEMD = CommandResult(ACTIVE_SERVICES, 1, "", "System has not been booted with systemd\n")


def services(*names: str) -> str:
    return "".join(f"{n} loaded active running x\n" for n in names)


# --- time-sync -----------------------------------------------------------------------


def test_time_ok() -> None:
    ctx = make_ctx(commands={ACTIVE_SERVICES: services("cron.service", "chrony.service")})
    assert TimeSyncCheck().run(ctx) == []


def test_no_time_service_and_unsynchronised() -> None:
    ctx = make_ctx(commands={ACTIVE_SERVICES: services("cron.service")}, clock_synced=False)
    fs = TimeSyncCheck().run(ctx)
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.WARNING, "No time synchronisation service is running"),
        (Severity.WARNING, "The system clock is not synchronised"),
    ]


def test_time_without_systemd_uses_clock_state_only() -> None:
    ctx = make_ctx(commands={ACTIVE_SERVICES: NO_SYSTEMD}, clock_synced=False)
    assert titles(TimeSyncCheck().run(ctx)) == ["The system clock is not synchronised"]


def test_time_skipped_when_nothing_is_known() -> None:
    ctx = make_ctx(commands={ACTIVE_SERVICES: NO_SYSTEMD}, clock_synced=None)
    assert run_check(TimeSyncCheck(), ctx).status is Status.SKIPPED


def test_time_baseline_and_service_change() -> None:
    ctx = make_ctx(commands={ACTIVE_SERVICES: services("chrony.service")})
    assert TimeSyncCheck().collect_baseline(ctx) == {"services": ["chrony"], "synchronized": True}
    (f,) = TimeSyncCheck().compare(ctx, {"services": ["ntp"], "synchronized": True})
    assert (f.severity, f.title) == (Severity.INFO, "Time synchronisation moved from ntp to chrony")
    assert TimeSyncCheck().compare(ctx, {"services": ["chrony"], "synchronized": True}) == []
    empty = make_ctx(commands={ACTIVE_SERVICES: services("cron.service")})
    assert TimeSyncCheck().compare(empty, {"services": ["ntp"], "synchronized": True}) == []


# --- network -------------------------------------------------------------------------


def iface(name: str, up: bool = True, *addrs: str) -> dict[str, Any]:
    info = []
    for a in addrs:
        local, prefix = a.split("/")
        info.append(
            {
                "family": "inet6" if ":" in local else "inet",
                "local": local,
                "prefixlen": int(prefix),
                "scope": "global",
            }
        )
    info.append({"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"})
    return {
        "ifname": name,
        "operstate": "UP" if up else "DOWN",
        "flags": ["UP", "LOWER_UP"] if up else [],
        "addr_info": info,
    }


ADDRS = json.dumps(
    [
        iface("lo", True, "127.0.0.1/8"),
        iface("eth0", True, "192.0.2.10/24", "2001:db8::10/64"),
        iface("wg0", True, "10.8.0.2/24"),
        iface("veth12ab", True),
    ]
)
ROUTE4 = json.dumps([{"dst": "default", "gateway": "192.0.2.1", "dev": "eth0"}])
RESOLV = "nameserver 192.0.2.53\nsearch example.org\n"


def net_ctx(**kw: Any) -> Any:
    commands = {
        IP_ADDR: kw.pop("addrs", ADDRS),
        IP_ROUTE4: kw.pop("route4", ROUTE4),
        IP_ROUTE6: kw.pop("route6", "[]"),
        ACTIVE_SERVICES: kw.pop("services", services("systemd-networkd.service")),
        **kw.pop("commands", {}),
    }
    files = {"/etc/resolv.conf": kw.pop("resolv", RESOLV), **kw.pop("files", {})}
    return make_ctx(commands=commands, files=files, **kw)


def test_network_ok() -> None:
    assert NetworkCheck().run(net_ctx()) == []


def test_no_default_route_and_no_dns() -> None:
    fs = NetworkCheck().run(net_ctx(route4="[]", resolv="# empty\n"))
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.WARNING, "No default route"),
        (Severity.WARNING, "No DNS servers configured"),
    ]


def test_resolved_stub_asks_resolvectl() -> None:
    out = "Global:\nLink 2 (eth0): 192.0.2.53 2001:db8::53\nLink 3 (wg0):\n\nsomething unexpected\n"
    ctx = net_ctx(resolv="nameserver 127.0.0.53\noptions edns0\n", commands={RESOLVECTL_DNS: out})
    assert NetworkCheck().run(ctx) == []
    assert NetworkCheck().collect_baseline(ctx)["dns"] == ["192.0.2.53", "2001:db8::53"]


def test_resolved_stub_without_upstream_servers() -> None:
    ctx = net_ctx(
        resolv="nameserver 127.0.0.53\n", commands={RESOLVECTL_DNS: "Global:\nLink 2 (eth0):\n"}
    )
    assert titles(NetworkCheck().run(ctx)) == ["No DNS servers configured"]


def test_resolvectl_failure_keeps_stub_address() -> None:
    res = CommandResult(
        RESOLVECTL_DNS,
        1,
        "",
        "Failed to get global data: Unit dbus-org.freedesktop.resolve1.service not found.\n",
    )
    ctx = net_ctx(resolv="nameserver 127.0.0.53\n", commands={RESOLVECTL_DNS: res})
    assert NetworkCheck().run(ctx) == []
    assert NetworkCheck().collect_baseline(ctx)["dns"] == ["127.0.0.53"]


def test_network_baseline_ignores_virtual_interfaces() -> None:
    base = NetworkCheck().collect_baseline(net_ctx())
    assert base == {
        "interfaces": {
            "eth0": {"up": True, "addresses": ["192.0.2.10/24", "2001:db8::10/64"]},
            "wg0": {"up": True, "addresses": ["10.8.0.2/24"]},
        },
        "default_routes": ["via 192.0.2.1 dev eth0"],
        "dns": ["192.0.2.53"],
        "managers": ["systemd-networkd"],
    }


def test_network_compare_reports_losses_and_changes() -> None:
    before = NetworkCheck().collect_baseline(net_ctx())
    after = net_ctx(
        addrs=json.dumps([iface("eth0", True, "192.0.2.10/24"), iface("ens3", False)]),
        route4=json.dumps([{"dst": "default", "gateway": "192.0.2.254", "dev": "eth0"}]),
        resolv="nameserver 198.51.100.53\n",
        services=services("NetworkManager.service"),
        files={"/etc/netplan/50-cloud-init.yaml": "network: {}"},
    )
    fs = NetworkCheck().compare(after, before)
    assert [(f.severity, f.title) for f in fs] == [
        (Severity.WARNING, "Interface wg0 was up before the upgrade and is gone now"),
        (Severity.WARNING, "eth0 lost addresses it had before the upgrade"),
        (Severity.WARNING, "The default route changed"),
        (
            Severity.WARNING,
            "Network configuration moved from systemd-networkd to NetworkManager, netplan",
        ),
        (Severity.INFO, "DNS servers changed"),
    ]
    assert fs[1].evidence == ["2001:db8::10/64"]


def test_network_compare_interface_down() -> None:
    before = NetworkCheck().collect_baseline(net_ctx())
    after = net_ctx(
        addrs=json.dumps(
            [iface("eth0", True, "192.0.2.10/24", "2001:db8::10/64"), iface("wg0", False)]
        )
    )
    assert titles(NetworkCheck().compare(after, before)) == [
        "Interface wg0 was up before the upgrade and is down now",
        "wg0 lost addresses it had before the upgrade",
    ]


def test_network_ignore_interfaces_option() -> None:
    base = NetworkCheck({"ignore_interfaces": ["wg*"]}).collect_baseline(net_ctx())
    assert list(base["interfaces"]) == ["eth0", "lo", "veth12ab"]
