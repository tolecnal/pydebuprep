"""listeners: what listens on this host, compared with the snapshot."""

from __future__ import annotations

from typing import Any

from pydebuprep.checks.listeners import ListenersCheck
from pydebuprep.model import Finding, Severity, Status
from pydebuprep.runner import run_check

from .helpers import make_ctx

TCP_HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
UNIX_HEAD = "Num       RefCount Protocol Flags    Type St Inode Path\n"
EPHEMERAL = "/proc/sys/net/ipv4/ip_local_port_range"


def tcp_line(address: str, port: int, inode: int, state: str = "0A") -> str:
    return f"   0: {address}:{port:04X} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000     0        0 {inode} 1\n"


LOOPBACK, ANYWHERE = "0100007F", "00000000"
LOOPBACK6 = "00000000000000000000000001000000"


def system(
    tcp: str = "",
    tcp6: str = "",
    udp: str = "",
    unix: str = "",
    owners: dict[int, tuple[int, str]] | None = None,
) -> dict[str, Any]:
    files = {
        "/proc/net/tcp": TCP_HEAD + tcp,
        "/proc/net/tcp6": TCP_HEAD + tcp6,
        "/proc/net/udp": TCP_HEAD + udp,
        "/proc/net/udp6": TCP_HEAD,
        "/proc/net/unix": UNIX_HEAD + unix,
        EPHEMERAL: "32768\t60999\n",
    }
    for line in unix.splitlines():  # every path named is a socket that exists
        if len(line.split()) >= 8:
            files[line.split()[7]] = ""
    links = {}
    for inode, (pid, name) in (owners or {}).items():
        files[f"/proc/{pid}/comm"] = f"{name}\n"
        links[f"/proc/{pid}/fd/{inode}"] = f"socket:[{inode}]"
    return {"files": files, "links": links}


SSHD = system(tcp=tcp_line(ANYWHERE, 22, 11), owners={11: (100, "sshd")})


def inventory(**kw: Any) -> dict[str, str]:
    return ListenersCheck().collect_baseline(make_ctx(**system(**kw)))


def compare(before: dict[str, str], **kw: Any) -> list[Finding]:
    return ListenersCheck().compare(make_ctx(**system(**kw)), before)


def summary(findings: list[Finding]) -> list[tuple[Severity, str, list[str]]]:
    return [(f.severity, f.title, f.evidence) for f in findings]


def test_needs_root() -> None:
    result = run_check(ListenersCheck(), make_ctx(root=False))
    assert result.status == Status.SKIPPED


def test_without_a_snapshot_it_reports_nothing() -> None:
    assert ListenersCheck().run(make_ctx(**SSHD)) == []


def test_inventory_names_protocol_address_port_and_process() -> None:
    assert ListenersCheck().collect_baseline(make_ctx(**SSHD)) == {"tcp/0.0.0.0:22": "sshd"}


def test_inventory_reads_ipv6() -> None:
    assert inventory(tcp6=tcp_line(LOOPBACK6, 80, 12)) == {"tcp/[::1]:80": ""}


def test_only_listening_sockets_count() -> None:
    assert inventory(tcp=tcp_line(ANYWHERE, 22, 11, state="01")) == {}


def test_malformed_lines_are_ignored() -> None:
    assert inventory(tcp="short line\n", unix="short\n") == {}


def test_udp_bound_sockets_count_but_not_random_ports() -> None:
    udp = tcp_line(ANYWHERE, 53, 13, state="07") + tcp_line(ANYWHERE, 40000, 14, state="07")
    assert inventory(udp=udp) == {"udp/0.0.0.0:53": ""}


def test_random_ports_on_loopback_are_left_out() -> None:
    tcp = tcp_line(LOOPBACK, 40000, 15) + tcp_line(ANYWHERE, 40000, 16)
    assert inventory(tcp=tcp) == {"tcp/0.0.0.0:40000": ""}


def test_unix_sockets_with_a_path_that_accept_count() -> None:
    unix = (
        "0000: 00000002 00000000 00010000 0001 01 21 /run/app.sock\n"
        "0001: 00000002 00000000 00010000 0001 01 22 @abstract\n"
        "0002: 00000002 00000000 00000000 0001 03 23 /run/connected.sock\n"
        "0003: 00000002 00000000 00010000 0001 01 24\n"
        "0004: 00000002 00000000 00010000 0001 01 25 /run/user/1000/bus\n"
        "0005: 00000002 00000000 00010000 0001 01 26 /tmp/x.sock\n"
    )
    assert inventory(unix=unix, owners={21: (101, "app")}) == {"unix:/run/app.sock": "app"}


def test_a_process_that_went_away_while_reading_is_not_a_problem() -> None:
    ctx = make_ctx(files=system(tcp=tcp_line(ANYWHERE, 22, 11))["files"],
                   links={"/proc/100/fd/1": "pipe:[5]", "/proc/100/fd/2": "socket:[11]"})  # fmt: skip
    assert ListenersCheck().collect_baseline(ctx) == {"tcp/0.0.0.0:22": ""}


def test_nothing_changed_is_silent() -> None:
    assert compare({"tcp/0.0.0.0:22": "sshd"}, tcp=tcp_line(ANYWHERE, 22, 11),
                   owners={11: (100, "sshd")}) == []  # fmt: skip


def test_a_listener_that_is_gone_is_a_warning() -> None:
    assert summary(compare({"tcp/0.0.0.0:443": "nginx"})) == [
        (Severity.WARNING, "1 listener from before the upgrade is gone",
         ["tcp/0.0.0.0:443 (nginx)"])
    ]  # fmt: skip


def test_a_unix_socket_that_is_gone_is_for_information() -> None:
    assert summary(compare({"unix:/run/app.sock": ""})) == [
        (Severity.INFO, "1 Unix socket from before the upgrade is gone", ["unix:/run/app.sock"])
    ]


def test_moving_from_loopback_to_everywhere_is_a_warning() -> None:
    fs = compare({"tcp/127.0.0.1:3306": "mysqld"}, tcp=tcp_line(ANYWHERE, 3306, 11),
                 owners={11: (100, "mysqld")})  # fmt: skip
    assert summary(fs) == [
        (Severity.WARNING, "1 port is now reachable from other hosts",
         ["tcp/3306 (mysqld): 127.0.0.1 to 0.0.0.0"])
    ]  # fmt: skip


def test_moving_to_another_loopback_form_is_for_information() -> None:
    fs = compare({"tcp/127.0.0.1:80": ""}, tcp6=tcp_line(LOOPBACK6, 80, 12))
    assert summary(fs) == [
        (Severity.INFO, "1 port listens on other addresses", ["tcp/80: 127.0.0.1 to ::1"])
    ]


def test_a_new_listener_other_hosts_can_reach_is_a_warning() -> None:
    fs = compare({}, tcp=tcp_line(ANYWHERE, 8080, 11), owners={11: (100, "java")})
    assert summary(fs) == [
        (Severity.WARNING, "1 new listener can be reached from other hosts",
         ["tcp/0.0.0.0:8080 (java)"])
    ]  # fmt: skip


def test_a_new_local_listener_is_for_information() -> None:
    unix = "0000: 00000002 00000000 00010000 0001 01 21 /run/new.sock\n"
    fs = compare({}, tcp=tcp_line(LOOPBACK, 8080, 11), unix=unix)
    assert summary(fs) == [
        (Severity.INFO, "2 new local listeners", ["tcp/127.0.0.1:8080", "unix:/run/new.sock"])
    ]


def test_another_process_on_the_same_port_is_for_information() -> None:
    fs = compare({"tcp/0.0.0.0:3306": "mysqld"}, tcp=tcp_line(ANYWHERE, 3306, 11),
                 owners={11: (100, "mariadbd")})  # fmt: skip
    assert summary(fs) == [
        (Severity.INFO, "1 listener has another process behind it",
         ["tcp/0.0.0.0:3306: mysqld to mariadbd"])
    ]  # fmt: skip


def test_an_unknown_process_is_not_a_change() -> None:
    assert compare({"tcp/0.0.0.0:22": ""}, tcp=tcp_line(ANYWHERE, 22, 11),
                   owners={11: (100, "sshd")}) == []  # fmt: skip
    assert compare({"tcp/0.0.0.0:22": "sshd"}, tcp=tcp_line(ANYWHERE, 22, 11)) == []


def test_listeners_can_be_left_out() -> None:
    check = ListenersCheck({"ignore_listeners": ["tcp/*:443", "unix:/run/app*"]})
    assert (
        check.compare(make_ctx(**system()), {"tcp/0.0.0.0:443": "", "unix:/run/app.sock": ""}) == []
    )
    ctx = make_ctx(**system(tcp=tcp_line(ANYWHERE, 443, 11)))
    assert check.collect_baseline(ctx) == {}


def test_a_unix_socket_still_there_is_silent() -> None:
    unix = "0000: 00000002 00000000 00010000 0001 01 21 /run/app.sock\n"
    assert compare({"unix:/run/app.sock": ""}, unix=unix) == []


def test_another_address_on_a_known_port_is_not_a_new_listener() -> None:
    tcp = tcp_line(LOOPBACK, 80, 11) + tcp_line(ANYWHERE, 80, 12)
    fs = compare({"tcp/127.0.0.1:80": ""}, tcp=tcp)
    assert [f.title for f in fs] == ["1 port is now reachable from other hosts"]


def test_a_forged_line_in_the_socket_list_is_not_a_listener() -> None:
    """A socket's path is printed as it is, so one with a newline in it writes a line of its
    own. What that line names isn't a socket, or isn't there."""
    forged = (
        "0000: 00000002 00000000 00010000 0001 01 21 /home/u/x\n"
        "0: 00000002 00000000 00010000 0001 01 21 /run/fake.sock\n"
    )
    parts = system(unix=forged, owners={21: (101, "evil")})
    del parts["files"]["/run/fake.sock"]
    found = ListenersCheck({"ignore_listeners": []}).collect_baseline(make_ctx(**parts))
    assert found == {"unix:/home/u/x": "evil"}  # the real socket, under its real name
