"""The SNI probe: does each TLS site serve the certificate its configuration names?"""

from __future__ import annotations

import base64
import re

from checks.helpers import make_ctx, titles, tls_fixture
from fakes import FakeSystem
from pydebuprep.checks._listeners import listening_addresses
from pydebuprep.checks._tls import MAX_PROBES, TlsSite, probe_targets, served_findings
from pydebuprep.checks.nginx import NginxCheck
from pydebuprep.model import Severity
from pydebuprep.remote_config import parse_remote

HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
ROW = "   0: {addr} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0\n"
ZERO6 = "00000000000000000000000000000000"
LOOP6 = "00000000000000000000000001000000"
PROC = {
    "/proc/net/tcp": HEAD
    + ROW.format(addr="0100007F:01BB", state="0A")
    + ROW.format(addr="0100000A:20FB", state="0A")
    + ROW.format(addr="00000000:0050", state="0A")
    + ROW.format(addr="0100007F:D431", state="01"),
    "/proc/net/tcp6": HEAD
    + ROW.format(addr=f"{ZERO6}:01BB", state="0A")
    + ROW.format(addr=f"{LOOP6}:22B3", state="0A"),
}


def der(name: str) -> bytes:
    body = re.search(rb"-----BEGIN CERTIFICATE-----(.*?)-----END", tls_fixture(name), re.S)
    assert body
    return base64.b64decode(body.group(1))


def site(
    *names: str, listen: tuple[tuple[str, int], ...] = (("", 443),), cert: str = "/etc/ssl/good.pem"
) -> TlsSite:
    return TlsSite("/etc/nginx/sites-enabled/s", names, (cert,), listen)


def test_listening_addresses() -> None:
    assert listening_addresses(FakeSystem(files=PROC)) == {
        ("127.0.0.1", 443),
        ("10.0.0.1", 8443),
        ("0.0.0.0", 80),
        ("::", 443),
        ("::1", 8883),
    }
    assert listening_addresses(FakeSystem()) == set()


def test_probe_targets_rules() -> None:
    listening = listening_addresses(FakeSystem(files=PROC))
    sites = [
        site("_", "*.example.org", "www.example.org"),
        site(
            "a.example.org",
            listen=(("[::]", 443), ("10.0.0.1", 8443), ("10.0.0.2", 443), ("", 9999)),
        ),
        site(
            "b.example.org",
            listen=(("*", 80), ("0.0.0.0", 80), ("[::1]", 8883), ("localhost", 443)),
        ),
        site("_", "~^re$"),  # no name to send
        site("www.example.org"),  # a duplicate target
    ]
    assert [(h, p, n) for h, p, n, _ in probe_targets(sites, listening)] == [
        ("127.0.0.1", 443, "www.example.org"),
        ("::1", 443, "a.example.org"),
        ("10.0.0.1", 8443, "a.example.org"),
        ("127.0.0.1", 80, "b.example.org"),
        ("::1", 8883, "b.example.org"),
    ]


def test_probe_targets_capped() -> None:
    listening = {("127.0.0.1", 443)}
    sites = [site(f"s{n}.example.org") for n in range(MAX_PROBES + 5)]
    assert len(probe_targets(sites, listening)) == MAX_PROBES


def ctx_serving(served: bytes | None):  # type: ignore[no-untyped-def] # test helper
    tls = {} if served is None else {("127.0.0.1", 443, "www.example.org"): served}
    return make_ctx(
        files={**PROC, "/etc/ssl/good.pem": tls_fixture("good.pem")}, tls=tls, root=False
    )


def test_served_matches_is_clean() -> None:
    ctx = ctx_serving(der("good.pem"))
    assert served_findings(ctx, "nginx", "nginx", [site("www.example.org")]) == []
    assert ctx.system.tls_calls == [("127.0.0.1", 443, "www.example.org", 5.0)]  # type: ignore[attr-defined] # FakeSystem


def test_served_differs_is_warning() -> None:
    [finding] = served_findings(
        ctx_serving(der("soon.pem")), "nginx", "nginx", [site("www.example.org")]
    )
    assert (finding.severity, finding.title) == (
        Severity.WARNING,
        "nginx serves different certificates than its configuration names",
    )
    [line] = finding.evidence
    assert line.startswith("www.example.org on 127.0.0.1:443 serves ")
    assert ", /etc/ssl/good.pem is " in line
    assert "sudo systemctl reload nginx" in finding.remediation


def test_probe_error_is_info() -> None:
    [finding] = served_findings(ctx_serving(None), "nginx", "nginx", [site("www.example.org")])
    assert (finding.severity, finding.title) == (
        Severity.INFO,
        "nginx: some TLS sites didn't answer the probe",
    )
    assert finding.evidence == ["www.example.org on 127.0.0.1:443: Connection refused"]


def test_unreadable_certificate_on_disk_is_not_compared() -> None:
    ctx = make_ctx(
        root=False,
        files={**PROC, "/etc/ssl/good.pem": b"junk"},
        tls={("127.0.0.1", 443, "www.example.org"): der("good.pem")},
    )
    assert served_findings(ctx, "nginx", "nginx", [site("www.example.org")]) == []
    assert ctx.system.tls_calls == []  # type: ignore[attr-defined] # nothing to compare: no connection


NGINX = {
    "/etc/nginx/nginx.conf": "http { server { listen 443 ssl; server_name www.example.org; "
    "ssl_certificate /etc/ssl/good.pem; } }\n",
}


def test_nginx_probes_by_default() -> None:
    ctx = make_ctx(files={**PROC, **NGINX, "/etc/ssl/good.pem": tls_fixture("good.pem")},
                   tls={("127.0.0.1", 443, "www.example.org"): der("soon.pem")}, root=False)  # fmt: skip
    assert "nginx serves different certificates than its configuration names" in titles(
        NginxCheck().run(ctx)
    )


def test_tls_probe_off() -> None:
    ctx = make_ctx(
        files={**PROC, **NGINX, "/etc/ssl/good.pem": tls_fixture("good.pem")}, root=False
    )
    assert NginxCheck({"tls_probe": False}).run(ctx) == []
    assert ctx.system.tls_calls == []  # type: ignore[attr-defined] # FakeSystem


def test_remote_config_may_set_tls_probe() -> None:
    config = parse_remote(
        "checks:\n  nginx:\n    tls_probe: false\n", "https://portal.example/c.yaml"
    )
    assert config is not None


def test_apache_tls_probe_off() -> None:
    from pydebuprep.checks.apache import ApacheCheck

    files = {
        "/etc/apache2/apache2.conf": "<VirtualHost *:443>\nServerName www.example.org\n"
        "SSLEngine on\nSSLCertificateFile /etc/ssl/good.pem\n</VirtualHost>\n",
        "/etc/ssl/good.pem": tls_fixture("good.pem"),
        **PROC,
    }
    served = {("127.0.0.1", 443, "www.example.org"): der("soon.pem")}
    found = ApacheCheck().run(make_ctx(files=files, tls=served, root=False))
    assert titles(found) == ["Apache serves different certificates than its configuration names"]
    ctx = make_ctx(files=files, tls=served, root=False)
    assert ApacheCheck({"tls_probe": False}).run(ctx) == []
    assert ctx.system.tls_calls == []  # type: ignore[attr-defined] # FakeSystem


def test_rsa_and_ecdsa_certificates_both_count() -> None:
    # nginx serves the ECDSA one to a client that prefers it; that's no stale certificate.
    files = {
        **PROC,
        "/etc/ssl/good.pem": tls_fixture("good.pem"),
        "/etc/ssl/ec.pem": tls_fixture("ec.pem"),
    }
    pair = TlsSite("/etc/nginx/sites-enabled/s", ("www.example.org", "ec.example.org"),
                   ("/etc/ssl/good.pem", "/etc/ssl/ec.pem"), (("", 443),))  # fmt: skip
    ctx = make_ctx(
        files=files, root=False, tls={("127.0.0.1", 443, "www.example.org"): der("ec.pem")}
    )
    assert served_findings(ctx, "nginx", "nginx", [pair]) == []
    from pydebuprep.checks._tls import name_findings

    assert name_findings(ctx, "nginx", [pair]) == []  # ec.example.org is on the second


def test_nginx_server_keeps_every_certificate() -> None:
    from pydebuprep.checks.nginx import read_config

    conf = "http { server { listen 443 ssl; server_name a.example.org;\n" \
        "ssl_certificate /etc/ssl/good.pem; ssl_certificate /etc/ssl/ec.pem; } }\n"  # fmt: skip
    [site] = read_config(make_ctx(files={"/etc/nginx/nginx.conf": conf})).sites
    assert site.certificates == ("/etc/ssl/good.pem", "/etc/ssl/ec.pem")


def test_apache_vhost_keeps_every_certificate() -> None:
    from pydebuprep.checks.apache import read_config

    conf = "<VirtualHost *:443>\nSSLEngine on\nSSLCertificateFile /etc/ssl/good.pem\n" \
        "SSLCertificateFile /etc/ssl/ec.pem\nSSLCertificateChainFile /etc/ssl/chain.pem\n</VirtualHost>\n"  # fmt: skip
    [site] = read_config(make_ctx(files={"/etc/apache2/apache2.conf": conf})).sites
    assert site.certificates == ("/etc/ssl/good.pem", "/etc/ssl/ec.pem")


def test_only_listeners_owned_by_root_are_probed() -> None:
    # nginx failed to start after the upgrade and an unprivileged user took its port:
    # that listener belongs to uid 1000, so nothing is sent to it. Without systemd too.
    user = ROW.replace("     0        0 1 1", "  1000        0 1 1")
    proc = {
        **PROC,
        "/proc/net/tcp": PROC["/proc/net/tcp"] + user.format(addr="00000000:20FB", state="0A"),
    }
    assert ("0.0.0.0", 8443) not in listening_addresses(FakeSystem(files=proc))
    files = {**proc, "/etc/ssl/good.pem": tls_fixture("good.pem")}
    ctx = make_ctx(files=files, tls={("127.0.0.1", 8443, "www.example.org"): der("soon.pem")})
    assert (
        served_findings(ctx, "nginx", "nginx", [site("www.example.org", listen=(("", 8443),))])
        == []
    )
    assert ctx.system.tls_calls == []  # type: ignore[attr-defined] # FakeSystem
