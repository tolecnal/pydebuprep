"""Shared TLS findings: expiry, crypto OpenSSL refuses, DH parameters, protocols, names."""

from __future__ import annotations

import pytest

from checks.helpers import make_ctx, titles, tls_fixture
from pydebuprep.checks._tls import (
    TlsSite,
    apache_protocols,
    certificate_findings,
    dhparam_findings,
    name_findings,
    name_matches,
    protocol_findings,
    validate_cert_days,
)
from pydebuprep.checks._x509 import parse_pem
from pydebuprep.model import Severity

WHERE = "(ssl_certificate in /etc/nginx/sites-enabled/site)"


def ctx_with(*names: str, root: bool = True):  # type: ignore[no-untyped-def] # test helper
    return make_ctx(files={f"/certs/{n}": tls_fixture(n) for n in names}, root=root)


def certs(ctx, *names: str, warning: int = 28, critical: int = 14):  # type: ignore[no-untyped-def] # test helper
    paths = [(f"/certs/{n}", WHERE) for n in names]
    return certificate_findings(ctx, "nginx", paths, warning_days=warning, critical_days=critical)


def test_expiry_thresholds() -> None:
    names = ("good.pem", "soon.pem", "critical.pem", "expired.pem", "future.pem")
    found = certs(ctx_with(*names), *names)
    by_title = {f.title: f for f in found}
    assert set(by_title) == {
        "nginx uses expired or not yet valid certificates",
        "nginx has certificates expiring within 14 days",
        "nginx has certificates expiring within 28 days",
    }
    invalid = by_title["nginx uses expired or not yet valid certificates"]
    assert invalid.severity is Severity.CRITICAL
    assert any(e.startswith("/certs/expired.pem: expired 2026-10-01") for e in invalid.evidence)
    assert any(
        e.startswith("/certs/future.pem: not valid before 2026-12-01") for e in invalid.evidence
    )
    soon = by_title["nginx has certificates expiring within 28 days"]
    assert soon.severity is Severity.WARNING
    assert soon.evidence == [f"/certs/soon.pem: expires 2026-11-20 (22 days) {WHERE}"]
    crit = by_title["nginx has certificates expiring within 14 days"]
    assert crit.severity is Severity.CRITICAL
    assert crit.evidence == [f"/certs/critical.pem: expires 2026-11-05 (7 days) {WHERE}"]
    assert any("openssl x509 -noout" in r for r in soon.remediation)


def test_good_certificate_is_clean() -> None:
    assert (
        certs(ctx_with("good.pem", "chain.pem", "ec.pem"), "good.pem", "chain.pem", "ec.pem") == []
    )


def test_thresholds_are_options() -> None:
    found = certs(ctx_with("soon.pem"), "soon.pem", warning=30, critical=25)
    assert titles(found) == ["nginx has certificates expiring within 25 days"]


@pytest.mark.parametrize("warning,critical", [(14, 14), (28, 0), (366, 14), (10, 20)])
def test_validate_cert_days_rejects(warning: int, critical: int) -> None:
    with pytest.raises(ValueError):
        validate_cert_days(warning, critical)


def test_validate_cert_days_accepts_defaults() -> None:
    validate_cert_days(28, 14)
    validate_cert_days(365, 1)


def test_each_path_once() -> None:
    ctx = ctx_with("soon.pem")
    paths = [("/certs/soon.pem", WHERE), ("/certs/soon.pem", "(elsewhere)")]
    [finding] = certificate_findings(ctx, "nginx", paths, warning_days=28, critical_days=14)
    assert finding.evidence == [f"/certs/soon.pem: expires 2026-11-20 (22 days) {WHERE}"]


def test_missing_or_garbage_is_critical() -> None:
    ctx = make_ctx(files={"/certs/junk.pem": b"junk"})
    [finding] = certificate_findings(
        ctx, "nginx", [("/certs/none.pem", WHERE), ("/certs/junk.pem", WHERE)],
        warning_days=28, critical_days=14,
    )  # fmt: skip
    assert finding.title == "nginx names certificates that can't be read"
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence[0] == f"/certs/none.pem: can't be read {WHERE}"
    assert finding.evidence[1].startswith("/certs/junk.pem: no certificate in the file")


def test_unreadable_as_non_root_is_info() -> None:
    ctx = ctx_with("soon.pem", root=False)
    found = certificate_findings(
        ctx, "nginx", [("/etc/letsencrypt/live/x/fullchain.pem", WHERE), ("/certs/soon.pem", WHERE)],
        warning_days=28, critical_days=14,
    )  # fmt: skip
    assert titles(found) == [
        "nginx has certificates expiring within 28 days",
        "nginx's certificates were not checked (needs root)",
    ]
    assert found[1].severity is Severity.INFO
    assert found[1].evidence == [f"/etc/letsencrypt/live/x/fullchain.pem {WHERE}"]


def test_weak_crypto() -> None:
    names = ("weak-rsa.pem", "sha1.pem", "ec.pem")
    [finding] = certs(ctx_with(*names), *names)
    assert finding.title == "nginx uses keys or signatures OpenSSL refuses"
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence == [
        f"/certs/weak-rsa.pem: RSA 1024 bits {WHERE}",
        f"/certs/sha1.pem: signed with SHA-1 {WHERE}",
    ]


def test_weak_crypto_other_keys() -> None:
    from pydebuprep.checks._tls import weakness

    leaf = parse_pem(tls_fixture("good.pem"))[0]
    assert weakness(leaf) is None
    assert (
        weakness(leaf.__class__(**{**leaf.__dict__, "key_type": "ec", "key_bits": 192}))
        == "EC 192 bits"
    )
    assert (
        weakness(leaf.__class__(**{**leaf.__dict__, "key_type": "dsa", "key_bits": 1024}))
        == "DSA 1024 bits"
    )
    assert (
        weakness(leaf.__class__(**{**leaf.__dict__, "signature_hash": "md5"})) == "signed with MD5"
    )
    assert weakness(leaf.__class__(**{**leaf.__dict__, "key_type": "ec", "key_bits": 0})) is None


def test_dhparams() -> None:
    files = {"/dh/1024.pem": tls_fixture("dh1024.pem"), "/dh/2048.pem": tls_fixture("dh2048.pem")}
    ctx = make_ctx(
        files={**files, "/dh/empty.pem": b"nothing", "/certs/good.pem": tls_fixture("good.pem")}
    )
    where = "(ssl_dhparam in /etc/nginx/nginx.conf)"
    [finding] = dhparam_findings(
        ctx,
        "nginx",
        [
            ("/dh/1024.pem", where),
            ("/dh/2048.pem", where),
            ("/dh/none.pem", where),
            ("/dh/empty.pem", where),
        ],
    )
    assert finding.title == "nginx uses DH parameters OpenSSL refuses"
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence == [
        f"/dh/1024.pem: 1024 bits {where}",
        f"/dh/none.pem: can't be read {where}",
        f"/dh/empty.pem: no DH parameters in the file {where}",
    ]
    # Parameters appended to a certificate file are optional there.
    assert dhparam_findings(ctx, "Apache", [("/certs/good.pem", where)], required=False) == []


def test_dhparams_malformed_and_non_root() -> None:
    bad = b"-----BEGIN DH PARAMETERS-----\nMAA=\n-----END DH PARAMETERS-----\n"
    ctx = make_ctx(files={"/dh/bad.pem": bad})
    [finding] = dhparam_findings(ctx, "nginx", [("/dh/bad.pem", "(x)")])
    assert finding.evidence[0].startswith("/dh/bad.pem: empty DH parameters")
    assert dhparam_findings(make_ctx(root=False), "nginx", [("/dh/none.pem", "(x)")]) == []


def test_protocols() -> None:
    old = frozenset({"TLSv1", "TLSv1.1"})
    mixed = frozenset({"TLSv1", "TLSv1.2"})
    modern = frozenset({"TLSv1.2", "TLSv1.3"})
    [only] = protocol_findings("nginx", [(old, "(ssl_protocols in a)")])
    assert (only.severity, only.title) == (
        Severity.CRITICAL,
        "nginx enables only TLS protocols OpenSSL refuses",
    )
    assert only.evidence == ["TLSv1 TLSv1.1 (ssl_protocols in a)"]
    [some] = protocol_findings("nginx", [(mixed, "(b)")])
    assert (some.severity, some.title) == (
        Severity.WARNING,
        "nginx enables TLS protocols OpenSSL refuses",
    )
    assert protocol_findings("nginx", [(modern, "(c)"), (frozenset(), "(d)")]) == []


def test_apache_protocols() -> None:
    base = frozenset({"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"})
    assert apache_protocols(["all", "-SSLv3"]) == base
    assert apache_protocols(["all", "-TLSv1", "-TLSv1.1"]) == {"TLSv1.2", "TLSv1.3"}
    assert apache_protocols(["TLSv1"]) == {"TLSv1"}
    assert apache_protocols(["+TLSv1.2"]) == {"TLSv1.2"}
    assert apache_protocols(["-ALL", "+tlsv1.3"]) == {"TLSv1.3"}


def test_name_matching() -> None:
    good = parse_pem(tls_fixture("good.pem"))[0]
    legacy = parse_pem(tls_fixture("cn-only.pem"))[0]
    assert name_matches("www.example.org", good)
    assert name_matches("WWW.Example.Org.", good)
    assert name_matches("a.example.net", good)
    assert not name_matches("a.b.example.net", good)
    assert not name_matches("example.net", good)
    assert not name_matches("other.org", good)
    assert name_matches("legacy.example.org", legacy)
    assert not name_matches("www.example.org", legacy)
    no_names = legacy.__class__(**{**legacy.__dict__, "subject_cn": None})
    assert not name_matches("legacy.example.org", no_names)


def site(*names: str, cert: str = "/certs/good.pem") -> TlsSite:
    return TlsSite(
        source="/etc/nginx/sites-enabled/site", names=names, certificate=cert, listen=(("", 443),)
    )


def test_name_findings_skip_unmatchable_names() -> None:
    ctx = make_ctx(files={"/certs/good.pem": tls_fixture("good.pem"), "/certs/junk.pem": b"junk"})
    odd = site("_", "~^x", "*.example.org", ".example.org", "", "www.example.org")
    assert (
        name_findings(
            ctx,
            "nginx",
            [odd, site("x.org", cert="/certs/missing.pem"), site("x.org", cert="/certs/junk.pem")],
        )
        == []
    )
    [finding] = name_findings(ctx, "nginx", [site("other.org", "example.org")])
    assert (finding.severity, finding.title) == (
        Severity.WARNING,
        "nginx has certificates that don't cover their server names",
    )
    assert finding.evidence == [
        "other.org isn't covered by /certs/good.pem (/etc/nginx/sites-enabled/site)"
    ]
