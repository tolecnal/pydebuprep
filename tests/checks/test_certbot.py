"""certbot: renewals that will fail, and certificates it hasn't renewed."""

from __future__ import annotations

import pytest

from checks.helpers import make_ctx, titles, tls_fixture
from pydebuprep.checks.base import CheckSkipped
from pydebuprep.checks.certbot import CertbotCheck, renewal_plugins, site_dirs
from pydebuprep.model import Severity

DIST = "/usr/lib/python3/dist-packages"


def renewal(authenticator: str, installer: str = "None", name: str = "example.org") -> str:
    return (
        f"version = 2.11.0\ncert = /etc/letsencrypt/live/{name}/cert.pem\n"
        f"[renewalparams]\naccount = abc\nauthenticator = {authenticator}\n"
        f"installer = {installer}\nserver = https://acme-v02.api.letsencrypt.org/directory\n"
    )


def plugin(name: str) -> str:
    return f"[certbot.plugins]\n{name} = certbot_x._internal:Authenticator\n\n[console_scripts]\nx = y\n"


def certbot_ctx(files: dict[str, str | bytes] | None = None, **kw):  # type: ignore[no-untyped-def] # test helper
    base: dict[str, str | bytes] = {
        "/usr/bin/certbot": "#! /usr/bin/python3\nfrom certbot.main import main\n",
        "/usr/bin/python3": "",
        "/etc/letsencrypt/renewal/example.org.conf": renewal("webroot"),
        "/etc/letsencrypt/live/example.org/cert.pem": tls_fixture("good.pem"),
    }
    base.update(files or {})
    return make_ctx(files=base, **kw)


def test_skipped_without_renewals() -> None:
    with pytest.raises(CheckSkipped, match="certbot has no renewals"):
        CertbotCheck().run(make_ctx())


def test_renewal_plugins() -> None:
    assert renewal_plugins(renewal("dns-cloudflare", "nginx")) == ("dns-cloudflare", "nginx")
    assert renewal_plugins(renewal("webroot")) == ("webroot", None)
    assert renewal_plugins("authenticator = x\n") == (None, None)  # not in [renewalparams]


def test_builtin_authenticators_need_nothing() -> None:
    files = {
        "/etc/letsencrypt/renewal/b.org.conf": renewal("standalone", name="b.org"),
        "/etc/letsencrypt/live/b.org/cert.pem": tls_fixture("good.pem"),
    }
    assert CertbotCheck().run(certbot_ctx(files)) == []


def test_missing_dns_plugin() -> None:
    files = {"/etc/letsencrypt/renewal/example.org.conf": renewal("dns-cloudflare", "nginx")}
    [finding] = CertbotCheck().run(certbot_ctx(files))
    assert (finding.severity, finding.title) == (
        Severity.CRITICAL,
        "certbot renewals use plugins that aren't installed",
    )
    assert finding.evidence == [
        "example.org.conf: authenticator dns-cloudflare",
        "example.org.conf: installer nginx",
    ]
    assert any("certbot renew --dry-run" in r for r in finding.remediation)


def test_plugin_found_in_dist_packages() -> None:
    files = {
        "/etc/letsencrypt/renewal/example.org.conf": renewal("dns-cloudflare", "nginx"),
        f"{DIST}/certbot_dns_cloudflare-2.11.0.dist-info/entry_points.txt": plugin(
            "dns-cloudflare"
        ),
        "/usr/local/lib/python3.13/dist-packages/certbot_nginx-2.11.0.egg-info/entry_points.txt": plugin(
            "nginx"
        ),
    }
    assert CertbotCheck().run(certbot_ctx(files)) == []


def test_site_dirs() -> None:
    ctx = certbot_ctx()  # python3 isn't a link here: any version's /usr/local directory
    assert site_dirs(ctx, "/usr/bin/python3") == [DIST, "/usr/local/lib/python3.*/dist-packages"]
    venv = certbot_ctx({"/opt/certbot/pyvenv.cfg": "home = /usr/bin\nversion = 3.11.2\n"})
    assert site_dirs(venv, "/opt/certbot/bin/python") == [
        "/opt/certbot/lib/python3.11/site-packages"
    ]


def test_venv_on_old_python() -> None:
    # certbot installed with pip into a virtualenv made with Python 3.11, which the
    # upgrade replaced with 3.13.
    files = {
        "/usr/local/bin/certbot": "#!/opt/certbot/bin/python\n",
        "/opt/certbot/pyvenv.cfg": "home = /usr/bin\nversion_info = 3.11.2.final.0\n",
        "/opt/certbot/bin/python": "",
        "/usr/bin/python3.13": "",
    }
    found = CertbotCheck().run(_without_apt(files))
    assert titles(found) == ["certbot's Python interpreter is missing"]
    assert found[0].evidence == [
        "/opt/certbot/bin/python: the virtualenv was made with Python 3.11, and /usr/bin/python3.11 is gone"
    ]
    files["/usr/bin/python3.11"] = ""
    assert CertbotCheck().run(_without_apt(files)) == []


def _without_apt(files: dict[str, str]):  # type: ignore[no-untyped-def] # test helper
    ctx = certbot_ctx(files)
    del ctx.system.files["/usr/bin/certbot"]  # type: ignore[attr-defined] # FakeSystem
    return ctx


def test_interpreter_missing() -> None:
    ctx = certbot_ctx({"/usr/bin/certbot": "#!/usr/bin/python3.11\n"})
    [finding] = CertbotCheck().run(ctx)
    assert (finding.severity, finding.title) == (
        Severity.CRITICAL,
        "certbot's Python interpreter is missing",
    )
    assert finding.evidence == ["/usr/bin/python3.11 doesn't exist (#! line of /usr/bin/certbot)"]


def test_env_shebang_and_no_shebang() -> None:
    assert CertbotCheck().run(certbot_ctx({"/usr/bin/certbot": "#!/usr/bin/env python3\n"})) == []
    # Without a #! line there is nothing to say about the interpreter.
    assert CertbotCheck().run(certbot_ctx({"/usr/bin/certbot": "\x7fELF"})) == []


def test_certbot_gone() -> None:
    ctx = certbot_ctx()
    del ctx.system.files["/usr/bin/certbot"]  # type: ignore[attr-defined] # FakeSystem
    [finding] = CertbotCheck().run(ctx)
    # Could be certbot in a container with /etc/letsencrypt mounted: a warning.
    assert (finding.severity, finding.title) == (
        Severity.WARNING,
        "certbot renewals are configured but certbot wasn't found",
    )


def test_snap_is_info() -> None:
    ctx = certbot_ctx(
        {"/snap/bin/certbot": "", "/etc/letsencrypt/renewal/example.org.conf": renewal("dns-x")}
    )
    del ctx.system.files["/usr/bin/certbot"]  # type: ignore[attr-defined] # FakeSystem
    [finding] = CertbotCheck().run(ctx)
    assert (finding.severity, finding.title) == (
        Severity.INFO,
        "certbot is a snap; its plugins aren't checked",
    )


def test_live_certificate_expiring() -> None:
    files = {"/etc/letsencrypt/live/example.org/cert.pem": tls_fixture("soon.pem")}
    [finding] = CertbotCheck().run(certbot_ctx(files))
    assert finding.title == "certbot has certificates expiring within 28 days"
    assert finding.evidence == [
        "/etc/letsencrypt/live/example.org/cert.pem: expires 2026-11-20 (22 days) "
        "(renewal/example.org.conf)"
    ]
    quiet = CertbotCheck({"cert_warning_days": 20, "cert_critical_days": 10}).run(
        certbot_ctx(files)
    )
    assert quiet == []
    with pytest.raises(ValueError):
        CertbotCheck({"cert_warning_days": 400})


def test_cert_path_defaults_to_live_dir() -> None:
    files = {
        "/etc/letsencrypt/renewal/b.org.conf": "[renewalparams]\nauthenticator = webroot\n",
        "/etc/letsencrypt/live/b.org/cert.pem": tls_fixture("critical.pem"),
    }
    found = CertbotCheck().run(certbot_ctx(files))
    assert titles(found) == ["certbot has certificates expiring within 14 days"]


def test_live_unreadable_as_non_root_is_info() -> None:
    ctx = certbot_ctx(root=False)
    del ctx.system.files["/etc/letsencrypt/live/example.org/cert.pem"]  # type: ignore[attr-defined] # FakeSystem
    assert titles(CertbotCheck().run(ctx)) == [
        "certbot's certificates were not checked (needs root)"
    ]


def test_pip_plugin_left_behind_for_the_old_python() -> None:
    # bullseye → bookworm: /usr/local/lib/python3.9 stays on disk, but python3 is 3.11.
    files = {
        "/etc/letsencrypt/renewal/example.org.conf": renewal("dns-cloudflare"),
        "/usr/bin/python3.11": "",
        "/usr/local/lib/python3.9/dist-packages/certbot_dns_cloudflare-1.0.dist-info/entry_points.txt": plugin(
            "dns-cloudflare"
        ),
    }
    ctx = certbot_ctx(files, links={"/usr/bin/python3": "python3.11"})
    del ctx.system.files["/usr/bin/python3"]  # type: ignore[attr-defined] # a link to python3.11 now
    assert site_dirs(ctx, "/usr/bin/python3") == [DIST, "/usr/local/lib/python3.11/dist-packages"]
    assert titles(CertbotCheck().run(ctx)) == ["certbot renewals use plugins that aren't installed"]
    moved = "/usr/local/lib/python3.11/dist-packages/certbot_dns_cloudflare-1.0.dist-info/entry_points.txt"
    ctx.system.files[moved] = plugin("dns-cloudflare")  # type: ignore[attr-defined] # FakeSystem
    assert CertbotCheck().run(ctx) == []


def test_versioned_interpreter_names_its_own_site_dir() -> None:
    assert site_dirs(certbot_ctx(), "/usr/bin/python3.13") == [
        DIST,
        "/usr/local/lib/python3.13/dist-packages",
    ]


def test_certbot_in_its_own_virtualenv_under_opt() -> None:
    files = {
        "/opt/certbot/bin/certbot": "#!/opt/certbot/bin/python\n",
        "/opt/certbot/bin/python": "",
        "/opt/certbot/pyvenv.cfg": "home = /usr/bin\nversion = 3.13.5\n",
        "/usr/bin/python3.13": "",
    }
    ctx = certbot_ctx(files)
    del ctx.system.files["/usr/bin/certbot"]  # type: ignore[attr-defined] # FakeSystem
    assert CertbotCheck().run(ctx) == []


def test_env_dash_s_shebang() -> None:
    from pydebuprep.checks.certbot import interpreter

    assert interpreter("#!/usr/bin/env -S python3 -u\n") == "/usr/bin/python3"
    assert interpreter("#!/usr/bin/env -S\n") is None
    assert interpreter("#!\n") is None
