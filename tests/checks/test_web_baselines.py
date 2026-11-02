"""nginx and Apache before and after the upgrade: modules, configuration files, listeners."""

from __future__ import annotations

from typing import Any

import pytest

from checks.helpers import make_ctx, titles
from checks.test_systemd_critical import listener_ctx
from pydebuprep.checks._webconfig import unversioned, web_compare
from pydebuprep.checks.apache import ApacheCheck
from pydebuprep.checks.nginx import NginxCheck
from pydebuprep.model import Severity
from pydebuprep.snapshot import build_snapshot

NGINX_FILES = {
    "/etc/nginx/nginx.conf": "load_module modules/ngx_stream_module.so;\n"
    "http { include /etc/nginx/sites-enabled/*; }\n",
    "/usr/lib/nginx/modules/ngx_stream_module.so": "",
    "/etc/nginx/sites-enabled/default": "server { listen 443 ssl; }\n",
}
NGINX_LINKS = {"/usr/share/nginx/modules": "../../lib/nginx/modules"}
APACHE_FILES = {
    "/etc/apache2/apache2.conf": "IncludeOptional mods-enabled/*.load\n"
    "IncludeOptional conf-enabled/*.conf\n",
    "/etc/apache2/mods-enabled/php8.2.load": "LoadModule php_module /usr/lib/apache2/modules/libphp8.2.so\n",
    "/etc/apache2/mods-enabled/ssl.load": "LoadModule ssl_module /usr/lib/apache2/modules/mod_ssl.so\n",
    "/etc/apache2/conf-enabled/php8.2-fpm.conf": "# FPM\n",
    "/usr/lib/apache2/modules/libphp8.2.so": "",
    "/usr/lib/apache2/modules/mod_ssl.so": "",
}


def now(**kw: list[str]) -> dict[str, list[str]]:
    return {"modules": [], "files": [], "listeners": [], **kw}


def test_unversioned() -> None:
    assert unversioned("libphp7.4.so") == unversioned("libphp8.2.so") == "libphp*.so"
    assert unversioned("php7.4.load") == unversioned("php8.3.load")
    assert unversioned("/etc/apache2/conf-enabled/php7.4-fpm.conf") == (
        "/etc/apache2/conf-enabled/php*-fpm.conf"
    )
    assert unversioned("php8") == "php*"
    assert unversioned("mod_ssl.so") == "mod_ssl.so"
    assert unversioned("graphql.conf") == "graphql.conf"


def test_php_upgrade_is_info_not_loss() -> None:
    before = {"modules": ["mod_ssl.so", "libphp7.4.so"], "files": ["/a/php7.4-fpm.conf"]}
    after = now(modules=["mod_ssl.so", "libphp8.2.so"], files=["/a/php8.2-fpm.conf"])
    [finding] = web_compare(make_ctx(), "Apache", "apache2.service", before, after)
    assert (finding.severity, finding.title) == (
        Severity.INFO,
        "Apache loads a new version of modules",
    )
    assert finding.evidence == ["libphp7.4.so → libphp8.2.so"]


def test_lost_module_is_warning() -> None:
    before = {"modules": ["mod_ssl.so", "libphp7.4.so", "ngx_stream_module.so"]}
    [finding] = web_compare(
        make_ctx(), "Apache", "apache2.service", before, now(modules=["mod_ssl.so"])
    )
    assert (finding.severity, finding.title) == (
        Severity.WARNING,
        "Apache no longer loads modules it loaded before the upgrade",
    )
    assert finding.evidence == ["libphp7.4.so", "ngx_stream_module.so"]


def test_lost_site_file_is_warning() -> None:
    before = {"files": ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/shop"]}
    [finding] = web_compare(
        make_ctx(), "nginx", "nginx.service", before, now(files=["/etc/nginx/nginx.conf"])
    )
    assert (finding.severity, finding.title) == (
        Severity.WARNING,
        "nginx no longer reads configuration files it read before the upgrade",
    )
    assert finding.evidence == ["/etc/nginx/sites-enabled/shop"]


def test_lost_listener_is_critical_as_root_only() -> None:
    before = {
        "modules": ["ngx_stream_module.so"],
        "files": ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/default"],
        "listeners": ["tcp/443", "tcp/80"],
    }
    ctx = listener_ctx(files=NGINX_FILES, links=NGINX_LINKS)
    [finding] = NginxCheck().compare(ctx, before)
    assert (finding.severity, finding.title) == (
        Severity.CRITICAL,
        "nginx listened on tcp/80 before the upgrade, not now",
    )
    assert (
        NginxCheck().compare(listener_ctx(files=NGINX_FILES, links=NGINX_LINKS, root=False), before)
        == []
    )


def test_collect_baseline_as_root_and_not() -> None:
    ctx = listener_ctx(files=NGINX_FILES, links=NGINX_LINKS)
    assert NginxCheck().collect_baseline(ctx) == {
        "modules": ["ngx_stream_module.so"],
        "files": ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/default"],
        "listeners": ["tcp/443"],
    }
    ctx = listener_ctx(files=NGINX_FILES, links=NGINX_LINKS, root=False)
    assert NginxCheck().collect_baseline(ctx)["listeners"] == []  # type: ignore[index] # a dict here
    stopped = listener_ctx(
        {"nginx.service": {"ActiveState": "inactive"}}, files=NGINX_FILES, links=NGINX_LINKS
    )
    assert NginxCheck().collect_baseline(stopped)["listeners"] == []  # type: ignore[index] # a dict here


def test_apache_baseline_and_compare() -> None:
    ctx = make_ctx(files=APACHE_FILES, root=False)
    baseline = ApacheCheck().collect_baseline(ctx)
    assert baseline == {
        "modules": ["libphp8.2.so", "mod_ssl.so"],
        "files": [
            "/etc/apache2/apache2.conf",
            "/etc/apache2/mods-enabled/php8.2.load",
            "/etc/apache2/mods-enabled/ssl.load",
            "/etc/apache2/conf-enabled/php8.2-fpm.conf",
        ],
        "listeners": [],
    }
    assert ApacheCheck().compare(ctx, baseline) == []


def test_not_installed_has_no_baseline() -> None:
    assert NginxCheck().collect_baseline(make_ctx()) is None
    assert ApacheCheck().collect_baseline(make_ctx()) is None


@pytest.mark.parametrize(
    "before",
    [None, [], "x", {"modules": "x"}, {"files": [1, None]}, {"listeners": {"a": 1}}],
)
def test_compare_ignores_malformed_baseline(before: Any) -> None:
    ctx = make_ctx(files={**APACHE_FILES, **NGINX_FILES}, links=NGINX_LINKS)
    assert ApacheCheck().compare(ctx, before) == []
    assert NginxCheck().compare(ctx, before) == []


def test_snapshot_round_trip() -> None:
    ctx = make_ctx(
        files={**NGINX_FILES, **APACHE_FILES}, links=NGINX_LINKS, root=False,
        commands={("uname", "-r"): "6.12.0-1-amd64\n"},
    )  # fmt: skip
    snapshot = build_snapshot([NginxCheck(), ApacheCheck()], ctx)
    assert set(snapshot["checks"]) == {"nginx", "apache"}
    assert titles(NginxCheck().compare(ctx, snapshot["checks"]["nginx"])) == []
