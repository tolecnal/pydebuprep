"""nginx and apache: what their configuration points at, read from the files only."""

from __future__ import annotations

import pytest

from checks.helpers import make_ctx, titles
from pydebuprep.checks.apache import ApacheCheck
from pydebuprep.checks.base import CheckSkipped
from pydebuprep.checks.nginx import NginxCheck
from pydebuprep.model import Severity

# --- nginx -----------------------------------------------------------------------------

NGINX_CONF = """\
user www-data;
include /etc/nginx/modules-enabled/*.conf;  # modules
events { worker_connections 768; }
http {
    include mime.types;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
"""
SITE = """\
upstream app { server unix:/run/app/gunicorn.sock; server 127.0.0.1:8001; }
server {
    listen 80;
    location ~ \\.php$ { fastcgi_pass unix:/run/php/php8.2-fpm.sock; }
    location /app { proxy_pass http://unix:/run/app/web.sock:/; }
    location /x { set $s /run/x.sock; fastcgi_pass unix:$s; }
}
"""
GEOIP = "load_module modules/ngx_http_geoip_module.so;\n"


def nginx_ctx(files: dict[str, str] | None = None, links: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
    base = {
        "/etc/nginx/nginx.conf": NGINX_CONF,
        "/etc/nginx/mime.types": "types { text/html html; }\n",
        "/etc/nginx/sites-available/default": SITE,
        "/usr/share/nginx/modules-available/mod-http-geoip.conf": GEOIP,
        "/usr/lib/nginx/modules/ngx_http_geoip_module.so": "",
        "/run/php/php8.2-fpm.sock": "",
        "/run/app/gunicorn.sock": "",
        "/run/app/web.sock": "",
    }
    base_links = {
        "/etc/nginx/sites-enabled/default": "/etc/nginx/sites-available/default",
        "/etc/nginx/modules-enabled/50-mod-http-geoip.conf":
            "/usr/share/nginx/modules-available/mod-http-geoip.conf",
        "/usr/share/nginx/modules": "../../lib/nginx/modules",
    }  # fmt: skip
    base.update(files or {})
    base_links.update(links or {})
    return make_ctx(files={k: v for k, v in base.items() if v is not None}, links=base_links)


def test_nginx_skipped_when_not_installed() -> None:
    with pytest.raises(CheckSkipped, match="nginx is not installed"):
        NginxCheck().run(make_ctx())


def test_nginx_healthy_configuration() -> None:
    assert NginxCheck().run(nginx_ctx()) == []


def test_nginx_dangling_module_link_is_critical() -> None:
    # The module's package was removed by the upgrade; its link in modules-enabled stays.
    ctx = nginx_ctx(files={"/usr/share/nginx/modules-available/mod-http-geoip.conf": None})
    (f,) = NginxCheck().run(ctx)
    assert (f.severity, f.title) == (Severity.CRITICAL, "nginx includes files that don't exist")
    assert f.evidence == [
        "/etc/nginx/modules-enabled/50-mod-http-geoip.conf: a link to "
        "/usr/share/nginx/modules-available/mod-http-geoip.conf, which doesn't exist "
        "(include /etc/nginx/modules-enabled/*.conf in /etc/nginx/nginx.conf)"
    ]
    assert any("find /etc/nginx -xtype l" in r for r in f.remediation)


def test_nginx_missing_plain_include_is_critical() -> None:
    (f,) = NginxCheck().run(nginx_ctx(files={"/etc/nginx/mime.types": None}))
    assert f.severity == Severity.CRITICAL
    assert f.evidence == [
        "/etc/nginx/mime.types doesn't exist (include mime.types in /etc/nginx/nginx.conf)"
    ]


def test_nginx_missing_module_is_critical() -> None:
    ctx = nginx_ctx(files={"/usr/lib/nginx/modules/ngx_http_geoip_module.so": None})
    (f,) = NginxCheck().run(ctx)
    assert (f.severity, f.title) == (Severity.CRITICAL, "nginx loads modules that don't exist")
    assert f.evidence == [
        "/usr/share/nginx/modules/ngx_http_geoip_module.so doesn't exist (load_module "
        "modules/ngx_http_geoip_module.so in "
        "/etc/nginx/modules-enabled/50-mod-http-geoip.conf)"
    ]


def test_nginx_missing_socket_is_a_warning_naming_the_ones_there() -> None:
    # PHP moved from 7.4 to 8.2, the site still points at the old socket.
    site = SITE.replace("php8.2-fpm.sock", "php7.4-fpm.sock")
    ctx = nginx_ctx(files={"/etc/nginx/sites-available/default": site})
    (f,) = NginxCheck().run(ctx)
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "nginx passes requests to sockets that don't exist",
    )
    assert f.evidence == [
        "/run/php/php7.4-fpm.sock (fastcgi_pass in /etc/nginx/sites-enabled/default); "
        "/run/php has php8.2-fpm.sock"
    ]


def test_nginx_proxy_and_upstream_sockets_are_checked() -> None:
    ctx = nginx_ctx(files={"/run/app/gunicorn.sock": None, "/run/app/web.sock": None})
    (f,) = NginxCheck().run(ctx)
    assert f.evidence == [
        "/run/app/gunicorn.sock (server in /etc/nginx/sites-enabled/default)",
        "/run/app/web.sock (proxy_pass in /etc/nginx/sites-enabled/default)",
    ]


def test_nginx_follows_nested_includes_once() -> None:
    files = {
        "/etc/nginx/conf.d/a.conf": "include /etc/nginx/snippets/x.conf;\ninclude conf.d/a.conf;\n",
        "/etc/nginx/snippets/x.conf": "fastcgi_pass unix:/run/gone.sock;\n",
    }
    (f,) = NginxCheck().run(nginx_ctx(files=files))
    assert f.evidence == ["/run/gone.sock (fastcgi_pass in /etc/nginx/snippets/x.conf)"]


def test_nginx_quoted_arguments_and_comments() -> None:
    files = {"/etc/nginx/conf.d/q.conf": '# include /etc/nginx/nope.conf;\ninclude "q2.conf";\n'}
    (f,) = NginxCheck().run(nginx_ctx(files=files))
    assert f.evidence == [
        "/etc/nginx/q2.conf doesn't exist (include q2.conf in /etc/nginx/conf.d/q.conf)"
    ]


def test_nginx_all_three_findings_together() -> None:
    ctx = nginx_ctx(
        files={
            "/etc/nginx/mime.types": None,
            "/usr/lib/nginx/modules/ngx_http_geoip_module.so": None,
            "/run/app/web.sock": None,
        }
    )
    assert titles(NginxCheck().run(ctx)) == [
        "nginx includes files that don't exist",
        "nginx loads modules that don't exist",
        "nginx passes requests to sockets that don't exist",
    ]


# --- apache ----------------------------------------------------------------------------

APACHE_CONF = """\
# Debian's apache2.conf, shortened
DefaultRuntimeDir ${APACHE_RUN_DIR}
Include ports.conf
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf
IncludeOptional conf-enabled/*.conf
IncludeOptional sites-enabled/*.conf
IncludeOptional local-overrides.conf
ErrorLog ${APACHE_LOG_DIR}/error.log
"""
PHP_FPM = """\
<FilesMatch ".+\\.php$">
    SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"
</FilesMatch>
"""
APP_SITE = """\
<VirtualHost *:80>
    ProxyPass "/app" \\
        "unix:/run/app/web.sock|http://localhost/"
    proxypassreverse "/app" "unix:/run/app/web.sock|http://localhost/"
</VirtualHost>
"""


def apache_ctx(files: dict[str, str | None] | None = None, links: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
    base: dict[str, str | None] = {
        "/etc/apache2/apache2.conf": APACHE_CONF,
        "/etc/apache2/ports.conf": "Listen 80\n",
        "/etc/apache2/mods-available/rewrite.load":
            "LoadModule rewrite_module /usr/lib/apache2/modules/mod_rewrite.so\n",
        "/usr/lib/apache2/modules/mod_rewrite.so": "",
        "/etc/apache2/conf-available/php8.2-fpm.conf": PHP_FPM,
        "/etc/apache2/sites-available/app.conf": APP_SITE,
        "/run/php/php8.2-fpm.sock": "",
        "/run/app/web.sock": "",
    }  # fmt: skip
    base_links = {
        "/etc/apache2/mods-enabled/rewrite.load": "../mods-available/rewrite.load",
        "/etc/apache2/conf-enabled/php8.2-fpm.conf": "../conf-available/php8.2-fpm.conf",
        "/etc/apache2/sites-enabled/app.conf": "../sites-available/app.conf",
    }
    base.update(files or {})
    base_links.update(links or {})
    return make_ctx(files={k: v for k, v in base.items() if v is not None}, links=base_links)


def test_apache_skipped_when_not_installed() -> None:
    with pytest.raises(CheckSkipped, match="Apache is not installed"):
        ApacheCheck().run(make_ctx())


def test_apache_healthy_configuration() -> None:
    assert ApacheCheck().run(apache_ctx()) == []


def test_apache_dangling_module_link_is_critical() -> None:
    # libapache2-mod-php7.4 was purged; its link in mods-enabled stays.
    ctx = apache_ctx(
        links={"/etc/apache2/mods-enabled/php7.4.load": "../mods-available/php7.4.load"}
    )
    (f,) = ApacheCheck().run(ctx)
    assert (f.severity, f.title) == (Severity.CRITICAL, "Apache includes files that don't exist")
    assert f.evidence == [
        "/etc/apache2/mods-enabled/php7.4.load: a link to ../mods-available/php7.4.load, "
        "which doesn't exist (IncludeOptional mods-enabled/*.load in /etc/apache2/apache2.conf)"
    ]
    assert "sudo systemctl reload apache2" in f.remediation[-1]


def test_apache_missing_module_is_critical() -> None:
    # libapache2-mod-php7.4 was removed but not purged: its .load file stays, the .so not.
    files = {
        "/etc/apache2/mods-available/php7.4.load":
            "LoadModule php7_module /usr/lib/apache2/modules/libphp7.4.so\n",
    }  # fmt: skip
    links = {"/etc/apache2/mods-enabled/php7.4.load": "../mods-available/php7.4.load"}
    (f,) = ApacheCheck().run(apache_ctx(files=files, links=links))
    assert (f.severity, f.title) == (Severity.CRITICAL, "Apache loads modules that don't exist")
    assert f.evidence == [
        "/usr/lib/apache2/modules/libphp7.4.so doesn't exist (LoadModule php7_module in "
        "/etc/apache2/mods-enabled/php7.4.load)"
    ]


def test_apache_include_must_exist_include_optional_need_not() -> None:
    (f,) = ApacheCheck().run(apache_ctx(files={"/etc/apache2/ports.conf": None}))
    assert f.evidence == [
        "/etc/apache2/ports.conf doesn't exist (Include ports.conf in /etc/apache2/apache2.conf)"
    ]


def test_apache_missing_php_fpm_socket_names_the_one_there() -> None:
    php = PHP_FPM.replace("php8.2", "php7.4")
    ctx = apache_ctx(files={"/etc/apache2/conf-available/php8.2-fpm.conf": php})
    (f,) = ApacheCheck().run(ctx)
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "Apache passes requests to sockets that don't exist",
    )
    assert f.evidence == [
        "/run/php/php7.4-fpm.sock (SetHandler in /etc/apache2/conf-enabled/php8.2-fpm.conf); "
        "/run/php has php8.2-fpm.sock"
    ]


def test_apache_continued_lines_and_any_case_once_per_socket() -> None:
    (f,) = ApacheCheck().run(apache_ctx(files={"/run/app/web.sock": None}))
    assert f.evidence == ["/run/app/web.sock (ProxyPass in /etc/apache2/sites-enabled/app.conf)"]


def test_nginx_last_directive_without_semicolon_still_counts() -> None:
    files = {"/etc/nginx/conf.d/cut.conf": "include missing.conf"}
    (f,) = NginxCheck().run(nginx_ctx(files=files))
    assert f.evidence == [
        "/etc/nginx/missing.conf doesn't exist (include missing.conf in /etc/nginx/conf.d/cut.conf)"
    ]


def test_apache_reads_a_file_included_twice_once() -> None:
    conf = APACHE_CONF + "Include ports.conf\n"
    ctx = apache_ctx(files={"/etc/apache2/apache2.conf": conf, "/run/app/web.sock": None})
    (f,) = ApacheCheck().run(ctx)
    assert len(f.evidence) == 1
