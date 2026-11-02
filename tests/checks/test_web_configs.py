"""nginx and apache: what their configuration points at, read from the files only."""

from __future__ import annotations

import pytest

from checks.helpers import make_ctx, titles, tls_fixture
from pydebuprep.checks._tls import TlsSite
from pydebuprep.checks.apache import ApacheCheck
from pydebuprep.checks.apache import read_config as apache_read_config
from pydebuprep.checks.base import CheckSkipped
from pydebuprep.checks.nginx import NginxCheck
from pydebuprep.checks.nginx import read_config as nginx_read_config
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


# --- nginx: TLS --------------------------------------------------------------------------

TLS_SITE = """\
server {
    listen 443 ssl;
    listen [::]:443 ssl http2;
    listen 80;
    server_name www.example.org example.org;
    include snippets/cert.conf;
}
"""


def nginx_tls_ctx(files: dict[str, str | bytes | None] | None = None, **kw):  # type: ignore[no-untyped-def] # test helper
    base: dict[str, str | bytes | None] = {
        "/etc/nginx/sites-available/tls": TLS_SITE,
        "/etc/nginx/snippets/cert.conf": "ssl_certificate /etc/ssl/good.pem;\n"
        "ssl_certificate_key /etc/ssl/private/good.key;\n",
        "/etc/ssl/good.pem": tls_fixture("good.pem"),
    }
    base.update(files or {})
    links = {
        "/etc/nginx/sites-enabled/tls": "/etc/nginx/sites-available/tls",
        **kw.pop("links", {}),
    }
    return nginx_ctx(files=base, links=links)  # type: ignore[arg-type] # bytes files are fine


def test_existing_nginx_findings_unchanged() -> None:
    # The TLS site adds nothing to a healthy configuration.
    assert NginxCheck().run(nginx_tls_ctx()) == []


def test_server_block_collects_tls_site() -> None:
    cfg = nginx_read_config(nginx_tls_ctx())
    assert cfg.sites == [
        TlsSite(
            source="/etc/nginx/sites-enabled/tls",
            names=("www.example.org", "example.org"),
            certificate="/etc/ssl/good.pem",
            listen=(("", 443), ("[::]", 443)),
        )
    ]
    assert cfg.certificates == [
        ("/etc/ssl/good.pem", "(ssl_certificate in /etc/nginx/snippets/cert.conf)")
    ]
    assert "/etc/nginx/snippets/cert.conf" in cfg.files


def test_listen_forms() -> None:
    site = """server { listen 10.0.0.1:8443 ssl; listen *:443 ssl; listen 192.0.2.1 ssl;
        listen unix:/run/x.sock ssl; listen localhost:9443 ssl default_server;
        ssl_certificate /etc/ssl/good.pem; }
        server { listen 8443; ssl on; ssl_certificate /etc/ssl/good.pem; }
        server { listen 8080; ssl_certificate /etc/ssl/good.pem; }
    """
    cfg = nginx_read_config(nginx_tls_ctx({"/etc/nginx/sites-available/tls": site}))
    assert [s.listen for s in cfg.sites] == [
        (("10.0.0.1", 8443), ("", 443), ("192.0.2.1", 80), ("localhost", 9443)),
        (("", 8443),),
    ]
    assert cfg.sites[0].names == ()


def test_http_level_certificate_is_inherited() -> None:
    conf = NGINX_CONF.replace("http {", "http {\n    ssl_certificate /etc/ssl/good.pem;")
    site = "server { listen 443 ssl; server_name a.example.net; }\n"
    cfg = nginx_read_config(
        nginx_tls_ctx({"/etc/nginx/nginx.conf": conf, "/etc/nginx/sites-available/tls": site})
    )
    assert [(s.names, s.certificate) for s in cfg.sites] == [
        (("a.example.net",), "/etc/ssl/good.pem")
    ]


def test_tls_server_without_any_certificate_is_no_site() -> None:
    site = "server { listen 443 ssl; server_name a.example.net; }\n"
    assert nginx_read_config(nginx_tls_ctx({"/etc/nginx/sites-available/tls": site})).sites == []


def test_snippet_in_two_servers_reported_once() -> None:
    site = TLS_SITE + TLS_SITE.replace("www.example.org example.org", "crit.example.org")
    files = {
        "/etc/nginx/sites-available/tls": site,
        "/etc/nginx/snippets/cert.conf": "ssl_certificate /etc/ssl/crit.pem;\n",
        "/etc/ssl/crit.pem": tls_fixture("critical.pem"),
    }
    ctx = nginx_tls_ctx(files)
    assert len(nginx_read_config(ctx).sites) == 2
    found = NginxCheck().run(ctx)
    expiring = next(f for f in found if "within 14 days" in f.title)
    assert len(expiring.evidence) == 1


def test_variable_and_data_certificates_skipped() -> None:
    files = {
        "/etc/nginx/snippets/cert.conf": "ssl_certificate $ssl_server_name.crt;\n"
        "ssl_certificate data:$cert;\nssl_certificate engine:pkcs11:x;\n",
    }
    ctx = nginx_tls_ctx(files)
    cfg = nginx_read_config(ctx)
    assert cfg.certificates == [] and cfg.sites == []
    assert NginxCheck().run(ctx) == []


def test_nginx_reports_expiry_crypto_dhparam_protocols_names() -> None:
    conf = NGINX_CONF.replace(
        "http {", "http {\n    ssl_protocols TLSv1 TLSv1.1;\n    ssl_dhparam /etc/ssl/dh.pem;"
    )
    site = TLS_SITE.replace("www.example.org example.org", "other.org") + (
        "server { listen 8443 ssl; ssl_certificate /etc/ssl/weak.pem; ssl_certificate /etc/ssl/soon.pem; }\n"
    )
    files = {
        "/etc/nginx/nginx.conf": conf,
        "/etc/nginx/sites-available/tls": site,
        "/etc/ssl/dh.pem": tls_fixture("dh1024.pem"),
        "/etc/ssl/weak.pem": tls_fixture("weak-rsa.pem"),
        "/etc/ssl/soon.pem": tls_fixture("soon.pem"),
    }
    found = NginxCheck().run(nginx_tls_ctx(files))
    assert titles(found) == [
        "nginx has certificates expiring within 28 days",
        "nginx uses keys or signatures OpenSSL refuses",
        "nginx uses DH parameters OpenSSL refuses",
        "nginx enables only TLS protocols OpenSSL refuses",
        "nginx has certificates that don't cover their server names",
    ]
    assert found[1].evidence == [
        "/etc/ssl/weak.pem: RSA 1024 bits (ssl_certificate in /etc/nginx/sites-enabled/tls)"
    ]


def test_nginx_cert_options() -> None:
    with pytest.raises(ValueError, match="cert_critical_days"):
        NginxCheck({"cert_critical_days": 30})
    files = {"/etc/ssl/good.pem": tls_fixture("soon.pem")}
    found = NginxCheck({"cert_warning_days": 20, "cert_critical_days": 10}).run(
        nginx_tls_ctx(files)
    )
    assert not [t for t in titles(found) if "expiring" in t]  # 22 days left


def test_nginx_odd_statements_are_ignored() -> None:
    # Empty statements, a directive without arguments, a listen port that isn't a number
    # and a certificate outside http (the mail module's) name no TLS site.
    conf = NGINX_CONF + "mail { ssl_certificate /etc/ssl/mail.pem; }\n"
    site = "server { ;; http2; listen 127.0.0.1:https ssl; ssl_certificate /etc/ssl/good.pem; }\n"
    ctx = nginx_tls_ctx({"/etc/nginx/nginx.conf": conf, "/etc/nginx/sites-available/tls": site})
    cfg = nginx_read_config(ctx)
    assert cfg.sites == []
    assert ("/etc/ssl/mail.pem", "(ssl_certificate in /etc/nginx/nginx.conf)") in cfg.certificates


# --- apache: TLS -------------------------------------------------------------------------

SSL_SITE = """\
<IfModule mod_ssl.c>
<VirtualHost *:443 [::]:443>
    ServerName www.example.org:443
    ServerAlias example.org a.example.net
    SSLEngine on
    SSLCertificateFile /etc/ssl/good.pem
    SSLCertificateKeyFile /etc/ssl/private/good.key
</VirtualHost>
</IfModule>
"""


def apache_tls_ctx(
    files: dict[str, str | bytes | None] | None = None, links: dict[str, str] | None = None
):  # type: ignore[no-untyped-def] # test helper
    base: dict[str, str | bytes | None] = {
        "/etc/apache2/sites-available/ssl.conf": SSL_SITE,
        "/etc/ssl/good.pem": tls_fixture("good.pem"),
    }
    base.update(files or {})
    return apache_ctx(
        files=base,  # type: ignore[arg-type] # bytes files are fine
        links={
            "/etc/apache2/sites-enabled/ssl.conf": "../sites-available/ssl.conf",
            **(links or {}),
        },
    )


def test_existing_apache_findings_unchanged() -> None:
    assert ApacheCheck().run(apache_tls_ctx()) == []


def test_virtualhost_collects_tls_site() -> None:
    cfg = apache_read_config(apache_tls_ctx())
    assert cfg.sites == [
        TlsSite(
            source="/etc/apache2/sites-enabled/ssl.conf",
            names=("www.example.org", "example.org", "a.example.net"),
            certificate="/etc/ssl/good.pem",
            listen=(("", 443), ("[::]", 443)),
        )
    ]
    assert cfg.listens == [("", 80)]
    assert cfg.certificates == [
        ("/etc/ssl/good.pem", "(SSLCertificateFile in /etc/apache2/sites-enabled/ssl.conf)")
    ]


def test_virtualhost_forms() -> None:
    site = """\
<VirtualHost _default_:8443 10.0.0.1:443 *>
    SSLEngine On
    SSLCertificateFile ssl/good.pem
</VirtualHost>
<VirtualHost *:80>
    ServerName plain.example.org
    SSLCertificateFile /etc/ssl/good.pem
</VirtualHost>
<VirtualHost *:443>
    SSLEngine on
</VirtualHost>
SSLCertificateFile /etc/ssl/global.pem
SSLCertificateFile ${CERT}
Listen 0.0.0.0:443 https
Listen [::]:8443
"""
    cfg = apache_read_config(apache_tls_ctx({"/etc/apache2/sites-available/ssl.conf": site}))
    assert [(s.listen, s.certificate) for s in cfg.sites] == [
        ((("", 8443), ("10.0.0.1", 443)), "/etc/apache2/ssl/good.pem"),
    ]
    assert [p for p, _ in cfg.certificates] == [
        "/etc/apache2/ssl/good.pem", "/etc/ssl/good.pem", "/etc/ssl/global.pem",
    ]  # fmt: skip
    assert cfg.listens == [("", 80), ("0.0.0.0", 443), ("[::]", 8443)]


def test_apache_reports_tls_findings() -> None:
    site = SSL_SITE.replace(
        "ServerAlias example.org a.example.net", "ServerAlias other.org"
    ).replace(
        "SSLEngine on",
        "SSLEngine on\n    SSLProtocol TLSv1 TLSv1.1\n"
        "    SSLOpenSSLConfCmd DHParameters /etc/ssl/dh.pem\n"
        "    SSLCertificateChainFile /etc/ssl/chain-sha1.pem",
    )
    files = {
        "/etc/apache2/sites-available/ssl.conf": site,
        "/etc/ssl/dh.pem": tls_fixture("dh1024.pem"),
        "/etc/ssl/chain-sha1.pem": tls_fixture("sha1.pem"),
    }
    found = ApacheCheck().run(apache_tls_ctx(files))
    assert titles(found) == [
        "Apache uses keys or signatures OpenSSL refuses",
        "Apache uses DH parameters OpenSSL refuses",
        "Apache enables only TLS protocols OpenSSL refuses",
        "Apache has certificates that don't cover their server names",
    ]
    assert found[-1].evidence == [
        "other.org isn't covered by /etc/ssl/good.pem (/etc/apache2/sites-enabled/ssl.conf)"
    ]


def test_apache_dh_parameters_in_the_certificate_file() -> None:
    files = {"/etc/ssl/good.pem": tls_fixture("good.pem") + tls_fixture("dh1024.pem")}
    [finding] = ApacheCheck().run(apache_tls_ctx(files))
    assert finding.title == "Apache uses DH parameters OpenSSL refuses"


def test_apache_cert_options() -> None:
    with pytest.raises(ValueError, match="cert_critical_days"):
        ApacheCheck({"cert_warning_days": 10, "cert_critical_days": 10})
    files = {"/etc/ssl/good.pem": tls_fixture("soon.pem")}
    ctx = apache_tls_ctx(files)
    assert "Apache has certificates expiring within 28 days" in titles(ApacheCheck().run(ctx))
    found = ApacheCheck({"cert_warning_days": 20, "cert_critical_days": 10}).run(ctx)
    assert not [t for t in titles(found) if "expiring" in t]


def test_files_without_conf_are_skipped_and_reported() -> None:
    files = {
        "/etc/apache2/sites-available/old-site": "<VirtualHost *:80>\nProxyPass / unix:/run/gone.sock|http://x/\n</VirtualHost>\n",
        "/etc/apache2/conf-available/legacy": "Alias /x /srv/x\n",
    }
    links = {
        "/etc/apache2/sites-enabled/old-site": "../sites-available/old-site",
        "/etc/apache2/conf-enabled/legacy": "../conf-available/legacy",
    }
    [finding] = ApacheCheck().run(apache_tls_ctx(files, links))
    assert (finding.severity, finding.title) == (
        Severity.WARNING,
        "Apache ignores files in sites-enabled or conf-enabled",
    )
    assert finding.evidence == [
        "/etc/apache2/conf-enabled/legacy",
        "/etc/apache2/sites-enabled/old-site",
    ]
    assert any("a2dissite" in r or ".conf" in r for r in finding.remediation)


def test_files_without_conf_read_by_a_wider_include_are_fine() -> None:
    conf = APACHE_CONF.replace("sites-enabled/*.conf", "sites-enabled/*")
    files = {
        "/etc/apache2/apache2.conf": conf,
        "/etc/apache2/sites-available/old-site": "ServerName x\n",
    }
    links = {"/etc/apache2/sites-enabled/old-site": "../sites-available/old-site"}
    assert ApacheCheck().run(apache_tls_ctx(files, links)) == []


def test_apache_include_loops_end() -> None:
    files = {"/etc/apache2/conf-available/loop.conf": "Include conf-enabled/loop.conf\n"}
    links = {"/etc/apache2/conf-enabled/loop.conf": "../conf-available/loop.conf"}
    ctx = apache_tls_ctx(files, links)
    assert ApacheCheck().run(ctx) == []
    assert apache_read_config(ctx).files.count("/etc/apache2/conf-enabled/loop.conf") == 1
