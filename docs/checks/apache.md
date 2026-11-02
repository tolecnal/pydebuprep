# apache — Apache configuration references

An upgrade can leave Apache's configuration pointing at things that are gone: a PHP
module's package is removed but its link in `mods-enabled` stays, its `.load` file
still loads a `libphp7.4.so` that no longer exists, or PHP-FPM moves to a new
version's socket. Apache won't start or reload with a missing include or module, and
requests to a missing socket fail with *503 Service Unavailable*.

<!-- facts: apache -->

## What it checks

Starting at `/etc/apache2/apache2.conf` and following every `Include` and
`IncludeOptional`:

- every included file exists. A missing file named by `IncludeOptional` is fine, and
  a pattern may match nothing; but each file a pattern matches must exist: a link
  whose target is gone is reported with where it points;
- every `LoadModule` file exists (relative paths start at `/etc/apache2`);
- every `unix:` socket exists, such as PHP-FPM's in
  `SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"` or one in
  `ProxyPass`. The evidence names the sockets that do exist in the same directory.
- no file in `sites-enabled/` or `conf-enabled/` is left out because its name doesn't
  end in `.conf` (Debian's `IncludeOptional sites-enabled/*.conf` skips it silently;
  names without `.conf` were common before Apache 2.4).

For TLS, following includes where they stand, so a directive belongs to the
`<VirtualHost>` it appears in:

- every `SSLCertificateFile` and `SSLCertificateChainFile` can be read and is valid:
  expired or not yet valid is critical, and so is expiring within
  `cert_critical_days` (14); within `cert_warning_days` (28) is a warning;
- no certificate has a key or signature that OpenSSL refuses at its default security
  level (RSA or DSA under 2048 bits, EC under 224 bits, MD5 or SHA-1 signatures);
- DH parameters (`SSLOpenSSLConfCmd DHParameters`, or appended to the certificate
  file) have at least 2048 bits;
- `SSLProtocol` enables TLSv1.2 or TLSv1.3 (older ones next to them, as in the stock
  `all -SSLv3`, are harmless and not reported);
- the certificate of each virtual host with `SSLEngine on` covers its `ServerName`
  and `ServerAlias` names.

As long as `tls_probe` is on (the default), it also connects to each TLS site on this
host, sending the site's first literal `ServerName` as SNI, and compares the certificate
served with the file the configuration names. A difference means the certificate was
renewed but Apache wasn't reloaded, so it still serves the old one. It connects only
where this host listens: a wildcard listen on loopback, a specific address only if the
kernel lists it as listening. At most 50 connections, 5 seconds each; the certificate
isn't verified, only compared. Apache logs each connection in its access log.

As root, unless `config_test` is off, it also runs `apache2ctl -t`, Apache's own check of the
whole configuration: syntax, directives modules no longer provide, and everything the
file checks above can't see.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | Apache includes files that don't exist | `sudo find /etc/apache2 -xtype l` lists broken links. Remove them with `a2dismod`, `a2disconf` or `a2dissite` (or reinstall the package), then `sudo systemctl reload apache2`. |
| critical | Apache loads modules that don't exist | Install the module's package for this release (for PHP, `libapache2-mod-phpX.Y` of the new version), or `sudo a2dismod` the old one. |
| warning | Apache passes requests to sockets that don't exist | Point the configuration at the socket that exists now (for PHP-FPM, `a2disconf php7.4-fpm` and `a2enconf php8.2-fpm`), or start the service that provides it. |
| warning | Apache ignores files in sites-enabled or conf-enabled | Rename the file in `sites-available` (or `conf-available`) to end in `.conf` and enable it again with `a2ensite` (`a2enconf`). |
| critical | Apache uses expired or not yet valid certificates | Renew the certificate, then `sudo systemctl reload apache2`. |
| critical | Apache has certificates expiring within 14 days | Renew it now; if it's renewed automatically, find out why that didn't happen (see the `certbot` check). |
| warning | Apache has certificates expiring within 28 days | As above: automatic renewals normally happen 30 days ahead. |
| critical | Apache names certificates that can't be read | Restore the file, or point `SSLCertificateFile` at the right one. |
| critical | Apache uses keys or signatures OpenSSL refuses | Issue a new certificate with a 2048-bit or larger RSA key, or an EC key. |
| critical | Apache uses DH parameters OpenSSL refuses | `openssl dhparam -out PATH 2048`. |
| critical | Apache enables only TLS protocols OpenSSL refuses | `SSLProtocol -all +TLSv1.2 +TLSv1.3` |
| warning | Apache has certificates that don't cover their server names | Add the names to the certificate, or remove them from `ServerName`/`ServerAlias`. |
| info | Apache's certificates were not checked (needs root) | Run as root. |
| warning | Apache serves different certificates than its configuration names | `sudo systemctl reload apache2`. |
| info | Apache: some TLS sites didn't answer the probe | The evidence says why; a site that doesn't answer on its address can't be compared. |
| critical | Apache rejects its configuration | The evidence has the errors; `sudo apache2ctl -t` shows the whole output. Fix them before Apache is restarted or reloaded. |
| info | Apache's configuration test gives warnings | Nothing breaks yet; deprecated directives may stop working in a later version. |
| info | Apache's configuration test needs root; not run | Run as root. |
| info | Apache's configuration test couldn't run | It timed out or failed to start; the detail says why. |

## Compared with a snapshot

The snapshot records the modules Apache loads, every configuration file it reads and,
as root, the TCP ports `apache2.service` listens on. After the upgrade:

| Severity | Finding | What to do |
|---|---|---|
| warning | Apache no longer loads modules it loaded before the upgrade | Install the module's package for this release and enable it again, or confirm it's no longer needed. |
| info | Apache loads a new version of modules | Expected after a release upgrade (`libphp7.4.so → libphp8.2.so`); check the sites that use it. |
| warning | Apache no longer reads configuration files it read before the upgrade | A site or setting is gone: enable it again, or confirm it's no longer needed. |
| critical | Apache listened on PORTS before the upgrade, not now | `systemctl status apache2.service` and `ss -tlpn`. |

A PHP version in a name doesn't count as a change of module or file: `php7.4.load`
replaced by `php8.3.load`, or `php7.4-fpm.conf` by `php8.2-fpm.conf`, is the same thing
in a new version.

## Commands it runs

It reads Apache's configuration files and looks up the paths they name.
Compared with a snapshot that recorded listening ports, as root, it also asks systemd
for the unit's control group, to find the ports its processes hold:

```sh
systemctl show --property=Id,Names,LoadState,ActiveState,SubState,UnitFileState,ConditionResult,ConditionTimestamp,TriggeredBy,Requires,BindsTo,ControlGroup -- apache2.service
```

As root, with `config_test` on (the default), it runs Apache's own configuration test:

```sh
apache2ctl -t
```

This is one of pydebuprep's [agreed side effects](../about/read-only.md#agreed-side-effects):
`apache2ctl -t` creates `/run/apache2` (with `socks` in it) and `/run/lock/apache2` if
they're missing, as Apache's own start-up would. Turn it off with `config_test: false`.

## Limitations

- Without root, or with `config_test` off, only paths are checked, not the syntax or
  the meaning of the configuration.
- Paths built from variables (`${APACHE_LOG_DIR}`) are left out, and so are sockets
  named in section tags such as `<Proxy "unix:...">`.
- Directives inside `<IfModule>` and `<IfDefine>` are checked whether or not they
  apply.
- Certificates are checked for themselves, not against a trust store: an incomplete
  chain or a revoked certificate isn't found. A virtual host without a port
  (`<VirtualHost *>`) isn't matched to its addresses.
- Skipped when Apache isn't installed (no `/etc/apache2/apache2.conf`).

<!-- options: apache -->
