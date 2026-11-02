# nginx — nginx configuration references

An upgrade can leave nginx's configuration pointing at things that are gone: a
module's package is removed but its link in `modules-enabled` stays, or PHP moves
from 7.4 to 8.2 and a site still sends requests to `php7.4-fpm.sock`. nginx won't
start or reload with a missing include or module, and requests to a missing socket
fail with *502 Bad Gateway*.

<!-- facts: nginx -->

## What it checks

Starting at `/etc/nginx/nginx.conf` and following every `include`:

- every included file exists. A pattern such as `sites-enabled/*` may match nothing,
  but each file it matches must exist: a link whose target is gone is reported with
  where it points;
- every `load_module` file exists (relative paths start at `/usr/share/nginx`);
- every `unix:` socket in a `*_pass` directive (`fastcgi_pass`, `proxy_pass`,
  `uwsgi_pass`, ...) or an upstream's `server` line exists. The evidence names the
  sockets that do exist in the same directory, which is often the fix.

For TLS, following includes where they stand, so a certificate in a snippet belongs to
the `server` block that includes it:

- every `ssl_certificate` can be read and is valid: expired or not yet valid is
  critical, and so is expiring within `cert_critical_days` (14); within
  `cert_warning_days` (28) is a warning;
- no certificate has a key or signature that OpenSSL refuses at its default security
  level (RSA or DSA under 2048 bits, EC under 224 bits, MD5 or SHA-1 signatures): nginx
  can't load it;
- `ssl_dhparam` files have at least 2048 bits;
- `ssl_protocols` enables TLSv1.2 or TLSv1.3: OpenSSL no longer negotiates the older
  ones;
- the certificate of each TLS `server` block covers its `server_name`s (wildcards
  cover one label; names that are regular expressions, wildcards or `_` are skipped).

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | nginx includes files that don't exist | `sudo find /etc/nginx -xtype l` lists broken links. Remove the links whose package is gone (or reinstall the package), fix or remove includes of missing files, then `sudo systemctl reload nginx`. |
| critical | nginx loads modules that don't exist | Install the module's package for this release, or remove its link from `modules-enabled`. |
| warning | nginx passes requests to sockets that don't exist | Point the configuration at the socket that exists now (the evidence names those next to it), or start the service that provides it. |
| critical | nginx uses expired or not yet valid certificates | Renew the certificate, then `sudo systemctl reload nginx`. |
| critical | nginx has certificates expiring within 14 days | Renew it now; if it's renewed automatically, find out why that didn't happen (see the `certbot` check). |
| warning | nginx has certificates expiring within 28 days | As above: automatic renewals normally happen 30 days ahead. |
| critical | nginx names certificates that can't be read | Restore the file, or point `ssl_certificate` at the right one. |
| critical | nginx uses keys or signatures OpenSSL refuses | Issue a new certificate with a 2048-bit or larger RSA key, or an EC key. |
| critical | nginx uses DH parameters OpenSSL refuses | `openssl dhparam -out PATH 2048`, or remove `ssl_dhparam`. |
| critical | nginx enables only TLS protocols OpenSSL refuses | `ssl_protocols TLSv1.2 TLSv1.3;` |
| warning | nginx enables TLS protocols OpenSSL refuses | Remove the old protocols from `ssl_protocols`; they're refused anyway. |
| warning | nginx has certificates that don't cover their server names | Add the names to the certificate, or remove them from `server_name`. |
| info | nginx's certificates were not checked (needs root) | Run as root. |

## Compared with a snapshot

The snapshot records the modules nginx loads, every configuration file it reads and,
as root, the TCP ports `nginx.service` listens on. After the upgrade:

| Severity | Finding | What to do |
|---|---|---|
| warning | nginx no longer loads modules it loaded before the upgrade | Install the module's package for this release and enable it again, or confirm it's no longer needed. |
| info | nginx loads a new version of modules | Expected after a release upgrade (`libphp7.4.so → libphp8.2.so`); check the sites that use it. |
| warning | nginx no longer reads configuration files it read before the upgrade | A site or setting is gone: enable it again, or confirm it's no longer needed. |
| critical | nginx listened on PORTS before the upgrade, not now | `systemctl status nginx.service` and `ss -tlpn`. |

A PHP version in a name doesn't count as a change of module or file: `php7.4.load`
replaced by `php8.3.load`, or `php7.4-fpm.conf` by `php8.2-fpm.conf`, is the same thing
in a new version.

## Commands it runs

It reads nginx's configuration files and looks up the paths they name.
Compared with a snapshot that recorded listening ports, as root, it also asks systemd
for the unit's control group, to find the ports its processes hold:

```sh
systemctl show --property=Id,Names,LoadState,ActiveState,SubState,UnitFileState,ConditionResult,ConditionTimestamp,TriggeredBy,Requires,BindsTo,ControlGroup -- nginx.service
```

`nginx -t` would check more, but it writes its PID file, cache directories and logs.

## Limitations

- Only paths are checked, not the syntax or the meaning of the configuration.
- Paths built from variables (`$document_root`, `$ssl_server_name.crt`) and inline
  certificates (`data:`) are left out; only nginx knows them.
- Certificates are checked for themselves, not against a trust store: an incomplete
  chain or a revoked certificate isn't found.
- A socket can be missing because its service is stopped; `systemd-failed` and
  `systemd-critical-services` say whether it should be running.
- Skipped when nginx isn't installed (no `/etc/nginx/nginx.conf`).

<!-- options: nginx -->
