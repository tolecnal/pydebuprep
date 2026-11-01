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

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | Apache includes files that don't exist | `sudo find /etc/apache2 -xtype l` lists broken links. Remove them with `a2dismod`, `a2disconf` or `a2dissite` (or reinstall the package), then `sudo systemctl reload apache2`. |
| critical | Apache loads modules that don't exist | Install the module's package for this release (for PHP, `libapache2-mod-phpX.Y` of the new version), or `sudo a2dismod` the old one. |
| warning | Apache passes requests to sockets that don't exist | Point the configuration at the socket that exists now (for PHP-FPM, `a2disconf php7.4-fpm` and `a2enconf php8.2-fpm`), or start the service that provides it. |

## Commands it runs

None: it reads Apache's configuration files and looks up the paths they name.
`apachectl -t` would check more, but it creates run and lock directories.

## Limitations

- Only paths are checked, not the syntax or the meaning of the configuration.
- Paths built from variables (`${APACHE_LOG_DIR}`) are left out, and so are sockets
  named in section tags such as `<Proxy "unix:...">`.
- Directives inside `<IfModule>` and `<IfDefine>` are checked whether or not they
  apply.
- Skipped when Apache isn't installed (no `/etc/apache2/apache2.conf`).

<!-- options: apache -->
