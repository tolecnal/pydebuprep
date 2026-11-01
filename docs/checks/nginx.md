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

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | nginx includes files that don't exist | `sudo find /etc/nginx -xtype l` lists broken links. Remove the links whose package is gone (or reinstall the package), fix or remove includes of missing files, then `sudo systemctl reload nginx`. |
| critical | nginx loads modules that don't exist | Install the module's package for this release, or remove its link from `modules-enabled`. |
| warning | nginx passes requests to sockets that don't exist | Point the configuration at the socket that exists now (the evidence names those next to it), or start the service that provides it. |

## Commands it runs

None: it reads nginx's configuration files and looks up the paths they name.
`nginx -t` would check more, but it writes its PID file, cache directories and logs.

## Limitations

- Only paths are checked, not the syntax or the meaning of the configuration.
- Paths built from variables (`$document_root`) are left out; only nginx knows them.
- A socket can be missing because its service is stopped; `systemd-failed` and
  `systemd-critical-services` say whether it should be running.
- Skipped when nginx isn't installed (no `/etc/nginx/nginx.conf`).

<!-- options: nginx -->
