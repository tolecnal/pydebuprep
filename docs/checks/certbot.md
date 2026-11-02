# certbot — certbot renewals

certbot renews certificates weeks after an upgrade, with whatever the upgrade left
behind. A DNS plugin installed with `pip` belongs to the Python it was installed for,
and a certbot installed into its own virtualenv stops working when the Python that
virtualenv was built on is replaced. Either way the renewal fails quietly and the
certificate expires.

<!-- facts: certbot -->

## What it checks

For every renewal configuration in `/etc/letsencrypt/renewal/*.conf`:

- certbot is still installed (`/usr/bin/certbot` or `/usr/local/bin/certbot`), and
  the Python its `#!` line names exists. For a certbot in a virtualenv, the Python
  the virtualenv was made with (`home` and `version` in its `pyvenv.cfg`) must exist
  too;
- the renewal's `authenticator` and `installer` plugins are installed for that Python:
  each needs a package whose `entry_points.txt` registers it under
  `[certbot.plugins]`, in `/usr/lib/python3/dist-packages`,
  the `/usr/local/lib/pythonX.Y/dist-packages` of the Python certbot runs now (one
  left behind for the old Python doesn't count), or the virtualenv's `site-packages`.
  `standalone`, `webroot`, `manual` and `null` are part of certbot;
- its certificate (the renewal's `cert`, by default `live/NAME/cert.pem`) isn't close
  to expiring. certbot renews 30 days ahead, so a certificate within
  `cert_warning_days` (28) of expiring means renewals are failing.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | certbot renewals are configured but certbot isn't installed | `sudo apt install certbot`, then `sudo certbot renew --dry-run`. |
| critical | certbot's Python interpreter is missing | Reinstall certbot (`sudo apt install --reinstall certbot`), or recreate its virtualenv with the current Python. |
| critical | certbot renewals use plugins that aren't installed | Install the plugin for this release, such as `python3-certbot-dns-cloudflare` or `python3-certbot-nginx`, then `sudo certbot renew --dry-run`. |
| critical | certbot uses expired or not yet valid certificates | `sudo certbot renew`, and find out why the renewal failed (`/var/log/letsencrypt/letsencrypt.log`). |
| critical | certbot has certificates expiring within 14 days | As above. |
| warning | certbot has certificates expiring within 28 days | As above. |
| critical | certbot names certificates that can't be read | Restore the files, or remove the renewal configuration of a certificate that's no longer used. |
| info | certbot is a snap; its plugins aren't checked | Snap plugins are snaps connected to certbot's; `snap connections certbot` lists them. |
| info | certbot's certificates were not checked (needs root) | Run as root: `/etc/letsencrypt/live` is readable by root only. |

## Commands it runs

None: certbot is never run (`certbot renew --dry-run` contacts the ACME server and
writes logs). It reads certbot's renewal configurations, its `#!` line and Python's
package metadata.

## Limitations

- Only the plugin names are checked, not whether a plugin works (its credentials, or
  the DNS provider's API).
- Plugins of a snap certbot aren't checked.
- The renewal timer is the `systemd-timers` check's: it reports a `certbot.timer` that
  stopped being scheduled.
- Skipped when there are no renewal configurations.

<!-- options: certbot -->
