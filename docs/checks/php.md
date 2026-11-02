# php — PHP extensions

A release upgrade moves PHP to a new version (7.4 → 8.2, 8.2 → 8.4), and every PHP
extension is a package of its own for each version: `php7.4-mysql`, `php8.2-mysql`.
The new version gets only the extensions something asked for, so a site that worked
before the upgrade fails after it with *Call to undefined function mysqli_connect()*.

<!-- facts: php -->

## What it checks

By itself, nothing: there is no "right" set of extensions to compare with. It needs
a [snapshot](../guide/snapshots.md) taken before the upgrade.

## Findings

Both come from comparing with a snapshot:

| Severity | Finding | What to do |
|---|---|---|
| warning | PHP extensions enabled before the upgrade aren't enabled now | Install them for the new version; the finding names the packages, for example `sudo apt install php8.2-intl php8.2-mysql`. Then restart PHP-FPM or reload the web server. |
| warning | PHP fpm (or apache2, cli) is no longer installed for any PHP version | `sudo apt install php-fpm` (`libapache2-mod-php`, `php-cli`). |

## Compared with a snapshot

The snapshot records, for each installed PHP version and each SAPI (`fpm`, `apache2`,
`cli`), the extensions its `conf.d/*.ini` files enable (`extension=` and
`zend_extension=`). After the upgrade, each SAPI is compared across versions: an
extension enabled for `fpm` in PHP 7.4 must be enabled for `fpm` in the newest PHP
installed now, when that's newer than any version in the snapshot (the old version's
packages stay installed until `apt autoremove`, but aren't what runs). Without a newer
version, any installed version that enables it will do.

Extensions that became part of PHP itself have no ini file of their own any more and
aren't missing: `json` from PHP 8.0 on.

## Commands it runs

None: it reads the ini files under `/etc/php`.

## Limitations

- Extensions loaded some other way (a `php_admin_value` in a pool or virtual host, or
  compiled in) aren't seen.
- Package names are a best guess: most extensions are `phpX.Y-NAME`; `mysqli` and
  `pdo_mysql` come from `phpX.Y-mysql`, `pdo_pgsql` from `phpX.Y-pgsql`, `pdo_sqlite`
  from `phpX.Y-sqlite3`. PECL extensions aren't packaged by Debian at all.
- Skipped when PHP isn't installed (no `/etc/php`).

<!-- options: php -->
