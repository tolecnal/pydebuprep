# Limitations

pydebuprep reports what it can see from the system, quickly and without changing
anything. That sets its limits.

## It doesn't know your intentions

A service that stopped, a repository that was disabled, a package that was removed:
pydebuprep can see the change, not whether you wanted it. Comparisons with a
snapshot are questions, not verdicts. Silence what's expected through the
[configuration](../configuration/index.md).

## It mostly checks configuration and state, not function

- An **active** service is a running process, not a working service. A database can
  run and refuse queries; a web server can run and serve errors.
- A **configured** repository isn't necessarily a working one. pydebuprep checks
  keys, signatures and metadata from the last `apt update`, but never runs it, so
  whether a repository is reachable right now can't be known.
- A **loaded** firewall ruleset is counted, not judged.

What it does test, and what that proves:

| Test | Runs | What passing shows | What it doesn't show |
|---|---|---|---|
| `nginx -t`, `apache2ctl -t` | On by default, as root | The server would accept its configuration | That the sites work |
| [TLS probe](../checks/nginx.md) | On by default, nginx and Apache | This host's site serves the certificate its configuration names | That clients trust it: the chain and revocation aren't checked, and the connection stays on this host |
| Certificate checks | Always, from the files | Dates, key strength and that its names cover the site's | The same: no trust chain or revocation |
| PostgreSQL and MariaDB probes | Opt-in | The server answers `SELECT 1` | That every database or application query works |
| Docker probes | Opt-in | A published port answers, or a URL on localhost gives 2xx or 3xx | That the application behaves correctly |

Otherwise it doesn't test connectivity: no pings, no DNS lookups, and no connection to
any other host. The [check matrix](../checks/matrix.md) lists what each check looks at.

## It works from what's already on disk

Package checks use the package lists from the last `apt update`; if those are old,
so are the results. [`apt-lists-age`](../checks/apt-lists-age.md) tells you how old
they are.

## Coverage

- Supported: Debian 12–13 and Ubuntu 22.04–26.04. On other releases or
  derivatives, many checks work, but results may be incomplete and the
  [`os-release`](../checks/os-release.md) check reports it as unsupported.
- Some areas aren't covered (yet): Podman and LXD (their clients write on first use),
  snaps and Flatpaks, kernel command-line changes, RAID and SMART health. libvirt is
  checked from its files, without its client.
- Several checks need **root**; without it they're skipped.
- In **containers** without systemd, checks that need systemd are skipped; a
  container also shares the host's kernel, clock and firewall, so those checks say
  more about the host.

## Some checks take a long time

[`debsums`](../checks/debsums.md) reads every file of every installed package, which can
take many minutes on a large system or slow disks, especially on a cold cache. It runs
whenever `debsums` is installed, which pydebuprep's package recommends. It gives up
after `timeout_seconds` (600). Leave it out with `--skip debsums` when you're short of
time.

## Heuristics

Some checks judge by patterns: what counts as a "third-party" repository, which
cron jobs guard themselves, which interfaces are virtual, which log messages are
"the same". Each check's page lists its limitations; options let you adjust most of
them.
