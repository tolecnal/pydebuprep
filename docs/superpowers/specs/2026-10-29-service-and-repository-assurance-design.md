# Service and repository assurance: design

Date: 2026-10-29. Status: agreed in conversation, waiting for the owner's approval.

## Why

pydebuprep reports what a Debian or Ubuntu release upgrade left broken. Today several
checks stop at "is it there and running": a failed unit, a stopped cluster, an unhealthy
container. A release upgrade can do subtler damage without any package-manager error:

- change a unit's enablement, mask it, rename it or drop a dependency;
- leave a repository that looks right in its source file but fails signature or
  metadata checks;
- leave a database whose process runs but doesn't answer;
- leave packages in states that need different fixes.

This round makes those visible, each with its own finding and remediation.

Guiding rule from the owner: **an active unit or a running process is evidence of
process state, not proof of application health.** Findings say which level of
assurance they establish, and different levels are reported separately, never folded
into one healthy/unhealthy verdict.

## Constraints (unchanged from the project)

- Read-only: pydebuprep never changes the system and only prints remediation.
  - Every new command gets its complete argv in `ALLOWED_COMMANDS` (`system.py`).
  - Variable operands are validated by pattern, as `UNIT_QUERIES` does today.
  - Every new command must pass `scripts/readonly-audit.sh` and be added to
    `scripts/ci-readonly-audit.sh` (and its `AUDIT_EXPECT`), so CI keeps exercising it.
  - A command that fails the audit is dropped, not worked around.
- **Probes that talk to a service** (databases, container ports) are **opt-in, off by
  default**. The owner accepts that an enabled probe makes the service log the
  connection or update its own statistics; pydebuprep itself still writes nothing.
  Probes connect only over Unix sockets or to localhost.
- Options are typed `Option`s with scalar or list values only (no dicts); anything
  map-like is a list of `key=value` strings.
- 100% line and branch coverage. Docs stay in sync (README checks/options tables, man
  page CHECKS, `make generated`; `tests/test_docs.py` and
  `tests/test_option_coverage.py` enforce it).
- No new runtime dependencies (stdlib + optional PyYAML).

## Build order

Each part is its own branch and pull request, built and merged in this order:

1. `systemd-critical-services` (new check);
2. `apt-sources`: repository usability;
3. readiness probes: `postgresql`, `mariadb` (gains MySQL), `docker`;
4. smaller improvements: `apt-upgradable`, `obsolete-packages`, `dpkg-audit`,
   `python-venvs`.

## 1. `systemd-critical-services` (category: services)

Validates the expected state of designated critical units.

**Unit list.**

- Built-in list: `ssh.service`, `cron.service`, `systemd-journald.service`, and the
  installed time-sync service (`systemd-timesyncd.service`, `chrony.service` or
  `ntpsec.service`).
  - Built-in units apply only where the unit exists (LoadState not `not-found`).
  - `ssh.service` is resolved through its alias (`sshd.service`) as systemd reports it.
- Options:
  - `required_active` (list): units that must be running, or socket-activated with a
    listening socket.
  - `required_enabled` (list): units that must be enabled.
  - `builtin` (bool, default true): include the built-in list (it counts as both
    required-active and required-enabled).
  - `ignore_units` (list, shell-style patterns, as in `systemd-failed`).
- Configured units add to the built-in list. A configured unit that doesn't exist is a
  finding.

**How it reads state.** One `systemctl show` call for all units, with properties:

- `Id`, `LoadState`, `ActiveState`, `SubState`, `UnitFileState`;
- `TriggeredBy`, `Requires`, `BindsTo`;
- `Names` (aliases).

The allowlist gains a form with a fixed property list and one or more unit operands
validated by `UNIT_NAME` (an extension of `UNIT_QUERIES` to several operands). A second
call reads the same properties for trigger and dependency units that need them.

**Findings from the configuration.**

| State | Severity | Remediation (examples) |
|---|---|---|
| not found (configured unit) | critical | `systemctl list-unit-files 'NAME*'` (the upgrade may have renamed it) |
| masked | critical | `sudo systemctl unmask UNIT` |
| failed | critical | `systemctl status UNIT`, `journalctl -u UNIT -b` |
| inactive, should be active, no listening trigger socket | critical | `sudo systemctl start UNIT` |
| activating, deactivating or reloading | warning | look again |
| inactive, but a `TriggeredBy` socket is active (listening) | no finding | (socket-activated: fine) |
| socket-activated and its socket isn't listening | critical | `sudo systemctl start SOCKET` |
| should be enabled; `UnitFileState` disabled | warning | `sudo systemctl enable UNIT` |
| running, but a `Requires=` or `BindsTo=` unit is inactive or failed | warning | `systemctl list-dependencies UNIT` |

- `enabled`, `enabled-runtime`, `static`, `indirect`, `generated` and `alias` satisfy
  `required_enabled`. A static or generated unit can't be enabled, so it isn't held to
  it.
- A socket-activated service satisfies `required_enabled` if its socket is enabled.
- Detail text on any "active" result says it shows process state, not application
  health.

**Findings against the snapshot** (reported separately, titled "…before the upgrade").

The snapshot stores, per unit in the effective list plus every enabled service:

- LoadState, ActiveState, UnitFileState;
- for critical units, the listening TCP/UDP ports.

Compare reports:

- units that became masked or not-found;
- listeners a critical unit had and has lost ("nginx.service listened on tcp/443
  before the upgrade, not now").

Listening ports are found by reading `/proc/net/{tcp,tcp6,udp,udp6}` (LISTEN or bound
sockets) and matching socket inodes to `/proc/<pid>/fd` links of the unit's processes.
The processes come from `/sys/fs/cgroup/<ControlGroup>/cgroup.procs`, using the
`ControlGroup` property. This needs root; without it the listener part is skipped with
a note.

**`systemd-failed`** is unchanged: it stays about failed units, so the same problem
isn't reported twice. Its snapshot comparison already reports services that were
enabled or active before the upgrade and aren't now, so the new check's comparison
leaves enablement to it and adds only masked, not-found and lost listeners (builder's
call, to avoid double reporting).

## 2. `apt-sources`: repository usability

Extends the existing check, which already parses one-line and deb822 sources. Findings:

- **Missing key** (critical): `Signed-By` names a keyring file that doesn't exist or
  can't be read. Inline keys are fine.
- **Legacy keyring** (warning): the source has no `Signed-By`, and keys exist in
  `/etc/apt/trusted.gpg` (or there is no matching key at all). apt 3 deprecates that
  keyring.
- **Suite mismatch** (warning): the downloaded `InRelease`/`Release` for the source (in
  `/var/lib/apt/lists`, file names derived from URI + suite as apt does) declares a
  `Codename`/`Suite` that matches neither the configured suite nor its base (for
  example `trixie` for `trixie-updates`).
- **No metadata** (warning): a configured, enabled source with no `InRelease` or
  `Release` file locally; its last `apt update` probably failed (signature or network).
- **Expired metadata** (warning): `Valid-Until` in the past.
- **Signature** (critical): `InRelease` does not verify against the source's keyring.
  - Run `sqv` (where installed: Debian 13, newer Ubuntu) or `gpgv` with the keyring
    and the `InRelease` file as operands.
  - The allowlist accepts only absolute paths under `/etc/apt/`, `/usr/share/keyrings/`
    and `/var/lib/apt/lists/`, with no `..`.
  - The owner's condition: **only if it passes the read-only audit.** If `gpgv` or `sqv`
    writes anything (a homedir, trustdb or lock), drop signature verification and keep
    the rest.
- **Missing security repository** (warning): on Debian or Ubuntu, no enabled source
  for `<codename>-security` from the distribution's security archive.

Every finding that depends on local metadata says that live usability can't be
verified without `apt update`, which pydebuprep never runs.

## 3. Readiness probes (opt-in)

Each check gets `probe` (bool, default **false**) and `credentials_file` (string,
default empty). Defaults come first; the credentials file is used only when set. Each
level of assurance is its own finding or evidence line. Probes run only as root;
otherwise they are skipped with a note.

**`postgresql`.** For each cluster `pg_lsclusters` reports online:

- `pg_isready -h /var/run/postgresql -p PORT`: accepting / rejecting / no response.
- `SELECT 1` on database `postgres`: `runuser -u postgres -- psql -X -A -t -w -h
  /var/run/postgresql -p PORT -d postgres -c 'SELECT 1'` (peer authentication, never
  prompts).
  - With `credentials_file` (a `.pgpass`), the user is taken from that file and
    `PGPASSFILE` is set.
- `PORT` is validated as digits only; the rest of the argv is fixed.

**`mariadb`** (title becomes "MariaDB/MySQL"). It also recognises Oracle MySQL
(`mysqld`, `mysqladmin`, `mysql`) for the probe; the upgrade-info comparison stays
MariaDB-only.

- `mariadb-admin ping` / `mysqladmin ping`: alive or not.
- `SELECT 1` against `information_schema`: `mariadb -N -B -e 'SELECT 1'
  information_schema` (or `mysql …`), as root over the Unix socket.
- With `credentials_file`, the probe adds `--defaults-extra-file=FILE` (absolute path,
  validated).
- "Access denied" is an info finding pointing at `credentials_file`, not a failure of
  the server.

**`docker`.** Per container, reported separately:

1. running: process state (`State`);
2. health check: passing / failing / starting / none defined (none is not a problem);
3. probe (only with `probe: true`):
   - a TCP connect from Python, timeout 3 s, to each port published on the host;
     wildcard bindings are probed on 127.0.0.1;
   - optional `http_probes` (list of `container=url` strings, localhost URLs only):
     an HTTP GET, where 2xx/3xx passes.

Containers that exited with code 0 still count as fine. `ignore_containers` (patterns)
leaves containers out.

## 4. Smaller improvements

- **`apt-upgradable`**: three groups:
  - security (suite ends `-security`): warning;
  - ordinary: info;
  - held back: from `apt-get -s upgrade` (with `APT_RO_OPTS`), "kept back" and on
    Ubuntu "deferred due to phasing". Phasing is called out as expected.
- **`obsolete-packages`**: origin of each installed version, read from the apt lists
  `*_Packages` files (plain or gzip; others mean "origin unknown").
  - Reports third-party packages grouped by origin host.
  - The snapshot stores the origin per package; compare reports origins that changed
    (vendor → distribution or the reverse).
- **`dpkg-audit`**: separate findings, each with its own fix:
  - unpacked / half-configured → `dpkg --configure -a`;
  - half-installed / reinstall-required → `apt-get install --reinstall PKG`;
  - triggers-awaited / pending → `dpkg --triggers-only -a`.
- **`python-venvs`**:
  - broken entry points: `bin/*` scripts whose shebang interpreter is missing;
  - missing native libraries: `DT_NEEDED` entries of compiled extensions, read by a
    small ELF parser in Python, that resolve nowhere in `/etc/ld.so.cache` or the
    standard library directories. Never `ldd`, which can execute code.

## Audit coverage for probes

`scripts/ci-readonly-audit.sh` writes an `/etc/pydebuprep.conf` that enables every
probe (and starts a container that publishes a port, where Docker runs) before the
audit, so CI exercises `pg_isready`, `psql`, `mariadb-admin`/`mysqladmin` and
`mariadb`/`mysql`, and they go into `AUDIT_EXPECT` (builder's call).

## Non-goals and anti-goals

- No `apt update`, no service restarts, no writes: remediation is text only.
- No probe runs unless enabled.
- No probe reaches beyond localhost.
- Don't flag inactive units in general: many healthy units are inactive by design.
- Don't report the same problem twice (`systemd-failed` against
  `systemd-critical-services`).
- Don't call anything "healthy" that only shows a process exists.

## Left to the builder

- Exact finding titles and wording, in the style of the existing checks.
- Grouping thresholds, like `systemd-failed`'s `GROUP_ABOVE`.
- How apt list file names are derived from URIs.
- Exact ELF parsing scope (64- and 32-bit little-endian; others are skipped).
- Where the shared `/proc` socket-to-process helper lives.
- Whether the parts need extra tests beyond the ones coverage requires.
