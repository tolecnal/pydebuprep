# Read-only by design

pydebuprep is usually run as root, on a production server, right after the most
disruptive thing that happens to it — a release upgrade. So the most important thing
about it is that it **changes nothing**. That's enforced at three levels.

## 1. It only runs allowlisted commands

Every external command goes through one function, which checks the **complete**
argument list against a built-in allowlist of read-only commands
(`ALLOWED_COMMANDS` in `src/pydebuprep/system.py`). Matching is exact: an extra
argument, however harmless it looks, is rejected. The few commands that take a
variable part (a systemd unit name) accept it only if it matches a strict pattern:
no leading `-`, no spaces or shell characters.

Commands are never run through a shell, and always with a timeout.

## 2. It avoids commands that write as a side effect

Some commands that look read-only aren't, and pydebuprep uses alternatives:

| Avoided | Why | Instead |
|---|---|---|
| `apt …` as plain | as root, apt takes locks, regenerates its binary caches, and writes its solver log | every apt command gets options that disable locking, the caches and the solver log |
| `ufw status` | writes a lock file | ufw's configuration plus the loaded rules |
| `postfix check` | creates missing directories | `postconf -n` |
| `nginx -t`, `apache2ctl -t` | write PID files, caches and logs | not used; a broken config shows as a failed unit |
| `docker …` with only `docker.socket` active | would start the daemon | the check is skipped unless `docker.service` runs |
| `nft list ruleset` without `nf_tables` loaded | would make the kernel load the module | rules are listed only for loaded modules |
| `needrestart` | can restart services | only its list mode (`-r l`) |
| `sqv --output -` | creates a file named `-` in the working directory | its output goes into pydebuprep's scratch directory |

Clock synchronisation is read from the kernel with a call that requests no changes,
rather than asking a daemon.

## 3. It's audited

Every pull request and release runs `scripts/readonly-audit.sh`: pydebuprep is run
as root under `strace`, with the services its checks inspect installed and running,
and the audit fails on:

- **any write by pydebuprep or a command it runs**: files opened for writing,
  created, deleted, renamed, re-permissioned; mounts, module loads, clock changes,
  signals to other processes. Even failed attempts to write UEFI variables count.
- **files changed anywhere** on the filesystem during the run (by timestamp),
  outside known background-service locations;
- **services started over D-Bus at the request of the run**, attributed by process
  ID, so indirect changes through daemons are caught too;
- **systemd starting, stopping or reloading anything** during the run (in the
  containers; on the shared CI virtual machines, whose own agents keep systemd busy,
  these are listed rather than failing the run);
- **commands that should have run but didn't**, so a check can't pass the audit by
  silently skipping its command.

This runs on every supported release, three ways: in plain containers, in
containers booted with systemd, and on Ubuntu virtual machines with real UEFI
firmware, systemd-resolved and Docker. A real regression was caught this way:
pydebuprep 0.3.0's simulated `apt-get autoremove` rewrote apt's solver log on hosts
with something to autoremove; 0.3.1 fixed it.

## What it does write

The hard rule: pydebuprep **never changes the system's state or any file the
operating system uses.** Within that, it writes only:

- **the snapshot file**, when you run `snapshot`;
- **the report file you asked for** with `--output` or `--output-dir` (never
  overwriting an existing file);
- **only when you use a [portal](../guide/portal.md)**: a report that failed to
  upload, in `/var/lib/pydebuprep/pending`, and a copy of a config fetched from a
  URL, in `/var/lib/pydebuprep/configs`. Both directories are created by the package
  (mode `0700`); pydebuprep writes files there (mode `0600`, under a temporary name
  renamed into place, never through a symlink) and creates no directories. A config
  from a URL can't move these paths;
- **temporary scratch files**, when a check needs a file to work with — for example
  to hand a signing key to `gpgv` in a form it can read. They go in a private
  directory of pydebuprep's own, created under `/tmp` with mode `0700` (files `0600`,
  never following symlinks), and the directory is removed before the check returns.
  Commands may write only into that directory, and the allowlist enforces it.

The audit holds pydebuprep to this: a scratch file that outlives the run, or a write
anywhere else, fails it. It also runs a report against a stand-in portal, once with
the portal up and once with it down, where writes outside `/var/lib/pydebuprep` fail
it the same way.

## What "read-only" can't cover

pydebuprep's own actions are what's guaranteed. Reading still has effects elsewhere
that no tool can avoid: the kernel updates access times (unless mounted `noatime`),
services you query may log the query, and systemd may load a unit's file into memory
to answer `systemctl show`. None of these change the system's configuration or
state.
