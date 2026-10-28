# pydebuprep — design

Date: 2026-10-28
Status: draft for approval

## 1. Intent

After a major release upgrade of Debian (12 → 13) or Ubuntu (22.04 → 24.04 → 26.04),
an admin wants one command that tells them whether the system landed cleanly, and
for anything that didn't, exactly what to run to fix it. Today this is a handful of
ad-hoc spot checks (`systemctl --failed`, `journalctl -b`, `apt update`); pydebuprep
turns the full post-upgrade checklist into a repeatable, read-only report.

Primary use: run by hand on a single host where the `.deb` is already installed.
Secondary use: run across a fleet via Ansible, with machine-readable output and
exit codes so a playbook can flag hosts without parsing text.

## 2. Goals

- One executable, `pydebuprep`, installed from a Debian package built to Debian
  packaging best practices.
- Optional pre-upgrade **snapshot**; post-upgrade **report** that compares against
  it when present.
- Report to STDOUT by default, or to a file whose name includes a timestamp.
- Five output formats (text, JSON, YAML, HTML, Markdown), all rendered from one
  in-memory data model so the structure is identical across formats.
- Modular checks: adding a check is adding one module.
- Every finding carries remediation instructions.

## 3. Non-goals (v1)

- Application/service-specific checks (PostgreSQL clusters, nginx/apache configtest,
  postfix, Docker/LXD, Python virtualenvs, mail/DNS/VPN). The plugin structure must
  make these easy to add later, but they are out of v1.
- Networking, firewall, time sync, AppArmor, unattended-upgrades, cron review —
  planned as the next check group, not v1.
- Off-host snapshot storage, central aggregation, a web UI.
- Running on non-Debian-family distros.

## 4. Anti-goals (failure even if it "works")

- **Making any change to the system.** No package operations, no `apt update`
  (it rewrites `/var/lib/apt/lists`), no `update-grub` (rewrites `grub.cfg`), no
  service restarts, no file writes other than (a) a snapshot file when the user runs
  `snapshot`, and (b) a report file when the user asks for one. Every external
  command executed must be on an explicit read-only allowlist (see §8).
- Format drift: a field present in JSON but missing from HTML, or ordering that
  differs between formats.
- Crashing when a tool is missing or the user isn't root. Missing tools/privileges
  produce a `skipped` result with a reason, never a traceback.
- Pulling in pip-only dependencies. The `.deb` must depend only on distro packages.

## 5. Constraints

- Platforms: Debian 12 (bookworm), Debian 13 (trixie), Ubuntu 22.04 (jammy),
  24.04 (noble), 26.04. Unknown Debian-family releases run with a warning.
- Python: **3.10 minimum** (oldest system Python among targets is jammy's 3.10).
  No syntax or stdlib APIs newer than 3.10 (e.g. no `tomllib` at runtime,
  no `datetime.UTC`, no `except*`, no PEP 695 generics).
- Runtime dependencies: Python stdlib + `python3-yaml` (PyYAML) only.
- Linting/quality: ruff (lint + format), flake8, mypy (strict-ish), all clean in CI.
  Target-version for ruff set to `py310`.
- Tests: pytest, runnable without root and without a Debian system (all command
  output is fed from fixtures).

## 6. CLI

```
pydebuprep report   [--format text|json|yaml|html|markdown]
                    [--output-dir DIR | --output FILE]
                    [--baseline FILE | --no-baseline]
                    [--checks ID,ID...] [--skip ID,ID...]
                    [--min-severity info|warning|critical]
                    [--no-color]
pydebuprep snapshot [--snapshot-dir DIR]
pydebuprep list-checks
pydebuprep --version
```

- `report` is also the default when no subcommand is given.
- `--output-dir DIR` writes `pydebuprep-<hostname>-<YYYYmmddTHHMMSSZ>.<ext>`
  (UTC, filesystem-safe) into DIR. `--output FILE` is accepted too; if FILE exists,
  the timestamp is inserted before the extension rather than overwriting.
  (Builder's call: `--output FILE` behaviour; requirement is "never overwrite".)
- Text output is colorised only when STDOUT is a TTY and `--no-color` isn't set.

### Exit codes (for Ansible)

| Code | Meaning |
|------|---------|
| 0 | No findings at warning or above |
| 1 | Highest finding is `warning` |
| 2 | At least one `critical` finding |
| 3 | Tool error (bad args, unreadable baseline, etc.) |

Skipped checks do not affect the exit code.

## 7. Snapshot

- `pydebuprep snapshot` writes JSON to `/var/lib/pydebuprep/snapshots/<timestamp>.json`
  (dir created mode 0750 if missing; requires root unless `--snapshot-dir` given).
  The `.deb` ships the directory.
- Contents: schema version, timestamp, hostname, os-release fields, running kernel,
  installed kernel packages, active + enabled systemd units, timers, APT sources
  (files, enabled/disabled state, suites/components, URIs), held packages, installed
  packages with version and origin, mounts/fstab entries, DKMS status.
- Each check that has something to compare implements an optional
  `collect_baseline()` producing its slice; the snapshot is the union keyed by check
  ID. So a new check can add baseline data without touching snapshot code.
- `report` picks the newest snapshot automatically unless `--baseline FILE` or
  `--no-baseline`. A snapshot whose OS version equals the current one is used but
  flagged ("baseline appears to be post-upgrade").
- Without a baseline, every comparison section renders as "no baseline" — the
  structure is unchanged.

## 8. Architecture

```
src/pydebuprep/
  __init__.py          version
  __main__.py          python -m pydebuprep
  cli.py               argparse, dispatch, exit codes
  model.py             dataclasses: Report, CheckResult, Finding, Severity, Status
  runner.py            discovers checks, runs them, isolates exceptions
  system.py            read-only command execution + file reading (the only place
                       subprocess is used), allowlist, timeouts, root detection
  osinfo.py            parse /etc/os-release, map to supported release table
  snapshot.py          create/load/select snapshots
  checks/
    __init__.py        registry
    base.py            Check base class
    <one module per check>
  render/
    __init__.py        format → renderer
    text.py json_.py yaml_.py html.py markdown.py
```

### Check interface

```python
class Check:
    id: str                 # stable, kebab-case, e.g. "apt-sources"
    title: str
    category: str           # "packages" | "boot" | "services" | "storage" | ...
    requires_root: bool
    requires_commands: tuple[str, ...]

    def run(self, ctx: Context) -> CheckResult: ...
    def collect_baseline(self, ctx: Context) -> dict | None: ...   # optional
    def compare(self, ctx: Context, baseline: dict) -> list[Finding]: ...  # optional
```

`Context` gives access to `system` (command runner), `osinfo`, `baseline` (or None),
and `is_root`. Checks never call `subprocess` directly; `system.run()` enforces the
allowlist and a per-command timeout (default 30 s) and never uses a shell.

Registry: explicit list in `checks/__init__.py` (simple, greppable, no entry-point
magic). Runner catches any exception from a check and records it as status
`error` with the message, so one broken check never kills the report.

### Data model (the single source of truth for every format)

```
Report
  schema_version: "1"
  tool: {name, version}
  generated_at: ISO-8601 UTC
  host: {hostname, os_id, os_version, codename, kernel, is_root}
  baseline: {path, created_at, os_version} | null
  summary: {critical, warning, info, ok, skipped, error, exit_code}
  results: [CheckResult]          # ordered by category, then check id

CheckResult
  id, title, category
  status: ok | findings | skipped | error
  skipped_reason / error: str | null
  findings: [Finding]
  baseline_diff: [Finding] | null   # null = no baseline; [] = baseline, no changes

Finding
  severity: critical | warning | info
  title: str                       # one line
  detail: str                      # what was observed
  evidence: [str]                  # raw lines (truncated to N with "... (+k more)")
  remediation: [str]               # human steps / commands to run; never executed
  references: [str]                # URLs (e.g. release notes)
```

Renderers take a `Report` and produce a string; JSON/YAML are a direct
`dataclasses.asdict` dump with stable key order. Text/HTML/Markdown walk the same
tree in the same order: header → summary → results grouped by category → per check:
status, findings (severity-sorted), baseline diff. HTML is a single self-contained
file (inline CSS, no JS, no external assets).

## 9. v1 checks

All read-only. "Root" = needs root for full results; without it → skipped or partial
with a note.

### Release / packages

| ID | Does | Severity rules (builder may refine) |
|----|------|---|
| `os-release` | Parse `/etc/os-release`; confirm supported release; baseline diff shows from→to | critical if unsupported/unknown codename; info shows upgrade path |
| `apt-sources` | Parse `/etc/apt/sources.list`, `sources.list.d/*.list` and deb822 `*.sources`; flag suites not matching current codename (incl. `-updates`, `-security`, `-backports`), disabled third-party repos (`.distUpgrade`, `.save`, `.disabled`, `Enabled: no`, commented-out lines added by the upgrader), duplicates. Does **not** run `apt update`. | warning for mismatched/disabled; info for duplicates |
| `apt-lists-age` | Report age of `/var/lib/apt/lists` so the user knows how fresh "upgradable" data is; suggest `apt update` in remediation | info |
| `dpkg-audit` | `dpkg --audit`, `apt-get check` | critical on any output |
| `apt-upgradable` | `apt list --upgradable` (from cached lists) | warning |
| `apt-held` | `apt-mark showhold`; diff vs baseline | warning |
| `apt-autoremove` | `apt-get -s autoremove` (simulate only) | info |
| `dpkg-rc` | packages in `rc` state | info |
| `obsolete-packages` | installed packages with no candidate from any configured repo, or local-only versions (`apt-cache policy` / `apt list --installed` origin parsing) | warning |
| `config-conflicts` | `*.dpkg-new/-old/-dist/-bak`, `*.ucf-new/-old/-dist` under `/etc`; highlight sshd_config, sudoers, etc. | warning; critical for sshd/sudoers |
| `debsums` | `debsums -c` if installed (root) | warning; skipped if not installed with remediation "apt install debsums" |

### Kernel / boot

| ID | Does | Severity |
|----|------|---|
| `kernel-running` | `uname -r` vs newest installed `linux-image-*`; `/var/run/reboot-required` (+ `.pkgs`) | critical if running kernel older than newest installed, or reboot-required present |
| `needrestart` | `needrestart -b -r l` (list only, batch) if installed | warning per stale service; skipped if missing |
| `dkms` | `dkms status`; modules not built for running kernel | critical |
| `bootloader` | GRUB: `grub.cfg` references running/newest kernel (read file only). UEFI: `efibootmgr -v` lists entries and BootCurrent is sane. | warning |
| `boot-space` | free space/inodes on `/boot` and ESP (`/boot/efi`) | critical < 10 %, warning < 25 % (builder's call on exact thresholds) |

### Services / logs

| ID | Does | Severity |
|----|------|---|
| `systemd-failed` | `systemctl list-units --state=failed`; baseline diff of active/enabled units | critical per failed unit; warning for units active before but not now |
| `systemd-timers` | `systemctl list-timers --all`; baseline diff | warning for missing timers |
| `journal-errors` | `journalctl -p err -b --no-pager -o short` (root or `adm`/`systemd-journal` group); dedupe and count | warning; evidence truncated |
| `dmesg-errors` | `dmesg --level=err,warn` (root) | info/warning |
| `boot-time` | `systemd-analyze` + top of `blame` | info |

### Storage

| ID | Does | Severity |
|----|------|---|
| `fstab` | `findmnt --verify` | critical on errors |
| `disk-space` | `df` / `df -i` on all real filesystems, emphasise `/`, `/var` | same thresholds as boot-space |

Each finding's `remediation` gives concrete commands (e.g.
`sudo sed -i 's/bookworm/trixie/' /etc/apt/sources.list.d/foo.list` is too risky to
suggest blindly — prefer "edit /etc/apt/sources.list.d/foo.list: change suite
`bookworm` → `trixie`, then run `sudo apt update`"). Commands in remediation are
text only.

### Release data

A small table in `osinfo.py` maps codename → version, family, previous release,
release-notes URL:
bookworm 12, trixie 13, jammy 22.04, noble 24.04, resolute 26.04. Used for suite
checks and `references`.

## 10. Packaging

- `pyproject.toml` (setuptools backend; build-deps available in all targets),
  `src/` layout, console-script entry point `pydebuprep = pydebuprep.cli:main`.
- `debian/` built with `dh $@ --with python3 --buildsystem=pybuild`:
  `control` (Source/Package `pydebuprep`, `Architecture: all`,
  `Depends: ${python3:Depends}, ${misc:Depends}, python3-yaml`,
  `Recommends: debsums, needrestart`, `Suggests: efibootmgr`),
  `rules`, `changelog`, `copyright` (DEP-5), Maintainer
  `Jostein Elvaker Haande <jehaande@gmail.com>` (from git config), `source/format` = `3.0 (native)`
  initially (builder's call; switch to quilt if upstream tarballs are released),
  `pydebuprep.dirs` for `/var/lib/pydebuprep/snapshots`, `watch` omitted while native.
- Man page `pydebuprep.1` (hand-written or from `argparse` via a small script),
  installed with `dh_installman`.
- Must build cleanly with `dpkg-buildpackage -us -uc` and pass `lintian` with no
  errors/warnings on bookworm and noble. One `.deb` (arch all) installs on all five
  targets.
- Run tests during build (`pybuild` + pytest) unless `nocheck`.

## 11. Ansible usage (documented, not shipped as a role in v1)

README example playbook: pre-task `pydebuprep snapshot`; upgrade; reboot;
`pydebuprep report --format json --output-dir /var/tmp` with
`failed_when: rc == 3`, `changed_when: false`; register rc to flag hosts;
`fetch` the JSON back.

## 12. Repo hygiene

- `README.md`, `LICENSE`: MIT (user wants a permissive license allowing any use including
commercial, with no warranty/liability; `debian/copyright` uses `Expat`, the DEP-5
name for MIT),
  `.gitignore`, `pyproject.toml` holding ruff/mypy/pytest config, `.flake8`
  (flake8 doesn't read pyproject), `Makefile` targets: `lint`, `test`, `deb`.
- GitHub Actions CI: lint + tests on Python 3.10–3.13; build `.deb` in
  `debian:bookworm` and `ubuntu:noble` containers and run lintian.

## 13. Left to the builder

- Exact text of findings and remediation, evidence truncation limits.
- Exact severity thresholds where marked.
- Internal helper structure, test fixture layout.
- HTML styling (clean, readable, printable; supports dark mode via `prefers-color-scheme`).
