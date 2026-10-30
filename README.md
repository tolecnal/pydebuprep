# pydebuprep

[![Latest release](https://img.shields.io/github/v/release/tolecnal/pydebuprep?sort=semver)](https://github.com/tolecnal/pydebuprep/releases/latest)
[![CI](https://github.com/tolecnal/pydebuprep/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tolecnal/pydebuprep/actions/workflows/ci.yml)
[![Security](https://github.com/tolecnal/pydebuprep/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/tolecnal/pydebuprep/actions/workflows/security.yml)
[![CodeQL](https://github.com/tolecnal/pydebuprep/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/tolecnal/pydebuprep/actions/workflows/codeql.yml)
[![Release build](https://github.com/tolecnal/pydebuprep/actions/workflows/release.yml/badge.svg?event=push)](https://github.com/tolecnal/pydebuprep/actions/workflows/release.yml)
[![Downloads](https://img.shields.io/github/downloads/tolecnal/pydebuprep/total)](https://github.com/tolecnal/pydebuprep/releases)
[![Documentation](https://img.shields.io/badge/docs-pydebuprep.app-526CFE?logo=materialformkdocs&logoColor=white)](https://pydebuprep.app/)

[![Coverage: 100% (enforced)](https://img.shields.io/badge/coverage-100%25%20(enforced)-brightgreen)](pyproject.toml)
[![Python 3.10–3.14](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.14-3776AB?logo=python&logoColor=white)](setup.cfg)
[![Debian 12 | 13](https://img.shields.io/badge/Debian-12%20%7C%2013-A81D33?logo=debian&logoColor=white)](#supported-systems)
[![Ubuntu 22.04 | 24.04 | 26.04](https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04%20%7C%2026.04-E95420?logo=ubuntu&logoColor=white)](#supported-systems)
[![License: MIT](https://img.shields.io/github/license/tolecnal/pydebuprep)](LICENSE)
[![Build provenance: attested](https://img.shields.io/badge/build%20provenance-attested-2EA44F?logo=github)](#releases)
[![Dependabot](https://img.shields.io/badge/dependabot-enabled-025E8C?logo=dependabot&logoColor=white)](.github/dependabot.yml)

A read-only health report for Debian and Ubuntu systems after a release upgrade
(Debian 12 → 13, Ubuntu 22.04 → 24.04 → 26.04, and minor upgrades too).

**Documentation: <https://pydebuprep.app/>** — a page per check
(what it looks at, what it reports, its limits), the configuration reference, and
guides.

`systemctl --failed` and a look at `journalctl` catch some problems. pydebuprep
runs the rest of the post-upgrade checklist in one go, with [37 checks](#checks):

- **packages:** APT sources still pointing at the old release, third-party
  repositories the upgrader disabled, half-configured packages, unmerged
  `*.dpkg-dist` configs, packages no repository provides any more;
- **boot and services:** a pending reboot, DKMS modules that didn't rebuild, a
  `grub.cfg` without the new kernel, failed units, missing timers, cron jobs whose
  program is gone, an unsynchronised clock;
- **applications:** PostgreSQL clusters still on the old version, MariaDB data not
  upgraded, postfix and BIND configuration errors, unhealthy Docker containers,
  virtualenvs whose Python is gone;
- **network and security:** no default route or DNS, firewall rules that didn't
  load, AppArmor disabled or denying, an SSH configuration that would lock you out
  on restart, unattended-upgrades still pointed at the old release;
- **storage:** a bad `fstab`, a filling `/boot`, `/` or `/var`.

With a snapshot taken before the upgrade, it also reports what changed: services,
network interfaces and routes, firewall rules, containers and database clusters that
were up before and aren't now.

**It never changes anything.** It doesn't install or remove packages, doesn't run
`apt update` or `update-grub`, and doesn't restart services. Every external command
it runs is checked against a built-in allowlist of read-only commands, and every
release is traced with strace on each supported release to prove a root run changes
nothing. Each finding comes with the commands to fix it, for you to review and run
yourself.

## Supported systems

Debian 12 (bookworm), Debian 13 (trixie), Ubuntu 22.04 (jammy), 24.04 (noble) and
26.04 (resolute). Python 3.10 or newer; the only dependency is `python3-yaml`, which
apt installs with the package. (Without it, pydebuprep still runs; only the config
file, `--format yaml` and `configtest` need it, and they say how to install it.)

## Install

Download the latest release, check it, and install it with apt (which also installs
`python3-yaml`):

```sh
gh release download -R tolecnal/pydebuprep --pattern '*.deb' --pattern SHA256SUMS
sha256sum -c SHA256SUMS
gh attestation verify pydebuprep_*_all.deb -R tolecnal/pydebuprep
sudo apt install ./pydebuprep_*_all.deb
```

Without the GitHub CLI, download a specific version and skip the attestation check:

```sh
VERSION=0.3.1
wget https://github.com/tolecnal/pydebuprep/releases/download/v$VERSION/pydebuprep_${VERSION}_all.deb \
     https://github.com/tolecnal/pydebuprep/releases/download/v$VERSION/SHA256SUMS
sha256sum -c SHA256SUMS && sudo apt install ./pydebuprep_${VERSION}_all.deb
```

To build the package yourself, see [Development](#development).

`debsums` and `needrestart` are recommended; the checks that need them are skipped
when they're missing.

The package installs tab completion for bash
(`/usr/share/bash-completion/completions/pydebuprep`, active when the
`bash-completion` package is installed) and zsh
(`/usr/share/zsh/vendor-completions/_pydebuprep`, picked up automatically,
including if zsh is installed later). Without the package, load them with
`source <(pydebuprep completion bash)` in `~/.bashrc`, or
`source <(pydebuprep completion zsh)` after `compinit` in `~/.zshrc`.

## Usage

```sh
sudo pydebuprep snapshot        # before the upgrade (optional, recommended)
sudo apt full-upgrade           # or: sudo do-release-upgrade
sudo reboot
sudo pydebuprep                 # after the upgrade
```

Run it as root for complete results. Without root, the checks that need it are
reported as skipped.

If a snapshot exists, `report` compares against the newest one automatically and
each check adds a "Changes since baseline" section: services, timers and cron jobs
that were there and aren't, repositories that were enabled and aren't, packages
that disappeared, network interfaces, addresses and routes that went away, firewall
rules that didn't come back, Docker containers and PostgreSQL clusters that stopped,
and the kernel you upgraded from. Use `--baseline FILE` to pick a snapshot or
`--no-baseline` to skip the comparison; without a baseline the report says so once,
in its header.

### Output

```sh
sudo pydebuprep report --format html --output-dir /var/tmp
# → /var/tmp/pydebuprep-<hostname>-20261028T120000Z.html
```

| Option | Effect |
|---|---|
| `--format text\|json\|yaml\|html\|markdown\|jira\|confluence` | Output format (default `text`). Every format has the same structure. |
| `--output-dir DIR` | Write to a timestamped file in `DIR` instead of stdout. |
| `--output FILE` | Write to `FILE`; if it exists, a timestamp is added instead of overwriting. `-o -` forces standard output even when the config sets `output_dir`. |
| `--baseline FILE` / `--no-baseline` | Compare against this snapshot instead of the newest one, or against none. |
| `--snapshot-dir DIR` | Where snapshots are stored and looked up (default `/var/lib/pydebuprep/snapshots`). |
| `--checks ID,...` / `--skip ID,...` | Run only, or leave out, specific checks. |
| `--min-severity warning\|critical` | Hide lower-severity findings (the exit code still counts them). |
| `--no-color` | Plain text output (also when not a TTY or `NO_COLOR` is set). |
| `--todo` / `--no-todo` | Add a TODO checklist at the end of the report (see below); `todo: true` in the config makes it the default. |
| `--check-option CHECK.OPTION=VALUE` | Set a check option; repeat it to add items to a list option. See `pydebuprep list-checks --verbose`. |
| `--config FILE` / `--no-config` | Use another config file, or none. |

### A TODO list to track the fixes

```sh
sudo pydebuprep report --todo --format markdown -o upgrade-todo.md
```

`--todo` ends the report with a checklist of what needs doing: one item per critical
or warning finding (critical first), with its remediation steps as sub-items to tick
off; an item for each check that failed to run; a reminder to run as root if checks
were skipped for that; and a final "run pydebuprep again" item. Info findings are
left out. Markdown renders it as a task list (tickable on GitHub and GitLab), HTML as
checkboxes, text as `[ ]`, Jira and Confluence as ☐ bullets, and JSON/YAML add a
`todo` array for tools. `convert --todo` adds it to a saved report.

### Converting a saved report

Keep a JSON (or YAML) copy of each report, and render it in any other format
later, without running the checks again:

```sh
sudo pydebuprep report --format json --output-dir /var/tmp
pydebuprep convert /var/tmp/pydebuprep-web1-20261028T120000Z.json --format jira -o -
pydebuprep convert report.json --format html --output-dir /srv/reports
```

The output is identical to what `report` would have produced in that format;
file names carry the original host and time. `-` reads the report from standard
input. Text, HTML, Markdown, Jira and Confluence output can't be read back, so
those are rejected. A damaged or hand-edited file is rejected with the field at
fault (exit code 3); `convert` exits 0 on success whatever the report found.

### Pasting into Jira or Confluence

`--format jira` produces Jira wiki markup: paste it into an issue or comment
(in the text editor, or the visual editor, which converts wiki markup on paste).
`--format confluence` produces Confluence wiki markup with status lozenges and
info/note/warning panels; insert it with **Insert → Markup → Confluence wiki**.
The two dialects differ, so use the one that matches where you paste. Both were
written against the documented markup; check them in your own Jira/Confluence
version before relying on the layout.

```sh
sudo pydebuprep --format jira -o - | xclip -selection clipboard
```

## Configuration

pydebuprep reads `/etc/pydebuprep.conf` if it exists (or the file in
`$PYDEBUPREP_CONFIG`, or `--config FILE`). It's YAML with three sections: `report`,
with defaults for the command-line options; `logs`, with ignore patterns shared by
the journal and dmesg checks; and `checks`, where each check can be disabled or given
options. Command-line options win over the file, and relative paths in it are
relative to the file.

```yaml
report:
  format: html
  output_dir: /var/tmp/pydebuprep
  baseline: auto            # auto | none | /path/to/snapshot.json
checks:
  debsums:
    enabled: false
  disk-space:
    include_remote: true    # also NFS, CIFS, sshfs, rclone, ...
    warning_pct: 20.0
    exclude_mounts: ["/mnt/scratch*"]
  journal-errors:
    ignore: ["^networkctl: Interface .* not found"]   # journal only: "IDENTIFIER: message"
logs:
  # Shared by journal-errors and dmesg-errors, matched against the message text.
  # Kernel messages show up in both, so one pattern here hides them in both.
  ignore: ["^ACPI BIOS Error"]
```

```sh
pydebuprep example-config > pydebuprep.conf   # every setting at its default, commented
sudo pydebuprep configtest                     # "Syntax OK", or every problem and exit 3
pydebuprep list-checks --verbose               # all checks and their options
```

The package also installs the example as
`/usr/share/doc/pydebuprep/examples/pydebuprep.conf`.

| Check | Options (defaults) |
|---|---|
| `apt-lists-age` | `max_age_days` (7) |
| `config-conflicts` | `critical_paths` (sshd_config, sshd_config.d/, sudoers, sudoers.d/), `ignore_paths` ([]): patterns for files to leave out, e.g. ones Ansible manages |
| `debsums` | `timeout_seconds` (600) |
| `boot-space` | `warning_pct` (25.0), `critical_pct` (10.0) |
| `dmesg-errors`, `journal-errors` | `ignore` ([]): regular expressions for messages to leave out (see also `logs: ignore:`) |
| `systemd-failed`, `systemd-timers` | `ignore_units` ([]): unit name patterns to leave out |
| `systemd-critical-services` | `required_active` ([]), `required_enabled` ([]): units that must be running / enabled, on top of the built-in list; `builtin` (true): include ssh, cron and journald where installed; `ignore_units` ([]) |
| `postgresql`, `mariadb` | `probe` (false): ask the server whether it answers (opt-in: connects as root, the server may log it); `credentials_file` (""): a `.pgpass` / MySQL option file for the probe's login |
| `docker` | `probe` (false): connect to every published TCP port, and run `http_probes`; `http_probes` ([]): `CONTAINER=URL` items, localhost only, 2xx/3xx passes; `ignore_containers` ([]): name patterns to leave out |
| `python-venvs` | `search_paths` (/opt, /srv, /usr/local, /root, /home, /var/www) and `max_depth` (5): where to look for virtualenvs; `exclude_paths` (\*/.cache/\*): ones to leave out |
| `network` | `ignore_interfaces` (lo, veth\*, docker\*, br-\*, virbr\*, vnet\*, tap\*, cni\*, flannel\*, cali\*): left out of the baseline comparison |
| `disk-space` | `include_remote` (false), `warning_pct` (25.0), `critical_pct` (10.0), `exclude_mounts` ([]), `important_mounts` (["/", "/var"]) and `min_free_mib` (2048): an absolute free-space floor for those mounts |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing at warning level or above |
| 1 | The most severe finding is a warning, or a check failed to run (status `error`) |
| 2 | At least one critical finding |
| 3 | pydebuprep itself failed (bad arguments, an invalid or unreadable config file, an unreadable baseline, unwritable output) |

Skipped checks (not root, tool not installed) don't affect the exit code. A check
that errors (for example a command that timed out) raises it to at least 1, so a
host never looks healthy just because a check couldn't look.

## Checks

| ID | Category | What it looks at |
|---|---|---|
| `apt-lists-age` | release | How stale the downloaded package lists are |
| `apt-sources` | release | Sources still on the old codename, repos disabled by the upgrade, missing distro archive or security archive, duplicates; missing signing keyrings, keys in the legacy trusted.gpg; repositories without downloaded metadata, serving another release than configured (from the last apt update; never runs it) |
| `os-release` | release | Supported release; upgrade path vs. the baseline |
| `apt-autoremove` | packages | Packages `apt autoremove` would remove (simulated) |
| `apt-held` | packages | Held packages |
| `apt-upgradable` | packages | Pending security updates, packages kept back, updates deferred by phasing, and other upgrades, separately |
| `config-conflicts` | packages | `*.dpkg-dist`, `*.dpkg-new`, `*.ucf-dist`… left in `/etc` (critical for sshd/sudoers) |
| `debsums` | packages | Package files that no longer match their checksums (root, needs `debsums`) |
| `dpkg-audit` | packages | Packages unpacked but not configured, needing reinstalling, or waiting for triggers (separately); `dpkg --audit` and `apt-get check` |
| `dpkg-rc` | packages | Removed packages with leftover config |
| `obsolete-packages` | packages | Installed packages no repository provides any more; packages from third-party repositories, by vendor; packages whose origin changed since the baseline |
| `boot-space` | boot | Free space and inodes on `/boot` and the EFI partition |
| `bootloader` | boot | `grub.cfg` references the newest kernel; UEFI boot entries |
| `dkms` | boot | DKMS modules built for the running kernel |
| `kernel-running` | boot | Running the newest installed kernel; reboot required |
| `boot-time` | services | `systemd-analyze`, the slowest units and the boot critical chain |
| `cron` | services | Jobs that run programs which no longer exist; crontabs without a running cron daemon; jobs removed since the baseline |
| `dmesg-errors` | services | Kernel errors and warnings (root) |
| `journal-errors` | services | Errors in the journal since boot, grouped |
| `needrestart` | services | Services still using old libraries (root, needs `needrestart`) |
| `systemd-critical-services` | services | Critical units (built-in ssh, cron and journald where installed, plus configured ones) not running (failed ones are left to `systemd-failed`), masked, missing, disabled, or running without a required unit; units masked or missing since the baseline; listeners lost since the baseline (root) |
| `systemd-failed` | services | Failed units; services active or enabled before the upgrade that aren't now |
| `systemd-timers` | services | Enabled timers that aren't active |
| `time-sync` | services | A time synchronisation service is running and the clock is synchronised (read from the kernel, no daemon queried); service changes since the baseline |
| `bind` | applications | `named-checkconf` errors (root) |
| `docker` | applications | Containers failing their health check, restarting, or still starting it (each its own finding); containers running before but not now; opt-in probes of published ports and HTTP URLs. Only queried when `docker.service` is running, so the daemon is never started (root) |
| `mariadb` | applications | MariaDB data directory not upgraded to the new server version; opt-in probe that MariaDB or MySQL answers a ping and a query (root) |
| `postfix` | applications | `postconf -n` warnings and errors (`postfix check` isn't used: it creates directories) |
| `postgresql` | applications | Clusters still on an older major version than the newest installed server, or left behind after migrating; clusters that should start but are down; clusters online before but not now; opt-in probe that each online cluster accepts connections and answers a query |
| `python-venvs` | applications | Virtualenvs whose Python no longer exists, or built for an older Python |
| `firewall` | network | ufw or nftables enabled but no rules loaded; rules lost since the baseline (root; only queries already-loaded kernel modules) |
| `network` | network | Default route and DNS servers; interfaces, addresses, routes, DNS and the network manager (ifupdown, netplan, NetworkManager, systemd-networkd) compared with the baseline |
| `apparmor` | security | AppArmor enabled, profiles in complain mode, denials this boot, profiles no longer enforced (root) |
| `ssh-server` | security | `sshd -t` errors and warnings (an invalid config locks you out on restart); DSA keys in `authorized_keys` (root) |
| `unattended-upgrades` | security | Installed but disabled, or still naming the old release in its allowed origins |
| `disk-space` | storage | Free space and inodes on local filesystems (network mounts optional); a minimum free-space floor for `/` and `/var` |
| `fstab` | storage | `findmnt --verify`; mounts that went missing since the baseline |

## Running across a fleet with Ansible

```yaml
- name: Release upgrade with pydebuprep checks
  hosts: upgrade_targets
  become: true
  tasks:
    - name: Take a pre-upgrade snapshot
      ansible.builtin.command: pydebuprep snapshot
      changed_when: false

    # ... your upgrade and reboot tasks ...

    - name: Create report directory
      ansible.builtin.file:
        path: /var/tmp/pydebuprep
        state: directory
        mode: "0750"

    - name: Run pydebuprep
      ansible.builtin.command: >-
        pydebuprep report --format json --output-dir /var/tmp/pydebuprep
      register: pydebuprep
      changed_when: false
      failed_when: pydebuprep.rc == 3

    - name: Find the newest report
      ansible.builtin.find:
        paths: /var/tmp/pydebuprep
        patterns: "pydebuprep-*.json"
      register: reports

    - name: Fetch the report
      ansible.builtin.fetch:
        src: "{{ (reports.files | sort(attribute='mtime') | last).path }}"
        dest: "reports/{{ inventory_hostname }}.json"
        flat: true

    - name: Flag hosts with critical findings
      ansible.builtin.debug:
        msg: "{{ inventory_hostname }} has critical findings, see reports/{{ inventory_hostname }}.json"
      when: pydebuprep.rc == 2
```

## Adding a check

1. Create `src/pydebuprep/checks/<name>.py` with a `Check` subclass: set `id`,
   `title`, `category`, and `requires_root` / `requires_commands` if needed, and
   implement `run(ctx) -> list[Finding]`. Give every finding at least one
   remediation step.
2. To take part in snapshots, also implement `collect_baseline(ctx)` and
   `compare(ctx, before)`. For settings, declare
   `options = (Option("name", default, "help"),)` and read them with
   `self.opt("name")`; the type comes from the default, and the option shows up
   in `example-config`, `list-checks --verbose` and config validation
   automatically. Override `validate()` to check values against each other.
3. Add the class to `ALL_CHECKS` in `src/pydebuprep/checks/__init__.py`. Its
   `category` must be one of `CATEGORY_ORDER` in `src/pydebuprep/model.py` (release,
   packages, boot, services, applications, network, security, storage).
4. Run commands only through `run_checked(ctx, argv)`, which turns a timeout or an
   unexpected exit status into a check error instead of empty output. If you need a
   new command, add its **complete** argv to `ALLOWED_COMMANDS` in
   `src/pydebuprep/system.py`. Matching is exact, so no extra argument can ever slip
   through. Use `apt_command()` for anything apt.
5. Write tests under `tests/checks/` with `FakeSystem` and real command output;
   coverage must stay at 100%. Map each option to the test that proves it in
   `tests/test_option_coverage.py`.
6. Document it: a page `docs/checks/<id>.md` and its entry in `mkdocs.yml`'s
   navigation, a row in this README's checks table (and options table, if it has
   options), and an entry in the man page's CHECKS section, in report order.
   `tests/test_docs.py` and `tests/test_docs_site.py` fail until they match the
   code. Run `make generated` to update the example config and shell completions.
7. Prove it's read-only: run the new command under `scripts/readonly-audit.sh` (or
   `strace`) as root with the service it inspects installed, and add that package
   to `scripts/ci-readonly-audit.sh` so every pull request is audited with it (and to
   `AUDIT_EXPECT` there, so the audit fails if the command never runs). Some obvious
   commands write (`nginx -t`, `postfix check`, `ufw status`); don't use those.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt && .venv/bin/pip install --no-deps -e .
make lint test
make coverage   # line and branch coverage, enforced at 100% (pyproject.toml)
make generated  # after changing commands, flags, checks or options
sudo make audit # with the package installed: strace proves a root run changes nothing
make deb        # needs: debhelper dh-python python3-all python3-setuptools python3-yaml python3-pytest
```

The documentation site lives in `docs/` (MkDocs with Material):

```sh
python3 -m venv .venv-docs && .venv-docs/bin/pip install -r requirements-docs.txt
make docs-serve   # http://127.0.0.1:8000
make docs         # strict build into site/
```

## Releases

Bump the version in `debian/changelog` (`dch -v X.Y.Z`) and in
`src/pydebuprep/__init__.py` together, merge that, then push a matching tag from
`main` (release tags are protected: only maintainers can create them):

```sh
git tag -a v0.3.1 -m "pydebuprep 0.3.1" && git push origin v0.3.1
```

The **Release** workflow builds the `.deb` once and lints it with lintian. It then
installs it on Debian 12, Debian 13, and Ubuntu 22.04, 24.04 and 26.04, runs a
smoke test, and runs the read-only audit on each. Only if all of that passes
does it publish a GitHub Release with the `.deb`, a `SHA256SUMS` file and a
build-provenance attestation. To check a download:

```sh
sha256sum -c SHA256SUMS
gh attestation verify pydebuprep_0.3.1_all.deb --repo tolecnal/pydebuprep
```

Running the workflow by hand (workflow_dispatch) builds and verifies the package
without publishing it.

## Security checks

To report a vulnerability, see [SECURITY.md](SECURITY.md). Please use GitHub's private
reporting, not a public issue.

| Workflow | What it covers |
|---|---|
| CodeQL | Python code and the workflow files (`security-extended` queries); results in the Security tab |
| Security / Bandit | Python security lint; deliberate exceptions are marked `# nosec <id>` with a reason |
| Security / ShellCheck | `scripts/*.sh`, the bash completion and the package maintainer scripts |
| Security / pip-audit | Known vulnerabilities in the pinned tools (`requirements-dev.txt`, `requirements-audit.txt`) |
| Security / zizmor | GitHub Actions security: pinning, permissions, credentials, injection; results in the Security tab |
| Security / Dependency review | New vulnerable dependencies in pull requests |
| CI / Package | Builds the `.deb` on every pull request, push to `main` and weekly, installs it on every supported release and proves a root run changes nothing (`scripts/readonly-audit.sh`): in plain containers, in containers booted with systemd (services running, UEFI variables mounted), and on the Ubuntu runner VMs |
| Release | For a release tag, runs the same packaging and audit jobs, then publishes the `.deb` with checksums and a provenance attestation |
| Docs | Builds the documentation site on every pull request (strict: broken links fail), publishes it to GitHub Pages from `main` |

Dependabot (`.github/dependabot.yml`) proposes weekly updates for the pinned action
commits and Python tools. It waits 7 days before suggesting a new release, so a
compromised version can be pulled first. The installed package's only runtime
dependency, PyYAML, comes from Debian/Ubuntu and gets their security updates.

## License

MIT. See [LICENSE](LICENSE).
