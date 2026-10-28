# pydebuprep

A read-only health report for Debian and Ubuntu systems after a release upgrade
(Debian 12 → 13, Ubuntu 22.04 → 24.04 → 26.04, and minor upgrades too).

`systemctl --failed` and a look at `journalctl` catch some problems. pydebuprep
runs the rest of the post-upgrade checklist in one go: APT sources still pointing
at the old release, third-party repositories the upgrader disabled, half-configured
packages, unmerged `*.dpkg-dist` configs, a pending reboot, DKMS modules that didn't
rebuild, failed units, missing timers, a bad `fstab`, a filling `/boot` and more.

**It never changes anything.** It doesn't install or remove packages, doesn't run
`apt update` or `update-grub`, and doesn't restart services. Every external command
it runs is checked against a built-in allowlist of read-only commands. Each finding
comes with the commands to fix it, for you to review and run yourself.

## Supported systems

Debian 12 (bookworm), Debian 13 (trixie), Ubuntu 22.04 (jammy), 24.04 (noble) and
26.04 (resolute). Python 3.10 or newer; the only dependency is `python3-yaml`.

## Install

Build the package (see [Development](#development)) and install it:

```sh
sudo apt install ./pydebuprep_0.2.0_all.deb
```

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
each check adds a "Changes since baseline" section: services that were running
and aren't, repositories that were enabled and aren't, packages that disappeared,
the kernel you upgraded from. Use `--baseline FILE` to pick a snapshot or
`--no-baseline` to skip the comparison.

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
| `--checks ID,...` / `--skip ID,...` | Run only, or leave out, specific checks. |
| `--min-severity warning\|critical` | Hide lower-severity findings (the exit code still counts them). |
| `--no-color` | Plain text output (also when not a TTY or `NO_COLOR` is set). |
| `--check-option CHECK.OPTION=VALUE` | Set a check option; repeat it to add items to a list option. See `pydebuprep list-checks --verbose`. |
| `--config FILE` / `--no-config` | Use another config file, or none. |

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
`$PYDEBUPREP_CONFIG`, or `--config FILE`). It's YAML: a `report` section with
defaults for the command-line options, and a `checks` section where each check
can be disabled or given options. Command-line options win over the file.

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
    ignore: ["^networkctl: Interface .* not found"]
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
| `config-conflicts` | `critical_paths` (sshd_config, sshd_config.d/, sudoers, sudoers.d/) |
| `debsums` | `timeout_seconds` (600) |
| `boot-space` | `warning_pct` (25.0), `critical_pct` (10.0) |
| `disk-space` | `include_remote` (false), `warning_pct` (25.0), `critical_pct` (10.0), `exclude_mounts` ([]) |
| `dmesg-errors`, `journal-errors` | `ignore` ([]): regular expressions for messages to leave out |
| `systemd-failed`, `systemd-timers` | `ignore_units` ([]): unit name patterns to leave out |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing at warning level or above |
| 1 | The most severe finding is a warning, or a check failed to run (status `error`) |
| 2 | At least one critical finding |
| 3 | pydebuprep itself failed (bad arguments, unreadable baseline, unwritable output) |

Skipped checks (not root, tool not installed) don't affect the exit code. A check
that errors (for example a command that timed out) raises it to at least 1, so a
host never looks healthy just because a check couldn't look.

## Checks

| ID | Category | What it looks at |
|---|---|---|
| `os-release` | release | Supported release; upgrade path vs. the baseline |
| `apt-sources` | release | Sources still on the old codename, repos disabled by the upgrade, missing distro archive, duplicates |
| `apt-lists-age` | release | How stale the downloaded package lists are |
| `apt-autoremove` | packages | Packages `apt autoremove` would remove (simulated) |
| `apt-held` | packages | Held packages |
| `apt-upgradable` | packages | Upgrades still pending |
| `config-conflicts` | packages | `*.dpkg-dist`, `*.dpkg-new`, `*.ucf-dist`… left in `/etc` (critical for sshd/sudoers) |
| `debsums` | packages | Package files that no longer match their checksums (root, needs `debsums`) |
| `dpkg-audit` | packages | `dpkg --audit` and `apt-get check` |
| `dpkg-rc` | packages | Removed packages with leftover config |
| `obsolete-packages` | packages | Installed packages no repository provides any more |
| `boot-space` | boot | Free space and inodes on `/boot` and the EFI partition |
| `bootloader` | boot | `grub.cfg` references the newest kernel; UEFI boot entries |
| `dkms` | boot | DKMS modules built for the running kernel |
| `kernel-running` | boot | Running the newest installed kernel; reboot required |
| `boot-time` | services | `systemd-analyze` and the slowest units |
| `dmesg-errors` | services | Kernel errors and warnings (root) |
| `journal-errors` | services | Errors in the journal since boot, grouped |
| `needrestart` | services | Services still using old libraries (root, needs `needrestart`) |
| `systemd-failed` | services | Failed units; services active or enabled before the upgrade that aren't now |
| `systemd-timers` | services | Enabled timers that aren't active |
| `disk-space` | storage | Free space and inodes on local filesystems (network mounts optional) |
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
3. Add the class to `ALL_CHECKS` in `src/pydebuprep/checks/__init__.py`.
4. Run commands only through `run_checked(ctx, argv)`, which turns a timeout or an
   unexpected exit status into a check error instead of empty output. If you need a
   new command, add its **complete** argv to `ALLOWED_COMMANDS` in
   `src/pydebuprep/system.py`. Matching is exact, so no extra argument can ever slip
   through. Use `apt_command()` for anything apt.
5. Write tests under `tests/checks/` with `FakeSystem` and real command output.

## Development

```sh
python3 -m venv .venv --system-site-packages
.venv/bin/pip install -e '.[dev]'
make lint test
make coverage   # branch coverage, must stay at or above fail_under (pyproject.toml)
make generated  # after changing commands, flags, checks or options
make deb        # needs: debhelper dh-python python3-all python3-setuptools python3-yaml python3-pytest
```

## License

MIT. See [LICENSE](LICENSE).
