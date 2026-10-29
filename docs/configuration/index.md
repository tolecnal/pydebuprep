# Configuration

pydebuprep works without any configuration. A configuration file lets you set
defaults for the command line, leave checks out, and tune what each check reports,
so that what's expected on your systems doesn't bury what isn't.

## Where it's read from

The first of these is used:

1. the file given with `--config FILE` (`-c`);
2. the file named in the `PYDEBUPREP_CONFIG` environment variable;
3. `/etc/pydebuprep.conf`, if it exists.

A file named with `--config` or `PYDEBUPREP_CONFIG` must exist; only the default
location is optional. `--no-config` ignores all of them. The package doesn't
install a configuration file; a commented example with every setting is at
`/usr/share/doc/pydebuprep/examples/pydebuprep.conf`.

## Format

The file is YAML with three optional sections:

```yaml title="/etc/pydebuprep.conf"
report:                       # defaults for the command line
  format: html
  output_dir: /var/tmp/pydebuprep
  baseline: auto              # auto | none | /path/to/snapshot.json

logs:                         # shared by journal-errors and dmesg-errors
  ignore: ["^ACPI BIOS Error"]

checks:                       # one section per check, by its ID
  debsums:
    enabled: false            # leave the check out
  disk-space:
    include_remote: true      # also NFS, CIFS, sshfs, rclone, ...
    warning_pct: 20.0
    exclude_mounts: ["/mnt/scratch*"]
  journal-errors:
    ignore: ["^networkctl: Interface .* not found"]
```

- **`report`** holds defaults for `report` and `snapshot`: format, output
  directory, minimum severity, colour, baseline and snapshot directory.
- **`logs`** holds `ignore`, regular expressions for log messages to leave out of
  both [`journal-errors`](../checks/journal-errors.md) and
  [`dmesg-errors`](../checks/dmesg-errors.md). Kernel messages appear in both, so
  one pattern here covers them.
- **`checks`** has a section per check, named by its ID. Every section accepts
  `enabled: false` to leave the check out; the other keys are the check's options,
  listed on each [check's page](../checks/index.md).

Every key, its type and its default is in the [reference](reference.md).

## How settings combine

From lowest to highest priority:

1. **built-in defaults**;
2. **the configuration file**;
3. **the command line**: `--format`, `--output-dir`, `--baseline`, … override the
   `report` section, and `--check-option CHECK.OPTION=VALUE` overrides a check
   option for one run.

A few details:

- **List options on the command line replace** the configured list. Repeat
  `--check-option` to give several items, or separate them with commas (regular
  expression options such as `ignore` take one pattern per `--check-option`, since
  a pattern may contain commas).
- **`--checks` wins over `enabled: false`**: naming a check explicitly runs it even
  if the file disables it. `--skip` adds to the disabled checks.
- **Relative paths** in the file (`output_dir`, `baseline`, `snapshot_dir`) are
  relative to the file's directory, not the current directory.
- `-o -` writes to standard output even if the file sets `output_dir`.

## Checking a configuration

```sh
sudo pydebuprep configtest                       # the file report would use
pydebuprep configtest --config ./pydebuprep.conf
```

`configtest` reports **every** problem — unknown sections, keys or checks, wrong
types, invalid regular expressions, values out of range — and exits 3, or prints
`Syntax OK` and exits 0. `report` and `snapshot` validate the file the same way and
refuse to run with an invalid one, so a typo can never silently turn a check off.

Run `configtest` in your configuration management after distributing the file.

## Starting from the example

```sh
pydebuprep example-config > pydebuprep.conf     # every setting at its default
pydebuprep list-checks --verbose                # all checks and their options
```

Keep only the settings you change: anything left out uses the built-in default,
which keeps your file short and picks up improved defaults in new versions.

## Best practices

- **Silence, don't ignore.** A finding that's expected on all your hosts belongs in
  the configuration (an ignore pattern, an option, or `enabled: false`), so the
  report stays short enough that real problems stand out.
- **Prefer the narrowest setting**: an ignore pattern for one unit or log message
  rather than disabling a whole check.
- **Anchor regular expressions** (`^…`) so they match only what you mean.
- **Keep one file for the fleet**, managed like any other configuration, and
  validate it with `configtest` where you deploy it.
- **Explain each exception** with a YAML comment; future you will want to know why
  a warning was silenced.
