# Running reports

```sh
sudo pydebuprep            # the same as: sudo pydebuprep report
```

`report` runs every check, compares against the newest snapshot if there is one,
and prints a text report to the terminal. Run it as root for complete results.

## Choosing checks

```sh
sudo pydebuprep report --checks apt-sources,dkms,systemd-failed   # only these
sudo pydebuprep report --skip debsums                              # all but these
```

Check IDs are listed in [Checks](../checks/index.md) and by
`pydebuprep list-checks`. To leave a check out permanently, set `enabled: false` for
it in the [configuration file](../configuration/index.md).

## Hiding low-severity findings

```sh
sudo pydebuprep report --min-severity warning
```

Hides `info` findings (or `info` and `warning` with `critical`). The
[exit code](../reference/exit-codes.md) still counts everything, so filtering the
display never makes a host look healthier than it is.

## Where the report goes

| You want | Use |
|---|---|
| the terminal | nothing (the default) |
| a file | `--output FILE` (`-o`). If `FILE` exists, a timestamp is added to the name instead of overwriting it. |
| a timestamped file in a directory | `--output-dir DIR`, e.g. `/var/tmp/pydebuprep-web1-20261028T120000Z.html` |
| the terminal, despite `output_dir` in the config | `-o -` |

pydebuprep never overwrites an existing file.

## A checklist of what to fix

```sh
sudo pydebuprep report --todo
```

Ends the report with a TODO list: the critical and warning findings with their fix
steps as checkboxes. See [A TODO list to track the fixes](output-formats.md#a-todo-list-to-track-the-fixes).

## Setting check options for one run

```sh
sudo pydebuprep report --check-option disk-space.warning_pct=15 \
                       --check-option disk-space.exclude_mounts=/mnt/scratch
```

Overrides the configuration file for this run. Each check's page lists its options;
`pydebuprep list-checks --verbose` lists them all. For list options, repeat
`--check-option` to give several items.

## Colour

Text output is coloured when writing to a terminal. `--no-color`, the `NO_COLOR`
environment variable, or `color: false` in the configuration turn it off.

## Running without root

Without root, checks that need it are reported as *skipped* with the reason, and
the report header notes "not run as root: some checks skipped". Everything else runs
normally. Nothing pydebuprep does needs write access anyway — root is only for
reading.
