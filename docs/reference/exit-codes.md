# Exit codes

## `report`

| Code | Meaning |
|---|---|
| 0 | Nothing at warning level or above. |
| 1 | The most severe finding is a warning, **or** a check failed to run (status `error`). |
| 2 | At least one critical finding. |
| 3 | pydebuprep itself failed: bad arguments, an invalid or unreadable configuration file, an unreadable baseline, unwritable output. |
| 130 | Interrupted (Ctrl-C). |

- **Skipped** checks (not root, a tool not installed) don't affect the exit code.
- A check that **errors** (a command timed out or failed unexpectedly) raises the
  code to at least 1, so a host never looks healthy just because a check couldn't
  look.
- `--min-severity` and the configuration's `min_severity` hide findings from the
  display only; the exit code still counts them.
- Changes since the baseline count like other findings.

## Other commands

| Command | 0 | 3 |
|---|---|---|
| `snapshot` | snapshot written | it couldn't be written, or the configuration is invalid |
| `convert` | report converted (whatever the report found) | the file is unreadable, not a JSON/YAML report, or invalid |
| `configtest` | the configuration is valid (`Syntax OK`) | it isn't; every problem is listed |
| `list-checks`, `example-config`, `completion` | always | — |

## In automation

```sh
sudo pydebuprep report --format json --output-dir /var/tmp/pydebuprep
case $? in
    0) echo "healthy" ;;
    1) echo "warnings" ;;
    2) echo "critical findings" ;;
    *) echo "pydebuprep failed" >&2 ;;
esac
```

Treat only 3 (and above) as a failure of the run itself; 1 and 2 are results.
