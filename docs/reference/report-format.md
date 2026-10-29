# Report format

`--format json` and `--format yaml` produce the same structure. It's versioned by
`schema_version`; fields may be added in later versions, but existing ones keep
their meaning until the version changes. These two formats can be read back by
[`pydebuprep convert`](../guide/output-formats.md#converting-a-saved-report).

```json
{
  "schema_version": "1",
  "tool": {"name": "pydebuprep", "version": "0.3.1"},
  "generated_at": "2026-10-28T12:00:00+00:00",
  "host": {
    "hostname": "web1",
    "os_id": "debian",
    "os_version": "13",
    "codename": "trixie",
    "kernel": "6.12.0-1-amd64",
    "is_root": true
  },
  "baseline": {
    "path": "/var/lib/pydebuprep/snapshots/20261027T100000Z.json",
    "created_at": "2026-10-27T10:00:00+00:00",
    "os_version": "12",
    "hostname": "web1"
  },
  "summary": {
    "critical": 1, "warning": 0, "info": 1,
    "ok": 30, "skipped": 4, "error": 0,
    "exit_code": 2
  },
  "results": [
    {
      "id": "apt-sources",
      "title": "APT sources",
      "category": "release",
      "status": "findings",
      "skipped_reason": null,
      "error": null,
      "findings": [
        {
          "severity": "critical",
          "title": "No enabled repository for the Debian archive",
          "detail": "No enabled source points at the distribution's own archive, ...",
          "evidence": ["..."],
          "remediation": ["Add the Debian archive for trixie to /etc/apt/sources.list.d/", "sudo apt update"],
          "references": []
        }
      ],
      "baseline_diff": []
    }
  ]
}
```

## Fields

**Top level**

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | `"1"` |
| `tool` | object | `name` and `version` of pydebuprep |
| `generated_at` | string | ISO 8601 time the report was made (UTC) |
| `host` | object | see below |
| `baseline` | object or null | the snapshot compared against, or `null` |
| `summary` | object | counts and the exit code |
| `results` | array | one entry per check, in report order |

**`host`**: `hostname`, `os_id` (`debian`, `ubuntu`), `os_version` (`13`,
`24.04`), `codename`, `kernel` (the running kernel), `is_root` (whether the report
ran as root).

**`baseline`**: `path`, `created_at`, `os_version` and `hostname` of the snapshot.

**`summary`**: the number of findings per severity (`critical`, `warning`, `info`)
and of checks per status (`ok`, `skipped`, `error`), and the `exit_code` the run
returned. Findings hidden with `--min-severity` are still counted.

**`results[]`**

| Field | Type | Meaning |
|---|---|---|
| `id`, `title`, `category` | string | the check |
| `status` | string | `ok`, `findings`, `skipped` or `error` |
| `skipped_reason` | string or null | why it was skipped |
| `error` | string or null | why it failed |
| `findings` | array | what it found now |
| `baseline_diff` | array or null | changes since the baseline; `null` when the check doesn't compare or there's no baseline |

**Findings**: `severity` (`critical`, `warning`, `info`), `title`, `detail`, and
the lists `evidence`, `remediation` and `references`.

**`todo`** (only with `--todo`): the [TODO list](../guide/output-formats.md#a-todo-list-to-track-the-fixes),
an array of `{"severity", "check", "title", "steps"}`. `severity` and `check` are
`null` for the items that aren't findings (a check that failed to run, running as
root, the confirmation run). `convert` accepts reports with or without it.

## Examples

```sh
# Hosts and their critical/warning counts, from collected reports
jq -r '[.host.hostname, .summary.critical, .summary.warning] | @tsv' reports/*.json

# Every critical finding with its check
jq -r '.results[] | .id as $id | .findings[] | select(.severity == "critical") | "\($id): \(.title)"' report.json
```
