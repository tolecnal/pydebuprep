# Output formats

Every format contains the same report: the host, a summary, then each check with
its findings and its changes since the baseline, in the same order. Choose one with
`--format` (`-f`) or `format:` in the [configuration](../configuration/index.md).

| Format | For | Notes |
|---|---|---|
| `text` (default) | reading in a terminal | coloured when writing to a terminal |
| `json` | scripts, monitoring, archiving | the [report format](../reference/report-format.md); can be [converted](#converting-a-saved-report) later |
| `yaml` | the same, for humans | needs `python3-yaml`; can be converted later |
| `html` | a browser, e-mail, a ticket attachment | one self-contained file, no scripts or external resources |
| `markdown` | Git hosting, wikis, chat | |
| `jira` | Jira issues and comments | Jira wiki markup |
| `confluence` | Confluence pages | Confluence wiki markup, with status lozenges and panels |

```sh
sudo pydebuprep report --format html --output-dir /var/tmp
# Report written to /var/tmp/pydebuprep-web1-20261028T120000Z.html
```

The human-readable formats escape what they show — command output, file names and
log messages come from the system and could contain markup — and strip terminal
control sequences. JSON and YAML carry the data as it is.

## Pasting into Jira or Confluence

`--format jira` produces Jira wiki markup: paste it into an issue or comment (in
the text editor, or the visual editor, which converts wiki markup on paste).
`--format confluence` produces Confluence wiki markup; insert it with
**Insert → Markup → Confluence wiki**. The two dialects differ, so use the one that
matches where you paste.

```sh
sudo pydebuprep --format jira -o - | xclip -selection clipboard
```

Both were written against the documented markup; check the result in your own
Jira or Confluence version before relying on the layout.

## Converting a saved report

Keep a JSON (or YAML) copy of each report, and render it in any other format later,
without running the checks again — for example to paste a host's report into a
ticket the next day, or to publish HTML for reports collected from a fleet:

```sh
sudo pydebuprep report --format json --output-dir /var/tmp
pydebuprep convert /var/tmp/pydebuprep-web1-20261028T120000Z.json --format jira -o -
pydebuprep convert report.json --format html --output-dir /srv/reports
cat report.json | pydebuprep convert - --format markdown
```

- The output is **identical** to what `report` would have produced in that format.
- With `--output-dir`, the file name carries the **original** host and time, not
  the time of conversion.
- `convert` needs no root and reads no configuration file.
- Only JSON and YAML can be read back. Text, HTML, Markdown, Jira and Confluence are
  renderings, not data, and are rejected with a hint.
- The file is validated field by field, since it may come from another host; a
  damaged or hand-edited file is rejected naming the field at fault (exit code 3).
  `convert` exits 0 on success, whatever the report found.
