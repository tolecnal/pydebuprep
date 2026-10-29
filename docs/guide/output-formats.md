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

## A TODO list to track the fixes

Add `--todo` (or set `todo: true` under `report:` in the
[configuration](../configuration/index.md)) and the report ends with a checklist of
what needs doing — handy when fixing a system takes several manual steps, or several
people:

```sh
sudo pydebuprep report --todo --format markdown -o upgrade-todo.md
```

```text
TODO
----
[ ] CRITICAL config-conflicts: Unmerged package config for /etc/ssh/sshd_config
    [ ] diff -u /etc/ssh/sshd_config /etc/ssh/sshd_config.ucf-dist
    [ ] Merge the changes you want into /etc/ssh/sshd_config, validate it (sshd -t / visudo -c), then remove the leftover file
[ ] WARNING obsolete-packages: 15 installed packages are not available from any configured repository
    [ ] Inspect each with: apt policy PACKAGE
    [ ] Replace it with the new release's equivalent, or remove it: sudo apt purge PACKAGE
[ ] Run pydebuprep as root: 9 checks were skipped without it
[ ] Run pydebuprep again to confirm everything is fixed
```

**What goes on it:**

- one item per **critical** and **warning** finding — critical first, changes since
  the baseline included — naming its check;
- the finding's **remediation steps as sub-items**, so you can tick off partial
  progress;
- an item for each check that **failed to run**, since it may hide problems;
- a reminder to **run as root** if checks were skipped for lack of it;
- a final **confirmation run**.

Info findings are left out — they're for awareness, not action — and so are findings
hidden by `--min-severity`. With nothing to do, the section says so.

**In each format:**

| Format | Checklist |
|---|---|
| text | `[ ]` items with indented `[ ]` steps |
| markdown | task lists (`- [ ]`), which GitHub, GitLab and many wikis render as tickable checkboxes |
| html | real checkboxes you can tick in the browser (nothing is saved; the page has no script) |
| jira, confluence | ☐ bullets — their wiki markup has no checkbox |
| json, yaml | a `todo` array of `{severity, check, title, steps}` for your own tooling |

`--no-todo` leaves it out for one run when the configuration turns it on.
[`convert --todo`](#converting-a-saved-report) adds it to a report saved earlier.

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
- `convert` needs no root and reads no configuration file. `--todo` adds the
  [TODO list](#a-todo-list-to-track-the-fixes).
- Only JSON and YAML can be read back. Text, HTML, Markdown, Jira and Confluence are
  renderings, not data, and are rejected with a hint.
- The file is validated field by field, since it may come from another host; a
  damaged or hand-edited file is rejected naming the field at fault (exit code 3).
  `convert` exits 0 on success, whatever the report found.
