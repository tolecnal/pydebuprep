# Running across a fleet

pydebuprep runs on one host at a time; to cover many, run it from your
configuration management. Use JSON output, collect the files, and act on the exit
code.

## With Ansible

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

Notes:

- `changed_when: false` — pydebuprep never changes the host, so the task never
  reports a change.
- `failed_when: pydebuprep.rc == 3` — exit codes 1 and 2 mean findings, not a
  failure of the run. Only 3 means pydebuprep itself failed.
- Distribute a common `/etc/pydebuprep.conf` (for example with
  `ansible.builtin.copy`) to silence findings that are expected everywhere, and
  check it with `pydebuprep configtest`.

## Turning collected reports into something to read

The fetched JSON files can be [converted](output-formats.md#converting-a-saved-report)
on the control node, without touching the hosts again:

```sh
for f in reports/*.json; do
    pydebuprep convert "$f" --format html --output-dir reports/html
done
```

For dashboards, the [report format](../reference/report-format.md) gives each
host's summary counts and exit code directly:

```sh
jq -r '[.host.hostname, .summary.critical, .summary.warning] | @tsv' reports/*.json
```
