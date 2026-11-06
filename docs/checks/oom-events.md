# oom-events — Processes killed for lack of memory

A new release's services may need more memory than the old ones. The kernel then kills a
process, and what was killed may not come back.

<!-- facts: oom-events -->

## What it checks

- Kernel messages this boot saying a process was killed for lack of memory, by the system
  or by a memory limit of its cgroup, counted by process.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* processes were killed for lack of memory this boot | `sudo journalctl -b -k --grep='ut of memory'`; check they're running again; `free -h`. |

## Commands it runs

```sh
journalctl -b -k --no-pager -o cat '--grep=ut of memory: Killed process'
```

## Limitations

- Only this boot: events from before the last reboot aren't seen.
- It needs a journal that keeps kernel messages, and a `journalctl` built with pattern
  matching, as Debian's and Ubuntu's are.

<!-- options: oom-events -->
