# Reading the results

## Severities

Each finding has one of three severities:

| Severity | Meaning | Examples |
|---|---|---|
| **critical** | Something is broken, or will break at the next restart or reboot. Fix it first. | an invalid SSH configuration, a DKMS module not built for the running kernel, broken packages, a full `/boot` |
| **warning** | Something is wrong or left over and should be looked at. | an APT source still on the old release, a service that was running before the upgrade and isn't, pending upgrades |
| **info** | Worth knowing; often expected. | the release you upgraded from, packages that can be autoremoved, how long boot took |

Severities are pydebuprep's judgement of the typical case. Your situation may
differ: a warning about a service that stopped is expected if you removed it on
purpose.

## Check statuses

Each check ends in one of four statuses:

| Status | Meaning |
|---|---|
| **ok** | The check ran and found nothing. |
| **findings** | The check ran and has findings (or changes since the baseline). |
| **skipped** | The check couldn't run here, with the reason: not root, a program not installed, or nothing to inspect (for example Docker not running). |
| **error** | The check failed to run: a command timed out or failed unexpectedly. The report shows the error. |

A skipped check doesn't affect the exit code. An **error** does — it raises the
exit code to at least 1 — so a host never looks healthy just because a check
couldn't look.

## Findings

Each finding has a title, and may have:

- **detail** — why it matters;
- **evidence** — what pydebuprep saw: file lines, unit names, command output
  (long lists are shortened);
- **remediation** — commands or steps to fix it, for you to review and run;
- **references** — documentation links.

Remediation is advice. pydebuprep sees the system, not your intentions: read each
step before running it, especially anything that removes packages or files.

## Changes since the baseline

With a [baseline](snapshots.md), checks that support it add a second section per
check: what was there before the upgrade and isn't now. "Not applicable" means the
check doesn't compare, or the baseline has no data for it; "no changes" means it
compared and found none.

## Exit codes

The exit code summarises the report for scripts and automation:

| Code | Meaning |
|---|---|
| 0 | Nothing at warning level or above |
| 1 | The most severe finding is a warning, or a check failed to run |
| 2 | At least one critical finding |
| 3 | pydebuprep itself failed (bad arguments, invalid configuration, unreadable baseline, unwritable output) |

`--min-severity` hides findings from the display only; the exit code still counts
them. See [Exit codes](../reference/exit-codes.md).

## Silencing expected findings

If a finding is expected on your systems, tell pydebuprep instead of learning to
ignore it — otherwise real problems get lost in the noise:

- turn a check off: `enabled: false`;
- use the check's options: ignore patterns for units, mounts, interfaces, log
  messages, config files;
- for log messages common to all your hosts, use `logs: ignore:`.

See the [configuration reference](../configuration/reference.md) and each
[check's page](../checks/index.md).
