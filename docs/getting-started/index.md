# Getting started

pydebuprep is a single command that inspects a Debian or Ubuntu system and prints a
report. It's most useful around a release upgrade:

1. **[Install](install.md)** the package on the host.
2. Take a **snapshot** before upgrading, so the report can tell you what changed.
3. Upgrade, reboot, and run the **report**.

[Before and after an upgrade](upgrade-workflow.md) walks through that in detail.
You can also run a report at any time without a snapshot: every check still looks
for problems, only the "what changed" comparison needs one.
