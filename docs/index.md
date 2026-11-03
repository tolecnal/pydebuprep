# pydebuprep

**A health report suite for Debian and Ubuntu systems after a release upgrade.**

A release upgrade (Debian 12 → 13, Ubuntu 22.04 → 24.04 → 26.04) usually works, but
it can leave things behind that no single error message tells you about: an APT
source still pointing at the old release, a third-party repository the upgrader
disabled, a DKMS module that didn't rebuild, a service that was running before and
isn't now, a PostgreSQL cluster still on the old version, an SSH configuration that
would lock you out on the next restart.

`systemctl --failed` and a look at the journal catch some of this. pydebuprep runs
the rest of the post-upgrade checklist in one go — [42 checks](checks/index.md)
across packages, boot, services, applications, network, security and storage — and
tells you what it found and how to fix it.

```sh
sudo pydebuprep snapshot     # before the upgrade
sudo do-release-upgrade      # or: sudo apt full-upgrade
sudo reboot
sudo pydebuprep              # after: what's wrong, what changed, how to fix it
```

## It never changes anything

A report only reads. It doesn't install or remove packages, doesn't run
`apt update` or `update-grub`, and doesn't restart services. Every finding comes
with the commands to fix it, for **you** to review and run.

That's enforced, not just promised: every external command a report runs must match a
built-in allowlist of commands that change nothing exactly, and every pull request and release
is traced with strace (releases on every supported release) to prove a run as root changes no
system state or configuration. See [What pydebuprep changes](about/what-it-changes.md), which
also lists the few [agreed side effects](about/what-it-changes.md#agreed-side-effects). The
separate [`pydebuprep-cleanup`](guide/cleanup.md) is the one command that changes the
system: only when asked, and only from an allowlist of its own.

## Where to go next

<div class="grid cards" markdown>

- **[Install](getting-started/install.md)** — the package, its checksum and
  provenance, shell completion.
- **[Before and after an upgrade](getting-started/upgrade-workflow.md)** — the
  workflow pydebuprep is built for.
- **[Reading the results](guide/results.md)** — severities, statuses, exit codes and
  what to do about them.
- **[Configuration](configuration/index.md)** — the config file, every setting, and
  how settings combine.
- **[Checks](checks/index.md)** — what each check looks at, what it reports, and its
  limits.
- **[Cleaning up](guide/cleanup.md)** — `pydebuprep-cleanup` purges old kernels and
  other leftovers, safely and only when asked.
- **[Command line](reference/cli.md)** — every command and option.

</div>

## Supported systems

| Distribution | Releases |
|---|---|
| Debian | 12 (bookworm), 13 (trixie) |
| Ubuntu | 22.04 (jammy), 24.04 (noble), 26.04 (resolute) |

Python 3.10 or newer. The only dependency is `python3-yaml`.
