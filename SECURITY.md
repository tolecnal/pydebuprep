# Security policy

pydebuprep is usually run as root, on servers right after a release upgrade, and it
promises never to change the system it inspects. Security reports are welcome and taken
seriously.

## Supported versions

Only the latest release gets security fixes. Upgrade to it before reporting, if you can.

| Version | Supported |
|---|---|
| 0.3.x (latest) | Yes |
| Older | No |

## Reporting a vulnerability

**Please don't open a public issue, pull request or discussion for a security problem.**

Report it privately through GitHub instead:

1. Go to the repository's **Security** tab.
2. Choose **Report a vulnerability**:
   <https://github.com/tolecnal/pydebuprep/security/advisories/new>

Only the maintainers can see the report. You can follow up in the same private advisory.

Please include:

- the pydebuprep version (`pydebuprep --version`) and the distribution and release;
- what you ran (command line and, if relevant, the config file) and whether as root;
- what happened, and what you expected to happen;
- steps to reproduce, or a proof of concept;
- the impact as you see it, and any fix or workaround you have in mind.

Don't include secrets, private keys or full reports from production hosts. Trim reports
to the parts that show the problem.

## What to expect

pydebuprep is maintained in spare time, so these are targets, not guarantees:

- acknowledgement of your report within **7 days**;
- an assessment, and either a plan for a fix or an explanation, within **30 days**;
- a fixed release as soon as practical after that. Critical issues come first.

Disclosure is coordinated with you. Please give us up to **90 days** from your report,
or until a fix is released, whichever comes first, before discussing it publicly. Once
fixed, a GitHub Security Advisory is published and you are credited, unless you prefer
not to be.

## Scope

In scope, for example:

- **anything that makes pydebuprep change the system it inspects** while running
  `report`: writing, deleting or rewriting files, changing packages, services or
  firmware settings, or starting commands outside its read-only allowlist. The read-only
  promise is the most important property of this tool. `snapshot` writing its snapshot
  file, a report file you asked for, and temporary files in pydebuprep's own private
  scratch directory (created under `/tmp` with mode 0700 and removed before it exits)
  are expected. A scratch file that outlives the run, or one written anywhere else, is
  in scope;
- command or argument injection, for example through config values, file names, or
  output of the commands it runs;
- unsafe file handling, such as following symlinks to overwrite files when writing
  reports or snapshots, or snapshot files readable by unprivileged users;
- text from logs or other users ending up as terminal escape sequences or active
  content in the text, HTML, Markdown, Jira or Confluence output;
- vulnerabilities in the release process: a way to publish a tampered package, or to
  make one pass `sha256sum -c SHA256SUMS` or `gh attestation verify`.

Out of scope:

- problems pydebuprep *reports* about your system. Those are its findings, not
  vulnerabilities in pydebuprep;
- issues that need an attacker who already has root on the host;
- vulnerabilities in Debian or Ubuntu packages pydebuprep depends on, such as
  python3-yaml. Report those to the distribution;
- missing hardening that has no demonstrated impact.

## Verifying releases

Every release is built by GitHub Actions from a tag, installed and audited for system
changes on each supported release, and published with checksums and a signed
build-provenance attestation:

```sh
gh release download v0.4.0 -R tolecnal/pydebuprep
sha256sum -c SHA256SUMS
gh attestation verify pydebuprep_0.4.0_all.deb -R tolecnal/pydebuprep
```

Install only packages that pass both checks.

## How this project stays secure

- Every command pydebuprep runs must match a complete entry in a read-only allowlist
  (`src/pydebuprep/system.py`). Every pull request and release is traced with strace
  on every supported release, with and without systemd and on real UEFI firmware, to
  prove a root run changes nothing (`scripts/readonly-audit.sh`).
- CodeQL, Bandit, ShellCheck, pip-audit and zizmor run on every change to `main`, and
  pull requests get a dependency review. Dependabot keeps pinned actions and tools up
  to date.
- GitHub Actions are pinned to commit hashes and run with least-privilege permissions.
- Release tags are protected; only maintainers can create them.
