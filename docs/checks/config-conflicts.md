# config-conflicts — Unmerged configuration files

When a package ships a new version of a configuration file you changed, the
upgrade keeps yours and saves the package's version next to it. Those leftovers
are easy to miss — and for files such as `sshd_config` or `sudoers`, the new
defaults may matter for security.

<!-- facts: config-conflicts -->

## What it checks

- Files under `/etc` ending in `.dpkg-new`, `.dpkg-old`, `.dpkg-dist`,
  `.dpkg-bak`, `.ucf-new`, `.ucf-old` or `.ucf-dist`.
- Leftovers of the files in `critical_paths` (by default `sshd_config`, its `.d`
  directory, `sudoers` and its `.d` directory) are reported individually as
  critical; the rest are grouped.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | Unmerged package config for *file* | `diff -u FILE FILE.dpkg-dist`, merge what you want, validate (`sshd -t`, `visudo -c`), then delete the leftover. |
| warning | *N* config files have unmerged package versions | Review each diff, merge, delete the leftovers. |
| info | Some directories under /etc were not readable | Run as root for complete results. |

## Commands it runs

None: it walks `/etc`.

## Limitations

- It finds leftovers by name. A configuration file you changed without a leftover
  next to it (because the package didn't change its version) isn't reported.
- Files managed by configuration management (Ansible, Puppet, …) produce leftovers
  that are expected; list them in `ignore_paths`.

<!-- options: config-conflicts -->
