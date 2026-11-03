# Cleaning up after an upgrade

`pydebuprep-cleanup` purges what a release upgrade leaves behind: old kernels, their
modules and headers, directories DKMS leaves in them, and the configuration of
removed packages (dpkg state `rc`, which the [dpkg-rc](../checks/dpkg-rc.md) check
reports). Unlike `pydebuprep report`, it changes the system: on purpose, and only when
you ask it to (see [What pydebuprep changes](../about/what-it-changes.md#the-cleanup-tool)).

## Dry run first

Without `--apply` it only shows what it would do, and changes nothing:

```sh
sudo pydebuprep-cleanup --all
```

```text
Kernels kept: 6.8.0-47, 6.8.0-49
Old kernels (2):
  linux-image-6.8.0-40-generic
  linux-image-6.8.0-45-generic
Modules and headers of old kernels (6):
  ...
Leftover directories (1):
  /lib/modules/6.8.0-36-generic
Configuration left by removed packages (14):
  ...
In all: 22 packages (412.0 MiB installed), 1 directory
Dry run: nothing changed. Run again with --apply to do this.
```

Then do it, and record the result:

```sh
sudo pydebuprep-cleanup --all --apply
sudo pydebuprep report
```

At a terminal it asks before acting; without one (cron, Ansible) it needs `--yes`.

## What it cleans up

| Option | Removes |
|---|---|
| `--kernels` | old kernel images (`linux-image-VERSION-FLAVOUR`) |
| `--modules` | modules, headers and tools of old kernels, also of those whose image is already gone |
| `--leftover-dirs` | directories of old kernels under `/lib/modules` and `/usr/src` that no package owns, or only packages this run purges, even when not empty (DKMS builds) |
| `--residual` | the configuration of removed packages, backed up first |
| `--all` | all of the above |

Packages are purged with `apt-get purge`, so their own scripts run: the initramfs, GRUB's
menu and DKMS are updated as on any removal. Directories are removed only after the
purges, and only if no package owns anything in them then.

`--keep N` sets how many kernels to keep (1 to 10, default 2), `--keep-package PKG`
leaves a package alone (repeat it for more), and `--json` prints the plan for scripts.
It reads `keep_packages` (below) from `/etc/pydebuprep.conf`, or `--config FILE`;
`--no-config` ignores any config file.

## Guardrails

- **Kernels kept:** the running kernel, the newest installed kernel image, the newest
  `N` images, and every kernel GRUB is set to boot: `GRUB_DEFAULT` in
  `/etc/default/grub` (and `grub.d/*.cfg`), and the saved and next entries in
  `/boot/grub/grubenv`. With a reboot pending after an upgrade (the running kernel
  older than the newest), both stay. Headers alone don't count as a kernel. Meta
  packages such as `linux-image-generic` and `linux-image-amd64` are never touched.
- **When it can't tell, it refuses:** if the running kernel can't be identified (a
  kernel built by hand), or `GRUB_DEFAULT` names an entry it can't match to a kernel
  (a menu position like `2`, or a title without a version), no kernel, module or
  directory is removed. Set `GRUB_DEFAULT` to the kernel's own entry, or to `0` or
  `saved`.
- **Held packages stay:** a package held with `apt-mark hold` is never purged, and the
  plan lists it as left alone.
- **Directories of installed kernels stay:** a kernel directory is planned only when
  no package of that kernel remains installed, and dpkg is asked about both
  `/lib/modules` and `/usr/lib/modules` (Debian 13 records its kernels there).
- **Before acting**, it refuses unless it runs as root, while apt or dpkg is running,
  when `dpkg --audit` reports problems, or while another cleanup runs.
- **apt's own simulation first:** `apt-get -s purge` with the plan, under the lock and
  after the plan was made there; if apt would remove or install anything not in the
  plan (a meta package, a dependency), it refuses. Each purge is simulated again with
  exactly its packages just before it runs, in case apt has come to want more since.
- **One failure stops it:** the log says what was done and what was left undone, and
  it exits with status 2. So does Ctrl-C: apt and dpkg run in a session of their own,
  so an interrupt doesn't stop them halfway; the cleanup waits for them, then stops.
  Purges have no time limit.
- **Packages to keep for good** go in `/etc/pydebuprep.conf`:

  ```yaml
  cleanup:
    keep_packages: [mysql-server-8.0, postgresql-15]
  ```

  A config fetched from a [portal](portal.md) can't set `keep_packages`.

## Logs and backups

Every run, dry or not, logs its plan and every action to
`/var/log/pydebuprep/cleanup.log` (rotated weekly) and to the journal:

```sh
journalctl -t pydebuprep-cleanup
```

Before purging removed packages' configuration, it saves their configuration files in
`/var/backups/pydebuprep/rc-TIMESTAMP.tar.gz`, so a purge you regret can be undone:

```sh
sudo tar -xzf /var/backups/pydebuprep/rc-20261103T150405Z.tar.gz -C / etc/hello/hello.conf
```

Purging pydebuprep itself removes its log but keeps those backups.

## Installed with pydebuprep

`pydebuprep-cleanup` comes with the pydebuprep package, in `/usr/sbin`, with its man
page (`man pydebuprep-cleanup`) and bash and zsh completion: options, `--keep`'s
range, and package names for `--keep-package`.

## Exit status

0: done, or nothing to do. 1: refused by a guardrail. 2: a step failed; the rest was
left undone. 3: a usage or config error.

## Commands it runs

To work out what it would remove, it only reads, like `pydebuprep report`:

```sh
dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${Installed-Size}\n'
dpkg --print-architecture
uname -r
dpkg-query -S /lib/modules/VERSION /usr/lib/modules/VERSION /usr/src/linux-headers-VERSION
dpkg-query -W -f='${Conffiles}\n' PACKAGE...
```

With `--apply`, from an allowlist of its own:

```sh
dpkg --audit
apt-get -s purge PACKAGE...
apt-get purge -y PACKAGE...
```
