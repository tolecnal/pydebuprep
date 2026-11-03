# Before and after an upgrade

pydebuprep is built around one workflow: record how the system looks **before** a
release upgrade, then check it **after**.

## 1. Before: take a snapshot

```sh
sudo pydebuprep snapshot
```

This records a baseline (OS release, kernel, active and enabled services, timers,
cron jobs, APT sources, held and installed packages, mounts, DKMS modules, network
interfaces, routes and DNS, firewall rules, the time service, AppArmor profiles,
unattended-upgrades, running Docker containers and online PostgreSQL clusters) and
prints where it saved it, by default under `/var/lib/pydebuprep/snapshots/`. Only
root can read it.

It's also worth running a report now: anything already broken before the upgrade
is better fixed first.

```sh
sudo pydebuprep report
```

## 2. Upgrade

Upgrade the way you normally would:

=== "Ubuntu"

    ```sh
    sudo do-release-upgrade
    ```

=== "Debian"

    ```sh
    # after pointing the APT sources at the new release
    sudo apt update && sudo apt full-upgrade
    ```

Then reboot, so the new kernel and libraries are in use.

## 3. After: run the report

```sh
sudo pydebuprep
```

`report` is the default command. It finds the newest snapshot automatically and
compares against it, so each check reports both:

- **problems now** — for example a failed unit, an APT source still on the old
  release, a DKMS module not built for the running kernel;
- **changes since the snapshot** — for example a service that was enabled and isn't,
  a network interface that lost its address, a Docker container that was running.

If the snapshot was taken on another host, or on the same release (so it may be a
post-upgrade snapshot by mistake), the report warns you.

## 4. Fix, then report again

Each finding lists remediation commands. Review them — pydebuprep doesn't know your
intentions, only what it sees — run the ones that apply, and run the report again
until it's clean, or until what's left is expected. Settings in the
[configuration file](../configuration/index.md) can silence findings that are
expected on your systems.

## 5. Clean up what the upgrade left

Once the report is clean and the new kernel boots, old kernels, their modules and
headers, and the configuration of removed packages can go. `pydebuprep-cleanup` shows
what it would remove, and only does it when asked:

```sh
sudo pydebuprep-cleanup --all            # the plan; nothing changes
sudo pydebuprep-cleanup --all --apply    # do it (asks first)
sudo pydebuprep                          # and record the result
```

It always keeps the running kernel, the newest one and the one GRUB boots, and refuses
when it can't tell which those are. See [Cleaning up after an upgrade](../guide/cleanup.md).

## Upgrading in several steps

Ubuntu upgrades one LTS at a time (22.04 → 24.04 → 26.04), and Debian one release at
a time. Repeat the workflow for each step: a snapshot before it, a report after it.

```sh
sudo pydebuprep snapshot   # on 22.04
sudo do-release-upgrade    # to 24.04, then reboot
sudo pydebuprep            # compares with the 22.04 snapshot
sudo pydebuprep snapshot   # on 24.04, before the next step
sudo do-release-upgrade    # to 26.04, then reboot
sudo pydebuprep            # compares with the 24.04 snapshot
```

Each report compares with the newest snapshot, so it shows what that one step
changed. Snapshot files are named by the time they were taken (UTC) and kept, so an
older one can still be used with `--baseline FILE`.

Take each snapshot as the last thing before the upgrade: anything you change after it
shows up as a change. A report run after you took the next snapshot, but before you
upgraded, warns that the snapshot was taken on the current release; that's expected
then.

pydebuprep is installed from a `.deb`, not from Ubuntu's archive, so
`do-release-upgrade` may offer to remove it with the obsolete packages at the end.
Keep it, or install it again after the upgrade: removing it keeps the snapshots
(only purging it deletes `/var/lib/pydebuprep`).

With a [portal](../guide/portal.md#snapshots-in-the-portal), each report's page says
which snapshot it was compared with, and the host's page shows the steps as a chain.

!!! tip "Run it as root"
    Several checks need root to read what they inspect (the firewall, AppArmor,
    `sshd -t`, Docker, debsums, …). Without root they are reported as *skipped*,
    and the report header says it wasn't run as root.
