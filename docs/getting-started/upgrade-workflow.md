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

!!! tip "Run it as root"
    Several checks need root to read what they inspect (the firewall, AppArmor,
    `sshd -t`, Docker, debsums, …). Without root they are reported as *skipped*,
    and the report header says it wasn't run as root.
