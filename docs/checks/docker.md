# docker — Docker containers

After an upgrade that touched Docker, containers may not come back: a changed
restart policy, a storage driver change, or a container that now crashes on start.

<!-- facts: docker -->

## What it checks

- Every container: those that are **unhealthy** (failing their health check) or
  **restarting** (crash-looping).
- With a snapshot: containers that were running before and aren't now.

It only queries Docker when `docker.service` is already running. With only
`docker.socket` active, any Docker command would start the daemon — which would be a
change — so the check is skipped instead.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* Docker containers are unhealthy or restarting | `docker logs CONTAINER`, `docker inspect CONTAINER`. |
| warning | *N* Docker containers were running before the upgrade but aren't now | `docker ps --all`; check their restart policy, then `docker start CONTAINER`. |

Stopped containers aren't reported (many are meant to run once), unless the
snapshot shows they were running.

## Compared with a snapshot

The snapshot records the running containers by name.

## Commands it runs

```sh
docker ps --all --no-trunc --format '{{json .}}'
systemctl list-units --type=service --state=active --no-legend --plain --no-pager
```

## Limitations

- A container without a health check counts as fine while it runs; whether the
  application inside works isn't tested.
- Podman, LXD and libvirt aren't covered: their clients create configuration or
  storage on first use, or need a daemon that may not be running.

<!-- options: docker -->
