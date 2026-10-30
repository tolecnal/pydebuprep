# docker — Docker containers

After an upgrade that touched Docker, containers may not come back: a changed
restart policy, a storage driver change, or a container that now crashes on start.
This check reports each level of assurance separately — running, passing its health
check, and (optionally) actually answering — rather than one healthy/unhealthy verdict.

<!-- facts: docker -->

## What it checks

- **Health**, each its own finding: containers **failing** their health check,
  **restarting** (crash-looping), and **still starting** their health check.
  Containers without a health check are fine while they run; stopped containers
  aren't reported (many are meant to run once), unless the snapshot shows they were
  running.
- **Port probe** (`probe: true`, off by default): a TCP connection to every TCP port
  a running container publishes on the host (wildcard bindings such as `0.0.0.0` are
  probed on localhost). Docker's proxy accepts connections on published ports even
  when nothing listens inside the container, then hangs up at once; so a port only
  passes if the service waits for the client or greets it.
- **HTTP probes** (`http_probes`, with `probe: true`): a `GET` to each
  `CONTAINER=URL` you list; 2xx and 3xx pass. URLs must point at localhost; redirects
  and proxies aren't followed, and for `https://` the certificate isn't checked (this
  asks whether the service answers, not who it is).
- With a snapshot: containers that were running before and aren't now.

`ignore_containers` leaves containers out of all of these.

It only queries Docker when `docker.service` is already running. With only
`docker.socket` active, any Docker command would start the daemon — which would be a
change — so the check is skipped instead.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* Docker containers fail their health check | `docker inspect --format '{{json .State.Health}}' CONTAINER`, `docker logs CONTAINER`. |
| warning | *N* Docker containers keep restarting | `docker logs CONTAINER`, `docker inspect CONTAINER`. |
| info | *N* Docker containers are still starting their health checks | Look again in a minute. |
| warning | *N* published container ports don't answer | (probe) The container runs but nothing answers behind the port: `docker logs`, `docker port`. |
| warning | *N* HTTP probes failed | (probe) The evidence shows the status, error, or that the container isn't running. |
| warning | *N* Docker containers were running before the upgrade but aren't now | `docker ps --all`; check their restart policy, then `docker start CONTAINER`. |

## Compared with a snapshot

The snapshot records the running containers by name.

## Commands it runs

```sh
docker ps --all --no-trunc --format '{{json .}}'
systemctl list-units --type=service --state=active --no-legend --plain --no-pager
```

The probes are plain TCP connections and HTTP requests from pydebuprep itself, to
localhost only; no command runs inside the containers.

## Example

```yaml
checks:
  docker:
    probe: true
    http_probes:
      - "web=http://127.0.0.1:8080/health"
      - "api=https://localhost:8443/ready"
    ignore_containers: ["ci-runner-*"]
```

## Limitations

- **The probes connect to your services**, which may log the requests; pydebuprep
  itself writes nothing. That's why they're off by default.
- A passing port probe means something accepts connections, not that it works; HTTP
  probes go one level further, for the URLs you name.
- UDP ports aren't probed, and port ranges are probed up to 32 ports.
- Podman, LXD and libvirt aren't covered: their clients create configuration or
  storage on first use, or need a daemon that may not be running.

<!-- options: docker -->
