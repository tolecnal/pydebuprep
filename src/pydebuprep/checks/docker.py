from __future__ import annotations

import fnmatch
import json
import re
from typing import Any
from urllib.parse import urlsplit

from pydebuprep.checks._probes import PROBE_OPTION
from pydebuprep.checks._systemd import active_services
from pydebuprep.checks.base import Check, CheckSkipped, Context, Option, count, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence

DOCKER_PS = ("docker", "ps", "--all", "--no-trunc", "--format", "{{json .}}")
CONNECT_TIMEOUT = 3.0
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
# "0.0.0.0:8080->80/tcp", "[::]:8000-8002->8000-8002/tcp", "127.0.0.1:9000->9000/tcp"
PUBLISHED = re.compile(r"^\[?([0-9a-fA-F.:]*?)\]?:(\d+)(?:-(\d+))?->[\d-]+/tcp$")
WILDCARD = {"0.0.0.0": "127.0.0.1", "::": "::1", "": "127.0.0.1"}
MAX_RANGE = 32
# Health states worth reporting, each its own finding: (state, severity, one, many, fix).
# Running without a health check is not a problem, and isn't reported.
HEALTH_FINDINGS = (
    (
        "unhealthy",
        Severity.WARNING,
        "Docker container fails its health check",
        "Docker containers fail their health check",
        ["docker inspect --format '{{json .State.Health}}' CONTAINER", "docker logs CONTAINER"],
    ),
    (
        "restarting",
        Severity.WARNING,
        "Docker container keeps restarting",
        "Docker containers keep restarting",
        ["docker logs CONTAINER", "docker inspect CONTAINER"],
    ),
    (
        "starting",
        Severity.INFO,
        "Docker container is still starting its health check",
        "Docker containers are still starting their health checks",
        ["Look again in a minute: docker ps"],
    ),
)


def _health(container: dict[str, Any]) -> str | None:
    status = str(container.get("Status", ""))
    if container.get("State") == "restarting":
        return "restarting"
    if "(unhealthy)" in status:
        return "unhealthy"
    return "starting" if "(health: starting)" in status else None


def _containers(ctx: Context) -> list[dict[str, Any]]:
    active = active_services(ctx)
    if active is None:
        raise CheckSkipped("systemd is not running, so the Docker daemon's state is unknown")
    if "docker.service" not in active:
        # With only docker.socket active, any docker command would start the daemon.
        raise CheckSkipped("docker.service is not running")
    containers = []
    for line in run_checked(ctx, DOCKER_PS, timeout=60).stdout.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        containers.append(item)
    return containers


def _published(ports: str) -> list[tuple[str, int]]:
    """Host addresses and TCP ports a container publishes, wildcards as localhost."""
    found = []
    for item in ports.split(","):
        m = PUBLISHED.match(item.strip())
        if not m:
            continue
        host = WILDCARD.get(m.group(1), m.group(1))
        first = int(m.group(2))
        last = int(m.group(3) or first)
        found += [(host, port) for port in range(first, min(last, first + MAX_RANGE - 1) + 1)]
    return list(dict.fromkeys(found))


class DockerCheck(Check):
    id = "docker"
    title = "Docker containers"
    category = "applications"
    requires_root = True
    requires_commands = ("docker",)
    options = (
        PROBE_OPTION,
        Option(
            "http_probes",
            [],
            "With probe: CONTAINER=URL items; GET each localhost URL, 2xx/3xx passes",
        ),
        Option("ignore_containers", [], "Containers to leave out (shell-style patterns)"),
    )

    def validate(self) -> None:
        for item in self.opt("http_probes"):
            name, sep, url = item.partition("=")
            parts = urlsplit(url)
            if not (name and sep and parts.scheme in ("http", "https")):
                raise ValueError(f"http_probes: expected CONTAINER=http(s)://... , got {item!r}")
            if parts.hostname not in LOCAL_HOSTS:
                raise ValueError(f"http_probes: only localhost URLs are probed, got {url!r}")

    def _containers(self, ctx: Context) -> list[dict[str, Any]]:
        return [
            c
            for c in _containers(ctx)
            if not any(
                fnmatch.fnmatchcase(str(c.get("Names")), p) for p in self.opt("ignore_containers")
            )
        ]

    def run(self, ctx: Context) -> list[Finding]:
        containers = self._containers(ctx)
        findings = []
        for state, severity, one, many, fix in HEALTH_FINDINGS:
            hits = sorted(
                f"{c.get('Names')}: {c.get('Status')}" for c in containers if _health(c) == state
            )
            if hits:
                findings.append(
                    Finding(
                        severity,
                        f"{len(hits)} {one if len(hits) == 1 else many}",
                        evidence=truncate_evidence(hits),
                        remediation=fix,
                    )
                )
        if self.opt("probe"):
            findings += self._probe_ports(ctx, containers) + self._probe_http(ctx, containers)
        return findings

    @staticmethod
    def _probe_ports(ctx: Context, containers: list[dict[str, Any]]) -> list[Finding]:
        failed = []
        for c in sorted(containers, key=lambda c: str(c.get("Names"))):
            if c.get("State") != "running":
                continue
            for host, port in _published(str(c.get("Ports", ""))):
                error = ctx.system.tcp_connect(host, port, CONNECT_TIMEOUT)
                if error is not None:
                    failed.append(f"{c.get('Names')}: {host} port {port} ({error})")
        if not failed:
            return []
        return [
            Finding(
                Severity.WARNING,
                f"{count(len(failed), 'published container port', 'published container ports')}"
                f" {'does' if len(failed) == 1 else 'do'}n't answer",
                detail="The container runs, but nothing answers on a port it publishes (Docker "
                "accepts the connection and hangs up): the application inside may have "
                "failed to start, or listens on another port.",
                evidence=truncate_evidence(failed),
                remediation=["docker logs CONTAINER", "docker port CONTAINER"],
            )
        ]

    def _probe_http(self, ctx: Context, containers: list[dict[str, Any]]) -> list[Finding]:
        running = {str(c.get("Names")) for c in containers if c.get("State") == "running"}
        failed = []
        for item in sorted(self.opt("http_probes")):
            name, _, url = item.partition("=")
            if name not in running:
                failed.append(f"{name}: not running")
                continue
            status, error = ctx.system.http_get(url, CONNECT_TIMEOUT)
            if status is None:
                failed.append(f"{name}: {url} failed: {error}")
            elif not 200 <= status < 400:
                failed.append(f"{name}: {url} answered {status}")
        if not failed:
            return []
        return [
            Finding(
                Severity.WARNING,
                f"{count(len(failed), 'HTTP probe', 'HTTP probes')} failed",
                detail="An application-level check: the container may run, and even pass its "
                "health check, while its service doesn't answer as expected.",
                evidence=truncate_evidence(failed),
                remediation=["docker logs CONTAINER", "curl -v URL"],
            )
        ]

    def collect_baseline(self, ctx: Context) -> Any:
        return sorted(
            str(c.get("Names")) for c in self._containers(ctx) if c.get("State") == "running"
        )

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now = set(self.collect_baseline(ctx))
        ignore = self.opt("ignore_containers")
        stopped = sorted(
            name
            for name in before
            if name not in now and not any(fnmatch.fnmatchcase(name, p) for p in ignore)
        )
        if not stopped:
            return []
        return [
            Finding(
                Severity.WARNING,
                f"{count(len(stopped), 'Docker container was', 'Docker containers were')} "
                "running before the upgrade but "
                f"{'isn' if len(stopped) == 1 else 'aren'}'t now",
                detail="Check their restart policy and whether the new Docker version "
                "changed anything they rely on.",
                evidence=truncate_evidence(stopped),
                remediation=["docker ps --all", "docker start CONTAINER"],
            )
        ]
