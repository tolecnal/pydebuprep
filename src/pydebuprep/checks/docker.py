from __future__ import annotations

import json
from typing import Any

from pydebuprep.checks._systemd import active_services
from pydebuprep.checks.base import Check, CheckSkipped, Context, count, run_checked
from pydebuprep.model import Finding, Severity, truncate_evidence

DOCKER_PS = ("docker", "ps", "--all", "--no-trunc", "--format", "{{json .}}")


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


class DockerCheck(Check):
    id = "docker"
    title = "Docker containers"
    category = "applications"
    requires_root = True
    requires_commands = ("docker",)

    def run(self, ctx: Context) -> list[Finding]:
        troubled = sorted(
            f"{c.get('Names')}: {c.get('Status')}"
            for c in _containers(ctx)
            if c.get("State") == "restarting" or "(unhealthy)" in str(c.get("Status", ""))
        )
        if not troubled:
            return []
        return [
            Finding(
                Severity.WARNING,
                f"{count(len(troubled), 'Docker container is', 'Docker containers are')} "
                "unhealthy or restarting",
                evidence=truncate_evidence(troubled),
                remediation=["docker logs CONTAINER", "docker inspect CONTAINER"],
            )
        ]

    def collect_baseline(self, ctx: Context) -> Any:
        return sorted(str(c.get("Names")) for c in _containers(ctx) if c.get("State") == "running")

    def compare(self, ctx: Context, before: Any) -> list[Finding]:
        now = set(self.collect_baseline(ctx))
        stopped = sorted(name for name in before if name not in now)
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
